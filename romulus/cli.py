"""Command line interface for deployment checks, hunting, resume, and offline demonstration."""
import argparse, importlib.util, shutil, sys
from copy import deepcopy
from dataclasses import replace
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pathlib import Path
from . import __version__
from .config import Settings, safe_url
from .store import Store
from .models import utc_now
from .investigation.workflow import HuntEngine
from .agent.providers import configured_model_name


def _configured_pcap_ready(path: Path, allowed_dirs: tuple[Path, ...]) -> bool:
    from .tools.tshark_client import approve_capture_path
    try: approve_capture_path(path,allowed_dirs)
    except (OSError,ValueError): return False
    return True


def doctor(settings: Settings) -> int:
    print(f"ROMULUS {__version__} deployment diagnostics (configured values; connectivity is checked now)")
    checks=[]
    try:
        ZoneInfo(settings.mission_timezone); checks.append(True)
        print(f"OK mission timezone: {settings.mission_timezone}")
    except ZoneInfoNotFoundError:
        checks.append(False); print(f"FAILED mission timezone: {settings.mission_timezone}")
    for name in ("langgraph","langgraph.checkpoint.sqlite","elasticsearch","requests","docx","dotenv"):
        try: present=importlib.util.find_spec(name) is not None
        except (ImportError,ModuleNotFoundError): present=False
        checks.append(present); print(f"{'OK' if present else 'MISSING'} dependency: {name}")
    try:
        from .intelligence.attack_catalog import (
            EXPECTED_RELEASE, EXPECTED_SOURCE_SHA256, EXPECTED_TECHNIQUE_COUNT,
            load_attack_catalog,
        )
        metadata=load_attack_catalog().get("metadata",{})
        catalog_ready=(
            metadata.get("release")==EXPECTED_RELEASE
            and metadata.get("source_sha256")==EXPECTED_SOURCE_SHA256
            and metadata.get("technique_count")==EXPECTED_TECHNIQUE_COUNT
            and int(metadata.get("detection_strategy_links",0) or 0)>0
            and int(metadata.get("analytic_links",0) or 0)>0
        )
        checks.append(catalog_ready)
        detail=(f"Enterprise v{metadata.get('release','unknown')}; "
                f"{metadata.get('technique_count',0)} techniques; "
                f"{metadata.get('detection_strategy_links',0)} Detection Strategy links; "
                f"{metadata.get('analytic_links',0)} Analytic links")
        print(f"{'OK' if catalog_ready else 'FAILED'} pinned ATT&CK catalog: {detail}")
    except Exception as e:
        checks.append(False); print(f"FAILED pinned ATT&CK catalog: {type(e).__name__}")
    try:
        from .agent.ollama import Ollama
        agent=Ollama(settings); o=agent.available(); model_ready=bool(o.get("available") and o.get("model_configured")); checks.append(model_ready)
        endpoint=settings.openai_base_url if settings.llm_provider=="openai" else settings.ollama_url
        model=configured_model_name(settings) or "not configured"
        detail=o.get("error") if not o.get("available") else None
        suffix=f"; {detail}" if detail else ""
        print(f"{'OK' if o.get('available') else 'UNAVAILABLE'} model provider {settings.llm_provider}: {safe_url(endpoint)}; configured model {'available' if o.get('model_configured') else 'not found'} ({model}){suffix}")
        reasoning=agent.reasoning_preflight(); checks.append(bool(reasoning.get("ready")))
        print(f"{'OK' if reasoning.get('ready') else 'FAILED'} iterative reasoning preparation and structured schema")
    except Exception as e: checks.append(False); print(f"UNAVAILABLE model provider {settings.llm_provider}: {type(e).__name__}")
    try:
        from .tools.elasticsearch_client import ElasticsearchAdapter
        es=ElasticsearchAdapter(settings).check(); checks.append(bool(es.get("available"))); detail=f"{es.get('matched_indices',0)} allowlisted index(es)" if es.get('available') else es.get('error','failed')
        print(f"{'OK' if es.get('available') else 'UNAVAILABLE'} Elasticsearch: {safe_url(settings.es_url)}; {detail}")
    except Exception as e: checks.append(False); print(f"UNAVAILABLE Elasticsearch: {type(e).__name__}")
    try:
        from .tools.arkime_client import ArkimeAdapter
        if not settings.arkime_username or not settings.arkime_password: print("UNCONFIGURED Arkime: API credentials missing; no request made")
        else:
            a=ArkimeAdapter(settings).check(); checks.append(bool(a.get("available"))); extra=f"; {a.get('total','unknown')} matching/total sessions" if a.get('available') else ''
            print(f"{'OK' if a.get('available') else 'UNAVAILABLE'} Arkime: {safe_url(settings.arkime_url)}; {a.get('status_code','not verified')}{extra}")
    except Exception as e: checks.append(False); print(f"UNAVAILABLE Arkime: {type(e).__name__}")
    from .tools.tshark_client import TSharkAdapter, ALLOWED_FIELDS
    from .investigation.search_planner import SOURCE_FIELDS
    ts=TSharkAdapter(settings).check();
    if settings.pcap_files: checks.append(bool(ts.get("available")))
    print(f"{'OK' if ts.get('available') else 'UNAVAILABLE'} TShark: {ts.get('version',ts.get('error','unavailable'))}")
    field_contract=set(SOURCE_FIELDS["tshark"])<=set(ALLOWED_FIELDS); checks.append(field_contract)
    print(f"{'OK' if field_contract else 'FAILED'} TShark planner/adapter field contract")
    for d in settings.pcap_allowed_dirs:
        present=d.is_dir(); checks.append(present); print(f"{'OK' if present else 'MISSING'} PCAP allowed directory: {d}")
    for p in settings.pcap_files:
        usable=_configured_pcap_ready(p,settings.pcap_allowed_dirs)
        checks.append(usable); print(f"{'OK' if usable else 'UNAVAILABLE/NOT ALLOWLISTED'} configured PCAP: {p}")
    for d in (settings.data_dir,settings.logs_dir,settings.reports_dir):
        try: d.mkdir(parents=True,exist_ok=True); probe=d/".romulus-write-check"; probe.write_text("ok"); probe.unlink(); checks.append(True); print(f"OK writable directory: {d}")
        except OSError: checks.append(False); print(f"UNWRITABLE directory: {d}")
    print("Secrets are never displayed. No service configuration is changed.")
    return 0 if all(checks) else 1


def model_check(settings: Settings) -> int:
    """Verify the selected provider with a fixed request that contains no hunt data."""
    from .agent.ollama import Ollama
    model=configured_model_name(settings) or "not configured"
    try:
        agent=Ollama(settings)
        availability=agent.available()
        if not availability.get("available") or not availability.get("model_configured"):
            detail=str(availability.get("error") or "selected model is unavailable")
            print(f"FAILED model provider {settings.llm_provider} ({model}): {detail}")
            return 1
        result=agent.connectivity_check()
        if result.get("status")!="ready":
            print(f"FAILED model provider {settings.llm_provider} ({model}): invalid readiness response")
            return 1
        metadata=getattr(result,"model_metadata",{})
        resolved=str(metadata.get("model") or model)
        tokens=metadata.get("total_tokens")
        usage=f"; total tokens={tokens}" if isinstance(tokens,int) else ""
        print(f"OK model provider {settings.llm_provider} ({resolved}) completed a fixed no-hunt-data check{usage}")
        return 0
    except Exception as exc:
        print(f"FAILED model provider {settings.llm_provider} ({model}): {type(exc).__name__}")
        return 1


def model_report(settings: Settings, hunt_id: str) -> int:
    """Re-synthesize one saved hunt into a separate report without new telemetry searches."""
    from .reporting.report import generate_report
    store=Store(settings.data_dir,settings.logs_dir)
    original=store.load_state(hunt_id)
    if not original:
        print(f"Unknown investigation ID: {hunt_id}")
        return 1
    state=deepcopy(original)
    state["source_hunt_id"]=hunt_id
    stamp=utc_now().replace("-","").replace(":","").replace("+00:00","Z")
    state["hunt_id"]=f"{hunt_id}-MODEL-{stamp}"
    state["tool_runs"]=[]
    state.pop("indicator_review",None)
    state.pop("report_manifest",None)
    state.pop("report_paths",None)
    coverage=state.setdefault("coverage",{})
    if isinstance(coverage,dict):
        coverage.pop("indicator_review",None)
    engine=HuntEngine(settings,store,offline=False)
    try:
        engine._indicator_review(state)
        output_dir=settings.reports_dir/"model-evaluations"
        paths=generate_report(state,output_dir)
    except Exception as exc:
        print(f"Model report failed: {type(exc).__name__}: {exc}")
        return 1
    result=(state.get("coverage",{}).get("indicator_review",{})
        if isinstance(state.get("coverage"),dict) else {})
    status=result.get("model_result_status","unknown") if isinstance(result,dict) else "unknown"
    review_status=(state.get("indicator_review",{}).get("status","unknown")
        if isinstance(state.get("indicator_review"),dict) else "unknown")
    print(f"Model report used provider {settings.llm_provider}; synthesis status={status}; admission status={review_status}; no new telemetry searches were run.")
    for path in paths:
        print(f"Report: {path}")
    return 0 if status=="ok" and review_status=="admitted" else 2

def main(argv=None):
    parser=argparse.ArgumentParser(prog="romulus",description="Local defensive cyber threat hunting")
    parser.add_argument("--version",action="version",version=__version__)
    sub=parser.add_subparsers(dest="command",required=True)
    sub.add_parser("doctor",help="check configured dependencies and deployment services")
    sub.add_parser("model-check",help="test the selected model provider without sending hunt data")
    model_report_parser=sub.add_parser("model-report",help="re-synthesize a saved hunt without new telemetry searches")
    model_report_parser.add_argument("--id",required=True)
    sub.add_parser("test",help="run local unit and synthetic integration tests")
    hunt=sub.add_parser("hunt",help="start a bounded investigation"); hunt.add_argument("--objective",required=True); hunt.add_argument("--offline",action="store_true",help="run the synthetic demonstration without external services"); hunt.add_argument("--retention",choices=("compact","full"))
    resume=sub.add_parser("resume",help="resume a persisted investigation"); resume.add_argument("--id",required=True); resume.add_argument("--offline",action="store_true"); resume.add_argument("--retention",choices=("compact","full"))
    inspect=sub.add_parser("inspect",help="show saved hunt outcome, tool counts, windows, and errors"); inspect.add_argument("--id",required=True)
    demo=sub.add_parser("demo",help="run the synthetic offline demonstration"); demo.add_argument("--retention",choices=("compact","full"))
    compact=sub.add_parser("compact",help="compact an existing completed hunt after verifying its reports"); compact.add_argument("--id",required=True)
    finalize=sub.add_parser("finalize",help="generate final reports and close a partial hunt"); finalize.add_argument("--id",required=True); finalize.add_argument("--retention",choices=("compact","full"))
    args=parser.parse_args(argv); settings=Settings.from_env()
    if getattr(args,"retention",None): settings=replace(settings,retention_policy=args.retention)
    if args.command=="doctor": return doctor(settings)
    if args.command=="model-check": return model_check(settings)
    if args.command=="model-report": return model_report(settings,args.id)
    if args.command=="test":
        import unittest
        suite=unittest.defaultTestLoader.discover(str(Path(__file__).resolve().parent.parent/"tests"))
        result=unittest.TextTestRunner(verbosity=2).run(suite); return 0 if result.wasSuccessful() else 1
    if args.command=="inspect":
        store=Store(settings.data_dir,settings.logs_dir); state=store.load_state(args.id)
        if not state: print(f"Unknown investigation ID: {args.id}"); return 1
        print(f"Investigation {args.id}: {state.get('status')} / {state.get('outcome','not recorded')}")
        print(f"Termination: {state.get('termination_reason','not recorded')}")
        print(f"Summary: {state.get('summary','not recorded')}")
        print(f"Evidence context: host={len(state.get('host',[]))}, network={len(state.get('network',[]))}; persisted unique={store.evidence_count(args.id)}; findings={len(state.get('findings',[]))}")
        print(f"Limits: calls={state.get('tool_calls',0)}/{settings.max_tool_calls}, analyst rounds={state.get('depth',0)}/{settings.max_depth}")
        print(f"Elapsed: {state.get('duration_ms','not recorded')} ms")
        for stage in state.get("stage_history",[]): print(f"STAGE {stage.get('timestamp')} {stage.get('stage')} status={stage.get('status')} details={stage.get('details')}")
        for call in state.get("tool_runs",[]):
            print(f"{call.get('timestamp')} {call.get('reasoning_stage')} {call.get('tool')} status={call.get('result_status')} results={call.get('result_count')} matched_total={call.get('source_total')} window={call.get('time_range')} duration_ms={call.get('duration_ms')} error={call.get('error') or 'none'} reason={call.get('error_reason') or 'none'} artifact={call.get('artifact_id') or 'none'}")
        for error in state.get("source_errors",[]): print(f"SOURCE ERROR {error.get('tool')} stage={error.get('stage')} error={error.get('error')} reason={error.get('reason') or 'none'}")
        retention=state.get("retention",{})
        print(f"Retention: {retention.get('policy','legacy/full')} / {retention.get('status','not finalized')}")
        if retention.get("status")=="completed": print("Per-hunt working audit records were removed after being captured in the technical report.")
        else: print(f"Audit log: {settings.logs_dir / 'tool_audit.jsonl'}")
        return 0
    if args.command in {"compact","finalize"}:
        from .retention import RetentionError, apply_retention, is_retention_finalized, validate_retention_transition
        store=Store(settings.data_dir,settings.logs_dir); state=store.load_state(args.id)
        if not state: print(f"Unknown investigation ID: {args.id}"); return 1
        finalized=is_retention_finalized(state)
        if args.command=="compact" and state.get("status")!="completed" and not finalized:
            print("Only completed hunts can use compact; use finalize for a partial hunt."); return 1
        if args.command=="finalize" and state.get("status") not in {"completed","partial"}:
            print("Only completed or partial hunts can be finalized."); return 1
        target_policy="compact" if args.command=="compact" else settings.retention_policy
        try:
            validate_retention_transition(
                state,target_policy,automatic=False,finalize=args.command=="finalize" or finalized)
        except RetentionError as exc:
            print(f"Retention precondition failed: {exc}"); return 1
        needs_report=(args.command=="finalize" and not finalized) or state.get("retention_policy")!=target_policy
        if needs_report:
            try:
                from .reporting.report import generate_report
                state["finalized_at"]=utc_now()
                state["retention_policy"]=target_policy
                state["report_paths"]=[str(path) for path in generate_report(state,settings.reports_dir)]
                store.save_state(args.id,state)
            except Exception as exc:
                print(f"Final report generation failed: {type(exc).__name__}"); return 1
        try:
            result=apply_retention(store,state,policy=target_policy,
                automatic=False,finalize=args.command=="finalize")
        except RetentionError as exc:
            print(f"Retention precondition failed: {exc}"); return 1
        print(f"Investigation {args.id} retention: {result.get('retention',{}).get('status','unknown')} ({result.get('retention',{}).get('policy','unknown')})")
        return 0 if result.get("retention",{}).get("status") in {"completed","retained"} else 1
    offline=args.command=="demo" or getattr(args,"offline",False)
    store=Store(settings.data_dir,settings.logs_dir); engine=HuntEngine(settings,store,offline=offline)
    if args.command=="hunt": result=engine.run(args.objective)
    elif args.command=="resume": result=engine.resume(args.id)
    else: result=engine.run("Synthetic demonstration: investigate possible SMB lateral movement",)
    print(f"\nInvestigation {result.get('hunt_id')} ended {result.get('status')} / {result.get('outcome')}: {result.get('summary','')}")
    print(f"Termination: {result.get('termination_reason','not recorded')}; external calls={result.get('tool_calls',0)}/{settings.max_tool_calls}; analyst rounds={result.get('depth',0)}/{settings.max_depth}")
    for p in result.get("report_paths",[]): print(f"Report: {p}")
    if result.get("error"): print(f"Limitations: {result['error']}")
    retention=result.get("retention",{}) if isinstance(result.get("retention"),dict) else {}
    if retention.get("status")=="incomplete":
        print(
            "RETENTION WARNING: compact cleanup is incomplete "
            f"({retention.get('error_type','unknown error')}); reports and the investigation conclusion were preserved."
        )
        return 3
    return 0 if result.get("status")=="completed" else 2
