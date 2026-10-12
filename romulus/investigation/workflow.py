"""Bounded, iterative LangGraph hunt with read-only evidence collection and auditable decisions."""
from typing import TypedDict, Any
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import ipaddress
import json
import hashlib
import re
import time
import uuid
from pathlib import Path

from ..config import Settings, safe_url
from ..models import Evidence, Finding, Hypothesis, encode, utc_now
from ..store import Store
from ..intelligence.knowledge import hypotheses_for, TECHNIQUES, ATTACK_RELEASE, ATTACK_RELEASE_DATE, ATTACK_DOMAIN
from ..intelligence.attack_catalog import load_attack_catalog, reference_seeds
from ..intelligence.correlate import correlate
from ..intelligence.investigation_graph import build_investigation_graph, derive_finding_paths
from ..intelligence.analytics import summarize_evidence, build_coverage_ledger
from ..intelligence.behavior_catalog import (
    load_behavior_catalog, load_local_indicators, resolve_semantic_fields, applicable_analytics,
    compile_elasticsearch_seed, compile_elasticsearch_indicator_seed, build_candidate_queue, merge_candidate_queue,
)
from ..tools.elasticsearch_client import ElasticsearchAdapter, validate_query
from ..tools.arkime_client import ArkimeAdapter
from ..tools.tshark_client import TSharkAdapter
from .search_planner import (candidate_fields, validate_spec, fingerprint, compile_es, compile_arkime, compile_tshark,
    compile_native_es, validate_native_arkime, validate_native_tshark, expand_anchor_selectors, anchor_time_range,
    SOURCE_FIELDS, TEXT_FIELDS)
from .scheduler import (initialize_scheduler, register_search_task, select_search_tasks, begin_search_task,
    record_search_outcome, outcome_resolves)
from .synthetic import sample_evidence


def _scheduled_time_bounds(time_range):
    if not isinstance(time_range,dict): return None,None
    start=time_range.get("start",time_range.get("gte")); end=time_range.get("end",time_range.get("lte"))
    if start is None and end is None: return None,None
    if not isinstance(start,str) or not isinstance(end,str): raise ValueError("Scheduled time range requires string start and end bounds")
    def parse(value):
        parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
        if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return parse(start),parse(end)


def _query_enforces_scheduled_window(value,start,end):
    if start is None and end is None: return True
    if not isinstance(value,dict): return False
    ranges=value.get("range")
    if isinstance(ranges,dict):
        for bounds in ranges.values():
            if not isinstance(bounds,dict): continue
            try:
                lower,_=_scheduled_time_bounds({"start":bounds.get("gte"),"end":bounds.get("lte")})
            except (TypeError,ValueError):
                continue
            try: _,upper=_scheduled_time_bounds({"start":bounds.get("gte"),"end":bounds.get("lte")})
            except (TypeError,ValueError):
                continue
            if lower==start and upper==end: return True
    for child in value.values():
        if isinstance(child,dict) and _query_enforces_scheduled_window(child,start,end): return True
        if isinstance(child,list) and any(_query_enforces_scheduled_window(item,start,end) for item in child): return True
    return False


def _scheduled_scope(time_range):
    if isinstance(time_range,dict) and time_range.get("scope"): return str(time_range["scope"])[:300]
    return json.dumps(time_range,sort_keys=True,default=str)[:300]


def _materialize_time_range(time_range):
    """Convert relative Elasticsearch-style bounds into one frozen UTC window."""
    if not isinstance(time_range,dict): return None
    now=datetime.now(timezone.utc)
    def parse(value):
        if value=="now": return now
        match=re.fullmatch(r"now-(\d+)([smhd])",str(value or ""))
        if match:
            seconds=int(match.group(1))*{"s":1,"m":60,"h":3600,"d":86400}[match.group(2)]
            return now-timedelta(seconds=seconds)
        parsed=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    start=parse(time_range.get("gte")); end=parse(time_range.get("lte"))
    return {"gte":start.isoformat(timespec="seconds"),"lte":end.isoformat(timespec="seconds")}


class HuntState(TypedDict, total=False):
    hunt_id: str; objective: str; status: str; outcome: str; termination_reason: str
    mission_mode: str
    hypotheses: list[dict]; host: list[dict]; network: list[dict]; evidence: list[dict]
    findings: list[dict]; correlations: list[dict]; queries: list[dict]; coverage: dict
    started_at: str; started_epoch: float; finished_at: str; error: str; summary: str
    local_model_note: str; report_paths: list[str]; mapping_errors: list[dict]
    depth: int; tool_calls: int; mode: str; tool_runs: list[dict]
    source_errors: list[dict]; es_fields_by_class: dict[str,list[str]]
    lead_catalog: list[dict]; lead_queue: list[str]; completed_leads: list[str]
    search_fingerprints: list[str]
    search_tasks: dict[str,dict]; search_queue: list[str]; search_outcomes: list[dict]; scheduler_history: list[dict]
    reasoning_history: list[dict]; reasoning_complete: bool; stage_history: list[dict]; es_indices: list[str]
    es_fields: list[str]; timestamp_field: str; explicit_time_range: bool
    analytic_summary: dict; search_artifacts: list[dict]; evidence_keys: list[str]
    candidate_leads: list[dict]; behavior_catalog_status: dict
    pivot_results: list[dict]
    investigation_graph: dict
    retention_policy: str


class HuntEngine:
    def __init__(self, settings: Settings, store: Store, offline: bool=False, use_ollama: bool=True):
        self.settings=settings; self.store=store; self.offline=offline; self.use_ollama=use_ollama
        self.es=ElasticsearchAdapter(settings); self.arkime=ArkimeAdapter(settings); self.tshark=TSharkAdapter(settings)
        self._seen_evidence_keys: dict[str,set[str]]={}
        self.behavior_catalog=load_behavior_catalog()
        self.local_indicators=load_local_indicators()

    def run(self, objective: str, hunt_id: str | None=None, _resume: bool=False) -> dict[str, Any]:
        if not objective or len(objective)>2000: raise ValueError("Mission must contain 1 to 2000 characters")
        self.settings.ensure_dirs(); hunt_id=hunt_id or "HUNT-"+uuid.uuid4().hex[:10].upper()
        prior=self.store.load_state(hunt_id) if _resume else None
        if prior:
            state: HuntState=prior; state["status"]="running"; state["started_epoch"]=time.time(); state["resumed_at"]=utc_now(); state["retention_policy"]=self.settings.retention_policy; state.pop("error",None)
        else:
            state={"hunt_id":hunt_id,"objective":objective,"status":"running","outcome":"pending",
            "hypotheses":[],"host":[],"network":[],"evidence":[],"findings":[],"correlations":[],
                "queries":[],"coverage":{},"source_errors":[],"started_at":utc_now(),"started_epoch":time.time(),"depth":0,
                "tool_calls":0,"mode":"offline" if self.offline else "live","tool_runs":[],"lead_catalog":[],
                "lead_queue":[],"completed_leads":[],"reasoning_history":[],"stage_history":[],"reasoning_complete":False,
                "search_fingerprints":[],"es_fields_by_class":{},
                "analytic_summary":{},"search_artifacts":[],"evidence_keys":[],"candidate_leads":[],
                "pivot_results":[],
                "investigation_graph":{"version":1,"nodes":[],"edges":[],"paths":[],"summary":{}},
                "retention_policy":self.settings.retention_policy,
                "behavior_catalog_status":{
                    "catalog_version":self.behavior_catalog.get("catalog_version"),
                    "analytics":len(self.behavior_catalog.get("analytics",[])),
                    "trusted_indicators":len(self.local_indicators.get("indicators",[]))}}
        initialize_scheduler(state)
        self.store.save_state(hunt_id,state)
        checkpoint_conn=None
        try:
            app,checkpoint_conn=self._graph()
            config={"configurable":{"thread_id":hunt_id},"recursion_limit":100}
            snapshot=app.get_state(config) if _resume else None
            if snapshot and snapshot.next: result=app.invoke(None,config=config)
            else: result=app.invoke(state,config=config)
        except Exception as e:
            # LangGraph creates new state mappings between nodes. Recover the
            # latest node checkpoint before recording a workflow failure so a
            # stale scalar snapshot cannot erase call counts, coverage, or the
            # current reasoning depth from the failure report.
            latest_state=self.store.load_state(hunt_id)
            if latest_state: state=latest_state
            state["status"]="partial"; state["outcome"]="incomplete_investigation"
            state["termination_reason"]="workflow_error"; state["error"]=f"Workflow error: {type(e).__name__}: {str(e)[:200]}"
            result=state
            try:
                from ..reporting.report import generate_report
                state["report_paths"]=[str(p) for p in generate_report(state,self.settings.reports_dir)]
            except Exception as report_error: state["error"]+=f"; report generation failed: {type(report_error).__name__}"
        finally:
            if checkpoint_conn is not None: checkpoint_conn.close()
        result["finished_at"]=utc_now(); result["duration_ms"]=round(max(0,time.time()-result.get("started_epoch",time.time()))*1000); self.store.save_state(hunt_id,result)
        try:
            from ..retention import RetentionError, apply_retention
            result=apply_retention(self.store,result,policy=self.settings.retention_policy,automatic=True)
        except RetentionError as exc:
            result["retention"]={"policy":self.settings.retention_policy,"status":"incomplete",
                "updated_at":utc_now(),"error_type":type(exc).__name__}
            self.store.save_state(hunt_id,result)
        if result.get("retention",{}).get("status")!="completed":
            self.store.prune_checkpoints(hunt_id,keep=1,compact=True)
        return result

    def resume(self,hunt_id: str) -> dict[str, Any]:
        state=self.store.load_state(hunt_id)
        if not state: raise ValueError(f"Unknown investigation ID: {hunt_id}")
        from ..retention import is_retention_finalized
        if state.get("status")=="completed" or is_retention_finalized(state): return state
        return self.run(state["objective"],hunt_id=hunt_id,_resume=True)

    def _graph(self):
        from langgraph.graph import StateGraph, END
        import sqlite3
        from langgraph.checkpoint.sqlite import SqliteSaver
        g=StateGraph(HuntState)
        for name,fn in (("plan",self._plan),("collect_host",self._collect_host),("collect_network",self._collect_network),
                        ("discover",self._discover),("analyze",self._analyze),("reason",self._reason),("pivot",self._pivot),("report",self._report)):
            g.add_node(name,fn)
        g.set_entry_point("plan")
        g.add_edge("plan","collect_host"); g.add_edge("collect_host","collect_network"); g.add_edge("collect_network","discover"); g.add_edge("discover","analyze")
        g.add_conditional_edges("analyze",self._after_analyze,{"reason":"reason","pivot":"pivot","report":"report"})
        g.add_conditional_edges("reason",self._after_reason,{"pivot":"pivot","reason":"reason","report":"report"})
        g.add_edge("pivot","analyze"); g.add_edge("report",END)
        connection=sqlite3.connect(self.store.checkpoint_path,check_same_thread=False,timeout=30)
        connection.execute("PRAGMA busy_timeout=30000"); connection.execute("PRAGMA journal_mode=WAL")
        checkpoint=SqliteSaver(connection); checkpoint.setup()
        return g.compile(checkpointer=checkpoint),connection

    def _save(self,s):
        self.store.save_state(s["hunt_id"],s)
        self.store.prune_checkpoints(s["hunt_id"],keep=1)
        return s

    def _stage(self,s,name,status,details=None):
        s.setdefault("stage_history",[]).append({"timestamp":utc_now(),"stage":name,"status":status,"details":details or {}})

    def _record_evidence(self,s,item):
        key=_evidence_key(item)
        stored_keys=s.setdefault("evidence_keys",[])
        seen=self._seen_evidence_keys.setdefault(s["hunt_id"],set(stored_keys))
        if key and key in seen: return None
        if key:
            seen.add(key); stored_keys.append(key)
            identity=f"{s['hunt_id']}:{key}"
            item["evidence_id"]="EV-"+hashlib.sha1(identity.encode("utf-8",errors="replace")).hexdigest()[:12].upper()
        self.store.add_evidence(s["hunt_id"],item)
        compact={"evidence_id":item["evidence_id"],"source":item["source"],
            "observed_at":item["observed_at"],"observation":item.get("observation",""),
            "asset":item.get("asset",""),"provenance":item.get("provenance",{}),"raw":_context_raw(item.get("raw",{}))}
        provenance=item.get("provenance",{}) if isinstance(item.get("provenance"),dict) else {}
        phase="pivot" if provenance.get("lead_id") else "baseline"
        bucket=f"{item.get('source','unknown')}:{phase}"
        retention=s.setdefault("coverage",{}).setdefault("evidence_retention",{})
        record=retention.setdefault(bucket,{"persisted":0,"retained_in_context":0,
            "context_limit":self.settings.context_evidence_per_source})
        record["persisted"]+=1
        if record["retained_in_context"]>=self.settings.context_evidence_per_source: return None
        record["retained_in_context"]+=1
        return compact

    def _add_tshark_row(self,s,row,provenance,query,lead_id=None):
        observed=_as_iso(row.get("frame.time_epoch")) if row.get("frame.time_epoch") else ""
        item=encode(Evidence.create("tshark",_event_description(row),observed_at=observed,
            query=query,provenance={**provenance,**({"lead_id":lead_id} if lead_id else {})},raw=_bounded(row)))
        compact=self._record_evidence(s,item)
        if compact:
            s.setdefault("network",[]).append(compact)
            return True
        return False

    def _time_scope(self,s):
        explicit=_explicit_dates(s["objective"])
        if explicit: return _time_filter(s["objective"],self.settings.es_default_hours,self.settings.mission_timezone), _date_scope(explicit,self.settings.mission_timezone)
        if self.settings.historical_search: return None,"all retained indexed time"
        return _time_filter(s["objective"],self.settings.es_default_hours),f"last {self.settings.es_default_hours} hours"

    def _budget_ok(self,s):
        if s.get("tool_calls",0)>=self.settings.max_tool_calls:
            s["termination_reason"]="tool_call_budget"; return False
        if time.time()-s.get("started_epoch",time.time())>=self.settings.max_runtime_seconds:
            s["termination_reason"]="runtime_budget"; return False
        return True

    def _call(self,s,tool,stage,parameters,time_range,fn,count):
        """Run one external call; every attempt gets a bounded, credential-free audit entry."""
        if not self._budget_ok(s): return None
        started=time.monotonic(); s["tool_calls"]=s.get("tool_calls",0)+1
        try:
            result=fn(); result_status="ok"; error=None
            result_count=count(result) if result is not None else 0
            source_total=(result.get("total",result.get("matched_count")) if isinstance(result,dict) else None)
            if isinstance(source_total,dict): source_total=source_total.get("value")
        except Exception as exc:
            result=None; result_status="error"; error=type(exc).__name__; result_count=0
            error_reason=_safe_error_reason(exc)
            source_total=None
            status_code=getattr(getattr(exc,"meta",None),"status",None) or getattr(exc,"status_code",None)
            s.setdefault("source_errors",[]).append({"tool":tool,"stage":stage,"error":error,"reason":error_reason,"status_code":status_code})
        else: status_code=None; error_reason=None
        record={"timestamp":utc_now(),"hunt_id":s["hunt_id"],"tool":tool,"reasoning_stage":stage,
            "parameters":parameters,"time_range":time_range,"result_count":result_count,"source_total":source_total,
            "duration_ms":round((time.monotonic()-started)*1000),"result_status":result_status,"error":error,"error_reason":error_reason,"status_code":status_code}
        if tool!="ollama.api.chat" and any(token in stage for token in ("search","pivot")):
            signature=json.dumps({"tool":tool,"stage":stage,"parameters":parameters,"time_range":time_range},sort_keys=True,default=str)
            artifact_id="SR-"+hashlib.sha1(signature.encode("utf-8",errors="replace")).hexdigest()[:12].upper()
            artifact={"artifact_id":artifact_id,"tool":tool,"stage":stage,"scope":time_range,"result_status":result_status,
                "returned":result_count,"matched_total":source_total,"error":error,"error_reason":error_reason,
                "adequate_negative":bool(result_status=="ok" and result_count==0 and not error and source_total==0),
                "timestamp":record["timestamp"]}
            if not any(x.get("artifact_id")==artifact_id for x in s.setdefault("search_artifacts",[])): s["search_artifacts"].append(artifact)
            record["artifact_id"]=artifact_id
        s.setdefault("tool_runs",[]).append(record); self.store.audit(record)
        reason=f" error={error_reason}" if error_reason else ""
        print(f"[ROMULUS] {stage}: {tool} status={result_status} results={result_count} matched_total={source_total}{reason} window={time_range}")
        return result

    def _plan(self,s):
        _validate_explicit_date_order(s["objective"],self.settings.mission_timezone)
        s["explicit_time_range"]=bool(_explicit_dates(s["objective"]))
        curated_seeds={tid:{"technique_id":tid,"name":v["name"],"tactic":v["tactic"],"tactics":v.get("tactics",[v["tactic"]]),"url":v["url"],
                "expected_host":v["host"],"expected_network":v["network"],"benign_explanations":v["benign"],
                "detection_strategies":v.get("detection_strategies",[]),"data_components":v.get("data_components",[]),
                "analytic_goal":v.get("analytic_goal"),"mutable_elements":v.get("mutable_elements",[])}
               for tid,v in TECHNIQUES.items()}
        seeds=[]
        for reference in reference_seeds(s["objective"],36):
            tid=reference.get("technique_id")
            seeds.append({**reference,**curated_seeds.get(tid,{})})
        if not seeds: seeds=list(curated_seeds.values())
        attack_catalog_metadata=load_attack_catalog().get("metadata",{})
        s["mission_mode"]="directed" if _mission_is_directed(s["objective"]) else "undirected"
        if self.offline:
            host,network=sample_evidence(); s["host"]=[encode(host[0])]; s["network"]=[encode(x) for x in network]
            for item in s["host"]+s["network"]: self._record_evidence(s,item)
            if s["mission_mode"]=="directed":
                offline_hypotheses=[encode(h) for h in hypotheses_for(s["objective"])]
                smb_fixture=[h for h in offline_hypotheses if h.get("technique_id")=="T1021.002"]
                s["hypotheses"]=(smb_fixture or offline_hypotheses)[:1]
                for hypothesis in s["hypotheses"]:
                    hypothesis["basis"]="operator_direction"
                    hypothesis["basis_details"]="Offline validation hypothesis is constrained by the operator's explicit direction."
            else:
                s["hypotheses"]=[]
            s["coverage"]={"host":"synthetic fixture searched","network":"synthetic fixture searched","time_scope":"synthetic fixture timestamps",
                "attack_knowledge":{"domain":ATTACK_DOMAIN,"release":ATTACK_RELEASE,"release_date":ATTACK_RELEASE_DATE,
                    "official_catalog_techniques":attack_catalog_metadata.get("technique_count",0)}}
            offline_leads=_lead_catalog(s["hypotheses"])
            s["lead_catalog"]=[next((lead for lead in offline_leads if lead.get("source")=="host"),offline_leads[0])] if offline_leads else []
            s["reasoning_complete"]=False
            self._stage(s,"plan","completed",{"hypotheses":len(s["hypotheses"]),"mode":"offline"})
            print(f"[ROMULUS] {s['hunt_id']} offline planning {len(s['hypotheses'])} hypotheses")
            return self._save(s)
        common_coverage={"host":"pending","network":"pending","hypotheses_total":0,
            "attack_knowledge":{"domain":ATTACK_DOMAIN,"release":ATTACK_RELEASE,"release_date":ATTACK_RELEASE_DATE,
                "model":"Technique -> Detection Strategy -> platform Analytic -> Data Component -> Mutable Element",
                "official_catalog_techniques":attack_catalog_metadata.get("technique_count",0),
                "official_catalog_sha256":attack_catalog_metadata.get("source_sha256")},
            "time_scope":self._time_scope(s)[1],"historical_search_enabled":self.settings.historical_search}
        if s["mission_mode"]=="undirected":
            s["hypotheses"]=[]; s["lead_catalog"]=[]; s["coverage"]=common_coverage
            s["reasoning_history"].append({"stage":"mission_discovery_plan","basis":"deterministic_telemetry_discovery",
                "hypotheses":[],"guardrail":"Hypotheses require an observed deterministic candidate or operator direction."})
            self._stage(s,"plan","completed",{"hypotheses":0,"candidate_leads":0,
                "basis":"deterministic_telemetry_discovery","time_scope":s["coverage"]["time_scope"]})
            print(f"[ROMULUS] {s['hunt_id']} undirected planning: deterministic telemetry discovery before hypotheses; scope={s['coverage']['time_scope']}")
            return self._save(s)
        planned=[]; planning_basis="local ATT&CK seeds constrained by operator direction"
        if self.use_ollama and self._budget_ok(s):
            try:
                from ..agent.ollama import Ollama
                planned=self._call(s,"ollama.api.chat","hypothesis_generation",{"model":self.settings.ollama_model,"reference_seed_count":len(seeds)},
                    "mission text; no telemetry",lambda:Ollama(self.settings).plan_hypotheses(s["objective"],seeds,12),len) or []
                if planned: planning_basis="local model generated hypotheses constrained by operator direction and ATT&CK seeds"
            except Exception: planned=[]
        normalized=_normalize_hypotheses(planned) if planned else []
        s["hypotheses"]=normalized if len(normalized)>=4 else [encode(h) for h in hypotheses_for(s["objective"])][:20]
        for hypothesis in s["hypotheses"]:
            hypothesis["basis"]="operator_direction"
            hypothesis["basis_details"]="Initial hypothesis is allowed because the operator supplied a specific behavior, technique, entity, or indicator."
        s["coverage"]={**common_coverage,"hypotheses_total":len(s["hypotheses"])}
        s["lead_catalog"]=_lead_catalog(s["hypotheses"])
        s["reasoning_history"].append({"stage":"mission_hypothesis_plan","basis":"operator_direction","planning_method":planning_basis,
            "hypotheses":[{"id":h.get("hypothesis_id"),"title":h.get("title"),"technique_id":h.get("technique_id")} for h in s["hypotheses"]]})
        self._stage(s,"plan","completed",{"hypotheses":len(s["hypotheses"]),"candidate_leads":len(s["lead_catalog"]),
            "basis":"operator_direction","time_scope":s["coverage"]["time_scope"]})
        print(f"[ROMULUS] {s['hunt_id']} directed planning {len(s['hypotheses'])} hypotheses; basis=operator_direction; scope={s['coverage']['time_scope']}")
        return self._save(s)

    def _collect_host(self,s):
        """Inventory Elasticsearch and mappings; evidence searches run in discover."""
        if self.offline:
            s.setdefault("coverage",{})["host_count"]=len(s.get("host",[]))
            return self._save(s)
        if not self._budget_ok(s):
            s.setdefault("coverage",{})["host"]="not inventoried: budget exhausted"
            self._stage(s,"host_inventory","incomplete",{"reason":s.get("termination_reason")})
            return self._save(s)
        indices=self._call(s,"elasticsearch.indices.get","host_discovery",
            {"patterns":list(self.settings.es_index_patterns)},"configured allowlist",self.es.indices,len)
        if indices is None:
            s.setdefault("coverage",{})["host"]="telemetry retrieval failed during index discovery"
            s.setdefault("source_health",{})["host"]=False
            self._stage(s,"host_inventory","failed")
            return self._save(s)
        names=[row["index"] for row in indices if row.get("index")]
        s["es_indices"]=names; s.setdefault("coverage",{})["es_indices"]=names
        if not names:
            s["coverage"]["host"]="no configured Elasticsearch indices matched"
            s.setdefault("source_health",{})["host"]=False
            self._stage(s,"host_inventory","unavailable",{"matched_indices":0})
            return self._save(s)
        mappings=self._call(s,"elasticsearch.indices.get_mapping","host_schema",{"indices":names},
            "configured indices",lambda:self.es.mappings_many(names),lambda value:len(value))
        if mappings is None:
            s["coverage"]["host"]="indices discovered; mapping retrieval failed"
            s["es_fields"]=[]; s["es_fields_by_class"]={}; s.setdefault("source_health",{})["host"]=False
            self._stage(s,"host_inventory","failed",{"matched_indices":len(names)})
            return self._save(s)
        s["es_fields"]=_field_names(mappings); s["es_fields_by_class"]=_field_names_by_class(mappings)
        fields=s.get("es_fields",[]); host_fields=s.get("es_fields_by_class",{}).get("host") or fields
        timestamp=next((field for field in ("@timestamp","timestamp","event.created","event.ingested","event.start","winlog.time_created")
            if field in host_fields),None)
        ready=bool(fields and (not self._time_scope(s)[0] or timestamp))
        s.setdefault("source_health",{})["host"]=ready
        if ready:
            s["timestamp_field"]=timestamp or "@timestamp"
            s["coverage"]["host"]="configured Elasticsearch inventory ready; deterministic discovery pending"
        else:
            s["coverage"]["host"]="not searched: no usable mapped fields or timestamp field to enforce the configured time window"
        self._stage(s,"host_inventory","completed" if ready else "incomplete",
            {"matched_indices":len(names),"mapped_fields":len(fields),"timestamp_field_available":bool(timestamp)})
        return self._save(s)

    def _add_es_hit(self,s,hit,query,lead_id=None):
        index=str(hit.get("_index", "")); document_id=hit.get("_id")
        category=str(_nested(hit,"event.category") or hit.get("event.category") or "").lower()
        module=str(_nested(hit,"event.module") or _nested(hit,"event.dataset") or hit.get("event.module") or "").lower()
        if "host" in index.lower(): key="host"
        elif "network" in index.lower() or any(x in module for x in ("zeek","suricata","netflow","packetbeat","panw","network")) or "network" in category:
            key="network"
        else: key="host"
        observed_value=_nested(hit,"@timestamp") or _nested(hit,"timestamp") or _nested(hit,"event.created") or _nested(hit,"event.ingested") or _nested(hit,"event.start")
        observed=_as_iso(observed_value) if observed_value is not None else ""
        host=_nested(hit,"host.name") or hit.get("host.name","")
        raw=_bounded(hit)
        for field in ("source.ip","destination.ip","source.port","destination.port","host.name","host.ip","event.code","winlog.event_id","process.name"):
            value=_nested(hit,field)
            if value is None: value=hit.get(field)
            if value is not None: raw[field]=value
        item=encode(Evidence.create("elasticsearch",_event_description(hit),asset=str(host),observed_at=observed,query=json.dumps(query,sort_keys=True),
            provenance={"index":index,"document_id":hit.get("_id"),"lead_id":lead_id},raw=raw))
        compact=self._record_evidence(s,item)
        if compact: s.setdefault(key,[]).append(compact)

    def _add_arkime_rows(self,s,rows,expression,scope,lead_id=None):
        known={str(e.get("provenance",{}).get("session_id")) for e in s.get("network",[])
               if e.get("source")=="arkime" and e.get("provenance",{}).get("session_id")}
        added=0
        for row in rows:
            session_id=row.get("id")
            if session_id and str(session_id) in known: continue
            item=encode(Evidence.create("arkime",_event_description(row),
                asset=str(row.get("destination.ip",row.get("dstIp",""))),
                observed_at=_as_iso(row.get("firstPacket")) if row.get("firstPacket") is not None else "",query=expression,
                provenance={"session_id":session_id,"lead_id":lead_id,"time_range":scope},raw=_bounded(row)))
            compact=self._record_evidence(s,item)
            if compact: s["network"].append(compact); added+=1
            if session_id: known.add(str(session_id))
        return added

    def _register_discovery_tasks(self,s):
        """Register bounded deterministic telemetry searches without executing them."""
        initialize_scheduler(s)
        registered=[]
        mission_range,scope=self._time_scope(s)
        mission_range=_materialize_time_range(mission_range)
        task_range={"scope":scope}
        if mission_range:
            task_range.update({"start":mission_range.get("gte"),"end":mission_range.get("lte")})
        names=list(s.get("es_indices",[])); fields=list(s.get("es_fields",[]))
        host_fields=s.get("es_fields_by_class",{}).get("host") or fields
        timestamp=s.get("timestamp_field") or next((field for field in
            ("@timestamp","timestamp","event.created","event.ingested","event.start","winlog.time_created")
            if field in host_fields),None)
        host_ready=bool(names and host_fields and (not mission_range or timestamp))
        s.setdefault("source_health",{})["host"]=host_ready
        behavior_seeds=[]; indicator_seeds=[]; behavior_unsupported=[]; indicator_unsupported=[]
        if host_ready:
            indicator_limit=min(12,max(1,self.settings.max_tool_calls//10))
            indicator_seeds,indicator_unsupported=_indicator_seed_queries(
                self.local_indicators,host_fields,timestamp or "@timestamp",mission_range,indicator_limit)
            behavior_limit=min(32,max(1,self.settings.max_tool_calls//5))
            behavior_seeds,behavior_unsupported=_behavior_seed_queries(
                self.behavior_catalog,host_fields,timestamp or "@timestamp",mission_range,behavior_limit)
            seed_size=min(25,self.settings.max_results)
            for origin,seeds,id_field in (("trusted_indicator",indicator_seeds,"indicator_id"),
                                          ("behavior_catalog",behavior_seeds,"analytic_id")):
                for seed in seeds:
                    task_id,_=register_search_task(s,{"source":"elasticsearch","source_family":"host",
                        "source_targets":names,"phase":"discovery","origin":origin,
                        "intent":f"Deterministic {origin.replace('_',' ')} discovery: {seed.get(id_field)}",
                        "query_spec":{"query":seed["query"],"size":seed_size},"time_range":task_range,
                        "candidate_ids":[],"follow_up_ids":[],"hypothesis_ids":[],"anchor_evidence_ids":[]})
                    if task_id not in registered: registered.append(task_id)
            surveys=_host_survey_queries(s.get("hypotheses",[]),host_fields,timestamp or "@timestamp",mission_range,
                s.get("objective",""),10)
            survey_names=[name for name in names if "host" in name.lower()] or names
            for survey in surveys:
                task_id,_=register_search_task(s,{"source":"elasticsearch","source_family":"host",
                    "source_targets":survey_names,"phase":"discovery","origin":"directed_survey",
                    "intent":survey.get("intent") or survey.get("why") or "Operator-directed host survey",
                    "query_spec":{"query":survey["query"],"size":min(500,self.settings.max_results)},
                    "time_range":task_range,"candidate_ids":[survey["candidate_id"]] if survey.get("candidate_id") else [],
                    "follow_up_ids":[survey["follow_up_id"]] if survey.get("follow_up_id") else [],
                    "hypothesis_ids":[survey["hypothesis_id"]] if survey.get("hypothesis_id") else [],
                    "anchor_evidence_ids":list(survey.get("anchor_evidence_ids",[]))})
                if task_id not in registered: registered.append(task_id)
            indicator_terms=_indicator_terms(s.get("objective",""))
            if indicator_terms:
                text_fields=[field for field in ("message","event.original","winlog.event_data.CommandLine",
                    "process.name","process.command_line") if field in host_fields] or ["message"]
                for term in indicator_terms:
                    query=_indicator_query([term],text_fields,timestamp or "@timestamp",mission_range)
                    task_id,_=register_search_task(s,{"source":"elasticsearch","source_family":"host",
                        "source_targets":names,"phase":"discovery","origin":"directed_survey",
                        "intent":f"Search operator-supplied indicator {term[:80]}",
                        "query_spec":{"query":query,"size":min(self.settings.max_results,50)},"time_range":task_range,
                        "candidate_ids":[],"follow_up_ids":[],"hypothesis_ids":[],"anchor_evidence_ids":[]})
                    if task_id not in registered: registered.append(task_id)
        bindings=resolve_semantic_fields(host_fields) if host_fields else {}
        s["behavior_catalog_status"]={"catalog_version":self.behavior_catalog.get("catalog_version"),
            "analytics":len(self.behavior_catalog.get("analytics",[])),
            "trusted_indicators":len(self.local_indicators.get("indicators",[])),
            "behavior_searches_planned":len(behavior_seeds),"indicator_searches_planned":len(indicator_seeds),
            "searches_executed":0,"returned":0,"failures":0,"unsupported_analytics":behavior_unsupported,
            "unsupported_indicators":indicator_unsupported,"semantic_bindings":bindings}
        s.setdefault("coverage",{})["behavior_catalog"]=s["behavior_catalog_status"]

        network_fields=s.get("es_fields_by_class",{}).get("network",[])
        network_indices=[name for name in s.get("es_indices",[]) if "network" in name.lower()]
        es_network_ready=bool(network_fields and network_indices)
        network_configured=es_network_ready
        network_sources=s.setdefault("coverage",{}).setdefault("network_sources",{})
        network_sources["elasticsearch"]=("configured network indices available for bounded investigation pivots"
            if es_network_ready else "no mapped network index available")
        if self.settings.arkime_username and self.settings.arkime_password:
            network_configured=True; network_sources["arkime"]="configured; deterministic discovery queued"
            expressions=[_arkime_expression(s.get("objective",""),s.get("hypotheses",[]))]
            expressions.extend(_arkime_indicator_expressions(_indicator_terms(s.get("objective",""))))
            for expression in expressions:
                task_id,_=register_search_task(s,{"source":"arkime","source_family":"network",
                    "source_targets":[safe_url(self.settings.arkime_url)],"phase":"discovery","origin":"coverage_frontier",
                    "intent":"Deterministic Arkime session discovery","query_spec":{"expression":expression,
                        "cap":self.settings.arkime_max_results},"time_range":task_range,
                    "candidate_ids":[],"follow_up_ids":[],"hypothesis_ids":[],"anchor_evidence_ids":[]})
                if task_id not in registered: registered.append(task_id)
        else: network_sources["arkime"]="not configured"
        if self.settings.pcap_files:
            network_configured=True; network_sources["tshark"]="configured; deterministic discovery queued"
            display_filter=_pcap_filter(s.get("hypotheses",[]))
            packet_fields=["frame.number","frame.time_epoch","ip.src","ip.dst","ipv6.src","ipv6.dst",
                "tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","dns.qry.name","http.host",
                "tls.handshake.extensions_server_name","smb2.cmd"]
            for pcap in self.settings.pcap_files:
                task_id,_=register_search_task(s,{"source":"tshark","source_family":"network",
                    "source_targets":[str(pcap)],"phase":"discovery","origin":"coverage_frontier",
                    "intent":"Deterministic configured-capture discovery","query_spec":{"display_filter":display_filter,
                        "fields":packet_fields,"limit":min(500,self.settings.max_results)},"time_range":task_range,
                    "candidate_ids":[],"follow_up_ids":[],"hypothesis_ids":[],"anchor_evidence_ids":[]})
                if task_id not in registered: registered.append(task_id)
        else: network_sources["tshark"]="no PCAP files configured"
        s.setdefault("source_health",{})["network"]=network_configured
        return registered

    def _drain_scheduled_tasks(self,s,*,phase,limit=None):
        """Execute selected tasks in scheduler order and checkpoint every outcome."""
        initialize_scheduler(s)
        queued=[task_id for task_id in s.get("search_queue",[]) if task_id in s.get("search_tasks",{})
            and s["search_tasks"][task_id].get("phase")==phase
            and s["search_tasks"][task_id].get("status") in {"queued","interrupted"}]
        remaining_calls=max(0,self.settings.max_tool_calls-int(s.get("tool_calls",0)))
        selection_limit=min(len(queued),remaining_calls)
        if limit is not None: selection_limit=min(selection_limit,max(0,int(limit)))
        selected=select_search_tasks(s,phase=phase,limit=selection_limit) if selection_limit else []
        if not selected and queued and remaining_calls<=0:
            families=sorted({s["search_tasks"][task_id].get("source_family") for task_id in queued})
            s.setdefault("scheduler_history",[]).append({"event":f"{phase}_budget_gap","phase":phase,
                "limit":0,"unserved_families":families})
        for selected_task in selected:
            task=begin_search_task(s,selected_task["task_id"])
            self._save(s)
            outcome=self._execute_search_task(s,task)
            record_search_outcome(s,task["task_id"],outcome)
            self._save(s)
            if outcome.get("status")=="budget_limited": break
        pending=[task_id for task_id in s.get("search_queue",[]) if task_id in s.get("search_tasks",{})
            and s["search_tasks"][task_id].get("phase")==phase
            and s["search_tasks"][task_id].get("status") in {"queued","interrupted"}]
        budget_limited=bool(pending and (limit is None) and
            (s.get("termination_reason") in {"tool_call_budget","runtime_budget"} or
             int(s.get("tool_calls",0))>=self.settings.max_tool_calls))
        if budget_limited:
            s["status"]="partial"
            s.setdefault("termination_reason","tool_call_budget")
            s.setdefault("coverage",{}).setdefault("scheduler_gaps",[]).append({"phase":phase,
                "reason":str(s.get("termination_reason") or "tool_call_budget"),"queued_task_ids":pending[:100]})
        return s

    def _discover(self,s):
        if self.offline:
            s.setdefault("coverage",{})["host_count"]=len(s.get("host",[]))
            s["coverage"]["network_count"]=len(s.get("network",[]))
            return self._save(s)
        self._register_discovery_tasks(s)
        self._drain_scheduled_tasks(s,phase="discovery")
        self._register_directed_initial_tasks(s)
        outcomes=[item for item in s.get("search_outcomes",[]) if item.get("phase")=="discovery"]
        host=[item for item in outcomes if item.get("source_family")=="host"]
        network=[item for item in outcomes if item.get("source_family")=="network"]
        def coverage_text(items,label):
            if not items: return f"not searched: no executable {label} discovery tasks"
            partial=sum(item.get("status")!="completed" for item in items)
            returned=sum(int(item.get("returned_total") or 0) for item in items)
            text=f"executed {len(items)} scheduled {label} discovery task(s); returned {returned} records"
            return ("partial: "+text+f"; {partial} task(s) incomplete" if partial else text)
        s.setdefault("coverage",{})["host"]=coverage_text(host,"host")
        if not s.get("source_health",{}).get("network"):
            s["coverage"]["network"]="not configured: Arkime and PCAP sources unavailable"
        else: s["coverage"]["network"]=coverage_text(network,"network")
        s["coverage"]["host_count"]=len(s.get("host",[])); s["coverage"]["network_count"]=len(s.get("network",[]))
        behavior_outcomes=[item for item in outcomes if s.get("search_tasks",{}).get(item.get("task_id"),{}).get("origin")
            in {"behavior_catalog","trusted_indicator"}]
        if s.get("behavior_catalog_status") is not None:
            s["behavior_catalog_status"]["searches_executed"]=len(behavior_outcomes)
            s["behavior_catalog_status"]["returned"]=sum(int(item.get("returned_total") or 0) for item in behavior_outcomes)
            s["behavior_catalog_status"]["failures"]=sum(item.get("status") not in {"completed","partial"} for item in behavior_outcomes)
            s["coverage"]["behavior_catalog"]=s["behavior_catalog_status"]
        self._stage(s,"discovery","partial" if any(item.get("status")!="completed" for item in outcomes) else "completed",
            {"tasks":len(outcomes),"host_tasks":len(host),"network_tasks":len(network)})
        return self._save(s)

    def _collect_network(self,s):
        """Inventory configured network sources and register all discovery work."""
        if self.offline:
            s.setdefault("coverage",{})["network_count"]=len(s.get("network",[]))
            return self._save(s)
        network_sources=s.setdefault("coverage",{}).setdefault("network_sources",{})
        arkime_ready=bool(self.settings.arkime_username and self.settings.arkime_password)
        tshark_ready=bool(self.settings.pcap_files)
        es_network_ready=bool(s.get("es_fields_by_class",{}).get("network") and
            any("network" in name.lower() for name in s.get("es_indices",[])))
        network_sources["elasticsearch"]=("configured network indices available for bounded investigation pivots"
            if es_network_ready else "no mapped network index available")
        network_sources["arkime"]="configured; deterministic discovery pending" if arkime_ready else "not configured"
        network_sources["tshark"]="configured; deterministic discovery pending" if tshark_ready else "no PCAP files configured"
        s.setdefault("source_health",{})["network"]=es_network_ready or arkime_ready or tshark_ready
        self._register_discovery_tasks(s)
        if es_network_ready or arkime_ready or tshark_ready:
            s["coverage"]["network"]="configured network inventory ready; deterministic discovery pending"
            status="completed"
        else:
            s["coverage"]["network"]="not configured: Arkime and PCAP sources unavailable"
            status="unavailable"
        self._stage(s,"network_inventory",status,{"arkime_configured":arkime_ready,
            "pcap_captures":len(self.settings.pcap_files),"registered_tasks":len(s.get("search_tasks",{}))})
        return self._save(s)

    def _ensure_initial_plan(self,s):
        """Expose validated source fields without creating a parallel execution queue."""
        source_fields={}
        if s.get("es_indices") and s.get("es_fields"):
            source_fields["elasticsearch"]=candidate_fields("elasticsearch",s["es_fields"])
        if self.settings.arkime_username and self.settings.arkime_password:
            source_fields["arkime"]=candidate_fields("arkime",list(SOURCE_FIELDS["arkime"]))
        if self.settings.pcap_files:
            source_fields["tshark"]=candidate_fields("tshark",list(SOURCE_FIELDS["tshark"]))
        coverage=s.setdefault("coverage",{})
        coverage["search_fields"]=source_fields
        field_classes=s.get("es_fields_by_class",{})
        coverage["search_field_classes"]={key:candidate_fields("elasticsearch",value)
            for key,value in field_classes.items() if value}
        if _state_mission_mode(s)=="undirected" and not s.get("candidate_leads"):
            coverage["model_initial_search_plan"]="deferred: undirected mission has no telemetry-backed candidate"
        elif not source_fields:
            coverage["model_initial_search_plan"]="not generated: no mapped source"
        else:
            coverage["model_initial_search_plan"]="deferred to unified investigation scheduler"
        return source_fields

    def _effective_task_window(self,s,plan):
        """Freeze the mission/anchor window used by one executable task."""
        mission_range,mission_scope=self._time_scope(s)
        mission_range=_materialize_time_range(mission_range)
        effective_range,anchor_scope=anchor_time_range(plan,_all_evidence(s),mission_range)
        task_range={"scope":anchor_scope or mission_scope}
        if effective_range:
            task_range.update({"start":effective_range.get("gte"),"end":effective_range.get("lte")})
        return effective_range,task_range

    def _task_owners(self,s,plan):
        candidate_id=plan.get("candidate_id")
        follow_up_id=plan.get("follow_up_id")
        candidate=next((item for item in s.get("candidate_leads",[])
            if item.get("candidate_id")==candidate_id),None)
        if not candidate:
            candidate_id=None; follow_up_id=None
        elif follow_up_id and not any(item.get("follow_up_id")==follow_up_id
                for item in candidate.get("follow_ups",[])):
            follow_up_id=None
        hypothesis_id=plan.get("hypothesis_id")
        hypothesis_ids={item.get("hypothesis_id") for item in s.get("hypotheses",[])}
        return {
            "candidate_ids":[candidate_id] if candidate_id else [],
            "follow_up_ids":[follow_up_id] if follow_up_id else [],
            "hypothesis_ids":[hypothesis_id] if hypothesis_id in hypothesis_ids else [],
            "anchor_evidence_ids":list(dict.fromkeys(plan.get("anchor_evidence_ids",[]) or []))[:8],
            "candidate_priority":candidate.get("priority_tier") if candidate else None,
            "trusted_indicator_match":bool(candidate and candidate.get("kind")=="trusted_indicator"),
        }

    def _compile_investigation_proposals(self,s,plan,origin):
        """Compile one grounded lead/spec into exact source scheduler proposals."""
        owners=self._task_owners(s,plan)
        intent=str(plan.get("intent") or plan.get("why") or "Bounded investigation search")[:500]
        if self.offline:
            return [{"source":"elasticsearch","source_family":"host",
                "source_targets":["offline-synthetic"],"phase":"investigation","origin":origin,
                "intent":intent,"query_spec":{"query":{"bool":{"must":[{"exists":{"field":"message"}}]}},"size":1},
                "time_range":{"scope":"synthetic fixture timestamps"},**owners}]

        effective_range,task_range=self._effective_task_window(s,plan)
        source=plan.get("source")
        proposals=[]
        if source in {"host","elasticsearch"}:
            all_names=list(s.get("es_indices",[])); by_class=s.get("es_fields_by_class",{})
            requested_group=plan.get("index_class","host" if source=="host" else "all")
            group=requested_group
            plan_fields=set(plan.get("fields",[]))
            host_score=len(plan_fields & set(by_class.get("host",[])))
            network_score=len(plan_fields & set(by_class.get("network",[])))
            if source=="elasticsearch":
                if group=="all" and max(host_score,network_score)>0 and host_score!=network_score:
                    group="host" if host_score>network_score else "network"
                elif group in {"host","network"}:
                    own_score=host_score if group=="host" else network_score
                    other_score=network_score if group=="host" else host_score
                    if other_score>own_score: group="network" if group=="host" else "host"
            else: group="host"
            names=all_names if group=="all" else [name for name in all_names if group in name.lower()]
            if not names and group=="host": names=[name for name in all_names if "network" not in name.lower()] or all_names
            if not names: raise ValueError(f"No configured Elasticsearch index matched index_class={group}")
            actual_fields=(by_class.get(group) if group in {"host","network"} else s.get("es_fields",[])) or s.get("es_fields",[])
            timestamp=next((field for field in ("@timestamp","timestamp","event.created","event.ingested","event.start","winlog.time_created")
                if field in actual_fields),None)
            if effective_range and not timestamp: raise ValueError("No mapped timestamp field is available to enforce the search window")
            if source=="host":
                query=_lead_host_query(plan,actual_fields,timestamp or s.get("timestamp_field","@timestamp"),effective_range,{})
            else:
                scoped={**plan,"index_class":group,"fields":[field for field in plan.get("fields",[]) if field in actual_fields]}
                if scoped.get("terms") and not scoped["fields"]:
                    scoped["fields"]=[field for field in TEXT_FIELDS if field in actual_fields][:4]
                query=None
                if plan.get("native_query_language")=="elasticsearch_dsl" and plan.get("native_query"):
                    query=compile_native_es(plan["native_query"],actual_fields,timestamp or s.get("timestamp_field","@timestamp"),effective_range)
                if query is None: query=compile_es(scoped,actual_fields,timestamp or s.get("timestamp_field","@timestamp"),effective_range)
            if query is None: raise ValueError("Investigation lead has no mapped Elasticsearch selectors")
            proposals.append({"source":"elasticsearch","source_family":"network" if group=="network" else "host",
                "source_targets":names,"phase":"investigation","origin":origin,"intent":intent,
                "query_spec":{"query":query,"size":min(500,self.settings.max_results)},
                "time_range":task_range,**owners})
            return proposals

        if source not in {"network","arkime","tshark"}: raise ValueError("Unsupported investigation source")
        if source in {"network","arkime"} and self.settings.arkime_username and self.settings.arkime_password:
            expression=None
            if source=="arkime" and plan.get("native_query_language")=="arkime" and plan.get("native_query"):
                expression=validate_native_arkime(plan["native_query"],list(SOURCE_FIELDS["arkime"]))
            if expression is None: expression=compile_arkime(plan) if source=="arkime" else _lead_network_expression(plan)
            expression=validate_native_arkime(expression,list(SOURCE_FIELDS["arkime"]))
            proposals.append({"source":"arkime","source_family":"network",
                "source_targets":[safe_url(self.settings.arkime_url)],"phase":"investigation","origin":origin,
                "intent":intent,"query_spec":{"expression":expression,"cap":self.settings.arkime_max_results},
                "time_range":task_range,**owners})
        if source in {"network","tshark"} and self.settings.pcap_files:
            display_filter=None; packet_fields=[]
            if source=="tshark" and plan.get("native_query_language")=="tshark" and plan.get("native_query"):
                display_filter=validate_native_tshark(plan["native_query"],list(SOURCE_FIELDS["tshark"]))
                packet_fields=list(dict.fromkeys(["frame.number","frame.time_epoch","ip.src","ip.dst","ipv6.src","ipv6.dst",
                    "tcp.srcport","tcp.dstport","udp.srcport","udp.dstport",
                    *[field for field in plan.get("fields",[]) if field in SOURCE_FIELDS["tshark"]]]))[:16]
            elif source=="tshark": display_filter,packet_fields=compile_tshark(plan)
            else:
                display_filter=_lead_pcap_filter(plan)
                packet_fields=["frame.number","frame.time_epoch","ip.src","ip.dst","ipv6.src","ipv6.dst",
                    "tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","dns.qry.name","http.host",
                    "tls.handshake.extensions_server_name","smb2.cmd"]
            validate_native_tshark(display_filter,list(SOURCE_FIELDS["tshark"]))
            for pcap in self.settings.pcap_files:
                proposals.append({"source":"tshark","source_family":"network","source_targets":[str(pcap)],
                    "phase":"investigation","origin":origin,"intent":intent,
                    "query_spec":{"display_filter":display_filter,"fields":packet_fields,
                        "limit":min(500,self.settings.max_results)},"time_range":task_range,**owners})
        if not proposals: raise ValueError("No configured source can execute the investigation lead")
        return proposals

    def _register_investigation_tasks(self,s):
        """Project deterministic candidate/directed/coverage leads into one queue."""
        initialize_scheduler(s); registered=[]
        hypotheses={item.get("hypothesis_id"):item for item in s.get("hypotheses",[])}
        candidates={item.get("candidate_id"):item for item in s.get("candidate_leads",[])}
        for lead in s.get("lead_catalog",[]):
            if not isinstance(lead,dict): continue
            candidate=candidates.get(lead.get("candidate_id"))
            hypothesis=hypotheses.get(lead.get("hypothesis_id"),{})
            if candidate and lead.get("follow_up_id"): origin="candidate_follow_up"
            elif hypothesis.get("basis")=="operator_direction": origin="directed_survey"
            else: origin="coverage_frontier"
            try: proposals=self._compile_investigation_proposals(s,lead,origin)
            except (ValueError,TypeError,json.JSONDecodeError) as exc:
                family="host" if lead.get("source") in {"host","elasticsearch"} else "network"
                if s.get("source_health",{}).get(family) is False and lead.get("candidate_id") and lead.get("follow_up_id"):
                    reason=f"{family} telemetry unavailable"
                    candidate=candidates.get(lead.get("candidate_id"))
                    if candidate:
                        gaps=candidate.setdefault("telemetry_gaps",[])
                        if reason not in gaps: gaps.append(reason)
                        follow_up=next((item for item in candidate.get("follow_ups",[])
                            if item.get("follow_up_id")==lead.get("follow_up_id")),None)
                        if follow_up:
                            follow_up["status"]="skipped_due_gap"
                            history=follow_up.setdefault("history",[])
                            if not any(item.get("reason")==reason for item in history):
                                history.append({"timestamp":utc_now(),"status":"skipped_due_gap","reason":reason,
                                    "error_kind":type(exc).__name__})
                continue
            for proposal in proposals:
                task_id,_=register_search_task(s,proposal)
                if task_id not in registered: registered.append(task_id)
        outcomes={item.get("task_id"):item for item in s.get("search_outcomes",[]) if item.get("task_id")}
        for task_id in registered:
            if task_id in outcomes: self._record_scheduled_followups(s,s["search_tasks"][task_id],outcomes[task_id])
        return registered

    def _register_directed_initial_tasks(self,s):
        """Register operator-grounded work; never model-plan an undirected hunt."""
        self._ensure_initial_plan(s)
        registered=self._register_investigation_tasks(s) if _state_mission_mode(s)=="directed" else []
        if _state_mission_mode(s)!="directed" or self.offline or not self.use_ollama: return registered
        coverage=s.setdefault("coverage",{})
        prior=coverage.get("model_initial_search_plan")
        if isinstance(prior,dict) and prior.get("attempted"): return registered
        source_fields=coverage.get("search_fields",{})
        plan_status={"attempted":True,"status":"not generated","accepted":0,"rejected_or_duplicate":0}
        coverage["model_initial_search_plan"]=plan_status
        if not source_fields or not self._budget_ok(s): return registered
        try:
            from ..agent.ollama import Ollama, model_evidence_context
            visible_evidence=model_evidence_context(_all_evidence(s),10)
            searches=self._call(s,"ollama.api.chat","initial_search_planning",
                {"model":self.settings.ollama_model,"hypotheses":len(s.get("hypotheses",[]))},
                "operator-directed mission and completed deterministic discovery",
                lambda:Ollama(self.settings).propose_searches(s.get("objective",""),s.get("hypotheses",[]),
                    visible_evidence,source_fields,6,_search_history_summary(s),"initial",
                    coverage.get("search_field_classes",{})),len) or []
        except Exception as exc:
            plan_status["status"]="failed"; plan_status["error"]=type(exc).__name__; return registered
        accepted=self._register_model_searches(s,searches,"initial",
            visible_evidence_ids={item.get("evidence_id") for item in visible_evidence if item.get("evidence_id")})
        for task in accepted:
            if task["task_id"] not in registered: registered.append(task["task_id"])
        planning=coverage.get("model_search_planning",[])
        latest=planning[-1] if planning else {}
        plan_status.update({"status":"completed","accepted":latest.get("accepted",0),
            "rejected_or_duplicate":latest.get("rejected_or_duplicate",0)})
        return registered

    def _search_arkime_pages(self,s,expression,stage,scope,start_ms,stop_ms,cap,all_history,details=None):
        """Page through an Arkime result set, but stop at the configured evidence cap."""
        sessions=[]; total=None; offset=0; pages=0; failed=False; seen=set(); duplicates=0
        page_size=min(2000,max(1,int(cap)),self.settings.arkime_max_results)
        while len(sessions)<cap:
            if not self._budget_ok(s): break
            length=min(page_size,cap-len(sessions))
            parameters={**(details or {}),"expression":expression,"start":offset,"length":length,
                "date":-1 if all_history else ("explicit" if start_ms is not None else self.settings.arkime_default_hours)}
            found=self._call(s,"arkime.api.sessions",stage,parameters,scope,
                lambda offset=offset,length=length:self.arkime.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,
                    length=length,all_history=all_history,start=offset),lambda x:len(x.get("sessions",[])))
            if found is None:
                failed=True; break
            rows=found.get("sessions",[]); pages+=1
            for row in rows:
                session_key=str(row.get("id") or (row.get("firstPacket"),row.get("source.ip",row.get("srcIp")),row.get("destination.ip",row.get("dstIp")),row.get("source.port",row.get("srcPort")),row.get("destination.port",row.get("dstPort"))))
                if session_key in seen: duplicates+=1; continue
                seen.add(session_key); sessions.append(row)
            value=found.get("total")
            if isinstance(value,(int,float)): total=int(value)
            if not rows or len(rows)<length: break
            offset+=len(rows)
            if total is not None and offset>=total: break
        capped=(total is not None and len(sessions)<total) or (not failed and len(sessions)>=cap and (total is None or len(sessions)<total))
        return {"sessions":sessions,"total":total,"pages":pages,"failed":failed,"capped":capped,"duplicates_suppressed":duplicates}

    def _execute_search_task(self,s,task):
        """Execute one validated scheduler task and return its exact bounded outcome."""
        task_id=str(task.get("task_id") or "")
        source=str(task.get("source") or "")
        query_spec=task.get("query_spec")
        time_range=task.get("time_range")
        if not task_id.startswith("ST-") or source not in {"elasticsearch","arkime","tshark"} or not isinstance(query_spec,dict):
            raise ValueError("Invalid scheduled search task")
        start_time,end_time=_scheduled_time_bounds(time_range)
        if start_time and end_time and start_time>end_time: raise ValueError("Scheduled time range is reversed")
        scope=_scheduled_scope(time_range)
        stage=f"scheduled_{task.get('phase','investigation')}_search"
        before_runs=len(s.setdefault("tool_runs",[])); before_errors=len(s.setdefault("source_errors",[]))
        before_evidence={item.get("evidence_id") for item in s.get("host",[])+s.get("network",[]) if item.get("evidence_id")}
        returned=0; matched=None; capped=False; timed_out=False; shard_failures=0; incomplete=False
        status="failed"; error_kind=None; reason=None; query_summary={}
        try:
            if not self._budget_ok(s):
                status="budget_limited"; incomplete=True; reason=str(s.get("termination_reason") or "search_budget_exhausted")
            elif source=="elasticsearch":
                targets=list(task.get("source_targets") or [])
                configured=set(s.get("es_indices",[]))
                if not targets or any(name not in configured for name in targets):
                    raise ValueError("Scheduled Elasticsearch target is outside discovered indices")
                query=query_spec.get("query")
                if not isinstance(query,dict): raise ValueError("Scheduled Elasticsearch query is missing")
                validate_query(query)
                if not _query_enforces_scheduled_window(query,start_time,end_time):
                    raise ValueError("Scheduled Elasticsearch query does not enforce its time range")
                size=max(1,min(int(query_spec.get("size",self.settings.max_results)),self.settings.max_results,500))
                found=self._call(s,"elasticsearch.search",stage,
                    {"task_id":task_id,"indices":targets,"query":query,"size":size},scope,
                    lambda:self.es.search_many(targets,query,size),lambda value:len(value.get("hits",[])))
                if found is None:
                    incomplete=True
                    if s.get("termination_reason") in {"tool_call_budget","runtime_budget"}: status="budget_limited"; reason=str(s["termination_reason"])
                    else: status="failed"
                else:
                    rows=found.get("hits",[]); returned=len(rows); matched=found.get("total")
                    if isinstance(matched,dict): matched=matched.get("value")
                    matched=int(matched) if isinstance(matched,(int,float)) else None
                    capped=bool(found.get("capped")); timed_out=bool(found.get("timed_out"))
                    failures=found.get("shard_failures",0); shard_failures=len(failures) if isinstance(failures,list) else int(failures or 0)
                    incomplete=matched is None or capped or timed_out or bool(shard_failures)
                    status="partial" if incomplete else "completed"
                    for hit in rows: self._add_es_hit(s,hit,query,task_id)
                query_summary={"indices":targets,"query":query,"size":size}
            elif source=="arkime":
                targets=list(task.get("source_targets") or [])
                if targets!=[safe_url(self.settings.arkime_url)]: raise ValueError("Scheduled Arkime target is not the configured deployment")
                if not self.settings.arkime_username or not self.settings.arkime_password: raise ValueError("Arkime API credentials are not configured")
                expression=validate_native_arkime(str(query_spec.get("expression") or ""),list(SOURCE_FIELDS["arkime"]))
                cap=max(1,min(int(query_spec.get("cap",self.settings.arkime_max_results)),self.settings.arkime_max_results))
                start_ms=int(start_time.timestamp()*1000) if start_time else None
                stop_ms=int(end_time.timestamp()*1000) if end_time else None
                all_history=bool(self.settings.historical_search and start_ms is None and stop_ms is None)
                found=self._search_arkime_pages(s,expression,stage,scope,start_ms,stop_ms,cap,all_history,
                    {"task_id":task_id,"source":"arkime"})
                rows=found.get("sessions",[]); returned=len(rows); matched=found.get("total")
                matched=int(matched) if isinstance(matched,(int,float)) else None
                capped=bool(found.get("capped")); incomplete=bool(found.get("failed")) or capped or matched is None
                if found.get("failed") and not rows:
                    status="budget_limited" if s.get("termination_reason") in {"tool_call_budget","runtime_budget"} else "failed"
                else: status="partial" if incomplete else "completed"
                self._add_arkime_rows(s,rows,expression,scope,task_id)
                query_summary={"expression":expression,"cap":cap,"pages":found.get("pages")}
            else:
                targets=list(task.get("source_targets") or [])
                configured={str(path.resolve()) for path in self.settings.pcap_files}
                if len(targets)!=1 or str(Path(targets[0]).resolve()) not in configured:
                    raise ValueError("Scheduled TShark target is outside configured captures")
                display_filter=validate_native_tshark(str(query_spec.get("display_filter") or ""),
                    list(SOURCE_FIELDS["tshark"]))
                fields=list(dict.fromkeys(query_spec.get("fields") or ["frame.number","frame.time_epoch","ip.src","ip.dst"]))
                if not fields or len(fields)>16 or any(field not in SOURCE_FIELDS["tshark"] for field in fields):
                    raise ValueError("Scheduled TShark fields are not allowlisted")
                limit=max(1,min(int(query_spec.get("limit",self.settings.max_results)),self.settings.max_results,500))
                time_filter=""
                if start_time and end_time:
                    time_filter=f"frame.time_epoch >= {start_time.timestamp():.3f} && frame.time_epoch <= {end_time.timestamp():.3f}"
                pcap=Path(targets[0]).resolve()
                found=self._call(s,"tshark.read_pcap",stage,
                    {"task_id":task_id,"pcap":str(pcap),"display_filter":display_filter,"fields":fields},scope,
                    lambda:self.tshark.inspect(pcap,display_filter=display_filter,fields=fields,limit=limit,time_filter=time_filter),
                    lambda value:value.get("count",0))
                if found is None:
                    incomplete=True
                    if s.get("termination_reason") in {"tool_call_budget","runtime_budget"}: status="budget_limited"; reason=str(s["termination_reason"])
                    else: status="failed"
                else:
                    rows=found.get("packets",[]); returned=int(found.get("count",len(rows)) or 0)
                    matched_value=found.get("matched_count",returned); matched=int(matched_value) if isinstance(matched_value,(int,float)) else None
                    capped=bool(found.get("output_capped")); incomplete=capped or matched is None
                    status="partial" if incomplete else "completed"
                    provenance=found.get("provenance",{}) if isinstance(found.get("provenance"),dict) else {}
                    for row in rows: self._add_tshark_row(s,row,{**provenance,"search_task_id":task_id},display_filter,task_id)
                query_summary={"pcap":str(pcap),"display_filter":display_filter,"fields":fields,"limit":limit}
        except Exception as exc:
            status="failed"; incomplete=True; error_kind=type(exc).__name__; reason=_safe_error_reason(exc)
            status_code=getattr(getattr(exc,"meta",None),"status",None) or getattr(exc,"status_code",None)
            s.setdefault("source_errors",[]).append({"tool":source,"stage":stage,"error":error_kind,
                "reason":reason,"status_code":status_code,"task_id":task_id})
        if len(s.get("source_errors",[]))>before_errors and error_kind is None:
            latest_error=s["source_errors"][-1]; error_kind=latest_error.get("error"); reason=latest_error.get("reason")
        new_runs=s.get("tool_runs",[])[before_runs:]
        artifact_id=next((item.get("artifact_id") for item in reversed(new_runs) if item.get("artifact_id")),None)
        if not artifact_id:
            artifact_id="SR-"+hashlib.sha1(f"scheduler:{task_id}:{task.get('attempt_count',0)}".encode()).hexdigest()[:12].upper()
            artifact={"artifact_id":artifact_id,"tool":source,"stage":stage,"scope":scope,
                "result_status":"ok" if status in {"completed","partial"} else "error","returned":returned,
                "matched_total":matched,"error":error_kind,"error_reason":reason,"adequate_negative":False,"timestamp":utc_now()}
            if not any(item.get("artifact_id")==artifact_id for item in s.setdefault("search_artifacts",[])): s["search_artifacts"].append(artifact)
        evidence_ids=[item.get("evidence_id") for item in s.get("host",[])+s.get("network",[])
            if item.get("evidence_id") and item.get("evidence_id") not in before_evidence]
        outcome={"task_id":task_id,"status":status,"returned_total":returned,"matched_total":matched,
            "capped":capped,"timed_out":timed_out,"shard_failures":shard_failures,"incomplete":incomplete,
            "artifact_id":artifact_id,"evidence_ids":evidence_ids,"time_range":time_range}
        if error_kind: outcome["error_kind"]=error_kind
        if reason: outcome["reason"]=str(reason)[:300]
        s.setdefault("queries",[]).append({"stage":stage,"source":source,"task_id":task_id,"intent":str(task.get("intent") or "")[:300],
            "time_range":time_range,"returned":returned,"matched_total":matched,"status":status,"capped":capped,
            "timed_out":timed_out,"shard_failures":shard_failures,"artifact_id":artifact_id,**query_summary})
        self._stage(s,stage,status,{"task_id":task_id,"source":source,"returned":returned,"matched_total":matched})
        return outcome

    def _execute_model_search(self,s,plan,stage):
        source=plan.get("source"); intent=plan.get("intent",""); fp=plan.get("fingerprint") or fingerprint(plan)
        mission_range,mission_scope=self._time_scope(s)
        effective_range=mission_range; anchor_scope=None; scope=mission_scope
        result_count=0; status="skipped"; details={"intent":intent,"search_id":plan.get("id"),"hypothesis_id":plan.get("hypothesis_id"),"anchor_evidence_id":(plan.get("anchor_evidence_ids") or [None])[0],
            "native_query_language":plan.get("native_query_language","none"),"native_query_validation":plan.get("native_query_validation","not_proposed")}
        try:
            effective_range,anchor_scope=anchor_time_range(plan,_all_evidence(s),mission_range)
            scope=anchor_scope or mission_scope
            if source=="elasticsearch":
                all_names=list(s.get("es_indices",[])); requested_group=plan.get("index_class","all"); group=requested_group
                by_class=s.get("es_fields_by_class",{}); plan_fields=set(plan.get("fields",[]))
                host_score=len(plan_fields & set(by_class.get("host",[])))
                network_score=len(plan_fields & set(by_class.get("network",[])))
                if group=="all" and max(host_score,network_score)>0 and host_score!=network_score:
                    group="host" if host_score>network_score else "network"
                elif group in {"host","network"}:
                    own_score=host_score if group=="host" else network_score
                    other_score=network_score if group=="host" else host_score
                    if other_score>own_score: group="network" if group=="host" else "host"
                names=all_names if group=="all" else [x for x in all_names if group in x.lower()]
                if not names: raise ValueError(f"No configured Elasticsearch index matched index_class={group}")
                actual_fields=(by_class.get(group) if group in {"host","network"} else s.get("es_fields",[])) or s.get("es_fields",[])
                scoped_plan={**plan,"index_class":group,"fields":[f for f in plan.get("fields",[]) if f in actual_fields]}
                if scoped_plan.get("terms") and not scoped_plan["fields"]:
                    scoped_plan["fields"]=[f for f in TEXT_FIELDS if f in actual_fields][:4]
                timestamp_field=next((f for f in ("@timestamp","timestamp","event.created","event.ingested","event.start","winlog.time_created") if f in actual_fields),None)
                if effective_range and not timestamp_field: raise ValueError("No mapped timestamp field is available to enforce the search window")
                query=None
                if plan.get("native_query_language")=="elasticsearch_dsl" and plan.get("native_query"):
                    try:
                        query=compile_native_es(plan["native_query"],actual_fields,timestamp_field or s.get("timestamp_field","@timestamp"),effective_range)
                        details["native_query_execution"]="accepted"
                    except (ValueError,TypeError,json.JSONDecodeError) as native_error:
                        details["native_query_execution"]="rejected_fallback"
                        details["native_query_error"]=_safe_error_reason(native_error)
                if query is None:
                    query=compile_es(scoped_plan,actual_fields,timestamp_field or s.get("timestamp_field","@timestamp"),effective_range)
                size=min(self.settings.max_results,500)
                details.update({"requested_index_class":requested_group,"effective_index_class":group})
                found=self._call(s,"elasticsearch.search",stage,{**details,"source":"elasticsearch","indices":names,"query":query,"size":size},scope,
                    lambda:self.es.search_many(names,query,size),lambda x:len(x.get("hits",[])))
                if found is None: status="failed_or_budget_limited"
                else:
                    rows=found.get("hits",[]); result_count=len(rows); status="completed"
                    for hit in rows: self._add_es_hit(s,hit,query,plan.get("id"))
                    details["matched_total"]=found.get("total")
                s["queries"].append({"stage":stage,"source":source,"search_id":plan.get("id"),"intent":intent,"indices":names,
                    "query":locals().get("query"),"time_range":scope,"returned":result_count,"status":status,
                    "native_query_language":details.get("native_query_language"),"native_query_execution":details.get("native_query_execution")})
            elif source=="arkime":
                if not self.settings.arkime_username or not self.settings.arkime_password: raise ValueError("Arkime API credentials are not configured")
                expression=None
                if plan.get("native_query_language")=="arkime" and plan.get("native_query"):
                    try:
                        expression=validate_native_arkime(plan["native_query"],list(SOURCE_FIELDS["arkime"]))
                        details["native_query_execution"]="accepted"
                    except ValueError as native_error:
                        details["native_query_execution"]="rejected_fallback"
                        details["native_query_error"]=_safe_error_reason(native_error)
                if expression is None: expression=compile_arkime(plan)
                explicit=_explicit_dates(s["objective"]); start_ms,stop_ms=_arkime_time_window(s["objective"],self.settings.mission_timezone)
                if anchor_scope and effective_range:
                    start_ms=_explicit_epoch(effective_range["gte"],scale=1000); stop_ms=_explicit_epoch(effective_range["lte"],scale=1000)
                all_history=self.settings.historical_search and not explicit
                found=self._search_arkime_pages(s,expression,stage,scope,start_ms,stop_ms,self.settings.arkime_max_results,all_history,details)
                if found["failed"] and not found["sessions"]: status="failed_or_budget_limited"
                else:
                    rows=found.get("sessions",[]); result_count=len(rows); status="partial" if found.get("capped") or found.get("failed") else "completed"
                    self._add_arkime_rows(s,rows,expression,scope,plan.get("id")); details["matched_total"]=found.get("total")
                s["queries"].append({"stage":stage,"source":source,"search_id":plan.get("id"),"intent":intent,"expression":locals().get("expression"),
                    "time_range":scope,"returned":result_count,"matched_total":found.get("total"),"pages":found.get("pages"),"capped":found.get("capped"),"status":status,
                    "native_query_language":details.get("native_query_language"),"native_query_execution":details.get("native_query_execution")})
            elif source=="tshark":
                if not self.settings.pcap_files: raise ValueError("No approved PCAPs are configured")
                filter_spec={**plan,"ports":list(plan.get("ports",[]))}
                display_filter=None
                packet_fields=list(dict.fromkeys(["frame.number","frame.time_epoch","ip.src","ip.dst","ipv6.src","ipv6.dst",
                    "tcp.srcport","tcp.dstport","udp.srcport","udp.dstport",*[f for f in plan.get("fields",[]) if f in SOURCE_FIELDS["tshark"]]]))[:16]
                if plan.get("native_query_language")=="tshark" and plan.get("native_query"):
                    try:
                        display_filter=validate_native_tshark(plan["native_query"],list(SOURCE_FIELDS["tshark"]))
                        details["native_query_execution"]="accepted"
                    except ValueError as native_error:
                        details["native_query_execution"]="rejected_fallback"
                        details["native_query_error"]=_safe_error_reason(native_error)
                if display_filter is None: display_filter,packet_fields=compile_tshark(filter_spec)
                date_filter=_pcap_time_filter(_explicit_dates(s["objective"]),self.settings.mission_timezone)
                if anchor_scope and effective_range:
                    start_seconds=_explicit_epoch(effective_range["gte"],scale=1); stop_seconds=_explicit_epoch(effective_range["lte"],scale=1)
                    date_filter=f"frame.time_epoch >= {start_seconds:.3f} && frame.time_epoch <= {stop_seconds:.3f}"
                attempted=0; failed=0; cap_hits=0; matched_total=0; output_cap=min(500,self.settings.max_results)
                for pcap in self.settings.pcap_files[:3]:
                    if not self._budget_ok(s): status="budget_limited"; break
                    found=self._call(s,"tshark.read_pcap",stage,{**details,"source":"tshark","pcap":str(pcap),"display_filter":display_filter,"fields":packet_fields},
                        "explicit mission dates; retained-match cap applies" if date_filter else "entire configured capture; retained-match cap applies",
                        lambda pcap=pcap:self.tshark.inspect(pcap,display_filter=display_filter,fields=packet_fields,
                            limit=output_cap,time_filter=date_filter),lambda x:x.get("count",0))
                    attempted+=1
                    if found is None: failed+=1; continue
                    result_count+=found.get("count",0)
                    matched_total+=int(found.get("matched_count",found.get("count",0)) or 0)
                    if found.get("output_capped"): cap_hits+=1
                    for row in found.get("packets",[]):
                        self._add_tshark_row(s,row,{**found["provenance"],"search_id":plan.get("id"),
                            "hypothesis_id":plan.get("hypothesis_id"),"search_fingerprint":fp},
                            found["provenance"]["display_filter"],plan.get("id"))
                if status!="budget_limited": status="partial" if failed or cap_hits else ("completed" if attempted else "skipped")
                s["queries"].append({"stage":stage,"source":source,"search_id":plan.get("id"),"intent":intent,"display_filter":locals().get("display_filter"),
                    "pcaps_attempted":attempted,"failed":failed,"cap_hits":cap_hits,"per_capture_output_cap":output_cap,
                    "time_range":scope,"returned":result_count,"matched_total":matched_total,"status":status,
                    "native_query_language":details.get("native_query_language"),"native_query_execution":details.get("native_query_execution")})
            else: raise ValueError("Unsupported search source")
        except Exception as exc:
            status="rejected_or_failed"; error_reason=_safe_error_reason(exc)
            status_code=getattr(getattr(exc,"meta",None),"status",None) or getattr(exc,"status_code",None)
            details["error_type"]=type(exc).__name__; details["error_reason"]=error_reason
            s.setdefault("source_errors",[]).append({"tool":str(source),"stage":stage,"error":type(exc).__name__,
                "reason":error_reason,"status_code":status_code})
            selectors={k:plan.get(k) for k in ("terms","fields","ips","hostnames","ports","protocols","event_codes","index_class") if plan.get(k)}
            s["queries"].append({"stage":stage,"source":source,"search_id":plan.get("id"),"intent":intent,"selectors":selectors,
                "time_range":scope,"returned":result_count,"status":status,"error":type(exc).__name__,"error_reason":error_reason,
                "native_query_language":details.get("native_query_language"),"native_query_execution":details.get("native_query_execution")})
        s.setdefault("coverage",{}).setdefault("model_search_results",[]).append({"search_id":plan.get("id"),"source":source,
            "hypothesis_id":plan.get("hypothesis_id"),"intent":intent,"returned":result_count,"status":status,"fingerprint":fp})
        self._stage(s,stage,status,{"search_id":plan.get("id"),"source":source,"intent":intent,"returned":result_count})
        print(f"[ROMULUS] {stage}: {source} intent={intent[:110]} status={status} results={result_count}")
        return result_count

    def _analyze(self,s):
        s["correlations"]=correlate(s.get("host",[]),s.get("network",[]))
        all_e=s.get("host",[])+s.get("network",[])
        s["investigation_graph"]=build_investigation_graph(all_e,s["correlations"])
        s["analytic_summary"]=summarize_evidence(s.get("host",[]),s.get("network",[]))
        s.setdefault("coverage",{})["analytic_summary"]=s["analytic_summary"]
        previous_candidates=list(s.get("candidate_leads",[]))
        fresh_candidates=build_candidate_queue(all_e,self.behavior_catalog,self.local_indicators,s["analytic_summary"])
        s["candidate_leads"]=merge_candidate_queue(previous_candidates,fresh_candidates)
        new_hypotheses=_candidate_hypotheses(s["candidate_leads"],s.get("hypotheses",[]),all_e)
        if new_hypotheses:
            s.setdefault("hypotheses",[]).extend(new_hypotheses)
            known_leads={lead.get("id") for lead in s.setdefault("lead_catalog",[])}
            s["lead_catalog"].extend(lead for lead in _lead_catalog(new_hypotheses) if lead.get("id") not in known_leads)
            s.setdefault("coverage",{})["hypotheses_total"]=len(s["hypotheses"])
            s.setdefault("reasoning_history",[]).append({"stage":"candidate_hypothesis_creation","basis":"observed_candidate",
                "hypotheses":[{"id":h.get("hypothesis_id"),"candidate_ids":h.get("basis_candidate_ids"),
                    "evidence_ids":h.get("basis_evidence_ids")} for h in new_hypotheses]})
        s["coverage"]["behavior_candidates"]={
            "total":len(s["candidate_leads"]),
            "customer_visible":sum(bool(item.get("customer_visible")) for item in s["candidate_leads"]),
            "unresolved_low_priority":sum(item.get("priority_tier")=="low" and item.get("disposition")=="observed" for item in s["candidate_leads"])}
        for hypothesis in s.get("hypotheses",[]):
            relevant=[e for e in all_e if _relevant(hypothesis["technique_id"],e)]
            # Heuristic matches are candidate context for the model, not an
            # assessment. Only a cited analyst assessment may mark a hypothesis
            # supported or contradicted.
            hypothesis["candidate_evidence_ids"]=[e["evidence_id"] for e in relevant if e.get("evidence_id")][:40]
            if not hypothesis.get("model_assessment") and not hypothesis.get("deterministic_assessment"):
                hypothesis["evidence_ids"]=[]
                hypothesis["status"]="candidate evidence found" if relevant else "not assessed"
                hypothesis["confidence"]="not assessed"
        if s["correlations"]: self._publish_smb_lead(s)
        self._publish_tooling_leads(s)
        _link_candidates_to_findings(s)
        _attach_finding_paths(s)
        host_available=bool(s.get("es_indices")) or self.offline
        network_available=self.offline or bool(s.get("source_health",{}).get("network"))
        ledger=build_coverage_ledger(s.get("hypotheses",[]),s.get("search_tasks",{}),s.get("search_outcomes",[]),
            host_available,network_available,s.get("candidate_leads",[]))
        s["coverage"]["hypothesis_coverage"]=ledger
        signals=len(s["analytic_summary"].get("behavioral_observations",[]))
        self._stage(s,"evidence_analysis","completed",{"host_events":len(s.get("host",[])),"network_events":len(s.get("network",[])),
            "correlations":len(s["correlations"]),"behavioral_observations":signals,
            "behavior_candidates":len(s.get("candidate_leads",[])),"findings":len(s.get("findings",[])),
            "high_priority_tested":ledger.get("high_priority_tested"),"high_priority_total":ledger.get("high_priority_total")})
        print(f"[ROMULUS] analysis stage: evidence={len(all_e)} analytic_observations={signals} behavior_candidates={len(s.get('candidate_leads',[]))} correlations={len(s['correlations'])} findings={len(s.get('findings',[]))} high_priority_tested={ledger.get('high_priority_tested')}/{ledger.get('high_priority_total')}")
        return self._save(s)

    def _publish_smb_lead(self,s):
        all_e=s.get("host",[])+s.get("network",[]); existing={f.get("finding_id"):f for f in self.store.list_findings(s["hunt_id"])}
        findings=[f for f in s.get("findings",[]) if f.get("finding_id")!="F-"+s["hunt_id"].replace("HUNT-","")+"-01"]
        refs=[]; ipset=set()
        for correlation in s["correlations"]:
            host_event=next((e for e in s.get("host",[]) if e.get("evidence_id")==correlation.get("host_ref")),{})
            network_event=next((e for e in s.get("network",[]) if e.get("evidence_id")==correlation.get("network_ref")),{})
            host_text=(host_event.get("observation","")+" "+str(host_event.get("raw",{}))).lower()
            network_text=(network_event.get("observation","")+" "+str(network_event.get("raw",{}))).lower()
            if not any(x in host_text for x in ("4624","4625","logon","authentication","7045","service")): continue
            if not any(x in network_text for x in ("445","smb")): continue
            for ref in (correlation.get("host_ref"),correlation.get("network_ref")):
                if ref and ref not in refs: refs.append(ref)
            if correlation.get("ip"): ipset.add(correlation["ip"])
        if not refs: return
        relevant=[event for event in all_e if event.get("evidence_id") in refs]
        finding=Finding("F-"+s["hunt_id"].replace("HUNT-","")+"-01","Correlated SMB activity and host logon lead","suspected","T1021.002",
            list(dict.fromkeys(e.get("asset","") for e in relevant if e.get("asset"))),
            "Network session and host event records share an address, fall within the correlation window, and contain behavior relevant to SMB movement.",
            "This is a lead consistent with SMB lateral-movement behavior. IP/time correlation alone does not establish source process, actor identity, or maliciousness.",
            refs,"moderate" if len(relevant)>=2 else "low","Multiple telemetry records align in time; attribution and benign administrative context remain unresolved.",
            ["authorized file sharing","backup/software deployment","NAT/DHCP or clock skew causing misleading association"],
            ["verify endpoint identity and DHCP/NAT mappings","inspect authentication and service creation context","attribute SMB session to process/account"])
        prior=existing.get(finding.finding_id)
        if prior: finding.created_at=prior.get("created_at",finding.created_at); event="updated"
        else: event="created"
        encoded=encode(finding); findings.append(encoded); s["findings"]=findings
        self.store.upsert_finding(s["hunt_id"],encoded,event)
        for hypothesis in s.get("hypotheses",[]):
            if hypothesis.get("technique_id") not in {"T1021","T1021.002"}: continue
            assessment={"status":"supported","rationale":finding.interpretation,
                "evidence_ids":list(refs),"assessed_at":utc_now(),"method":"deterministic_smb_correlation"}
            hypothesis["deterministic_assessment"]=assessment
            hypothesis["evidence_ids"]=list(refs)
            hypothesis["status"]="supported lead"
            hypothesis["confidence"]="moderate" if len(relevant)>=2 else "low"
        print(f"[ROMULUS] evidence-backed lead published: {finding.finding_id}; evidence_refs={len(refs)}; shared_ips={len(ipset)}")

    def _publish_tooling_leads(self,s):
        """Publish cautious findings for command-line transfer and enumeration signals."""
        groups={}
        for event in s.get("host",[]):
            raw=event.get("raw",{})
            message=str(raw.get("message", "")) if isinstance(raw,dict) else ""
            text=(event.get("observation","")+" "+message+" "+json.dumps(raw,ensure_ascii=False)).lower()
            asset=str(event.get("asset") or "unknown host")
            enum=any(token in text for token in ("linpeas","linenum","linux-exploit-suggester","meterpreter"))
            enum_execution=bool(re.search(r'\ba0=["\']?(?:[^"\']*/)?(?:linpeas|linenum|linux-exploit-suggester)(?:\.sh)?["\']?',text))
            invocation=bool(re.search(r'\ba0=["\']?(?:wget|curl)["\']?',text))
            destination=bool(re.search(r'(?:https?|ftp)://|metadata\.google\.internal',text))
            trusted_motd="motd.ubuntu.com" in text
            transfer=invocation and destination and not trusted_motd
            metadata=invocation and "metadata.google.internal" in text
            if not (enum or transfer or metadata): continue
            entry=groups.setdefault(asset,{"enum":[],"enum_execution":[],"transfer":[],"metadata":[]})
            if enum: entry["enum"].append(event)
            if enum_execution: entry["enum_execution"].append(event)
            if transfer: entry["transfer"].append(event)
            if metadata: entry["metadata"].append(event)

        for asset,group in groups.items():
            enum_events=group["enum"]; enum_execution=group["enum_execution"]
            transfer_events=group["transfer"]; metadata_events=group["metadata"]
            supporting=enum_events+metadata_events
            linked=any(_within_minutes(a.get("observed_at"),b.get("observed_at"),60)
                for a in supporting for b in transfer_events)
            relevant=[]
            if linked:
                relevant.extend(supporting); relevant.extend(transfer_events)
                relevant.extend(e for e in enum_execution if e not in relevant)
            else:
                relevant.extend(transfer_events or metadata_events or enum_events)
            relevant=list({e.get("evidence_id"):e for e in relevant if e.get("evidence_id")}.values())
            if not relevant: continue
            host_ips=_evidence_ips(relevant)
            related_network=[]
            for network_event in s.get("network",[]):
                network_text=_event_text(network_event)
                has_shared_ip=any(ip in network_text for ip in host_ips)
                near_host=any(_within_minutes(network_event.get("observed_at"),e.get("observed_at"),2) for e in relevant)
                network_signal=any(x in network_text for x in ("/pwnkit","elf file download over http","wget user-agent to bare ip","metadata.google.internal","169.254.169.254"))
                if has_shared_ip and near_host and network_signal: related_network.append(network_event)
            relevant.extend(e for e in related_network if e.get("evidence_id") not in {x.get("evidence_id") for x in relevant})
            refs=list(dict.fromkeys(e.get("evidence_id") for e in relevant if e.get("evidence_id")))
            if not refs: continue
            host_excerpts=[f"HOST {e.get('observed_at','time unknown')}: {e.get('observation','')[:350]}" for e in relevant if e in s.get("host",[])][:4]
            network_excerpts=[f"NETWORK {e.get('observed_at','time unknown')}: {e.get('observation','')[:500]}" for e in related_network[:4]]
            excerpts=host_excerpts+network_excerpts
            network_text=" ".join(_event_text(e) for e in related_network)
            network_status_200=re.search(r'(?:"status"\s*:\s*200|http\.statuscode\s*[=:]\s*200|"statuscode"\s*:\s*\[?\s*200)',network_text)
            network_confirmed=("/pwnkit" in network_text and network_status_200 and
                ("elf file download over http" in network_text or "fileinfo" in network_text))
            if linked:
                title=f"Possible suspicious payload transfer and post-exploitation activity on {asset}"
                if enum_execution:
                    enumeration_note="A process record also shows Linux enumeration tooling. "
                elif enum_events:
                    enumeration_note="A nearby audit command references a LinPEAS path in a grep filter; that is not proof LinPEAS itself executed. "
                else: enumeration_note="Nearby curl activity targets the cloud metadata service. "
                interpretation=("Within one hour, host telemetry records command-line transfer activity and a related enumeration or metadata-service signal. "+enumeration_note)
                if network_confirmed:
                    interpretation+=(" Network-index events tied to the same host IP show an HTTP 200 response for /PwnKit and file/IDS telemetry for an ELF download over HTTP. ")
                interpretation+=("This is a suspicious investigation lead; the logs do not establish that the downloaded file executed or that the host was compromised.")
                confidence="moderate"
                justification=("Host audit events and matching network-index records show the same host IP requested a PwnKit path and received HTTP 200; network evidence corroborates transfer but not file execution." if network_confirmed else
                    "Multiple behavior types appear on the same host within a short interval, including a path named PwnKit; no event proves successful transfer or execution.")
                technique="T1105"
            elif transfer_events:
                title=f"Possible command-line download or metadata access on {asset}"
                interpretation=("A host audit record shows wget/curl directed at a remote URL or cloud metadata name. "
                    "Treat this as a lead until response status, process ancestry, destination ownership, and file execution are checked.")
                confidence="low"
                justification="A command-line transfer attempt is recorded, but the event does not establish the response or file outcome."
                technique="T1105"
            else:
                title=f"Possible host enumeration tooling reference on {asset}"
                interpretation=("A host audit message references Linux enumeration or post-exploitation tooling. "
                    "A path or grep reference alone does not prove the named tool itself executed.")
                confidence="low"
                justification="The evidence is a tool-name reference in a host audit message without corroborating transfer or execution evidence."
                technique="T1082"
            observation=f"Related host telemetry for {asset}: " + "; ".join(excerpts)
            identity=hashlib.sha1(asset.encode("utf-8",errors="replace")).hexdigest()[:8].upper()
            finding=Finding("F-"+s["hunt_id"].replace("HUNT-","")+"-TOOL-"+identity,title,"suspected",technique,[asset],observation,
                interpretation,refs,confidence,justification,
                ["authorized security assessment or red-team exercise","administrator troubleshooting or software deployment","the tool name appears in a search/filter command rather than as an executed tool"],
                ["inspect process ancestry, user, and adjacent audit events","verify HTTP response and destination from network telemetry","check downloaded file path, hash, and subsequent execution","confirm whether the activity was authorized"])
            encoded=encode(finding)
            old=next((f for f in self.store.list_findings(s["hunt_id"]) if f.get("finding_id")==finding.finding_id),None)
            if old: encoded["created_at"]=old.get("created_at",encoded["created_at"]); encoded["updated_at"]=utc_now(); action="updated"
            else: action="created"
            current=[f for f in s.get("findings",[]) if f.get("finding_id")!=finding.finding_id]
            current.append(encoded); s["findings"]=current
            self.store.upsert_finding(s["hunt_id"],encoded,action)
            print(f"[ROMULUS] command-line tooling lead published: {finding.finding_id}; evidence_refs={len(refs)}; confidence={confidence}")

    def _after_analyze(self,s):
        self._register_investigation_tasks(s)
        queued=select_search_tasks(s,phase="investigation",limit=1)
        if queued and self._can_pivot(s): s.pop("termination_reason",None); return "pivot"
        if queued and not s.get("termination_reason"):
            s["termination_reason"]="tool_call_budget" if s.get("tool_calls",0)>=self.settings.max_tool_calls else "runtime_budget"
        if queued: self._save(s); return "report"
        ledger=s.get("coverage",{}).get("hypothesis_coverage",{})
        if ledger.get("closure_ready"):
            s.setdefault("termination_reason","lead_queue_exhausted"); self._save(s); return "report"
        grounded=_state_mission_mode(s)=="directed" or bool(s.get("candidate_leads"))
        if grounded and s.get("depth",0)<self.settings.max_depth and self._budget_ok(s):
            s.pop("termination_reason",None); self._save(s); return "reason"
        if not s.get("termination_reason"): s["termination_reason"]="coverage_frontier_exhausted"
        self._save(s)
        return "report"

    def _after_reason(self,s):
        queued=select_search_tasks(s,phase="investigation",limit=1)
        if queued and self._can_pivot(s): s.pop("termination_reason",None); return "pivot"
        if queued and not s.get("termination_reason"):
            s["termination_reason"]="tool_call_budget" if s.get("tool_calls",0)>=self.settings.max_tool_calls else "runtime_budget"
        if queued: self._save(s); return "report"
        grounded=_state_mission_mode(s)=="directed" or bool(s.get("candidate_leads"))
        if (grounded and s.get("depth",0)<self.settings.min_reasoning_rounds
                and s.get("depth",0)<self.settings.max_depth and self._budget_ok(s)):
            s.pop("termination_reason",None); self._save(s); return "reason"
        if not s.get("termination_reason"):
            s["termination_reason"]="lead_queue_exhausted" if self.offline else "no_useful_leads"
        self._save(s)
        return "report"

    def _can_pivot(self,s):
        return self._budget_ok(s)

    def _reason(self,s):
        if s.get("depth",0)>=self.settings.max_depth:
            s["termination_reason"]="depth_budget"
            self._stage(s,"analyst_reasoning","budget_exhausted",{"reasoning_rounds":s.get("depth",0)})
            return self._save(s)
        s.setdefault("depth",0); s["depth"]+=1
        selected=[]; basis="deterministic scheduler coverage"; analysis=None; model_error=None
        source_fields=s.get("coverage",{}).get("search_fields",{})
        if not source_fields: self._ensure_initial_plan(s); source_fields=s.get("coverage",{}).get("search_fields",{})
        self._register_investigation_tasks(s)
        elapsed=max(0,time.time()-s.get("started_epoch",time.time()))
        s.setdefault("coverage",{})["tool_calls_remaining"]=max(0,self.settings.max_tool_calls-s.get("tool_calls",0))
        s["coverage"]["runtime_seconds_remaining"]=max(0,round(self.settings.max_runtime_seconds-elapsed))
        s["coverage"]["reasoning_rounds_remaining"]=max(0,self.settings.max_depth-s.get("depth",0))
        s["coverage"]["recent_search_artifacts"]=s.get("search_artifacts",[])[-12:]
        mission_mode=_state_mission_mode(s)
        candidate_grounded=(mission_mode!="undirected" or bool(s.get("candidate_leads")))
        if not self.offline and self.use_ollama and source_fields and candidate_grounded and self._budget_ok(s):
            try:
                from ..agent.ollama import Ollama, model_evidence_context
                visible_evidence_ids={e.get("evidence_id") for e in model_evidence_context(_all_evidence(s),12) if e.get("evidence_id")}
                visible_candidate_ids={x.get("candidate_id") for x in s.get("candidate_leads",[])[:12] if x.get("candidate_id")}
                model_coverage=dict(s.get("coverage",{}))
                model_coverage["candidate_queue"]=[{"candidate_id":c.get("candidate_id"),"title":str(c.get("title",""))[:120],
                    "priority_score":c.get("priority_score"),"priority_tier":c.get("priority_tier"),
                    "disposition":c.get("disposition"),"evidence_ids":c.get("evidence_ids",[])[:5],
                    "assets":c.get("assets",[])[:4],"attack_techniques":c.get("attack_techniques",[])[:4],
                    "follow_ups":[{"follow_up_id":f.get("follow_up_id"),"intent":str(f.get("intent",""))[:140],"status":f.get("status")}
                        for f in c.get("follow_ups",[])[:3]]} for c in s.get("candidate_leads",[])[:12]]
                model_coverage["existing_findings"]=[{"title":str(f.get("title",""))[:100],
                    "technique_id":f.get("technique_id"),"evidence_ids":f.get("evidence_ids",[])[:5]}
                    for f in s.get("findings",[])[-5:]]
                analysis=self._call(s,"ollama.api.chat","analyst_reasoning",
                    {"model":self.settings.ollama_model,"hypotheses":len(s.get("hypotheses",[])),
                     "evidence_count":len(_all_evidence(s)),"completed_searches":len(s.get("search_outcomes",[]))},
                    "bounded mission, evidence excerpts, query coverage, and mapped source fields",
                    lambda:Ollama(self.settings).reason_hunt(s["objective"],s.get("hypotheses",[]),_all_evidence(s),
                        model_coverage,_search_history_summary(s),3),lambda x:len(x.get("searches",[])))
                if analysis is None:
                    last_call=next((r for r in reversed(s.get("tool_runs",[])) if r.get("tool")=="ollama.api.chat" and r.get("reasoning_stage")=="analyst_reasoning"),{})
                    model_error=last_call.get("error_reason") or last_call.get("error") or "unavailable"
                if isinstance(analysis,dict):
                    created=self._append_model_hypotheses(s,analysis.get("new_hypotheses",[]),visible_evidence_ids|visible_candidate_ids)
                    if created:
                        created_set=set(created); known={lead.get("id") for lead in s.setdefault("lead_catalog",[])}
                        additions=_lead_catalog([item for item in s.get("hypotheses",[]) if item.get("hypothesis_id") in created_set])
                        s["lead_catalog"].extend(item for item in additions if item.get("id") not in known)
                    self._apply_model_assessments(s,analysis,visible_evidence_ids)
                    self._publish_model_findings(s,analysis.get("findings",[]),visible_evidence_ids)
                    analysis["created_hypothesis_ids"]=created
                    basis="model assessed cited evidence and proposed fresh bounded searches"
            except Exception as exc:
                analysis=None; model_error=type(exc).__name__
        if isinstance(analysis,dict):
            raw_searches=analysis.get("searches",[])
            validated=self._register_model_searches(s,raw_searches,"iterative",
                visible_candidate_ids=visible_candidate_ids,visible_evidence_ids=visible_evidence_ids)
            self._register_investigation_tasks(s)
            planning=s.get("coverage",{}).get("model_search_planning",[])
            planning=planning[-1] if planning else {"accepted":0,"rejected_or_duplicate":0}
            print(f"[ROMULUS] model follow-up plan: proposed={planning.get('proposed',len(raw_searches) if isinstance(raw_searches,list) else 0)} accepted={planning.get('accepted',0)} rejected_or_duplicate={planning.get('rejected_or_duplicate',0)} repeated_empty_anchor={planning.get('repeated_empty_anchor',0)}")
        selected=[item["task_id"] for item in select_search_tasks(s,phase="investigation",limit=3)]
        if selected:
            s.pop("termination_reason",None)
        elif isinstance(analysis,dict):
            closure=s.get("coverage",{}).get("hypothesis_coverage",{}).get("closure_ready",False)
            if closure and not analysis.get("continue_investigation",True): s["termination_reason"]="coverage_closure_reached"
            else: s["termination_reason"]="coverage_frontier_exhausted"
        elif not self.offline:
            basis=("structured model output unavailable; deterministic ATT&CK coverage frontier used" if self.use_ollama and candidate_grounded
                else "deterministic ATT&CK coverage frontier used")
            s["termination_reason"]=("model_unavailable_no_fallback_leads" if self.use_ollama and candidate_grounded
                else "coverage_frontier_exhausted")
        else:
            basis="offline deterministic fixture pivot"; s["termination_reason"]="lead_queue_exhausted"
        s["reasoning_history"].append({"stage":"analyst_reasoning","basis":basis,"round":s["depth"],
            "reasoning":str(analysis.get("reasoning",""))[:350] if isinstance(analysis,dict) else "",
            "model_error":model_error,
            "model_search_plan":s.get("coverage",{}).get("model_search_planning",[])[-1] if s.get("coverage",{}).get("model_search_planning") else None,
            "created_hypothesis_ids":analysis.get("created_hypothesis_ids",[]) if isinstance(analysis,dict) else [],
            "selected_searches":[{"task_id":q["task_id"],"source":q.get("source"),
                "hypothesis_ids":q.get("hypothesis_ids",[]),"intent":q.get("intent")} for q in
                (s.get("search_tasks",{}).get(task_id,{}) for task_id in selected)],
            "evidence_count":len(_all_evidence(s)),"completed_search_count":len(s.get("search_outcomes",[]))})
        self._stage(s,"analyst_reasoning","completed" if selected else "stopped",{"basis":basis,"round":s["depth"],"selected_searches":selected,
            "continue_investigation":analysis.get("continue_investigation") if isinstance(analysis,dict) else None,
            "reason":s.get("termination_reason")})
        print(f"[ROMULUS] analyst round {s['depth']}/{self.settings.max_depth}: {basis}; next searches={selected or 'none'}")
        return self._save(s)

    def _apply_model_assessments(self,s,analysis,visible_ids=None):
        hypotheses={h.get("hypothesis_id"):h for h in s.get("hypotheses",[])}
        valid_evidence=set(visible_ids or {e.get("evidence_id") for e in _all_evidence(s) if e.get("evidence_id")})
        for item in analysis.get("assessments",[]) if isinstance(analysis.get("assessments"),list) else []:
            if not isinstance(item,dict): continue
            hypothesis=hypotheses.get(item.get("hypothesis_id")); status=item.get("status")
            if not hypothesis or status not in {"supported","contradicted","inconclusive","not_tested"}: continue
            refs=list(dict.fromkeys(x for x in item.get("evidence_ids",[]) if isinstance(x,str) and x in valid_evidence))
            if status in {"supported","contradicted"} and not refs:
                status="inconclusive"
            assessment={"status":status,"rationale":str(item.get("rationale",""))[:500],"evidence_ids":refs,
                "assessed_at":utc_now(),"reasoning_round":s.get("depth",0)}
            hypothesis.setdefault("assessment_history",[]).append(assessment)
            previous=hypothesis.get("model_assessment",{}) if isinstance(hypothesis.get("model_assessment"),dict) else {}
            # A later inconclusive pass must not erase earlier cited support or
            # contradiction. The full history remains visible for review.
            if previous.get("status") in {"supported","contradicted"} and status in {"inconclusive","not_tested"}:
                continue
            hypothesis["model_assessment"]=assessment
            hypothesis["evidence_ids"]=refs
            if status=="supported": hypothesis["status"]="supported lead"
            elif status=="contradicted": hypothesis["status"]="evidence contradicts this hypothesis"
            elif status=="inconclusive": hypothesis["status"]="inconclusive"
            else: hypothesis["status"]="not tested"

    def _append_model_hypotheses(self,s,proposals,visible_ids=None):
        if not isinstance(proposals,list): return []
        known={re.sub(r"[^a-z0-9]+","",str(h.get("title","")).lower()) for h in s.get("hypotheses",[])}
        candidate_ids={item.get("candidate_id") for item in s.get("candidate_leads",[]) if item.get("candidate_id")}
        evidence_ids={item.get("evidence_id") for item in _all_evidence(s) if item.get("evidence_id")}
        groundable_ids=candidate_ids|evidence_ids
        visible=(set(visible_ids) & groundable_ids) if visible_ids is not None else groundable_ids
        added=[]; next_number=len(s.get("hypotheses",[]))+1
        for proposal in proposals[:3]:
            if len(s.get("hypotheses",[]))>=24: break
            if not isinstance(proposal,dict): continue
            basis=list(dict.fromkeys(x for x in proposal.get("basis_evidence_ids",[]) if x in visible))
            normalized=_normalize_hypotheses([proposal])
            if not basis or not normalized: continue
            hypothesis=normalized[0]; key=re.sub(r"[^a-z0-9]+","",hypothesis.get("title","").lower())
            if not key or key in known: continue
            ident="H-FOLLOWUP-"+f"{next_number:02d}"
            while any(h.get("hypothesis_id")==ident for h in s.get("hypotheses",[])):
                next_number+=1; ident="H-FOLLOWUP-"+f"{next_number:02d}"
            hypothesis["hypothesis_id"]=ident; hypothesis["evidence_ids"]=[]
            hypothesis["basis_candidate_ids"]=[value for value in basis if value in candidate_ids]
            hypothesis["basis_evidence_ids"]=[value for value in basis if value in evidence_ids]
            hypothesis["basis"]="model_proposal_from_visible_context"
            hypothesis["status"]="untested"; hypothesis["confidence"]="low"
            s.setdefault("hypotheses",[]).append(hypothesis); known.add(key); added.append(ident); next_number+=1
        s.setdefault("coverage",{})["hypotheses_total"]=len(s.get("hypotheses",[]))
        return added

    def _publish_model_findings(self,s,proposals,visible_ids=None):
        if not isinstance(proposals,list): return
        evidence={e.get("evidence_id"):e for e in _all_evidence(s) if e.get("evidence_id")}
        if visible_ids is not None: evidence={k:v for k,v in evidence.items() if k in visible_ids}
        for proposal in proposals[:5]:
            if not isinstance(proposal,dict): continue
            refs=list(dict.fromkeys(x for x in proposal.get("evidence_ids",[]) if x in evidence))
            if not refs: continue
            title=str(proposal.get("title",""))[:140].strip(); observation=str(proposal.get("observation",""))[:700].strip()
            interpretation=str(proposal.get("interpretation",""))[:800].strip()
            if len(title)<8 or len(observation)<10 or len(interpretation)<10: continue
            technique=proposal.get("technique_id")
            if technique not in TECHNIQUES: technique="unmapped"
            supporting=[evidence[x] for x in refs]
            assets=list(dict.fromkeys(str(e.get("asset")) for e in supporting if e.get("asset")))[:12]
            sources={e.get("source") for e in supporting}
            confidence=proposal.get("confidence") if proposal.get("confidence") in {"low","moderate","high"} else "low"
            if confidence=="high" and (len(refs)<3 or len(sources)<2): confidence="moderate" if len(refs)>1 else "low"
            if confidence=="moderate" and len(refs)<2: confidence="low"
            def event_ips(events):
                found=set(_evidence_ips(events))
                for event in events:
                    text=str(event.get("observation",""))+" "+json.dumps(event.get("raw",{}),ensure_ascii=False,default=str)
                    for candidate in re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)",text):
                        try:
                            address=ipaddress.ip_address(candidate)
                            if not address.is_unspecified and not address.is_multicast: found.add(str(address))
                        except ValueError: pass
                return found
            proposed_events=[evidence[x] for x in refs]
            proposed_times=[e.get("observed_at") for e in proposed_events if e.get("observed_at")]
            proposed_ips=event_ips(proposed_events)
            duplicate=None
            for prior in s.get("findings",[]):
                prior_refs=set(prior.get("evidence_ids",[]))
                union=prior_refs|set(refs)
                overlap=len(prior_refs&set(refs))/max(1,len(union))
                prior_events=[evidence[x] for x in prior_refs if x in evidence]
                prior_times=[e.get("observed_at") for e in prior_events if e.get("observed_at")]
                same_cluster=len(proposed_ips & event_ips(prior_events))>=2 and any(
                    _within_minutes(left,right,60) for left in proposed_times for right in prior_times)
                if overlap>=0.6 or same_cluster:
                    duplicate=prior; break
            if duplicate:
                merged=dict(duplicate)
                merged["evidence_ids"]=list(dict.fromkeys((duplicate.get("evidence_ids",[])+refs)))[:24]
                merged["updated_at"]=utc_now()
                s["findings"]=[merged if f.get("finding_id")==duplicate.get("finding_id") else f for f in s.get("findings",[])]
                self.store.upsert_finding(s["hunt_id"],merged,"updated")
                print(f"[ROMULUS] duplicate model lead merged into {merged.get('finding_id')}; total_evidence_refs={len(merged['evidence_ids'])}")
                continue
            identifier="F-"+s["hunt_id"].replace("HUNT-","")+"-AI-"+hashlib.sha1((title+"|"+"|".join(sorted(refs))).encode()).hexdigest()[:8].upper()
            finding=Finding(identifier,title,"suspected",technique,assets,observation,interpretation,refs,confidence,
                str(proposal.get("confidence_justification",""))[:500],
                _clean_string_list(proposal.get("alternatives"),6,180) or ["benign administrative or expected application activity"],
                _clean_string_list(proposal.get("follow_up"),6,180) or ["review cited evidence and validate the activity with the system owner"])
            encoded=encode(finding)
            old=next((f for f in self.store.list_findings(s["hunt_id"]) if f.get("finding_id")==identifier),None)
            if old: encoded["created_at"]=old.get("created_at",encoded["created_at"]); encoded["updated_at"]=utc_now(); action="updated"
            else: action="created"
            s["findings"]=[f for f in s.get("findings",[]) if f.get("finding_id")!=identifier]+[encoded]
            self.store.upsert_finding(s["hunt_id"],encoded,action)
            print(f"[ROMULUS] model-proposed evidence-cited lead: {identifier}; evidence_refs={len(refs)}; confidence={confidence}")

    def _register_model_searches(self,s,raw_searches,phase,*,visible_candidate_ids=None,visible_evidence_ids=None):
        source_fields=s.get("coverage",{}).get("search_fields",{})
        ids={h.get("hypothesis_id") for h in s.get("hypotheses",[]) if h.get("hypothesis_id")}
        all_evidence_ids={e.get("evidence_id") for e in _all_evidence(s) if e.get("evidence_id")}
        evidence_ids=all_evidence_ids if visible_evidence_ids is None else all_evidence_ids & set(visible_evidence_ids)
        candidates={item.get("candidate_id"):item for item in s.get("candidate_leads",[]) if item.get("candidate_id")}
        if visible_candidate_ids is not None:
            candidates={key:value for key,value in candidates.items() if key in set(visible_candidate_ids)}
        accepted=[]; rejected=0; duplicate=0; repeated_empty_anchor=0
        proposed=raw_searches if isinstance(raw_searches,list) else []
        for raw in proposed:
            if not isinstance(raw,dict): rejected+=1; continue
            raw_candidate=raw.get("candidate_id"); raw_follow_up=raw.get("follow_up_id")
            raw_anchors=raw.get("anchor_evidence_ids",[])
            if raw_candidate and raw_candidate not in candidates: rejected+=1; continue
            if raw_candidate and raw_follow_up and not any(item.get("follow_up_id")==raw_follow_up
                    for item in candidates[raw_candidate].get("follow_ups",[])):
                rejected+=1; continue
            if not isinstance(raw_anchors,list) or any(anchor not in evidence_ids for anchor in raw_anchors):
                rejected+=1; continue
            if raw.get("hypothesis_id") not in ids|{"general"}: rejected+=1; continue
            if _state_mission_mode(s)=="undirected" and not raw_candidate and not raw_anchors:
                rejected+=1; continue
            item=expand_anchor_selectors(raw,_all_evidence(s))
            spec=validate_spec(item,allowed_sources=list(source_fields),hypothesis_ids=ids,fields_by_source=source_fields,evidence_ids=evidence_ids)
            if not spec: rejected+=1; continue
            spec.update({"candidate_id":raw_candidate,"follow_up_id":raw_follow_up})
            try: proposals=self._compile_investigation_proposals(s,spec,"model_proposal")
            except (ValueError,TypeError,json.JSONDecodeError): rejected+=1; continue
            proposal_tasks=[]
            for proposal in proposals:
                task_id,created=register_search_task(s,proposal)
                if not created: duplicate+=1
                task=s["search_tasks"][task_id]
                if not any(existing.get("task_id")==task_id for existing in accepted): accepted.append(task)
                proposal_tasks.append(task_id)
            if not proposal_tasks: rejected+=1
        s.setdefault("coverage",{}).setdefault("model_search_planning",[]).append({"phase":phase,"proposed":len(proposed),
            "accepted":len(accepted),"rejected_or_duplicate":rejected+duplicate,"duplicate":duplicate,
            "repeated_empty_anchor":repeated_empty_anchor,"invalid_or_unmappable":rejected})
        return accepted

    def _anchor_exhausted_on_sources(self,s,spec):
        """Stop retrying a zero-result evidence anchor across already-tried sources."""
        anchors=spec.get("anchor_evidence_ids") or []
        if not anchors: return False
        anchor=anchors[0]
        plans={p.get("id"):p for p in s.get("lead_catalog",[]) if p.get("id")}
        zero_sources=set()
        for result in s.get("coverage",{}).get("model_search_results",[]):
            plan=plans.get(result.get("search_id"),{})
            if plan.get("phase")!="iterative": continue
            if anchor not in (plan.get("anchor_evidence_ids") or []): continue
            if result.get("status")=="completed" and result.get("returned")==0:
                zero_sources.add(plan.get("source"))
            elif result.get("status")=="completed" and result.get("returned",0)>0:
                zero_sources.clear()
        return len({source for source in zero_sources if source})>=2

    def _record_scheduled_followups(self,s,task,outcome):
        candidate_ids=set(task.get("candidate_ids",[])); follow_up_ids=set(task.get("follow_up_ids",[]))
        if not candidate_ids or not follow_up_ids: return
        terminal={"completed","partial","failed","skipped","budget_limited"}
        outcomes={item.get("task_id"):item for item in s.get("search_outcomes",[]) if item.get("task_id")}
        for candidate in s.get("candidate_leads",[]):
            candidate_id=candidate.get("candidate_id")
            if candidate_id not in candidate_ids: continue
            if candidate.get("disposition")=="observed": candidate["disposition"]="investigating"
            for follow_up in candidate.get("follow_ups",[]):
                follow_up_id=follow_up.get("follow_up_id")
                if follow_up_id not in follow_up_ids: continue
                history=follow_up.setdefault("history",[])
                if not any(item.get("task_id")==task.get("task_id") and
                        item.get("attempt_count")==outcome.get("attempt_count") for item in history):
                    history.append({"timestamp":utc_now(),"task_id":task.get("task_id"),
                        "attempt_count":outcome.get("attempt_count"),"status":outcome.get("status","attempted"),
                        "returned":int(outcome.get("returned_total") or 0)})
                required=[item for item in s.get("search_tasks",{}).values()
                    if candidate_id in (item.get("candidate_ids") or [])
                    and follow_up_id in (item.get("follow_up_ids") or [])]
                current=[outcomes.get(item.get("task_id")) for item in required]
                if required and all(outcome_resolves(item) for item in current): follow_up["status"]="completed"
                elif required and all(isinstance(item,dict) and item.get("status") in terminal for item in current):
                    follow_up["status"]="blocked"
                else: follow_up["status"]="in_progress"

    def _pivot(self,s):
        selected=select_search_tasks(s,phase="investigation",limit=1)
        if not selected: return self._save(s)
        task=begin_search_task(s,selected[0]["task_id"])
        self._save(s)
        print(f"[ROMULUS] investigation round {s.get('depth',0)}/{self.settings.max_depth}, task {task['task_id']}: {task.get('intent','follow-up search')}")
        if self.offline:
            host,_=sample_evidence(); item=encode(host[1]); item["query"]="synthetic scheduled follow-up"
            item["provenance"]={"fixture":"fixtures/synthetic_host.json","lead_id":task["task_id"]}
            compact=self._record_evidence(s,item)
            if compact: s.setdefault("host",[]).append(compact)
            outcome={"task_id":task["task_id"],"status":"completed","returned_total":1,"matched_total":1,
                "capped":False,"timed_out":False,"shard_failures":0,"incomplete":False,
                "artifact_id":"SR-"+hashlib.sha1(("offline:"+task["task_id"]).encode()).hexdigest()[:12].upper(),
                "evidence_ids":[compact["evidence_id"]] if compact else [],"time_range":task.get("time_range",{})}
            s.setdefault("coverage",{})["offline_pivot"]="completed: synthetic host service event retrieved after scheduled lead"
            s.setdefault("queries",[]).append({"stage":"offline_synthetic_pivot","task_id":task["task_id"],"returned":1})
        else: outcome=self._execute_search_task(s,task)
        recorded=record_search_outcome(s,task["task_id"],outcome)
        if task["task_id"] not in s.setdefault("completed_leads",[]): s["completed_leads"].append(task["task_id"])
        s.setdefault("pivot_results",[]).append({"lead_id":task["task_id"],"task_id":task["task_id"],
            "status":recorded.get("status"),"returned":recorded.get("returned_total",0)})
        self._record_scheduled_followups(s,s["search_tasks"][task["task_id"]],recorded)
        self._stage(s,"follow_up_pivot",recorded.get("status","attempted"),
            {"task_id":task["task_id"],"returned":recorded.get("returned_total",0)})
        return self._save(s)

    def _host_pivot(self,s,lead):
        indices=s.get("es_indices",[])
        if not indices:
            s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],"status":"skipped: Elasticsearch indices unavailable","returned":0})
            return
        indices=[name for name in indices if "host" in name.lower()] or indices
        fields=s.get("es_fields_by_class",{}).get("host") or s.get("es_fields",[])
        # Recipe fallbacks are hypothesis-wide searches. Do not constrain them
        # with the first arbitrary IPs from a large evidence collection; the
        # dynamic model queries carry explicit, validated anchors when a pivot
        # really should be entity-scoped.
        mission_range,mission_scope=self._time_scope(s)
        effective_range=mission_range; scope=mission_scope
        try:
            effective_range,anchor_scope=anchor_time_range(lead,_all_evidence(s),mission_range)
            scope=anchor_scope or mission_scope
        except ValueError as exc:
            s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],
                "status":f"skipped: {_safe_error_reason(exc)}","returned":0,"time_range":scope})
            return
        query=_lead_host_query(lead,fields,s.get("timestamp_field","@timestamp"),effective_range,{})
        if query is None:
            s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],
                "status":"skipped: hypothesis has no mapped host selectors","returned":0,"time_range":scope})
            return
        raw=self._call(s,"elasticsearch.search","iterative_host_pivot",{"lead_id":lead["id"],"indices":indices,"query":query,"size":min(500,self.settings.max_results)},
            scope,lambda:self.es.search_many(indices,query,min(500,self.settings.max_results)),lambda x:len(x.get("hits",[])))
        if raw is None:
            status="failed or budget prevented query"; count=0
        else:
            count=len(raw["hits"])
            for hit in raw["hits"]: self._add_es_hit(s,hit,query,lead["id"])
            status=_search_coverage(count,min(500,self.settings.max_results),scope)
        s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],"status":status,"returned":count,"time_range":scope})
        s["queries"].append({"stage":"iterative_host_pivot","lead_id":lead["id"],"query":query,"time_range":scope,"returned":count})

    def _network_pivot(self,s,lead):
        before=len(s.get("network",[])); details=[]
        mission_range,mission_scope=self._time_scope(s)
        effective_range=mission_range; scope=mission_scope
        try:
            effective_range,anchor_scope=anchor_time_range(lead,_all_evidence(s),mission_range)
            scope=anchor_scope or mission_scope
        except ValueError as exc:
            s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],
                "status":f"skipped: {_safe_error_reason(exc)}","returned":0,"sources":[]})
            return
        if lead.get("technique_id")=="T1105" or lead["id"]=="network_transfer_context":
            network_indices=[name for name in s.get("es_indices",[]) if "network" in name.lower()]
            indicator_events=[]
            for event in s.get("host",[]):
                raw_event=event.get("raw",{}) if isinstance(event.get("raw",{}),dict) else {}
                text=(event.get("observation","")+" "+json.dumps(raw_event,ensure_ascii=False)).lower()
                transfer_command=bool(re.search(r'\ba0=["\']?(?:wget|curl)["\']?',text))
                if any(x in text for x in ("linpeas","pwnkit","metadata.google.internal")) or (transfer_command and "motd.ubuntu.com" not in text):
                    indicator_events.append(event)
            windows_by_ip={}
            for event in indicator_events:
                for ip in _evidence_ips([event]): windows_by_ip.setdefault(ip,[]).append(event)
            if network_indices and windows_by_ip:
                fields=[f for f in ("message","source.ip","destination.ip","src_ip","dest_ip") if f in s.get("es_fields",[])] or ["message"]
                timestamp=s.get("timestamp_field","@timestamp"); size=min(500,self.settings.max_results)
                returned_total=0; failed_windows=[]; queried_windows=0; cap_hit=False
                for ip,events in windows_by_ip.items():
                    for cluster,bounds in _timestamp_clusters(events,gap_minutes=5,padding_minutes=2):
                        time_range=f"{bounds[0]} through {bounds[1]}"
                        ip_match={"bool":{"should":[{"match_phrase":{field:ip}} for field in fields],"minimum_should_match":1}}
                        query={"bool":{"must":[ip_match],"filter":[{"range":{timestamp:{"gte":bounds[0],"lte":bounds[1]}}}]}}
                        found=self._call(s,"elasticsearch.search","iterative_network_es_pivot",
                            {"lead_id":lead["id"],"indices":network_indices,"ip":ip,"fields":fields,"query":query,"size":size},
                            time_range,lambda q=query:self.es.search_many(network_indices,q,size),lambda x:len(x.get("hits",[])))
                        queried_windows+=1
                        if found is None: failed_windows.append(time_range); continue
                        hits=found.get("hits",[]); returned_total+=len(hits); cap_hit=cap_hit or len(hits)>=size
                        for hit in hits: self._add_es_hit(s,hit,query,lead["id"])
                        details.append({"source":"elasticsearch.network_index","ip":ip,"returned":len(hits),"time_range":time_range})
                        s["queries"].append({"stage":"iterative_network_es_pivot","lead_id":lead["id"],"ip":ip,
                            "time_range":time_range,"returned":len(hits)})
                coverage=f"searched {queried_windows} host-linked time window(s); returned {returned_total}"
                if cap_hit: coverage+="; result cap reached, additional records may exist"
                if failed_windows: coverage+=f"; {len(failed_windows)} window(s) failed"
                s.setdefault("coverage",{}).setdefault("network_sources",{})["elasticsearch"]=coverage
            else: details.append({"source":"elasticsearch.network_index","status":"skipped: no matching index, host IP, or event time"})
        if self.settings.arkime_username and self.settings.arkime_password:
            expression=_lead_network_expression(lead)
            ips=[ip for ip in lead.get("ips",[]) if isinstance(ip,str)]
            if ips: expression=f"({expression}) && ("+" || ".join(f"ip.src == {ip} || ip.dst == {ip}" for ip in ips[:4])+")"
            explicit=_explicit_dates(s["objective"]); start_ms,stop_ms=_arkime_time_window(s["objective"],self.settings.mission_timezone)
            anchored_bounds=_epoch_range(effective_range,1000) if lead.get("anchor_evidence_ids") else None
            if anchored_bounds: start_ms,stop_ms=anchored_bounds
            all_history=self.settings.historical_search and not explicit and not anchored_bounds
            raw=self._call(s,"arkime.api.sessions","iterative_network_pivot",{"lead_id":lead["id"],"expression":expression,
                "date":-1 if all_history else ("explicit" if explicit else self.settings.arkime_default_hours)},scope,
                lambda:self.arkime.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,length=min(100,self.settings.max_results),all_history=all_history),
                lambda x:len(x.get("sessions",[])))
            if raw is not None:
                added=self._add_arkime_rows(s,raw["sessions"],expression,scope,lead["id"])
                details.append({"source":"arkime","returned":len(raw["sessions"]),"added":added,"matched_total":raw.get("total"),"time_range":scope})
        if self.settings.pcap_files:
            display_filter=_lead_pcap_filter(lead); ips=[ip for ip in lead.get("ips",[]) if isinstance(ip,str)]
            if ips: display_filter="("+display_filter+") && ("+" || ".join(f"ip.addr == {ip}" if ":" not in ip else f"ipv6.addr == {ip}" for ip in ips[:4])+")"
            date_filter=(_pcap_range_filter(effective_range) if lead.get("anchor_evidence_ids")
                else _pcap_time_filter(_explicit_dates(s["objective"]),self.settings.mission_timezone))
            for pcap in self.settings.pcap_files[:3]:
                if not self._budget_ok(s): break
                raw=self._call(s,"tshark.read_pcap","iterative_pcap_pivot",{"lead_id":lead["id"],"pcap":str(pcap),"display_filter":display_filter},
                    "explicit mission dates; retained-match cap applies" if date_filter else "entire configured capture; retained-match cap applies",
                    lambda pcap=pcap:self.tshark.inspect(pcap,display_filter=display_filter,limit=min(500,self.settings.max_results),time_filter=date_filter),
                    lambda x:x.get("count",0))
                if raw is None: continue
                for row in raw["packets"]:
                    self._add_tshark_row(s,row,raw["provenance"],raw["provenance"]["display_filter"],lead["id"])
                details.append({"source":"tshark","pcap":str(pcap),"returned":raw["count"],
                    "matched_total":raw.get("matched_count"),"capped":bool(raw.get("output_capped")),
                    "time_range":raw["provenance"]["time_range"]})
        count=len(s.get("network",[]))-before
        s.setdefault("coverage",{})["network_count"]=len(s.get("network",[]))
        incomplete=any(bool(item.get("capped")) or (isinstance(item.get("matched_total"),(int,float))
            and int(item.get("matched_total"))>int(item.get("returned",0) or 0)) for item in details)
        pivot_status=("partial: configured network search reached a result cap" if incomplete else
            "queried configured network sources" if details else "no configured network source queried")
        s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],"status":pivot_status,
            "returned":count,"sources":details})
        s["queries"].append({"stage":"iterative_network_pivot","lead_id":lead["id"],"sources":details,"returned":count})

    def _report(self,s):
        if s.get("started_epoch"):
            s["duration_ms"]=max(0,round((time.time()-s["started_epoch"])*1000))
        errors=s.get("source_errors",[])
        telemetry_errors=[e for e in errors if str(e.get("tool","")).startswith(("elasticsearch.","arkime.","tshark."))]
        model_calls=[r for r in s.get("tool_runs",[]) if r.get("tool")=="ollama.api.chat"]
        model_failures=[r for r in model_calls if r.get("result_status")!="ok"]
        planning=s.get("coverage",{}).get("model_search_planning",[])
        s["coverage"]["analyst_model"]={"calls":len(model_calls),"failed_calls":len(model_failures),
            "search_plans_accepted":sum(x.get("accepted",0) for x in planning),
            "search_plans_rejected_or_duplicate":sum(x.get("rejected_or_duplicate",0) for x in planning),
            "model_findings":sum(1 for f in s.get("findings",[]) if "-AI-" in str(f.get("finding_id","")))}
        host_missing=not s.get("es_indices") and not self.offline
        network_missing=s["coverage"].get("network")=="not configured: Arkime and PCAP sources unavailable"
        missing_sources=host_missing or network_missing
        host_coverage=str(s.get("coverage",{}).get("host","" )).lower()
        network_coverage=str(s.get("coverage",{}).get("network","" )).lower()
        network_source_coverage=[str(value).lower() for value in s.get("coverage",{}).get("network_sources",{}).values()]
        coverage_limited=("result cap reached" in host_coverage or "cap reached" in network_coverage or
            any(("cap reached" in value or "reached by" in value) and "reached by 0" not in value
                for value in network_source_coverage))
        incomplete_coverage=coverage_limited or network_coverage.startswith("partial") or host_coverage.startswith("partial")
        ledger=s.get("coverage",{}).get("hypothesis_coverage",{})
        coverage_frontier_incomplete=bool(ledger) and not ledger.get("closure_ready",False)
        scheduler_incomplete=bool(s.get("coverage",{}).get("scheduler_gaps"))
        incomplete_coverage=incomplete_coverage or coverage_frontier_incomplete or scheduler_incomplete
        interrupted=s.get("termination_reason") in {"tool_call_budget","runtime_budget","depth_budget","workflow_error"}
        successful_search=any(r.get("result_status")=="ok" and any(x in str(r.get("reasoning_stage","")) for x in ("search","pivot")) for r in s.get("tool_runs",[]))
        if s.get("findings"):
            s["outcome"]="evidence_supported_lead"
            titles="; ".join(f.get("title","") for f in s["findings"][:3] if f.get("title"))
            s["summary"]=f"ROMULUS identified {len(s['findings'])} suspected investigative lead(s) supported by cited telemetry"+(f": {titles}." if titles else ".")+" These leads do not confirm compromise; review the evidence, benign alternatives, and follow-up actions in the report."
            if model_failures: s["summary"]+=f" {len(model_failures)} structured model call(s) failed; deterministic coverage searches were used and the investigation is partial."
            if incomplete_coverage: s["summary"]+=" Coverage is partial because a source cap, source error, or required hypothesis-coverage item remains unresolved."
        elif (telemetry_errors or model_failures) and not successful_search:
            s["outcome"]="failed_telemetry_retrieval"
            s["summary"]="Telemetry retrieval or model reasoning failed before enough evidence could be assessed. The hunt could not reliably assess whether suspicious activity occurred."
        elif interrupted or missing_sources or telemetry_errors or model_failures or incomplete_coverage:
            s["outcome"]="incomplete_investigation"
            s["summary"]="The investigation was incomplete because a configured source was unavailable, a result cap limited coverage, telemetry retrieval or model reasoning failed, or a resource limit stopped follow-up. No conclusion about the absence of suspicious activity is supported."
        elif not _all_evidence(s):
            s["outcome"]="no_suspicious_activity_identified_in_examined_evidence"
            s["summary"]="No suspicious activity was identified by the bounded searches of the configured telemetry. This result is limited to the recorded data, queries, retention, retained packet output, and tool timeouts; it is not evidence that the environment is clean."
        else:
            s["outcome"]="insufficient_evidence"
            s["summary"]="The retrieved evidence was insufficient to support or reject the investigated hypotheses. No finding is not a clean bill of health; review source coverage, query scope, and follow-up needs."
        if telemetry_errors or model_failures or interrupted or missing_sources or incomplete_coverage: s["status"]="partial"
        else: s["status"]="completed"
        if not s.get("termination_reason"):
            s["termination_reason"]="lead_queue_exhausted" if not s.get("lead_queue") else "resource_limit"
        s["coverage"]["tool_calls_used"]=s.get("tool_calls",0)
        s["coverage"]["tool_call_limit"]=self.settings.max_tool_calls
        s["coverage"]["depth_used"]=s.get("depth",0)
        s["coverage"]["depth_limit"]=self.settings.max_depth
        s["coverage"]["minimum_reasoning_rounds"]=self.settings.min_reasoning_rounds
        s["coverage"]["termination_reason"]=s["termination_reason"]
        s["coverage"]["source_error_count"]=len(errors)
        s["coverage"]["coverage_closure_ready"]=not coverage_frontier_incomplete
        _attach_finding_paths(s)
        try:
            from ..reporting.report import generate_report
            s["report_paths"]=[str(p) for p in generate_report(s,self.settings.reports_dir)]
        except Exception as e:
            s["status"]="partial"; s["error"]=(s.get("error","")+f" Report generation failed: {type(e).__name__}: {str(e)[:150]}").strip()
        self._stage(s,"report","completed" if s.get("report_paths") else "failed",{"outcome":s.get("outcome"),"termination_reason":s.get("termination_reason")})
        print(f"[ROMULUS] termination={s['termination_reason']} outcome={s['outcome']} tools={s.get('tool_calls',0)}")
        return self._save(s)

    def _summarize(self,objective,observations):
        from ..agent.ollama import Ollama
        return Ollama(self.settings).summarize(objective,observations)


def _attach_finding_paths(state):
    graph=state.setdefault("investigation_graph",{"version":1,"nodes":[],"edges":[],"paths":[],"summary":{}})
    paths=derive_finding_paths(graph,state.get("findings",[]))
    graph["paths"]=paths
    path_ids_by_finding={}
    for path in paths:
        path_ids_by_finding.setdefault(path["finding_id"],[]).append(path["path_id"])
    for finding in state.get("findings",[]):
        finding["attack_path_ids"]=path_ids_by_finding.get(finding.get("finding_id"),[])
    return state


def _normalize_hypotheses(values):
    if not isinstance(values,list): return []
    out=[]
    for item in values[:20]:
        if not isinstance(item,dict): continue
        title=_clean_string(item.get("title"),140)
        rationale=_clean_string(item.get("rationale"),500)
        if len(title)<5 or len(rationale)<10: continue
        technique=item.get("technique_id")
        if technique not in TECHNIQUES: technique="unmapped"
        meta=TECHNIQUES.get(technique,{})
        def strings(key,limit=8): return _clean_string_list(item.get(key),limit,140)
        benign=_clean_string_list(item.get("benign_explanations"),6,180) or ["authorized administration or expected application activity"]
        priority=item.get("priority") if isinstance(item.get("priority"),int) and 1<=item["priority"]<=5 else 3
        hypothesis=Hypothesis("H-AI-"+f"{len(out)+1:02d}",title,technique,rationale,
            strings("expected_host") or meta.get("host",[]),strings("expected_network") or meta.get("network",[]),benign,
            tactics=meta.get("tactics",[]),detection_strategies=meta.get("detection_strategies",[]),
            data_components=strings("required_data_components",6) or meta.get("data_components",[]),
            analytic_goal=_clean_string(item.get("analytic_goal"),400) or meta.get("analytic_goal",""),
            mutable_elements=meta.get("mutable_elements",[]),priority=priority)
        out.append(encode(hypothesis))
    return out


def _mission_is_directed(objective):
    """Return true only when the operator supplied a concrete hunt direction.

    A time range or a generic request to find threats scopes discovery but is
    not evidence for any attack hypothesis. Specific entities, indicators,
    ATT&CK IDs, protocols, tools, event IDs, or technique language are valid
    operator direction.
    """
    text=str(objective or "").strip().lower()
    if not text: return False
    if re.search(r"\bT\d{4}(?:\.\d{3})?\b",str(objective or ""),flags=re.IGNORECASE): return True
    if re.search(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])",text): return True
    if re.search(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b",text): return True
    if re.search(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|mil|gov|io|co|local)\b",text): return True
    explicit_terms={
        "powershell","encoded command","command shell","smb","rdp","winrm","dcom","ssh","vnc",
        "lateral movement","credential access","credential dumping","brute force","password spray",
        "service creation","scheduled task","persistence","privilege escalation","defense evasion",
        "data exfiltration","exfiltration","command and control","c2","dns tunneling","beaconing",
        "port scan","port scanning","network scan","reconnaissance","remote execution","ransomware",
        "mimikatz","psexec","wmi","certutil","bitsadmin","wget","curl","linpeas","pwnkit",
    }
    if any(re.search(r"(?<![a-z0-9_])"+re.escape(term)+r"(?![a-z0-9_])",text) for term in explicit_terms): return True
    if _has_concrete_entity_direction(text): return True
    return False


def _has_concrete_entity_direction(text):
    """Recognize typed targets without treating telemetry-scope prose as a target."""
    entity_key=r"(?P<key>event(?:\s+id)?|port|process|user|account|host|hostname|hash|indicator|ioc)"
    value=r"(?P<value>[\w./\\-]{2,})"
    matches=list(re.finditer(rf"\b{entity_key}\s*(?:=|:)\s*{value}\b",text))
    matches.extend(re.finditer(rf"\b{entity_key}\s+(?P<quote>['\"]){value}(?P=quote)",text))
    directive=(r"(?:investigate|inspect|analy[sz]e|check|examine|review|target|find|"
        r"focus(?:ing)?\s+on|look(?:ing)?\s+(?:at|into|for)|hunt(?:ing)?\s+for|search(?:ing)?(?:\s+for)?|involving|involves)")
    target=rf"(?:activity\s+)?(?:(?:on|from|for|involving)\s+)?(?:the\s+)?{entity_key}\s+(?:is\s+)?{value}\b"
    matches.extend(re.finditer(rf"\b{directive}\s+{target}",text))
    matches.extend(re.finditer(rf"^{target}",text))
    for match in re.finditer(rf"\b{entity_key}\s+(?:is\s+)?{value}\b",text):
        candidate=match.group("value")
        if any(character.isdigit() or character in "./\\-" for character in candidate):
            matches.append(match)
    scope_words={
        "access","accounts","activity","all","and","are","available","behavior","behaviors",
        "command","connected","connecting","connection","connections","data","environment","environments",
        "events","execution","field","fields","for","from","internal","local","log","login","logins",
        "logs","machines","malicious","monitored","network","networks","on","or","processes","remote",
        "scanning","scope","suspicious","systems","telemetry","traffic","unknown","unusual","usage","was",
        "with","without",
    }
    for match in matches:
        key=" ".join(match.group("key").split())
        candidate=match.group("value").lower()
        if candidate in scope_words: continue
        if key=="port" and (not candidate.isdigit() or not 1<=int(candidate)<=65535): continue
        if key.startswith("event") and not any(character.isdigit() for character in candidate): continue
        return True
    return False


def _state_mission_mode(state):
    """Recover legacy/checkpointed state without ever failing open to directed mode."""
    mode=state.get("mission_mode")
    if mode not in {"directed","undirected"}:
        mode="directed" if _mission_is_directed(state.get("objective","")) else "undirected"
        state["mission_mode"]=mode
    return mode


def _candidate_hypotheses(candidates,existing,evidence=None):
    """Create bounded hypotheses only from deterministic candidates with citations."""
    existing_candidates={candidate_id for hypothesis in existing for candidate_id in hypothesis.get("basis_candidate_ids",[])}
    out=[]
    for candidate in candidates:
        candidate_id=candidate.get("candidate_id")
        evidence_ids=[str(value) for value in candidate.get("evidence_ids",[]) if value]
        score=int(candidate.get("priority_score",0) or 0)
        if not candidate_id or candidate_id in existing_candidates or not evidence_ids: continue
        if score<40 and candidate.get("kind")!="trusted_indicator": continue
        technique=next((value for value in candidate.get("attack_techniques",[]) if value in TECHNIQUES),"unmapped")
        meta=TECHNIQUES.get(technique,{})
        asset=next(iter(candidate.get("assets",[]) or []),"unknown asset")
        cited=set(evidence_ids)
        cited_events=[event for event in (evidence or []) if event.get("evidence_id") in cited]
        assets=[str(value) for value in candidate.get("assets",[]) if value and str(value)!="unknown"][:8]
        for event in cited_events:
            value=str(event.get("asset") or "")
            if value and value!="unknown" and value not in assets: assets.append(value)
        assets=assets[:8]
        ips=[]; hostnames=[]
        for value in assets:
            try: ipaddress.ip_address(value); ips.append(value)
            except ValueError: hostnames.append(value)
        for value in _evidence_ips(cited_events):
            if value not in ips: ips.append(value)
        priority=5 if score>=90 else (4 if score>=70 else 3)
        identifier="H-CAND-"+str(candidate_id).replace("CL-","")[:18]
        title=f"Investigate {candidate.get('title','observed behavior')} on {asset}"[:140]
        rationale=(f"Deterministic candidate {candidate_id} scored {score}/100 and cites "
            f"{len(evidence_ids)} retained telemetry record(s); the behavior still requires benign-alternative testing.")
        hypothesis=encode(Hypothesis(identifier,title,technique,rationale,
            meta.get("host",[]) or (["Review cited host behavior and adjacent process/account activity."] if candidate.get("kind")=="behavior" else []),
            meta.get("network",[]) or ["Review cited entity across network telemetry and adjacent time windows."],
            candidate.get("benign_explanations",[]) or ["authorized administration or expected application activity"],
            tactics=meta.get("tactics",[]),detection_strategies=meta.get("detection_strategies",[]),
            data_components=meta.get("data_components",[]),analytic_goal=meta.get("analytic_goal",candidate.get("description","")),
            mutable_elements=meta.get("mutable_elements",[]),priority=priority))
        hypothesis.update({"basis":"observed_candidate","basis_candidate_ids":[candidate_id],
            "basis_evidence_ids":evidence_ids[:20],"candidate_evidence_ids":evidence_ids[:20],
            "candidate_id":candidate_id,"follow_ups":candidate.get("follow_ups",[]),
            "candidate_assets":assets,"ips":ips,"hostnames":hostnames,
            "status":"untested","confidence":"not assessed"})
        out.append(hypothesis); existing_candidates.add(candidate_id)
        if len(out)>=8: break
    return out


def _clean_string(value,limit):
    return re.sub(r"\s+"," ",value).strip()[:limit] if isinstance(value,str) else ""


def _clean_string_list(value,limit,item_limit):
    if not isinstance(value,list): return []
    return list(dict.fromkeys(_clean_string(x,item_limit) for x in value if isinstance(x,str) and _clean_string(x,item_limit)))[:limit]


def _lead_catalog(hypotheses):
    out=[]; seen=set()
    for hypothesis in hypotheses:
        tid=hypothesis.get("technique_id"); meta=TECHNIQUES.get(tid,{})
        sources=[]
        if hypothesis.get("expected_host") or meta.get("host"): sources.append("host")
        if hypothesis.get("expected_network") or meta.get("network") or meta.get("ports") or meta.get("protocols"): sources.append("network")
        if not sources: sources=["host"]
        follow_ups=hypothesis.get("follow_ups",[]) or []
        for source_index,source in enumerate(sources):
            ident=_coverage_lead_id(hypothesis.get("hypothesis_id"),source)
            why=(hypothesis.get("analytic_goal") or meta.get("analytic_goal") or
                 f"Test {hypothesis.get('title','this hypothesis')} in available {source} telemetry.")
            follow_up=follow_ups[min(source_index,len(follow_ups)-1)] if follow_ups else {}
            intent=follow_up.get("intent") or why
            if ident not in seen:
                seen.add(ident); out.append({"id":ident,"source":source,"title":hypothesis.get("title") or ident,
                    "why":why,"intent":intent,"hypothesis_id":hypothesis.get("hypothesis_id"),"technique_id":tid,
                    "candidate_id":hypothesis.get("candidate_id"),
                    "follow_up_id":follow_up.get("follow_up_id"),
                    "anchor_evidence_ids":list(hypothesis.get("basis_evidence_ids",[]))[:8],
                    "ips":list(hypothesis.get("ips",[]))[:8],"hostnames":list(hypothesis.get("hostnames",[]))[:8],
                    "priority":hypothesis.get("priority",3),
                    "tactics":hypothesis.get("tactics") or meta.get("tactics",[])})
    return out


def _link_candidates_to_findings(s):
    findings=s.get("findings",[])
    for candidate in s.get("candidate_leads",[]):
        evidence_ids=set(candidate.get("evidence_ids",[]))
        linked=[finding.get("finding_id") for finding in findings
                if finding.get("finding_id") and evidence_ids.intersection(finding.get("evidence_ids",[]))]
        if linked:
            candidate["finding_ids"]=list(dict.fromkeys(candidate.get("finding_ids",[])+linked))
            candidate["disposition"]="corroborated"


def _record_candidate_follow_up(s,lead,result):
    candidate_id=lead.get("candidate_id") if isinstance(lead,dict) else None
    follow_up_id=lead.get("follow_up_id") if isinstance(lead,dict) else None
    if not candidate_id or not follow_up_id: return
    status=str(result.get("status") or "attempted")
    failed=any(token in status.lower() for token in (
        "failed","skipped","budget","no configured","rejected","error","partial","cap reached"))
    for candidate in s.get("candidate_leads",[]):
        if candidate.get("candidate_id")!=candidate_id: continue
        if candidate.get("disposition")=="observed": candidate["disposition"]="investigating"
        for follow_up in candidate.get("follow_ups",[]):
            if follow_up.get("follow_up_id")!=follow_up_id: continue
            follow_up.setdefault("history",[]).append({"timestamp":utc_now(),"search_id":lead.get("id"),
                "status":status,"returned":result.get("returned",0)})
            required={item.get("id") for item in s.get("lead_catalog",[])
                if item.get("candidate_id")==candidate_id and item.get("follow_up_id")==follow_up_id and item.get("id")}
            latest={}
            for entry in follow_up.get("history",[]):
                if entry.get("search_id") in required: latest[entry["search_id"]]=entry
            successful={search_id for search_id,entry in latest.items()
                if not any(token in str(entry.get("status","")).lower()
                    for token in ("failed","skipped","budget","no configured","rejected","error","partial","cap reached"))}
            if required and required <= successful:
                follow_up["status"]="completed"
            elif failed:
                follow_up["status"]="blocked"
            else:
                follow_up["status"]="in_progress"


def _query_terms(technique_ids):
    terms=[]; codes=[]
    for tid in technique_ids:
        meta=TECHNIQUES.get(tid,{})
        terms.extend(meta.get("terms",[])); codes.extend(meta.get("event_codes",[]))
    return list(dict.fromkeys(terms)),list(dict.fromkeys(codes))


def _coverage_lead_id(hypothesis_id,source):
    clean=re.sub(r"[^A-Za-z0-9-]+","-",str(hypothesis_id or "GENERAL")).strip("-")[:48]
    return f"C-{clean}-{source.upper()}"


def _host_survey_queries(hypotheses,fields,timestamp_field,time_range,objective,limit=10):
    """Build tactic-diverse bounded surveys instead of one cap-filling OR query."""
    ordered=sorted(hypotheses,key=lambda h:-int(h.get("priority",3) or 3))
    selected=[]; seen_tactics=set()
    for hypothesis in ordered:
        tid=hypothesis.get("technique_id")
        if tid not in TECHNIQUES: continue
        tactics=tuple(hypothesis.get("tactics") or TECHNIQUES[tid].get("tactics",[]))
        family=tactics[0] if tactics else tid
        if family in seen_tactics: continue
        seen_tactics.add(family); selected.append(hypothesis)
        if len(selected)>=limit: break
    for hypothesis in ordered:
        if len(selected)>=limit: break
        if hypothesis not in selected and hypothesis.get("technique_id") in TECHNIQUES: selected.append(hypothesis)
    if not selected: selected=hypotheses[:1]
    return [{"hypothesis_id":h.get("hypothesis_id"),"technique_id":h.get("technique_id"),
             "lead_id":_coverage_lead_id(h.get("hypothesis_id"),"host"),
             "query":_host_query([h],fields,timestamp_field,time_range,objective)} for h in selected]


def _host_query(hypotheses,fields,timestamp_field,time_range,objective,lead_id=None,state=None):
    ids=[h.get("technique_id") for h in hypotheses]
    if lead_id:
        ids={"host_auth_service":["T1021.002"],"host_failed_logons":["T1110"],"host_powershell":["T1059.001"],"host_service_install":["T1543.003"],"host_transfer_tools":["T1105"]}.get(lead_id,ids)
    terms,codes=_query_terms(ids)
    text_fields=[f for f in ("message","event.original","winlog.event_data.SubjectUserName","winlog.event_data.CommandLine","process.name","process.command_line","dns.question.name") if f in fields]
    if not text_fields: text_fields=["message"]
    code_fields=[f for f in ("event.code","winlog.event_id","event.id") if f in fields]
    should=[{"match_phrase":{field:term}} for term in terms[:8] for field in text_fields[:4]]
    if codes and code_fields: should.extend({"terms":{field:codes}} for field in code_fields)
    if not should:
        fallback=_clean_string(objective,50)
        if not fallback: return None
        should=[{"match":{"message":fallback}}]
    body={"should":should,"minimum_should_match":1}
    query={"bool":{"must":[{"bool":body}]}}
    if time_range: query["bool"]["filter"]=[{"range":{timestamp_field:time_range}}]
    if lead_id and state:
        ips=_evidence_ips(state.get("network",[]))
        ip_fields=[f for f in ("source.ip","destination.ip","host.ip","winlog.event_data.IpAddress") if f in fields]
        if ips and ip_fields:
            query["bool"].setdefault("filter",[]).append({"bool":{"should":[{"terms":{field:ips}} for field in ip_fields],"minimum_should_match":1}})
    return query


def _lead_host_query(lead,fields,timestamp_field,time_range,state):
    lead_id=lead.get("id","") if isinstance(lead,dict) else str(lead)
    legacy={"host_auth_service":"T1021.002","host_failed_logons":"T1110","host_powershell":"T1059.001",
            "host_service_install":"T1543.003","host_transfer_tools":"T1105"}
    technique=lead.get("technique_id") if isinstance(lead,dict) else None
    hypothesis=[{"technique_id":technique or legacy.get(lead_id,"T1021.002")}]
    query=_host_query(hypothesis,fields,timestamp_field,time_range,"",lead_id,state)
    if not isinstance(lead,dict): return query
    selectors=[]
    ips=[value for value in lead.get("ips",[]) if isinstance(value,str)]
    hostnames=[value for value in lead.get("hostnames",[]) if isinstance(value,str)]
    ip_fields=[field for field in ("source.ip","destination.ip","host.ip","winlog.event_data.IpAddress") if field in fields]
    host_fields=[field for field in ("host.name","host.hostname","computer_name","winlog.computer_name") if field in fields]
    selectors.extend({"terms":{field:ips[:8]}} for field in ip_fields if ips)
    selectors.extend({"terms":{field:hostnames[:8]}} for field in host_fields if hostnames)
    if query is None and selectors:
        query={"bool":{}}
        if time_range: query["bool"]["filter"]=[{"range":{timestamp_field:time_range}}]
    if query is None: return None
    if selectors:
        query["bool"].setdefault("filter",[]).append({"bool":{"should":selectors,"minimum_should_match":1}})
    return query


def _field_names(mapping):
    fields=set()
    def walk(props,prefix=""):
        for name,desc in props.items():
            full=(prefix+"."+name).strip("."); fields.add(full)
            if isinstance(desc,dict) and isinstance(desc.get("properties"),dict): walk(desc["properties"],full)
    for entry in mapping.values(): walk(entry.get("mappings",{}).get("properties",{}))
    return sorted(fields)


def _field_names_by_class(mapping):
    grouped={"host":set(),"network":set(),"other":set()}
    for name,entry in mapping.items():
        lower=str(name).lower()
        fields=set(_field_names({name:entry}))
        host_score=sum(field in fields for field in ("process.name","process.command_line","winlog.event_id","event.code","user.name","host.name"))
        network_score=sum(field in fields for field in ("source.ip","destination.ip","source.port","destination.port","network.protocol","dns.question.name","http.request.method"))
        category="network" if "network" in lower else ("host" if "host" in lower else
            ("network" if network_score>host_score else ("host" if host_score else "other")))
        grouped[category].update(fields)
    return {key:sorted(value) for key,value in grouped.items() if value}


def _search_history_summary(s):
    """Return scheduler intent and exact outcomes without raw response bodies."""
    tasks=s.get("search_tasks",{}) if isinstance(s.get("search_tasks"),dict) else {}
    outcomes={item.get("task_id"):item for item in s.get("search_outcomes",[]) if item.get("task_id")}
    out=[]
    for task_id,task in tasks.items():
        result=outcomes.get(task_id)
        if not result: continue
        out.append({"task_id":task_id,"source":task.get("source"),"intent":task.get("intent"),
            "origins":task.get("origins",[]),"hypothesis_ids":task.get("hypothesis_ids",[]),
            "status":result.get("status"),"returned":result.get("returned_total",0),
            "matched_total":result.get("matched_total"),"time_range":task.get("time_range",{})})
    return out[-20:]


def _all_evidence(s):
    """Return the bounded graph context; complete evidence stays in Store."""
    combined=list(s.get("host",[]))+list(s.get("network",[]))
    return combined or list(s.get("evidence",[]))


def _coverage_fallback(s,limit=3,exclude=None):
    """Choose unexecuted hypothesis analytics by marginal coverage value."""
    if limit<=0: return []
    exclude=set(exclude or ())
    completed=set(s.get("completed_leads",[])) | exclude
    ledger={x.get("hypothesis_id"):x for x in s.get("coverage",{}).get("hypothesis_coverage",{}).get("rows",[])}
    candidates=[]
    for position,lead in enumerate(s.get("lead_catalog",[])):
        if lead.get("fingerprint") or lead.get("id") in completed: continue
        hid=lead.get("hypothesis_id"); row=ledger.get(hid,{})
        tested=int(row.get("executed_analytics",0) or 0)
        priority=int(lead.get("priority",3) or 3)
        candidates.append((tested,-priority,position,lead))
    candidates.sort(key=lambda item:item[:3])
    selected=[]; used_tactics=set(); used_sources=set()
    for _,_,_,lead in candidates:
        tactics=tuple(lead.get("tactics") or ())
        family=tactics[0] if tactics else lead.get("technique_id")
        # First pass rewards a new tactic or source. A second pass below fills
        # remaining slots, so systematic coverage never deadlocks on diversity.
        if family in used_tactics and lead.get("source") in used_sources: continue
        selected.append(lead["id"]); used_tactics.add(family); used_sources.add(lead.get("source"))
        if len(selected)>=limit: return selected
    for _,_,_,lead in candidates:
        if lead["id"] not in selected:
            selected.append(lead["id"])
            if len(selected)>=limit: break
    return selected


def _safe_error_reason(exc):
    """Keep bounded, actionable error detail without recording response bodies."""
    if isinstance(exc,ValueError): return str(exc)[:180]
    name=type(exc).__name__
    if name in {"ConnectTimeout","ReadTimeout","Timeout"}: return "source request timed out"
    if name in {"ConnectionError","NewConnectionError","ConnectError"}: return "source connection failed"
    body=getattr(getattr(exc,"meta",None),"body",None) or getattr(exc,"body",None)
    error=body.get("error",{}) if isinstance(body,dict) else {}
    causes=error.get("root_cause",[]) if isinstance(error,dict) else []
    reason=causes[0].get("reason","") if causes and isinstance(causes[0],dict) else (error.get("reason","") if isinstance(error,dict) else "")
    if isinstance(reason,str):
        mismatch=re.search(r"not on \[([A-Za-z0-9_.-]+)\].{0,80}?type \[([A-Za-z0-9_-]+)\]",reason,re.I)
        if mismatch: return f"Elasticsearch text selector used on non-text field {mismatch.group(1)} ({mismatch.group(2)})"
        unmapped=re.search(r"No mapping found for \[([A-Za-z0-9_.-]+)\]",reason,re.I)
        if unmapped: return f"Elasticsearch field is unmapped: {unmapped.group(1)}"
        if "all shards failed" in reason.lower(): return "Elasticsearch rejected the query on all shards"
    return name


def _event_description(row):
    return " ".join(f"{k}={v}" for k,v in list(row.items())[:18] if not str(k).startswith("_"))[:1200]


def _evidence_key(item):
    source=str(item.get("source") or "unknown")
    provenance=item.get("provenance",{}) if isinstance(item.get("provenance"),dict) else {}
    raw=item.get("raw",{}) if isinstance(item.get("raw"),dict) else {}
    if source=="elasticsearch" and provenance.get("index") and provenance.get("document_id"):
        return f"es:{provenance['index']}:{provenance['document_id']}"
    if source=="arkime" and provenance.get("session_id"):
        return f"arkime:{provenance['session_id']}"
    if source=="tshark" and provenance.get("pcap") and raw.get("frame.number"):
        return f"pcap:{provenance['pcap']}:{raw['frame.number']}"
    stable={"source":source,"observed_at":item.get("observed_at"),"asset":item.get("asset"),"raw":raw}
    return "row:"+hashlib.sha1(json.dumps(stable,sort_keys=True,default=str).encode("utf-8",errors="replace")).hexdigest()


def _bounded(value,depth=0):
    if depth>5: return "[truncated]"
    if isinstance(value,dict): return {str(k)[:100]:_bounded(v,depth+1) for k,v in list(value.items())[:40]}
    if isinstance(value,list): return [_bounded(x,depth+1) for x in value[:40]]
    if isinstance(value,str): return value[:2000]
    return value


def _context_raw(raw):
    """Keep model/checkpoint context compact; complete evidence stays in SQLite."""
    if not isinstance(raw,dict): return {}
    exact={"message","event.original","event.action","event.dataset","event.category","event.code","event.id",
        "process.name","process.command_line","process.executable","process.parent.name","user.name","host.name","host.ip",
        "source.ip","destination.ip","source.port","destination.port","network.protocol","network.transport",
        "dns.question.name","dns.qry.name","dns.host","http.host","host.http","http.uri","http.request.uri","http.user-agent",
        "tls.handshake.extensions_server_name","frame.number","frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport",
        "udp.srcport","udp.dstport","smb2.cmd","smb2.filename","srcIp","dstIp","srcPort","dstPort","firstPacket","lastPacket",
        "network.bytes","network.packets","ipProtocol"}
    prefixes=("winlog.event_data.",)
    out={}
    for key,value in raw.items():
        if key in exact or any(str(key).startswith(prefix) for prefix in prefixes) or key in {"event","process","user","host","source","destination","network","winlog","dns","http","tls"}:
            out[key]=_bounded(value)
        if len(out)>=32: break
    return out


def _nested(obj,path):
    value=obj
    for part in path.split("."):
        if not isinstance(value,dict): return None
        value=value.get(part)
    return value


def _as_iso(value):
    try:
        number=float(value)
        if number>10_000_000_000: number/=1000
        if number>0: return datetime.fromtimestamp(number,tz=timezone.utc).isoformat(timespec="seconds")
    except (ValueError,TypeError,OSError,OverflowError): pass
    try:
        dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError,TypeError): return str(value)


def _explicit_dates(objective):
    return re.findall(r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?\b",objective)


def _validate_explicit_date_order(objective,time_zone="UTC"):
    dates=_explicit_dates(objective)
    if len(dates)<2: return
    try: start,end=_explicit_datetime(dates[0],False,time_zone),_explicit_datetime(dates[1],True,time_zone)
    except (ValueError,ZoneInfoNotFoundError) as exc: raise ValueError("Mission contains an invalid ISO date, time, or configured timezone") from exc
    if end<start: raise ValueError(f"End of requested time range ({dates[1]}) precedes its start ({dates[0]}); correct the mission dates before starting the hunt")


def _indicator_terms(objective):
    """Return a bounded, read-only indicator sweep for transfer-oriented missions."""
    text=objective.lower()
    catalog=("linpeas","linenum","wget","curl","meterpreter","pwnkit","certutil","bitsadmin")
    terms=[term for term in catalog if re.search(r"(?<![a-z0-9_])"+re.escape(term)+r"(?![a-z0-9_])",text)]
    if any(word in text for word in ("download","outbound","payload","transfer","http","https","new connection")):
        terms.extend(catalog[:6])
    return list(dict.fromkeys(terms))[:8]


def _within_minutes(left,right,minutes):
    try:
        a=datetime.fromisoformat(str(left).replace("Z","+00:00")); b=datetime.fromisoformat(str(right).replace("Z","+00:00"))
        if a.tzinfo is None: a=a.replace(tzinfo=timezone.utc)
        if b.tzinfo is None: b=b.replace(tzinfo=timezone.utc)
        return abs((a-b).total_seconds())<=minutes*60
    except (ValueError,TypeError,OverflowError): return False


def _timestamp_bounds(events,padding_minutes=0):
    stamps=[]
    for event in events:
        try:
            value=event.get("observed_at")
            if not value: continue
            stamp=datetime.fromisoformat(str(value).replace("Z","+00:00"))
            if stamp.tzinfo is None: stamp=stamp.replace(tzinfo=timezone.utc)
            stamps.append(stamp.astimezone(timezone.utc))
        except (ValueError,TypeError,OverflowError): continue
    if not stamps: return None
    pad=timedelta(minutes=padding_minutes)
    return (min(stamps)-pad).isoformat(timespec="seconds"),(max(stamps)+pad).isoformat(timespec="seconds")


def _timestamp_clusters(events,gap_minutes=5,padding_minutes=2):
    rows=[]
    for event in events:
        try:
            value=event.get("observed_at")
            if not value: continue
            stamp=datetime.fromisoformat(str(value).replace("Z","+00:00"))
            if stamp.tzinfo is None: stamp=stamp.replace(tzinfo=timezone.utc)
            rows.append((stamp.astimezone(timezone.utc),event))
        except (ValueError,TypeError,OverflowError): continue
    rows.sort(key=lambda item:item[0]); clusters=[]
    for stamp,event in rows:
        if not clusters or (stamp-clusters[-1][-1][0]).total_seconds()>gap_minutes*60: clusters.append([])
        clusters[-1].append((stamp,event))
    pad=timedelta(minutes=padding_minutes)
    result=[]
    for cluster in clusters:
        bounds=((cluster[0][0]-pad).isoformat(timespec="seconds"),(cluster[-1][0]+pad).isoformat(timespec="seconds"))
        result.append(([event for _,event in cluster],bounds))
    return result


def _event_text(event):
    raw=event.get("raw",{}) if isinstance(event.get("raw",{}),dict) else {}
    parts=[str(event.get("observation","")),str(raw.get("message","")),json.dumps(raw,ensure_ascii=False)]
    return " ".join(parts).lower()


def _indicator_query(terms,fields,timestamp_field=None,time_range=None):
    usable=fields or ["message"]
    query={"bool":{"should":[{"match_phrase":{field:term}} for term in terms for field in usable],"minimum_should_match":1}}
    if timestamp_field and time_range: query["bool"]["filter"]=[{"range":{timestamp_field:time_range}}]
    return query


def _date_scope(dates,time_zone="UTC"):
    suffix=f" ({time_zone} for timestamps without an offset)" if any(_is_naive_explicit(value) for value in dates) else ""
    return f"{dates[0]} through {dates[1] if len(dates)>1 else 'current time'}{suffix}"


def _time_filter(objective,lookback_hours,time_zone="UTC"):
    found=_explicit_dates(objective)
    if len(found)>=2: return {"gte":_explicit_iso(found[0],False,time_zone),"lte":_explicit_iso(found[1],True,time_zone)}
    if found: return {"gte":_explicit_iso(found[0],False,time_zone),"lte":"now"}
    return {"gte":f"now-{lookback_hours}h","lte":"now"}


def _arkime_time_window(objective,time_zone="UTC"):
    found=_explicit_dates(objective)
    if not found: return None,None
    try:
        now=int(datetime.now(timezone.utc).timestamp()*1000)
        return _explicit_epoch(found[0],False,1000,time_zone),_explicit_epoch(found[1],True,1000,time_zone) if len(found)>1 else now
    except (ValueError,OverflowError): return None,None


def _pcap_time_filter(dates,time_zone="UTC"):
    if not dates: return ""
    try:
        start=_explicit_epoch(dates[0],False,1,time_zone); end=_explicit_epoch(dates[1],True,1,time_zone) if len(dates)>1 else time.time()
        return f"frame.time_epoch >= {start:.3f} && frame.time_epoch <= {end:.3f}"
    except (ValueError,OverflowError): return ""


def _epoch_range(time_range,multiplier=1):
    if not isinstance(time_range,dict): return None
    try:
        values=[]
        for key in ("gte","lte"):
            value=time_range.get(key)
            if not isinstance(value,str) or value.startswith("now"): return None
            parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
            if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
            values.append(parsed.astimezone(timezone.utc).timestamp()*multiplier)
        return tuple(int(value) if multiplier!=1 else float(value) for value in values)
    except (ValueError,TypeError,OverflowError): return None


def _pcap_range_filter(time_range):
    bounds=_epoch_range(time_range,1)
    return (f"frame.time_epoch >= {bounds[0]:.3f} && frame.time_epoch <= {bounds[1]:.3f}"
        if bounds else "")


def _arkime_expression(objective,hypotheses):
    ids={h.get("technique_id") for h in hypotheses}; text=objective.lower(); clauses=[]
    if _is_broad_objective(text):
        return "protocols == tcp || protocols == udp || protocols == icmp"
    remote_ids={"T1021.001","T1021.002","T1021.003","T1021.004","T1021.006","T1047","T1569.002"}
    if ids & remote_ids or any(x in text for x in ("smb","lateral movement","remote service","445","rdp","ssh","winrm")):
        clauses.append("port == 445 || port == 139 || port == 3389 || port == 22 || port == 5985 || port == 5986 || port == 135 || port == 5900")
    elif "T1110" in ids: clauses.append("port == 3389 || port == 22 || port == 5985 || port == 5986")
    if "T1071.001" in ids or any(x in text for x in ("dns","http","command and control","c2")): clauses.append("protocols == dns || protocols == http")
    return " || ".join(dict.fromkeys(clauses)) or "protocols == tcp"


def _arkime_indicator_expressions(terms):
    variants={"linpeas":("linpeas","LinPEAS"),"linenum":("linenum","LinEnum"),
        "wget":("wget","Wget"),"curl":("curl","Curl"),
        "meterpreter":("meterpreter","Meterpreter"),"pwnkit":("pwnkit","PwnKit"),
        "certutil":("certutil","CertUtil"),"bitsadmin":("bitsadmin","BITSAdmin")}
    groups=[terms[i:i+3] for i in range(0,min(len(terms),8),3)]
    expressions=[]
    for group in groups:
        clauses=[]
        for term in group:
            for variant in variants.get(term,(term,)):
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}",variant): continue
                clauses.extend((f"http.uri == *{variant}*",f"http.user-agent == *{variant}*"))
        if clauses: expressions.append("protocols == http && ("+" || ".join(clauses)+")")
    return expressions or ["protocols == http"]


def _is_naive_explicit(value):
    try: return datetime.fromisoformat(value.replace("Z","+00:00")).tzinfo is None
    except ValueError: return False


def _explicit_datetime(value,end_of_day=False,time_zone="UTC"):
    if end_of_day and re.fullmatch(r"\d{4}-\d{2}-\d{2}",value):
        dt=datetime.fromisoformat(value).replace(hour=23,minute=59,second=59,microsecond=999000)
    else:
        dt=datetime.fromisoformat(value.replace("Z","+00:00"))
    if dt.tzinfo is None: dt=dt.replace(tzinfo=ZoneInfo(time_zone))
    return dt.astimezone(timezone.utc)


def _explicit_iso(value,end_of_day=False,time_zone="UTC"):
    return _explicit_datetime(value,end_of_day,time_zone).isoformat(timespec="milliseconds").replace("+00:00","Z")


def _explicit_epoch(value,end_of_day=False,scale=1,time_zone="UTC"):
    return _explicit_datetime(value,end_of_day,time_zone).timestamp()*scale


def _pcap_filter(hypotheses):
    ids={h.get("technique_id") for h in hypotheses}; clauses=[]
    protocol_map={"https":"tls","rdp":"tcp","ssh":"tcp","smb":"smb2","dcom":"dcerpc","winrm":"http"}
    for tid in ids:
        meta=TECHNIQUES.get(tid,{})
        clauses.extend(f"tcp.port == {port} || udp.port == {port}" for port in meta.get("ports",[])[:8])
        clauses.extend(protocol_map.get(protocol,protocol) for protocol in meta.get("protocols",[])[:5]
            if protocol_map.get(protocol,protocol) in {"tcp","udp","icmp","dns","http","tls","smb2","dcerpc"})
    unique=list(dict.fromkeys(clauses)); selected=[]
    for clause in unique:
        candidate=" || ".join([*selected,clause])
        if len(candidate)>400: break
        selected.append(clause)
    return " || ".join(selected) or "ip"


def _lead_network_expression(lead):
    tid=lead.get("technique_id") if isinstance(lead,dict) else None
    meta=TECHNIQUES.get(tid,{})
    clauses=[]
    for port in meta.get("ports",[])[:10]: clauses.append(f"port == {port}")
    protocol_map={"https":"tls","rdp":"tcp","ssh":"tcp","smb":"tcp","dcom":"tcp","winrm":"tcp"}
    for protocol in meta.get("protocols",[])[:6]:
        value=protocol_map.get(protocol,protocol)
        if value in {"tcp","udp","icmp","dns","http","tls"}: clauses.append(f"protocols == {value}")
    legacy={"network_smb_context":"port == 445","network_auth_context":"port == 3389 || port == 22 || port == 5985 || port == 5986",
            "network_dns_http_context":"protocols == dns || protocols == http || protocols == tls",
            "network_transfer_context":"protocols == dns || protocols == http || protocols == tls"}
    if not clauses and isinstance(lead,dict) and lead.get("id") in legacy: return legacy[lead["id"]]
    return " || ".join(dict.fromkeys(clauses)) or "protocols == tcp || protocols == udp || protocols == icmp"


def _lead_pcap_filter(lead):
    tid=lead.get("technique_id") if isinstance(lead,dict) else None
    meta=TECHNIQUES.get(tid,{})
    clauses=[]
    for port in meta.get("ports",[])[:10]: clauses.append(f"tcp.port == {port} || udp.port == {port}")
    protocol_map={"https":"tls","rdp":"tcp","ssh":"tcp","smb":"smb2","dcom":"dcerpc","winrm":"http"}
    for protocol in meta.get("protocols",[])[:6]:
        value=protocol_map.get(protocol,protocol)
        if value in {"tcp","udp","icmp","dns","http","tls","smb2","dcerpc"}: clauses.append(value)
    legacy={"network_smb_context":"tcp.port == 445","network_auth_context":"tcp.port == 3389 || tcp.port == 22 || tcp.port == 5985 || tcp.port == 5986",
        "network_dns_http_context":"dns || http || tls","network_transfer_context":"dns || http || tls"}
    if not clauses and isinstance(lead,dict) and lead.get("id") in legacy: return legacy[lead["id"]]
    return " || ".join(dict.fromkeys(clauses)) or "ip"


def _evidence_ips(events):
    out=[]
    for event in events:
        raw=event.get("raw",{})
        for key in ("ip.src","ip.dst","source.ip","destination.ip","srcIp","dstIp","src_ip","dst_ip","host.ip"):
            value=raw.get(key) if isinstance(raw,dict) else None
            for candidate in value if isinstance(value,list) else [value]:
                if not candidate: continue
                try:
                    address=ipaddress.ip_address(str(candidate))
                    if not address.is_unspecified and not address.is_multicast and str(address) not in out: out.append(str(address))
                except ValueError: pass
    return out[:8]


def _search_coverage(returned,cap,scope):
    suffix="; result cap reached, additional records may exist" if returned>=cap else ""
    return f"searched {scope}; returned {returned}{suffix}"


def _relevant(tid,e):
    raw=e.get("raw",{}) if isinstance(e.get("raw"),dict) else {}
    text=(str(e.get("observation", ""))+" "+" ".join(str(raw.get(k,"")) for k in ("message","event.original","process.command_line","process.name","process.executable"))).lower()
    ports=set()
    for key in ("source.port","destination.port","srcPort","dstPort","src_port","dst_port","port","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport"):
        value=_nested(raw,key)
        for candidate in value if isinstance(value,list) else [value]:
            try: ports.add(int(candidate))
            except (ValueError,TypeError): pass
    codes=set()
    for key in ("event.code","event.id","winlog.event_id","event_id"):
        value=_nested(raw,key)
        for candidate in value if isinstance(value,list) else [value]:
            try: codes.add(int(candidate))
            except (ValueError,TypeError): pass
    meta=TECHNIQUES.get(tid,{})
    words=tuple(str(x).lower() for x in meta.get("terms",[]))
    if ports & set(meta.get("ports",[])): return True
    if codes & set(meta.get("event_codes",[])): return True
    return any(re.search(r"(?<![a-z0-9_])"+re.escape(term)+r"(?![a-z0-9_])",text) for term in words)


def _is_broad_objective(text):
    return any(phrase in text for phrase in ("broad threat hunt","broad defensive threat hunt","broad hunt",
        "malicious actors across all available","all available historical host and network","do not assume one technique"))


def _behavior_seed_queries(catalog, fields, timestamp_field, time_range, limit=32):
    """Build a bounded, priority-ordered set of portable behavior searches."""
    bindings = resolve_semantic_fields(fields)
    applicable, unsupported = applicable_analytics(catalog, bindings, "elasticsearch")
    compiled = []
    for analytic in applicable:
        query = compile_elasticsearch_seed(analytic, bindings, timestamp_field, time_range)
        if query is None:
            unsupported.append({"id": analytic["id"], "missing_roles": [], "reason": "predicate requires post-collection evaluation"})
            continue
        compiled.append({
            "analytic_id": analytic["id"], "title": analytic["title"],
            "base_priority": analytic["base_priority"], "query": query,
        })
    compiled.sort(key=lambda item: (-int(item["base_priority"]), item["analytic_id"]))
    selected = compiled[:max(0, int(limit))]
    temp_seed = next((item for item in compiled if item["analytic_id"] == "BH-XPLAT-001"), None)
    if temp_seed and temp_seed not in selected and selected:
        selected[-1] = temp_seed
        selected.sort(key=lambda item: (-int(item["base_priority"]), item["analytic_id"]))
    return selected, sorted(unsupported, key=lambda item: item["id"])


def _indicator_seed_queries(indicators, fields, timestamp_field, time_range, limit=12):
    bindings = resolve_semantic_fields(fields)
    compiled = []
    unsupported = []
    reference = datetime.now(timezone.utc)
    for indicator in indicators.get("indicators", []):
        expires = indicator.get("expires_at")
        if expires:
            try:
                parsed = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
                parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
                if parsed <= reference:
                    unsupported.append({"id": indicator.get("id"), "reason": "expired"})
                    continue
            except (TypeError, ValueError):
                unsupported.append({"id": indicator.get("id"), "reason": "invalid expiration"})
                continue
        query = compile_elasticsearch_indicator_seed(indicator, bindings, timestamp_field, time_range)
        if query is None:
            unsupported.append({"id": indicator.get("id"), "reason": "required semantic fields unavailable"})
            continue
        compiled.append({
            "indicator_id": indicator["id"], "confidence": int(indicator.get("confidence", 0)),
            "query": query, "type": indicator.get("type"),
        })
    compiled.sort(key=lambda item: (-item["confidence"], item["indicator_id"]))
    return compiled[:max(0, int(limit))], unsupported
