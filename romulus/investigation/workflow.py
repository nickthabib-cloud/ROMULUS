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

from ..config import Settings
from ..models import Evidence, Finding, Hypothesis, encode, utc_now
from ..store import Store
from ..intelligence.knowledge import hypotheses_for, TECHNIQUES, ATTACK_RELEASE, ATTACK_RELEASE_DATE, ATTACK_DOMAIN
from ..intelligence.attack_catalog import load_attack_catalog, reference_seeds
from ..intelligence.correlate import correlate
from ..intelligence.analytics import summarize_evidence, build_coverage_ledger
from ..tools.elasticsearch_client import ElasticsearchAdapter
from ..tools.arkime_client import ArkimeAdapter
from ..tools.tshark_client import TSharkAdapter
from .search_planner import (candidate_fields, validate_spec, fingerprint, compile_es, compile_arkime, compile_tshark,
    compile_native_es, validate_native_arkime, validate_native_tshark, expand_anchor_selectors, anchor_time_range,
    SOURCE_FIELDS, TEXT_FIELDS)
from .synthetic import sample_evidence


class HuntState(TypedDict, total=False):
    hunt_id: str; objective: str; status: str; outcome: str; termination_reason: str
    hypotheses: list[dict]; host: list[dict]; network: list[dict]; evidence: list[dict]
    findings: list[dict]; correlations: list[dict]; queries: list[dict]; coverage: dict
    started_at: str; started_epoch: float; finished_at: str; error: str; summary: str
    local_model_note: str; report_paths: list[str]; mapping_errors: list[dict]
    depth: int; tool_calls: int; mode: str; tool_runs: list[dict]
    source_errors: list[dict]; es_fields_by_class: dict[str,list[str]]
    lead_catalog: list[dict]; lead_queue: list[str]; completed_leads: list[str]
    search_fingerprints: list[str]; dynamic_plan_created: bool; dynamic_initial_queue: list[str]
    reasoning_history: list[dict]; reasoning_complete: bool; stage_history: list[dict]; es_indices: list[str]
    es_fields: list[str]; timestamp_field: str; explicit_time_range: bool
    analytic_summary: dict; search_artifacts: list[dict]; evidence_keys: list[str]


class HuntEngine:
    def __init__(self, settings: Settings, store: Store, offline: bool=False, use_ollama: bool=True):
        self.settings=settings; self.store=store; self.offline=offline; self.use_ollama=use_ollama
        self.es=ElasticsearchAdapter(settings); self.arkime=ArkimeAdapter(settings); self.tshark=TSharkAdapter(settings)
        self._seen_evidence_keys: dict[str,set[str]]={}

    def run(self, objective: str, hunt_id: str | None=None, _resume: bool=False) -> dict[str, Any]:
        if not objective or len(objective)>2000: raise ValueError("Mission must contain 1 to 2000 characters")
        self.settings.ensure_dirs(); hunt_id=hunt_id or "HUNT-"+uuid.uuid4().hex[:10].upper()
        prior=self.store.load_state(hunt_id) if _resume else None
        if prior:
            state: HuntState=prior; state["status"]="running"; state["started_epoch"]=time.time(); state["resumed_at"]=utc_now(); state.pop("error",None)
        else:
            state={"hunt_id":hunt_id,"objective":objective,"status":"running","outcome":"pending",
            "hypotheses":[],"host":[],"network":[],"evidence":[],"findings":[],"correlations":[],
                "queries":[],"coverage":{},"source_errors":[],"started_at":utc_now(),"started_epoch":time.time(),"depth":0,
                "tool_calls":0,"mode":"offline" if self.offline else "live","tool_runs":[],"lead_catalog":[],
                "lead_queue":[],"completed_leads":[],"reasoning_history":[],"stage_history":[],"reasoning_complete":False,
                "search_fingerprints":[],"dynamic_plan_created":False,"dynamic_initial_queue":[],"es_fields_by_class":{},
                "analytic_summary":{},"search_artifacts":[],"evidence_keys":[]}
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
        self.store.prune_checkpoints(hunt_id,keep=1,compact=True)
        return result

    def resume(self,hunt_id: str) -> dict[str, Any]:
        state=self.store.load_state(hunt_id)
        if not state: raise ValueError(f"Unknown investigation ID: {hunt_id}")
        if state.get("status")=="completed": return state
        return self.run(state["objective"],hunt_id=hunt_id,_resume=True)

    def _graph(self):
        from langgraph.graph import StateGraph, END
        import sqlite3
        from langgraph.checkpoint.sqlite import SqliteSaver
        g=StateGraph(HuntState)
        for name,fn in (("plan",self._plan),("collect_host",self._collect_host),("collect_network",self._collect_network),
                        ("analyze",self._analyze),("reason",self._reason),("pivot",self._pivot),("report",self._report)):
            g.add_node(name,fn)
        g.set_entry_point("plan")
        g.add_edge("plan","collect_host"); g.add_edge("collect_host","collect_network"); g.add_edge("collect_network","analyze")
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
        if self.offline:
            host,network=sample_evidence(); s["host"]=[encode(host[0])]; s["network"]=[encode(x) for x in network]
            for item in s["host"]+s["network"]: self._record_evidence(s,item)
            offline_hypotheses=[encode(h) for h in hypotheses_for(s["objective"])]
            smb_fixture=[h for h in offline_hypotheses if h.get("technique_id")=="T1021.002"]
            s["hypotheses"]=(smb_fixture or offline_hypotheses)[:1]
            s["coverage"]={"host":"synthetic fixture searched","network":"synthetic fixture searched","time_scope":"synthetic fixture timestamps",
                "attack_knowledge":{"domain":ATTACK_DOMAIN,"release":ATTACK_RELEASE,"release_date":ATTACK_RELEASE_DATE,
                    "official_catalog_techniques":attack_catalog_metadata.get("technique_count",0)}}
            offline_leads=_lead_catalog(s["hypotheses"])
            s["lead_catalog"]=[next((lead for lead in offline_leads if lead.get("source")=="host"),offline_leads[0])] if offline_leads else []
            s["reasoning_complete"]=False
            self._stage(s,"plan","completed",{"hypotheses":len(s["hypotheses"]),"mode":"offline"})
            print(f"[ROMULUS] {s['hunt_id']} offline planning {len(s['hypotheses'])} hypotheses")
            return self._save(s)
        planned=[]; basis="broad local ATT&CK seed set"
        if self.use_ollama and self._budget_ok(s):
            try:
                from ..agent.ollama import Ollama
                planned=self._call(s,"ollama.api.chat","hypothesis_generation",{"model":self.settings.ollama_model,"reference_seed_count":len(seeds)},
                    "mission text; no telemetry",lambda:Ollama(self.settings).plan_hypotheses(s["objective"],seeds,12),len) or []
                if planned: basis="local model generated a diverse hypothesis set from ATT&CK seeds and mission context"
            except Exception: planned=[]
        normalized=_normalize_hypotheses(planned) if planned else []
        s["hypotheses"]=normalized if len(normalized)>=4 else [encode(h) for h in hypotheses_for(s["objective"])][:20]
        s["coverage"]={"host":"pending","network":"pending","hypotheses_total":len(s["hypotheses"]),
            "attack_knowledge":{"domain":ATTACK_DOMAIN,"release":ATTACK_RELEASE,"release_date":ATTACK_RELEASE_DATE,
                "model":"Technique -> Detection Strategy -> platform Analytic -> Data Component -> Mutable Element",
                "official_catalog_techniques":attack_catalog_metadata.get("technique_count",0),
                "official_catalog_sha256":attack_catalog_metadata.get("source_sha256")},
            "time_scope":self._time_scope(s)[1],"historical_search_enabled":self.settings.historical_search}
        s["lead_catalog"]=_lead_catalog(s["hypotheses"])
        s["reasoning_history"].append({"stage":"mission_hypothesis_plan","basis":basis,"hypotheses":[{"id":h.get("hypothesis_id"),"title":h.get("title"),"technique_id":h.get("technique_id")} for h in s["hypotheses"]]})
        self._stage(s,"plan","completed",{"hypotheses":len(s["hypotheses"]),"candidate_leads":len(s["lead_catalog"]),"basis":basis,"time_scope":s["coverage"]["time_scope"]})
        print(f"[ROMULUS] {s['hunt_id']} planning {len(s['hypotheses'])} hypotheses; basis={basis}; scope={s['coverage']['time_scope']}")
        return self._save(s)

    def _collect_host(self,s):
        if self.offline: s["coverage"]["host_count"]=len(s.get("host",[])); return self._save(s)
        if not self._budget_ok(s):
            s["coverage"]["host"]="not searched: budget exhausted"; self._stage(s,"host_collection","incomplete",{"reason":s.get("termination_reason")}); return self._save(s)
        indices=self._call(s,"elasticsearch.indices.get","host_discovery",{"patterns":list(self.settings.es_index_patterns)},
            "configured allowlist",self.es.indices,len)
        if indices is None:
            s["coverage"]["host"]="telemetry retrieval failed during index discovery"; self._stage(s,"host_collection","failed"); return self._save(s)
        names=[r["index"] for r in indices if r.get("index")]
        s["es_indices"]=names; s["coverage"]["es_indices"]=names
        if not names:
            s["coverage"]["host"]="no configured Elasticsearch indices matched"; self._stage(s,"host_collection","unavailable",{"matched_indices":0}); return self._save(s)
        mappings=self._call(s,"elasticsearch.indices.get_mapping","host_schema",{"indices":names},
            "configured indices",lambda:self.es.mappings_many(names),lambda x:len(x))
        if mappings is None:
            s["coverage"]["host"]="indices discovered; mapping retrieval failed"; s["es_fields"]=[]; s["es_fields_by_class"]={}
        else:
            s["es_fields"]=_field_names(mappings); s["es_fields_by_class"]=_field_names_by_class(mappings)
        fields=s.get("es_fields",[])
        host_fields=s.get("es_fields_by_class",{}).get("host") or fields
        timestamp=next((f for f in ("@timestamp","timestamp","event.created","event.ingested","event.start","winlog.time_created") if f in host_fields),None)
        if not fields or (self._time_scope(s)[0] and not timestamp):
            s["coverage"]["host"]="not searched: no usable mapped fields or timestamp field to enforce the configured time window"
            self._stage(s,"host_collection","incomplete",{"mapped_fields":len(fields),"timestamp_field_available":bool(timestamp)})
            self._ensure_initial_plan(s)
            return self._save(s)
        s["timestamp_field"]=timestamp or "@timestamp"
        timestamp=s["timestamp_field"]
        scope=self._time_scope(s)[1]
        surveys=_host_survey_queries(s["hypotheses"],host_fields,timestamp,self._time_scope(s)[0],s["objective"],10)
        survey_names=[name for name in names if "host" in name.lower()] or names
        returned=0; survey_failures=0; cap_hits=0; survey_details=[]
        per_survey=min(500,self.settings.max_results)
        for survey in surveys:
            query=survey["query"]
            found=self._call(s,"elasticsearch.search","initial_host_survey",
                {"indices":survey_names,"hypothesis_id":survey.get("hypothesis_id"),"technique_id":survey.get("technique_id"),"query":query,"size":per_survey},
                scope,lambda q=query:self.es.search_many(survey_names,q,per_survey),lambda x:len(x.get("hits",[])))
            if found is None:
                survey_failures+=1; continue
            rows=found.get("hits",[]); returned+=len(rows)
            cap_hit=bool(found.get("capped") or found.get("timed_out") or found.get("shard_failures"))
            cap_hits+=int(cap_hit)
            for hit in rows: self._add_es_hit(s,hit,query,survey.get("lead_id"))
            if survey.get("lead_id") and survey["lead_id"] not in s.setdefault("completed_leads",[]): s["completed_leads"].append(survey["lead_id"])
            s.setdefault("pivot_results",[]).append({"lead_id":survey.get("lead_id"),"status":"initial host survey completed",
                "returned":len(rows),"time_range":scope,"capped":cap_hit})
            detail={"stage":"initial_host_survey","hypothesis_id":survey.get("hypothesis_id"),"technique_id":survey.get("technique_id"),
                "query":query,"time_range":scope,"returned":len(rows),"matched_total":found.get("total"),"capped":found.get("capped"),
                "timed_out":found.get("timed_out"),"shard_failures":found.get("shard_failures"),"pagination":found.get("pagination")}
            s["queries"].append(detail); survey_details.append({k:detail.get(k) for k in ("hypothesis_id","technique_id","returned","matched_total","capped")})
        if not survey_details:
            s["coverage"]["host"]="telemetry retrieval failed during every host survey"; self._stage(s,"host_collection","failed"); return self._save(s)
        s["coverage"]["host"]=(f"searched {scope} with {len(survey_details)} tactic-diverse behavioral surveys; returned {returned} records"+
            (f"; {survey_failures} survey(s) failed" if survey_failures else "")+
            (f"; {cap_hits} survey(s) were capped or partial" if cap_hits else ""))
        s["coverage"]["host_surveys"]=survey_details
        s["coverage"]["host_count"]=len(s["host"])
        self._stage(s,"host_collection","partial" if survey_failures or cap_hits else "completed",
            {"returned":returned,"surveys":len(survey_details),"failed":survey_failures,"partial":cap_hits,"time_scope":scope})
        indicator_terms=_indicator_terms(s["objective"])
        if indicator_terms:
            text_fields=[f for f in ("message","event.original","winlog.event_data.CommandLine","process.name","process.command_line") if f in host_fields]
            if not text_fields: text_fields=["message"]
            total_returned=0; failed_terms=[]
            for term in indicator_terms:
                indicator_query=_indicator_query([term],text_fields,timestamp,self._time_scope(s)[0]); indicator_size=min(self.settings.max_results,50)
                indicators=self._call(s,"elasticsearch.search","host_indicator_search",
                    {"indices":names,"term":term,"fields":text_fields,"query":indicator_query,"size":indicator_size},
                    scope,lambda q=indicator_query:self.es.search_many(names,q,indicator_size),lambda x:len(x.get("hits",[])))
                if indicators is None:
                    failed_terms.append(term); continue
                total_returned+=len(indicators["hits"])
                for hit in indicators["hits"]: self._add_es_hit(s,hit,indicator_query,"indicator_sweep")
                s["queries"].append({"stage":"host_indicator_search","term":term,"fields":text_fields,
                    "time_range":scope,"returned":len(indicators["hits"])})
            s["coverage"]["indicator_sweep"]={"terms":indicator_terms,"returned":total_returned,"failed_terms":failed_terms,
                "status":"partial" if failed_terms else "completed"}
            self._stage(s,"host_indicator_sweep","partial" if failed_terms else "completed",
                {"terms":indicator_terms,"returned":total_returned,"failed_terms":failed_terms})
            s["coverage"]["host_count"]=len(s["host"])
        self._ensure_initial_plan(s)
        for search_id in list(s.get("dynamic_initial_queue", [])):
            plan=next((p for p in s.get("lead_catalog",[]) if p.get("id")==search_id),None)
            if plan and plan.get("source")=="elasticsearch" and search_id not in s.get("completed_leads",[]):
                self._execute_model_search(s,plan,"initial_model_host_search")
                s.setdefault("completed_leads",[]).append(search_id)
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

    def _collect_network(self,s):
        if self.offline:
            s["coverage"]["network_count"]=len(s.get("network",[])); return self._save(s)
        explicit=_explicit_dates(s["objective"]); start_ms,stop_ms=_arkime_time_window(s["objective"],self.settings.mission_timezone)
        scope=self._time_scope(s)[1]; s["coverage"]["network_sources"]={}
        self._ensure_initial_plan(s)
        if self.settings.arkime_username and self.settings.arkime_password:
            expression=_arkime_expression(s["objective"],s["hypotheses"])
            all_history=self.settings.historical_search and not explicit
            result=self._search_arkime_pages(s,expression,"initial_network_search",scope,start_ms,stop_ms,
                self.settings.arkime_max_results,all_history,{"source":"arkime"})
            if result["failed"] and not result["sessions"]: s["coverage"]["network_sources"]["arkime"]="failed"
            else:
                sessions=result.get("sessions",[])
                self._add_arkime_rows(s,sessions[:self.settings.arkime_max_results],expression,scope)
                s["queries"].append({"stage":"initial_network_search","source":"arkime","expression":expression,"time_range":scope,
                    "returned":len(sessions),"matched_total":result.get("total"),"pages":result.get("pages"),"capped":result.get("capped"),"failed":result.get("failed")})
                coverage=f"searched {scope}; returned {len(sessions)} of {result.get('total','unknown')} matching sessions across {result.get('pages',0)} page(s)"
                if result.get("capped"): coverage+="; configured result cap reached, more matching sessions remain"
                if result.get("failed"): coverage+="; a later page failed, so this source is partial"
                s["coverage"]["network_sources"]["arkime"]=coverage
            indicator_terms=_indicator_terms(s["objective"])
            if indicator_terms:
                indicator_expressions=_arkime_indicator_expressions(indicator_terms)
                indicator_size=min(self.settings.max_results,100)
                returned=0; added=0; group_matches=0; failures=[]; cap_hit=False
                for group_number,indicator_expression in enumerate(indicator_expressions,1):
                    indicator_result=self._call(s,"arkime.api.sessions","arkime_indicator_search",
                        {"terms":indicator_terms,"group":group_number,"expression":indicator_expression,"length":indicator_size,
                         "date":-1 if all_history else ("explicit" if explicit else self.settings.arkime_default_hours)},scope,
                        lambda expression=indicator_expression:self.arkime.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,
                            length=indicator_size,all_history=all_history),lambda x:len(x.get("sessions",[])))
                    if indicator_result is None:
                        failures.append(group_number); continue
                    indicator_sessions=indicator_result.get("sessions",[])
                    returned+=len(indicator_sessions); added+=self._add_arkime_rows(s,indicator_sessions,indicator_expression,scope,"arkime_indicator_sweep")
                    total=indicator_result.get("total")
                    if isinstance(total,(int,float)): group_matches+=int(total)
                    cap_hit=cap_hit or len(indicator_sessions)>=indicator_size
                    s["queries"].append({"stage":"arkime_indicator_search","source":"arkime","group":group_number,
                        "terms":indicator_terms,"expression":indicator_expression,"time_range":scope,
                        "returned":len(indicator_sessions),"matched_total":total})
                if failures:
                    s["coverage"]["network_sources"]["arkime_indicator_sweep"]=(
                        f"partial; {len(failures)} query group(s) failed; returned {returned}, added {added} unique sessions; query-group matches {group_matches}")
                else:
                    cap_note="; result cap reached, additional matches may exist" if cap_hit else ""
                    s["coverage"]["network_sources"]["arkime_indicator_sweep"]=(
                        f"searched {scope}; returned {returned}, added {added} unique sessions; query-group matches {group_matches}{cap_note}")
                self._stage(s,"arkime_indicator_sweep",
                    "partial" if failures else "completed",
                    {"terms":indicator_terms,"query_groups":len(indicator_expressions),"returned":returned,
                     "added_unique_sessions":added,"query_group_matches":group_matches,"failed_groups":failures})
        else: s["coverage"]["network_sources"]["arkime"]="not configured"

        if self.settings.pcap_files:
            display_filter=_pcap_filter(s["hypotheses"])
            date_filter=_pcap_time_filter(explicit,self.settings.mission_timezone)
            fields=["frame.number","frame.time_epoch","ip.src","ip.dst","ipv6.src","ipv6.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","dns.qry.name","http.host","tls.handshake.extensions_server_name","smb2.cmd"]
            attempted=0; failed=0; returned_total=0; matched_total=0; cap_hits=0; output_cap=min(500,self.settings.max_results)
            for pcap in self.settings.pcap_files[:3]:
                if not self._budget_ok(s): break
                result=self._call(s,"tshark.read_pcap","initial_pcap_search",{"pcap":str(pcap),"display_filter":display_filter,"fields":fields},
                    "explicit mission dates; retained-match cap applies" if date_filter else "entire configured capture; retained-match cap applies",
                    lambda pcap=pcap:self.tshark.inspect(pcap,display_filter=display_filter,fields=fields,limit=output_cap,time_filter=date_filter),
                    lambda x:x.get("count",0))
                attempted+=1
                if result is None: failed+=1; continue
                returned_total+=result["count"]
                matched_total+=int(result.get("matched_count",result["count"]) or 0)
                if result.get("output_capped"): cap_hits+=1
                for row in result["packets"]:
                    self._add_tshark_row(s,row,result["provenance"],result["provenance"]["display_filter"])
                s["queries"].append({"stage":"initial_pcap_search","source":"tshark","pcap":str(pcap),"display_filter":display_filter,
                    "time_range":result["provenance"]["time_range"],"returned":result["count"],
                    "matched_packets":result.get("matched_count"),"retained_match_cap":output_cap,"capped":bool(result.get("output_capped"))})
            s["coverage"]["network_sources"]["tshark"]=(f"searched {attempted} configured capture(s) completely under the per-call timeout; "
                f"retained {returned_total} of {matched_total} matching packets; retained-match cap {output_cap} per capture reached by {cap_hits}"+
                (f"; failed for {failed} capture(s)" if failed else ""))
        else: s["coverage"]["network_sources"]["tshark"]="no PCAP files configured"
        for search_id in list(s.get("dynamic_initial_queue", [])):
            plan=next((p for p in s.get("lead_catalog",[]) if p.get("id")==search_id),None)
            if plan and plan.get("source") in {"arkime","tshark"} and search_id not in s.get("completed_leads",[]):
                self._execute_model_search(s,plan,"initial_model_network_search")
                s.setdefault("completed_leads",[]).append(search_id)
        statuses=list(s["coverage"]["network_sources"].values())
        source_failed=any("failed" in str(x).lower() for x in statuses)
        source_capped=any(("cap reached" in str(x).lower() or "reached by" in str(x).lower()) and
            "reached by 0" not in str(x).lower() for x in statuses)
        source_partial=any("partial" in str(x).lower() for x in statuses)
        if source_failed:
            s["coverage"]["network"]="partial: one or more configured sources failed"
        elif source_capped:
            s["coverage"]["network"]="partial: configured sources responded, but one or more result caps were reached"
        elif source_partial:
            s["coverage"]["network"]="partial: a configured network source returned incomplete coverage"
        elif all(x=="not configured" or x=="no PCAP files configured" for x in statuses):
            s["coverage"]["network"]="not configured: Arkime and PCAP sources unavailable"
        else: s["coverage"]["network"]="configured Arkime and/or PCAP sources searched"
        s["coverage"]["network_count"]=len(s["network"])
        self._stage(s,"network_collection","partial" if s["coverage"]["network"].startswith("partial") else "completed",
            {"returned":len(s["network"]),"sources":s["coverage"]["network_sources"],"time_scope":scope})
        return self._save(s)

    def _ensure_initial_plan(self,s):
        if s.get("dynamic_plan_created") or self.offline: return
        source_fields={}
        if s.get("es_indices") and s.get("es_fields"):
            source_fields["elasticsearch"]=candidate_fields("elasticsearch",s["es_fields"])
        if self.settings.arkime_username and self.settings.arkime_password:
            source_fields["arkime"]=candidate_fields("arkime",list(SOURCE_FIELDS["arkime"]))
        if self.settings.pcap_files:
            source_fields["tshark"]=candidate_fields("tshark",list(SOURCE_FIELDS["tshark"]))
        s.setdefault("coverage",{})["search_fields"]=source_fields
        field_classes=s.get("es_fields_by_class",{})
        s.setdefault("coverage",{})["search_field_classes"]={k:candidate_fields("elasticsearch",v) for k,v in field_classes.items() if v}
        s["dynamic_plan_created"]=True
        if not source_fields or not self.use_ollama or not self._budget_ok(s):
            s["coverage"]["model_initial_search_plan"]="not generated: no mapped source, Ollama disabled, or budget exhausted"
            return
        try:
            from ..agent.ollama import Ollama
            raw=self._call(s,"ollama.api.chat","initial_search_planning",
                {"model":self.settings.ollama_model,"sources":list(source_fields),"field_counts":{k:len(v) for k,v in source_fields.items()}},
                "mission, hypotheses, actual field catalogs; no raw telemetry",
                lambda:Ollama(self.settings).propose_searches(s["objective"],s.get("hypotheses",[]),_all_evidence(s),source_fields,6,[],"initial",
                    s.get("coverage",{}).get("search_field_classes",{})),len)
        except Exception: raw=None
        ids={h.get("hypothesis_id") for h in s.get("hypotheses",[]) if h.get("hypothesis_id")}
        evidence_ids={e.get("evidence_id") for e in _all_evidence(s) if e.get("evidence_id")}
        accepted=[]; rejected=0
        for item in raw or []:
            # Initial searches establish broad coverage across retained time.
            # Evidence-anchored windows are reserved for later pivots after an
            # analyst assessment identifies a concrete record worth following.
            if isinstance(item,dict): item={**item,"anchor_evidence_ids":[]}
            item=expand_anchor_selectors(item,_all_evidence(s))
            spec=validate_spec(item,allowed_sources=list(source_fields),hypothesis_ids=ids,
                fields_by_source=source_fields,evidence_ids=evidence_ids)
            if not spec:
                rejected+=1; continue
            fp=fingerprint(spec)
            if fp in s.setdefault("search_fingerprints",[]):
                rejected+=1; continue
            s["search_fingerprints"].append(fp)
            search_id="Q-"+fp
            entry={"id":search_id,"fingerprint":fp,"phase":"initial",**spec}
            s.setdefault("lead_catalog",[]).append(entry); s.setdefault("dynamic_initial_queue",[]).append(search_id); accepted.append(search_id)
        s["coverage"]["model_initial_search_plan"]={"status":"generated" if accepted else "empty_or_unavailable",
            "accepted":len(accepted),"rejected_or_duplicate":rejected,"sources":list(source_fields)}
        self._stage(s,"initial_search_planning","completed" if accepted else "no_searches",
            {"accepted":len(accepted),"rejected_or_duplicate":rejected,"sources":list(source_fields)})
        print(f"[ROMULUS] model initial search plan: accepted={len(accepted)} rejected_or_duplicate={rejected} sources={list(source_fields)}")

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
        s["analytic_summary"]=summarize_evidence(s.get("host",[]),s.get("network",[]))
        s.setdefault("coverage",{})["analytic_summary"]=s["analytic_summary"]
        for hypothesis in s.get("hypotheses",[]):
            relevant=[e for e in all_e if _relevant(hypothesis["technique_id"],e)]
            # Heuristic matches are candidate context for the model, not an
            # assessment. Only a cited analyst assessment may mark a hypothesis
            # supported or contradicted.
            hypothesis["candidate_evidence_ids"]=[e["evidence_id"] for e in relevant if e.get("evidence_id")][:40]
            if not hypothesis.get("model_assessment"):
                hypothesis["evidence_ids"]=[]
                hypothesis["status"]="candidate evidence found" if relevant else "not assessed"
                hypothesis["confidence"]="not assessed"
        if s["correlations"]: self._publish_smb_lead(s)
        self._publish_tooling_leads(s)
        results=list(s.get("coverage",{}).get("model_search_results",[]))+list(s.get("pivot_results",[]))
        host_available=bool(s.get("es_indices")) or self.offline
        network_available=self.offline or str(s.get("coverage",{}).get("network","")).startswith(("configured","partial"))
        ledger=build_coverage_ledger(s.get("hypotheses",[]),s.get("lead_catalog",[]),s.get("completed_leads",[]),
            results,host_available,network_available)
        s["coverage"]["hypothesis_coverage"]=ledger
        signals=len(s["analytic_summary"].get("behavioral_observations",[]))
        self._stage(s,"evidence_analysis","completed",{"host_events":len(s.get("host",[])),"network_events":len(s.get("network",[])),
            "correlations":len(s["correlations"]),"behavioral_observations":signals,"findings":len(s.get("findings",[])),
            "high_priority_tested":ledger.get("high_priority_tested"),"high_priority_total":ledger.get("high_priority_total")})
        print(f"[ROMULUS] analysis stage: evidence={len(all_e)} analytic_observations={signals} correlations={len(s['correlations'])} findings={len(s.get('findings',[]))} high_priority_tested={ledger.get('high_priority_tested')}/{ledger.get('high_priority_total')}")
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
        if not s.get("reasoning_complete"): return "reason"
        if s.get("lead_queue") and self._can_pivot(s): return "pivot"
        if s.get("lead_queue") and not s.get("termination_reason"):
            s["termination_reason"]="tool_call_budget" if s.get("tool_calls",0)>=self.settings.max_tool_calls else "runtime_budget"
        if not s.get("termination_reason"): s["termination_reason"]="lead_queue_exhausted"
        self._save(s)
        return "report"

    def _after_reason(self,s):
        if s.get("lead_queue") and self._can_pivot(s): return "pivot"
        if s.get("lead_queue") and not s.get("termination_reason"):
            s["termination_reason"]="tool_call_budget" if s.get("tool_calls",0)>=self.settings.max_tool_calls else "runtime_budget"
        if not s.get("lead_queue") and s.get("depth",0)<self.settings.min_reasoning_rounds and self._budget_ok(s):
            s.pop("termination_reason",None); self._save(s); return "reason"
        if not s.get("lead_queue") and not s.get("termination_reason"): s["termination_reason"]="no_useful_leads"
        self._save(s)
        return "report"

    def _can_pivot(self,s):
        return self._budget_ok(s)

    def _reason(self,s):
        if s.get("depth",0)>=self.settings.max_depth:
            s["termination_reason"]="depth_budget"; s["lead_queue"]=[]; s["reasoning_complete"]=True
            self._stage(s,"analyst_reasoning","budget_exhausted",{"reasoning_rounds":s.get("depth",0)})
            return self._save(s)
        s.setdefault("depth",0); s["depth"]+=1
        selected=[]; basis="bounded deterministic coverage fallback"; analysis=None; model_error=None
        source_fields=s.get("coverage",{}).get("search_fields",{})
        if not source_fields: self._ensure_initial_plan(s); source_fields=s.get("coverage",{}).get("search_fields",{})
        elapsed=max(0,time.time()-s.get("started_epoch",time.time()))
        s.setdefault("coverage",{})["tool_calls_remaining"]=max(0,self.settings.max_tool_calls-s.get("tool_calls",0))
        s["coverage"]["runtime_seconds_remaining"]=max(0,round(self.settings.max_runtime_seconds-elapsed))
        s["coverage"]["reasoning_rounds_remaining"]=max(0,self.settings.max_depth-s.get("depth",0))
        s["coverage"]["recent_search_artifacts"]=s.get("search_artifacts",[])[-12:]
        if not self.offline and self.use_ollama and source_fields and self._budget_ok(s):
            try:
                from ..agent.ollama import Ollama, model_evidence_context
                visible_model_ids={e.get("evidence_id") for e in model_evidence_context(_all_evidence(s),12) if e.get("evidence_id")}
                visible_model_ids.update(x.get("artifact_id") for x in s.get("search_artifacts",[])[-12:] if x.get("artifact_id"))
                model_coverage=dict(s.get("coverage",{}))
                model_coverage["existing_findings"]=[{"title":str(f.get("title",""))[:100],
                    "technique_id":f.get("technique_id"),"evidence_ids":f.get("evidence_ids",[])[:5]}
                    for f in s.get("findings",[])[-5:]]
                analysis=self._call(s,"ollama.api.chat","analyst_reasoning",
                    {"model":self.settings.ollama_model,"hypotheses":len(s.get("hypotheses",[])),
                     "evidence_count":len(_all_evidence(s)),"completed_searches":len(s.get("search_fingerprints",[]))},
                    "bounded mission, evidence excerpts, query coverage, and mapped source fields",
                    lambda:Ollama(self.settings).reason_hunt(s["objective"],s.get("hypotheses",[]),_all_evidence(s),
                        model_coverage,_search_history_summary(s),3),lambda x:len(x.get("searches",[])))
                if analysis is None:
                    last_call=next((r for r in reversed(s.get("tool_runs",[])) if r.get("tool")=="ollama.api.chat" and r.get("reasoning_stage")=="analyst_reasoning"),{})
                    model_error=last_call.get("error_reason") or last_call.get("error") or "unavailable"
                if isinstance(analysis,dict):
                    created=self._append_model_hypotheses(s,analysis.get("new_hypotheses",[]),visible_model_ids)
                    self._apply_model_assessments(s,analysis,visible_model_ids)
                    self._publish_model_findings(s,analysis.get("findings",[]),visible_model_ids)
                    analysis["created_hypothesis_ids"]=created
                    basis="model assessed cited evidence and proposed fresh bounded searches"
            except Exception as exc:
                analysis=None; model_error=type(exc).__name__
        if isinstance(analysis,dict):
            raw_searches=analysis.get("searches",[])
            validated=self._register_model_searches(s,raw_searches,"iterative")
            # Reserve one slot for the deterministic coverage frontier. The
            # model retains creative freedom for two searches each round while
            # code guarantees broad hypotheses are not silently abandoned.
            selected=[x["id"] for x in validated[:2]]
            frontier=_coverage_fallback(s,max(0,3-len(selected)),exclude=set(selected))
            selected.extend(x for x in frontier if x not in selected)
            planning=s.get("coverage",{}).get("model_search_planning",[])
            planning=planning[-1] if planning else {"accepted":0,"rejected_or_duplicate":0}
            print(f"[ROMULUS] model follow-up plan: proposed={planning.get('proposed',len(raw_searches) if isinstance(raw_searches,list) else 0)} accepted={planning.get('accepted',0)} rejected_or_duplicate={planning.get('rejected_or_duplicate',0)} repeated_empty_anchor={planning.get('repeated_empty_anchor',0)}")
            if not selected:
                # Do not let an LLM proposal collapse the hunt onto one event
                # cluster. When it has no fresh valid query, continue with
                # untried hypothesis-backed host and network pivots, even after
                # the minimum reasoning-round threshold has been met.
                if source_fields:
                    selected=_coverage_fallback(s,3)
                    if selected: basis="breadth fallback: untried hypothesis-backed host/network pivots after no fresh model query"
                if not selected:
                    closure=s.get("coverage",{}).get("hypothesis_coverage",{}).get("closure_ready",False)
                    if closure and not analysis.get("continue_investigation",True) and s["depth"]>=self.settings.min_reasoning_rounds:
                        s["termination_reason"]="coverage_closure_reached"
                    else:
                        s["termination_reason"]="coverage_frontier_exhausted"
        elif not self.offline:
            selected=_coverage_fallback(s,3); basis="structured model output unavailable; deterministic ATT&CK coverage frontier used"
            if not selected: s["termination_reason"]="model_unavailable_no_fallback_leads"
        else:
            selected=_coverage_fallback(s,3); basis="offline deterministic fixture pivot"
            if not selected: s["termination_reason"]="lead_queue_exhausted"
        s["reasoning_complete"]=bool(selected)
        s["lead_queue"]=list(selected)
        s["reasoning_history"].append({"stage":"analyst_reasoning","basis":basis,"round":s["depth"],
            "reasoning":str(analysis.get("reasoning",""))[:350] if isinstance(analysis,dict) else "",
            "model_error":model_error,
            "model_search_plan":s.get("coverage",{}).get("model_search_planning",[])[-1] if s.get("coverage",{}).get("model_search_planning") else None,
            "created_hypothesis_ids":analysis.get("created_hypothesis_ids",[]) if isinstance(analysis,dict) else [],
            "selected_searches":[{"id":q["id"],"source":q.get("source"),"hypothesis_id":q.get("hypothesis_id"),"intent":q.get("intent")} for q in s.get("lead_catalog",[]) if q.get("id") in selected],
            "evidence_count":len(_all_evidence(s)),"completed_search_count":len(s.get("search_fingerprints",[]))})
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
        visible=set(visible_ids or {e.get("evidence_id") for e in _all_evidence(s) if e.get("evidence_id")})
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
            hypothesis["hypothesis_id"]=ident; hypothesis["evidence_ids"]=basis
            hypothesis["basis_evidence_ids"]=basis; hypothesis["status"]="untested"; hypothesis["confidence"]="low"
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

    def _register_model_searches(self,s,raw_searches,phase):
        source_fields=s.get("coverage",{}).get("search_fields",{})
        ids={h.get("hypothesis_id") for h in s.get("hypotheses",[]) if h.get("hypothesis_id")}
        evidence_ids={e.get("evidence_id") for e in _all_evidence(s) if e.get("evidence_id")}
        accepted=[]; rejected=0; duplicate=0; repeated_empty_anchor=0
        proposed=raw_searches if isinstance(raw_searches,list) else []
        for item in proposed:
            item=expand_anchor_selectors(item,_all_evidence(s))
            spec=validate_spec(item,allowed_sources=list(source_fields),hypothesis_ids=ids,fields_by_source=source_fields,evidence_ids=evidence_ids)
            if not spec: rejected+=1; continue
            if phase=="iterative" and self._anchor_exhausted_on_sources(s,spec):
                rejected+=1; duplicate+=1; repeated_empty_anchor+=1; continue
            fp=fingerprint(spec)
            if fp in s.setdefault("search_fingerprints",[]): rejected+=1; duplicate+=1; continue
            s["search_fingerprints"].append(fp)
            entry={"id":"Q-"+fp,"fingerprint":fp,"phase":phase,**spec}
            s.setdefault("lead_catalog",[]).append(entry); accepted.append(entry)
        s.setdefault("coverage",{}).setdefault("model_search_planning",[]).append({"phase":phase,"proposed":len(proposed),
            "accepted":len(accepted),"rejected_or_duplicate":rejected,"duplicate":duplicate,
            "repeated_empty_anchor":repeated_empty_anchor,"invalid_or_unmappable":rejected-duplicate})
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

    def _pivot(self,s):
        queue=list(s.get("lead_queue",[]))
        if not queue: return self._save(s)
        lead_id=queue.pop(0); s["lead_queue"]=queue; s["completed_leads"].append(lead_id); s["reasoning_complete"]=bool(queue)
        lead=next((x for x in s.get("lead_catalog",[]) if x["id"]==lead_id),None)
        if not lead: return self._save(s)
        print(f"[ROMULUS] investigation round {s['depth']}/{self.settings.max_depth}, search {lead_id}: {lead.get('intent',lead.get('why','follow-up lead'))}")
        if self.offline:
            host,_=sample_evidence(); item=encode(host[1]); item["query"]="synthetic follow-up after SMB network evidence"
            item["provenance"]={"fixture":"fixtures/synthetic_host.json","pivot":lead_id}
            s["host"].append(item); self._record_evidence(s,item)
            s.setdefault("pivot_results",[]).append({"lead_id":lead_id,"status":"synthetic fixture pivot completed","returned":1})
            s["coverage"]["offline_pivot"]="completed: synthetic host service event retrieved after SMB lead"
            s["queries"].append({"stage":"offline_synthetic_pivot","lead_id":lead_id,"returned":1})
        elif lead.get("fingerprint"):
            self._execute_model_search(s,lead,"iterative_model_search")
        elif lead["source"]=="host": self._host_pivot(s,lead)
        else: self._network_pivot(s,lead)
        latest=s.get("pivot_results",[])[-1] if s.get("pivot_results") else {}
        self._stage(s,"follow_up_pivot",latest.get("status","attempted"),{"lead_id":lead_id,"returned":latest.get("returned",0)})
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
        pivot_context=s if lead.get("anchor_evidence_ids") else {}
        query=_lead_host_query(lead,fields,s.get("timestamp_field","@timestamp"),self._time_scope(s)[0],pivot_context)
        scope=self._time_scope(s)[1]
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
            scope=self._time_scope(s)[1]; all_history=self.settings.historical_search and not explicit
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
            date_filter=_pcap_time_filter(_explicit_dates(s["objective"]),self.settings.mission_timezone)
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
        s.setdefault("pivot_results",[]).append({"lead_id":lead["id"],"status":"queried configured network sources" if details else "no configured network source queried",
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
        incomplete_coverage=incomplete_coverage or coverage_frontier_incomplete
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
        for source in sources:
            ident=_coverage_lead_id(hypothesis.get("hypothesis_id"),source)
            why=(hypothesis.get("analytic_goal") or meta.get("analytic_goal") or
                 f"Test {hypothesis.get('title','this hypothesis')} in available {source} telemetry.")
            if ident not in seen:
                seen.add(ident); out.append({"id":ident,"source":source,"title":hypothesis.get("title") or ident,
                    "why":why,"intent":why,"hypothesis_id":hypothesis.get("hypothesis_id"),"technique_id":tid,
                    "priority":hypothesis.get("priority",3),"tactics":hypothesis.get("tactics") or meta.get("tactics",[])})
    return out


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
    return _host_query(hypothesis,fields,timestamp_field,time_range,"",lead_id,state)


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
    """Return query intent and outcomes, not opaque fingerprints or raw query DSL."""
    completed=set(s.get("completed_leads",[]))
    model_results={x.get("search_id"):x for x in s.get("coverage",{}).get("model_search_results",[]) if x.get("search_id")}
    pivots={x.get("lead_id"):x for x in s.get("pivot_results",[]) if x.get("lead_id")}
    out=[]
    for plan in s.get("lead_catalog",[]):
        if plan.get("id") not in completed: continue
        result=model_results.get(plan.get("id"),pivots.get(plan.get("id"),{}))
        selectors={k:plan.get(k) for k in ("terms","ips","hostnames","ports","protocols","event_codes","index_class") if plan.get(k)}
        out.append({"source":plan.get("source"),"intent":plan.get("intent") or plan.get("why"),"selectors":selectors,
            "status":result.get("status"),"returned":result.get("returned",0)})
    for query in s.get("queries",[]):
        stage=str(query.get("stage",""))
        if not stage.startswith(("initial_host_search","host_indicator_search","initial_network_search","arkime_indicator_search","initial_pcap_search")):
            continue
        out.append({"source":query.get("source") or ("elasticsearch" if "host" in stage else None),"intent":stage,
            "selectors":{k:query.get(k) for k in ("term","terms","protocol","display_filter") if query.get(k)},
            "status":query.get("status","completed"),"returned":query.get("returned",0)})
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
