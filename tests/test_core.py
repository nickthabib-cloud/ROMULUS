import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from romulus.config import Settings
from romulus.intelligence.knowledge import hypotheses_for
from romulus.intelligence.correlate import correlate
from romulus.models import Evidence, encode
from romulus.store import Store
from romulus.tools.elasticsearch_client import validate_query
from romulus.tools.tshark_client import ALLOWED_FIELDS
from romulus.config import safe_url

class CoreTests(unittest.TestCase):
    def test_hypotheses_are_mission_relevant(self):
        hs=hypotheses_for("Hunt lateral movement over SMB")
        self.assertTrue(any(h.technique_id=="T1021.002" for h in hs))
    def test_time_window_filter_uses_explicit_scope_or_bounded_default(self):
        from romulus.investigation.workflow import _time_filter, _pcap_time_filter
        self.assertEqual(_time_filter("from 2026-01-01 to 2026-01-02",24),
            {"gte":"2026-01-01T00:00:00.000Z","lte":"2026-01-02T23:59:59.999Z"})
        self.assertEqual(_time_filter("from 2026-01-01 to 2026-01-02",24,"America/New_York"),
            {"gte":"2026-01-01T05:00:00.000Z","lte":"2026-01-03T04:59:59.999Z"})
        self.assertEqual(_time_filter("look at recent logs",12),{"gte":"now-12h","lte":"now"})
        self.assertIn("frame.time_epoch >=",_pcap_time_filter(["2024-11-13","2024-11-14"]))
    def test_host_query_uses_hypothesis_indicators_and_can_search_all_history(self):
        from romulus.investigation.workflow import _host_query
        hypotheses=[{"technique_id":"T1021.002"}]
        query=_host_query(hypotheses,["message","event.code","@timestamp"],"@timestamp",None,"Hunt for SMB lateral movement")
        encoded=str(query)
        self.assertIn("smb",encoded.lower()); self.assertIn("7045",encoded); self.assertNotIn("Hunt for SMB lateral movement",encoded)
        self.assertNotIn("range",query["bool"])
    def test_default_configuration_searches_retained_history_and_has_iterative_budget(self):
        cfg=Settings.from_env()
        self.assertTrue(cfg.historical_search)
        self.assertGreaterEqual(cfg.max_tool_calls,24)
    def test_url_redaction(self):
        self.assertEqual(safe_url("http://alice:secret@example.test:8005/api?token=hide"),"http://example.test:8005/api")
    def test_arkime_adapter_uses_digest_and_bounded_documented_query(self):
        try:
            from requests.auth import HTTPDigestAuth
            from romulus.tools.arkime_client import ArkimeAdapter
        except ImportError: self.skipTest("Install requirements.txt for Arkime adapter verification")
        from dataclasses import replace
        class Response:
            ok=True; status_code=200
            def json(self): return {"data":[{"id":"abc123"}]}
            def raise_for_status(self): pass
            def iter_content(self,chunk_size): return iter([b"pcap-bytes"])
        class Session:
            def __init__(self): self.calls=[]
            def get(self,*args,**kwargs): self.calls.append((args,kwargs)); return Response()
        sess=Session(); cfg=replace(Settings.from_env(),arkime_username="agent",arkime_password="secret",arkime_max_results=25,arkime_default_hours=24,historical_search=False)
        api=ArkimeAdapter(cfg,sess); found=api.search_sessions("port == 445",length=1000)
        self.assertEqual(len(found["sessions"]),1); self.assertEqual(sess.calls[-1][1]["params"]["length"],25)
        self.assertEqual(sess.calls[-1][1]["params"]["date"],24); self.assertIsInstance(sess.calls[-1][1]["auth"],HTTPDigestAuth)
        self.assertEqual(api.retrieve_pcap(["abc123"]),b"pcap-bytes")
        with self.assertRaises(ValueError): api.retrieve_pcap(["../../all"])
        api.check()
        self.assertTrue(sess.calls[-1][0][0].endswith("/api/sessions"))
        self.assertEqual(sess.calls[-1][1]["params"],{"date":-1,"length":1})
    def test_elasticsearch_adapter_is_allowlisted_and_caps_hits(self):
        from dataclasses import replace
        from romulus.tools.elasticsearch_client import ElasticsearchAdapter
        class Indices:
            def get(self,**kwargs): return {"ainception-hostlogs-a-b":{}}
            def get_mapping(self,**kwargs): return {"ainception-hostlogs-a-b":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}
        class Client:
            indices=Indices()
            def search(self,**kwargs): return {"hits":{"hits":[{"_index":kwargs["index"],"_id":"1","_source":{"message":"synthetic"}}],"total":{"value":1}}}
        cfg=replace(Settings.from_env(),max_results=5)
        api=ElasticsearchAdapter(cfg,Client())
        self.assertTrue(api.indices()); self.assertIn("ainception-hostlogs-a-b",api.mappings("ainception-hostlogs-a-b"))
        self.assertTrue(api.check()["authenticated"])
        self.assertEqual(len(api.search("ainception-hostlogs-a-b",{"match":{"message":"synthetic"}},100)["hits"]),1)
        self.assertEqual(len(api.search_many(["ainception-hostlogs-a-b"],{"match":{"message":"synthetic"}},100)["hits"]),1)
        with self.assertRaises(ValueError): api.search("unapproved-index",{"match":{"message":"x"}},10)
    def test_tshark_wrapper_uses_allowlist_and_no_shell(self):
        from romulus.tools.tshark_client import TSharkAdapter
        adapter=TSharkAdapter(Settings.from_env())
        class Process:
            stdout=["1\t10.0.0.1\n"]
            stderr=[]
            def wait(self,timeout): return 0
            def kill(self): pass
        with patch.object(adapter,"_approved",return_value=Path("approved.pcap")), patch("romulus.tools.tshark_client.shutil.which",return_value="tshark"), patch("romulus.tools.tshark_client.subprocess.Popen",return_value=Process()) as popen:
            out=adapter.inspect("approved.pcap",display_filter="tcp.port == 445",fields=["frame.number","ip.src"])
            self.assertEqual(out["packets"][0]["ip.src"],"10.0.0.1"); self.assertNotIn("shell",popen.call_args.kwargs)
            with self.assertRaises(ValueError): adapter.inspect("approved.pcap",display_filter="tcp.port == 445; rm -rf")
            with self.assertRaises(ValueError): adapter.inspect("approved.pcap",fields=["frame.payload"])
    def test_ollama_adapter_uses_local_api_and_caps_telemetry(self):
        try: from romulus.agent.ollama import Ollama
        except ImportError: self.skipTest("Install requirements.txt for Ollama adapter verification")
        class Response:
            def __init__(self,body): self.body=body
            def raise_for_status(self): pass
            def json(self): return self.body
        class Session:
            def __init__(self): self.payload=None
            def post(self,url,**kwargs): self.payload=kwargs["json"]; return Response({"message":{"content":"Evidence remains inconclusive."}})
        session=Session(); model=Ollama(Settings.from_env(),session)
        note=model.summarize("Hunt SMB",["synthetic data"]*25)
        self.assertIn("inconclusive",note); self.assertEqual(len(session.payload["messages"][1]["content"].split("UNTRUSTED TELEMETRY DATA:")),2)
        self.assertEqual(session.payload["options"]["num_ctx"],6144)
        class PlanningSession:
            def __init__(self): self.payload=None
            def post(self,url,**kwargs):
                self.payload=kwargs["json"]
                content='{"searches":[{"source":"elasticsearch","hypothesis_id":"H1","intent":"Find PowerShell execution","terms":["powershell"],"fields":["process.name"],"ips":[],"hostnames":[],"ports":[],"protocols":[],"event_codes":[],"index_class":"host","anchor_evidence_ids":[],"native_query_language":"none","native_query":""}]}'
                return Response({"message":{"content":content}})
        planning_session=PlanningSession()
        searches=Ollama(Settings.from_env(),planning_session).propose_searches(
            "Hunt PowerShell",[{"hypothesis_id":"H1","title":"PowerShell execution"}],[],
            {"elasticsearch":["process.name"]},1)
        self.assertEqual(searches[0]["intent"],"Find PowerShell execution")
        schema=planning_session.payload["format"]
        self.assertEqual(schema["properties"]["searches"]["items"]["properties"]["source"]["enum"],["elasticsearch"])
        self.assertEqual(schema["required"],["searches"]); self.assertFalse(schema["additionalProperties"])
        self.assertEqual(planning_session.payload["options"]["temperature"],0.15)
        class ReasoningSession:
            def __init__(self): self.payload=None
            def post(self,url,**kwargs):
                self.payload=kwargs["json"]
                content='{"assessments":[],"findings":[],"new_hypotheses":[],"searches":[],"continue_investigation":false,"reasoning":"No supported expansion."}'
                return Response({"message":{"content":content}})
        reasoning_session=ReasoningSession()
        result=Ollama(Settings.from_env(),reasoning_session).reason_hunt(
            "Hunt for threats",[],[],{
                "search_fields":{"elasticsearch":["process.name"]},
                "model_initial_search_plan":"deferred: undirected mission has no telemetry-backed candidate",
                "candidate_queue":[{"candidate_id":"CL-1","evidence_ids":["EV-1"]}],
            },[],1)
        self.assertFalse(result["continue_investigation"])
        prompt=reasoning_session.payload["messages"][1]["content"]
        self.assertIn("deferred: undirected mission",prompt)
        self.assertIn("CL-1",prompt)
    def test_elasticsearch_query_validation(self):
        validate_query({"bool":{"should":[{"match":{"message":"SMB"}}],"minimum_should_match":1}})
        with self.assertRaises(ValueError): validate_query({"query_string":{"query":"*"}})
    def test_correlation_needs_shared_ip_and_time(self):
        h={"evidence_id":"h","observed_at":"2026-01-01T00:00:00Z","raw":{"ip":"10.0.0.2","event_id":4624}}
        n={"evidence_id":"n","observed_at":"2026-01-01T00:01:00Z","raw":{"src_ip":"10.0.0.2","dst_port":445,"protocol":"smb"}}
        self.assertEqual(len(correlate([h],[n])),1)
        n["raw"]["src_ip"]="10.0.0.3"; self.assertEqual(correlate([h],[n]),[])
        n["raw"]["src_ip"]="10.0.0.2"; h["raw"].pop("event_id"); self.assertEqual(correlate([h],[n]),[])
    def test_store_roundtrip_and_event_log(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            p=Path(d); st=Store(p/"data",p/"logs"); st.save_state("H1",{"status":"partial"})
            self.assertEqual(st.load_state("H1")["status"],"partial")
            st.upsert_finding("H1",{"finding_id":"F1","status":"suspected"})
            self.assertIn('"event": "created"',st.events_path.read_text())
            st.audit({"hunt_id":"H1","parameters":{"nested":{"api_token":"do-not-write"}},"result_count":0})
            self.assertNotIn("do-not-write",st.audit_path.read_text()); self.assertEqual(st.audit_records("H1")[0]["result_count"],0)
    def test_reasoning_depth_limit_wins_over_minimum_rounds(self):
        from dataclasses import replace
        from romulus.investigation.workflow import HuntEngine
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            p=Path(d); cfg=replace(Settings.from_env(),home=p,reports_dir=p/"reports",data_dir=p/"data",logs_dir=p/"logs",
                max_depth=2,min_reasoning_rounds=3)
            state={"hunt_id":"H-DEPTH","depth":2,"lead_queue":[],"termination_reason":"depth_budget"}
            engine=HuntEngine(cfg,Store(cfg.data_dir,cfg.logs_dir),offline=True)
            self.assertEqual(engine._after_reason(state),"report")
            self.assertEqual(state["termination_reason"],"depth_budget")
    def test_empty_partial_reports_are_generated(self):
        try: import docx
        except ImportError: self.skipTest("Install requirements.txt for Word report verification")
        from romulus.reporting.report import generate_report
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            out=Path(d); paths=generate_report({"hunt_id":"HUNT-EMPTY","status":"partial","objective":"empty synthetic test\x01","summary":"No data was returned.\x01","coverage":{"host":"unavailable\x01"},"host":[{"evidence_id":"E1","observation":"malformed\x0b telemetry"}]},out)
            self.assertEqual({p.suffix for p in paths},{".docx",".txt"})
            self.assertIn("does not establish",paths[1].read_text()); self.assertNotIn("\x01",paths[1].read_text()); self.assertNotIn("\x0b",paths[1].read_text())
            from docx import Document
            doc=Document(next(p for p in paths if p.suffix==".docx"))
            body="\n".join(p.text for p in doc.paragraphs)+"\n"+"\n".join(cell.text for table in doc.tables for row in table.rows for cell in row.cells)
            self.assertNotIn("\x01",body); self.assertNotIn("\x0b",body)
            self.assertNotIn("malformed telemetry",body)
            self.assertIn("malformed telemetry",paths[1].read_text())
    def test_synthetic_full_investigation_and_reports(self):
        try:
            import langgraph,docx
        except ImportError: self.skipTest("Install requirements.txt for the full offline graph and Word report")
        from romulus.investigation.workflow import HuntEngine
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            p=Path(d); base=Settings.from_env()
            from dataclasses import replace
            cfg=replace(base,home=p,reports_dir=p/"reports",data_dir=p/"data",logs_dir=p/"logs")
            store=Store(cfg.data_dir,cfg.logs_dir); state=HuntEngine(cfg,store,offline=True).run("Hunt for lateral movement using SMB")
            self.assertEqual(state["status"],"completed"); self.assertTrue(state["findings"])
            self.assertEqual(state["outcome"],"evidence_supported_lead")
            self.assertEqual(state["termination_reason"],"lead_queue_exhausted")
            self.assertEqual(len(state["host"])+len(state["network"]),3)
            self.assertEqual(len(store.list_evidence(state["hunt_id"])),3)
            import sqlite3
            db=sqlite3.connect(store.checkpoint_path)
            try: self.assertGreater(db.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0],0)
            finally: db.close()
            self.assertIn('"event": "created"',(cfg.logs_dir/"findings.jsonl").read_text())
            self.assertTrue(any(p.suffix==".docx" for p in map(Path,state["report_paths"])))
            self.assertTrue(any(p.suffix==".txt" for p in map(Path,state["report_paths"])))
            from docx import Document
            doc=Document(next(Path(p) for p in state["report_paths"] if p.endswith(".docx")))
            body="\n".join(p.text for p in doc.paragraphs)
            self.assertIn("Executive Summary",body); self.assertIn("Correlated SMB",body)

    def test_live_workflow_runs_bounded_historical_pivots_and_audits_every_call(self):
        try: import langgraph,docx
        except ImportError: self.skipTest("Install requirements.txt for the LangGraph integration check")
        from dataclasses import replace
        from datetime import datetime,timezone
        from romulus.investigation.workflow import HuntEngine
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            p=Path(d); cfg=replace(Settings.from_env(),home=p,reports_dir=p/"reports",data_dir=p/"data",logs_dir=p/"logs",
                arkime_username="agent",arkime_password="secret",pcap_files=(),pcap_allowed_dirs=(),
                max_tool_calls=40,max_depth=4,min_reasoning_rounds=1,historical_search=True)
            class ES:
                def __init__(self): self.searches=0
                def indices(self): return [{"index":"ainception-hostlogs-a-b"}]
                def mappings_many(self,indices): return {"ainception-hostlogs-a-b":{"mappings":{"properties":{
                    "@timestamp":{"type":"date"},"message":{"type":"text"},"event":{"properties":{"code":{"type":"long"}}},
                    "source":{"properties":{"ip":{"type":"ip"}}},"host":{"properties":{"name":{"type":"keyword"}}}}}}}
                def search_many(self,indices,query,size):
                    self.searches+=1
                    code=4624 if self.searches==1 else 7045
                    msg="successful 4624 logon" if code==4624 else "7045 service installation"
                    return {"hits":[{"_index":indices[0],"_id":str(self.searches),"@timestamp":"2024-11-13T10:00:00Z",
                        "message":msg,"event":{"code":code},"source":{"ip":"10.0.0.5"},"host":{"name":"ws-01"}}]}
            class Arkime:
                def __init__(self): self.calls=[]
                def search_sessions(self,expression,**kwargs):
                    self.calls.append((expression,kwargs))
                    stamp=datetime(2024,11,13,10,0,tzinfo=timezone.utc).timestamp()
                    return {"sessions":[{"id":f"session-{len(self.calls)}","source.ip":"10.0.0.5","destination.ip":"10.0.0.9",
                        "destination.port":445,"firstPacket":stamp}],"provenance":{"expression":expression}}
            store=Store(cfg.data_dir,cfg.logs_dir); engine=HuntEngine(cfg,store,use_ollama=False)
            es=ES(); arkime=Arkime(); engine.es=es; engine.arkime=arkime
            state=engine.run("Hunt for SMB lateral movement")
            self.assertEqual(state["status"],"completed")
            self.assertEqual(state["coverage"]["time_scope"],"all retained indexed time")
            self.assertTrue(any(lead.endswith("-HOST") for lead in state["completed_leads"]))
            self.assertTrue(any(lead.endswith("-NETWORK") for lead in state["completed_leads"]))
            self.assertGreaterEqual(len(state["host"]),2); self.assertGreaterEqual(len(state["network"]),2)
            self.assertTrue(all(call[1].get("all_history") for call in arkime.calls))
            self.assertLessEqual(state["tool_calls"],cfg.max_tool_calls)
            self.assertEqual(state["tool_calls"],len(store.audit_records(state["hunt_id"])))
            self.assertTrue(all("result_count" in item and "time_range" in item and "duration_ms" in item for item in state["tool_runs"]))
            self.assertEqual(state["termination_reason"],"coverage_frontier_exhausted")

if __name__=="__main__": unittest.main()
