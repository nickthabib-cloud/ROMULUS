import json
import importlib
import os
import sys
import tempfile
import time
import types
import unittest
from contextlib import contextmanager, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from romulus.config import Settings


@contextmanager
def _analyst_module():
    requests_stub = types.ModuleType("requests")
    requests_stub.Session = lambda: None
    sys.modules.pop("romulus.agent.ollama", None)
    sys.modules.pop("romulus.agent.providers", None)
    with patch.dict(sys.modules, {"requests": requests_stub}):
        try:
            yield importlib.import_module("romulus.agent.ollama")
        finally:
            sys.modules.pop("romulus.agent.ollama", None)
            sys.modules.pop("romulus.agent.providers", None)


class _Response:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            error = RuntimeError(f"HTTP {self.status_code}: {self._body}")
            error.response = self
            raise error


class _Session:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.response

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.response


class ModelProviderConfigurationTests(unittest.TestCase):
    def test_configuration_defaults_to_ollama_and_loads_explicit_openai_settings(self):
        names = (
            "LLM_PROVIDER", "OPENAI_API_KEY", "OPENAI_MODEL",
            "OPENAI_BASE_URL", "ALLOW_CLOUD_LLM",
        )
        with patch.dict(os.environ, {name: "" for name in names}, clear=False):
            for name in names:
                os.environ.pop(name, None)
            local = Settings.from_env()

        self.assertEqual(local.llm_provider, "ollama")
        self.assertFalse(local.allow_cloud_llm)

        with patch.dict(os.environ, {
            "LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "test-secret",
            "OPENAI_MODEL": "gpt-test",
            "OPENAI_BASE_URL": "https://api.example.test/v1/",
            "ALLOW_CLOUD_LLM": "true",
        }, clear=False):
            cloud = Settings.from_env()

        self.assertEqual(cloud.llm_provider, "openai")
        self.assertEqual(cloud.openai_api_key, "test-secret")
        self.assertEqual(cloud.openai_model, "gpt-test")
        self.assertEqual(cloud.openai_base_url, "https://api.example.test/v1")
        self.assertTrue(cloud.allow_cloud_llm)


class OpenAIProviderTests(unittest.TestCase):
    def _settings(self, **changes):
        values = {
            "llm_provider": "openai",
            "openai_api_key": "test-secret",
            "openai_model": "gpt-test",
            "openai_base_url": "https://api.example.test/v1",
            "allow_cloud_llm": True,
        }
        values.update(changes)
        return replace(Settings.from_env(), **values)

    def test_openai_provider_uses_strict_schema_and_returns_usage_metadata(self):
        response = _Response({
            "id": "resp_test_123",
            "status": "completed",
            "model": "gpt-test-2026-10-01",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps({"value": "ok"})}],
            }],
            "usage": {"input_tokens": 101, "output_tokens": 17, "total_tokens": 118},
        })
        session = _Session(response)
        schema = {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        }

        with _analyst_module() as module:
            result = module.Ollama(self._settings(), session)._json_chat(
                "system instruction", "bounded evidence", schema, tokens=300
            )

        self.assertEqual(result, {"value": "ok"})
        self.assertEqual(result.model_metadata, {
            "provider": "openai",
            "model": "gpt-test-2026-10-01",
            "request_id": "resp_test_123",
            "input_tokens": 101,
            "output_tokens": 17,
            "total_tokens": 118,
        })
        method, url, request = session.calls[0]
        self.assertEqual((method, url), ("POST", "https://api.example.test/v1/responses"))
        self.assertEqual(request["headers"]["Authorization"], "Bearer test-secret")
        payload = request["json"]
        self.assertEqual(payload["model"], "gpt-test")
        self.assertEqual(payload["instructions"], "system instruction")
        self.assertEqual(payload["input"], "bounded evidence")
        self.assertFalse(payload["store"])
        self.assertEqual(payload["max_output_tokens"], 300)
        self.assertEqual(payload["text"]["format"]["type"], "json_schema")
        self.assertTrue(payload["text"]["format"]["strict"])
        self.assertEqual(payload["text"]["format"]["schema"], schema)

    def test_openai_provider_normalizes_schema_to_the_strict_supported_subset(self):
        response=_Response({"id":"resp_schema","status":"completed","model":"gpt-test",
            "output":[{"type":"message","content":[{"type":"output_text",
                "text":'{"values":["one"],"optional_note":""}'}]}]})
        session=_Session(response)
        schema={"type":"object","properties":{
            "values":{"type":"array","uniqueItems":True,"items":{"type":"string"}},
            "optional_note":{"type":"string"}},
            "required":["values"]}
        original=json.loads(json.dumps(schema))

        with _analyst_module() as module:
            result=module.Ollama(self._settings(),session)._json_chat(
                "system","bounded input",schema,tokens=100)

        sent=session.calls[0][2]["json"]["text"]["format"]["schema"]
        self.assertEqual(result["values"],["one"])
        self.assertEqual(schema,original)
        self.assertEqual(sent["required"],["values","optional_note"])
        self.assertFalse(sent["additionalProperties"])
        self.assertNotIn("uniqueItems",sent["properties"]["values"])

    def test_every_current_structured_contract_normalizes_for_openai_strict_mode(self):
        def assert_strict(node):
            if isinstance(node,list):
                for item in node: assert_strict(item)
                return
            if not isinstance(node,dict): return
            self.assertNotIn("uniqueItems",node)
            if "properties" in node:
                self.assertEqual(node.get("type"),"object")
                properties=node.get("properties",{})
                self.assertEqual(node.get("required"),list(properties))
                self.assertIs(node.get("additionalProperties"),False)
            for item in node.values(): assert_strict(item)

        with _analyst_module() as module:
            providers=importlib.import_module("romulus.agent.providers")
            case={"items":[{"item_id":"I-1"}],
                "evidence":[{"evidence_id":"E-1","observables":[]}],
                "relationships":[]}
            schemas=[
                module._activity_narrative_schema(case),
                module._indicator_review_schema(case),
                module._investigator_schema(["elasticsearch"],["H-1"],3,3),
                module._critic_schema({"assessments":[{"proposal_id":"P-1"}]}),
                module._reason_schema(["elasticsearch"],[{"hypothesis_id":"H-1"}],3),
                module._search_schema(["elasticsearch"],3),
            ]
            for schema in schemas:
                assert_strict(providers._openai_strict_schema(schema))

    def test_openai_provider_handles_the_plain_text_summary_path(self):
        response = _Response({
            "id": "resp_summary",
            "status": "completed",
            "model": "gpt-test",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps({
                    "summary": "Evidence remains inconclusive.",
                })}],
            }],
            "usage": {"input_tokens": 25, "output_tokens": 4, "total_tokens": 29},
        })
        session = _Session(response)

        with _analyst_module() as module:
            summary = module.Ollama(self._settings(), session).summarize(
                "Hunt for threats", ["one bounded observation"]
            )

        self.assertEqual(summary, "Evidence remains inconclusive.")
        _, url, request = session.calls[0]
        self.assertEqual(url, "https://api.example.test/v1/responses")
        output_format = request["json"]["text"]["format"]
        self.assertEqual(output_format["type"], "json_schema")
        self.assertTrue(output_format["strict"])
        self.assertEqual(output_format["schema"]["required"], ["summary"])
        self.assertFalse(output_format["schema"]["additionalProperties"])
        self.assertFalse(request["json"]["store"])

    def test_openai_provider_rejects_a_summary_outside_the_strict_contract(self):
        response = _Response({
            "id": "resp_bad_summary",
            "status": "completed",
            "model": "gpt-test",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps({"not_summary": "x"})}],
            }],
        })

        with _analyst_module() as module:
            with self.assertRaisesRegex(ValueError, "summary output"):
                module.Ollama(self._settings(), _Session(response)).summarize(
                    "Hunt for threats", ["one bounded observation"]
                )

    def test_openai_provider_refuses_cloud_requests_without_explicit_authorization(self):
        session = _Session(_Response({}))
        schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}

        with _analyst_module() as module:
            with self.assertRaisesRegex(RuntimeError, "ALLOW_CLOUD_LLM"):
                module.Ollama(self._settings(allow_cloud_llm=False), session)._json_chat(
                    "system", "evidence", schema, tokens=10
                )

        self.assertEqual(session.calls, [])

    def test_openai_provider_rejects_incomplete_or_missing_structured_output(self):
        schema = {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        }
        incomplete = _Session(_Response({
            "id": "resp_incomplete",
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "output": [],
        }))
        missing = _Session(_Response({
            "id": "resp_missing",
            "status": "completed",
            "output": [{"type": "message", "content": []}],
        }))

        with _analyst_module() as module:
            with self.assertRaisesRegex(ValueError, "incomplete"):
                module.Ollama(self._settings(), incomplete)._json_chat("system", "evidence", schema, tokens=10)
            with self.assertRaisesRegex(ValueError, "structured output"):
                module.Ollama(self._settings(), missing)._json_chat("system", "evidence", schema, tokens=10)

    def test_openai_provider_error_never_exposes_key_prompt_or_response_body(self):
        session = _Session(_Response({
            "error": {"message": "provider echoed bounded evidence and test-secret"}
        }, status_code=401))
        schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}

        with _analyst_module() as module:
            with self.assertRaises(Exception) as caught:
                module.Ollama(self._settings(), session)._json_chat(
                    "system", "bounded evidence", schema, tokens=10
                )

        rendered = str(caught.exception)
        self.assertNotIn("test-secret", rendered)
        self.assertNotIn("bounded evidence", rendered)
        self.assertNotIn("provider echoed", rendered)

    def test_openai_availability_checks_the_selected_model_without_exposing_the_key(self):
        session = _Session(_Response({"id": "gpt-test", "object": "model"}))

        with _analyst_module() as module:
            status = module.Ollama(self._settings(), session).available()

        self.assertTrue(status["available"])
        self.assertTrue(status["model_configured"])
        self.assertEqual(status["provider"], "openai")
        method, url, request = session.calls[0]
        self.assertEqual((method, url), ("GET", "https://api.example.test/v1/models/gpt-test"))
        self.assertEqual(request["headers"]["Authorization"], "Bearer test-secret")
        self.assertNotIn("test-secret", json.dumps(status))

    def test_connectivity_check_uses_a_fixed_schema_without_telemetry(self):
        session = _Session(_Response({
            "id": "resp_check",
            "status": "completed",
            "model": "gpt-test",
            "output": [{"type": "message", "content": [
                {"type": "output_text", "text": '{"status":"ready"}'}]}],
            "usage": {"input_tokens": 9, "output_tokens": 5, "total_tokens": 14},
        }))

        with _analyst_module() as module:
            result = module.Ollama(self._settings(), session).connectivity_check()

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result.model_metadata["total_tokens"], 14)
        payload = session.calls[0][2]["json"]
        serialized = json.dumps(payload).lower()
        self.assertNotIn("telemetry", serialized)
        self.assertNotIn("evidence", serialized)
        schema = payload["text"]["format"]["schema"]
        self.assertEqual(schema["properties"]["status"]["enum"], ["ready"])


class ModelProviderCliTests(unittest.TestCase):
    def test_model_check_reports_selected_provider_without_secret(self):
        from romulus.cli import model_check

        settings = replace(Settings.from_env(), llm_provider="openai",
            openai_model="gpt-test", openai_api_key="test-secret",
            allow_cloud_llm=True)
        fake_agent = types.SimpleNamespace(
            available=lambda: {"available": True, "model_configured": True,
                "provider": "openai"},
            connectivity_check=lambda: types.SimpleNamespace(
                model_metadata={"provider": "openai", "model": "gpt-test",
                    "request_id": "resp_check", "total_tokens": 14},
                __getitem__=lambda self, key: "ready"),
        )
        # SimpleNamespace cannot emulate mapping subscription, so use a tiny dict subtype.
        class Result(dict):
            model_metadata = {"provider": "openai", "model": "gpt-test",
                "request_id": "resp_check", "total_tokens": 14}
        fake_agent.connectivity_check = lambda: Result(status="ready")
        output = StringIO()

        agent_module=types.ModuleType("romulus.agent.ollama")
        agent_module.Ollama=lambda configured: fake_agent
        with patch.dict(sys.modules,{"romulus.agent.ollama":agent_module}), redirect_stdout(output):
            code = model_check(settings)

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("openai", rendered.lower())
        self.assertIn("gpt-test", rendered)
        self.assertIn("14", rendered)
        self.assertNotIn("test-secret", rendered)

    def test_model_check_does_not_echo_untrusted_exception_text(self):
        from romulus.cli import model_check

        settings=replace(Settings.from_env(),llm_provider="openai",
            openai_model="gpt-test",openai_api_key="test-secret",allow_cloud_llm=True)
        fake_agent=types.SimpleNamespace(
            available=lambda:{"available":True,"model_configured":True},
            connectivity_check=lambda:(_ for _ in ()).throw(
                RuntimeError("provider echoed test-secret and bounded content")),
        )
        agent_module=types.ModuleType("romulus.agent.ollama")
        agent_module.Ollama=lambda configured:fake_agent
        output=StringIO()

        with patch.dict(sys.modules,{"romulus.agent.ollama":agent_module}), redirect_stdout(output):
            code=model_check(settings)

        self.assertEqual(code,1)
        self.assertIn("RuntimeError",output.getvalue())
        self.assertNotIn("test-secret",output.getvalue())
        self.assertNotIn("bounded content",output.getvalue())

    def test_model_report_uses_a_copy_and_writes_under_model_evaluations(self):
        from romulus.cli import model_report

        settings = replace(Settings.from_env(), llm_provider="openai",
            openai_model="gpt-test", openai_api_key="test-secret",
            allow_cloud_llm=True, reports_dir=Path("C:/safe/reports"))
        original={"hunt_id":"HUNT-ORIGINAL","status":"completed",
            "coverage":{},"tool_runs":[],"candidate_leads":[]}
        fake_store=types.SimpleNamespace(load_state=lambda hunt_id: original)
        captured={}

        class Engine:
            def __init__(self,*args,**kwargs): pass
            def _indicator_review(self,state):
                state["indicator_review"]={"status":"admitted"}
                state["tool_runs"].append({"tool":"openai.responses"})
                state["coverage"]["indicator_review"]={"model_result_status":"ok",
                    "status":"admitted"}

        def generate(state, output_dir):
            captured["state"]=state
            captured["output_dir"]=output_dir
            return [Path(output_dir)/"evaluation.docx",Path(output_dir)/"evaluation.txt"]

        output=StringIO()
        with patch("romulus.cli.Store",return_value=fake_store), \
                patch("romulus.cli.HuntEngine",Engine), \
                patch("romulus.reporting.report.generate_report",side_effect=generate), \
                redirect_stdout(output):
            code=model_report(settings,"HUNT-ORIGINAL")

        self.assertEqual(code,0)
        self.assertIsNot(captured["state"],original)
        self.assertEqual(original["tool_runs"],[])
        self.assertEqual(original["hunt_id"],"HUNT-ORIGINAL")
        self.assertEqual(captured["state"]["source_hunt_id"],"HUNT-ORIGINAL")
        self.assertTrue(captured["state"]["hunt_id"].startswith("HUNT-ORIGINAL-MODEL-"))
        self.assertEqual(captured["output_dir"],Path("C:/safe/reports/model-evaluations"))
        self.assertIn("evaluation.docx",output.getvalue())

    def test_model_report_returns_nonzero_when_synthesis_falls_back(self):
        from romulus.cli import model_report

        settings=replace(Settings.from_env(),llm_provider="openai",
            reports_dir=Path("C:/safe/reports"))
        original={"hunt_id":"HUNT-ORIGINAL","status":"completed",
            "coverage":{},"tool_runs":[],"candidate_leads":[]}
        fake_store=types.SimpleNamespace(load_state=lambda hunt_id:original)

        class Engine:
            def __init__(self,*args,**kwargs): pass
            def _indicator_review(self,state):
                state["indicator_review"]={"status":"fallback"}
                state["coverage"]["indicator_review"]={"model_result_status":"error",
                    "status":"fallback"}

        output=StringIO()
        with patch("romulus.cli.Store",return_value=fake_store), \
                patch("romulus.cli.HuntEngine",Engine), \
                patch("romulus.reporting.report.generate_report",return_value=[]), \
                redirect_stdout(output):
            code=model_report(settings,"HUNT-ORIGINAL")

        self.assertEqual(code,2)
        self.assertIn("synthesis status=error",output.getvalue())


class ModelAuditTests(unittest.TestCase):
    class _Result(dict):
        model_metadata = {
            "provider": "openai", "model": "gpt-test-2026-10-01",
            "request_id": "resp_123", "input_tokens": 101,
            "output_tokens": 17, "total_tokens": 118,
            "api_key": "must-not-persist",
        }

    def _engine(self, root):
        from romulus.investigation.workflow import HuntEngine
        from romulus.store import Store

        settings = replace(
            Settings.from_env(), home=Path(root), data_dir=Path(root) / "data",
            logs_dir=Path(root) / "logs", reports_dir=Path(root) / "reports",
            llm_provider="openai",
        )
        store = Store(settings.data_dir, settings.logs_dir)
        return HuntEngine(settings, store, offline=True), store

    def test_model_call_audit_records_provider_usage_without_prompt_or_secret(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            engine, store = self._engine(os.path.abspath(directory))
            state = {"hunt_id": "HUNT-PROVIDER", "tool_calls": 0,
                "started_epoch": time.time(), "tool_runs": []}

            engine._call(
                state, "openai.responses", "grounded_investigator",
                {"case": "bounded-counts-only"}, "bounded evidence",
                lambda: self._Result({"value": "ok"}), lambda result: 1,
            )

            record = state["tool_runs"][0]
            self.assertEqual(record["model_provider"], "openai")
            self.assertEqual(record["model_name"], "gpt-test-2026-10-01")
            self.assertEqual(record["provider_request_id"], "resp_123")
            self.assertEqual(record["input_tokens"], 101)
            self.assertEqual(record["output_tokens"], 17)
            self.assertEqual(record["total_tokens"], 118)
            serialized = store.audit_path.read_text(encoding="utf-8")
            self.assertNotIn("must-not-persist", serialized)
            self.assertNotIn("api_key", serialized)

    def test_report_finalization_audit_records_the_same_bounded_provider_usage(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            engine, _ = self._engine(os.path.abspath(directory))
            state = {"hunt_id": "HUNT-FINALIZE", "tool_runs": []}

            engine._finalization_call(
                state, "openai.responses", "indicator_review_finalization",
                {"report_items": 2}, "bounded accepted evidence",
                lambda: self._Result({"strong_indicators": []}), lambda result: 0,
            )

            record = state["tool_runs"][0]
            self.assertEqual(record["model_provider"], "openai")
            self.assertEqual(record["model_name"], "gpt-test-2026-10-01")
            self.assertEqual(record["provider_request_id"], "resp_123")
            self.assertEqual(record["total_tokens"], 118)


if __name__ == "__main__":
    unittest.main()
