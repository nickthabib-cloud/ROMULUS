"""Suspicious telemetry is labelled without suppressing supported assessment prose."""
from copy import deepcopy
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from romulus.agent.aliases import AliasBook
from romulus.agent.assessment import check_assessment
from romulus.agent.safety import injection_flags
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, TypedEvent, fv
from romulus.report import executive, markdown
from romulus.report.manifest import build_manifest
from romulus.store.db import utcnow
from romulus.web import app
from romulus.web.agent_views import assessment_view
from tests.test_agent_render_a6 import _docx
from tests.test_report import T, _repo_with_finding
from tests.test_windows_evidence import _hit

LABEL = "Cites only content flagged as possible prompt injection."
# Standard Security 4624 rendered message structure, with synthetic identities.
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
LOGON_MESSAGE = (
    "An account was successfully logged on.\n\n"
    "Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS01$\n"
    "\tAccount Domain:\t\tEXAMPLE\n\tLogon ID:\t\t0x3E7\n\n"
    "Logon Information:\n\tLogon Type:\t\t3\n\n"
    "New Logon:\n\tSecurity ID:\t\tS-1-5-21-1-2-3-1001\n"
    "\tAccount Name:\t\talice\n\tAccount Domain:\t\tEXAMPLE\n\n"
    "Network Information:\n\tWorkstation Name:\tWS01\n"
    "\tSource Network Address:\t192.0.2.10\n\tSource Port:\t\t50000\n\n"
    "Detailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp\n"
    "\tAuthentication Package:\tNTLM\n"
    "\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event."
)


@pytest.fixture
def repo():
    value, _ = _repo_with_finding()
    yield value
    value.engine.dispose()


def _logon(repo):
    hit = _hit(4624, data={"TargetUserName": "alice", "LogonType": "3", "IpAddress": "192.0.2.10"})
    hit["_source"]["message"] = LOGON_MESSAGE
    events, skipped, errors = normalize_hits([hit])
    assert len(events) == 1 and not skipped and not errors
    assert events[0].family == "auth" and events[0].outcome == Outcome.success
    assert any("markdown_control" in item["detections"] for item in injection_flags(LOGON_MESSAGE))
    repo.save_evidence("h1", events, {f"{hit['_index']}/{hit['_id']}": hit["_source"]}, None)
    return events[0].id


def _body(text, aliases):
    return {"overall": [{"text": text, "cites": aliases, "kind": "observed"}], "key_steps": [],
            "confidence": {"overall": "low", "reasons": []}, "alternatives": [], "gaps": [],
            "next_checks": []}


def test_standard_winlogbeat_logon_message_keeps_sentence_and_labels_it(repo):
    event_id = _logon(repo)
    body = _body("Alice authenticated from the recorded source address.",
                 [AliasBook(repo, "h1").alias_for("E", event_id)])
    checked, counts = check_assessment(repo, "h1", body)
    assert checked["overall"] == [{**body["overall"][0], "cites": [event_id], "suspicious_content": True}]
    assert counts == {"labelled_suspicious_only": 1}


@pytest.mark.parametrize("command", ["/bin/id\n# x", "/bin/id tool_call", "/bin/id\n# x tool_call"])
def test_attacker_command_cannot_hide_the_description_of_its_execution(repo, command):
    event = TypedEvent(id="command-event", family="process_exec", ts=T, host="web01", outcome=Outcome.success,
                       fields={"process.command_line": fv(command, "fixture:command")}, raw=[], normalizer="test")
    repo.save_evidence("h1", [event], {}, None)
    body = _body("The recorded process executed the displayed command.",
                 [AliasBook(repo, "h1").alias_for("E", event.id)])
    checked, counts = check_assessment(repo, "h1", body)
    assert checked["overall"] == [{**body["overall"][0], "cites": [event.id], "suspicious_content": True}]
    assert counts == {"labelled_suspicious_only": 1}


def test_mixed_flagged_and_clean_citations_keep_the_existing_shape(repo):
    event_id = _logon(repo)
    book = AliasBook(repo, "h1")
    body = _body("The records show authentication and process activity.",
                 [book.alias_for("E", event_id), book.alias_for("E", "ev1")])
    checked, counts = check_assessment(repo, "h1", body)
    assert checked["overall"] == [{**body["overall"][0], "cites": [event_id, "ev1"]}]
    assert counts == {}


def test_existing_absence_check_still_applies_to_flagged_support(repo):
    event_id = _logon(repo)
    checked, counts = check_assessment(repo, "h1", _body("There is no evidence of compromise.",
        [AliasBook(repo, "h1").alias_for("E", event_id)]))
    assert checked["overall"] == []
    assert counts == {"removed_absence_claim": 1}


def test_labels_and_checker_counts_reach_every_rendered_sentence_group(repo, tmp_path, monkeypatch):
    event_id = _logon(repo)
    sentence = _body("The recorded authentication warrants review.",
                     [AliasBook(repo, "h1").alias_for("E", event_id)])["overall"][0]
    body = {"overall": [sentence], "key_steps": [{"time": None, "tactic": None, "sentence": sentence}],
            "confidence": {"overall": "low", "reasons": [sentence]}, "alternatives": [sentence],
            "gaps": [sentence], "next_checks": [sentence]}
    checked, counts = check_assessment(repo, "h1", deepcopy(body))
    assert counts == {"labelled_suspicious_only": 6}
    repo.save_agent_run({"hunt_id": "h1", "state": "completed"})
    repo.save_agent_assessment({"id": "labelled", "hunt_id": "h1", "revision": 1, "source": "agent",
                               "model": {}, "body": checked, "checker": counts, "created_at": utcnow()})
    manifest = build_manifest(repo, "h1", "test")
    manifest["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    rendered = markdown.render(manifest)
    assert rendered.count(LABEL) == 6
    assert '"labelled\\_suspicious\\_only": 6' in rendered
    path = _docx(tmp_path, monkeypatch, manifest)
    with ZipFile(path) as archive:
        document = ElementTree.fromstring(archive.read("word/document.xml"))
    words = "\n".join(node.text or "" for node in document.iter(f"{{{executive._WORD}}}t"))
    assert words.count(LABEL) == 6
    assert '"labelled_suspicious_only": 6' in words
    view = assessment_view(repo, "h1")
    assert sum(item.get("suspicious_content", False)
               for section in view["sections"] for item in section["sentences"]) == 6
    environment = Environment(loader=FileSystemLoader(app.HERE / "templates"), autoescape=select_autoescape())
    html = environment.get_template("agent_panel.html").render(
        ai_panel={"state": "completed", "run": {}, "usage": {}, "budgets": {}, "counts": {},
                  "assessment": view}, h={"id": "h1"}, user={"r": "analyst"})
    assert html.count(LABEL) == 6
    assert "labelled_suspicious_only" in html
