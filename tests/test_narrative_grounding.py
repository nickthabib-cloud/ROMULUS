"""The AI narrative is grounded in what the cited activity is, not only in that it is cited (fake providers).

The AI triage pass runs inside the agent phase, after the investigation and before the assessment, under the phase's
lease and on its own budget; its verdicts and each listed finding's evidence strength reach the assess input. The
checker then holds every narrative paragraph to the deterministic evidence: an attack-phase label needs a Reported,
confirmed or likely-attack finding, an observed sentence needs a reportable finding, and a paragraph resting only on
benign-triaged activity is shown as weakly supported. Nothing is removed, and every renderer shows the labels.
"""
from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from romulus.agent import grounding
from romulus.agent import provider as provider_port
from romulus.agent.aliases import AliasBook
from romulus.agent.assessment import _assessment_input, check_assessment
from romulus.agent.grounding import TriageContext, triage_context
from romulus.agent.investigate import run_agent_phase
from romulus.agent.provider import ProviderUnavailable
from romulus.agent.provider.base import ToolCall
from romulus.agent.toolbox import Toolbox
from romulus.agent.triage import latest_summary
from romulus.config import Settings
from romulus.hunt import run as hunt_run
from romulus.hunt.rank import place_late_findings
from romulus.hunt.triage import run_cited_triage_in_phase, run_triage_in_phase, write_export
from romulus.report import executive, markdown
from romulus.report.manifest import build_manifest, narrative_paragraphs
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import TRIAGE_PURPOSE, Repo
from tests import test_ai_triage as ta
from tests import test_web_agent_a6
from tests.agent_scripted import ScriptedProvider, response
from tests.test_agent_render_a6 import _docx
from tests.test_report import _repo_with_finding

IN_WINDOW = "2024-11-18T10:30:00Z"
USED = TriageContext(True, "complete", 1)
OFF = TriageContext(False, "off")


@pytest.fixture(autouse=True)
def _stage(tmp_path):
    ta._STAGE[:] = [tmp_path / "stage"]
    yield


def _hunt():
    """A ranked hunt: two confirmed findings, unreported filler groups, the attack rule r.attack deep in the order
    and one agent proposal; triaged with r.attack likely attack and every other group likely benign."""
    repo = ta._hunt(filler=10)
    summary = run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                                  provider=ta.FakeTriage(ta.by_rule({"r.attack"})))
    assert summary["status"] == "complete"
    return repo


def _file_hunt(tmp_path, name="hunt"):
    """The same hunt, untriaged, in a file database: the agent phase runs its sessions on worker threads."""
    engine = make_engine(tmp_path / f"{name}.sqlite")
    migrate(engine)
    return ta._hunt(filler=10, repo=Repo(engine))


def _s(alias, text="The recorded activity ran on the host.", kind="observed"):
    return {"text": text, "cites": [alias] if isinstance(alias, str) else alias, "kind": kind}


def _p(sentences, phase):
    return {"time_span": {"start": IN_WINDOW, "end": IN_WINDOW}, "phase": phase, "sentences": sentences}


def _reply(narrative):
    return {"overall": [], "key_steps": [], "narrative": narrative,
            "confidence": {"overall": "medium", "reasons": []}, "alternatives": [], "gaps": [], "next_checks": []}


def _f(repo, finding_id):
    return AliasBook(repo, "h1").alias_for("F", finding_id)


# ------------------------------------------------------------------------------------------------ evidence strength
def test_strength_reads_lane_reported_confirmed_and_the_group_verdict():
    repo = _hunt()
    found = grounding.EvidenceStrength(repo, "h1", USED).findings(
        ["c-urgent", "f-0001", "z-attack-0", "zz-agent", "missing"])
    assert found["c-urgent"].view() == {"lane": "urgent", "reported": True, "confirmed": True,
                                        "triage": "likely_benign"}
    assert found["c-urgent"].strong and not found["c-urgent"].benign      # confirmed outranks a benign verdict
    assert found["f-0001"].view() == {"lane": "lead", "reported": False, "confirmed": False,
                                      "triage": "likely_benign"}
    assert found["f-0001"].benign and not found["f-0001"].strong
    assert found["z-attack-0"].triage == "likely_attack" and found["z-attack-0"].strong
    # the agent's own proposal is never triaged and never supports the narrative
    assert found["zz-agent"].triage == "not_triaged" and not found["zz-agent"].reportable
    assert "missing" not in found
    # without a usable pass every finding reads as not triaged
    off = grounding.EvidenceStrength(repo, "h1", OFF).findings(["z-attack-0"])
    assert off["z-attack-0"].triage == "not_triaged" and not off["z-attack-0"].strong


def test_without_a_final_ranking_reported_follows_the_lanes_of_the_headline_result():
    repo, cid = _repo_with_finding()
    assert repo.detection_result("h1")[1] == "reportable_findings"
    assert grounding.EvidenceStrength(repo, "h1", OFF).findings([cid])[cid].reported      # lane high
    with repo.engine.begin() as connection:
        connection.exec_driver_sql("UPDATE candidate SET lane = 'lead'")
    assert not grounding.EvidenceStrength(repo, "h1", OFF).findings([cid])[cid].reported


def test_verdicts_are_read_by_group_on_an_unranked_hunt_and_reported_is_not_only_confirmed():
    repo = ta._hunt(filler=10, ranked=False)
    run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                        provider=ta.FakeTriage(ta.by_rule({"r.attack"})))
    found = grounding.EvidenceStrength(repo, "h1", USED).findings(["z-attack-0", "f-0001", "f-0000"])
    assert found["z-attack-0"].triage == "likely_attack" and found["f-0001"].triage == "likely_benign"
    assert found["f-0000"].reported and not found["f-0000"].confirmed                     # lane high, unranked
    # ranked: a lead finding on a confirmed entity is Reported without being confirmed, and anchors a phase
    ranked = ta._repo()
    ta._insert(ranked, [ta._row("c-urgent", "r.confirmed", lane="urgent", host="quiet"),
                        ta._row("q-lead", "r.q", lane="lead", host="quiet"),
                        ta._row("o-lead", "r.o", lane="lead", host="other")])
    from romulus.hunt.rank import PASS_FINAL, compute_rank_pass
    compute_rank_pass(ranked, "h1", PASS_FINAL)
    strength = grounding.EvidenceStrength(ranked, "h1", OFF).findings(["q-lead", "o-lead"])
    assert strength["q-lead"].reported and not strength["q-lead"].confirmed and strength["q-lead"].strong
    assert not strength["o-lead"].reported
    checked, counts = check_assessment(ranked, "h1", _reply([_p([_s(_f(ranked, "q-lead"))], "Discovery"),
                                                             _p([_s(_f(ranked, "o-lead"))], "Discovery")]),
                                       triage=OFF)
    assert [p["phase"] for p in checked["narrative"]] == ["Discovery", "Context"]
    assert counts == {"phase_weakly_supported": 1}


def test_an_assessment_outside_the_phase_reads_the_latest_pass_unless_triage_is_off(tmp_path):
    from romulus.agent.assessment import run_assessment
    from romulus.agent.provider import AgentBudget, BudgetLimits
    repo = _hunt()
    seen = {}

    def answer(request):
        seen["input"] = json.loads(request.messages[1]["content"].split("\n", 1)[1])
        return response(parsed=_reply([_p([_s(_f(repo, "f-0001"))], "Persistence")]))
    for value, expected in (("on", {"verdicts": "available", "status": "complete", "pass": 1}),
                            ("off", {"verdicts": "unavailable", "status": "off"})):
        budget = AgentBudget.from_usage(BudgetLimits(10, 1_000_000, 600, 0, 0, 0), {}, clock=lambda: 0.0)
        result = run_assessment(Settings(home=tmp_path, agent_triage=value), repo, "h1",
                                ScriptedProvider([answer]), budget, clock=lambda: 0.0)
        assert seen["input"]["triage"] == expected
        assert result["body"]["narrative"][0]["support_reason"] == (
            "triaged_likely_benign" if value == "on" else "no_reported_finding")


def test_triage_context_says_whether_verdicts_are_available():
    assert triage_context(None, enabled=False).view() == {"verdicts": "unavailable", "status": "off"}
    assert triage_context(None).view() == {"verdicts": "unavailable", "status": "not_run"}
    assert triage_context({"status": "failed", "reason": "provider_unavailable"}).view() == {
        "verdicts": "unavailable", "status": "failed"}
    assert triage_context({"status": "partial", "pass": 3}).view() == {"verdicts": "available",
                                                                       "status": "partial", "pass": 3}


# ----------------------------------------------------------------------------------------------- the evidence rules
def test_an_attack_phase_citing_only_unreported_benign_triaged_findings_becomes_weakly_supported_context():
    repo = _hunt()
    body = _reply([_p([_s(_f(repo, "f-0001")), _s(_f(repo, "f-0003"), "This likely set up persistence.",
                                                    "inferred")], "Persistence")])
    checked, counts = check_assessment(repo, "h1", deepcopy(body), triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Context" and "tactic" not in paragraph
    assert paragraph["weakly_supported"] and paragraph["support_reason"] == "triaged_likely_benign"
    assert paragraph["model_phase"] == "Persistence"
    # nothing is removed: both sentences stay, marked uncertain
    assert [(s["text"], s["kind"]) for s in paragraph["sentences"]] == [
        ("The recorded activity ran on the host.", "uncertain"), ("This likely set up persistence.", "uncertain")]
    assert counts == {"weakly_supported_benign_triage": 1, "labelled_uncertain_benign_triage": 2}
    # without verdicts the same paragraph cites no Reported finding: context, its sentences as written
    checked, counts = check_assessment(repo, "h1", deepcopy(body), triage=OFF)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Context" and paragraph["support_reason"] == "no_reported_finding"
    assert [s["kind"] for s in paragraph["sentences"]] == ["observed", "inferred"]
    assert counts == {"phase_weakly_supported": 1}


def test_a_paragraph_citing_a_reported_confirmed_or_likely_attack_finding_keeps_its_phase():
    repo = _hunt()
    for cited in ("c-urgent", "z-attack-0"):
        body = _reply([_p([_s(_f(repo, cited)), _s(_f(repo, "f-0001"), "A routine job ran.", "inferred")],
                          "Lateral Movement")])
        checked, counts = check_assessment(repo, "h1", body, triage=USED)
        paragraph = checked["narrative"][0]
        assert paragraph["phase"] == "Lateral Movement" and paragraph["tactic"] == "lateral-movement"
        assert "weakly_supported" not in paragraph and counts == {}
        assert [s["kind"] for s in paragraph["sentences"]] == ["observed", "inferred"]
    # a confirmed finding triaged likely benign still anchors the phase: the deterministic evidence outranks the model
    checked, counts = check_assessment(repo, "h1", _reply([_p([_s(_f(repo, "c-urgent"))], "Impact")]), triage=USED)
    assert checked["narrative"][0]["phase"] == "Impact" and counts == {}


def test_any_label_without_strong_support_is_weakly_supported_whatever_it_says():
    repo = _hunt()
    body = _reply([_p([_s(_f(repo, "f-0001"), kind="inferred")], "Routine provisioning"),
                   _p([_s([_f(repo, "f-0001"), _f(repo, "z-attack-1")], kind="inferred")], "Staging"),
                   _p([_s(_f(repo, "f-0003"), kind="inferred")], "Exploitation of the web server"),
                   _p([_s(_f(repo, "f-0005"), kind="inferred")], "")])
    checked, counts = check_assessment(repo, "h1", body, triage=OFF)
    labels = [(p["phase"], p.get("model_phase"), p.get("support_reason")) for p in checked["narrative"]]
    # a free-text label is no way around the rule: it becomes Context, the model's words kept beside it
    assert labels == [("Context", "Routine provisioning", "no_reported_finding"),
                      ("Context", "Staging", "no_reported_finding"),       # no verdicts: r.attack is not strong
                      ("Context", "Exploitation of the web server", "no_reported_finding"),
                      ("Context", None, "no_reported_finding")]
    assert counts == {"phase_weakly_supported": 4}
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    first = checked["narrative"][0]
    assert first["phase"] == "Context" and first["support_reason"] == "triaged_likely_benign"
    assert first["sentences"][0]["kind"] == "uncertain"
    assert checked["narrative"][1]["phase"] == "Staging" and "weakly_supported" not in checked["narrative"][1]
    assert counts == {"weakly_supported_benign_triage": 3, "labelled_uncertain_benign_triage": 3}


def test_an_observed_sentence_needs_a_reportable_finding():
    repo = _hunt()
    ta._insert(repo, [ta._row("ctx-1", "r.context", lane="context", host="victim")])
    with repo.engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO typed_event (id, hunt_id, family, ts, host, raw_ids, normalizer, event) VALUES "
            "('uncited-event', 'h1', 'process_exec', '2024-11-18 10:30:00', 'victim', '[]', 't', '{}')")
    event = AliasBook(repo, "h1").alias_for("E", "uncited-event")
    body = _reply([_p([_s(_f(repo, "ctx-1"), "A context record shows the logon."),
                       _s(event, "An uncited record shows the process."),
                       _s(_f(repo, "z-attack-2"), "The attack rule fired.")], "Execution")])
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    paragraph = checked["narrative"][0]
    assert [s["kind"] for s in paragraph["sentences"]] == ["inferred", "inferred", "observed"]
    assert paragraph["phase"] == "Execution" and counts == {"downgraded_observed_weak_evidence": 2}


def test_an_evidence_record_stands_for_its_findings_and_an_incomplete_lookup_is_never_strong(monkeypatch):
    repo, _cid = _repo_with_finding()
    with repo.engine.begin() as connection:
        connection.exec_driver_sql("UPDATE candidate SET lane = 'lead'")     # reportable, not Reported
    event = AliasBook(repo, "h1").alias_for("E", "ev1")
    body = _reply([_p([_s(event, "The process read the credential store.")], "Credential Access")])
    checked, counts = check_assessment(repo, "h1", deepcopy(body), triage=OFF)
    assert checked["narrative"][0]["phase"] == "Context" and checked["narrative"][0]["sentences"][0]["kind"] == (
        "observed")                                                            # the record's finding is reportable
    assert counts == {"phase_weakly_supported": 1}
    # more findings cite the record than the lookup reads: support of unknown strength is weak, and says so
    with repo.engine.begin() as connection:
        connection.exec_driver_sql("UPDATE candidate SET lane = 'high'")     # Reported, but past the lookup's cap
    monkeypatch.setattr(grounding, "EVENT_FINDINGS", 0)
    checked, counts = check_assessment(repo, "h1", deepcopy(body), triage=OFF)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Context" and paragraph["support_reason"] == "support_unknown"
    assert paragraph["model_phase"] == "Credential Access" and paragraph["sentences"][0]["kind"] == "observed"
    assert counts == {"weakly_supported_unknown_support": 1}
    assert markdown.narrative_weak_reason(paragraph) == (
        "Weakly supported: support could not be determined (citation cap); the model labelled it Credential "
        "Access.")


def test_the_evidence_fields_never_enter_the_response_schema():
    from romulus.agent.assessment import ASSESSMENT_SCHEMA
    text = json.dumps(ASSESSMENT_SCHEMA)
    assert "weakly_supported" not in text and "support_reason" not in text and "model_phase" not in text


# ------------------------------------------------------------------------------------------------- the assess input
def test_the_assess_input_gives_each_listed_finding_its_evidence_strength_and_nothing_more():
    repo = _hunt()
    data = _assessment_input(repo, "h1", token_budget=200_000, triage=USED)["data"]
    assert data["triage"] == {"verdicts": "available", "status": "complete", "pass": 1}
    cards = {card["alias"]: card for incident in data["incidents"] for card in incident["top_findings"]}
    attack = cards.get(_f(repo, "z-attack-0"))
    confirmed = cards[_f(repo, "c-urgent")]
    assert {key: confirmed[key] for key in ("lane", "reported", "confirmed", "triage")} == {
        "lane": "urgent", "reported": True, "confirmed": True, "triage": "likely_benign"}
    assert attack is None or attack["triage"] == "likely_attack"
    assert all(set(card) == {"alias", "lane", "time", "claim", "reported", "confirmed", "triage"}
               for card in cards.values())
    # an agent proposal is never presented as Reported evidence
    assert data["agent_findings"][0]["triage"] == "not_triaged" and "reported" not in data["agent_findings"][0]
    text = json.dumps(data)
    for internal in ("score", "rank_position", "rank_reasons", "rationale", "incident_label", "best_position"):
        assert internal not in text
    off = _assessment_input(repo, "h1", token_budget=200_000, triage=OFF)["data"]
    assert off["triage"] == {"verdicts": "unavailable", "status": "off"}
    assert {card["triage"] for incident in off["incidents"] for card in incident["top_findings"]} == {"not_triaged"}


# ------------------------------------------------------------------------------------- the phase order, end to end
def _assessment_body(repo):
    return _reply([_p([_s(_f(repo, "z-attack-0"))], "Lateral Movement"),
                   _p([_s(_f(repo, "f-0001"))], "Persistence")])


def _agent_script(repo, seen: dict):
    finish = [ToolCall("f", "finish_session", {"summary": "The evidence review is complete."}, "{}")]

    def assess(request):
        seen["assess_input"] = json.loads(request.messages[1]["content"].split("\n", 1)[1])
        seen["sessions_at_assess"] = [row["purpose"] for row in repo.agent_sessions("h1")]
        return response(parsed=_assessment_body(repo))
    return ScriptedProvider([response(tool_calls=finish), response(tool_calls=finish), assess])


def _phase_settings(**overrides):
    return ta.settings(agent_max_initial_hypotheses=1, **overrides)


def test_the_phase_runs_orient_investigate_triage_then_assess_under_one_lease(tmp_path):
    repo = _file_hunt(tmp_path)
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    seen: dict = {}
    triage_provider = ta.FakeTriage(ta.by_rule({"r.attack"}))

    def triage(heartbeat):
        seen["sessions_at_triage"] = [row["purpose"] for row in repo.agent_sessions("h1")]
        seen["lease_at_triage"] = repo.agent_run("h1")["lease_owner"]
        return run_triage_in_phase(_phase_settings(), repo, "h1", owner_token=owner, heartbeat=heartbeat,
                                   provider=triage_provider)
    provider = _agent_script(repo, seen)
    result = run_agent_phase(_phase_settings(), repo, "h1", provider=provider, owner_token=owner,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0, triage=triage)
    # orient and investigate ran before triage; the assessment after it, reading its verdicts
    assert seen["sessions_at_triage"] == ["orient", "investigate"]
    assert seen["sessions_at_assess"] == ["orient", "investigate", "assess"]
    # the pass ran under the phase's own lease: no second claim (it would have been refused)
    assert seen["lease_at_triage"] == owner
    assert seen["assess_input"]["triage"] == {"verdicts": "available", "status": "complete", "pass": 1}
    verdicts = {card["triage"] for incident in seen["assess_input"]["incidents"]
                for card in incident["top_findings"]}
    assert {"likely_attack", "likely_benign"} <= verdicts
    # the stored narrative was checked against those verdicts
    stored = repo.agent_assessments("h1")[-1]
    assert [p["phase"] for p in stored["body"]["narrative"]] == ["Lateral Movement", "Context"]
    assert stored["checker"] == {"weakly_supported_benign_triage": 1, "labelled_uncertain_benign_triage": 1}
    # the phase result carries the pass; the stored phase summary keeps a short record of it (the pass's full
    # summary is stored on its own); its own usage leaves the triage calls out
    assert result.state == "completed" and result.as_dict()["ai_triage"]["status"] == "complete"
    record = repo.latest_audit("h1", "hunt.ai_agent_summary")["detail"]["ai_triage"]
    assert record == {"status": "complete", "reason": None, "pass": 1, "model": "fake-triage-model",
                      "cited": {"status": "skipped", "reason": "no cited group lacks a verdict", "groups": 0,
                                "untriaged_cited_skipped": 0}}
    assert result.usage["calls"] == 3 == len(provider.requests)
    # the agent's late finding was placed into the final ranking before the pass: the view stays current after the
    # phase finalizes, in the manifest and in the web's own check
    from romulus.report.triage import triage_view
    assert repo.agent_run("h1")["state"] == "completed" and not repo.unranked_findings("h1")
    assert build_manifest(repo, "h1", "test")["ai_triage"]["stale"] is False
    assert triage_view(repo, "h1")["stale"] is False
    assert repo.agent_usage("h1", purposes=(TRIAGE_PURPOSE,))["calls"] == len(triage_provider.requests) > 0


def test_the_in_phase_pass_is_reused_on_the_same_digest_and_late_findings_never_make_it_stale(tmp_path):
    repo = ta._hunt(filler=10)
    provider = ta.FakeTriage(ta.by_rule({"r.attack"}))
    first = run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                                provider=provider)
    calls = len(provider.requests)
    second = run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                                 provider=provider)
    assert second.get("reused") and second["prompt_digest"] == first["prompt_digest"]
    assert len(provider.requests) == calls
    # the agent's proposal is placed into the final ranking when the phase finishes: the pass stays current
    assert place_late_findings(repo, "h1") is not None
    header = write_export(repo, "h1", tmp_path / "order.json")
    assert header["stale"] is False and header["pass"] == first["pass"]


def test_the_hunt_uses_the_in_phase_pass_and_runs_no_second_one(monkeypatch):
    repo = ta._hunt(filler=10)
    built = []
    monkeypatch.setattr(hunt_run, "agent_readiness", lambda s, *_a: SimpleNamespace(ready=True, model=s.agent_model))

    def build(s, **_kw):
        built.append(ta.FakeTriage(ta.by_rule({"r.attack"})))
        return built[-1]
    monkeypatch.setattr(hunt_run, "build_provider", build)
    in_phase = {"status": "complete", "pass": 7}
    result = hunt_run._with_agent_result({"hunt_id": "h1"}, repo, {"status": "completed", "ai_triage": in_phase},
                                         settings=ta.settings(), manifest={"ai_agent": {"requested": True}})
    assert result["ai_triage"] == in_phase and built == []
    # a phase that ran none (it reused its assessment) leaves the pass to after the phase, as before
    result = hunt_run._with_agent_result({"hunt_id": "h1"}, repo, {"status": "completed"},
                                         settings=ta.settings(), manifest={"ai_agent": {"requested": True}})
    assert result["ai_triage"]["status"] == "complete" and len(built) == 1


def test_the_hunt_agent_phase_builds_the_triage_hook_on_the_triage_model(monkeypatch, tmp_path):
    repo = _file_hunt(tmp_path)
    seen: dict = {}
    models = []
    def ready(s, *_a):
        return SimpleNamespace(ready=True, model=s.agent_model)
    monkeypatch.setattr(hunt_run, "agent_readiness", ready)
    monkeypatch.setattr(provider_port, "agent_readiness", ready)              # the triage model's own check

    def build(s, **_kw):
        models.append(s.agent_model)
        if s.agent_model != "triage-model":
            return _agent_script(repo, seen)
        triage = ta.FakeTriage(ta.by_rule({"r.attack"}))
        triage.model = s.agent_model
        return triage
    monkeypatch.setattr(hunt_run, "build_provider", build)
    from romulus.hunt import agent_tools
    monkeypatch.setattr(agent_tools, "build_agent_toolbox",
                        lambda s, repo, hunt_id, session_id, **_kw: Toolbox(repo, hunt_id, session_id=session_id))
    s = _phase_settings(agent_model="agent-model", agent_triage_model="triage-model")
    manifest = {"ai_agent": {"requested": True}}
    summary = hunt_run._ai_agent_phase(s, repo, "h1", manifest, None, None, {})
    assert models == ["agent-model", "triage-model"]
    assert seen["sessions_at_assess"] == ["orient", "investigate", "assess"]
    assert summary["ai_triage"]["status"] == "complete" and summary["ai_triage"]["model"] == "triage-model"
    combined = hunt_run._with_agent_result({"hunt_id": "h1"}, repo, summary, settings=s, manifest=manifest)
    assert combined["ai_triage"] == summary["ai_triage"] and models == ["agent-model", "triage-model"]
    # off: no hook, and the assessment says triage was off
    repo2 = _file_hunt(tmp_path, "off")
    seen.clear()
    monkeypatch.setattr(hunt_run, "build_provider", lambda s, **_kw: _agent_script(repo2, seen))
    summary = hunt_run._ai_agent_phase(_phase_settings(agent_triage="off"), repo2, "h1", manifest, None, None, {})
    assert "ai_triage" not in summary and seen["assess_input"]["triage"] == {"verdicts": "unavailable",
                                                                             "status": "off"}


def _run_phase(repo, triage, *, clock=lambda: 0.0, **settings):
    seen: dict = {}
    provider = _agent_script(repo, seen)
    result = run_agent_phase(_phase_settings(**settings), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=clock, triage=triage)
    return result, seen


def test_a_failed_or_raising_triage_pass_leaves_the_assessment_as_it_was(tmp_path):
    for number, (hook, status) in enumerate( ((lambda _hb: {"status": "failed", "reason": "provider_unavailable"}, "failed"),
                         (lambda _hb: 1 / 0, "failed"),
                         (None, "not_run"))):
        repo = _file_hunt(tmp_path, f"run{number}")
        result, seen = _run_phase(repo, hook)
        assert result.state == "completed"
        assert seen["assess_input"]["triage"] == {"verdicts": "unavailable", "status": status}
        stored = repo.agent_assessments("h1")[-1]
        # no verdicts: neither cited finding is Reported or confirmed, so both paragraphs are context, their
        # sentences as written
        assert stored["checker"] == {"phase_weakly_supported": 2}
        if hook is not None:
            assert result.as_dict()["ai_triage"]["status"] == "failed"
        if number == 1:
            assert "ZeroDivisionError" in result.as_dict()["ai_triage"]["reason"]


def test_triage_wall_time_and_calls_are_not_charged_to_the_agent_budget(tmp_path):
    repo = _file_hunt(tmp_path)
    now = [0.0]

    def slow(heartbeat):
        now[0] += 10_000.0                         # longer than the agent's whole wall budget
        return run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=heartbeat,
                                   provider=ta.FakeTriage(ta.by_rule({"r.attack"})))
    result, seen = _run_phase(repo, slow, clock=lambda: now[0], agent_max_wall_seconds=600)
    assert result.state == "completed" and "assess_input" in seen
    assert "wall-clock" not in str(result.reason) and repo.agent_assessments("h1")[-1]["source"] == "agent"
    # the agent's budget counts only its own calls: the triage pass's are its own
    assert result.usage["calls"] == 3 and repo.agent_usage("h1")["calls"] > 3


def test_a_reused_assessment_runs_no_triage_in_the_phase(tmp_path):
    repo = _file_hunt(tmp_path)
    first, _seen = _run_phase(repo, None)
    calls = []
    second = run_agent_phase(_phase_settings(), repo, "h1", provider=ScriptedProvider([]),
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0, triage=lambda hb: calls.append(1) or {"status": "complete"})
    assert first.state == "completed" and second.state == "completed" and calls == []
    assert "ai_triage" not in second.as_dict()


# ----------------------------------------------------------------------------------------------------------- render
HOSTILE_PHASE = "<Persistence>"


def _weak_assessment(repo, tmp_path):
    """A stored model assessment with one supported and one weakly supported paragraph."""
    from romulus.agent.assessment import run_assessment
    from romulus.agent.provider import AgentBudget, BudgetLimits
    body = _reply([_p([_s(_f(repo, "z-attack-0"))], "Lateral Movement"),
                   _p([_s(_f(repo, "f-0001"), "<script>alert(1)</script> ran on boot.")], HOSTILE_PHASE)])
    budget = AgentBudget.from_usage(BudgetLimits(10, 100_000, 600, 0, 0, 0), repo.agent_usage("h1"),
                                    clock=lambda: 0.0)
    result = run_assessment(Settings(home=tmp_path), repo, "h1", ScriptedProvider([response(parsed=body)]), budget,
                            clock=lambda: 0.0, triage=triage_context(latest_summary(repo, "h1")))
    assert result is not None
    weak = result["body"]["narrative"][1]
    assert weak["phase"] == "Context" and weak["model_phase"] == HOSTILE_PHASE
    return result


def _manifest(repo):
    manifest = build_manifest(repo, "h1", "test")
    manifest["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    return manifest


def test_the_manifest_carries_the_weak_labels_and_drops_anything_else():
    paragraphs = narrative_paragraphs([
        {"time_span": {}, "phase": "Context", "tactic": "persistence", "weakly_supported": True,
         "support_reason": "made-up", "model_phase": "Persistence", "extra": "x",
         "sentences": [{"text": "t", "kind": "uncertain", "cites": ["F1"]}]},
        {"time_span": {}, "phase": "Impact", "weakly_supported": "yes", "sentences": [{"text": "t", "kind": "observed",
                                                                                      "cites": []}]}])
    assert paragraphs[0] == {"time_span": {"start": "", "end": ""}, "phase": "Context", "weakly_supported": True,
                             "support_reason": "no_reported_finding", "model_phase": "Persistence",
                             "sentences": [{"text": "t", "kind": "uncertain", "cites": ["F1"]}]}
    assert "weakly_supported" not in paragraphs[1]                     # an old or malformed body is not weak


def test_markdown_and_docx_label_weak_paragraphs_and_escape_them(tmp_path, monkeypatch):
    repo = _hunt()
    _weak_assessment(repo, tmp_path)
    manifest = _manifest(repo)
    text = markdown.render(manifest)
    section = text[text.index("## AI assessment"):]
    assert "**1. Lateral Movement · " in section
    assert f"**2. Context (weakly supported) · {IN_WINDOW}**" in section
    assert ("*Weakly supported: cited activity was triaged as likely benign; the model labelled it "
            "\\<Persistence\\>.*") in section
    assert "<Persistence>" not in text and "<script>" not in text
    # each paragraph's support mix, muted, after its sentences
    first = section[section.index("**1. Lateral Movement"):section.index("**2. Context")]
    assert first.rstrip().endswith("*Support: 1 triaged possible or likely attack.*")
    assert "*Support: 1 triaged likely benign.*" in section
    path = _docx(tmp_path, monkeypatch, manifest)
    with ZipFile(path) as archive:
        document = ElementTree.fromstring(archive.read("word/document.xml"))
    word = executive._WORD
    paragraphs = [(["".join(t.text or "" for t in p.iter(f"{{{word}}}t"))],
                   [node.tag.rsplit("}", 1)[-1] for node in p.iter()]) for p in document.iter(f"{{{word}}}p")]
    heading = next(tags for texts, tags in paragraphs if texts[0].startswith("2. Context (weakly supported)"))
    assert "i" in heading and "color" in heading                      # muted
    reason = next(tags for texts, tags in paragraphs
                  if texts[0] == ("Weakly supported: cited activity was triaged as likely benign; the model labelled "
                                  "it <Persistence>."))
    assert "i" in reason
    supported = next(tags for texts, tags in paragraphs if texts[0].startswith("1. Lateral Movement"))
    assert "i" not in supported and "color" not in supported
    support = next(tags for texts, tags in paragraphs if texts[0] == "Support: 1 triaged possible or likely attack.")
    assert "i" in support and "color" in support


web_setup = test_web_agent_a6.setup


def test_the_web_shows_weak_paragraphs_muted_with_their_reason_escaped(web_setup):
    client, repo, cid, *_ = web_setup
    test_web_agent_a6.run_row(repo)
    ta._insert(repo, [ta._row("lead-1", "r.lead", lane="lead", host="web01"),      # reportable, not Reported
                      ta._row("urg-1", "r.urgent", lane="urgent", host="web01")])  # confirmed
    body = _reply([_p([_s(_f(repo, "lead-1"), "The process read the credential store.")], HOSTILE_PHASE),
                   _p([_s(_f(repo, cid), "The read was done by the attacker.", "inferred")], "Objective"),
                   _p([_s(_f(repo, "urg-1"), "An administrator ran the tool.", "inferred")], "Context: admin work")])
    checked, counts = check_assessment(repo, "h1", body, triage=OFF)
    assert counts == {"phase_weakly_supported": 1, "model_context_cites_attack": 1}
    repo.save_agent_assessment({"id": "aa-weak", "hunt_id": "h1", "revision": 1, "source": "agent",
                                "model": {"provider": "scripted", "model_requested": "m"}, "body": checked,
                                "checker": counts, "created_at": utcnow()})
    for path in ("/hunts/h1", "/hunts/h1/assessment"):
        page = client.get(path).text
        narrative = page[page.index('<ol class="narrative">'):]
        narrative = narrative[:narrative.index("</ol>")]
        assert narrative.count('<li class="weak">') == 1 and narrative.count("<li>") == 2
        # model context citing a confirmed finding: Context, unmuted, its reason in plain view
        assert "<li><div class=\"narrative-head\"><b>Context</b>" in narrative
        assert ('<p class="small context-reason">Labelled context by the model, but it cites confirmed or '
                "attack-triaged findings; the model labelled it Context: admin work.</p>") in narrative
        assert "<b>Context (weakly supported)</b>" in narrative and "<b>Objective</b>" in narrative
        assert ('<p class="help small weak-reason">Weakly supported: no reported finding cited; the model labelled '
                "it &lt;Persistence&gt;.</p>") in narrative
        assert "<Persistence>" not in page
        # every paragraph shows its support mix, muted
        assert '<p class="help small support-mix">Support: 1 not reported.</p>' in narrative
        assert '<p class="help small support-mix">Support: 1 reported, no benign verdict.</p>' in narrative


# ------------------------------------------------------------------------- the verdict outweighs Reported; support mix
def _reported_rows(repo=None, count=4):
    """A ranked hunt where `count` lead findings on a confirmed host are Reported (not confirmed), untriaged."""
    from datetime import timedelta

    from romulus.hunt.rank import PASS_FINAL, compute_rank_pass
    repo = ta._repo(repo)
    ta._insert(repo, [ta._row("c-urgent", "r.confirmed", lane="urgent", host="quiet"),
                      *[ta._row(f"q-{index}", f"r.q{index}", lane="lead", host="quiet",
                                ts=ta.START + timedelta(minutes=5 * index)) for index in range(count)]])
    compute_rank_pass(repo, "h1", PASS_FINAL)
    ta._finished(repo)
    found = grounding.EvidenceStrength(repo, "h1", OFF).findings([f"q-{index}" for index in range(count)])
    assert len(found) == count and all(item.reported and not item.confirmed for item in found.values())
    return repo


def by_rules(verdicts: dict[str, str | None], default: str | None = "likely_benign"):
    """A triage policy by rule; a rule mapped to None (or the default None) gets no answer, so no verdict."""
    def policy(cards):
        return {"groups": [ta.verdict(card, assessment) for card in cards
                           if (assessment := verdicts.get(card["rule"]["id"], default)) is not None]}
    return policy


def _reported_hunt(verdicts: dict[str, str], count=4):
    """`_reported_rows`, triaged by rule: `verdicts` maps a rule to its assessment, every other group is likely
    benign."""
    repo = _reported_rows(count=count)
    summary = run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                                  provider=ta.FakeTriage(by_rules(verdicts)))
    assert summary["status"] == "complete"
    return repo


def _quiet(repo, count=4):
    return _reply([_p([_s([_f(repo, f"q-{index}") for index in range(count)])], "Persistence")])


def test_reported_findings_all_triaged_likely_benign_are_weak():
    repo = _reported_hunt({})
    checked, counts = check_assessment(repo, "h1", _quiet(repo), triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Context" and paragraph["support_reason"] == "triaged_likely_benign"
    assert paragraph["model_phase"] == "Persistence" and paragraph["sentences"][0]["kind"] == "uncertain"
    assert paragraph["support"] == {"benign": 4}
    assert counts == {"weakly_supported_benign_triage": 1, "labelled_uncertain_benign_triage": 1}


def test_one_attack_triaged_cite_keeps_the_paragraph_and_the_support_line_shows_the_mix():
    for verdict in ("possible_attack", "likely_attack"):
        repo = _reported_hunt({"r.q2": verdict})
        # balanced: one attack-triaged cite beside one benign holds the label
        body = _reply([_p([_s([_f(repo, "q-2"), _f(repo, "q-0")])], "Persistence")])
        checked, counts = check_assessment(repo, "h1", body, triage=USED)
        paragraph = checked["narrative"][0]
        assert paragraph["phase"] == "Persistence" and "weakly_supported" not in paragraph and counts == {}
        assert paragraph["support"] == {"attack": 1, "benign": 1} and "context_reason" not in paragraph
        # 1 of 4: the paragraph is mostly benign, shown as context, and its attack-triaged cite is lifted out
        checked, counts = check_assessment(repo, "h1", _quiet(repo), triage=USED)
        paragraph = checked["narrative"][0]
        assert paragraph["phase"] == "Context" and paragraph["context_reason"] == "mostly_benign_support"
        assert "weakly_supported" not in paragraph and counts == {"context_mostly_benign_support": 1}
        assert [step["finding"] for step in paragraph["attack_steps"]] == ["q-2"]
        assert paragraph["support"] == {"attack": 1, "benign": 3}
        assert markdown.narrative_support(paragraph) == (
            "Support: 1 triaged possible or likely attack, 3 triaged likely benign.")


def test_reported_findings_without_a_verdict_stay_strong_and_a_failed_pass_keeps_the_old_rule():
    repo = _reported_hunt({"r.q1": "insufficient_evidence"})
    for context in (OFF, TriageContext(False, "failed"), TriageContext(False, "skipped"),
                    TriageContext(False, "not_run")):
        checked, counts = check_assessment(repo, "h1", _quiet(repo), triage=context)
        paragraph = checked["narrative"][0]
        assert paragraph["phase"] == "Persistence" and counts == {} and paragraph["support"] == {"reported": 4}
    # an insufficient-evidence verdict is no benign verdict: that Reported finding is strong support, so beside three
    # benign cites it is lifted out of a context paragraph with its verdict as it stands, never called attack-triaged
    checked, counts = check_assessment(repo, "h1", _quiet(repo), triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Context" and counts == {"context_mostly_benign_support": 1}
    assert paragraph["support"] == {"reported": 1, "benign": 3}
    assert [(step["finding"], step["support"], step["triage"]) for step in paragraph["attack_steps"]] == [
        ("q-1", "reported", "insufficient_evidence")]
    assert markdown.narrative_step_text(paragraph["attack_steps"][0]) == (
        "r.q1 · lane lead · triage: insufficient evidence")
    # a confirmed finding outweighs any verdict
    body = _reply([_p([_s([_f(repo, "c-urgent"), _f(repo, "q-0")])], "Impact")])
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    assert checked["narrative"][0]["phase"] == "Impact" and checked["narrative"][0]["support"] == {
        "confirmed": 1, "benign": 1}


@pytest.mark.parametrize("label", ["Context", "context: routine deployment", "CONTEXT",
                                   "Ｃｏｎｔｅｘｔ - provisioning"])
def test_a_model_context_label_is_rendered_as_product_context(label):
    repo = _reported_hunt({"r.q1": "insufficient_evidence"})
    # Reported findings without a benign verdict (q-1) are strong support, but they never lift model context
    body = _reply([_p([_s([_f(repo, "q-0"), _f(repo, "q-1")], kind="inferred")], label)])
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Context" and paragraph["model_phase"] == label and "tactic" not in paragraph
    assert paragraph["weakly_supported"] and paragraph["support_reason"] == "model_labelled_context"
    assert paragraph["sentences"][0]["kind"] == "inferred" and paragraph["support"] == {"reported": 1, "benign": 1}
    assert counts == {"model_labelled_context": 1}
    # one look for every kind of context: the same label and muted style as a product-weakened paragraph
    shown = narrative_paragraphs(checked["narrative"])[0]
    assert markdown.narrative_label(shown) == "Context (weakly supported)"
    assert markdown.narrative_weak_reason(shown) == (
        f"Weakly supported: labelled context by the model; the model labelled it {label}.")


@pytest.mark.parametrize("cited", ["c-urgent", "q-2"])
def test_a_model_context_paragraph_citing_confirmed_or_attack_triaged_findings_is_never_demoted(cited):
    repo = _reported_hunt({"r.q2": "likely_attack"})
    label = "Context: routine administration"
    body = _reply([_p([_s([_f(repo, cited), _f(repo, "q-0")]),
                       _s(_f(repo, "q-0"), "A routine job ran.", "inferred")], label)])
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    paragraph = checked["narrative"][0]
    # labelled Context as the model asked, but neither weak nor muted, and its sentences as written
    assert paragraph["phase"] == "Context" and paragraph["model_phase"] == label and "tactic" not in paragraph
    assert "weakly_supported" not in paragraph and paragraph["context_reason"] == "model_context_cites_attack"
    assert [s["kind"] for s in paragraph["sentences"]] == ["observed", "inferred"]
    assert paragraph["support"] == ({"confirmed": 1, "benign": 1} if cited == "c-urgent"
                                    else {"attack": 1, "benign": 1})
    assert counts == {"model_context_cites_attack": 1}
    shown = narrative_paragraphs(checked["narrative"])[0]
    assert shown["context_reason"] == "model_context_cites_attack" and shown["model_phase"] == label
    assert markdown.narrative_label(shown) == "Context" and markdown.narrative_weak_reason(shown) == ""
    reason = ("Labelled context by the model, but it cites confirmed or attack-triaged findings; the model labelled "
              f"it {label}.")
    assert markdown.narrative_context_reason(shown) == reason
    # every renderer shows the reason in plain view, unmuted
    manifest = {"ai_assessment": {"source": "agent", "header": "h", "body": {}, "checker": {},
                                  "narrative": [shown]}}
    text = "\n".join(markdown._assessment_section(manifest))
    assert f"\n{reason}\n" in text and f"*{reason}*" not in text


@pytest.mark.parametrize("label", ["Contextual discovery", "Contexts", "In context", "Contextualizing the access"])
def test_only_context_itself_is_a_model_context_label(label):
    repo = _reported_hunt({})
    checked, counts = check_assessment(repo, "h1", _reply([_p([_s(_f(repo, "c-urgent"))], label)]), triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == label and "weakly_supported" not in paragraph and counts == {}


def test_the_support_summary_counts_distinct_cites_and_stays_bounded_at_the_lookup_cap(monkeypatch):
    repo, cid = _repo_with_finding()
    event = AliasBook(repo, "h1").alias_for("E", "ev1")
    finding = _f(repo, cid)
    # the same cites in every sentence count once each
    body = _reply([_p([_s([event, finding], f"Sentence {index} about the read.") for index in range(6)],
                      "Credential Access")])
    checked, _counts = check_assessment(repo, "h1", deepcopy(body), triage=OFF)
    assert checked["narrative"][0]["support"] == {"reported": 2}
    # a record with more findings than the lookup reads is one unknown cite, whatever their number
    monkeypatch.setattr(grounding, "EVENT_FINDINGS", 0)
    checked, _counts = check_assessment(repo, "h1", _reply([_p([_s(event)], "Credential Access")]), triage=OFF)
    assert checked["narrative"][0]["support"] == {"unknown": 1}
    # the manifest keeps known categories with a bounded count, nothing else
    stored = [{"time_span": {}, "phase": "Execution", "support": {"attack": 2, "benign": 10**9, "made-up": 3,
                                                                  "reported": "7", "other": True},
               "sentences": [{"text": "t", "kind": "inferred", "cites": []}]}]
    assert narrative_paragraphs(stored)[0]["support"] == {"attack": 2}


# ------------------------------------------------- a mostly-benign paragraph: context, its attack steps lifted out
def _nine(repo, label="Persistence"):
    """One paragraph citing q-0..q-8 (two sentences), under `label`."""
    return _reply([_p([_s([_f(repo, f"q-{index}") for index in range(5)]),
                       _s([_f(repo, f"q-{index}") for index in range(5, 9)], "The job ran again.", "inferred")],
                      label)])


def _state(repo):
    """Everything about the findings the narrative must never change: lanes, ranks and Reported flags, verdicts."""
    from romulus.hunt.rank import PASS_FINAL
    ids = [row["id"] for row in repo.candidates("h1")]
    groups = []
    after = 0
    while page := repo.triage_groups("h1", after_position=after, limit=500):
        groups += [(group["rule_id"], group["status"], group["assessment"]) for group in page]
        after = page[-1]["position"]
    return ({row["id"]: row["lane"] for row in repo.candidates("h1")}, repo.rank_state("h1"),
            repo.finding_ranks_for("h1", PASS_FINAL, ids), groups)


def test_eight_benign_and_one_attack_triaged_cite_is_context_with_the_attack_step_lifted_everywhere(
        tmp_path, monkeypatch):
    repo = _reported_hunt({"r.q4": "likely_attack"}, count=9)
    before = _state(repo)
    checked, counts = check_assessment(repo, "h1", _nine(repo), triage=USED)
    paragraph = checked["narrative"][0]
    # shown as context, never weakly supported: the sentences keep their kinds, the model's label is kept
    assert paragraph["phase"] == "Context" and paragraph["model_phase"] == "Persistence" and "tactic" not in paragraph
    assert paragraph["context_reason"] == "mostly_benign_support" and "weakly_supported" not in paragraph
    assert [s["kind"] for s in paragraph["sentences"]] == ["observed", "inferred"]
    assert paragraph["support"] == {"attack": 1, "benign": 8}
    assert paragraph["attack_steps"] == [{"finding": "q-4", "rule_id": "r.q4", "lane": "lead",
                                          "triage": "likely_attack", "support": "attack", "title": "r.q4"}]
    assert counts == {"context_mostly_benign_support": 1}
    # presentation only: no lane, rank, Reported flag or verdict changed
    assert _state(repo) == before
    repo.save_agent_assessment({"id": "aa-split", "hunt_id": "h1", "revision": 1, "source": "agent",
                                "model": {"provider": "scripted", "model_requested": "m"}, "body": checked,
                                "checker": counts, "created_at": utcnow()})
    manifest = _manifest(repo)
    shown = manifest["ai_assessment"]["narrative"][0]
    assert shown["context_reason"] == "mostly_benign_support" and shown["attack_steps"] == paragraph["attack_steps"]
    assert "attack_steps_more" not in shown and markdown.narrative_muted(shown)
    reason = ("Shown as context: most of what it cites was triaged as likely benign; each attack-associated step it "
              "cites is listed with it; the model labelled it Persistence.")
    assert markdown.narrative_context_reason(shown) == reason
    # Markdown: the label, the reason and the lifted step, linked to the finding's section
    text = markdown.render(manifest)
    section = text[text.index("## AI assessment"):]
    assert f"**1. Context · {IN_WINDOW}**" in section and f"\n{reason}\n" in section
    step = "- **Attack-associated step cited here:** r.q4 · lane lead · triage: likely attack (finding [q-4](#f-q-4))"
    assert step in section and '<a id="f-q-4"></a>' in text
    # DOCX: the paragraph muted, the step bold and never muted
    path = _docx(tmp_path, monkeypatch, manifest)
    with ZipFile(path) as archive:
        document = ElementTree.fromstring(archive.read("word/document.xml"))
    word = executive._WORD
    paragraphs = [("".join(t.text or "" for t in p.iter(f"{{{word}}}t")),
                   [node.tag.rsplit("}", 1)[-1] for node in p.iter()]) for p in document.iter(f"{{{word}}}p")]
    heading = next(tags for text, tags in paragraphs if text.startswith("1. Context · "))
    assert "i" in heading and "color" in heading
    lifted = next(tags for text, tags in paragraphs if text == ("Attack-associated step cited here: r.q4 · lane lead · "
                                                               "triage: likely attack (finding q-4)"))
    assert "b" in lifted and "i" not in lifted and "color" not in lifted
    sentence = next(tags for text, tags in paragraphs if text.startswith("inferred: The job ran again."))
    assert "color" in sentence


@pytest.mark.parametrize("cited", ["c-urgent", "q-4"])
def test_confirmed_support_is_never_split_and_model_context_keeps_its_own_rule(cited):
    repo = _reported_hunt({"r.q4": "likely_attack"}, count=9)
    # a confirmed cite (triaged likely benign, but confirmed outweighs any verdict) among eight benign keeps the label
    body = _reply([_p([_s([_f(repo, "c-urgent"), *[_f(repo, f"q-{index}") for index in range(9) if index != 4]])],
                      "Impact")])
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["phase"] == "Impact" and counts == {} and paragraph["support"] == {"confirmed": 1, "benign": 8}
    assert "context_reason" not in paragraph and "attack_steps" not in paragraph
    # a model Context label citing confirmed or attack-triaged findings: unmuted model context, never split
    body = _reply([_p([_s([_f(repo, cited), *[_f(repo, f"q-{index}") for index in range(9) if index != 4]])],
                      "Context: build-day provisioning")])
    checked, counts = check_assessment(repo, "h1", body, triage=USED)
    paragraph = checked["narrative"][0]
    assert paragraph["context_reason"] == "model_context_cites_attack" and "attack_steps" not in paragraph
    assert "weakly_supported" not in paragraph and counts == {"model_context_cites_attack": 1}
    assert not markdown.narrative_muted(narrative_paragraphs([paragraph])[0])


def _cite(category, *, complete=True, finding_id="f"):
    """A cite resting on one finding of `category` (or on none, for raw or other)."""
    if category == "raw":
        return grounding.CiteStrength(raw=True)
    if category == "other":
        return grounding.CiteStrength(complete=complete)
    found = grounding.FindingStrength(
        lane="urgent" if category == "confirmed" else "lead", deterministic=True, reported=True,
        confirmed=category == "confirmed", triage={"attack": "likely_attack", "benign": "likely_benign",
                                                    "confirmed": "likely_benign"}.get(category, "not_triaged"),
        finding_id=finding_id, rule_id="r." + finding_id)
    return grounding.CiteStrength((found,), complete)


@pytest.mark.parametrize("mix,split", [
    ({"attack": 1, "benign": 2}, False),                  # under the benign floor: one verdict must not flip it
    ({"attack": 1, "benign": 3}, True),
    ({"reported": 1, "benign": 3}, True),
    ({"attack": 1, "benign": 1}, False),                  # balanced
    ({"attack": 2, "benign": 4}, True),                   # exactly two-thirds
    ({"attack": 2, "benign": 3}, False),                  # under two-thirds
    ({"attack": 3, "benign": 9}, False),                  # more than two strong cites: several steps, kept
    ({"attack": 1, "benign": 3, "other": 2}, False),      # unreported cites count toward the whole
    ({"attack": 1, "benign": 3, "raw": 2}, False),
    ({"confirmed": 1, "benign": 8}, False),               # confirmed activity is never split
    ({"attack": 1, "benign": 0}, False),
])
def test_the_split_rule_at_its_boundaries(mix, split):
    from collections import Counter

    from romulus.agent.assessment import _mostly_benign
    cites = [_cite(category, finding_id=f"{category}{index}") for category, count in mix.items()
             for index in range(count)]
    assert _mostly_benign(cites, Counter(item.category for item in cites)) is split


def test_an_incomplete_lookup_never_splits_and_lifted_steps_are_bounded_and_counted(monkeypatch):
    from collections import Counter

    from romulus.agent import assessment
    cites = [_cite("attack", finding_id="a"), *[_cite("benign", finding_id=f"b{index}") for index in range(4)]]
    assert assessment._mostly_benign(cites, Counter(item.category for item in cites))
    # a capped evidence lookup may hide a confirmed finding past what it read
    capped = [*cites[:-1], _cite("benign", complete=False, finding_id="b9")]
    assert not assessment._mostly_benign(capped, Counter(item.category for item in capped))
    # one evidence record standing for many strong findings: each is lifted once, attack-triaged before Reported,
    # at most ATTACK_STEPS kept and the rest counted
    many = tuple(_cite("reported" if index % 2 else "attack", finding_id=f"s{index:02}").findings[0]
                 for index in range(14))
    record = grounding.CiteStrength(many)
    steps = assessment._attack_steps([record, record, _cite("benign", finding_id="b")])
    assert len(steps) == 14 and [step["support"] for step in steps] == ["attack"] * 7 + ["reported"] * 7
    paragraph = {"time_span": {"start": IN_WINDOW, "end": IN_WINDOW}, "phase": "Discovery",
                 "sentences": [{"text": "t", "kind": "observed", assessment.REFS: [("E", "ev")]}]}
    strengths = {("E", "ev"): record}
    monkeypatch.setattr(assessment, "_mostly_benign", lambda *_args: True)
    counts = Counter()
    out = assessment._ground_paragraph(paragraph, strengths, counts)
    assert len(out["attack_steps"]) == 10 and out["attack_steps_more"] == 4
    shown = narrative_paragraphs([{**out, "sentences": [{"text": "t", "kind": "observed", "cites": []}]}])[0]
    assert len(shown["attack_steps"]) == 10 and shown["attack_steps_more"] == 4
    assert markdown.narrative_steps_more(shown) == (
        "4 more attack-associated finding(s) cited here; its citations and support line count them.")


def test_the_manifest_whitelists_the_split_reason_and_bounds_its_steps():
    step = {"finding": "F1", "rule_id": "r.a", "title": "<b>T</b>", "lane": "lead", "triage": "likely_attack",
            "support": "attack", "extra": "x"}
    base = {"time_span": {}, "phase": "Context", "sentences": [{"text": "t", "kind": "inferred", "cites": []}]}
    shown = narrative_paragraphs([{**base, "context_reason": "mostly_benign_support", "model_phase": "Persistence",
                                   "attack_steps": [step, {"finding": "", "support": "attack"},
                                                    {"finding": "F2", "support": "benign"}, "junk",
                                                    *[{**step, "finding": f"G{index}"} for index in range(12)]],
                                   "attack_steps_more": 3}])[0]
    assert shown["context_reason"] == "mostly_benign_support" and shown["model_phase"] == "Persistence"
    assert shown["attack_steps"][0] == {key: value for key, value in step.items() if key != "extra"}
    # ten kept; the stored count plus every entry not kept (malformed or past the bound) is counted
    assert len(shown["attack_steps"]) == 10 and shown["attack_steps_more"] == 3 + 16 - 10
    # steps ride only on a mostly-benign context paragraph; an unknown reason is dropped with them
    for extra in ({"context_reason": "model_context_cites_attack"}, {"context_reason": "made-up"},
                  {"context_reason": "mostly_benign_support", "weakly_supported": True}, {}):
        other = narrative_paragraphs([{**base, **extra, "attack_steps": [step]}])[0]
        assert "attack_steps" not in other and "attack_steps_more" not in other
    assert "context_reason" not in narrative_paragraphs([{**base, "context_reason": "made-up"}])[0]


def test_a_narrative_without_a_mostly_benign_paragraph_renders_as_before(tmp_path):
    repo = _hunt()
    _weak_assessment(repo, tmp_path)
    manifest = _manifest(repo)
    for paragraph in manifest["ai_assessment"]["narrative"]:
        assert not {"attack_steps", "attack_steps_more"} & set(paragraph)
        assert paragraph.get("context_reason") != "mostly_benign_support"
    assert "context_mostly_benign_support" not in manifest["ai_assessment"]["checker"]
    assert "Attack-associated step cited here" not in markdown.render(manifest)


def test_the_web_lifts_the_attack_step_out_of_a_muted_context_paragraph(web_setup):
    client, repo, cid, *_ = web_setup
    test_web_agent_a6.run_row(repo)
    paragraph = {"time_span": {"start": IN_WINDOW, "end": IN_WINDOW}, "phase": "Context",
                 "context_reason": "mostly_benign_support", "model_phase": HOSTILE_PHASE,
                 "attack_steps": [{"finding": cid, "rule_id": "r.x", "title": "<i>Tool</i>", "lane": "high",
                                   "triage": "possible_attack", "support": "attack"}],
                 "support": {"attack": 1, "benign": 8},
                 "sentences": [{"text": "Provisioning ran.", "kind": "observed", "cites": [cid]}]}
    supported = {"time_span": {"start": IN_WINDOW, "end": IN_WINDOW}, "phase": "Objective",
                 "sentences": [{"text": "The read was done.", "kind": "inferred", "cites": [cid]}]}
    repo.save_agent_assessment({"id": "aa-split", "hunt_id": "h1", "revision": 1, "source": "agent",
                                "model": {"provider": "scripted", "model_requested": "m"},
                                "body": {**_reply([paragraph, supported])},
                                "checker": {"context_mostly_benign_support": 1}, "created_at": utcnow()})
    for path in ("/hunts/h1", "/hunts/h1/assessment"):
        page = client.get(path).text
        narrative = page[page.index('<ol class="narrative">'):]
        narrative = narrative[:narrative.index("</ol>")]
        assert narrative.count('<li class="context-split">') == 1 and narrative.count("<li>") == 1
        assert ('<p class="small context-reason">Shown as context: most of what it cites was triaged as likely '
                "benign; each attack-associated step it cites is listed with it; the model labelled it "
                "&lt;Persistence&gt;.</p>") in narrative
        assert ('<p class="attack-step"><b>Attack-associated step cited here:</b> &lt;i&gt;Tool&lt;/i&gt; · lane high'
                f' · triage: possible attack (finding <a href="/findings/{cid}">{cid}</a>)</p>') in narrative
        assert "<i>Tool</i>" not in page and "<Persistence>" not in page


def test_a_cited_verdict_that_makes_a_paragraph_mostly_benign_is_counted_when_grounded_again():
    from romulus.agent.assessment import cited_triage_groups, reground_narrative
    repo = _reported_rows(count=6)
    run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                        provider=ta.FakeTriage(by_rules(IN_PHASE, default=None)))
    context = triage_context(latest_summary(repo, "h1"))
    body = _reply([_p([_s([_f(repo, f"q-{index}") for index in range(6)])], "Persistence")])
    ungrounded: list = []
    checked, counts = check_assessment(repo, "h1", body, triage=context, ungrounded=ungrounded)
    # q-1..q-5 Reported without a verdict hold the paragraph
    assert checked["narrative"][0]["phase"] == "Persistence" and checked["narrative"][0]["support"] == {
        "reported": 5, "benign": 1}
    groups, _skipped = cited_triage_groups(repo, "h1", ungrounded, context, 10)
    summary = run_cited_triage_in_phase(ta.settings(), repo, "h1", groups, owner_token=None,
                                        heartbeat=lambda: None,
                                        provider=ta.FakeTriage(by_rules({"r.q5": "likely_attack"})))
    assert summary["status"] == "complete", summary
    before = _state(repo)
    narrative, checker, changed = reground_narrative(repo, "h1", ungrounded, checked["narrative"], counts,
                                                     triage_context(latest_summary(repo, "h1")))
    paragraph = narrative[0]
    assert changed == 1 and checker == {"context_mostly_benign_support": 1}
    assert paragraph["context_reason"] == "mostly_benign_support" and paragraph["support"] == {"attack": 1,
                                                                                             "benign": 5}
    assert [step["finding"] for step in paragraph["attack_steps"]] == ["q-5"]
    assert _state(repo) == before


# ---------------------------------------------------------------- targeted triage of the narrative's cited groups
# the in-phase pass answers only the confirmed group and r.q0 (benign): r.q1-r.q3 are Reported and left untriaged
IN_PHASE = {"r.confirmed": "likely_benign", "r.q0": "likely_benign"}


def _cited_phase(tmp_path, cited_policy, *, name="cited", settings=None, cited_provider=None):
    """The agent phase end to end on `_reported_rows`: orient, investigate, the in-phase pass (IN_PHASE), an
    assessment whose one Persistence paragraph cites q-0..q-2, then the extension to the cited groups."""
    engine = make_engine(tmp_path / f"{name}.sqlite")
    migrate(engine)
    repo = _reported_rows(Repo(engine))
    settings = settings or _phase_settings()
    seen: dict = {"calls": []}
    finish = [ToolCall("f", "finish_session", {"summary": "The evidence review is complete."}, "{}")]
    body = _reply([_p([_s([_f(repo, "q-0"), _f(repo, "q-1"), _f(repo, "q-2")], "The tool ran at start-up.")],
                      "Persistence")])
    provider = ScriptedProvider([response(tool_calls=finish), response(tool_calls=finish), response(parsed=body)])
    extension = cited_provider or ta.FakeTriage(cited_policy)

    def triage(heartbeat, cited=None):
        groups = cited
        if groups is None:
            return run_triage_in_phase(settings, repo, "h1", owner_token=None, heartbeat=heartbeat,
                                       provider=ta.FakeTriage(by_rules(IN_PHASE, default=None)))
        seen["calls"].append(list(groups))
        seen["before"] = deepcopy(repo.agent_assessments("h1")[-1])
        return run_cited_triage_in_phase(settings, repo, "h1", groups, owner_token=None, heartbeat=heartbeat,
                                         provider=extension)
    lanes = {row["id"]: row["lane"] for row in repo.candidates("h1")}
    rank_state = repo.rank_state("h1")
    result = run_agent_phase(settings, repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0, triage=triage)
    assert result.state == "completed"
    # promote-only: no lane, rank or Reported flag changed
    assert {row["id"]: row["lane"] for row in repo.candidates("h1")} == lanes and repo.rank_state("h1") == rank_state
    return repo, result, seen


def test_cited_untriaged_reported_groups_triaged_benign_make_the_paragraph_weak(tmp_path):
    repo, result, seen = _cited_phase(tmp_path, by_rules({}))
    assert [key[2] for key in seen["calls"][0]] == ["r.q1", "r.q2"]
    # at assess time the untriaged Reported cites held the paragraph
    before = seen["before"]["body"]["narrative"][0]
    assert before["phase"] == "Persistence" and before["support"] == {"reported": 2, "benign": 1}
    # once the extension calls them likely benign, it is grounded again: the model's text unchanged
    revisions = repo.agent_assessments("h1")
    stored = revisions[-1]
    assert len(revisions) == 2 and stored["revision"] == seen["before"]["revision"] + 1
    paragraph = stored["body"]["narrative"][0]
    assert paragraph["phase"] == "Context" and paragraph["support_reason"] == "triaged_likely_benign"
    assert paragraph["support"] == {"benign": 3} and paragraph["model_phase"] == "Persistence"
    assert paragraph["sentences"][0]["text"] == before["sentences"][0]["text"]
    assert stored["checker"] == {"weakly_supported_benign_triage": 1, "labelled_uncertain_benign_triage": 1,
                                 "regrounded_after_cited_triage": 1, "paragraphs_strength_changed": 1}
    cited = result.as_dict()["ai_triage"]["cited"]
    assert cited["status"] == "complete" and cited["triaged"] == 2 and cited["paragraphs_strength_changed"] == 1
    # the pass was extended, not replaced: its number, digest and placement kept, and its view still current
    from romulus.report.triage import triage_view
    summary = latest_summary(repo, "h1")
    assert summary["pass"] == 1 and summary["status"] == "partial" and summary["cited"]["triaged"] == 2
    assert summary["groups"]["triaged"] == 4 and summary["groups"]["not_triaged"] == 1        # r.q3 still untriaged
    assert build_manifest(repo, "h1", "test")["ai_triage"]["stale"] is False
    assert triage_view(repo, "h1")["stale"] is False


@pytest.mark.parametrize("verdict", ["possible_attack", "likely_attack"])
def test_one_attack_verdict_from_the_extension_keeps_the_paragraph_strong(tmp_path, verdict):
    repo, _result, _seen = _cited_phase(tmp_path, by_rules({"r.q2": verdict}))
    paragraph = repo.agent_assessments("h1")[-1]["body"]["narrative"][0]
    assert paragraph["phase"] == "Persistence" and "weakly_supported" not in paragraph
    assert paragraph["support"] == {"attack": 1, "benign": 2}
    assert repo.agent_assessments("h1")[-1]["checker"] == {"regrounded_after_cited_triage": 1,
                                                          "paragraphs_strength_changed": 0}


def test_cited_groups_are_capped_by_the_most_cited_first_and_the_rest_counted(tmp_path):
    from romulus.agent.assessment import cited_triage_groups
    repo = _reported_rows()
    run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                        provider=ta.FakeTriage(by_rules(IN_PHASE, default=None)))
    context = triage_context(latest_summary(repo, "h1"))
    body = _reply([_p([_s([_f(repo, "q-1"), _f(repo, "q-3")])], "Execution"),
                   _p([_s([_f(repo, "q-3"), _f(repo, "q-0")])], "Persistence"),
                   _p([_s([_f(repo, "q-2"), _f(repo, "q-3")])], "Discovery")])
    ungrounded: list = []
    check_assessment(repo, "h1", body, triage=context, ungrounded=ungrounded)
    groups, skipped = cited_triage_groups(repo, "h1", ungrounded, context, 2)
    # r.q3 is cited by three paragraphs; r.q1 and r.q2 by one each (ties by section, rule and target)
    assert [key[2] for key in groups] == ["r.q3", "r.q1"] and skipped == 1
    assert cited_triage_groups(repo, "h1", ungrounded, context, 0) == ([], 3)
    # nothing to extend without a usable pass
    assert cited_triage_groups(repo, "h1", ungrounded, OFF, 5) == ([], 0)
    # through the phase: over the cap, the rest are counted on the regrounded revision and the phase's record
    repo, result, seen = _cited_phase(tmp_path, by_rules({}), settings=_phase_settings(
        agent_triage_cited_max_groups=1))
    assert [key[2] for key in seen["calls"][0]] == ["r.q1"]
    assert result.as_dict()["ai_triage"]["cited"]["untriaged_cited_skipped"] == 1
    assert repo.agent_assessments("h1")[-1]["checker"]["untriaged_cited_skipped"] == 1
    # r.q2 is still untriaged and Reported: the paragraph stays strong
    assert repo.agent_assessments("h1")[-1]["body"]["narrative"][0]["phase"] == "Persistence"


def test_a_failed_or_spent_extension_leaves_the_grounding_unchanged(tmp_path):
    failing = ta.FakeTriage(lambda _cards: ProviderUnavailable("down"))
    # the in-phase pass made one call: with two allowed, the extension has one left; with one, none
    for name, settings, provider, reason in (
            ("down", _phase_settings(), failing, "provider_unavailable"),
            ("spent", _phase_settings(agent_triage_max_calls=1), ta.FakeTriage(by_rules({})), "budget:calls")):
        repo, result, seen = _cited_phase(tmp_path, None, name=name, settings=settings, cited_provider=provider)
        cited = result.as_dict()["ai_triage"]["cited"]
        assert cited["status"] == "failed" and cited["reason"] == reason and cited["triaged"] == 0
        # no new revision, no new verdict: the paragraph keeps its assess-time grounding, never read as benign
        assert repo.agent_assessments("h1") == [seen["before"]]
        assert seen["before"]["body"]["narrative"][0]["phase"] == "Persistence"
        assert latest_summary(repo, "h1")["groups"]["not_triaged"] == 3 and "cited" not in latest_summary(repo, "h1")


def test_the_extension_spends_from_the_pass_budget_and_stops_on_its_wall_clock():
    from romulus.agent.triage import run_cited_triage
    repo = _reported_rows()
    run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                        provider=ta.FakeTriage(by_rules(IN_PHASE, default=None)))
    first = latest_summary(repo, "h1")
    evidence = grounding.EvidenceStrength(repo, "h1", triage_context(first))
    keys = [found.group for found in evidence.findings(["q-1", "q-2"]).values()]
    # past its wall budget: no call, nothing published
    late = run_cited_triage(ta.settings(), repo, "h1", ta.FakeTriage(by_rules({})), keys, clock=iter(
        [0.0, *[10.0**6] * 50]).__next__)
    assert late["status"] == "failed" and late["reason"] == "budget:wall-clock"
    assert latest_summary(repo, "h1") == first
    # within it: the pass's usage continues from where the pass left it
    done = run_cited_triage(ta.settings(), repo, "h1", ta.FakeTriage(by_rules({})), keys)
    assert done["status"] == "complete" and done["triaged"] == 2
    usage = latest_summary(repo, "h1")["usage"]
    assert usage["calls"] == first["usage"]["calls"] + 1 and usage["input_tokens"] > first["usage"]["input_tokens"]
    assert latest_summary(repo, "h1")["calls"]["sent"] == first["calls"]["sent"] + 1
    # an extension never runs on another model, settings or cards: the pass's digest must hold
    other = ta.FakeTriage(by_rules({}))
    other.model = "another-model"
    assert run_cited_triage(ta.settings(), repo, "h1", other, keys)["status"] == "skipped"


def _untriaged(repo=None):
    """`_reported_rows` after an in-phase pass that answered only IN_PHASE: r.q1-r.q3 have no verdict."""
    repo = _reported_rows(repo)
    run_triage_in_phase(ta.settings(), repo, "h1", owner_token=None, heartbeat=lambda: None,
                        provider=ta.FakeTriage(by_rules(IN_PHASE, default=None)))
    found = grounding.EvidenceStrength(repo, "h1", triage_context(latest_summary(repo, "h1"))).findings(
        ["q-1", "q-2", "q-3"])
    return repo, [found[item].group for item in ("q-1", "q-2", "q-3")]


def test_a_partial_extension_says_so_and_counts_why():
    from romulus.agent.triage import run_cited_triage
    repo, keys = _untriaged()
    # the model answers r.q1 only: r.q2 and r.q3 get no valid answer
    done = run_cited_triage(ta.settings(), repo, "h1", ta.FakeTriage(by_rules({"r.q1": "likely_benign"},
                                                                              default=None)), keys)
    assert done["status"] == "partial" and done["triaged"] == 1 and done["targets"] == 3
    assert done["reason"] == "no valid verdict for some cited groups"
    summary = latest_summary(repo, "h1")
    assert summary["status"] == "partial" and summary["groups"]["not_triaged_by_reason"] == {"no valid answer": 2}
    assert summary["reason"] == "no valid answer" and summary["cited"]["triaged"] == 1


def test_an_extension_is_skipped_when_the_pass_digest_or_order_changed():
    from romulus.agent.triage import run_cited_triage
    repo, keys = _untriaged()
    first = latest_summary(repo, "h1")
    # other settings than the pass ran with: another digest
    changed = run_cited_triage(ta.settings(agent_triage_call_input_tokens=5000), repo, "h1",
                               ta.FakeTriage(by_rules({})), keys)
    assert changed["status"] == "skipped" and "cannot be extended" in changed["reason"]
    # a finding stored after the pass: another order
    ta._insert(repo, [ta._row("late-1", "r.late", lane="high", host="elsewhere")])
    moved = run_cited_triage(ta.settings(), repo, "h1", ta.FakeTriage(by_rules({})), keys)
    assert moved["status"] == "skipped" and "cannot be extended" in moved["reason"]
    assert latest_summary(repo, "h1") == first


def test_a_reground_failure_after_publishing_is_recorded_as_such(tmp_path, monkeypatch):
    from romulus.agent import assessment

    def broken(*_a, **_kw):
        raise RuntimeError("store unavailable")
    monkeypatch.setattr(assessment, "reground_narrative", broken)
    repo, result, seen = _cited_phase(tmp_path, by_rules({}))
    cited = result.as_dict()["ai_triage"]["cited"]
    assert cited["status"] == "failed" and cited["reason"].startswith("reground_error: RuntimeError")
    assert cited["triaged"] == 2 and cited["groups"] == 2
    # the verdicts are published; the stored grounding is the assess-time one, and the mismatch is visible
    assert latest_summary(repo, "h1")["cited"]["triaged"] == 2
    assert repo.agent_assessments("h1") == [seen["before"]]


def test_an_extension_resumes_from_every_billed_triage_call_of_the_pass(monkeypatch):
    from romulus.agent.triage import TriageBudget, pass_billed, run_cited_triage
    repo, keys = _untriaged()
    first = latest_summary(repo, "h1")
    assert first["usage_base"]["calls"] == 0 and first["usage"]["calls"] == 1

    # an extension bills its call, then ends before publishing (a crash)
    def crash(*_a, **_kw):
        raise RuntimeError("crashed before publishing")
    monkeypatch.setattr(repo, "publish_triage", crash)
    with pytest.raises(RuntimeError):
        run_cited_triage(ta.settings(), repo, "h1", ta.FakeTriage(by_rules({})), keys)
    monkeypatch.undo()
    assert latest_summary(repo, "h1") == first                     # nothing published: the snapshot says 1 call
    billed = pass_billed(repo, "h1", first)
    assert billed["calls"] == 2 and billed["prompt_tokens"] == 200 and billed["completion_tokens"] == 80
    resumed = TriageBudget.resume(ta.settings(), first["usage"], billed=billed)
    assert resumed.calls == 2 and resumed.input_tokens == 200 and resumed.output_tokens == 80
    # so a pass allowed two calls has none left for another extension
    from romulus.agent.provider import BudgetExhausted
    with pytest.raises(BudgetExhausted) as stopped:
        TriageBudget.resume(ta.settings(agent_triage_max_calls=2), first["usage"], billed=billed).check(100, 100)
    assert stopped.value.budget == "calls"
    # with room left, the next extension spends on top of every billed call
    done = run_cited_triage(ta.settings(), repo, "h1", ta.FakeTriage(by_rules({})), keys)
    assert done["status"] == "complete" and latest_summary(repo, "h1")["usage"]["calls"] == 3
    # the pass's base stays the hunt's calls before it: the extension's calls are the pass's
    assert latest_summary(repo, "h1")["usage_base"] == first["usage_base"]
    assert latest_summary(repo, "h1")["rank_state"] == repo.rank_state("h1")
