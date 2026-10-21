"""Context-only playbooks: anchor-gated behavior, lane caps, citations and coverage."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.decide.policy import decide
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.context import EntryPointPromotion, PostAccessDiscovery
from romulus.detect.registry import anchor_class_for_rule, fresh_context_pack, fresh_pack, pack_manifest
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.context import evaluate_context, finalize_context
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def _seed_anchor(repo, hunt_id, anchor_id, rule_id, events):
    repo.save_evidence(hunt_id, events, {}, None)
    repo.save_candidate({
        "id": anchor_id, "hunt_id": hunt_id, "rule_id": rule_id, "rule_version": "1", "claim": "a foothold",
        "claim_type": "observed_action", "event_ids": [e.id for e in events], "predicate_fields": [],
        "entities": [["host", "web1", "host"]], "ts": T0, "severity": "critical", "confidence": "high",
        "lane": "urgent", "priority": 100.0, "priority_reasons": [], "gate_results": {},
        "benign_alternatives": [], "next_checks": [], "group_key": anchor_id, "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None})
    repo.save_expansion_anchor({
        "id": anchor_id, "hunt_id": hunt_id, "candidate_id": anchor_id, "depth": 0, "parent_anchor_id": None,
        "host": "web1", "lane": "urgent", "severity": "critical", "ts": T0, "status": "pending", "reasons": []})


def _seed_link(repo, hunt_id, link_id, anchor_id, link_events, *, link_type="process_lineage",
               strength="observed", status="complete"):
    repo.save_evidence(hunt_id, link_events, {}, None)
    repo.save_expansion_link({
        "id": link_id, "hunt_id": hunt_id, "anchor_id": anchor_id, "link_type": link_type,
        "window_label": "anchor ±5 min", "window_start": T0 - timedelta(minutes=5),
        "window_end": T0 + timedelta(minutes=5), "strength": strength, "key": {}, "status": status,
        "event_ids": [e.id for e in link_events], "evidence_ids": [], "task_ids": [], "coverage": [],
        "reasons": [], "duration_ms": 0, "query_spend": 0, "evaluated": 1})


def event(event_id, family="process_exec", *, outcome=Outcome.success, **fields):
    return TypedEvent(
        id=event_id, family=family, ts=T0, host="web1", outcome=outcome,
        fields={name.replace("__", "."): fv(value, f"{event_id}:{name}")
                for name, value in fields.items()},
        raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1",
    )


def anchor(anchor_class="web_shell"):
    evidence = event("anchor-event", process__argv=["/bin/sh"], process__session_id=42)
    return ContextAnchor(
        id="F-anchor", anchor_class=anchor_class, lane="urgent",
        claim="a web-service shell was recorded", events=[evidence],
    )


def link(strength="observed", link_type="login_session", status="complete"):
    evidence = event("link-event", process__argv=["/usr/bin/sshd"], process__session_id=42)
    return ContextLink(
        id="L-session", link_type=link_type, strength=strength,
        key={"host": "web1", "process.session_id": 42}, evidence_events=[evidence], status=status,
    )


@pytest.mark.parametrize("argv,technique", [
    (["id"], "T1033"),
    (["hostname"], "T1082"),
    (["ip", "addr"], "T1016"),
    (["getent", "passwd"], "T1087"),
    (["groups"], "T1069"),
])
def test_post_access_discovery_matches_attack_behavior_classes(argv, technique):
    observed = event(
        "discovery", process__executable=f"/usr/bin/{argv[0]}",
        process__argv=argv, process__session_id=42,
    )

    matches = PostAccessDiscovery().consume_linked(anchor(), link(), [observed])

    assert len(matches) == 1
    match = matches[0]
    assert technique in match.notes
    assert "F-anchor" in match.claim and "L-session" in match.claim
    assert {item.id for item in match.events} == {"discovery", "anchor-event", "link-event"}
    decision = decide(match, "hunt-1")
    # one discovery class in the session is a lead; a burst of three or more is a high (see test_context_catalog)
    assert decision.admitted and decision.lane == "lead"


@pytest.mark.parametrize("argv", [
    ["echo", "whoami"], ["whoami-helper"], ["getent", "hosts", "example.test"], ["ipcalc", "10.0.0.1"],
])
def test_post_access_discovery_rejects_mentions_and_near_names(argv):
    observed = event(
        "benign", process__executable=f"/usr/bin/{argv[0]}",
        process__argv=argv, process__session_id=42,
    )

    assert PostAccessDiscovery().consume_linked(anchor(), link(), [observed]) == []


def test_context_rules_reject_real_events_reached_by_disallowed_gates():
    discovery = event(
        "discovery", process__executable="/usr/bin/whoami",
        process__argv=["whoami"], process__session_id=42,
    )
    login = event(
        "login", family="auth", auth__service="sshd", source__ip="203.0.113.8",
        user__name="root", outcome=Outcome.success,
    )

    assert PostAccessDiscovery().consume_linked(anchor("network_observation"), link(), [discovery]) == []
    assert EntryPointPromotion().consume_linked(
        anchor("credential_access"), link(link_type="process_lineage"), [login],
    ) == []


def test_inferred_link_caps_context_finding_at_lead_and_labels_hypothesis():
    observed = event(
        "discovery", process__executable="/usr/bin/uname",
        process__argv=["uname", "-a"], process__session_id=42,
    )

    match = PostAccessDiscovery().consume_linked(
        anchor(), link(strength="inferred", link_type="process_lineage"), [observed],
    )[0]

    assert match.proposed_lane == "lead"
    assert "hypothesis" in match.claim.lower()


def test_host_after_link_does_not_turn_routine_discovery_into_context_findings():
    routine = [
        event("id", process__executable="/usr/bin/id", process__argv=["id"]),
        event("uname", process__executable="/usr/bin/uname", process__argv=["uname", "-a"]),
        event("ip", process__executable="/usr/sbin/ip", process__argv=["ip", "addr"]),
    ]

    assert PostAccessDiscovery().consume_linked(
        anchor(), link(strength="inferred", link_type="host_after_anchor"), routine,
    ) == []


def test_finalize_aggregates_every_reach_into_one_candidate():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    # a discovery burst (three distinct classes) in one session, reached three ways: high through the observed
    # links, capped to lead would apply only if every reach were inferred. The representative is the observed
    # link with the lowest id.
    burst = [
        event("whoami", process__executable="/usr/bin/whoami", process__argv=["whoami"], process__session_id=42),
        event("uname", process__executable="/usr/bin/uname", process__argv=["uname", "-a"],
              process__session_id=42),
        event("ss", process__executable="/usr/bin/ss", process__argv=["ss", "-tunap"], process__session_id=42),
    ]
    _seed_anchor(repo, "h1", "F-anchor", "host.web_shell",
                 [event("anchor-event", process__executable="/bin/sh", process__argv=["/bin/sh"],
                        process__session_id=42)])
    _seed_link(repo, "h1", "L-inferred", "F-anchor", burst, link_type="process_lineage", strength="inferred")
    _seed_link(repo, "h1", "L-observed", "F-anchor", burst, link_type="login_session", strength="observed")
    _seed_link(repo, "h1", "L-third", "F-anchor", burst, link_type="process_lineage", strength="observed")

    finalize_context(repo, "h1")

    candidates = [c for c in repo.candidates("h1") if c["rule_id"] == "context.post_access_discovery"]
    assert len(candidates) == 1
    assert candidates[0]["lane"] == "high"
    assert candidates[0]["source_link_id"] == "L-observed"
    assert candidates[0]["gate_results"]["_context_reaches"] == [
        {"anchor_id": "F-anchor", "link_id": "L-inferred",
         "link_type": "process_lineage", "strength": "inferred"},
        {"anchor_id": "F-anchor", "link_id": "L-observed",
         "link_type": "login_session", "strength": "observed"},
        {"anchor_id": "F-anchor", "link_id": "L-third",
         "link_type": "process_lineage", "strength": "observed"},
    ]


def test_entry_point_promotion_requires_successful_external_ssh_login_in_observed_session():
    login = event(
        "login", family="auth", auth__service="sshd", source__ip="203.0.113.8",
        user__name="root", outcome=Outcome.success,
    )

    match = EntryPointPromotion().consume_linked(anchor("credential_access"), link(), [login])[0]

    assert match.proposed_lane == "high"
    assert "session that later performed F-anchor" in match.claim
    assert decide(match, "hunt-1").admitted


@pytest.mark.parametrize("source,outcome,service", [
    ("10.0.0.8", Outcome.success, "sshd"),
    ("203.0.113.8", Outcome.failure, "sshd"),
    ("203.0.113.8", Outcome.success, "sudo"),
])
def test_entry_point_promotion_adversarial_negatives(source, outcome, service):
    login = event(
        "login", family="auth", auth__service=service, source__ip=source,
        user__name="root", outcome=outcome,
    )

    assert EntryPointPromotion().consume_linked(anchor("credential_access"), link(), [login]) == []


def test_context_pack_is_excluded_from_sweep_pack():
    assert fresh_context_pack()
    assert all(playbook.kind == "context" for playbook in fresh_context_pack())
    assert all(playbook.kind != "context" for playbook in fresh_pack())


def test_anchor_classes_are_declared_and_resolved_by_exact_rule_id():
    assert all(row["anchor_class"] for row in pack_manifest())
    assert anchor_class_for_rule("host.ssh_login_external_source") == "remote_login"
    assert anchor_class_for_rule("host.web_service_spawns_interpreter") == "web_shell"
    assert anchor_class_for_rule("custom.ssh_web_credential") == "execution"


def test_post_access_discovery_uses_kernel_executable_not_spoofable_argv_zero():
    spoofed = event(
        "spoofed", process__executable="/usr/bin/echo",
        process__argv=["whoami"], process__session_id=42,
    )
    renamed = event(
        "renamed", process__executable="/usr/bin/whoami",
        process__argv=["totally-benign-name"], process__session_id=42,
    )

    assert PostAccessDiscovery().consume_linked(anchor(), link(), [spoofed]) == []
    assert len(PostAccessDiscovery().consume_linked(anchor(), link(), [renamed])) == 1


def test_context_coverage_cell_is_scoped_to_anchor_and_link():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    observed = event(
        "discovery", process__executable="/usr/bin/whoami",
        process__argv=["whoami"], process__session_id=42,
    )

    evaluated = evaluate_context(repo, "h1", anchor(), link(), [observed])

    assert len(evaluated) == 1
    cells = repo.rule_cells("h1")
    row = next(cell for cell in cells if cell["rule_id"] == "context.post_access_discovery")
    assert row["target"] == "link:login_session"
    assert row["partition"] == "anchor:F-anchor|link:L-session"
    assert row["state"] == "matched"
    assert row["detail"]["strength"] == "observed"


def test_context_coverage_write_is_lease_fenced():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    owner = repo.claim_hunt("h1", 60)["lease_owner"]
    observed = event(
        "discovery", process__executable="/usr/bin/whoami",
        process__argv=["whoami"], process__session_id=42,
    )

    with pytest.raises(RuntimeError, match="lease ownership lost"):
        evaluate_context(repo, "h1", anchor(), link(), [observed], owner_token="stale")

    assert evaluate_context(repo, "h1", anchor(), link(), [observed], owner_token=owner)


def test_incompatible_context_family_never_writes_complete_negative():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    process = event("process-only", process__argv=["/bin/true"], process__session_id=42)

    evaluate_context(repo, "h1", anchor(), link(), [process])

    row = next(
        cell for cell in repo.rule_cells("h1")
        if cell["rule_id"] == "context.entry_point_promotion"
    )
    assert row["evaluated"] == 0
    assert row["state"] in {"not_applicable_no_events", "evaluated_partial"}
    assert row["state"] != "no_match_complete"


def test_entry_point_promotion_fires_once_per_login_not_for_the_session_opening():
    login = event("login", family="auth", auth__service="sshd", auth__phase="login", source__ip="203.0.113.8",
                  user__name="root", outcome=Outcome.success)
    session_open = event("open", family="auth", auth__service="sshd", auth__phase="session_open",
                         source__ip="203.0.113.8", user__name="root", outcome=Outcome.success)
    matches = EntryPointPromotion().consume_linked(anchor("credential_access"), link(), [login, session_open])
    assert len(matches) == 1
    cited = {e.id for e in matches[0].events}
    assert "login" in cited and "open" not in cited
