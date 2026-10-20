"""Context-only playbooks: anchor-gated behavior, lane caps, citations and coverage."""
from datetime import UTC, datetime

import pytest

from romulus.decide.policy import decide
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.context import EntryPointPromotion, PostAccessDiscovery
from romulus.detect.registry import fresh_context_pack, fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.context import evaluate_context
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


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
    observed = event("discovery", process__argv=argv, process__session_id=42)

    matches = PostAccessDiscovery().consume_linked(anchor(), link(), [observed])

    assert len(matches) == 1
    match = matches[0]
    assert technique in match.notes
    assert "F-anchor" in match.claim and "L-session" in match.claim
    assert {item.id for item in match.events} == {"discovery", "anchor-event", "link-event"}
    decision = decide(match, "hunt-1")
    assert decision.admitted and decision.lane == "high"


@pytest.mark.parametrize("argv", [
    ["echo", "whoami"], ["whoami-helper"], ["getent", "hosts", "example.test"], ["ipcalc", "10.0.0.1"],
])
def test_post_access_discovery_rejects_mentions_and_near_names(argv):
    observed = event("benign", process__argv=argv, process__session_id=42)

    assert PostAccessDiscovery().consume_linked(anchor(), link(), [observed]) == []


def test_context_rule_never_fires_without_an_anchor():
    observed = event("discovery", process__argv=["whoami"], process__session_id=42)

    assert PostAccessDiscovery().consume_linked(None, link(), [observed]) == []
    assert EntryPointPromotion().consume_linked(None, link(), [observed]) == []


def test_inferred_link_caps_context_finding_at_lead_and_labels_hypothesis():
    observed = event("discovery", process__argv=["uname", "-a"], process__session_id=42)

    match = PostAccessDiscovery().consume_linked(
        anchor(), link(strength="inferred", link_type="host_after_anchor"), [observed],
    )[0]

    assert match.proposed_lane == "lead"
    assert "hypothesis" in match.claim.lower()


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


def test_context_coverage_cell_is_scoped_to_anchor_and_link():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    observed = event("discovery", process__argv=["whoami"], process__session_id=42)

    evaluated = evaluate_context(repo, "h1", anchor(), link(), [observed])

    assert len(evaluated) == 1
    cells = repo.rule_cells("h1")
    row = next(cell for cell in cells if cell["rule_id"] == "context.post_access_discovery")
    assert row["target"] == "link:login_session"
    assert row["partition"] == "anchor:F-anchor|link:L-session"
    assert row["state"] == "matched"
    assert row["detail"]["strength"] == "observed"
