"""Fixtures for SSH password guessing, spraying and success after failures. Addresses are documentation ranges;
accounts and hosts are invented."""
import random
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.auth import SshPasswordGuessing, SshPasswordSpraying, SshSuccessAfterFailures
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
ATTACKER = "203.0.113.9"
_n = 0


def ssh(ts, outcome=Outcome.failure, phase="authentication", user="root", ip=ATTACKER, port=40000, valid=True,
        method="password", host="app01", service="sshd"):
    global _n
    _n += 1
    fields = {"auth.service": service, "auth.phase": phase, "source.ip": ip, "source.port": port,
              "auth.user_valid": valid, "auth.method": method, "user.name": user}
    fields = {k: fv(v, f"fixture{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"s{_n:05d}", family="auth", ts=ts, host=host, outcome=outcome, fields=fields,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def failures(n, start=T0, step=30, user="root", ip=ATTACKER, port0=40000, **kw):
    return [ssh(start + timedelta(seconds=step * i), user=user, ip=ip, port=port0 + i, **kw) for i in range(n)]


def accepted(ts, user="root", ip=ATTACKER, port=50000, method="password", **kw):
    return ssh(ts, Outcome.success, user=user, ip=ip, port=port, method=method, **kw)


def run(cls, *partitions):
    pb = cls()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


# ---------------------------------------------------------------- password guessing
def test_guessing_burst_is_one_grouped_lead_with_denominators():
    pb, out = run(SshPasswordGuessing, failures(12))
    assert len(out) == 1
    m = out[0]
    assert (m.proposed_lane, m.severity, m.confidence) == ("lead", "medium", "high")
    assert "12 failed authentication attempt(s) for account 'root' from 203.0.113.9 in 12 connection(s)" in m.claim
    assert "the most within any 10 minutes was 12 (threshold 10)" in m.claim
    assert "no accepted sshd login for this account from this source" in m.claim
    assert "succeeded" not in m.claim and "brute force" not in m.claim.lower()
    assert len(m.events) == 11 and m.events[0].ts == T0                 # the crossing window plus the last attempt
    assert pb.evaluated == 12 and pb.missing_required == 0


def test_below_threshold_is_not_reported():
    assert run(SshPasswordGuessing, failures(9))[1] == []


@pytest.mark.parametrize("span,found", [(600.0, True), (600.001, False)])
def test_window_boundary_is_inclusive(span, found):
    events = failures(9, step=1) + [ssh(T0 + timedelta(seconds=span), port=49999)]
    events[0] = ssh(T0, port=48888)
    out = run(SshPasswordGuessing, events)[1]
    assert bool(out) is found


def test_key_probes_inside_connections_that_log_in_are_not_failures():
    events = []
    for i in range(6):                               # a client offering three keys before the accepted one
        start = T0 + timedelta(minutes=i)
        events += [ssh(start, port=41000 + i, method="publickey"),
                   ssh(start + timedelta(seconds=1), port=41000 + i, method="publickey"),
                   accepted(start + timedelta(seconds=2), port=41000 + i, method="publickey")]
    pb, out = run(SshPasswordGuessing, events)
    assert out == [] and pb.probe_failures == 12


def test_several_failed_lines_in_one_connection_count_each_but_one_connection():
    events = [ssh(T0 + timedelta(seconds=i), port=42000 + i // 2) for i in range(10)]
    m = run(SshPasswordGuessing, events)[1][0]
    assert "10 failed authentication attempt(s)" in m.claim and "in 5 connection(s)" in m.claim


def test_key_only_server_counts_one_attempt_per_connection_and_names_invalid_users():
    events = []
    for i in range(10):
        ts = T0 + timedelta(seconds=20 * i)
        events += [ssh(ts, phase="user_lookup", user="admin", valid=False, port=43000 + i, method=None),
                   ssh(ts + timedelta(seconds=1), phase="preauth_disconnect", user="admin", valid=False,
                       port=43000 + i, method=None)]
    m = run(SshPasswordGuessing, events)[1][0]
    assert "10 failed authentication attempt(s) for account 'admin'" in m.claim and "in 10 connection(s)" in m.claim
    assert "sshd reported 'admin' as an invalid user" in m.claim


def test_audit_login_failures_and_other_services_are_not_counted():
    audit = [ssh(T0 + timedelta(seconds=i), phase="login", port=None) for i in range(20)]
    other = [ssh(T0 + timedelta(seconds=i), service="sudo", port=44000 + i) for i in range(20)]
    pb, out = run(SshPasswordGuessing, audit + other)
    assert out == [] and pb.evaluated == 0 and pb.missing_required == 0


def test_missing_source_or_unknown_outcome_is_partial_never_silent():
    no_source = failures(12)
    for e in no_source:
        del e.fields["source.ip"]
    unknown = [ssh(T0, Outcome.unknown, port=45000)]
    pb, out = run(SshPasswordGuessing, no_source + unknown)
    assert out == [] and pb.missing_required == 13 and pb.evaluated == 0


def test_attempts_split_across_partitions_are_counted_together():
    events = failures(12)
    pb, out = run(SshPasswordGuessing, events[:5], events[5:])
    assert len(out) == 1 and "12 failed authentication attempt(s)" in out[0].claim
    assert not pb._heap and pb.retained_events() != []


def test_accepted_login_from_the_source_is_stated_as_a_denominator():
    out = run(SshPasswordGuessing, failures(12) + [accepted(T0 + timedelta(minutes=20))])[1]
    assert "1 accepted sshd login(s) for this account from this source" in out[0].claim


def test_results_are_deterministic_under_input_order_within_partitions():
    # The sweep hands partitions over in time order; inside a partition the record order is arbitrary.
    events = failures(12) + failures(11, user="admin", port0=46000) + failures(10, ip="198.51.100.20", port0=47000)
    cut = T0 + timedelta(minutes=3)
    early, late = [e for e in events if e.ts < cut], [e for e in events if e.ts >= cut]
    claims = []
    for seed in (1, 2, 3):
        parts = [list(early), list(late)]
        for part in parts:
            random.Random(seed).shuffle(part)
        claims.append(sorted((m.group_key, m.claim, [e.id for e in m.events])
                             for m in run(SshPasswordGuessing, *parts)[1]))
    assert claims[0] == claims[1] == claims[2] and len(claims[0]) == 3


# ---------------------------------------------------------------- password spraying
def test_spraying_many_names_is_one_lead_per_source():
    names = ["root", "admin", "oracle", "test", "ubuntu", "postgres"]
    events = [ssh(T0 + timedelta(minutes=8 * i), user=name, port=40100 + i, valid=name in {"root", "ubuntu"})
              for i, name in enumerate(names)]
    out = run(SshPasswordSpraying, events)[1]
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and "6 distinct account name(s) from 203.0.113.9" in m.claim
    assert "threshold 5" in m.claim and "reported 4 of them as invalid users" in m.claim
    assert "'oracle'" in m.claim and len(m.events) == 6


def test_four_names_or_names_spread_beyond_the_window_are_not_spraying():
    four = [ssh(T0 + timedelta(minutes=i), user=f"u{i}", port=40200 + i) for i in range(4)]
    assert run(SshPasswordSpraying, four)[1] == []
    spread = [ssh(T0 + timedelta(minutes=m), user=f"v{i}", port=40300 + i) for i, m in enumerate((0, 15, 30, 45, 61))]
    assert run(SshPasswordSpraying, spread)[1] == []


def test_spray_window_boundary():
    events = [ssh(T0 + timedelta(seconds=900 * i), user=f"w{i}", port=40400 + i) for i in range(5)]   # 0 .. 3600 s
    assert len(run(SshPasswordSpraying, events)[1]) == 1


# ---------------------------------------------------------------- success after failures
def test_success_from_the_failing_source_is_high_and_restrained():
    events = failures(6) + [accepted(T0 + timedelta(minutes=8))]
    out = run(SshSuccessAfterFailures, events)[1]
    assert len(out) == 1
    m = out[0]
    assert (m.proposed_lane, m.severity, m.confidence) == ("high", "high", "high")
    assert "accepted a password login for account 'root' from 203.0.113.9" in m.claim
    assert "after 6 failed attempt(s) from 203.0.113.9 in the preceding 30 minutes" in m.claim
    assert "whether one actor made both is not established" in m.claim
    assert len(m.events) == 7 and m.events[-1].outcome == Outcome.success
    assert m.claim_type == "correlated_observation"


def test_success_after_spraying_names_the_accounts_tried():
    events = [ssh(T0 + timedelta(seconds=10 * i), user=u, port=40500 + i) for i, u in
              enumerate(["admin", "test", "oracle", "ubuntu", "deploy"])]
    m = run(SshSuccessAfterFailures, events + [accepted(T0 + timedelta(minutes=2), user="deploy")])[1][0]
    assert "accounts tried: 'admin', 'deploy', 'oracle', 'test', 'ubuntu'" in m.claim
    assert "T1110.003" in m.notes


def test_a_user_who_mistyped_twice_is_not_reported():
    assert run(SshSuccessAfterFailures, failures(2) + [accepted(T0 + timedelta(minutes=2))])[1] == []


def test_failures_older_than_the_window_do_not_count():
    assert run(SshSuccessAfterFailures, failures(6) + [accepted(T0 + timedelta(minutes=40))])[1] == []


def test_failures_after_the_success_do_not_count():
    assert run(SshSuccessAfterFailures, [accepted(T0)] + failures(6, start=T0 + timedelta(seconds=5)))[1] == []


def test_probes_inside_the_successful_connection_are_not_failures():
    events = [ssh(T0 + timedelta(seconds=i), port=50000, method="publickey") for i in range(6)]
    assert run(SshSuccessAfterFailures, events + [accepted(T0 + timedelta(seconds=7), method="publickey")])[1] == []


def test_failures_from_other_sources_against_the_account_are_a_lead():
    scanners = (failures(4, ip="192.0.2.10", port0=40600) + failures(4, ip="192.0.2.11", port0=40700)
                + failures(4, ip="192.0.2.12", port0=40800))
    m = run(SshSuccessAfterFailures, scanners + [accepted(T0 + timedelta(minutes=5), ip="198.51.100.7",
                                                          method="publickey")])[1][0]
    assert (m.proposed_lane, m.confidence) == ("lead", "medium")
    assert "12 failed attempt(s) against 'root' from 3 other source address(es)" in m.claim
    assert "and 0 from 198.51.100.7 itself" in m.claim and "do not link them" in m.claim


def test_repeated_successes_are_one_grouped_finding():
    events = failures(6) + [accepted(T0 + timedelta(minutes=4 + i), port=50100 + i) for i in range(3)]
    out = run(SshSuccessAfterFailures, events)[1]
    assert len(out) == 1 and "followed such failures 3 time(s)" in out[0].claim


# ---------------------------------------------------------------- registry
@pytest.mark.parametrize("cls", [SshPasswordGuessing, SshPasswordSpraying, SshSuccessAfterFailures])
def test_rules_are_registered_positive_only_aggregates_with_cards_and_valid_attack_ids(cls):
    import gzip
    import json
    from pathlib import Path
    assert cls in ALL_PLAYBOOKS and any(isinstance(pb, cls) for pb in fresh_pack())
    assert cls.kind == "aggregate" and not cls.assures_negative and cls.positive_only_reason
    assert {"behavior", "telemetry", "fidelity", "thresholds", "research_basis", "retrieval"} <= set(cls.card)
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    ids = {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
           and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
           for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert set(cls.attack) <= ids
