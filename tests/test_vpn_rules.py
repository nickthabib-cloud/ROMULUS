"""Synthetic lifecycle witnesses; OpenVPN/strongSwan log contracts do not imply overlapping sessions."""
from datetime import timedelta

import pytest

from romulus.baseline.spec import SPEC_BY_ID, KeyContext, Missing, NotApplicable
from romulus.evidence.typed import Outcome
from tests.test_service_auth import T0, event, rule, run

BASELINE = "vpn.login_from_new_source_ip_for_user"
CONCURRENT = "vpn.concurrent_sessions_same_user_distinct_sources"


def session(n, action, session_id, ip="203.0.113.9", user="alice", service="strongswan", **kwargs):
    return event(n, family="vpn_session", ip=ip, user=user, outcome=Outcome.success,
                 extra={"vpn.action": action, "vpn.service": service, "vpn.session_id": session_id}, **kwargs)


def test_concurrent_requires_two_closed_overlapping_lifecycles():
    rows = [session(0, "connect", "a"), session(10, "connect", "b", "198.51.100.8"),
            session(20, "disconnect", "a"), session(30, "disconnect", "b", "198.51.100.8")]
    out = run(rule(CONCURRENT), rows[2:], rows[:2])
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "overlap" in out[0].claim and len(out[0].events) == 4


@pytest.mark.parametrize("mode", ["unclosed", "nonoverlap", "same_ip", "service", "user", "missing_id"])
def test_vpn_concurrency_adversarial_negatives(mode):
    a = [session(0, "connect", "a"), session(10, "disconnect", "a")]
    kw = {"ip": "198.51.100.8"}
    start, end, session_id = 5, 20, "b"
    if mode == "unclosed":
        a.pop()
    elif mode == "nonoverlap":
        start = 10
    elif mode == "same_ip":
        kw["ip"] = "203.0.113.9"
    elif mode == "service":
        kw["service"] = "openvpn"
    elif mode == "user":
        kw["user"] = "bob"
    else:
        session_id = None
    pb = rule(CONCURRENT)
    assert run(pb, a + [session(start, "connect", session_id, **kw),
                       session(end, "disconnect", session_id, **kw)]) == []
    if mode in {"unclosed", "missing_id"}:
        assert pb.missing_required > 0


def test_vpn_baseline_requires_history_and_successful_explicit_authentication():
    pb = rule(BASELINE)
    assert pb.kind == "baseline" and pb.lane == "lead"
    assert run(pb, [event(0, service="openvpn", outcome=Outcome.success)]) == []
    assert BASELINE in SPEC_BY_ID
    spec = SPEC_BY_ID[BASELINE]
    good = event(0, service="openvpn", outcome=Outcome.success)
    keys = spec.keys(good, KeyContext())
    assert len(keys) == 1 and keys[0].key["source_ip"] == "203.0.113.9"
    assert isinstance(spec.keys(event(1, service="openvpn"), KeyContext()), NotApplicable)
    assert isinstance(spec.keys(event(2, service="dovecot", outcome=Outcome.success), KeyContext()), NotApplicable)
    assert isinstance(spec.keys(event(3, service="openvpn", ip=None, outcome=Outcome.success), KeyContext()), Missing)
    assert isinstance(spec.keys(event(4, service="openvpn", phase="session_open", outcome=Outcome.success),
                                KeyContext()), NotApplicable)


def test_vpn_baseline_cell_missing_user_is_partial():
    pb = rule(BASELINE)
    pb.begin_cell("cell", (T0, T0 + timedelta(hours=1)), KeyContext())
    pb.consume([event(0, service="openvpn", user=None, outcome=Outcome.success)])
    cell = pb.finish_cell()
    assert cell.partial and not cell.observations


@pytest.mark.parametrize("history,verdict,matches", [("none", "unresolved", 0), ("known", "common", 0),
                                                   ("new", "first_seen", 1), ("other_service", "unresolved", 0)])
def test_vpn_baseline_real_history_judgement(history, verdict, matches):
    from romulus.hunt.baseline_stage import run_baseline_stage
    from tests.test_baseline_stage import START, WINDOW, TimedHistory, _observation, _repo

    pb = rule(BASELINE)
    repo = _repo(spec_ids=(BASELINE,), budget={"queries": 1000, "records": 1000, "seconds": 1800})
    current = event(0, service="openvpn", outcome=Outcome.success)
    current.ts = START
    key = pb.spec.keys(current, KeyContext())[0]
    row = _observation(current, key_id=key.key_id, key_digest=key.key_digest, path="unused")
    row.update(spec_id=BASELINE, scope_kind=key.scope_kind, scope=key.scope, key=key.key)
    repo.upsert_baseline_observation(row)
    repo.save_evidence("h1", [current], {current.raw[0].key: {"fixture": "current"}}, None)
    prior = []
    if history != "none":
        for i in range(48):
            observed = event(100+i, service="charon" if history == "other_service" else "openvpn",
                             ip="203.0.113.9" if history == "known" else "198.51.100.8", outcome=Outcome.success)
            observed.ts = START - timedelta(hours=48-i)
            prior.append(observed)
    run_baseline_stage(repo, "h1", WINDOW, source=TimedHistory({"host-index": prior}))
    assert next(repo.baseline_observations("h1"))["verdict"] == verdict
    candidates = repo.candidates("h1")
    assert len(candidates) == matches
    assert all(candidate["lane"] == "lead" for candidate in candidates)
    if history == "none":
        assert all(cell["state"] != "no_match_complete" for cell in repo.rule_cells("h1"))


@pytest.mark.parametrize("duplicate,closed,expected", [(False, True, 1), (False, False, 0), (True, True, 0)])
def test_openvpn_log_lifecycles_reach_concurrency_rule(duplicate, closed, expected):
    # OpenVPN socket.c release/2.6 L2394; multi.c multi_close_instance_on_signal -> print_signal.
    from romulus.evidence.normalize import normalize_hits

    lines = [(0, "[alice] Peer Connection Initiated with [AF_INET]192.0.2.2:51234"),
             (5, "[alice] Peer Connection Initiated with [AF_INET]198.51.100.8:51235"),
             (30, "alice/198.51.100.8:51235 SIGTERM[soft,remote-exit] received, client-instance exiting")]
    if closed:
        lines.append((20, "alice/192.0.2.2:51234 SIGTERM[soft,remote-exit] received, client-instance exiting"))
    if duplicate:
        lines.append((10, "[alice] Peer Connection Initiated with [AF_INET]192.0.2.2:51234"))
    hits = [{"_index": "fixture", "_id": str(n), "_source": {"@timestamp": (T0 + timedelta(seconds=n)).isoformat(),
             "event": {"dataset": "system.syslog"}, "host": {"name": "vpn01"},
             "process": {"name": "openvpn"}, "message": line}}
            for n, line in lines]
    normalized, skips, errors = normalize_hits(hits)
    assert not skips and not errors
    sessions = [row for row in normalized if row.family == "vpn_session"]
    assert len(sessions) == len(lines)
    assert all(row.get("vpn.session_id") is None for row in sessions)
    pb = rule(CONCURRENT)
    out = run(pb, sessions)
    assert len(out) == expected
    if expected:
        assert out[0].proposed_lane == "lead"
    else:
        assert pb.missing_required > 0
