"""Synthetic service decisions; NIST SP 800-63B-4 section 3.2.2 informs the rate heuristic."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 1, 6, 9, tzinfo=UTC)


def event(n, *, service="dovecot", user="alice", ip="203.0.113.9", outcome=Outcome.failure,
          phase="authentication", seconds=None, host="mail01", family="auth", extra=None):
    values = {"auth.service": service, "auth.phase": phase, "user.name": user, "source.ip": ip}
    values.update(extra or {})
    return TypedEvent(id=f"e{n}", family=family, ts=T0 + timedelta(seconds=n if seconds is None else seconds),
                      host=host, outcome=outcome, fields={k: fv(v, "synthetic:" + k)
                                                        for k, v in values.items() if v is not None},
                      raw=[RawRef(target="fixture", native_id=str(n))], normalizer="fixture")


def rule(rule_id, **kwargs):
    types = {cls.id: cls for cls in ALL_PLAYBOOKS}
    assert rule_id in types, f"missing implemented rule: {rule_id}"
    return types[rule_id](**kwargs)


def run(pb, *parts):
    out = []
    for part in parts:
        out.extend(pb.consume(part))
    out.extend(pb.finalize())
    return out


@pytest.mark.parametrize("service", ["dovecot", "postfix", "openvpn", "vsftpd", "roundcube", "mysql", "samba"])
def test_guessing_counts_explicit_failures_and_isolates_each_service(service):
    pb = rule("auth.password_guessing")
    out = run(pb, [event(i, service=service) for i in range(12)])
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert service in out[0].claim and "10" in out[0].claim


@pytest.mark.parametrize("mode", ["below", "separated", "service", "successes", "session", "sshd"])
def test_guessing_adversarial_negatives(mode):
    rows = [event(i) for i in range(10)]
    if mode == "below":
        rows.pop()
    elif mode == "separated":
        rows[-1] = event(9, seconds=601)
    elif mode == "service":
        rows[-1] = event(9, service="openvpn")
    elif mode == "successes":
        rows[-1] = event(9, outcome=Outcome.success)
    elif mode == "session":
        rows = [event(i, phase="session_open") for i in range(12)]
    else:
        rows = [event(i, service="sshd") for i in range(12)]
    assert run(rule("auth.password_guessing"), rows) == []


def test_spray_requires_ten_distinct_accounts_within_the_same_service_window():
    pb = rule("auth.password_spraying")
    rows = [event(i, user=f"user{i}") for i in range(10)]
    assert len(run(pb, rows[:4], rows[4:])) == 1
    assert run(rule(pb.id), [event(i, user=f"user{i % 9}") for i in range(20)]) == []
    assert run(rule(pb.id), rows[:9] + [event(10, user="new", service="openvpn")]) == []
    assert run(rule(pb.id), rows[:9] + [event(10, user="new", seconds=601)]) == []


def test_success_requires_preceding_same_source_account_service_failures_and_names_scope():
    rows = [event(i) for i in range(10)]
    out = run(rule("auth.success_new_source_after_failures"), rows, [event(20, outcome=Outcome.success)])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "supplied window" in out[0].claim
    assert any(e.outcome == Outcome.success for e in out[0].events)


@pytest.mark.parametrize("mode", ["below", "service", "before", "old", "known"])
def test_success_after_failure_adversarial_negatives(mode):
    rows = [event(i) for i in range(10)]
    kw = {"outcome": Outcome.success}
    if mode == "below":
        rows.pop()
    elif mode == "service":
        kw["service"] = "openvpn"
    elif mode == "before":
        kw["seconds"] = -1
    elif mode == "old":
        kw["seconds"] = 610
    else:
        rows.insert(0, event(100, seconds=-1, outcome=Outcome.success))
    assert run(rule("auth.success_new_source_after_failures"), rows + [event(20, **kw)]) == []


def test_success_from_a_different_source_after_account_failures_is_only_a_lead():
    rows = [event(i) for i in range(10)]
    out = run(rule("auth.success_new_source_after_failures"), rows,
              [event(20, ip="198.51.100.8", outcome=Outcome.success)])
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "other sources" in out[0].claim


def test_source_spray_followed_by_first_login_for_another_account_is_high():
    rows = [event(i, user=f"target{i}") for i in range(10)]
    out = run(rule("auth.success_new_source_after_failures"), rows,
              [event(20, user="newaccount", outcome=Outcome.success)])
    assert len(out) == 1 and out[0].proposed_lane == "high"


def test_account_variant_retains_earlier_failures_when_nine_own_source_failures_follow():
    rows = [event(i, ip="198.51.100.8") for i in range(10)] + [event(20+i) for i in range(9)]
    out = run(rule("auth.success_new_source_after_failures"), rows, [event(40, outcome=Outcome.success)])
    assert len(out) == 1 and out[0].proposed_lane == "lead"


@pytest.mark.parametrize("rule_id", ["auth.password_guessing", "auth.password_spraying",
                                    "auth.success_new_source_after_failures"])
@pytest.mark.parametrize("missing", ["source.ip", "user.name", "auth.service", "auth.phase", "host", "outcome"])
def test_missing_auth_fields_are_unresolved(rule_id, missing):
    row = event(0)
    if missing == "host":
        row.host = None
    elif missing == "outcome":
        row.outcome = Outcome.unknown
    else:
        del row.fields[missing]
    pb = rule(rule_id)
    assert run(pb, [row]) == []
    assert pb.missing_required == 1


def test_auth_order_replay_and_spill_preserve_one_candidate_per_key(tmp_path):
    rows = [event(i, user=f"u{i // 10}") for i in range(600)]
    pb = rule("auth.password_guessing")
    pb.spill_dir = tmp_path
    pb.HOT = 2
    out = run(pb, list(reversed(rows)), rows[:10])
    assert len(out) == 60
    assert len({m.group_key for m in out}) == 60
    assert pb.holds_state and pb._spill is not None
    pb.close_spill()


def test_disk_refusal_counts_unevaluated_records_honestly(tmp_path):
    from romulus.detect.bounded import StateBudget

    pb = rule("auth.password_guessing")
    pb.budget = StateBudget(tmp_path, reserve=0)
    pb.budget.broken = "synthetic unavailable disk"
    assert run(pb, [event(0)]) == []
    assert pb.capped == 1 and pb.evaluated == 0
    assert pb.limit_reasons()


def test_ssh_and_session_events_allocate_no_generic_auth_state():
    pb = rule("auth.password_guessing")
    assert run(pb, [event(0, service="sshd"), event(1, phase="session_open")]) == []
    assert len(pb._ids) == 0


def test_many_single_attempt_accounts_spill_without_masking_late_burst(tmp_path):
    pb = rule("auth.password_guessing")
    pb.spill_dir = tmp_path
    pb.HOT = 16
    for offset in range(0, 20_000, 200):
        pb.consume([event(i, user=f"account{i}") for i in range(offset, offset + 200)])
        assert len(pb._rows.buffer) <= 16 and len(pb._ids.hot) <= 16
    pb.consume([event(30_000+i, user="late", seconds=30_000+i) for i in range(10)])
    out = list(pb.finalize())
    assert len(out) == 1 and "'late'" in out[0].claim
    assert pb.evaluated == 20_010 and pb.capped == 0
    assert len(pb._groups.hot) <= 16 and pb._groups.on_disk > 19_000
    pb.close_spill()


def test_malformed_phase_is_unresolved_rather_than_an_out_of_scope_session():
    row = event(0)
    row.fields["auth.phase"] = fv(["authentication"], "synthetic")
    pb = rule("auth.password_guessing")
    assert run(pb, [row]) == [] and pb.missing_required == 1


def test_simultaneous_failure_cannot_hide_ten_strictly_earlier_failures():
    rows = [event(i) for i in range(10)]
    rows += [event(10, seconds=20), event(20, outcome=Outcome.success)]
    out = run(rule("auth.success_new_source_after_failures"), rows)
    assert len(out) == 1 and out[0].proposed_lane == "high"


@pytest.mark.parametrize("ip,failed_users,login_user,validity,wanted_lane", [
    ("203.0.113.9", ("alice",), "bob", None, "lead"),
    ("127.0.0.1", ("alice",), "bob", None, "lead"),
    ("::1", ("alice",), "bob", None, "lead"),
    ("203.0.113.9", ("alice",), "alice", None, "high"),
    ("127.0.0.1", ("alice",), "alice", None, "high"),
    ("203.0.113.9", ("alice", "carol"), "bob", None, "lead"),
    ("203.0.113.9", ("alice", "carol", "dave"), "bob", None, "high"),
    ("203.0.113.9", ("missing",), "bob", False, "high"),
    ("203.0.113.9", ("alice",), "bob", True, "lead"),
    ("203.0.113.9", ("alice",), "bob", "false", "lead"),
    ("203.0.113.9", ("alice",), "bob", 0, "lead"),
])
def test_success_source_guard_requires_account_spray_or_explicit_invalid_user(
        ip, failed_users, login_user, validity, wanted_lane):
    extra = {} if validity is None else {"auth.user_valid": validity}
    rows = [event(i, ip=ip, user=failed_users[i % len(failed_users)], extra=extra) for i in range(10)]
    success = event(20, ip=ip, user=login_user, outcome=Outcome.success)
    out = run(rule("auth.success_new_source_after_failures"), rows[:5], rows[5:], [success])
    assert len(out) == 1
    match = out[0]
    assert match.proposed_lane == wanted_lane
    assert {row.id for row in match.events} == {row.id for row in rows + [success]}
    assert "failures from that source" in match.claim and "other sources" not in match.claim
    if wanted_lane == "lead":
        assert match.confidence == "medium" and match.severity == "medium"
        assert "need not belong to this login" in match.claim
    if validity is False:
        assert any(field.field == "auth.user_valid" and field.value is False for field in match.predicate)


PAM = {"auth.channel": "pam"}


@pytest.mark.parametrize("rule_id", ["auth.password_guessing", "auth.password_spraying"])
def test_a_daemon_and_its_pam_backend_never_add_up(rule_id):
    users = (lambda i: "alice") if rule_id == "auth.password_guessing" else (lambda i: f"user{i}")
    # nine attempts, each logged once by the daemon and once by its PAM backend
    pairs = [event(2 * i + k, user=users(i), extra=PAM if k else None) for i in range(9) for k in (0, 1)]
    assert run(rule(rule_id), pairs) == []


@pytest.mark.parametrize("rule_id", ["auth.password_guessing", "auth.password_spraying"])
def test_pam_lines_alone_still_reach_the_threshold(rule_id):
    users = (lambda i: "alice") if rule_id == "auth.password_guessing" else (lambda i: f"user{i}")
    out = run(rule(rule_id), [event(i, user=users(i), extra=PAM) for i in range(10)])
    assert len(out) == 1 and all(e.get("auth.channel") == "pam" for e in out[0].events)


@pytest.mark.parametrize("rule_id", ["auth.password_guessing", "auth.password_spraying"])
def test_a_burst_logged_by_both_channels_is_reported_once(rule_id):
    users = (lambda i: "alice") if rule_id == "auth.password_guessing" else (lambda i: f"user{i}")
    pairs = [event(2 * i + k, user=users(i), extra=PAM if k else None) for i in range(10) for k in (0, 1)]
    out = run(rule(rule_id), pairs)
    assert len(out) == 1 and not any(e.get("auth.channel") for e in out[0].events)


def test_success_after_failures_weighs_each_channel_alone():
    pb = rule("auth.success_new_source_after_failures")
    pairs = [event(2 * i + k, extra=PAM if k else None) for i in range(9) for k in (0, 1)]
    assert run(pb, pairs + [event(100, outcome=Outcome.success)]) == []
    pb = rule("auth.success_new_source_after_failures")
    out = run(pb, [event(i, extra=PAM) for i in range(10)] + [event(100, outcome=Outcome.success)])
    assert len(out) == 1 and out[0].proposed_lane == "high"


def test_a_pam_alias_does_not_report_the_daemons_burst_again():
    native = [event(i, service="proftpd") for i in range(10)]
    pam = [event(100 + i, service="ftp", extra=PAM) for i in range(10)]
    out = run(rule("auth.password_guessing"), native + pam)
    assert len(out) == 1 and all(e.get("auth.service") == "proftpd" for e in out[0].events)


def test_evidence_from_a_mismatched_writer_never_reaches_high():
    from romulus.evidence.linux_text_types import WRITER_MISMATCH_CAVEAT

    failures = [event(i) for i in range(10)]
    success = event(100, outcome=Outcome.success)
    success.caveats.append(WRITER_MISMATCH_CAVEAT)
    out = run(rule("auth.success_new_source_after_failures"), failures + [success])
    assert len(out) == 1 and out[0].proposed_lane == "lead" and "fabricated" in out[0].claim
