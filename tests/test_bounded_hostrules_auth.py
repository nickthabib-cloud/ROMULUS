"""Mission-scale state of the sshd attempt rules and the account-change rule: tallies, sliding windows, login counts,
found logins, changes and tool records spill to disk and read back exactly; only a disk budget refuses, a refused
record is not counted as evaluated, and an accepted-login count the budget cut short is stated as a lower bound."""
from datetime import timedelta

import pytest

from romulus.detect.auth import (
    AccountOrGroupChange,
    SshPasswordGuessing,
    SshPasswordSpraying,
    SshSuccessAfterFailures,
)
from tests.test_account_changes import ev as account_ev
from tests.test_account_changes import ex, record
from tests.test_bounded_host import same_small_and_unbounded, staged_run
from tests.test_ssh_auth_attacks import T0, accepted, failures, ssh


def _by_time(events, chunks):
    events = sorted(events, key=lambda e: (e.ts, e.id))
    size = -(-len(events) // chunks)
    return [events[i:i + size] for i in range(0, len(events), size)]


def ssh_hunt():
    """Guessing from 30 sources (ten then log in), spraying from 15 sources, and one account guessed from 12 other
    addresses before its owner logs in from elsewhere; read in 12 partitions."""
    events = []
    for s in range(30):
        start = T0 + timedelta(minutes=7 * s)
        events += failures(12, start=start, step=20, ip=f"203.0.113.{s + 1}", port0=40000 + 100 * s,
                           host=f"node{s % 4}")
        if s % 3 == 0:
            events.append(accepted(start + timedelta(minutes=5), ip=f"203.0.113.{s + 1}", port=50000 + s,
                                   host=f"node{s % 4}"))
    for s in range(15):
        start = T0 + timedelta(hours=4, minutes=5 * s)
        events += [ssh(start + timedelta(seconds=30 * k), user=f"user{k}", ip=f"198.51.100.{s + 1}",
                       port=41000 + 100 * s + k, valid=k % 2 == 0, host="node9") for k in range(7)]
    for k in range(12):
        events.append(ssh(T0 + timedelta(hours=6, seconds=60 * k), user="deploy", ip=f"192.0.2.{k + 1}",
                          port=42000 + k, host="node9"))
    events.append(accepted(T0 + timedelta(hours=6, minutes=14), user="deploy", ip="192.0.2.200", host="node9"))
    return _by_time(events, 12)


@pytest.mark.parametrize("cls, store", [(SshPasswordGuessing, "tallies"), (SshPasswordSpraying, "tallies"),
                                        (SshSuccessAfterFailures, "by_source")])
def test_ssh_attempt_state_spills_and_reads_back_exactly(cls, store, tmp_path, monkeypatch):
    rule, _out = same_small_and_unbounded(cls, ssh_hunt(), tmp_path, monkeypatch, store)
    assert rule.retained_events() == []


def test_guessing_disk_budget_refuses_a_new_key_and_the_attempt_is_not_evaluated(tmp_path, monkeypatch):
    """Two sources' tallies are made and one moves to disk, spending the budget; a third source's attempts are
    refused. (An accepted login settles the first partition without touching the tallies.)"""
    parts = [failures(12, ip="203.0.113.1", port0=40000) + failures(12, ip="203.0.113.2", port0=41000),
             [accepted(T0 + timedelta(minutes=30), ip="203.0.113.9")],
             failures(12, start=T0 + timedelta(hours=1), ip="203.0.113.3", port0=42000)]
    rule, out = staged_run(SshPasswordGuessing, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"tallies": 1})
    assert len(out) == 2 and rule.capped == 12 and rule.evaluated == 24 + 1
    assert any("disk budget is spent" in r for r in rule.limit_reasons())


def test_a_login_count_the_disk_budget_cut_short_is_stated_as_a_lower_bound(tmp_path, monkeypatch):
    """Two sources' login counts are made and one moves to disk, spending the budget; a later login of a third key
    is not counted, so every count is stated as a lower bound."""
    parts = [failures(12, ip="203.0.113.1", port0=40000) + failures(12, ip="203.0.113.2", port0=41000)
             + [accepted(T0 + timedelta(minutes=7), ip="203.0.113.1"),
                accepted(T0 + timedelta(minutes=8), ip="203.0.113.4", port=50004)],
             [ssh(T0 + timedelta(minutes=30), user="other", ip="203.0.113.8", port=43000)],
             [accepted(T0 + timedelta(hours=1), ip="203.0.113.2", port=50002)]]
    rule, out = staged_run(SshPasswordGuessing, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"successes": 1})
    assert rule.capped == 0 and any("accepted login is not counted" in r for r in rule.limit_reasons())
    claims = {m.group_key: m.claim for m in out}
    assert "at least 1 accepted sshd login(s)" in claims["app01|203.0.113.1|root"]
    assert "at least 0 accepted sshd login(s)" in claims["app01|203.0.113.2|root"]


@pytest.mark.slow
def test_sixty_thousand_guessing_sources_spill_and_none_is_refused(tmp_path, monkeypatch):
    attempts = [ssh(T0 + timedelta(milliseconds=100 * i), ip=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}",
                    port=40000 + i % 20000) for i in range(60_000)]
    attempts += failures(12, start=T0 + timedelta(hours=3), ip="203.0.113.77")
    rule, out = staged_run(SshPasswordGuessing, _by_time(attempts, 30), tmp_path, hot=1_000,
                           monkeypatch=monkeypatch)
    assert rule.tallies.on_disk > 50_000 and rule.capped == 0 and rule.evaluated == 60_012
    [m] = out
    assert m.group_key == "app01|203.0.113.77|root"


# ---------------------------------------------------------------- account and group changes
def account_hunt():
    """Commands with their tools' records on 20 hosts and pids, record-only changes after a boot, and package
    lineage, read in 6 partitions."""
    events = []
    for h in range(20):
        ts = T0 + timedelta(minutes=h)
        command = ex(["useradd", "-m", f"u{h}"], pid=7000 + h, ts=ts)
        rec = record("ADD_USER", "create_user", ts=ts + timedelta(milliseconds=40), pid=7000 + h,
                     account__op="add-user", account__name=f"u{h}")
        promote = ex(["usermod", "-aG", "sudo", f"u{h}"], pid=7100 + h, ts=ts + timedelta(seconds=5))
        for e in (command, rec, promote):
            e.host = f"node{h % 5}"
        events += [command, rec, promote]
    boot = account_ev("system_state", T0 + timedelta(hours=2), system__event="boot")
    events.append(boot)
    events += [record("USER_CHAUTHTOK", "password_change", ts=T0 + timedelta(hours=2, minutes=k), pid=8000 + k,
                      account__op="change-password", account__name=f"svc{k}") for k in range(8)]
    return _by_time(events, 6)


def test_account_changes_spill_and_read_back_exactly(tmp_path, monkeypatch):
    rule, out = same_small_and_unbounded(AccountOrGroupChange, account_hunt(), tmp_path, monkeypatch, "by_pid")
    assert rule.retained_events() == [] and any(m.proposed_lane == "high" for m in out)


@pytest.mark.parametrize("budget, refused", [("by_pid", "account changes'"), ("records", "account records'")])
def test_account_disk_budgets_refuse_and_the_record_is_not_evaluated(budget, refused, tmp_path, monkeypatch):
    parts = account_hunt()
    unbounded, _ = staged_run(AccountOrGroupChange, parts, tmp_path / "big", hot=10**6, monkeypatch=monkeypatch)
    rule, _ = staged_run(AccountOrGroupChange, parts, tmp_path / "small", hot=1, monkeypatch=monkeypatch,
                         budgets={budget: 1})
    assert rule.capped > 0 and rule.evaluated == unbounded.evaluated - rule.capped
    assert any(refused in r and "disk budget is spent" in r for r in rule.limit_reasons())
