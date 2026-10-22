"""Mission-scale exec history and per-key tallies of the host rules: bounded, honest when exceeded, and a cited
record's lineage survives the release of its processes."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import auth
from romulus.detect.correlation import InterpreterExternalConnection, PidTable
from romulus.detect.host import ProcessLineage
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)


def ev(event_id, family, ts, host="web1", outcome=Outcome.success, **fields):
    return TypedEvent(id=event_id, family=family, ts=ts, host=host, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"{event_id}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def execd(pid, ppid, exe, ts, **fields):
    return ev(f"exec-{pid}-{ts.timestamp()}", "process_exec", ts, process__pid=pid, process__ppid=ppid,
              process__executable=exe, process__argv=[exe], **fields)


@pytest.mark.slow
def test_pid_table_holds_at_most_its_capacity_over_a_million_processes():
    table = PidTable(capacity=10_000)
    for pid in range(1_000_000):
        table.add(execd(pid, 1, "/usr/bin/true", T0 + timedelta(milliseconds=pid)))
        assert len(table.execs) <= 10_000
    assert table.evicted == 990_000
    assert table.lookup("web1", 999_999, (T0 + timedelta(hours=1)).timestamp()) is not None
    unbounded = PidTable()                                       # expansion and baseline callers: everything
    for pid in range(20_000):
        unbounded.add(execd(pid, 1, "/usr/bin/true", T0))
    assert len(unbounded.execs) == 20_000 and unbounded.evicted == 0


def test_a_cited_connection_keeps_its_web_server_lineage_after_release(monkeypatch):
    monkeypatch.setattr(PidTable, "CAPACITY", 50)
    rule = InterpreterExternalConnection()
    apache = execd(90, 1, "/usr/sbin/apache2", T0)
    sock = ev("s1", "net_socket", T0 + timedelta(seconds=5), socket__syscall="connect",
              process__executable="/usr/bin/perl", process__user="www-data", process__pid=100, process__ppid=90,
              destination__ip="203.0.113.5", destination__port=443)
    churn = [execd(1000 + i, 1, "/usr/bin/true", T0 + timedelta(seconds=10 + i)) for i in range(500)]
    rule.consume([apache])
    rule.consume([sock])
    rule.consume(churn)
    assert len(rule.pids.execs) <= 50 and rule.pids.evicted > 0
    [m] = rule.finalize()
    assert "ancestry includes the web server '/usr/sbin/apache2'" in m.claim and m.proposed_lane == "high"
    assert any("released" in reason for reason in rule.limit_reasons())


def test_process_lineage_keeps_an_active_parent_and_states_releases(monkeypatch):
    monkeypatch.setattr(ProcessLineage, "CAPACITY", 20)
    lineage = ProcessLineage()
    lineage.observe(execd(50, 1, "/usr/bin/dpkg", T0))
    for i in range(200):
        child = execd(1000 + i, 50, "/bin/sh", T0 + timedelta(seconds=i + 1))
        lineage.observe(child)
        assert lineage.classify(child).kind == "package"           # the parent stays while it keeps starting children
    assert len(lineage.records) <= 20 and lineage.evicted > 0

    class Owner:
        def __init__(self):
            self.noted = []

        def note_limit(self, name, text, records=0):
            self.noted.append((name, text))
    owner = Owner()
    lineage.note(owner)
    assert owner.noted and owner.noted[0][0] == "lineage"


def test_ssh_tallies_budget_refuses_new_sources(monkeypatch):
    monkeypatch.setattr(auth._SshAttemptStream, "MAX_KEYS", 3)
    rule = auth.SshPasswordGuessing()
    events = [ev(f"a{i}", "auth", T0 + timedelta(seconds=i), outcome=Outcome.failure, auth__service="sshd",
                 auth__phase="authentication", source__ip=f"198.51.100.{i}", source__port=40000 + i,
                 user__name="root") for i in range(1, 8)]
    rule.consume(events)
    rule.finalize()
    assert len(rule.tallies) == 3 and rule.capped == 4
    assert any("4 record(s) not evaluated" in r for r in rule.limit_reasons())


def test_account_change_budget_refuses_later_changes(monkeypatch):
    monkeypatch.setattr(auth.AccountOrGroupChange, "MAX_HELD", 2)
    rule = auth.AccountOrGroupChange()
    events = [ev(f"u{i}", "process_exec", T0 + timedelta(seconds=i), process__pid=300 + i, process__ppid=1,
                 process__executable="/usr/sbin/useradd", process__argv=["useradd", f"user{i}"], process__uid="0",
                 process__user="root") for i in range(5)]
    rule.consume(events)
    assert len(rule.changes) == 2 and rule.capped == 3
