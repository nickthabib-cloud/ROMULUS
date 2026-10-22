"""The boot-interval map: an audit record without a boot id takes the boot its host was observed running at its time.

Records that name a boot with a time (every journald record, audit events joined to a journald copy) give each boot
of a host a span [first seen, last seen]. A time well inside exactly one span takes that boot; a time in a gap
between boots, near an edge, inside overlapping spans or near a boot record that names no boot stays unknown. The
sweep builds the map, records it with the hunt, and link fetches and the context pass use it. Hosts, boot ids,
accounts and addresses are invented (documentation ranges).
"""
import json
import random
import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.kernel_files import PersistencePathChange
from romulus.detect.lineage import ReverseShellByLineage
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import (
    BOOT_EDGE_SKEW,
    BOOT_INTERVAL_ORIGIN,
    BootIntervals,
    _micros,
    normalize_hits,
)
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.hunt.context import finalize_context
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_boot_identity import (
    BOOT_A,
    BOOT_B,
    JOB,
    T0,
    _projection,
    _shell_events,
    change,
    ev,
    exc,
    hx,
    run,
)
from tests.test_context_playbooks import T0 as CTX_T0
from tests.test_context_playbooks import _seed_anchor, _seed_link
from tests.test_expansion_links import FakePivot

EPOCH = 1_900_000_000                    # 2030-03-17T17:46:40Z
SKEW = int(BOOT_EDGE_SKEW.total_seconds())


def at(seconds: float) -> datetime:
    return datetime.fromtimestamp(EPOCH, UTC) + timedelta(seconds=seconds)


def us(seconds: float) -> int:
    return _micros(at(seconds))


# ---------------------------------------------------------------- raw records
def hit(_id, dataset, original, seconds, host="host01", sent=None):
    """A raw record whose shipper timestamp is `sent` seconds (default: the record's own time)."""
    stamp = at(seconds if sent is None else sent).isoformat().replace("+00:00", "Z")
    src = {"@timestamp": stamp, "message": original, "event": {"dataset": dataset, "original": original},
           "host": {"name": host}}
    return {"_id": _id, "_index": "host-logs-x", "_source": src}


def exec_hits(seconds, serial, *, pid=700, ses=5, host="host01", sent=None):
    stamp = f"{EPOCH + seconds:.3f}"
    execve = f'type=EXECVE msg=audit({stamp}:{serial}): argc=1 a0="id"'
    syscall = (f'type=SYSCALL msg=audit({stamp}:{serial}): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 '
               f'a2=3 a3=0 items=1 ppid=1 pid={pid} auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 '
               f'fsgid=0 tty=pts0 ses={ses} comm="id" exe="/usr/bin/id" subj=unconfined key=(null)')
    return [hit(f"x{serial}", "linux.audit", execve, seconds, host, sent),
            hit(f"s{serial}", "linux.audit", syscall, seconds, host, sent)]


def journal(_id, seconds, boot, *, host="host01", ident="CRON", realtime=True, sent=None, **fields):
    record = {"SYSLOG_IDENTIFIER": ident, "_HOSTNAME": host, "_BOOT_ID": boot, "MESSAGE": "(root) CMD (true)",
              **({"__REALTIME_TIMESTAMP": str(us(seconds))} if realtime else {}), **fields}
    return hit(_id, "systemd.journal", json.dumps(record), seconds, host, sent)


def copy_of(_id, seconds, serial, kind, boot, host="host01"):
    """journald's copy of one audit record, received at the record's own time."""
    return journal(_id, seconds, boot, host=host, ident="audit", _TRANSPORT="audit", _AUDIT_ID=str(serial),
                   _SOURCE_REALTIME_TIMESTAMP=str(us(seconds)), _AUDIT_TYPE_NAME=kind)


def system_boot(seconds, serial, host="host01", sent=None):
    raw = (f"type=SYSTEM_BOOT msg=audit({EPOCH + seconds:.3f}:{serial}): pid=1 uid=0 auid=4294967295 ses=4294967295 "
           "msg=' comm=\"systemd-update-utmp\" exe=\"/usr/lib/systemd/systemd-update-utmp\" hostname=? addr=? "
           "terminal=? res=success'")
    return hit(f"b{serial}", "linux.audit", raw, seconds, host, sent)


def aev(family, when, **fields):
    """A typed audit event whose audit header (the host's clock) gives `when`."""
    return ev(family, when, audit__time=when.isoformat(), **fields)


def execs(events):
    return sorted((e for e in events if e.family == "process_exec"), key=lambda e: e.ts)


def boot(event):
    return event.get("host.boot.id")


def two_boots(skew=BOOT_EDGE_SKEW) -> BootIntervals:
    """host01: boot A observed from 0 s to 1000 s, boot B from 1100 s to 2000 s."""
    boots = BootIntervals(skew)
    for seconds, ref in ((0, "a0"), (400, "a1"), (1000, "a2")):
        boots.observe("host01", BOOT_A, us(seconds), ref)
    for seconds, ref in ((1100, "b0"), (2000, "b1")):
        boots.observe("host01", BOOT_B, us(seconds), ref)
    return boots


def placed(boots, seconds, host="host01"):
    found = boots.boot_at(host, us(seconds))
    return None if found is None else found[0]


# ---------------------------------------------------------------- the map itself
def test_a_time_inside_one_boots_span_takes_that_boot_and_cites_its_first_and_last_records():
    event = aev("process_exec", at(500), process__pid=7)
    two_boots().fill([event])
    assert boot(event) == BOOT_A
    assert event.fields["host.boot.id"].origin == f"a0..a2{BOOT_INTERVAL_ORIGIN}"


def test_a_time_in_the_gap_between_boots_stays_unknown():
    boots = two_boots()
    for seconds in (1001, 1050, 1099):
        assert placed(boots, seconds) is None
    event = aev("process_exec", at(1050), process__pid=7)
    boots.fill([event])
    assert not event.has("host.boot.id")
    assert placed(boots, 1500) == BOOT_B


def test_boot_edge_skew_is_inclusive_and_never_crossed():
    boots, step = two_boots(), 0.001
    assert placed(boots, SKEW) == BOOT_A and placed(boots, SKEW - step) is None
    assert placed(boots, 1000 - SKEW) == BOOT_A and placed(boots, 1000 - SKEW + step) is None
    assert placed(boots, 1100 + SKEW) == BOOT_B and placed(boots, 1100 + SKEW - step) is None
    assert placed(boots, 2000 - SKEW) == BOOT_B and placed(boots, 2000 - SKEW + step) is None
    # outside every span (before the first record, after the last): unknown
    assert placed(boots, -500) is None and placed(boots, 2500) is None


def test_a_reboot_shorter_than_the_skew_places_nothing_between_the_two_boots():
    boots = BootIntervals()
    boots.observe("host01", BOOT_A, us(0), "a0")
    boots.observe("host01", BOOT_A, us(1000), "a1")
    boots.observe("host01", BOOT_B, us(1010), "b0")
    boots.observe("host01", BOOT_B, us(2000), "b1")
    assert placed(boots, 975) is None and placed(boots, 1005) is None and placed(boots, 1035) is None
    assert placed(boots, 965) == BOOT_A and placed(boots, 1045) == BOOT_B


def test_overlapping_spans_place_nothing_inside_them():
    # records of two boots at the same times: a clock step at a reboot, or two hosts under one name
    boots = BootIntervals()
    for seconds, boot_id in ((0, BOOT_A), (1000, BOOT_A), (500, BOOT_B), (1500, BOOT_B)):
        boots.observe("host01", boot_id, us(seconds), f"r{seconds}")
    for seconds in (100, 300, 700, 1200, 1400):
        assert placed(boots, seconds) is None, seconds


def test_a_boot_record_that_names_no_boot_is_a_boundary():
    boots = two_boots()
    boots.boundary("host01", us(600), "sb1")
    assert placed(boots, 600 - SKEW) is None and placed(boots, 600 + SKEW) is None
    assert placed(boots, 500) == BOOT_A and placed(boots, 700) == BOOT_A


def test_another_host_and_a_single_record_place_nothing():
    boots = two_boots()
    assert placed(boots, 500, host="host02") is None
    single = BootIntervals()
    single.observe("host01", BOOT_A, us(0), "a0")
    assert placed(single, 0) is None


def test_a_recorded_boot_is_never_changed_and_network_records_are_not_placed():
    recorded = aev("process_exec", at(500), boot=BOOT_B, process__pid=7)
    flow = ev("net_flow", at(500), source__ip="192.0.2.1")
    two_boots().fill([recorded, flow])
    assert boot(recorded) == BOOT_B and recorded.fields["host.boot.id"].origin.endswith(":boot")
    assert not flow.has("host.boot.id")


def test_rederive_places_a_derived_boot_again_with_the_whole_map():
    event = aev("process_exec", at(500), process__pid=7)
    two_boots().fill([event])
    assert boot(event) == BOOT_A
    whole = two_boots()
    whole.observe("host01", BOOT_B, us(450), "late")          # a later observation overlaps boot A's span
    whole.fill([event])                                       # without rederive, a derived boot stands
    assert boot(event) == BOOT_A
    whole.fill([event], rederive=True)
    assert not event.has("host.boot.id")
    BootIntervals().fill([event], rederive=True)              # an empty map (an older hunt) changes nothing
    assert not event.has("host.boot.id")


def test_the_map_round_trips_through_json_exactly():
    boots = two_boots()
    boots.observe("host01", BOOT_A, us(0.000001), "a-micro", marker=True)
    boots.boundary("host02", us(10), "sb")
    data = json.loads(json.dumps(boots.to_json()))
    again = BootIntervals.from_json(data)
    assert again.to_json() == boots.to_json()
    assert again.skew_us == boots.skew_us
    for seconds in (0, 15, 30, 500, 999, 1050, 1130, 1970, 1971):
        assert placed(again, seconds) == placed(boots, seconds)
    assert data["hosts"]["host01"]["boots"][0]["marker_ref"] == "a-micro"
    assert data["hosts"]["host02"] == {"boots": [], "boundaries": [{"at": at(10).isoformat(), "ref": "sb"}]}
    assert not BootIntervals.from_json({}) and BootIntervals.from_json({}).to_json()["hosts"] == {}


# ---------------------------------------------------------------- the normalizer with a map
def test_an_exec_whose_copy_is_in_another_batch_takes_the_boot_of_the_journald_records_around_it():
    batch = [journal("j0", 0, BOOT_A), *exec_hits(300, 4321), journal("j1", 600, BOOT_A)]
    blind, _skips, errors = normalize_hits(batch)
    assert errors == [] and not execs(blind)[0].has("host.boot.id")
    boots = BootIntervals()
    events, _skips, errors = normalize_hits(batch, boots)
    assert errors == []
    assert boot(execs(events)[0]) == BOOT_A
    assert execs(events)[0].fields["host.boot.id"].origin == f"j0..j1{BOOT_INTERVAL_ORIGIN}"
    assert [e.id for e in events] == [e.id for e in blind]                # the same records, the same ids


def test_the_map_grows_across_batches_and_audit_copies_are_observations():
    boots = BootIntervals()
    first, _s, _e = normalize_hits([copy_of("c0", 0, 1, "SYSCALL", BOOT_A), *exec_hits(100, 4321)], boots)
    assert not execs(first)[0].has("host.boot.id")                       # one observation: no span to be inside
    second, _s, _e = normalize_hits([*exec_hits(200, 4400), copy_of("c1", 400, 2, "PATH", BOOT_A)], boots)
    assert boot(execs(second)[0]) == BOOT_A
    span = boots.to_json()["hosts"]["host01"]["boots"]
    # each copy states one time (receive time, audit time and shipper timestamp agree): one observation each
    assert [(b["boot"], b["first_ref"], b["last_ref"], b["observations"]) for b in span] == [(BOOT_A, "c0", "c1", 2)]


def test_a_record_shipped_late_after_a_reboot_stays_at_its_host_clock_time():
    # boot A's last record was received at 500 s but stamped by the shipper at 1500 s, inside boot B's records:
    # spans are built from the host's own clock, so boot A still ends at 500 s and nothing overlaps
    boots = BootIntervals()
    normalize_hits([journal("j0", 0, BOOT_A), journal("late", 500, BOOT_A, sent=1500), journal("j1", 1100, BOOT_B),
                    journal("j2", 2000, BOOT_B)], boots)
    entry = boots.to_json()["hosts"]["host01"]
    assert [(b["boot"], b["last"], b["observations"]) for b in entry["boots"]] == [
        (BOOT_A, at(500).isoformat(), 2), (BOOT_B, at(2000).isoformat(), 2)]
    assert "blind" not in entry
    assert [placed(boots, seconds) for seconds in (300, 800, 1200, 1700)] == [BOOT_A, None, BOOT_B, BOOT_B]


def test_an_exec_is_placed_by_its_audit_header_time_not_the_shipper_timestamp():
    # the exec happened at 300 s by the host's clock; the shipper stamped it at 1500 s, inside boot B
    batch = [journal("j0", 0, BOOT_A), journal("j1", 1000, BOOT_A), journal("j2", 1100, BOOT_B),
             journal("j3", 2000, BOOT_B), *exec_hits(300, 4321, sent=1500)]
    boots = BootIntervals()
    event = execs(normalize_hits(batch, boots)[0])[0]
    assert event.ts == at(1500)                                         # the event's own time is unchanged
    assert event.get("audit.time") == at(300).isoformat()
    assert event.fields["audit.time"].origin == "x4321:event.original#auditd:msg.timestamp"
    assert boot(event) == BOOT_A


def test_every_audit_event_carries_its_header_time():
    batch = [*exec_hits(300, 4321, sent=900), system_boot(400, 77, sent=900)]
    events, _s, errors = normalize_hits(batch)
    assert errors == []
    assert {(e.family, e.get("audit.time")) for e in events} == {("process_exec", at(300).isoformat()),
                                                                 ("system_state", at(400).isoformat())}


def test_an_event_without_a_host_clock_time_is_never_placed():
    # a typed event that does not carry its host's clock (no audit header time) is not placed by its shipper time
    boots = two_boots()
    event = ev("process_exec", at(500), process__pid=7)
    assert boots.fill([event]) == {"no host-clock time": 1}
    assert not event.has("host.boot.id")


def test_a_late_record_in_a_later_partition_changes_no_earlier_placement_and_no_overlap():
    # The sweep reads partitions in shipper-time order. Partition 2 holds boot A's last record, written at 590 s
    # by the host's clock but stamped with its send time (1500 s), after the reboot into boot B.
    boots = BootIntervals()
    first = execs(normalize_hits([journal("j0", 0, BOOT_A), *exec_hits(300, 4321), journal("j1", 600, BOOT_A)],
                                 boots)[0])
    assert boot(first[0]) == BOOT_A
    second = execs(normalize_hits([journal("late", 590, BOOT_A, sent=1500), journal("j2", 1100, BOOT_B),
                                   *exec_hits(1500, 4400), journal("j3", 2000, BOOT_B)], boots)[0])
    assert boot(second[0]) == BOOT_B
    entry = boots.to_json()["hosts"]["host01"]
    assert "blind" not in entry and "sweep_conflicts" not in entry
    # the whole map places the earlier exec exactly as the sweep did
    again = first[0].model_copy(update={"fields": dict(first[0].fields)})
    BootIntervals.from_json(boots.to_json()).fill([again], rederive=True)
    assert boot(again) == BOOT_A and again.fields["host.boot.id"] == first[0].fields["host.boot.id"]


def _late_contradiction(late):
    """Partition 1 places an exec at 300 s in boot A; partition 2 brings `late` records (host-clock time near
    300 s, shipped after the reboot) and an exec at 1500 s inside boot B."""
    boots = BootIntervals()
    first = execs(normalize_hits([journal("j0", 0, BOOT_A), *exec_hits(300, 4321), journal("j1", 600, BOOT_A)],
                                 boots)[0])
    assert boot(first[0]) == BOOT_A
    second = execs(normalize_hits([*late, journal("j2", 1100, BOOT_B), *exec_hits(1500, 4400),
                                   journal("j3", 2000, BOOT_B)], boots)[0])
    return boots, first[0], second[0]


@pytest.mark.parametrize("late", [
    [system_boot(310, 90, sent=1400)],                                 # a boot record naming no boot, sent late
    [journal("c0", 290, "c" * 32, sent=1400), journal("c1", 320, "c" * 32, sent=1400)],   # another boot, same times
], ids=["nameless-boundary", "another-boot"])
def test_a_late_record_that_contradicts_a_sweep_placement_stops_sweep_placement_on_that_host(late):
    boots, earlier, later = _late_contradiction(late)
    # the whole map refuses the earlier placement; the sweep records that, and places nothing more on the host
    assert boots.boot_at("host01", us(300)) is None
    assert boots.to_json()["hosts"]["host01"]["sweep_conflicts"] == [
        {"boot": BOOT_A, "from": at(300).isoformat(), "to": at(300).isoformat()}]
    assert not later.has("host.boot.id")
    # the later exec, and the late boot record itself (a system_state event) when there is one
    assert boots.unplaced["sweep placement stopped on this host"] == 1 + sum(h["_id"].startswith("b") for h in late)
    # expansion and the context pass use the whole map, which still places the later exec in boot B
    whole = BootIntervals.from_json(boots.to_json())
    again = later.model_copy(update={"fields": dict(later.fields)})
    whole.fill([again], rederive=True)
    assert boot(again) == BOOT_B
    stored = earlier.model_copy(update={"fields": dict(earlier.fields)})
    whole.fill([stored], rederive=True)
    assert not stored.has("host.boot.id")


def test_a_copy_in_the_batch_still_wins_over_the_map():
    boots = two_boots()
    events, _s, _e = normalize_hits([*exec_hits(500, 4321), copy_of("c9", 500, 4321, "SYSCALL", BOOT_B)], boots)
    event = execs(events)[0]
    assert boot(event) == BOOT_B and event.fields["host.boot.id"].origin == "c9:event.original#journal:_BOOT_ID"


def test_journald_records_without_a_host_clock_time_are_counted_not_spanned_and_malformed_boots_are_ignored():
    boots = BootIntervals()
    normalize_hits([journal("j0", 0, BOOT_A, realtime=False), journal("j1", 600, BOOT_A, realtime=False),
                    journal("j2", 300, BOOT_A, realtime=False, _SOURCE_REALTIME_TIMESTAMP=str(us(250))),
                    journal("bad", 300, "not-a-boot-id"), journal("nohost", 300, BOOT_B, host=None)], boots)
    spans = boots.to_json()["hosts"]
    assert list(spans) == ["host01"]
    # the shipper's timestamp never makes a span; journald's source time (any transport) does
    assert [(b["boot"], b["first"], b["last"]) for b in spans["host01"]["boots"]] == [
        (BOOT_A, at(250).isoformat(), at(250).isoformat())]
    assert spans["host01"]["unclocked_records"] == 2


def test_typed_boot_records_mark_a_boot_or_bound_it():
    banner = journal("k0", 0, BOOT_A, ident="kernel", _TRANSPORT="kernel", SYSLOG_FACILITY="0",
                     MESSAGE="Linux version 6.8.0-49-generic (buildd@lcy02) #49-Ubuntu SMP")
    forged = journal("k1", 1, BOOT_A, ident="kernel", _TRANSPORT="kernel", SYSLOG_FACILITY="1",
                     MESSAGE="Linux version 1.0 (written to /dev/kmsg from user space)")
    boots = BootIntervals()
    normalize_hits([banner, forged, journal("j1", 900, BOOT_A), system_boot(400, 77, host="host02")], boots)
    data = boots.to_json()["hosts"]
    assert data["host01"]["boots"][0]["marker_ref"] == "k0"
    assert data["host02"] == {"boots": [], "boundaries": [{"at": at(400).isoformat(), "ref": "b77"}]}
    # a SYSTEM_BOOT joined to its journald copy names its boot: an observation and the boot's marker
    named = BootIntervals()
    events, _s, _e = normalize_hits([system_boot(400, 78), copy_of("c78", 400, 78, "SYSTEM_BOOT", BOOT_B)], named)
    assert boot(next(e for e in events if e.family == "system_state")) == BOOT_B
    entry = named.to_json()["hosts"]["host01"]
    assert entry["boundaries"] == [] and {b["marker_ref"] for b in entry["boots"]} == {"b78"}


def test_the_map_and_its_placements_do_not_depend_on_record_order():
    hits = [journal("j0", 0, BOOT_A), *exec_hits(300, 4321), journal("j1", 600, BOOT_A),
            *exec_hits(650, 4322, pid=701), journal("j2", 700, BOOT_B), *exec_hits(900, 4323, pid=702),
            journal("j3", 1200, BOOT_B), copy_of("c1", 1000, 9, "PATH", BOOT_B)]
    expected = None
    rng = random.Random(11)
    for _ in range(6):
        rng.shuffle(hits)
        boots = BootIntervals()
        events, _s, _e = normalize_hits(list(hits), boots)
        got = (json.dumps(boots.to_json(), sort_keys=True),
               sorted((e.id, boot(e), e.fields["host.boot.id"].origin if e.has("host.boot.id") else None)
                      for e in execs(events)))
        assert expected is None or got == expected
        expected = got
    # 300 s is inside boot A's span, 650 s in the gap before boot B, 900 s inside boot B's span
    assert sorted(str(b) for _id, b, _origin in expected[1]) == sorted(str(b) for b in (BOOT_A, None, BOOT_B))


# ---------------------------------------------------------------- single boot: the same findings as boot-blind
def _placed_copy(events, boots):
    """Copies of the records as audit events (their header time is their time), placed by the map."""
    out = [event.model_copy(update={"fields": {**event.fields, "audit.time": fv(event.ts.isoformat(), "fx:time")}})
           for event in events]
    boots.fill(out)
    return out


def test_single_boot_findings_with_placed_boots_equal_boot_blind_findings():
    one = BootIntervals()
    one.observe("host01", BOOT_A, _micros(T0 - timedelta(hours=1)), "first")
    one.observe("host01", BOOT_A, _micros(T0 + timedelta(hours=5)), "last")
    shells = _shell_events(None) + [exc("/bin/bash", 502, T0 + timedelta(seconds=40), ppid=500, argv=["bash", "-i"])]
    writer = hx(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=0, ses=4, pid=900, ppid=899)
    jobs = [writer, hx(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(hours=2), auid=0, ses=4, pid=950,
                       ppid=949),
            ev("auth", T0 + timedelta(minutes=1), auth__service="cron", auth__phase="session_open",
               process__session_id=12, process__pid=5000, user__name="root", process__auid="0")]
    changes = [exc("/usr/bin/dpkg", 6, T0, ppid=1, process__uid="0"),
               change("/etc/cron.d/x", T0 + timedelta(seconds=5)), change("/etc/cron.d/y", T0, pid=70, ppid=69)]
    for factory, events in ((ReverseShellByLineage, shells), (NonRootWriteRootExecutedFile, jobs),
                            (PersistencePathChange, changes)):
        filled = _placed_copy(events, one)
        assert all(boot(e) == BOOT_A for e in filled if e.family != "net_flow")
        assert _projection(run(factory(), filled)) == _projection(run(factory(), events)) != []


def test_single_boot_full_pack_over_raw_records_equals_boot_blind():
    hits = [journal("j0", 0, BOOT_A)]
    for i in range(12):
        hits += exec_hits(60 + 30 * i, 5000 + i, pid=800 + i, ses=3)
    hits.append(journal("j1", 600, BOOT_A))

    def findings(boots):
        events, _s, _e = normalize_hits(list(hits), boots)
        out = []
        for playbook in fresh_pack():
            out += playbook.consume(events)
            if playbook.kind == "aggregate" and not playbook.staged:
                out += playbook.finalize()
        return _projection(out), events

    blind, _events = findings(None)
    placed_findings, events = findings(BootIntervals())
    assert sum(boot(e) == BOOT_A for e in execs(events)) == 12
    assert placed_findings == blind


# ---------------------------------------------------------------- link fetches
def _session_record(event_id, seconds, boot_id=None):
    when = CTX_T0 + timedelta(seconds=seconds)
    fields = {"process.pid": fv(100 + int(seconds), f"{event_id}:pid"), "process.session_id": fv(42, "x:ses"),
              "audit.time": fv(when.isoformat(), f"{event_id}:time"),
              "process.auid": fv("1000", "x:auid"), "process.executable": fv("/usr/bin/id", "x:exe")}
    if boot_id:
        fields["host.boot.id"] = fv(boot_id, f"{event_id}:boot")
    return TypedEvent(id=event_id, family="process_exec", ts=CTX_T0 + timedelta(seconds=seconds), host="web1",
                      outcome=Outcome.success, fields=fields,
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def _web1_boots() -> BootIntervals:
    """web1: boot A observed until 60 s after the anchor, boot B from 120 s after it."""
    boots = BootIntervals()
    for seconds, boot_id, ref in ((-600, BOOT_A, "a0"), (60, BOOT_A, "a1"), (120, BOOT_B, "b0"),
                                  (1200, BOOT_B, "b1")):
        boots.observe("web1", boot_id, _micros(CTX_T0 + timedelta(seconds=seconds)), ref)
    return boots


def _session_fetch(boots):
    root = _session_record("root", 0, BOOT_A)
    fetched = [_session_record("same-boot", 20), _session_record("gap", 90), _session_record("next-boot", 300)]
    window = LinkWindow(label="anchor ±10 min", start=CTX_T0 - timedelta(minutes=10),
                        end=CTX_T0 + timedelta(minutes=10))
    anchor = LinkAnchor(finding_id="F-x", ts=root.ts, host="web1", event_ids=[root.id], events=[root])
    result = LinkFetcher(FakePivot([root, *fetched]), window.start, window.end, boots=boots).fetch(
        anchor, "login_session", window)
    return result, {event.id: event for event in fetched}


def test_a_session_id_reused_after_a_reboot_inside_one_link_window_is_another_session():
    result, fetched = _session_fetch(_web1_boots())
    # the record after the reboot is placed in boot B and refused; the one in the gap stays unknown and is kept
    assert result.event_ids == ["same-boot", "gap"]
    assert boot(fetched["same-boot"]) == BOOT_A and boot(fetched["next-boot"]) == BOOT_B
    assert not fetched["gap"].has("host.boot.id")
    blind, _fetched = _session_fetch(None)
    assert blind.event_ids == ["same-boot", "gap", "next-boot"]


# ---------------------------------------------------------------- the context pass and resume
def _repo():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo, engine


def _discovery(event_id, exe, argv, seconds):
    return TypedEvent(id=event_id, family="process_exec", ts=CTX_T0 + timedelta(seconds=seconds), host="web1",
                      outcome=Outcome.success,
                      fields={"process.executable": fv(exe, f"{event_id}:exe"),
                              "process.argv": fv(argv, f"{event_id}:argv"),
                              "process.session_id": fv(42, f"{event_id}:ses"),
                              "audit.time": fv((CTX_T0 + timedelta(seconds=seconds)).isoformat(), f"{event_id}:t")},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def _context_lanes(boots):
    repo, _engine = _repo()
    if boots is not None:
        repo.audit("system", sw.BOOT_INTERVALS_AUDIT, "h1", boots.to_json())
    shell = _discovery("anchor-event", "/bin/sh", ["/bin/sh"], 0)
    shell.fields["host.boot.id"] = fv(BOOT_A, "anchor:boot")
    _seed_anchor(repo, "h1", "F-anchor", "host.web_shell", [shell])
    _seed_link(repo, "h1", "L-observed", "F-anchor",
               [_discovery("whoami", "/usr/bin/whoami", ["whoami"], 10),
                _discovery("uname", "/usr/bin/uname", ["uname", "-a"], 180),
                _discovery("ss", "/usr/bin/ss", ["ss", "-tunap"], 240)], link_type="login_session")
    finalize_context(repo, "h1")
    return sorted((c["lane"], tuple(sorted(c["event_ids"]))) for c in repo.candidates("h1")
                  if c["rule_id"] == "context.post_access_discovery" and c["lane"] != "context")


def test_context_sessions_split_at_a_reboot_the_map_places_records_across():
    blind = _context_lanes(None)
    assert [lane for lane, _ids in blind] == ["high"]                   # boot-blind: one session of three classes
    # the records after the reboot (placed in boot B) are another session than the one in boot A
    assert _context_lanes(_web1_boots()) == [("lead", ("anchor-event", "ss", "uname")),
                                             ("lead", ("anchor-event", "whoami"))]


def test_context_results_are_unchanged_when_every_record_is_in_one_boot():
    one = BootIntervals()
    one.observe("web1", BOOT_A, _micros(CTX_T0 - timedelta(hours=1)), "a0")
    one.observe("web1", BOOT_A, _micros(CTX_T0 + timedelta(hours=1)), "a1")
    assert _context_lanes(one) == _context_lanes(None)


def _complete(intent, records):
    now = datetime.now(UTC)
    return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                         completeness=Completeness.complete, total=len(records), total_relation="eq",
                         returned=len(records), records=records)


class _Client:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def test_the_sweep_records_the_map_and_a_resumed_hunt_reads_the_same_one(monkeypatch):
    batches = {
        at(0): [journal("j0", 0, BOOT_A), *exec_hits(100, 4321), *exec_hits(590, 4322, pid=701),
                journal("j1", 500, BOOT_A)],
        at(600): [*exec_hits(700, 4323, pid=702), journal("j2", 650, BOOT_A), journal("j3", 1100, BOOT_A)],
    }
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent,
                                                                                    batches[intent.window.start]))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["host-logs-x"]}, "d", "t")
    window = Window(start=at(0), end=at(1200))
    sweep = sw.Sweep(repo, _Client(), "h1", window, {"host-logs-x": None})
    sweep.run_partition("host-logs-x", None, [], Window(start=at(0), end=at(600)), est=10)
    sweep.run_partition("host-logs-x", None, [], Window(start=at(600), end=at(1200)), est=10)
    sweep.finalize()
    # the exec 10 s before its batch's last journald record waits for the whole map
    assert sweep.stats["boot"] == {"recorded": 0, "from_interval": 2, "unknown": 1,
                                   "unknown_reasons": {"not well inside exactly one boot": 1},
                                   "sweep_conflicts": [], "sweep_conflicts_total": 0}
    assert not [r for r in sweep.partial_reasons if r.startswith("boot placement:")]
    recorded = sweep.boots.to_json()
    assert recorded["hosts"]["host01"]["boots"][0]["last_ref"] == "j3"

    resumed = Repo(engine)                                       # a resumed run: a new process, the same store
    assert sw.stored_boot_intervals(resumed, "h1").to_json() == recorded
    fetcher = LinkFetcher(FakePivot([]), window.start, window.end)
    expansion = ExpansionEngine(resumed, "h1", window, fetcher)
    assert fetcher.boots is expansion.boots and expansion.boots.to_json() == recorded
    tail = TypedEvent.model_validate(normalize_hits(exec_hits(590, 4322, pid=701))[0][0].model_dump(mode="json"))
    resumed.save_evidence("h1", [tail], {}, None)
    assert boot(expansion._events([tail.id])[0]) == BOOT_A
    assert sw.stored_boot_intervals(resumed, "other-hunt").to_json()["hosts"] == {}


# ---------------------------------------------------------------- scale: per-host indexes, not scans
def test_ten_thousand_boundaries_on_one_host_place_by_bisect():
    # SYSTEM_BOOT/SYSTEM_SHUTDOWN records that name no boot can come from any process allowed to write audit
    # records, so one host can carry thousands of them. Boot A runs 0 s to 1,000,000 s with a nameless boundary
    # every 100 s at 50 s past each hundred; a time places only when it is more than the skew from every boundary.
    boots = BootIntervals()
    boots.observe("host01", BOOT_A, us(0), "a0")
    boots.observe("host01", BOOT_A, us(1_000_000), "a1")
    for k in range(10_000):
        boots.boundary("host01", us(100 * k + 50), f"sb{k}")
    for host in range(200):                                    # other hosts, each with a few boots
        for n in range(5):
            boots.observe(f"h{host}", f"{host:016x}{n:016x}", us(1000 * n), f"o{host}-{n}a")
            boots.observe(f"h{host}", f"{host:016x}{n:016x}", us(1000 * n + 900), f"o{host}-{n}b")
    times = [100 * k + offset for k in range(0, 10_000, 2) for offset in (0, 15, 19.5, 50, 80.5, 99)]
    events = [aev("process_exec", at(seconds), process__pid=7) for seconds in times]
    started = time.perf_counter()
    boots.fill(events)
    elapsed = time.perf_counter() - started
    for seconds, event in zip(times, events, strict=True):
        offset = seconds % 100
        expected = BOOT_A if SKEW <= seconds <= 1_000_000 - SKEW and abs(offset - 50) > SKEW else None
        assert boot(event) == expected, seconds
    assert placed(boots, 1500, host="h7") == "0000000000000007" + "0000000000000001"
    assert elapsed < 5.0, elapsed                              # a scan of every boundary per event takes minutes


def _reference(boots, host, when):
    """The placement rule stated directly, one scan per time: inside exactly one merged interval of a single boot
    by the skew, more than the skew from every other interval and every boundary."""
    skew = boots.skew_us
    near = [item for item in boots._intervals(host) if item[0] - skew <= when <= item[1] + skew]
    if len(near) != 1 or len(near[0][2]) != 1 or not near[0][0] + skew <= when <= near[0][1] - skew:
        return None
    if any(abs(when - at) <= skew for at, _ref in boots.boundaries.get(host, ())):
        return None
    return near[0][2][0]


def test_the_bisect_index_agrees_with_the_rule_stated_directly():
    rng = random.Random(5)
    for trial in range(40):
        boots = BootIntervals(timedelta(seconds=rng.choice((0, 1, 30))))
        for n in range(rng.randint(1, 8)):
            start = rng.randint(0, 5000)
            for _ in range(rng.randint(1, 3)):
                boots.observe("host01", f"{n:032x}", us(start + rng.randint(0, 800)), f"r{trial}-{n}")
        for k in range(rng.randint(0, 6)):
            boots.boundary("host01", us(rng.randint(0, 6000)), f"sb{k}")
        edges = [point for span in boots.spans["host01"].values() for point in (span.first[0], span.last[0])]
        edges += [at for at, _ref in boots.boundaries.get("host01", ())]
        probes = [us(seconds) for seconds in [rng.uniform(-100, 6100) for _ in range(300)] + list(range(-50, 6050, 7))]
        probes += [edge + sign * boots.skew_us + nudge for edge in edges for sign in (-1, 1) for nudge in (-1, 0, 1)]
        for when in probes:
            found = boots.boot_at("host01", when)
            assert (None if found is None else found[0]) == _reference(boots, "host01", when), (trial, when)


def test_a_contradicted_sweep_placement_is_reported_with_the_sweep(monkeypatch):
    batches = {
        at(0): [journal("j0", 0, BOOT_A), *exec_hits(300, 4321), journal("j1", 600, BOOT_A)],
        at(1200): [system_boot(310, 90, sent=1400), journal("j2", 1100, BOOT_B), *exec_hits(1500, 4400),
                   journal("j3", 2000, BOOT_B)],
    }
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent,
                                                                                    batches[intent.window.start]))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["host-logs-x"]}, "d", "t")
    sweep = sw.Sweep(repo, _Client(), "h1", Window(start=at(0), end=at(2400)), {"host-logs-x": None})
    sweep.run_partition("host-logs-x", None, [], Window(start=at(0), end=at(1200)), est=10)
    sweep.run_partition("host-logs-x", None, [], Window(start=at(1200), end=at(2400)), est=10)
    sweep.finalize()
    assert sweep.stats["boot"]["sweep_conflicts"] == [
        {"host": "host01", "boot": BOOT_A, "from": at(300).isoformat(), "to": at(300).isoformat()}]
    assert sweep.stats["boot"]["unknown_reasons"]["sweep placement stopped on this host"] == 2
    assert [r for r in sweep.partial_reasons if r.startswith("boot placement:")] == [
        ("boot placement: 1 range on 1 host placed during the sweep was contradicted by records read later "
         "(host01); a boot-keyed join there may have been refused (see the hunt's boot-interval map)")]
    recorded = sw.stored_boot_intervals(repo, "h1").to_json()
    assert recorded["hosts"]["host01"]["sweep_conflicts"] == [
        {"boot": BOOT_A, "from": at(300).isoformat(), "to": at(300).isoformat()}]


@pytest.mark.parametrize("seconds,expected", [(300, BOOT_A), (1050, None), (1500, BOOT_B)])
def test_audit_events_of_every_host_family_are_placed(seconds, expected):
    boots = two_boots()
    events = [aev(family, at(seconds), process__pid=7) for family in
              ("process_exec", "net_socket", "file_change", "auth", "account_change", "service_change",
               "audit_config", "system_state")]
    boots.fill(events)
    assert {boot(e) for e in events} == {expected}
