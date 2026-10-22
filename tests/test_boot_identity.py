"""Boot identity: where an audit event's boot id comes from, and how pid and session joins use it.

Process ids and audit session ids restart at every boot, so a join across a reboot is false. A record's boot id is
the shipper's own field, or journald's copy of one of its audit records in the same batch. A record without one
stays unknown and joins as it did before boot identity existed; two recorded boots that differ never join. Hosts,
boot ids, accounts and addresses are invented (documentation ranges).
"""
import json
import random
from datetime import UTC, datetime, timedelta

from romulus.detect.base import ContextAnchor
from romulus.detect.context import _session_boots, _session_key
from romulus.detect.correlation import (
    InterpreterExternalConnection,
    PidTable,
    boots_conflict,
    merge_unknown_boot,
)
from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.kernel_files import PersistencePathChange
from romulus.detect.lineage import ReverseShellByLineage
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from tests.test_expansion_links import FakePivot

BOOT_A = "0a" * 16
BOOT_B = "0b" * 16
T0 = datetime(2030, 2, 1, 8, 0, tzinfo=UTC)
EXT = "203.0.113.7"


# ---------------------------------------------------------------- raw record builders (normalizer)
def raw_hit(_id, dataset, original, host="host01", **extra):
    src = {"@timestamp": "2030-03-17T17:46:40.250Z", "message": original,
           "event": {"dataset": dataset, "original": original}, "host": {"name": host}, **extra}
    return {"_id": _id, "_index": "host-logs-x", "_source": src}


def exec_records(ts="1900000000.250", serial=4321, pid=700, ses=5):
    execve = f'type=EXECVE msg=audit({ts}:{serial}): argc=1 a0="id"'
    syscall = (f'type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 '
               f'a2=3 a3=0 items=1 ppid=1 pid={pid} auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 '
               f'fsgid=0 tty=pts0 ses={ses} comm="id" exe="/usr/bin/id" subj=unconfined key=(null)')
    return [raw_hit(f"x{serial}", "linux.audit", execve), raw_hit(f"s{serial}", "linux.audit", syscall)]


def journal_copy(_id, *, serial=4321, micros="1900000000250000", kind="SYSCALL", boot=BOOT_A, host="host01",
                 **overrides):
    record = {"_TRANSPORT": "audit", "SYSLOG_IDENTIFIER": "audit", "_AUDIT_ID": str(serial),
              "_SOURCE_REALTIME_TIMESTAMP": micros, "_AUDIT_TYPE_NAME": kind, "_BOOT_ID": boot,
              "_HOSTNAME": host, "MESSAGE": f"{kind} ..."}
    record.update(overrides)
    record = {k: v for k, v in record.items() if v is not None}
    return raw_hit(_id, "systemd.journal", json.dumps(record), host=host)


def only(events, family="process_exec"):
    found = [e for e in events if e.family == family]
    assert len(found) == 1, found
    return found[0]


# ---------------------------------------------------------------- normalizer: the journald join
def test_journald_copy_in_the_batch_supplies_the_boot_id():
    events, skips, errors = normalize_hits([*exec_records(), journal_copy("j1")])
    assert errors == []
    event = only(events)
    assert event.get("host.boot.id") == BOOT_A
    assert event.fields["host.boot.id"].origin == "j1:event.original#journal:_BOOT_ID"
    assert skips == {"journal copy of an audit record (normalized from linux.audit)": 1}
    # the partner is not one of the event's records: the same exec keeps one id with or without it
    alone, _skips, _errors = normalize_hits(exec_records())
    assert only(alone).id == event.id and {r.native_id for r in event.raw} == {"x4321", "s4321"}


def test_missing_journal_partner_leaves_the_boot_unknown():
    events, _skips, errors = normalize_hits(exec_records())
    assert errors == [] and not only(events).has("host.boot.id")


def test_partner_must_match_host_time_serial_and_a_record_type():
    for copy in (journal_copy("j1", serial=4322),                               # another event's serial
                 journal_copy("j1", micros="1900000000251000"),                 # another millisecond
                 journal_copy("j1", host="host02"),                             # another host
                 journal_copy("j1", kind="PATH")):                              # a record the group does not hold
        events, _skips, errors = normalize_hits([*exec_records(), copy])
        assert errors == [] and not only(events).has("host.boot.id"), copy


def test_copies_naming_two_boots_leave_the_boot_unknown():
    events, _skips, _errors = normalize_hits([*exec_records(), journal_copy("j1"),
                                              journal_copy("j2", kind="EXECVE", boot=BOOT_B)])
    assert not only(events).has("host.boot.id")


def test_malformed_journald_fields_never_join():
    for copy in (journal_copy("j1", boot="not-a-boot-id"), journal_copy("j1", _BOOT_ID=None),
                 journal_copy("j1", _AUDIT_ID=None), journal_copy("j1", micros="1900000000250123"),
                 journal_copy("j1", _SOURCE_REALTIME_TIMESTAMP=None), journal_copy("j1", _AUDIT_TYPE_NAME=None)):
        events, skips, errors = normalize_hits([*exec_records(), copy])
        assert errors == [] and not only(events).has("host.boot.id")
        assert sum(skips.values()) == 1                                          # still counted as a duplicate


def test_join_at_a_second_boundary_is_exact_to_the_millisecond():
    records = exec_records(ts="1900000000.999")
    joined, _s, _e = normalize_hits([*records, journal_copy("j1", micros="1900000000999000")])
    assert only(joined).get("host.boot.id") == BOOT_A
    missed, _s, _e = normalize_hits([*records, journal_copy("j1", micros="1900000001000000")])
    assert not only(missed).has("host.boot.id")


def test_shipper_boot_field_takes_precedence():
    records = [{**h, "_source": {**h["_source"], "system": {"boot": {"id": "shipper-boot"}}}}
               for h in exec_records()]
    events, _skips, _errors = normalize_hits([*records, journal_copy("j1")])
    assert only(events).get("host.boot.id") == "shipper-boot"


def test_login_records_take_the_boot_of_their_copy():
    raw = ('type=USER_START msg=audit(1900000000.400:4400): pid=900 uid=0 auid=1000 ses=9 '
           'msg=\'op=PAM:session_open acct="alice" exe="/usr/sbin/sshd" addr=192.0.2.10 terminal=ssh res=success\'')
    events, _skips, errors = normalize_hits([raw_hit("u1", "linux.audit", raw),
                                             journal_copy("j1", serial=4400, micros="1900000000400000",
                                                          kind="USER_START", boot=BOOT_B)])
    assert errors == [] and only(events, "auth").get("host.boot.id") == BOOT_B


def test_journal_native_record_carries_its_own_boot_id():
    line = json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "host01", "_BOOT_ID": BOOT_A,
                       "MESSAGE": "Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x"})
    events, _skips, _errors = normalize_hits([raw_hit("a1", "systemd.journal", line)])
    assert only(events, "auth").get("host.boot.id") == BOOT_A
    bad = json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_BOOT_ID": "x" * 32,
                      "MESSAGE": "Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x"})
    events, _skips, _errors = normalize_hits([raw_hit("a2", "systemd.journal", bad)])
    assert not only(events, "auth").has("host.boot.id")


def test_boot_join_is_deterministic_under_input_order():
    hits = [*exec_records(), journal_copy("j1"), journal_copy("j2", kind="EXECVE"),
            *exec_records(ts="1900000005.000", serial=4500, pid=701), journal_copy("j3", serial=4500,
                                                                                  micros="1900000005000000")]
    expected = None
    rng = random.Random(7)
    for _ in range(6):
        rng.shuffle(hits)
        events, _skips, _errors = normalize_hits(list(hits))
        boots = sorted((e.id, e.get("host.boot.id"), e.fields["host.boot.id"].origin) for e in events)
        assert expected is None or boots == expected
        expected = boots
    assert {origin for _id, _boot, origin in expected} == {"j1:event.original#journal:_BOOT_ID",
                                                           "j3:event.original#journal:_BOOT_ID"}


# ---------------------------------------------------------------- typed fixtures (detectors)
_n = 0


def ev(family, ts, *, host="host01", boot=None, outcome=Outcome.success, **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fx{_n}:{k}") for k, v in fields.items() if v is not None}
    if boot is not None:
        f["host.boot.id"] = fv(boot, f"fx{_n}:boot")
    return TypedEvent(id=f"b{_n:05d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def exc(exe, pid, ts, *, ppid=None, argv=None, boot=None, **kw):
    return ev("process_exec", ts, boot=boot, process__executable=exe, process__pid=pid, process__ppid=ppid,
              process__argv=argv or [exe], **kw)


def run(playbook, *partitions):
    store = {}
    for part in partitions:
        assert playbook.consume(list(part)) == []
        for event in playbook.drain_staged() if playbook.staged else []:
            store[event.id] = event
    if playbook.staged:
        playbook.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    return playbook.finalize()


def test_boots_conflict_only_when_both_are_recorded_and_differ():
    assert boots_conflict(BOOT_A, BOOT_B)
    assert not boots_conflict(BOOT_A, BOOT_A)
    assert not boots_conflict(None, BOOT_B) and not boots_conflict(BOOT_A, None) and not boots_conflict(None, None)


# ---------------------------------------------------------------- PidTable: pid reuse across a reboot
def test_pid_reused_after_a_reboot_is_no_lineage_join():
    table = PidTable()
    table.add(exc("/usr/sbin/apache2", 500, T0, ppid=1, boot=BOOT_A))
    later = (T0 + timedelta(hours=1)).timestamp()
    assert table.lookup("host01", 500, later, BOOT_B) is None
    assert table.lookup("host01", 500, later, BOOT_A)[1] == "/usr/sbin/apache2"
    assert table.lookup("host01", 500, later)[1] == "/usr/sbin/apache2"         # unknown boot: boot-blind
    assert table.ancestry("host01", 500, later, BOOT_B) == ("unknown", [])
    assert table.ancestry("host01", 500, later, BOOT_A)[0] == "web_server"
    assert table.exec_before("host01", 500, later, BOOT_B) is None


def test_lineage_walk_carries_an_ancestors_boot_up_the_chain():
    table = PidTable()
    table.add(exc("/usr/sbin/apache2", 100, T0, ppid=1, boot=BOOT_A))               # an earlier boot
    table.add(exc("/usr/bin/bash", 200, T0 + timedelta(hours=1), ppid=100, boot=BOOT_B))
    # a child with no recorded boot reaches bash (boot B), whose parent pid 100 has no exec in boot B
    entries = table.lineage_entries("host01", 200, (T0 + timedelta(hours=2)).timestamp())
    assert [pid for pid, *_rest in entries] == [200]


def test_service_manager_ancestry_in_another_boot_never_lowers_a_web_lane():
    def connect(boot):
        return ev("net_socket", T0 + timedelta(hours=1), boot=boot, socket__syscall="connect",
                  process__executable="/usr/bin/python3", process__user="www-data", process__pid=301,
                  process__ppid=300, destination__ip=EXT, destination__port=443)
    manager = exc("/usr/lib/systemd/systemd", 300, T0, ppid=1, boot=BOOT_A)
    same = InterpreterExternalConnection()
    same.consume([manager, connect(BOOT_A)])
    assert same.finalize()[0].proposed_lane == "lead"                              # a daemon of the account
    other = InterpreterExternalConnection()
    other.consume([manager, connect(BOOT_B)])
    assert other.finalize()[0].proposed_lane == "high"                             # pid 300 is another process


# ---------------------------------------------------------------- reverse shell by lineage
def _shell_events(shell_boot):
    return [exc("/usr/bin/python3", 500, T0, ppid=1, boot=BOOT_A),
            ev("net_socket", T0 + timedelta(seconds=1), boot=BOOT_A, socket__syscall="connect", process__pid=500,
               process__executable="/usr/bin/python3", destination__ip=EXT, destination__port=4444),
            exc("/bin/sh", 501, T0 + timedelta(seconds=30), ppid=500, argv=["sh", "-i"], boot=shell_boot)]


def test_reverse_shell_parent_pid_reused_after_a_reboot_does_not_join():
    assert run(ReverseShellByLineage(), _shell_events(BOOT_B)) == []
    assert len(run(ReverseShellByLineage(), _shell_events(BOOT_A))) == 1
    assert len(run(ReverseShellByLineage(), _shell_events(None))) == 1             # unknown: boot-blind


def test_reverse_shell_records_without_a_boot_stay_with_the_only_recorded_boot():
    events = _shell_events(BOOT_A) + [exc("/bin/bash", 502, T0 + timedelta(seconds=40), ppid=500,
                                          argv=["bash", "-i"])]
    out = run(ReverseShellByLineage(), events)
    assert len(out) == 1 and out[0].group_key == f"host01|{BOOT_A}|500|{EXT}"
    assert "2 shell/interpreter exec(s)" in out[0].claim


# ---------------------------------------------------------------- scheduler and login sessions (hijack)
JOB = "/srv/tasks/rotate.sh"


def hx(argv, exe, uid, ts, *, boot=None, auid=None, ses=None, pid=None, ppid=None, user=None):
    return ev("process_exec", ts, boot=boot, process__argv=argv, process__executable=exe, process__uid=str(uid),
              process__user=user or {"0": "root", "33": "www-data", "1000": "alice"}.get(str(uid)),
              process__auid=None if auid is None else str(auid), process__session_id=ses, process__pid=pid,
              process__ppid=ppid, process__cwd="/root")


def test_scheduler_session_id_reused_after_a_reboot_is_another_session():
    writer = hx(["vi", JOB], "/usr/bin/vim.basic", 33, T0, user="www-data", pid=4000, ppid=3999)
    cron = ev("auth", T0 + timedelta(minutes=1), boot=BOOT_A, auth__service="cron", auth__phase="session_open",
              process__session_id=12, process__pid=5000, user__name="root", process__auid="0")

    def root_run(boot):
        return hx(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(hours=2), boot=boot, auid=0, ses=12,
                  pid=5001, ppid=5000)
    same = run(NonRootWriteRootExecutedFile(), [writer, cron, root_run(BOOT_A)])
    assert "the scheduler 'cron'" in same[0].claim
    other = run(NonRootWriteRootExecutedFile(), [writer, cron, root_run(BOOT_B)])
    assert "the scheduler" not in other[0].claim and "a login session (audit session 12)" in other[0].claim
    unknown = run(NonRootWriteRootExecutedFile(), [writer, cron, root_run(None)])
    assert "the scheduler 'cron'" in unknown[0].claim


def test_own_session_id_reused_after_a_reboot_is_not_own_elevation():
    writer = hx(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, boot=BOOT_A, auid=0, ses=4, pid=900, ppid=899)

    def root_run(boot):
        return hx(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(hours=2), boot=boot, auid=0, ses=4, pid=950,
                  ppid=949)
    assert "the writer's own elevation" in run(NonRootWriteRootExecutedFile(), [writer, root_run(BOOT_A)])[0].claim
    other = run(NonRootWriteRootExecutedFile(), [writer, root_run(BOOT_B)])
    assert len(other) == 1 and "own elevation" not in other[0].claim
    assert "the writer's own elevation" in run(NonRootWriteRootExecutedFile(), [writer, root_run(None)])[0].claim


# ---------------------------------------------------------------- persistence path changes (kernel_files)
def change(path, ts, *, boot=None, pid=7, ppid=6, exe="/usr/bin/bash"):
    return ev("file_change", ts, boot=boot, file__path=path, file__change="create", file__owner__id="0",
              process__uid="0", process__user="root", process__executable=exe, process__pid=pid,
              process__ppid=ppid)


def test_package_manager_parent_pid_reused_after_a_reboot_is_not_package_activity():
    dpkg = exc("/usr/bin/dpkg", 6, T0, ppid=1, boot=BOOT_A, process__uid="0")
    same = run(PersistencePathChange(), [dpkg, change("/etc/cron.d/x", T0 + timedelta(seconds=5), boot=BOOT_A)])
    assert same[0].group_key == "host01|package:dpkg"
    other = run(PersistencePathChange(), [dpkg, change("/etc/cron.d/x", T0 + timedelta(hours=1), boot=BOOT_B)])
    assert "package" not in other[0].group_key


def test_one_processs_records_without_a_boot_join_its_only_recorded_boot():
    records = [change("/etc/cron.d/a", T0, boot=BOOT_A), change("/etc/cron.d/b", T0 + timedelta(seconds=1))]
    assert len(run(PersistencePathChange(), records)) == 1
    records.append(change("/etc/cron.d/c", T0 + timedelta(seconds=2), boot=BOOT_B))
    # two recorded boots: the unrecorded record cannot be placed in either, so it is never merged
    assert len(run(PersistencePathChange(), records)) == 3


# ---------------------------------------------------------------- the grouping helper
def test_merge_unknown_boot_merges_only_into_a_single_recorded_boot():
    groups = {("h", None, 5): ["u"], ("h", "A", 5): ["a"], ("h", None, 6): ["v"]}
    assert merge_unknown_boot(groups, 1) == {("h", "A", 5): ["u", "a"], ("h", None, 6): ["v"]}
    groups[("h", "B", 5)] = ["b"]
    assert merge_unknown_boot(groups, 1) == {("h", "A", 5): ["a"], ("h", "B", 5): ["b"], ("h", None, 5): ["u"],
                                             ("h", None, 6): ["v"]}
    reordered = dict(reversed(list(groups.items())))
    assert merge_unknown_boot(reordered, 1) == merge_unknown_boot(groups, 1)


# ---------------------------------------------------------------- expansion links
def link_event(event_id, ts, boot=None, **fields):
    if boot is not None:
        fields["host__boot__id"] = boot
    return TypedEvent(id=event_id, family="process_exec", ts=ts, host="web1",
                      fields={k.replace("__", "."): fv(v, f"{event_id}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def test_lineage_link_refuses_an_ancestor_pid_from_another_boot_and_keeps_unrecorded_boots():
    start = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
    old_parent = link_event("old-parent", start, BOOT_B, process__executable="/usr/sbin/apache2",
                            process__pid=100, process__ppid=1)
    root = link_event("root", start + timedelta(seconds=5), BOOT_A, process__executable="/bin/sh",
                      process__pid=200, process__ppid=100)
    child = link_event("child", start + timedelta(seconds=6), process__executable="/usr/bin/id",
                       process__pid=201, process__ppid=200)
    anchor = LinkAnchor(finding_id="finding-x", ts=root.ts, host="web1", event_ids=[root.id], events=[root])
    window = LinkWindow(label="anchor +10 min", start=start, end=start + timedelta(minutes=10))
    result = LinkFetcher(FakePivot([old_parent, root, child]), start, window.end).fetch(
        anchor, "process_lineage", window)
    assert result.event_ids == ["child"]
    assert result.key["host.boot.id"] == BOOT_A


# ---------------------------------------------------------------- context: session keys
def test_context_session_keys_do_not_split_a_session_by_boot_presence():
    anchor = ContextAnchor(id="cand-1", anchor_class="execution", lane="high", claim="x", events=[], rule_id="r")
    with_boot = exc("/usr/bin/id", 10, T0, boot=BOOT_A, process__session_id=3)
    without = exc("/usr/bin/id", 11, T0, process__session_id=3)
    boots = _session_boots([with_boot, without], anchor)
    assert _session_key(with_boot, anchor, boots) == _session_key(without, anchor, boots) == ("host01", BOOT_A, 3)
    other = exc("/usr/bin/id", 12, T0, boot=BOOT_B, process__session_id=3)
    boots = _session_boots([with_boot, without, other], anchor)
    # two recorded boots: two sessions, and the record without a boot id joins neither
    assert {_session_key(e, anchor, boots) for e in (with_boot, without, other)} == {
        ("host01", BOOT_A, 3), ("host01", None, 3), ("host01", BOOT_B, 3)}


# ---------------------------------------------------------------- single-boot data: identical to boot-blind
def _projection(matches):
    return sorted((m.playbook_id, m.claim, m.proposed_lane, m.severity, tuple(sorted(e.id for e in m.events)))
                  for m in matches)


def _rebooted(events, boot, every=1):
    """The same records, with `boot` recorded on every `every`-th one (the rest unknown)."""
    out = []
    for i, event in enumerate(events):
        fields = dict(event.fields)
        fields.pop("host.boot.id", None)
        if boot is not None and i % every == 0:
            fields["host.boot.id"] = fv(boot, "fx:boot")
        out.append(event.model_copy(update={"fields": fields}))
    return out


def test_single_boot_results_equal_boot_blind_results():
    shells = _shell_events(None) + [exc("/bin/bash", 502, T0 + timedelta(seconds=40), ppid=500,
                                        argv=["bash", "-i"])]
    writer = hx(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=0, ses=4, pid=900, ppid=899)
    jobs = [writer, hx(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(hours=2), auid=0, ses=4, pid=950,
                       ppid=949),
            ev("auth", T0 + timedelta(minutes=1), auth__service="cron", auth__phase="session_open",
               process__session_id=12, process__pid=5000, user__name="root", process__auid="0"),
            hx(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(hours=3), auid=0, ses=12, pid=5001,
               ppid=5000)]
    changes = [exc("/usr/bin/dpkg", 6, T0, ppid=1, process__uid="0"),
               change("/etc/cron.d/x", T0 + timedelta(seconds=5)), change("/etc/cron.d/y", T0, pid=70, ppid=69),
               change("/etc/cron.d/z", T0 + timedelta(seconds=1), pid=70, ppid=69)]
    for factory, events in ((ReverseShellByLineage, shells), (NonRootWriteRootExecutedFile, jobs),
                            (PersistencePathChange, changes)):
        blind = _projection(run(factory(), _rebooted(events, None)))
        assert blind
        for every in (1, 2, 3):
            assert _projection(run(factory(), _rebooted(events, BOOT_A, every))) == blind, (factory, every)
