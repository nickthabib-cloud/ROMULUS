"""Boot identity, review fixes: malformed journald copies, numeric record types, context buckets across boots,
boot-aware exec ancestry for account and tamper rules, filling a stored row's boot forward, and link and socket
joins whose records lack a boot id. Hosts, boot ids, accounts and addresses are invented."""
from datetime import timedelta

import pytest

from romulus.detect.host import ProcessLineage
from romulus.detect.lineage import ReverseShellByLineage
from romulus.evidence.normalize import normalize_hits
from romulus.hunt.context import finalize_context
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_boot_identity import BOOT_A, BOOT_B, EXT, T0, ev, exc, exec_records, journal_copy, only, run
from tests.test_context_playbooks import T0 as CTX_T0
from tests.test_context_playbooks import _seed_anchor, _seed_link
from tests.test_context_playbooks import event as ctx_event
from tests.test_expansion_links import FakePivot


# ---------------------------------------------------------------- 1. malformed journald copies never crash
@pytest.mark.parametrize("overrides", [
    {"_AUDIT_ID": "²"}, {"_AUDIT_ID": "４３２１"}, {"_SOURCE_REALTIME_TIMESTAMP": "1900000000250000²"},
    {"_AUDIT_ID": 4321}, {"_AUDIT_TYPE_NAME": ["SYSCALL"]},
])
def test_non_ascii_or_non_string_journald_numbers_leave_the_boot_unknown(overrides):
    events, skips, errors = normalize_hits([*exec_records(), journal_copy("j1", **overrides)])
    assert errors == [] and not only(events).has("host.boot.id") and sum(skips.values()) == 1


def test_array_valued_host_name_on_a_copy_leaves_the_boot_unknown():
    copy = journal_copy("j1")
    copy["_source"]["host"] = {"name": ["host01", "alias"]}
    events, skips, errors = normalize_hits([*exec_records(), copy])
    assert errors == [] and not only(events).has("host.boot.id") and sum(skips.values()) == 1


# ---------------------------------------------------------------- 6. numeric record type (older journald)
def test_numeric_audit_type_names_the_record_when_the_name_is_absent():
    joined, _s, _e = normalize_hits([*exec_records(), journal_copy("j1", _AUDIT_TYPE_NAME=None, _AUDIT_TYPE="1300")])
    assert only(joined).get("host.boot.id") == BOOT_A
    for number in ("1302", "9999", "13OO"):                    # PATH (not in the group), unknown, not a number
        missed, _s, _e = normalize_hits([*exec_records(),
                                         journal_copy("j1", _AUDIT_TYPE_NAME=None, _AUDIT_TYPE=number)])
        assert not only(missed).has("host.boot.id"), number


# ---------------------------------------------------------------- 2. context buckets never merge two boots
def _repo():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _login(event_id, source, boot):
    kw = {"host__boot__id": boot} if boot else {}
    return ctx_event(event_id, family="auth", auth__service="sshd", auth__phase="login", source__ip=source,
                     user__name="root", process__session_id=42, **kw)


def _shell(event_id, boot):
    kw = {"host__boot__id": boot} if boot else {}
    return ctx_event(event_id, process__executable="/bin/sh", process__argv=["/bin/sh"], process__session_id=42,
                     **kw)


def test_entry_point_is_not_withdrawn_by_another_boots_login_reusing_the_session_id():
    # Session 42 in boot A began with an external login; after a reboot, session id 42 is an internal login.
    repo = _repo()
    _seed_anchor(repo, "h1", "F-a", "host.web_shell", [_shell("shell-a", BOOT_A)])
    _seed_link(repo, "h1", "L-a", "F-a", [_login("login-a", "203.0.113.8", BOOT_A)], link_type="login_session")
    _seed_anchor(repo, "h1", "F-b", "host.web_shell", [_shell("shell-b", BOOT_B)])
    _seed_link(repo, "h1", "L-b", "F-b", [_login("login-b", "10.0.0.8", BOOT_B)], link_type="login_session")
    finalize_context(repo, "h1")
    entries = [c for c in repo.candidates("h1") if c["rule_id"] == "context.entry_point_promotion"
               and c["lane"] != "context"]
    assert len(entries) == 1
    assert entries[0]["lane"] == "high" and "login-a" in entries[0]["event_ids"]


def _discovery(event_id, exe, argv, boot):
    kw = {"host__boot__id": boot} if boot else {}
    return ctx_event(event_id, process__executable=exe, process__argv=argv, process__session_id=42, **kw)


def _burst(boots):
    return [_discovery("whoami", "/usr/bin/whoami", ["whoami"], boots[0]),
            _discovery("uname", "/usr/bin/uname", ["uname", "-a"], boots[1]),
            _discovery("ss", "/usr/bin/ss", ["ss", "-tunap"], boots[2])]


def _discovery_candidates(burst, anchor_boot):
    repo = _repo()
    _seed_anchor(repo, "h1", "F-anchor", "host.web_shell", [_shell("anchor-event", anchor_boot)])
    _seed_link(repo, "h1", "L-observed", "F-anchor", burst, link_type="login_session")
    finalize_context(repo, "h1")
    return sorted((c["lane"], tuple(sorted(c["event_ids"]))) for c in repo.candidates("h1")
                  if c["rule_id"] == "context.post_access_discovery" and c["lane"] != "context")


def test_two_recorded_boots_never_share_a_context_bucket():
    # three discovery classes would be a high burst in one session; across two boots they are two sessions
    split = _discovery_candidates(_burst([BOOT_A, BOOT_A, BOOT_B]), BOOT_A)
    assert [lane for lane, _ids in split] == ["lead", "lead"]


@pytest.mark.parametrize("boots,anchor_boot", [
    ([BOOT_A, None, None], BOOT_A), ([None, None, None], BOOT_A), ([BOOT_A, BOOT_A, BOOT_A], None),
    ([None, BOOT_A, None], None),
])
def test_single_boot_context_results_equal_boot_blind(boots, anchor_boot):
    assert _discovery_candidates(_burst(boots), anchor_boot) == _discovery_candidates(_burst([None] * 3), None)
    assert [lane for lane, _ids in _discovery_candidates(_burst(boots), anchor_boot)] == ["high"]


# ---------------------------------------------------------------- 3. ProcessLineage across a reboot
def test_process_lineage_pid_reused_after_a_reboot_attaches_no_package_or_web_lineage():
    for parent, kind in ((exc("/usr/bin/dpkg", 100, T0, ppid=1, boot=BOOT_A), "package"),
                         (exc("/usr/sbin/apache2", 100, T0, ppid=1, boot=BOOT_A, process__user="www-data"), "web")):
        lineage = ProcessLineage()
        lineage.observe(parent)
        later = T0 + timedelta(hours=1)
        same = exc("/usr/bin/chpasswd", 200, later, ppid=100, boot=BOOT_A)
        other = exc("/usr/bin/chpasswd", 201, later, ppid=100, boot=BOOT_B)
        unknown = exc("/usr/bin/chpasswd", 202, later, ppid=100)
        for child in (same, other, unknown):
            lineage.observe(child)
        assert lineage.classify(same).kind == kind
        assert lineage.classify(other).kind == ""                      # pid 100 is another process in boot B
        assert lineage.classify(unknown).kind == kind                  # no boot recorded: boot-blind
        ts = (later + timedelta(seconds=1)).timestamp()
        assert lineage.classify_pid("host01", 201, ts, BOOT_B).kind == ""
        assert lineage.classify_pid("host01", 200, ts, BOOT_A).kind == kind
        assert lineage.parent("host01", 100, ts, BOOT_B) is None
        assert lineage.parent("host01", 100, ts, BOOT_A) is not None


# ---------------------------------------------------------------- 4. a stored row's boot is filled forward
def test_save_evidence_fills_a_missing_boot_forward_and_never_overwrites_one():
    repo = _repo()
    bare = _shell("e1", None)
    repo.save_evidence("h1", [bare], {}, None)
    assert "host.boot.id" not in repo.events_by_ids(["e1"])[0]["event"]["fields"]
    repo.save_evidence("h1", [_shell("e1", BOOT_A)], {}, None)
    stored = repo.events_by_ids(["e1"])[0]["event"]
    assert stored["fields"]["host.boot.id"]["value"] == BOOT_A
    assert stored["fields"]["process.argv"] == bare.model_dump(mode="json")["fields"]["process.argv"]
    repo.save_evidence("h1", [_shell("e1", BOOT_B), bare], {}, None)
    assert repo.events_by_ids(["e1"])[0]["event"]["fields"]["host.boot.id"]["value"] == BOOT_A


# ---------------------------------------------------------------- 5. link and socket joins with unbooted records
def test_session_link_keeps_unbooted_records_of_a_booted_anchor():
    root = ctx_event("root", process__pid=100, process__session_id=42, process__auid="1000", host__boot__id=BOOT_A)
    fetched = ctx_event("fetched", process__pid=101, process__session_id=42, process__auid="1000")
    other = ctx_event("other-boot", process__pid=102, process__session_id=42, process__auid="1000",
                      host__boot__id=BOOT_B)
    window = LinkWindow(label="anchor +10 min", start=CTX_T0, end=CTX_T0 + timedelta(minutes=10))
    anchor = LinkAnchor(finding_id="F-x", ts=root.ts, host="web1", event_ids=[root.id], events=[root])
    result = LinkFetcher(FakePivot([root, fetched, other]), window.start, window.end).fetch(
        anchor, "login_session", window)
    assert result.event_ids == ["fetched"]


def test_socket_in_another_boot_than_the_shell_never_joins_through_an_unbooted_owner_exec():
    def events(socket_boot):
        return [exc("/usr/bin/python3", 500, T0, ppid=1),                         # owner exec: no boot recorded
                ev("net_socket", T0 + timedelta(seconds=1), boot=socket_boot, socket__syscall="connect",
                   process__pid=500, process__executable="/usr/bin/python3", destination__ip=EXT,
                   destination__port=4444),
                exc("/bin/sh", 501, T0 + timedelta(seconds=30), ppid=500, argv=["sh", "-i"], boot=BOOT_A)]
    assert run(ReverseShellByLineage(), events(BOOT_B)) == []
    assert len(run(ReverseShellByLineage(), events(BOOT_A))) == 1
    assert len(run(ReverseShellByLineage(), events(None))) == 1
