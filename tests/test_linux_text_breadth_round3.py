"""Third review round: automation and network-daemon accounts, shell escapes through sudo-allowed programs (GTFOBins),
and the success store at mission scale. Synthetic sudo lines follow sudoers(5) EVENT LOGGING; Ansible's become wrapper
is `/bin/sh -c 'echo BECOME-SUCCESS-<id> ; <module>'`. Hosts and accounts are invented."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.privilege_brokers import PrivilegeBrokerSuspiciousSuccess
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.citations import COMPACT_CITATION_NOTE
from tests.test_linux_text_breadth_review import journal_doc, refused, run, sudo_line

T0 = datetime(2026, 11, 9, 12, tzinfo=UTC)
ANSIBLE = ("ansible : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c echo BECOME-SUCCESS-abcdefgh ; "
           "/usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py")


def line(seconds, text, nid):
    return sudo_line(seconds, text, nid=nid)


def judged(*events):
    _rule, matches = run(PrivilegeBrokerSuspiciousSuccess, list(events))
    return matches


# ---------------------------------------------------------------------------------------------- automation accounts
def test_ansible_become_runs_fold_into_one_lead():
    matches = judged(*(line(600 * n, ANSIBLE, f"an{n}") for n in range(5)))
    assert {m.proposed_lane for m in matches} == {"lead"} and len({m.group_key for m in matches}) == 1
    assert matches[-1].aggregate_summary["count"] == 5 and "BECOME-SUCCESS marker" in matches[-1].claim


@pytest.mark.parametrize("command,lane", [
    ("/bin/bash deploy.sh", "lead"),
    ("/bin/sh -c ./build.sh --release", "lead"),
    ("/bin/bash", "high"),
    ("/usr/bin/python3", "high"),
    ("/bin/bash -i", "high"),
])
def test_jenkins_shell_scripts_are_leads_and_bare_shells_high(command, lane):
    [match] = judged(line(0, f"jenkins : TTY=unknown ; PWD=/var/lib/jenkins ; USER=root ; COMMAND={command}", "j"))
    assert match.proposed_lane == lane


def test_ansible_su_and_refusals_first_are_high():
    su = normalize_hits([journal_doc({"MESSAGE": "(to root) ansible on pts/0", "SYSLOG_IDENTIFIER": "su",
                                      "_COMM": "su", "_PID": "9"}, "asu")])[0][0]
    [match] = judged(su)
    assert match.proposed_lane == "high" and "used su" in match.claim
    [match] = judged(refused(0, "1 incorrect password attempt", "ansible"), line(30, ANSIBLE, "a1"))
    assert match.proposed_lane == "high" and "refusals came first" in match.claim


# ---------------------------------------------------------------------------------------------- network daemons
@pytest.mark.parametrize("actor", ["named", "redis", "elasticsearch", "postfix"])
def test_network_daemon_accounts_are_high(actor):
    [match] = judged(line(0, f"{actor} : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", f"d{actor}"))
    assert match.proposed_lane == "high" and "network daemon's account" in match.claim


# ---------------------------------------------------------------------------------------------- shell escapes
@pytest.mark.parametrize("actor,tty,command,lane", [
    ("nagios", "unknown", "/usr/bin/find . -exec /bin/sh ;", "high"),
    ("zabbix", "unknown", "/usr/bin/vim /etc/hosts", "high"),
    ("jenkins", "pts/1", "/bin/systemctl status nginx", "high"),
    ("postgres", "unknown", "/bin/systemctl restart postgresql", "lead"),
    ("postgres", "unknown", "/usr/bin/pg_ctlcluster 14 main restart", "lead"),
    ("nagios", "unknown", "/bin/journalctl -u nginx --since today", "lead"),
    ("ansible", "unknown", "/usr/bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
     "high"),
])
def test_shell_escape_programs_and_plain_service_actions(actor, tty, command, lane):
    [match] = judged(line(0, f"{actor} : TTY={tty} ; PWD=/ ; USER=root ; COMMAND={command}", "e"))
    assert match.proposed_lane == lane


# ---------------------------------------------------------------------------------------------- held success store
def _success(index: int, seconds: float, host="h1", target="t"):
    return TypedEvent(id=f"s{index:07d}", family="privilege_use", ts=T0 + timedelta(seconds=seconds), host=host,
                      outcome=Outcome.success, normalizer="fixture",
                      fields={"auth.service": fv("sudo", f"n{index}:a"), "user.name": fv(f"u{index}", f"n{index}:u"),
                              "auth.target_user": fv("root", f"n{index}:t"),
                              "sudo.command": fv("/usr/bin/id", f"n{index}:c"),
                              "process.cwd": fv("/home/u", f"n{index}:p")},
                      raw=[RawRef(target=target, native_id=f"n{index}", digest="")])


def test_a_late_refusal_cites_the_compact_success_for_fetching_at_publication():
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        success = _success(1, 60)
        assert rule.consume([success]) == []
        [match] = rule.consume([refused(0, actor="u1", host="h1")])
        cited = next(e for e in match.events if e.id == success.id)
        assert COMPACT_CITATION_NOTE in cited.caveats and cited.raw == success.raw
        assert cited.has("process.cwd")                         # the whole typed event is held, without its raw copy
    finally:
        rule.close_spill()


def test_cross_target_successes_are_held_until_every_target_has_read_past_them():
    rule = PrivilegeBrokerSuspiciousSuccess()
    rule.linux_host_targets = ("auth-a", "auth-b")
    try:
        rule.bind_raw({}, "auth-a")
        for start in range(0, 20_000, 1000):                    # target a: successes over about 5.5 hours
            rule.consume([_success(i, i, target="auth-a") for i in range(start, start + 1000)])
        assert rule.prune() == 0 and len(rule.successes) == 20_000   # b not read yet: nothing is pruned
        rule.bind_raw({}, "auth-b")
        [match] = rule.consume([refused(-30, actor="u5", host="h1")])  # b, read afterwards, from the start
        assert match.proposed_lane == "high"
        rule.consume([refused(19_000, actor="nobody-here", host="h1")])  # b reads on: a's early rows go
        assert 0 < len(rule.successes) < 20_000
    finally:
        rule.close_spill()


def test_success_store_at_mission_scale_stays_bounded_and_prunes_stale_rows():
    rule = PrivilegeBrokerSuspiciousSuccess()
    started = time.perf_counter()
    try:
        for start in range(0, 200_000, 10_000):                 # 200,000 keys, one success each, 10 s apart
            rule.consume([_success(i, i * 10.0) for i in range(start, start + 10_000)])
        held = len(rule.successes)
        rows = [row for _key, rows in rule.successes.items() for row in rows]
        held_bytes = sum(len(blob) for blob, _at, _judged in rows)
        # the window plus the margin is 1,800 s, 180 rows at one per 10 s, plus one 300 s bucket in flight
        assert held <= 240 and len(rule.buckets) <= 12
        assert held_bytes < 240 * 1024                           # compact rows: about 1 KB or less each
        assert rule.successes.on_disk == 0
    finally:
        rule.close_spill()
    assert time.perf_counter() - started < 300
