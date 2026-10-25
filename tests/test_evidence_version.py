"""Normalization changes must change the evidence version.

Typed events are stored once per event id. When normalization improved without a version change, a new hunt
silently reused an older hunt's rows (no `process.session_id`), and every login-session link went unsupported.
Event ids now carry the version of the producer that made them. These tests pin each producer's source to its
version: if you changed how raw records become typed events, bump the version and record the new digest here. If
you only changed comments or formatting, record the new digest under the same version.
"""
import hashlib
import inspect
from pathlib import Path

from romulus.detect import packets as packet_rules
from romulus.evidence import typed
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import EVIDENCE_VERSION, RawRef, event_id
from romulus.evidence.windows import WINDOWS_NORMALIZER
from romulus.hunt import packets as packet_stage
from romulus.sources import packets as packet_sources

# The files that turn ES/OpenSearch records into typed events (not shellparse.py, which only detectors use).
EVIDENCE_FILES = ("__init__.py", "auditd.py", "normalize.py", "typed.py")
PINNED_EVIDENCE = {9: "4e9103b2e1eab468361e1cde83127dd13cd5d87a4c7a0926ac35cf2116524009",
                   10: "e4dffd0944b86200b3c94aa301bead206967c58f565b30d426ee0071bd4f1aa9",
                   11: "150e5e4d74cb0f4891ef4cca7114a709f2038a42fc456e69f7952dcf0f6c9b32",
                   12: "fcda4d383cdb9d9d56aadffc237dcab81d4902dd3893e7b673aafd6cb6bdfb64",
                   # Suricata TCP/ICMP, Arkime ICMP and Zeek ICMP conn fields gained strict typed contracts.
                   13: "faf22327da69e63f594c999c9c5c68b909408308e37b0d1ab22ad86da1111b44"}
WINDOWS_EVIDENCE_FILES = ("windows.py", "windows_catalog.py")
PINNED_WINDOWS = {
    "windows-ecs@1": "8c2f1668700a3f7d0a143eef00473770e2e5c746fadf6ce3b2c95ae6bbe6a419",
    "windows-ecs@2": "c8931d60bb8eeb86c02b50d07950baea0e4225e01d3b9999cd12454609093255",
}
# The packet stage's normalizer: HTTP bodies rebuilt by TShark -> http_body events, and TCP connections rebuilt
# from per-segment payload -> tcp_stream events (with the shell analysis and the tables it reads).
PACKET_FUNCTIONS = (packet_stage._body_event, packet_rules.analyze_body, packet_rules._text, packet_rules._shebang,
                    packet_sources.decode_hex_body, packet_stage._stream_event, packet_sources.addresses,
                    packet_sources._endpoint, packet_sources.reassemble_tcp, packet_sources.TcpStreams,
                    packet_sources._flag, packet_stage._StreamTarget._judge,
                    packet_rules._echo, packet_sources._address, packet_sources._port, packet_sources.stream_key,
                    packet_sources._first, packet_sources._last, packet_stage._first, packet_stage._canon,
                    packet_rules.analyze_stream, packet_rules._Side, packet_rules._clean, packet_rules._lines,
                    packet_rules._bursts, packet_rules._texty, packet_rules._tokens, packet_rules._args_fit,
                    packet_rules._command_name, packet_rules.ShellIndicator)
PACKET_TABLES = (packet_sources.STREAM_PREFS, packet_sources.QUERIES["tcp_payload"],
                 [p.pattern for p in (*packet_rules.PROMPTS, *packet_rules.BANNERS, *packet_rules.SHELL_ERRORS,
                                      packet_rules.BARE_PROMPT, packet_rules.LOGIN_PROMPT,
                                      packet_rules.PASSWORD_PROMPT, packet_rules._IAC, packet_rules._ANSI,
                                      packet_rules._LINE_END)],
                 packet_rules.OUTPUT_SIGNATURES, sorted(packet_rules.WINDOWS_COMMANDS), packet_rules.OPENING_BYTES,
                 packet_rules.OUTPUT_WINDOW_BYTES, packet_rules.MAX_COMMAND_CHARS, packet_rules.MAX_COMMANDS,
                 packet_rules.PROMPT_SCAN_BYTES, packet_rules.MIN_INDICATORS, sorted(packet_rules.TYPED_TEXT_KINDS),
                 packet_sources.MAX_ADDRESS_CHARS, packet_stage.STREAM_DIRECTION_BYTES)
PINNED_PACKETS = {"tshark-packets@5": "1d6045c6230687d41dd4c0d6b541dd16b23031598fa5eb2fea1bc17e7388054d"}


def _files_digest() -> str:
    h = hashlib.sha256()
    for name in EVIDENCE_FILES:
        path = Path(typed.__file__).parent / name
        h.update(name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def _windows_files_digest() -> str:
    h = hashlib.sha256()
    for name in WINDOWS_EVIDENCE_FILES:
        path = Path(typed.__file__).parent / name
        h.update(name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def _functions_digest() -> str:
    h = hashlib.sha256()
    for fn in PACKET_FUNCTIONS:
        h.update(fn.__qualname__.encode() + b"\0" + inspect.getsource(fn).replace("\r\n", "\n").encode() + b"\0")
    h.update(repr(PACKET_TABLES).encode())
    return h.hexdigest()


def test_evidence_normalization_matches_the_pinned_version():
    assert PINNED_EVIDENCE.get(EVIDENCE_VERSION) == _files_digest(), (
        "evidence normalization changed: if its output changed, bump EVIDENCE_VERSION in evidence/typed.py; then "
        f"record {_files_digest()} for version {EVIDENCE_VERSION} in tests/test_evidence_version.py")


def test_windows_normalization_matches_the_pinned_producer_version():
    assert PINNED_WINDOWS.get(WINDOWS_NORMALIZER) == _windows_files_digest(), (
        "Windows evidence normalization changed: bump WINDOWS_NORMALIZER, then record "
        f"{_windows_files_digest()} for {WINDOWS_NORMALIZER} in tests/test_evidence_version.py"
    )


def test_packet_normalization_matches_the_pinned_version():
    version = packet_stage.PACKET_NORMALIZER
    assert PINNED_PACKETS.get(version) == _functions_digest(), (
        "packet normalization changed: if its output changed, bump PACKET_NORMALIZER in hunt/packets.py; then "
        f"record {_functions_digest()} for {version} in tests/test_evidence_version.py")


def test_event_ids_carry_the_producer_and_version():
    ref = RawRef(target="idx", native_id="doc-1")
    assert NORMALIZER_VERSION.endswith(f"@{EVIDENCE_VERSION}")
    legacy = hashlib.sha256(b"process_exec|" + ref.key.encode()).hexdigest()[:24]
    assert event_id("process_exec", [ref]) != legacy                    # never collides with pre-versioned rows
    assert event_id("process_exec", [ref], WINDOWS_NORMALIZER) != event_id("process_exec", [ref])
    assert event_id("http_body", [ref], "tshark-http@3") != event_id("http_body", [ref], "tshark-http@4")
    assert event_id("http_body", [ref], "tshark-http@4") != event_id("http_body", [ref], "tshark-packets@5")
