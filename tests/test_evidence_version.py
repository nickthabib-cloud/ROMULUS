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
from romulus.hunt import packets as packet_stage
from romulus.sources import packets as packet_sources

# The files that turn ES/OpenSearch records into typed events (not shellparse.py, which only detectors use).
EVIDENCE_FILES = ("__init__.py", "auditd.py", "normalize.py", "typed.py")
PINNED_EVIDENCE = {7: "1741c2bd9e7d6f028f14e020e385c37e0e2ae1ca0f7f4b67f75a2f8849097b42"}
# The packet stage's normalizer: HTTP bodies rebuilt by TShark -> http_body events.
PACKET_FUNCTIONS = (packet_stage._body_event, packet_rules.analyze_body, packet_rules._text, packet_rules._shebang,
                    packet_sources.decode_hex_body)
PINNED_PACKETS = {"tshark-http@4": "ef5e1478246e695dc7b70cc178b431669728f0497c61b86f297724b7c8722492"}


def _files_digest() -> str:
    h = hashlib.sha256()
    for name in EVIDENCE_FILES:
        path = Path(typed.__file__).parent / name
        h.update(name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def _functions_digest() -> str:
    h = hashlib.sha256()
    for fn in PACKET_FUNCTIONS:
        h.update(fn.__qualname__.encode() + b"\0" + inspect.getsource(fn).replace("\r\n", "\n").encode() + b"\0")
    return h.hexdigest()


def test_evidence_normalization_matches_the_pinned_version():
    assert PINNED_EVIDENCE.get(EVIDENCE_VERSION) == _files_digest(), (
        "evidence normalization changed: if its output changed, bump EVIDENCE_VERSION in evidence/typed.py; then "
        f"record {_files_digest()} for version {EVIDENCE_VERSION} in tests/test_evidence_version.py")


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
    assert event_id("http_body", [ref], "tshark-http@3") != event_id("http_body", [ref], "tshark-http@4")
