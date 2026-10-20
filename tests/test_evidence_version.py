"""Normalization changes must change the evidence version (eval run 10).

Typed events are stored once per event id. When normalization improved without a version change, a new hunt
silently reused an older hunt's rows (no `process.session_id`), and every login-session link went unsupported.
The event id now carries EVIDENCE_VERSION. This test pins the evidence package's source to that version: if you
changed how raw records become typed events, bump EVIDENCE_VERSION in `evidence/typed.py` and record the new
digest here. If you only changed comments or formatting, record the new digest with the same version.
"""
import hashlib
from pathlib import Path

from romulus.evidence import typed
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import EVIDENCE_VERSION, RawRef, event_id

PINNED = {2: "59f5eae93909cfd6ea0bb01deb055f1dea9a2a03a48f7e431339eea939c76b7d"}


def _sources_digest() -> str:
    h = hashlib.sha256()
    for path in sorted(Path(typed.__file__).parent.glob("*.py")):
        h.update(path.name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def test_evidence_sources_match_the_pinned_version():
    assert PINNED.get(EVIDENCE_VERSION) == _sources_digest(), (
        "romulus/evidence changed: if normalization output changed, bump EVIDENCE_VERSION; then record the new "
        f"digest {_sources_digest()} for version {EVIDENCE_VERSION} in tests/test_evidence_version.py")


def test_the_event_id_and_normalizer_carry_the_version():
    ref = RawRef(target="idx", native_id="doc-1")
    assert NORMALIZER_VERSION.endswith(f"@{EVIDENCE_VERSION}")
    legacy = hashlib.sha256(b"process_exec|" + ref.key.encode()).hexdigest()[:24]
    assert event_id("process_exec", [ref]) != legacy            # never collides with pre-versioned rows
