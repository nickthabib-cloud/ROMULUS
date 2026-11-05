"""The pinned ATT&CK for ICS bundle loads through the same bounded, hash-checked loader as the Enterprise one."""
import gzip
import hashlib

from romulus.catalog.attack import ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256, load_attack_bundle


def test_the_ics_bundle_matches_its_pinned_hash():
    raw = gzip.decompress(ICS_ATTACK_BUNDLE.read_bytes())
    assert hashlib.sha256(raw).hexdigest() == ICS_PINNED_JSON_SHA256


def test_the_ics_bundle_loads_and_names_live_and_revoked_ids():
    knowledge = load_attack_bundle(ICS_ATTACK_BUNDLE, expected_sha256=ICS_PINNED_JSON_SHA256)
    assert knowledge.version == "20.0"
    techniques = {technique.id: technique for technique in knowledge.techniques}
    for live in ("T0843", "T0836", "T0831", "T0858", "T0816", "T0845", "T0888", "T0846", "T0814", "T1692.001"):
        assert live in techniques and not techniques[live].revoked and not techniques[live].deprecated, live
    # Unauthorized Command Message was revoked in this release; rules cite its replacement, T1692.001
    assert "T0855" not in techniques or techniques["T0855"].revoked
    assert knowledge.replacements.get("T0855") == "T1692.001"
