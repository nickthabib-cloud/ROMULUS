"""Overlapping shipper markers cannot bypass producer credential redaction."""
import copy
import hashlib
import json

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.raw_scrub import clean_source
from tests.test_arkime_sessions import session
from tests.test_suricata_protocols import hit


@pytest.mark.parametrize("producer", ["suricata-eve@2", "arkime@1"])
@pytest.mark.parametrize("surrogate", [False, True])
def test_loose_zeek_marker_cannot_bypass_network_credential_scrubbing(producer, surrogate):
    secret = "synthetic-marker-secret"
    if producer == "suricata-eve@2":
        raw = hit("ftp", {"command": "PASS", "command_data": secret})
        raw["_source"]["event"]["module"] = "zeek"
    else:
        raw = session("credential")
        raw["_source"].update(event={"provider": "arkime", "module": "zeek"},
                              http={"request-authorization": [secret]})
    if surrogate:
        raw["_source"]["unrelated"] = "lone-\ud800"
    before = copy.deepcopy(raw)
    events, skips, errors = normalize_hits([raw])
    assert len(events) == 1 and not skips and not errors
    assert events[0].normalizer == producer
    cleaned = clean_source(raw["_source"])
    assert secret not in json.dumps(cleaned)
    digest = hashlib.sha256(json.dumps(cleaned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert events[0].raw[0].digest == digest
    assert raw == before
