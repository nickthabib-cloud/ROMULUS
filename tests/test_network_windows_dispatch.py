"""Synthetic Windows envelopes using the public EVTX JSON and Winlogbeat schemas.

https://github.com/omerbenamram/evtx
https://www.elastic.co/guide/en/beats/winlogbeat/8.19/exported-fields-winlog.html
"""
import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.sources.profile import contract_from_types
from tests.test_evtx_json import raw_hit, twin


@pytest.mark.parametrize("windows_hit", [raw_hit(), twin(raw_hit())])
def test_windows_records_on_network_target_are_counted_without_affecting_network_families(windows_hit):
    contract = contract_from_types("network", {"@timestamp": "date"}, role="network", os_family="unknown")
    affected = {}
    events, skips, errors = normalize_hits([windows_hit], contract=contract, skip_families=affected)
    reason = "Windows event records on a network target: not evaluated"
    assert events == [] and errors == []
    assert skips == {reason: 1}
    assert affected == {reason: frozenset()}
