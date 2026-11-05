"""Signed driver names do not substitute for a curated byte hash."""
import importlib

import pytest

from tests.windows_event_support import event, run


@pytest.mark.parametrize('digest,hit', [
    ('D969845EF6ACC8E5D3421A7CE7E244F419989710871313B04148F9B322751E5D', True),
    ('1e0eb0811a7cf1bdaf29d3d2cab373ca51eb8d8b58889ab7728e2d3aed244abe', True),
    ('0' * 64, False), ('d969845e', False), (None, False),
])
def test_dual_use_driver_matches_hash_even_when_renamed_and_validly_signed(digest, hit):
    rule = importlib.import_module('romulus.detect.windows_driver_hashes').KnownDualUseDriver()
    matches = run(rule, [event('image_load', 6, **{
        'image.path': r'C:\Windows\System32\drivers\renamed.sys', 'image.kind': 'driver',
        'image.signed': True, 'image.signature_status': 'Valid', 'image.hash.sha256': digest})])
    assert bool(matches) is hit
    if matches:
        assert matches[0].proposed_lane == 'lead' and matches[0].severity == 'low'
        assert 'exploitation' in ' '.join(matches[0].notes).lower()
