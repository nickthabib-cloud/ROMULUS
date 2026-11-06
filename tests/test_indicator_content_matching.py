"""Analyst indicator kinds use typed hash/URL/certificate fields and honest roles."""
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from romulus.content.indicator_import import ImportedIndicator
from romulus.content.indicator_lists import IndicatorLists
from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import BITS_CHANNEL, BITS_PROVIDER, SYSMON, SYSMON_CHANNEL
from tests.fixtures import zeek_logs as zl
from tests.test_indicators import net_event, run
from tests.test_malcolm_suricata import EVE, MALCOLM, filebeat_hit, malcolm_hit
from tests.test_network_normalizers import SELF_SIGNED, arkime, eve, one
from tests.test_sweep import _repo
from tests.test_zeek_windows_protocols import normalize
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

VALUES = {'md5': 'ab'*16, 'sha1': 'bc'*20, 'sha256': 'cd'*32}


def rule(kind, value):
    return IndicatorMatch(IndicatorSet([Indicator('test.value', kind, (value,), 'Mission value', 'medium', 'lead')]))


@pytest.mark.parametrize('shape', ['winlogbeat_7', 'winlogbeat_8', 'elastic_agent'])
@pytest.mark.parametrize('kind', VALUES)
@pytest.mark.parametrize('code,phrase', [(1, 'process image'), (7, 'loaded image'), (11, 'file-change')])
def test_windows_hash_kinds_keep_process_loaded_image_and_file_roles_distinct(shape, kind, code, phrase):
    stamp = '2026-01-02T03:04:05Z'
    data = {'UtcTime': stamp, 'Image': r'C:\Tools\actor.exe', 'ProcessId': '123',
            'ProcessGuid': '{00000000-0000-0000-0000-000000000001}',
            'Hashes': kind.upper()+'='+VALUES[kind].upper(),
            'ImageLoaded': r'C:\Tools\library.dll', 'TargetFilename': r'C:\Tools\payload.bin'}
    event = normalize_windows(windows_hit(LogicalWindowsEvent(
        SYSMON_CHANNEL, SYSMON, code, 'ws01', 3000+code, stamp, data), shape))
    owner = rule(kind, VALUES[kind])
    try:
        [match] = run(owner, event)
        assert phrase in match.claim.lower()
        assert VALUES[kind] in match.claim.lower()
        assert 'malicious' not in match.claim.lower()
        if code != 1:
            assert 'image ran' not in match.claim.lower()
        assert any(kind in field.field or field.field == 'file.hashes' for field in match.predicate)
    finally:
        owner.release_state()


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
@pytest.mark.parametrize('kind', VALUES)
def test_zeek_file_hashes_are_transfer_observations_where_typed(shape, kind):
    event = normalize(zl.WRITERS[shape](zl.FILES.with_(**{kind: VALUES[kind]}), 'file-hash'))
    owner = rule(kind, VALUES[kind])
    try:
        matches = run(owner, event)
        if shape == 'security_onion' and kind == 'sha256':
            assert matches == []
            assert any('sha256' in note and 'cannot' in note for note in owner.coverage_notes())
        else:
            [match] = matches
            assert 'transfer' in match.claim.lower() and VALUES[kind] in match.claim
            assert re.search(r'\bran\b', match.claim.lower()) is None
    finally:
        owner.release_state()


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
@pytest.mark.parametrize('standalone', [False, True])
def test_zeek_sha256_certificates_match_typed_chain_or_standalone_observation(shape, standalone):
    source = zl.X509 if standalone else zl.SSL
    event = normalize(zl.WRITERS[shape](source, 'certificate'))
    owner = rule('x509_sha256', zl.FP_LEAF.upper())
    try:
        [match] = run(owner, event)
        assert 'certificate' in match.claim.lower() and zl.FP_LEAF in match.claim.lower()
        assert 'file with' not in match.claim.lower()
    finally:
        owner.release_state()


@pytest.mark.parametrize('arkime_source', [False, True])
def test_sha1_certificate_aliases_are_one_match_per_record(arkime_source):
    digest = VALUES['sha1']
    event = one(arkime(cert=[{**SELF_SIGNED, 'hash': digest}]) if arkime_source else eve('cert', {
        'event_type': 'tls', 'tls': {'fingerprint': digest, 'subject': 'CN=example.test',
                                   'issuerdn': 'CN=example.test'}}))
    owner = rule('x509_sha1', ':'.join(digest[n:n+2] for n in range(0, 40, 2)).upper())
    try:
        [match] = run(owner, event)
        assert '1 ' in match.claim and 'certificate' in match.claim.lower()
        assert 'malicious' not in match.claim.lower()
    finally:
        owner.release_state()


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_absolute_typed_http_target_matches_exact_normalized_url(shape):
    uri = 'HTTP://Example.TEST:80/Keep%2F?a=1&b=2'
    event = normalize(zl.WRITERS[shape](zl.HTTP.with_(uri=uri, host='example.test'), 'url'))
    owner = rule('url', 'http://example.test/Keep%2F?a=1&b=2')
    try:
        [match] = run(owner, event)
        assert 'URL' in match.claim and 'Keep%2F?a=1&b=2' in match.claim
        assert any(field.field == 'url.original' for field in match.predicate)
    finally:
        owner.release_state()


def test_url_does_not_guess_scheme_or_normalize_path_and_query():
    owner = rule('url', 'https://example.test/Case?q=1&x=2')
    try:
        assert run(owner, net_event('http_tx', http__hostname='example.test',
                                   url__original='/Case?q=1&x=2')) == []
        assert any('url' in note and 'cannot' in note for note in owner.coverage_notes())
        assert run(owner, net_event('http_tx', 'other', url__full='https://example.test/case?x=2&q=1')) == []
    finally:
        owner.release_state()


@pytest.mark.parametrize('malcolm', [False, True])
@pytest.mark.parametrize('kind', ['url', 'x509_sha1'])
def test_suricata_native_and_malcolm_new_kinds(malcolm, kind):
    family = 'http' if kind == 'url' else 'tls'
    value = 'HTTP://Example.TEST:80/Keep?q=1' if kind == 'url' else VALUES['sha1']
    source = deepcopy((MALCOLM if malcolm else EVE)[family])
    block = source['suricata'][family] if malcolm else source[family]
    block['url' if kind == 'url' else 'fingerprint'] = value
    event = one(malcolm_hit(source) if malcolm else filebeat_hit(source))
    owner = rule(kind, value)
    try:
        [match] = run(owner, event)
        assert ('URL' if kind == 'url' else 'certificate') in match.claim
        assert match.proposed_lane == 'lead'
    finally:
        owner.release_state()


@pytest.mark.parametrize('shape', ['winlogbeat_7', 'winlogbeat_8', 'elastic_agent'])
def test_bits_remote_url_is_a_recorded_resource_not_an_http_request(shape):
    event = normalize_windows(windows_hit(LogicalWindowsEvent(BITS_CHANNEL, BITS_PROVIDER, 59, 'ws01',
        900, '2026-01-02T03:04:05Z', {'Url': 'HTTPS://Example.TEST:443/Payload'}), shape))
    owner = rule('url', 'https://example.test/Payload')
    try:
        [match] = run(owner, event)
        assert 'recorded URL' in match.claim and 'HTTP request' not in match.claim
        assert any(field.field == 'bits.remote_url' for field in match.predicate)
    finally:
        owner.release_state()


def test_absolute_access_log_target_is_searchable():
    from romulus.evidence.normalize import normalize_apache_access
    event = normalize_apache_access({'_index': 'apache', '_id': 'url', '_source': {
        '@timestamp': '2026-01-02T03:04:05Z', 'host': {'name': 'web'},
        'url': {'original': 'http://Example.TEST/Path'}, 'http': {'request': {'method': 'GET'}}}})
    owner = rule('url', 'http://example.test/Path')
    try:
        assert len(run(owner, event)) == 1
    finally:
        owner.release_state()


def test_analyst_overlay_matches_without_loading_its_values_and_cites_pinned_provenance():
    repo = _repo()
    now = datetime(2026, 1, 10, tzinfo=UTC)
    lists = IndicatorLists(repo)
    original = lists.create_version([ImportedIndicator('sha256', VALUES['sha256'], 'Partner hash')],
        name='Mission list', source='Partner offline CSV', author='analyst1',
        now=now-timedelta(days=3), expires_at=now+timedelta(days=30))
    pinned = lists.pin(now)
    lists.create_version([ImportedIndicator('sha256', 'ff'*32)], list_id=original['id'],
        name='Mission list', source='Partner offline CSV', author='analyst1',
        now=now, expires_at=now+timedelta(days=30))
    owner = IndicatorMatch(IndicatorSet())
    try:
        owner.bind_indicators(repo, pinned)
        [match] = run(owner, net_event('file_transfer', file__hash__sha256=VALUES['sha256']))
        text = match.claim+' '+str(match.notes)
        for phrase in ('Mission list', 'Partner offline CSV', 'analyst1', 'version 1', '3 days'):
            assert phrase in text
        assert match.proposed_lane == 'lead'
        assert len(owner.by_id) == 0
    finally:
        owner.release_state()
        repo.engine.dispose()
