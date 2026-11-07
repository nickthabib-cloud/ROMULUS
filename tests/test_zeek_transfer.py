"""Sniffed content, file direction and exact analyzer joins determine transfer evidence."""
import importlib
import itertools
from dataclasses import replace

import pytest

from romulus.evidence.typed import fv
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import every_shape

SHAPES = ('malcolm', 'elastic', 'security_onion', 'plain')
PE = zl.FILES.with_(filename='payload.exe', mime_type='application/x-dosexec', source='HTTP', is_orig=False)
HTTP = zl.HTTP.with_(uri='/payload.exe', host='203.0.113.10')


def detector():
    return importlib.import_module('romulus.detect.zeek_transfer').ExecutableTransfer()


def run(rows, shape='plain'):
    owner = detector()
    found = {}
    try:
        for row in rows:
            for match in owner.consume([every_shape(row)[shape]]):
                found[match.group_key] = match
        for match in owner.finalize():
            found[match.group_key] = match
        return list(found.values())
    finally:
        owner.release_state()


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('order', [(0, 1), (1, 0)])
def test_http_ingress_is_joined_in_both_orders_and_shapes(shape, order):
    rows = [PE, HTTP]
    [match] = run([rows[i] for i in order], shape)
    assert match.proposed_lane == 'lead'
    assert '203.0.113.10' in match.claim and '10.0.0.5' in match.claim
    assert len(match.events) == 2 and match.attack == ('T1105',)


@pytest.mark.parametrize('name,uri,lane', [
    ('photo.jpg', '/payload.exe', 'high'), ('payload.exe', '/photo.pdf?download=1', 'high'),
    ('payload', '/download', 'lead'), ('payload.EXE', '/payload.exe', 'lead'),
    ('payload.exe', '/payload.exe?name=photo.jpg', 'lead'),
])
def test_masquerade_uses_filename_or_uri_path_never_query(name, uri, lane):
    [match] = run([PE.with_(filename=name), HTTP.with_(uri=uri)])
    assert match.proposed_lane == lane
    assert ('T1036.008' in match.attack) == (lane == 'high')


@pytest.mark.parametrize('mime', [
    'application/x-executable', 'application/x-sharedlib', 'application/x-mach-o-executable',
    'text/x-shellscript', 'text/x-python', 'application/javascript', 'text/x-msdos-batch',
    'application/x-python-bytecode', 'text/x-perl', 'text/x-php', 'application/x-setupscript',
])
def test_verified_binary_and_script_mimes(mime):
    [match] = run([PE.with_(mime_type=mime), HTTP])
    assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('mime', ['image/jpeg', 'application/octet-stream', 'text/plain',
                                  'application/x-coredump', 'application/x-object'])
def test_filename_alone_and_nonexecutable_content_are_negative(mime):
    assert run([PE.with_(mime_type=mime), HTTP]) == []


@pytest.mark.parametrize('shape', SHAPES)
def test_truncated_content_keeps_its_positive_and_zeek_caveats(shape):
    [match] = run([PE.with_(filename='photo.jpg', missing_bytes=9, overflow_bytes=4, timedout=True), HTTP], shape)
    assert match.proposed_lane == 'high'
    caveats = ' '.join(caveat for event in match.events for caveat in event.caveats)
    assert all(word in caveats for word in ('missing', 'overflow', 'timed'))


@pytest.mark.parametrize('shape', SHAPES)
def test_old_layout_uses_actual_senders_and_receivers_without_uid(shape):
    row = PE.without('uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'is_orig').with_(
        tx_hosts=[zl.SERVER], rx_hosts=[zl.CLIENT], source='FTP_DATA', filename='payload')
    owner = detector()
    try:
        event = every_shape(row)[shape]
        found = list(owner.consume([event])) + list(owner.finalize())
        [match] = found
        assert match.proposed_lane == 'lead' and owner.missing_required == 0
        assert zl.SERVER in match.claim and zl.CLIENT in match.claim
    finally:
        owner.release_state()


def test_missing_direction_is_unresolved_but_pe_rows_need_no_connection():
    owner = detector()
    try:
        list(owner.consume([every_shape(zl.PE)['plain'], every_shape(PE.without('is_orig'))['plain']]))
        assert list(owner.finalize()) == []
        assert owner.missing_required == 1
        assert 'direction' in ' '.join(owner.limit_reasons() + owner.coverage_notes())
    finally:
        owner.release_state()


@pytest.mark.parametrize('order', list(itertools.permutations(range(3))))
@pytest.mark.parametrize('shape', SHAPES)
def test_pe_analyzer_supplies_type_with_sensor_fuid_join(order, shape):
    rows = [PE.with_(mime_type='application/octet-stream'), HTTP, zl.PE.with_(id=zl.FUID_HTTP)]
    [match] = run([rows[i] for i in order], shape)
    assert match.proposed_lane == 'lead' and any(e.get('pe.is_exe') is True for e in match.events)


@pytest.mark.parametrize('change', [{'resp_fuids': ['Fother']}, {'uid': 'Cother'},
                                    {'id.orig_h': '10.0.0.99'}, {'id.resp_h': '203.0.113.99'}])
def test_unrelated_http_context_cannot_supply_host_uri_or_port(change):
    owner = detector()
    try:
        for row in [PE.with_(filename='payload'), HTTP.with_(**change)]:
            list(owner.consume([every_shape(row)['plain']]))
        assert list(owner.finalize()) == []
        assert 'HTTP' in ' '.join(owner.limit_reasons())
    finally:
        owner.release_state()


@pytest.mark.parametrize('port,host,lane', [(80, 'updates.example.test', 'context'),
                                          (8080, 'updates.example.test', 'lead'),
                                          (80, '[2001:db8::10]:80', 'lead')])
def test_http_standard_port_and_named_host_context(port, host, lane):
    [match] = run([PE.with_(**{'id.resp_p': port}), HTTP.with_(host=host, **{'id.resp_p': port})])
    assert match.proposed_lane == lane


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('share,lane', [(r'\\DC01\packages', 'lead'), (r'\\DC01\ADMIN$', None),
                                       (r'\\DC01\C$', None), (r'\\DC01\IPC$', None)])
def test_smb_nonadmin_lateral_and_admin_share_no_double_report(shape, share, lane):
    files = PE.with_(fuid=zl.FUID_SMB, uid=zl.UID_SMB, source='SMB', is_orig=True,
                     **{'id.resp_h': zl.DC, 'id.resp_p': 445})
    found = run([files, zl.SMB_FILES.with_(path=share)], shape)
    assert [match.proposed_lane for match in found] == ([] if lane is None else [lane])


def test_receiver_sender_type_fold_counts_first_last_and_duplicates():
    rows = [PE, HTTP]
    for i in range(1, 5):
        rows += [replace(PE.with_(fuid=f'Fmore{i}'), ts=zl.T0+i),
                 replace(HTTP.with_(resp_fuids=[f'Fmore{i}'], trans_depth=i+1), ts=zl.T0+i)]
    [match] = run(rows + rows[:2])
    assert '5 files' in match.claim
    assert min(e.ts.timestamp() for e in match.events) == pytest.approx(zl.T0)
    assert max(e.ts.timestamp() for e in match.events) == pytest.approx(zl.T0+4)
    assert len(match.events) <= 6


def test_disk_refusal_names_partial_coverage(monkeypatch):
    owner = detector()
    try:
        owner.rows.store()
        monkeypatch.setattr(owner.rows, 'room', lambda: False)
        assert list(owner.consume([every_shape(PE)['plain']])) == []
        assert owner.capped and 'disk' in ' '.join(owner.limit_reasons()).lower()
    finally:
        owner.release_state()


def test_direction_is_never_guessed_from_source_ip():
    event = every_shape(PE)['plain']
    event.fields['file.is_orig'] = fv(None, 'test:unknown')
    owner = detector()
    try:
        assert list(owner.consume([event])) == []
        assert owner.missing_required == 1
    finally:
        owner.release_state()


def test_real_physical_disk_budget_refusal_is_partial(tmp_path):
    from romulus.detect.bounded import StateBudget
    owner = detector()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=1, reserve=0, reserve_floor=0)
    try:
        assert not list(owner.consume([every_shape(PE)['plain']]))
        assert owner.limit_reasons()
    finally:
        owner.release_state()


def test_many_transfer_groups_are_on_disk_and_first_last_witnesses_stay_bounded():
    owner = detector()
    try:
        for i in range(600):
            files = every_shape(PE.with_(fuid=f'Fvolume{i}', filename='photo.jpg'))['plain']
            matches = list(owner.consume([files]))
            assert len(matches) == 1 and len(matches[0].events) <= 3
        assert owner.rows.store().execute('SELECT COUNT(*) FROM transfer_files').fetchone()[0] == 600
        assert owner.rows.store().execute('SELECT COUNT(*) FROM transfer_verdict').fetchone()[0] == 600
        assert not list(owner.finalize())
        assert not getattr(owner, 'groups', {})
    finally:
        owner.release_state()


def test_promoted_context_then_new_receiver_context_keeps_correct_first_last():
    files = replace(PE.with_(fuid='Fsecond'), ts=zl.T0+5)
    http = replace(HTTP.with_(host='updates.example.test', resp_fuids=['Fsecond'], trans_depth=3), ts=zl.T0+5)
    matches = run([PE, HTTP.with_(host='updates.example.test'),
                   HTTP.with_(uri='/photo.jpg', trans_depth=2), files, http])
    [context] = [match for match in matches if match.proposed_lane == 'context']
    assert '1 file' in context.claim
    assert {event.get('file.fuid') for event in context.events if event.family == 'file_transfer'} == {'Fsecond'}
    assert min(event.ts.timestamp() for event in context.events) == pytest.approx(zl.T0+5)


def test_fresh_replay_prefix_cannot_lower_published_count_or_masquerade_lane():
    from romulus.hunt.publish import publish_match
    from tests.test_report import _repo_with_finding
    from tests.test_zeek_windows_protocols import normalize

    logical = []
    for i in range(4):
        logical += [replace(PE.with_(fuid=f'Freplay{i}', filename='photo.jpg' if i == 3 else 'payload.exe'), ts=zl.T0+i),
                    replace(HTTP.with_(resp_fuids=[f'Freplay{i}'], trans_depth=i+1), ts=zl.T0+i)]
    native = [zl.plain(row, nid=f'transfer-replay-{i}') for i, row in enumerate(logical)]
    sources = {hit['_index'] + '/' + hit['_id']: hit['_source'] for hit in native}
    repo, _ = _repo_with_finding()
    for hits in (native, native[:4]):
        owner = detector()
        try:
            for hit in hits:
                for match in owner.consume([normalize(hit)]):
                    publish_match(repo, 'h1', owner, match, None, sources)
        finally:
            owner.release_state()
    [saved] = [candidate for candidate in repo.candidates('h1') if candidate['rule_id'] == 'net.executable_transfer']
    assert saved['lane'] == 'high' and '4 files' in saved['claim']
