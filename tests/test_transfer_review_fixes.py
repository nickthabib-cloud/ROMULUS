"""Transfer review regressions: administrative shares, reads, compact joins and weak MIME."""
import itertools
from dataclasses import replace

import pytest

from romulus.detect.zeek_transfer import ExecutableTransfer
from romulus.evidence.typed import fv
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_transfer import HTTP, PE
from tests.test_zeek_windows_protocols import every_shape


def smb_file(mime, *, name='run.bat', is_orig=True):
    return zl.FILES.with_(fuid=zl.FUID_SMB, uid=zl.UID_SMB, source='SMB', mime_type=mime,
        filename=name, is_orig=is_orig, **{'id.resp_h': zl.DC, 'id.resp_p': 445})


def run(events):
    owner = ExecutableTransfer()
    found = {}
    try:
        for event in events:
            for match in owner.consume([event]):
                found[match.group_key] = match
        for match in owner.finalize():
            found[match.group_key] = match
        return list(found.values()), owner.limit_reasons()
    finally:
        owner.release_state()


@pytest.mark.parametrize('mime,name', [('text/x-msdos-batch', 'run.bat'), ('text/x-shellscript', 'x.sh'),
                                     ('application/x-executable', 'implant'), ('text/x-python', 'x.py')])
@pytest.mark.parametrize('share', [r'\\DC01\ADMIN$', r'\\DC01\C$', r'\\DC01\IPC$', r'\\DC01\X$'])
@pytest.mark.parametrize('reverse', [False, True])
def test_uncovered_executable_admin_share_writes_are_high(mime, name, share, reverse):
    records = [every_shape(smb_file(mime, name=name))['plain'],
               every_shape(zl.SMB_FILES.with_(path=share, name='Temp\\' + name))['plain']]
    found, limits = run(records[::-1] if reverse else records)
    [match] = found
    assert match.proposed_lane == 'high' and 'admin-share' in match.claim
    assert any(field.field == 'smb.share' for field in match.predicate)
    assert not any('lack matching' in text for text in limits)


@pytest.mark.parametrize('shape', ('malcolm', 'elastic', 'security_onion', 'plain'))
@pytest.mark.parametrize('share,mime,name,lane', [
    (r'\\DC01\C$', 'application/x-dosexec', 'app.exe', 'lead'),
    (r'\\DC01\ADMIN$', 'text/x-shellscript', 'x.sh', 'lead'),
    (r'\\DC01\NETLOGON', 'text/x-msdos-batch', 'logon.bat', 'context'),
    (r'\\FS01\apps', 'application/x-dosexec', 'app.exe', 'context'),
])
def test_typed_reads_keep_administrative_lead_and_routine_context(shape, share, mime, name, lane):
    events = [every_shape(smb_file(mime, name=name, is_orig=False))[shape],
              every_shape(zl.SMB_FILES.with_(path=share, name=name))[shape]]
    [match], limits = run(events)
    assert match.proposed_lane == lane and not limits


def test_unknown_smb_direction_is_lead_with_explicit_caveat():
    events = [every_shape(smb_file('text/x-msdos-batch', is_orig=None))['plain'],
              every_shape(zl.SMB_FILES.with_(path=r'\\DC01\NETLOGON', name='logon.bat'))['plain']]
    [match], _limits = run(events)
    assert match.proposed_lane == 'lead'
    assert 'direction not recorded' in ' '.join([match.claim, *match.notes,
        *(note for event in match.events for note in event.caveats)])
    assert 'sent from' not in match.claim


def test_only_covered_pe_admin_write_is_suppressed():
    events = [every_shape(smb_file('application/x-dosexec', name='app.exe'))['plain'],
              every_shape(zl.SMB_FILES.with_(path=r'\\DC01\C$', name='app.exe'))['plain']]
    assert run(events) == ([], [])


@pytest.mark.parametrize('name', ['setup.ini', 'setup.jpg', 'setup.zip'])
def test_setupscript_mime_alone_never_produces_masquerade_high(name):
    events = [every_shape(PE.with_(mime_type='application/x-setupscript', filename=name))['plain'],
              every_shape(HTTP.with_(host='updates.example.test', uri='/' + name))['plain']]
    [match], _limits = run(events)
    assert match.proposed_lane == 'lead' and 'T1036.008' not in match.attack


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('field,encoding,lane', [
    ('http.response.content_encoding', 'gzip', 'lead'),
    ('http.response.content_encoding', None, 'high'),
    ('http.request.content_encoding', 'gzip', 'high'),
])
def test_compression_suffix_is_stripped_only_with_matching_side_encoding(reverse, field, encoding, lane):
    file_event = every_shape(PE.with_(filename='payload.exe.gz'))['plain']
    context = every_shape(HTTP.with_(uri='/payload.exe.gz'))['plain']
    if encoding is not None:
        context.fields[field] = fv(encoding, 'test:typed-content-encoding')
    events = [file_event, context]
    [match], _limits = run(events[::-1] if reverse else events)
    assert match.proposed_lane == lane


@pytest.mark.parametrize('order', list(itertools.permutations(range(3))))
def test_unknown_mime_retains_pending_pe_in_every_order(order):
    events = [every_shape(PE.with_(mime_type=None, filename='payload.jpg'))['plain'],
              every_shape(HTTP)['plain'], every_shape(zl.PE.with_(id=zl.FUID_HTTP))['plain']]
    [match], _limits = run([events[index] for index in order])
    assert match.proposed_lane == 'high' and any(event.get('pe.is_exe') for event in match.events)


def test_context_is_a_typed_tuple_and_has_no_packed_event():
    owner = ExecutableTransfer()
    try:
        assert not list(owner.consume([every_shape(HTTP)['plain']]))
        columns = {row[1]: row[2] for row in owner.rows.store().execute('PRAGMA table_info(transfer_context)')}
        assert 'event' not in columns and columns['facts'] == 'TEXT'
        [(facts,)] = owner.rows.store().execute('SELECT facts FROM transfer_context')
        assert facts.startswith('[') and '"fields"' not in facts
    finally:
        owner.release_state()


@pytest.mark.parametrize('contexts_first', [False, True])
def test_hundred_thousand_benign_pairs_leave_only_dispositions_and_an_embedded_pe(contexts_first):
    owner = ExecutableTransfer()
    files = every_shape(PE.with_(mime_type='text/html', filename='index.html'))['plain']
    context = every_shape(HTTP)['plain']
    total = 100_000
    found = {}

    def rows(context_rows):
        for index in range(total):
            template = context if context_rows else files
            fields = dict(template.fields)
            fields['http.resp_fuids' if context_rows else 'file.fuid'] = fv(
                [f'Fbenign{index}'] if context_rows else f'Fbenign{index}', 'test:fuid')
            if not context_rows:
                fields['file.mime_type'] = fv('image/png' if index % 2 else 'text/html', 'test:sniffed-mime')
            yield template.model_copy(update={'id': f'{"context" if context_rows else "file"}-{index}', 'fields': fields})

    try:
        assert not list(owner.consume([files]))
        assert owner.rows.store().execute('SELECT COUNT(*) FROM transfer_files').fetchone()[0] == 0
        pe_file = every_shape(replace(PE.with_(fuid='Fembedded', filename='photo.jpg'), ts=zl.T0+1))['plain']
        pe_context = every_shape(HTTP.with_(resp_fuids=['Fembedded']))['plain']
        for context_rows in (contexts_first, not contexts_first):
            for event in itertools.chain(rows(context_rows), [pe_context if context_rows else pe_file]):
                for match in owner.consume([event]):
                    found[match.group_key] = match
        for match in owner.finalize():
            found[match.group_key] = match
        [match] = found.values()
        assert match.proposed_lane == 'high' and '1 file' in match.claim
        store = owner.rows.store()
        assert store.execute('SELECT COUNT(*) FROM transfer_files').fetchone()[0] == 1
        assert store.execute('SELECT COUNT(*) FROM transfer_context').fetchone()[0] <= 1
        assert not getattr(owner, 'groups', {})
        assert not owner.capped
    finally:
        owner.release_state()
