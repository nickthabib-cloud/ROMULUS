"""Real BITS field aliases retain producer provenance and canonical creator paths."""
import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import BITS_CHANNEL, BITS_PROVIDER
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


@pytest.mark.parametrize('shape', ['winlogbeat_7', 'winlogbeat_8', 'elastic_agent'])
def test_bits_native_creator_path_is_canonical_and_owner_is_not_provider_user(shape):
    data = {'jobTitle': 'job', 'jobOwner': r'EXAMPLE\alice', 'processPath': r'\\?\C:\Users\Alice\download.EXE',
            'processId': '42', 'jobId': '{00000000-0000-0000-0000-000000000001}'}
    event = normalize_windows(windows_hit(LogicalWindowsEvent(BITS_CHANNEL, BITS_PROVIDER, 3,
        'host', 1, '2026-01-02T03:00:00Z', data), shape))
    assert event.get('bits.process_path_key') == r'c:\users\alice\download.exe'
    assert event.get('bits.owner') == r'EXAMPLE\alice'
    assert event.get('bits.process_id') == 42
    assert event.fields['bits.process_path_key'].origin.startswith(event.fields['bits.process_path'].origin)


@pytest.mark.parametrize('code,data,expected', [
    (3, {'string': 'old job', 'string2': r'EXAMPLE\alice'}, {'bits.job_name': 'old job', 'bits.owner': r'EXAMPLE\alice'}),
    (59, {'url': r'C:\Windows\System32\cmd.exe'}, {'bits.remote_url': r'C:\Windows\System32\cmd.exe', 'bits.url_scheme': 'file'}),
    (60, {'url': r'\\host\share\payload.exe'}, {'bits.remote_url': r'\\host\share\payload.exe', 'bits.url_scheme': 'unc'}),
])
def test_win7_and_lowercase_transfer_fields_are_typed_without_inventing_a_creator(code, data, expected):
    event = normalize_windows(windows_hit(LogicalWindowsEvent(BITS_CHANNEL, BITS_PROVIDER, code,
        'host', 1, '2026-01-02T03:00:00Z', data), 'winlogbeat_8'))
    assert {name: event.get(name) for name in expected} == expected
    assert not event.has('bits.process_path_key')
