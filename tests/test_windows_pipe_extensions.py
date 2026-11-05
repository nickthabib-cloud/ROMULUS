"""Nested pipe creation, renamed service streams and exact management endpoints."""
import pytest

from romulus.detect import windows_endpoint_events as endpoint
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.windows_event_support import START, event, run
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def rule(rule_id):
    found = [cls for cls in endpoint.WINDOWS_ENDPOINT_PLAYBOOKS if cls.id == rule_id]
    assert len(found) == 1, f'{rule_id} must be exported for the sweep'
    return found[0]()


def pipe(name, code=17, **fields):
    return event('pipe_event', code, **{'pipe.name': name, 'pipe.action': 'created' if code == 17 else 'connected',
                                    'process.executable': r'C:\Users\alice\agent.exe', 'process.pid': 1024, **fields})


@pytest.mark.parametrize('name', [r'\synthetic-guid\pipe\spoolss', r'\RoguePotato\pipe\epmapper',
    r'\\.\pipe\synthetic-guid\pipe\srvsvc', r'\??\pipe\rogue\PIPE\epmapper',
    r'\Device\NamedPipe\rogue\pipe\spoolss', r'\PIPE\rogue\pipe\spoolss',
    r'\\?\pipe\rogue\pipe\spoolss'])
def test_nested_pipe_creation_is_high_with_recorded_user_process(name):
    [hit] = rule('win.potato_pipe_created').judge(pipe(name))
    assert hit.lane == 'high' and hit.attack == ('T1134.001',)
    assert any(p.field == 'process.pid' and p.value == 1024 for p in hit.predicate)
    assert any('actor' in note.lower() and 'not recorded' in note.lower() for note in hit.notes)


@pytest.mark.parametrize('fields', [{'process.pid': 4}, {'process.executable': 'System'},
    {'process.executable': r'\\?\C:\Windows\System32\System'}, {'process.pid': None},
    {'process.executable': ''}, {'process.executable': None}])
def test_kernel_system_or_unresolved_process_does_not_support_potato_high(fields):
    assert rule('win.potato_pipe_created').judge(pipe(r'\rogue\pipe\spoolss', **fields)) == []


@pytest.mark.parametrize('name,code', [(r'\rogue\pipe\spoolss', 18), (r'\spoolss', 17),
    (r'\\.\pipe\spoolss', 17), (r'C:\temp\rogue\pipe\spoolss', 17),
    (r'\rogue\pipeline\spoolss', 17), ('\\rogue\\pipe\\', 17), (r'\pipe\spoolss', 17),
    (r'\rogue/pipe/spoolss', 17), (r'\\server\pipe\spoolss', 17)])
def test_nested_pipe_requires_creation_and_embedded_component(name, code):
    assert rule('win.potato_pipe_created').judge(pipe(name, code)) == []


def test_recorded_actor_is_cited_without_inventing_identity():
    [hit] = rule('win.potato_pipe_created').judge(pipe(r'\rogue\pipe\spoolss', **{'user.name': 'alice'}))
    assert any(p.field == 'user.name' and p.value == 'alice' for p in hit.predicate)
    assert not any('not recorded' in note for note in hit.notes)


@pytest.mark.parametrize('code', [17, 18])
@pytest.mark.parametrize('name', [r'\custom-HOST-123-stdin', r'\\.\pipe\svc-name-HOST-A-1-STDOUT',
    r'\Device\NamedPipe\tool-computer-800-stderr', r'\??\pipe\x-host-3-stdin'])
def test_renamed_psexec_streams_are_high(code, name):
    [hit] = rule('win.renamed_psexec_pipe').judge(pipe(name, code))
    assert hit.lane == 'high' and hit.attack == ('T1569.002',)
    assert 'does not establish' in ' '.join(hit.notes)


@pytest.mark.parametrize('name', [r'\PSEXESVC-host-2-stdin', r'\custom-host-x-stdin',
    r'\custom-host-1-stdin.txt', r'\custom-host-1-stdin\child', r'\host-1-stdin',
    r'C:\custom-host-1-stdin', r'\custom--1-stdin', r'\-host-1-stdin',
    r'\custom-host-1-stdinx', r'\custom-host-0-stdout'])
def test_renamed_psexec_rejects_default_and_partial_stream_templates(name):
    assert rule('win.renamed_psexec_pipe').judge(pipe(name)) == []


def test_pipe_mentions_and_other_event_codes_do_not_match():
    for rule_id in ('win.potato_pipe_created', 'win.renamed_psexec_pipe'):
        assert rule(rule_id).judge(event('pipe_event', 17, **{'process.command_line': r'echo \rogue\pipe\spoolss'})) == []
        assert rule(rule_id).judge(pipe(r'\custom-host-1-stdin', 11)) == []


@pytest.mark.parametrize('name', [r'\kekeo_tsssp_endpoint', r'\\.\pipe\KEKEO_TSSSP_ENDPOINT'])
def test_kekeo_documented_default_keeps_lead_and_kerberos_mapping(name):
    [hit] = endpoint.ToolNamedPipe().judge(pipe(name))
    assert hit.lane == 'lead' and hit.attack == ('T1558',)


@pytest.mark.parametrize('name', [r'\kekeo_tsssp_endpoint_extra', r'\prefix_kekeo_tsssp_endpoint',
    r'\kekeo_tsssp_endpoint\child'])
def test_kekeo_name_matches_exactly(name):
    assert endpoint.ToolNamedPipe().judge(pipe(name)) == []


@pytest.mark.parametrize('name,attack', [('spoolss', ('T1187',)), ('efsrpc', ('T1187',)),
    ('protected_storage', ('T1555',)), ('netlogon', ('T1021.002',))])
@pytest.mark.parametrize('prefix', ['', '\\PIPE\\', '\\\\.\\pipe\\'])
def test_new_management_pipe_names_are_leads_with_precise_mapping(name, attack, prefix):
    ev = event('share_access', 5145, **{'share.name': r'\\*\IPC$', 'share.relative_target': prefix + name.upper(),
                                     'share.access_mask': 1})
    [hit] = endpoint.RemoteManagementPipe().judge(ev)
    assert hit.lane == 'lead' and hit.attack == attack


@pytest.mark.parametrize('name', ['spoolss.bak', 'efsrpc_more', r'x\protected_storage', 'xnetlogon'])
def test_new_management_names_reject_neighbors(name):
    ev = event('share_access', 5145, **{'share.name': r'\\*\IPC$', 'share.relative_target': name})
    assert endpoint.RemoteManagementPipe().judge(ev) == []


def test_native_pipe_record_reaches_sweep_rule_without_actor_guesses():
    logical = LogicalWindowsEvent(event_id=17, provider=SYSMON, channel=SYSMON_CHANNEL,
        computer='ws01', record_id=17, timestamp=START.isoformat(),
        data={'PipeName': r'\synthetic\pipe\spoolss', 'ProcessId': '1920',
              'Image': r'C:\Users\alice\tool.exe'})
    native = windows_hit(logical, 'winlogbeat_8')
    typed = normalize_windows(native)
    matches = run(rule('win.potato_pipe_created'), [typed])
    assert matches and matches[0].proposed_lane == 'high'

@pytest.mark.parametrize('rule_id,name,lane,attack', [
    ('win.renamed_psexec_pipe', r'\\?\pipe\custom-host-1-stdin', 'high', ('T1569.002',)),
    ('win.tool_named_pipe', r'\\?\pipe\KEKEO_TSSSP_ENDPOINT', 'lead', ('T1558',)),
])
def test_extended_local_pipe_namespace_preserves_exact_template_detection(rule_id, name, lane, attack):
    [hit] = rule(rule_id).judge(pipe(name))
    assert hit.lane == lane and hit.attack == attack
