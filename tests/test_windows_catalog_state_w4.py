"""Native Windows catalog signals, including correlation through real Sweep publication."""
import importlib
import importlib.util
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from romulus.hunt import sweep as sw
from romulus.sources.models import Window
from tests.test_sweep import _complete, _repo
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

START = datetime(2026, 1, 2, tzinfo=UTC)
RDP = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS'
CHANNEL = RDP + '/Operational'


def rule_type(name):
    module = 'romulus.detect.windows_catalog_state'
    assert importlib.util.find_spec(module), 'Catalog correlation rules have not been implemented'
    return getattr(importlib.import_module(module), name)


def native(code, data, n=1, *, provider=SECURITY, channel='Security', activity=None, offset=0, host='host.example.test'):
    rule_type('MssqlLoginBruteforce')
    record = LogicalWindowsEvent(channel, provider, code, host, n,
                                 (START + timedelta(seconds=offset)).isoformat(), data)
    hit = windows_hit(record, 'winlogbeat_8')
    payload = hit['_source']['winlog']
    payload['event_id'] = str(code)
    payload.pop('time_created', None)
    if activity:
        payload['activity_id'] = activity
    event = normalize_windows(hit)
    return event, hit


def sweep_run(tmp_path, monkeypatch, name, batches):
    rule = rule_type(name)()
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [rule])
    sweep = sw.Sweep(_repo(), None, 'h1', Window(start=START, end=START + timedelta(hours=1)), {}, stage_dir=tmp_path)
    try:
        for batch in batches:
            monkeypatch.setattr(sw, 'execute', lambda client, intent, contract, batch=batch:
                                _complete(intent, [hit for _, hit in batch]))
            sweep.run_partition(batch[0][1]['_index'], None, [], Window(start=START, end=START + timedelta(hours=1)), est=len(batch))
        sweep.finalize()
        return sweep.repo.candidates('h1'), rule
    finally:
        sweep.close_stage()


def sql(n, *, account='sa', ip='192.0.2.1', offset=None):
    return native(18456, {'param1': account, 'param2': 'Password did not match',
                         'param3': f'[CLIENT: {ip}]' if ip else '-'}, n,
                  provider='MSSQLSERVER', channel='Application', offset=n if offset is None else offset)


def test_sql_threshold_and_partition_replay_are_real_sweep_findings(tmp_path, monkeypatch):
    events = [sql(n) for n in range(1, 13)]
    findings, _ = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce', [events[:6], events[6:]])
    assert len(findings) == 1 and findings[0]['lane'] == 'high'
    assert '300' in findings[0]['claim'] and findings[0]['event_ids']


@pytest.mark.parametrize('gate', ['sa', 'breadth'])
@pytest.mark.parametrize('arrival', ['one_batch', 'partitioned', 'late_archive'])
def test_sql_qualifying_login_older_than_latest_ten_is_cited(tmp_path, monkeypatch, gate, arrival):
    deciding = ([sql(1, account='sa')] if gate == 'sa' else
                [sql(1, account='first'), sql(2, account='second')])
    records = deciding + [sql(n, account='client') for n in range(3, 15)]
    if arrival == 'one_batch':
        batches = [records]
    elif arrival == 'partitioned':
        batches = [deciding, records[len(deciding):8], records[8:]]
    else:
        # The future unrelated client moves the retained window into archive;
        # its deciding older record(s) then arrive late into that same archive.
        batches = [records[len(deciding):], [sql(100, account='unrelated', ip='192.0.2.99', offset=1000)], deciding]
    findings, _ = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce', batches)
    [finding] = [row for row in findings if set(row['event_ids']) & {event.id for event, _ in records}]
    cited = [event for event, _ in records if event.id in finding['event_ids']]
    accounts = {event.get('db.login.name') for event in cited}
    assert finding['lane'] == 'high'
    assert 'sa' in accounts if gate == 'sa' else len(accounts) >= 3
    assert len(cited) == 10
    assert max(event.ts for event in cited) - min(event.ts for event in cited) <= timedelta(seconds=300)
    assert all(event.fields['db.login.name'].origin for event in cited)
    if arrival != 'one_batch':
        assert 'Authentication witness body not retrieved' in finding['claim']


def test_sql_eight_distinct_gate_keeps_all_native_breadth_witnesses(tmp_path, monkeypatch):
    records = [sql(n, account=f'login{n}') for n in range(8)]
    [finding], _ = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce', [records])
    cited = [event for event, _ in records if event.id in finding['event_ids']]
    assert finding['lane'] == 'high' and len(cited) == 8
    assert len({event.get('db.login.name') for event in cited}) == 8


@pytest.mark.parametrize('gate', ['sa', 'breadth'])
def test_sql_deciding_login_outside_the_count_window_does_not_raise(tmp_path, monkeypatch, gate):
    deciding = ([sql(1, account='sa', offset=0)] if gate == 'sa' else
                [sql(1, account='first', offset=0), sql(2, account='second', offset=1)])
    retries = [sql(n, account='client', offset=400+n) for n in range(3, 15)]
    [finding], _ = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce', [deciding, retries])
    assert finding['lane'] == 'lead'


@pytest.mark.parametrize('accounts,count,expected', [(False, 3, 'lead'), (True, 8, 'high')])
def test_sql_breadth_and_low_count(tmp_path, monkeypatch, accounts, count, expected):
    events = [sql(n, account=f'user{n}' if accounts else 'sa') for n in range(count)]
    findings, _ = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce', [events])
    assert len(findings) == 1 and findings[0]['lane'] == expected


@pytest.mark.parametrize('code,data,name,lane', [
    (148, {'ChannelName': 'ms_t120', 'TunnelID': '0'}, 'RdpBluekeepChannel', 'high'),
    (168, {'MonitorWidth': '200', 'MonitorHeight': '200'}, 'RdpHeadlessClient', 'lead'),
])
def test_rdp_context_join_and_positive_survival(tmp_path, monkeypatch, code, data, name, lane):
    connection = native(131, {'ClientIP': '[192.0.2.8]:44333'}, provider=RDP, channel=CHANNEL, activity='a')
    signal = native(code, data, 2, provider=RDP, channel=CHANNEL, activity='a', offset=1)
    findings, _ = sweep_run(tmp_path, monkeypatch, name, [[connection], [signal]])
    assert len(findings) == 1 and findings[0]['lane'] == lane
    assert '192.0.2.8' in findings[0]['claim'] and 'correlat' in findings[0]['claim'].lower()
    assert {connection[0].id, signal[0].id} <= set(findings[0]['event_ids'])


def test_rdp_connection_arriving_late_adds_cited_context_without_losing_positive(tmp_path, monkeypatch):
    connection = native(131, {'ClientIP': '192.0.2.8:44333'}, provider=RDP, channel=CHANNEL, activity='a')
    observed = native(148, {'ChannelName': 'ms_t120', 'TunnelID': '0'}, 2,
                      provider=RDP, channel=CHANNEL, activity='a', offset=1)
    findings, _ = sweep_run(tmp_path, monkeypatch, 'RdpBluekeepChannel', [[observed], [connection]])
    assert len(findings) == 1 and findings[0]['lane'] == 'high'
    assert '192.0.2.8' in findings[0]['claim']
    assert {connection[0].id, observed[0].id} <= set(findings[0]['event_ids'])


def test_sql_refused_history_still_reports_native_failed_login(monkeypatch):
    rule = rule_type('MssqlLoginBruteforce')()
    monkeypatch.setattr(rule.rows, 'put', lambda *args: False)
    try:
        [match] = rule.consume([sql(1)[0]])
        assert match.proposed_lane == 'lead' and match.events[0].id == sql(1)[0].id
        assert rule.limits
    finally:
        rule.release_state()


def test_computed_sql_high_survives_missing_compact_witnesses(monkeypatch):
    from tests.test_windows_auth_round5 import publish
    rule, repo = rule_type('MssqlLoginBruteforce')(), _repo()
    events = [sql(n)[0] for n in range(12)]
    try:
        initial = rule.consume(events)
        assert any(match.proposed_lane == 'high' for match in initial)
        monkeypatch.setattr(rule.rows, 'compact', lambda ids: [])
        matches = list(rule.finalize())
        assert len(matches) == 1 and matches[0].proposed_lane == 'high'
        assert matches[0].citation_unavailable and not matches[0].events
        assert matches[0].ts == events[-1].ts
        publish(repo, rule, matches[0])
        [stored] = repo.candidates('h1')
        assert stored['lane'] == 'high' and not stored['event_ids']
    finally:
        rule.release_state()


def test_rdp_finalize_streams_native_findings():
    rule = rule_type('RdpBluekeepChannel')()
    events = [native(148, {'ChannelName': 'ms_t120', 'TunnelID': '0'}, n,
                     provider=RDP, channel=CHANNEL, host=f'host{n}.example.test')[0] for n in range(30)]
    staged = {}
    rule.load = lambda ids: [staged[key] for key in ids if key in staged]
    try:
        rule.consume(events)
        staged.update((event.id, event) for event in rule.drain_staged())
        final = rule.finalize()
        assert iter(final) is final
        first = next(final)
        assert first.proposed_lane == 'high'
        assert {event.id for event in first.events} <= {event.id for event in events}
        final.close()
    finally:
        rule.release_state()


def test_sql_real_physical_full_keeps_the_native_positive(tmp_path):
    from romulus.detect.bounded import StateBudget
    rule = rule_type('MssqlLoginBruteforce')()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=16384, reserve=0)
    try:
        matches = rule.consume([sql(1)[0]])
        assert matches and matches[0].proposed_lane == 'lead'
        assert rule.limits
        assert sum(path.stat().st_size for path in tmp_path.rglob('*') if path.is_file()) <= 16384
    finally:
        rule.release_state()


def test_rdp_real_physical_context_refusal_preserves_channel_positive(tmp_path):
    from romulus.detect.bounded import StateBudget
    rule = rule_type('RdpBluekeepChannel')()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=16384, reserve=0)
    connection = native(131, {'ClientIP': '192.0.2.8:44333'}, provider=RDP, channel=CHANNEL, activity='a')[0]
    observed = native(148, {'ChannelName': 'ms_t120', 'TunnelID': '0'}, 2,
                      provider=RDP, channel=CHANNEL, activity='a', offset=1)[0]
    try:
        matches = rule.consume([connection, observed])
        assert any(match.proposed_lane == 'high' for match in matches)
        assert rule.limits
        assert sum(path.stat().st_size for path in tmp_path.rglob('*') if path.is_file()) <= 16384
    finally:
        rule.release_state()


@pytest.mark.parametrize('missing_ip', [False, True])
def test_sql_window_and_absent_source_do_not_invent_concentration(tmp_path, monkeypatch, missing_ip):
    events = [sql(n, ip='' if missing_ip else '192.0.2.1', offset=n * 600) for n in range(12)]
    findings, _ = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce', [events])
    assert len(findings) == 1 and findings[0]['lane'] == 'lead'


@pytest.mark.slow
def test_ten_thousand_native_sql_failures_use_disk_history_and_bounded_citations(tmp_path, monkeypatch):
    events = [sql(n, offset=n / 100) for n in range(10000)]
    findings, rule = sweep_run(tmp_path, monkeypatch, 'MssqlLoginBruteforce',
                               [events[start:start + 100] for start in range(0, len(events), 100)])
    assert len(findings) == 1 and findings[0]['lane'] == 'high'
    assert '10000 failed-login' in findings[0]['claim']
    assert len(findings[0]['event_ids']) <= 10
    assert len(rule.rows._symbol_cache) <= 8192


@pytest.mark.parametrize('accounts', [['app'], ['sa'], ['a', 'b', 'c']])
def test_sql_breadth_and_sa_gates_do_not_rescan_the_window_for_in_order_records(tmp_path, monkeypatch, accounts):
    # A sustained single-login or sa burst must stay linear: the gates read tracked state,
    # never a distinct scan or sa lookup of the whole window per record.
    rule = rule_type('MssqlLoginBruteforce')()
    scans = []
    original = rule.rows.witnesses
    monkeypatch.setattr(rule.rows, 'witnesses', lambda key, end, seconds, count, **kw:
                        scans.append(count) if count == 3 else None or original(key, end, seconds, count, **kw))
    monkeypatch.setattr(rule.rows, '_execute', lambda *a, original=rule.rows._execute: (
        scans.append('sa') if 'value=?' in a[0] and 'ts>=?' in a[0] else None) or original(*a))
    try:
        events = [sql(n, account=accounts[n % len(accounts)], offset=n / 200)[0] for n in range(600)]
        matches = [match for start in range(0, 600, 100) for match in rule.consume(events[start:start + 100])]
        matches += list(rule.finalize())
        assert scans == []
        assert {match.proposed_lane for match in matches} >= ({'lead'} if accounts == ['app'] else {'high'})
    finally:
        rule.release_state()


def seed_snapshot():
    """Whole subprocess entry point; no source or fixture is extracted into executable fragments."""
    import json
    import tempfile
    from pathlib import Path

    from pytest import MonkeyPatch
    with tempfile.TemporaryDirectory() as directory, MonkeyPatch.context() as patch:
        findings, _ = sweep_run(Path(directory), patch, 'MssqlLoginBruteforce',
                                 [[sql(n, account=f'user{n % 8}') for n in range(32)]])
        print(json.dumps([{name: row[name] for name in ('id', 'claim', 'lane', 'event_ids', 'group_key')}
                          for row in findings], sort_keys=True))


def test_sql_storage_full_result_is_hash_seed_independent():
    import os
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    outputs = []
    for seed in ('0', '2', '6'):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=os.pathsep.join((str(root/'src'), str(root))))
        outputs.append(subprocess.check_output([sys.executable, str(Path(__file__).resolve()), 'seed'],
                                              cwd=root, env=environment, text=True))
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.parametrize('code,data,name', [
    (148, {'ChannelName': 'rdpdr', 'TunnelID': '0'}, 'RdpBluekeepChannel'),
    (148, {'ChannelName': 'ms_t120', 'TunnelID': '1'}, 'RdpBluekeepChannel'),
    (168, {'MonitorWidth': '1920', 'MonitorHeight': '1080'}, 'RdpHeadlessClient'),
    (168, {'MonitorWidth': 'bad', 'MonitorHeight': '200'}, 'RdpHeadlessClient'),
])
def test_rdp_hard_negatives_and_malformed(tmp_path, monkeypatch, code, data, name):
    findings, _ = sweep_run(tmp_path, monkeypatch, name, [[native(code, data, provider=RDP, channel=CHANNEL)]])
    assert not findings


def test_wfp_loopback_is_native_high_and_system_client_is_negative(tmp_path, monkeypatch):
    data = {'Application': r'C:\Users\alice\plink.exe', 'DestAddress': '127.0.0.2', 'DestPort': '3389',
            'SourceAddress': '127.0.0.1', 'SourcePort': '2000', 'Direction': '%%14593', 'Protocol': '6'}
    findings, _ = sweep_run(tmp_path, monkeypatch, 'RdpLoopbackTunnel', [[native(5156, data)]])
    assert findings and findings[0]['lane'] == 'high'
    data['Application'] = r'C:\Windows\System32\mstsc.exe'
    findings, _ = sweep_run(tmp_path / 'negative', monkeypatch, 'RdpLoopbackTunnel', [[native(5156, data)]])
    assert not findings


def test_sam_enum_folds_but_machine_accounts_do_not_match(tmp_path, monkeypatch):
    data = {'TargetSid': 'S-1-5-32-544', 'TargetUserName': 'Administrators',
            'SubjectUserName': 'alice', 'SubjectDomainName': 'EXAMPLE', 'CallerProcessName': r'C:\Windows\System32\net1.exe'}
    findings, _ = sweep_run(tmp_path, monkeypatch, 'SamAdminEnumeration', [[native(4799, data, n) for n in range(3)]])
    assert len(findings) == 1 and findings[0]['lane'] == 'lead'
    data['SubjectUserName'] = 'HOST$'
    findings, _ = sweep_run(tmp_path / 'machine', monkeypatch, 'SamAdminEnumeration', [[native(4799, data)]])
    assert not findings


def test_sam_writable_caller_keeps_each_hosts_first_finding(tmp_path, monkeypatch):
    data = {'TargetSid': 'S-1-5-32-544', 'TargetUserName': 'Administrators',
            'SubjectUserName': 'alice', 'CallerProcessName': r'C:\Users\alice\tool.exe'}
    events = [native(4799, data, n, host=f'host{n}.example.test') for n in range(2)]
    findings, _ = sweep_run(tmp_path, monkeypatch, 'SamAdminEnumeration', [events])
    assert len(findings) == 2


def test_denied_sam_handle_request_never_claims_completed_enumeration(tmp_path, monkeypatch):
    _, hit = native(4661, {'SubjectUserName': 'alice', 'ObjectServer': 'Security Account Manager',
                          'ObjectType': 'SAM_USER', 'ObjectName': 'S-1-5-21-1-2-3-500',
                          'Status': '0xC0000022', 'AccessMask': '0x1'})
    hit['_source']['winlog']['keywords'] = ['Audit Failure']
    event = normalize_windows(hit)
    assert event.outcome.value == 'failure'
    findings, _ = sweep_run(tmp_path, monkeypatch, 'SamAdminEnumeration', [[(event, hit)]])
    assert len(findings) == 1 and findings[0]['lane'] == 'lead'
    assert 'refused' in findings[0]['claim'] and 'handle request' in findings[0]['claim']
    assert 'enumerated privileged' not in findings[0]['claim']


@pytest.mark.parametrize('sid', ['S-1-not-a-sid-544', 'S-1-0-0', '-', 'S-1-5-32-545'])
def test_malformed_or_unprivileged_sam_target_is_not_called_privileged(tmp_path, monkeypatch, sid):
    event = native(4799, {'SubjectUserName': 'alice', 'TargetSid': sid})
    findings, _ = sweep_run(tmp_path, monkeypatch, 'SamAdminEnumeration', [[event]])
    assert not findings


if __name__ == '__main__':
    import sys
    assert sys.argv[1:] == ['seed']
    seed_snapshot()
