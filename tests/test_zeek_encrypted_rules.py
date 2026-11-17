"""Connection-level and Kerberos rules for remote administration, RPC and directory traffic the sensor cannot read,
in every Zeek shipper shape, with the lookalikes they must not report and mission-scale volume."""
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from romulus.detect import netdef
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, SiteNetworks
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.detect.zeek_encrypted import (
    EpmDynamicRpc,
    KerberosServiceTicketFanout,
    LdapBulkResponse,
    RemoteShellFanout,
    SmbRpcFanout,
)
from romulus.detect.zeek_rates import Rc4TgsFanout
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import normalize
from tests.windows_process_support import run

SHAPES = zf.SHAPES
ATTACKER, DC = '10.1.0.66', '10.0.0.10'


def facts(**changes):
    return SimpleNamespace(internal_networks=changes.get('internal_networks', ('10.0.0.0/8',)),
                           external_networks=(), management_hosts=changes.get('management_hosts', ()),
                           domain_controller_addresses=changes.get('domain_controller_addresses', ()),
                           directory_sync_hosts=(), directory_sync_addresses=changes.get('directory_sync_addresses', ()))


@pytest.fixture(autouse=True)
def default_networks():
    netdef.install(SiteNetworks.default())
    yield
    netdef.install(SiteNetworks.default())


def conn(n, dst, port, *, src=ATTACKER, ts=0.0, history='ShADadFf', state='SF', sent=900, received=2400,
         service=None, **changes):
    return zf.Conn(uid=f'Cenc{n:012d}', ts=zf.T0 + ts, orig_h=src, orig_p=50000 + n % 15000, resp_h=dst, resp_p=port,
                   service=service, history=history, conn_state=state, orig_bytes=sent, resp_bytes=received,
                   local_orig=True, local_resp=True, **changes)


def events(rows, shape):
    return [normalize(zf.WRITERS[shape](row, f'{shape}-{n}')) for n, row in enumerate(rows)]


def evaluate(cls, rows, shape='plain', site=None, *, normalized=None):
    rule = cls()
    rule.site_facts = site or facts()
    try:
        observations = normalized if normalized is not None else events(rows, shape)
        matches = run(rule, [[event] for event in observations])
        return matches, rule
    finally:
        rule.release_state()


def lanes(matches):
    return [match.proposed_lane for match in matches]


# ---- registration ------------------------------------------------------------------------------------------------

def test_the_rules_are_registered_positive_only_with_current_attack_ids():
    ids = {pb.id: pb for pb in ALL_PLAYBOOKS}
    for cls in (RemoteShellFanout, SmbRpcFanout, KerberosServiceTicketFanout, EpmDynamicRpc, LdapBulkResponse):
        assert ids[cls.id] is cls
        assert cls.assures_negative is False and cls.positive_only_reason
        assert {'behavior', 'telemetry', 'fidelity', 'benign_and_cost', 'next_pivot', 'adds', 'research_basis',
                'lanes', 'window'} <= set(cls.card), cls.id
    import gzip
    import json
    bundle = json.load(gzip.open('content/attack/enterprise-attack-20.0.json.gz'))
    current = {ref['external_id'] for item in bundle['objects'] if item.get('type') == 'attack-pattern'
               and not item.get('revoked') and not item.get('x_mitre_deprecated')
               for ref in item.get('external_references', []) if ref.get('source_name') == 'mitre-attack'}
    for cls in (RemoteShellFanout, SmbRpcFanout, KerberosServiceTicketFanout, EpmDynamicRpc, LdapBulkResponse):
        assert set(cls.attack) <= current, cls.id


# ---- remote-shell fan-out ------------------------------------------------------------------------------------------

def shells(count, *, spacing=60.0, src=ATTACKER):
    ports = (22, 3389, 5985, 5986)
    return [conn(n, f'10.2.0.{n + 1}', ports[n % 4], src=src, ts=n * spacing) for n in range(count)]


@pytest.mark.parametrize('shape', SHAPES)
def test_four_answered_remote_shell_connections_to_distinct_hosts_are_one_lead(shape):
    [match], _rule = evaluate(RemoteShellFanout, shells(4), shape)
    assert match.proposed_lane == 'lead' and match.severity == 'high'
    assert f'Source {ATTACKER}' in match.claim and 'at least 4 distinct internal hosts' in match.claim
    assert 'not logons' in ' '.join(match.notes)
    assert evaluate(RemoteShellFanout, shells(3), shape)[0] == []


def test_the_ten_minute_window_is_inclusive_at_its_boundary():
    assert lanes(evaluate(RemoteShellFanout, shells(4, spacing=200.0))[0]) == ['lead']       # 600 s span
    assert evaluate(RemoteShellFanout, shells(4, spacing=200.4))[0] == []                    # 601.2 s span


def test_refused_unanswered_and_one_sided_connections_are_never_members():
    syn_only = [conn(n, f'10.2.0.{n}', 22, history='S', state='S0', received=0, sent=0) for n in range(1, 30)]
    refused = [conn(n, f'10.2.1.{n}', 3389, history='Sr', state='REJ', received=0, sent=0) for n in range(1, 30)]
    no_reply_data = [conn(n, f'10.2.2.{n}', 5985, history='ShAF', state='SF', received=0) for n in range(1, 30)]
    midstream = [conn(n, f'10.2.3.{n}', 22, history='DdA', state='OTH') for n in range(1, 30)]
    for rows in (syn_only, refused, no_reply_data, midstream):
        assert evaluate(RemoteShellFanout, rows)[0] == []


def test_one_host_repeatedly_and_other_ports_are_not_fanout():
    again = [conn(n, '10.2.0.9', 22, ts=n) for n in range(40)]
    web = [conn(n, f'10.2.0.{n + 1}', 443, ts=n) for n in range(40)]
    assert evaluate(RemoteShellFanout, again)[0] == [] and evaluate(RemoteShellFanout, web)[0] == []


def test_external_destinations_and_icmp_rows_are_not_counted():
    outside = [conn(n, f'203.0.113.{n + 1}', 22, ts=n) for n in range(10)]
    assert evaluate(RemoteShellFanout, outside)[0] == []
    icmp = [replace(conn(n, f'10.2.0.{n + 1}', 22, ts=n), proto='icmp', history=None) for n in range(10)]
    assert evaluate(RemoteShellFanout, icmp)[0] == []


def test_a_declared_management_source_keeps_its_lead_and_is_named():
    [match], _rule = evaluate(RemoteShellFanout, shells(5), site=facts(management_hosts=(ATTACKER,)))
    assert match.proposed_lane == 'lead' and any('declared management source' in note for note in match.notes)


def test_an_assumed_internal_definition_is_stated_and_counted():
    matches, rule = evaluate(RemoteShellFanout, shells(4), site=facts(internal_networks=()))
    assert lanes(matches) == ['lead'] and DIRECTION_ASSUMED_REASON in matches[0].notes
    assert rule.direction_assumed == 4


@pytest.mark.parametrize('missing', ['history', 'orig_bytes', 'resp_bytes'])
def test_missing_history_or_payload_counts_are_unevaluated_never_a_clean_negative(missing):
    rows = [replace(row, **{missing: None}) for row in shells(6)]
    matches, rule = evaluate(RemoteShellFanout, rows)
    assert matches == [] and rule.missing_required == 6 and rule.evaluated == 0


def test_missing_ports_are_unevaluated():
    rows = [replace(row, resp_p=None) for row in shells(6)]
    hits = [zf.WRITERS['plain'](row, f'p-{n}') for n, row in enumerate(rows)]
    for item in hits:
        item['_source'].pop('id.resp_p', None)
    matches, rule = evaluate(RemoteShellFanout, [], normalized=[normalize(item) for item in hits])
    assert matches == [] and rule.missing_required == 6


def test_repeat_connections_of_a_pair_within_a_minute_are_stored_once_and_still_counted():
    rows = [conn(n, f'10.2.0.{n % 4 + 1}', 22, ts=n * 0.5) for n in range(400)]       # 4 hosts, 200 s
    rule = RemoteShellFanout()
    rule.site_facts = facts()
    try:
        matches = run(rule, [[event] for event in events(rows, 'plain')])
        stored = rule.rows.store().db.execute('SELECT COUNT(*) FROM history').fetchone()[0]
    finally:
        rule.release_state()
    assert lanes(matches) == ['lead'] and stored == 16                                    # one per pair per minute


# ---- SMB / RPC fan-out ---------------------------------------------------------------------------------------------

def smb(count, *, spacing=30.0, src=ATTACKER):
    return [conn(n, f'10.3.0.{n + 1}', (445, 135, 139)[n % 3], src=src, ts=n * spacing,
                 service=('smb,gssapi', 'dce_rpc', 'smb')[n % 3]) for n in range(count)]


@pytest.mark.parametrize('shape', SHAPES)
def test_ten_answered_smb_or_rpc_hosts_in_fifteen_minutes_are_one_lead(shape):
    [match], _rule = evaluate(SmbRpcFanout, smb(10), shape)
    assert match.proposed_lane == 'lead' and 'at least 10 distinct internal hosts within fifteen minutes' in match.claim
    assert evaluate(SmbRpcFanout, smb(9), shape)[0] == []


def test_smb_window_boundary():
    assert lanes(evaluate(SmbRpcFanout, smb(10, spacing=100.0))[0]) == ['lead']             # 900 s span
    assert evaluate(SmbRpcFanout, smb(10, spacing=100.2))[0] == []


def test_a_client_using_its_few_servers_all_day_is_not_fanout():
    servers = ['10.0.0.10', '10.0.0.11', '10.0.5.20', '10.0.5.21']
    rows = [conn(n, servers[n % 4], (445, 135)[n % 2], src='10.7.0.5', ts=n * 7.0) for n in range(2000)]
    assert evaluate(SmbRpcFanout, rows)[0] == []


def test_an_unanswered_sweep_of_445_belongs_to_the_sweep_rule_not_this_one():
    sweep = [conn(n, f'10.4.{n // 250}.{n % 250}', 445, history='S', state='S0', sent=0, received=0, ts=n * 0.1)
             for n in range(300)]
    assert evaluate(SmbRpcFanout, sweep)[0] == []


# ---- endpoint mapper then dynamic port -----------------------------------------------------------------------------

def epm_pair(n, dst, *, src=ATTACKER, ts=0.0, delay=0.4, port=49712, service='dce_rpc', dynamic_service='dce_rpc'):
    return [conn(2 * n, dst, 135, src=src, ts=ts, service=service),
            conn(2 * n + 1, dst, port, src=src, ts=ts + delay, service=dynamic_service)]


@pytest.mark.parametrize('shape', SHAPES)
def test_mapper_then_high_port_to_the_same_host_is_a_lead_citing_both(shape):
    [match], _rule = evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7'), shape,
                              site=facts(domain_controller_addresses=(DC,)))
    assert match.proposed_lane == 'lead' and match.severity == 'high'
    assert {event.get('destination.port') for event in match.events} == {135, 49712}
    assert 'followed 0.400 s later' in match.claim and 'not proof of execution' in ' '.join(match.notes)


def test_order_window_and_pair_identity_are_enforced():
    site = facts(domain_controller_addresses=(DC,))
    dynamic_first = list(reversed(epm_pair(0, '10.5.0.7', delay=0.0)))
    dynamic_first[0] = replace(dynamic_first[0], ts=zf.T0)
    dynamic_first[1] = replace(dynamic_first[1], ts=zf.T0 + 1)
    assert evaluate(EpmDynamicRpc, dynamic_first, site=site)[0] == []
    assert lanes(evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7', delay=30.0), site=site)[0]) == ['lead']
    assert evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7', delay=30.5), site=site)[0] == []
    other_source = epm_pair(0, '10.5.0.7')
    other_source[1] = replace(other_source[1], orig_h='10.1.0.67')
    assert evaluate(EpmDynamicRpc, other_source, site=site)[0] == []
    other_host = epm_pair(0, '10.5.0.7')
    other_host[1] = replace(other_host[1], resp_h='10.5.0.8')
    assert evaluate(EpmDynamicRpc, other_host, site=site)[0] == []


def test_other_services_on_high_ports_and_fixed_service_ports_are_not_the_dynamic_leg():
    site = facts(domain_controller_addresses=(DC,))
    assert evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7', dynamic_service='ssl'), site=site)[0] == []
    assert evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7', port=1433, dynamic_service=None), site=site)[0] == []
    assert evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7', port=445, dynamic_service='smb'), site=site)[0] == []
    unnamed = evaluate(EpmDynamicRpc, epm_pair(0, '10.5.0.7', dynamic_service=None), site=site)[0]
    assert lanes(unnamed) == ['lead']


def test_member_rpc_to_a_declared_controller_and_controller_to_controller_are_not_reported():
    site = facts(domain_controller_addresses=(DC, '10.0.0.11'))
    member = epm_pair(0, DC, src='10.7.0.5')
    replication = epm_pair(1, '10.0.0.11', src=DC, ts=100.0)
    assert evaluate(EpmDynamicRpc, member + replication, site=site)[0] == []


def test_undeclared_controllers_are_still_reported_and_say_why_they_may_be_routine():
    [match], _rule = evaluate(EpmDynamicRpc, epm_pair(0, DC, src='10.7.0.5'))
    assert match.proposed_lane == 'lead' and any('not declared' in note for note in match.notes)


def test_many_sources_to_one_server_fold_into_one_finding_without_lowering_the_lane():
    site = facts(domain_controller_addresses=(DC,))
    rows = [row for n in range(40) for row in epm_pair(n, '10.5.0.30', src=f'10.7.1.{n + 1}', ts=n * 5.0)]
    matches, _rule = evaluate(EpmDynamicRpc, rows, site=site)
    assert lanes(matches) == ['lead'] and '10.5.0.30' in matches[0].claim


def test_unanswered_mapper_or_missing_counters_never_pair():
    site = facts(domain_controller_addresses=(DC,))
    refused = epm_pair(0, '10.5.0.7')
    refused[0] = replace(refused[0], history='Sr', conn_state='REJ', orig_bytes=0, resp_bytes=0)
    assert evaluate(EpmDynamicRpc, refused, site=site)[0] == []
    missing = [replace(row, history=None) for row in epm_pair(0, '10.5.0.7')]
    matches, rule = evaluate(EpmDynamicRpc, missing, site=site)
    assert matches == [] and rule.missing_required == 2


# ---- Kerberos service-ticket fan-out -------------------------------------------------------------------------------

def tgs(n, service, *, client='alice/EXAMPLE.TEST', cipher='aes256-cts-hmac-sha1-96', src=zl.CLIENT, ts=None):
    row = zl.KERBEROS.with_(uid=f'Ctgs{n:012d}', service=service, client=client, cipher=cipher,
                            till=zl.T0 + 36000, **{'id.orig_h': src})
    return replace(row, ts=zl.T0 + (n if ts is None else ts))


def krb_events(rows, shape):
    return [normalize(zl.WRITERS[shape](row, f'k{shape}{n}')) for n, row in enumerate(rows)]


@pytest.mark.parametrize('shape', SHAPES)
def test_ten_distinct_services_with_aes_tickets_are_a_lead_the_rc4_rule_does_not_see(shape):
    rows = [tgs(n, f'MSSQLSvc/sql{n:02d}.example.test:1433') for n in range(10)]
    observations = krb_events(rows, shape)
    [match], _rule = evaluate(KerberosServiceTicketFanout, [], normalized=observations)
    assert match.proposed_lane == 'lead' and 'at least 10 distinct services within five minutes' in match.claim
    assert 'alice/example.test' in match.claim
    assert evaluate(Rc4TgsFanout, [], normalized=observations)[0] == []
    assert evaluate(KerberosServiceTicketFanout, [], normalized=observations[:9])[0] == []


def test_krbtgt_referrals_repeats_case_and_realm_variants_are_not_distinct_services():
    rows = [tgs(n, f'krbtgt/REALM{n}.TEST') for n in range(20)]
    rows += [tgs(20 + n, ('HTTP/web01.example.test', 'http/WEB01.example.test@EXAMPLE.TEST')[n % 2]) for n in range(20)]
    rows += [tgs(40 + n, 'kadmin/changepw') for n in range(5)]
    assert evaluate(KerberosServiceTicketFanout, [], normalized=krb_events(rows, 'plain'))[0] == []


def test_clients_sharing_one_address_are_kept_apart():
    rows = [tgs(n, f'cifs/fs{n:02d}.example.test', client=('alice/EXAMPLE.TEST', 'bob/EXAMPLE.TEST')[n % 2])
            for n in range(18)]
    assert evaluate(KerberosServiceTicketFanout, [], normalized=krb_events(rows, 'plain'))[0] == []


def test_kerberos_window_boundary():
    inside = [tgs(n, f'cifs/fs{n:02d}.example.test', ts=n * 300 / 9) for n in range(10)]
    outside = [tgs(n, f'cifs/fs{n:02d}.example.test', ts=n * 301 / 9) for n in range(10)]
    assert lanes(evaluate(KerberosServiceTicketFanout, [], normalized=krb_events(inside, 'plain'))[0]) == ['lead']
    assert evaluate(KerberosServiceTicketFanout, [], normalized=krb_events(outside, 'plain'))[0] == []


def test_tgs_rows_without_a_service_are_unevaluated():
    rows = [tgs(n, 'x').without('service') for n in range(12)]
    matches, rule = evaluate(KerberosServiceTicketFanout, [], normalized=krb_events(rows, 'plain'))
    assert matches == [] and rule.missing_required == 12


# ---- LDAP bulk response --------------------------------------------------------------------------------------------

@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('port', [389, 636, 3268, 3269])
def test_a_bulk_directory_response_to_a_member_is_a_lead(shape, port):
    rows = [conn(0, DC, port, src='10.7.0.5', received=6_000_000, sent=40_000, service='ldap' if port == 389 else None)]
    [match], _rule = evaluate(LdapBulkResponse, rows, shape, site=facts(domain_controller_addresses=(DC,)))
    assert match.proposed_lane == 'lead' and match.severity == 'medium' and '6000000 payload bytes' in match.claim


def test_routine_directory_traffic_and_controller_clients_are_not_bulk():
    site = facts(domain_controller_addresses=(DC, '10.0.0.11'))
    routine = [conn(n, DC, 389, src=f'10.7.0.{n % 200 + 1}', received=40_000, ts=n) for n in range(500)]
    boundary = [conn(600, DC, 389, src='10.7.0.9', received=4_999_999)]
    replication = [conn(601, DC, 3268, src='10.0.0.11', received=80_000_000)]
    assert evaluate(LdapBulkResponse, routine + boundary + replication, site=site)[0] == []
    assert lanes(evaluate(LdapBulkResponse, [conn(602, DC, 389, src='10.7.0.9', received=5_000_000)], site=site)[0]) \
        == ['lead']


def test_a_declared_sync_host_keeps_its_lead_with_a_note_and_missing_bytes_are_unevaluated():
    site = facts(domain_controller_addresses=(DC,), directory_sync_addresses=('10.7.0.40',))
    [match], _rule = evaluate(LdapBulkResponse, [conn(0, DC, 636, src='10.7.0.40', received=9_000_000)], site=site)
    assert match.proposed_lane == 'lead' and any('directory-sync' in note for note in match.notes)
    matches, rule = evaluate(LdapBulkResponse, [conn(1, DC, 389, src='10.7.0.9', received=None)],
                             site=site)
    assert matches == [] and rule.missing_required == 1


# ---- mission-scale volume ------------------------------------------------------------------------------------------

def _template(port):
    return normalize(zf.WRITERS['plain'](conn(0, '10.0.0.1', port), 'tmpl'))


def _clone(template, n, src, dst, port, ts):
    fields = dict(template.fields)
    for name, value in (('source.ip', src), ('destination.ip', dst), ('destination.port', port)):
        fields[name] = fields[name].model_copy(update={'value': value})
    raw = [ref.model_copy(update={'native_id': f'v{n}'}) for ref in template.raw]
    return template.model_copy(update={'id': f'vol-{n}', 'ts': template.ts.replace(microsecond=0) + ts,
                                       'fields': fields, 'raw': raw})


def _background(count, port_cycle=(445, 135, 445, 22)):
    from datetime import timedelta
    templates = {port: _template(port) for port in set(port_cycle) | {49700}}
    out = []
    for n in range(count):
        port = port_cycle[n % len(port_cycle)]
        src = f'10.{20 + n % 50}.{(n // 50) % 200}.{n % 7 + 1}'
        dst = f'10.0.0.{10 + n % 3}'
        out.append(_clone(templates[port], n, src, dst, port, timedelta(seconds=n * 0.05)))
    return out, templates


@pytest.mark.parametrize('cls', [SmbRpcFanout, RemoteShellFanout, EpmDynamicRpc])
def test_large_benign_background_stays_quiet_and_one_attacker_inside_it_is_found(cls):
    from datetime import timedelta
    background, templates = _background(40_000)
    site = facts(domain_controller_addresses=('10.0.0.10', '10.0.0.11', '10.0.0.12'))
    attack = []
    for n in range(12):
        stamp = timedelta(seconds=1000 + n)
        if cls is EpmDynamicRpc:
            attack.append(_clone(templates[135], 100_000 + 2 * n, ATTACKER, f'10.9.0.{n + 1}', 135, stamp))
            attack.append(_clone(templates[49700], 100_001 + 2 * n, ATTACKER, f'10.9.0.{n + 1}', 49700,
                                 stamp + timedelta(seconds=0.2)))
        else:
            port = 445 if cls is SmbRpcFanout else 22
            attack.append(_clone(templates[port], 100_000 + n, ATTACKER, f'10.9.0.{n + 1}', port, stamp))
    batches = [background[i:i + 2000] for i in range(0, len(background), 2000)]
    rule = cls()
    rule.site_facts = site
    try:
        matches = run(rule, [*batches, attack])
    finally:
        rule.release_state()
    if cls is EpmDynamicRpc:
        assert lanes(matches) == ['lead'] * 12 and all(ATTACKER in m.claim for m in matches)
    else:
        assert lanes(matches) == ['lead'] and ATTACKER in matches[0].claim


@pytest.mark.parametrize('cls', [SmbRpcFanout, EpmDynamicRpc, LdapBulkResponse])
def test_background_time_grows_linearly(cls):
    timings = []
    for count in (5_000, 20_000):
        background, _templates = _background(count, (445, 135, 389, 49700))
        rule = cls()
        rule.site_facts = facts()
        start = time.perf_counter()
        try:
            run(rule, [background[i:i + 2000] for i in range(0, len(background), 2000)])
        finally:
            rule.release_state()
        timings.append(time.perf_counter() - start)
    assert timings[1] <= 8 * timings[0], timings              # linear is 4x; quadratic would be 16x
