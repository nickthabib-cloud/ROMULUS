"""Synthetic writer-provenance checks limited to the new Linux fallback paths."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.auth import SshPasswordGuessing, SshSuccessAfterFailures
from romulus.detect.service_auth import ServicePasswordGuessing
from romulus.evidence.linux_auth_text import parse_auth
from romulus.evidence.normalize import (
    normalize_hits,
    normalize_journal,
    normalize_journal_fields,
    normalize_syslog,
)

PAM = ('pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 '
       'tty=ssh ruser= rhost=192.0.2.1  user=root')
ACCEPTED = 'Accepted password for alice from 192.0.2.1 port 4400 ssh2'
SESSION = 'pam_unix(sshd:session): session opened for user root by root(uid=0)'
UNVERIFIABLE = 'Writer identity not verifiable'
SHAPES = ('json', 'fields', 'system', 'text', 'bare_text')


def _hit(shape, program, message, trusted=None):
    trusted = trusted or {}
    source = {'@timestamp': '2026-11-10T12:00:00Z', 'host': {'name': 'server'}}
    if shape == 'json':
        source['event'] = {'dataset': 'systemd.journal', 'original': json.dumps({
            'SYSLOG_IDENTIFIER': program, 'MESSAGE': message, '_HOSTNAME': 'server', **trusted})}
    else:
        source.update(message=message, event={'dataset': {
            'fields': 'journald.logs', 'system': 'system.auth', 'text': 'custom.log',
            'bare_text': 'custom.log',
        }[shape]})
        if shape == 'fields':
            source['syslog'] = {'identifier': program}
        elif shape in ('system', 'bare_text'):
            source['process'] = {'name': program}
        else:
            source['message'] = f'Nov 10 12:00:00 server {program}: {message}'
        if shape == 'system':
            source['input'] = {'type': 'journald'}
        for key, path in {'_COMM': 'journald.process.name', '_EXE': 'journald.process.executable',
                          '_SYSTEMD_UNIT': 'systemd.unit'}.items():
            if key in trusted:
                cursor = source
                parts = path.split('.')
                for part in parts[:-1]:
                    cursor = cursor.setdefault(part, {})
                cursor[parts[-1]] = trusted[key]
    return {'_index': 'host-logs', '_id': 'writer-1', '_source': source}


def _events(hit):
    events, skips, errors = normalize_hits([hit])
    assert not errors
    return events, skips


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('program,message', [
    ('x', PAM), ('sshd', PAM), ('CRON', '(root) CMD (/bin/true)'),
    ('crontab', '(root) REPLACE (root)'),
])
def test_trusted_logger_cannot_claim_privileged_service(shape, program, message):
    events, skips = _events(_hit(shape, program, message, {'_COMM': 'logger', '_EXE': '/usr/bin/logger'}))
    assert not events
    assert sum(skips.values()) == 1
    assert 'writer identity mismatch' in next(iter(skips)).lower()


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('trusted', [
    {'_COMM': 'logger', '_EXE': '/usr/sbin/sshd', '_SYSTEMD_UNIT': 'ssh.service'},
    {'_COMM': 'sshd', '_EXE': '/usr/bin/logger', '_SYSTEMD_UNIT': 'sshd.service'},
    {'_COMM': 'sshd', '_EXE': '/usr/sbin/sshd', '_SYSTEMD_UNIT': 'cron.service'},
])
def test_one_valid_trusted_field_cannot_override_a_disagreement(shape, trusted):
    events, skips = _events(_hit(shape, 'sshd', PAM, trusted))
    assert not events and sum(skips.values()) == 1
    assert 'writer identity mismatch' in next(iter(skips)).lower()


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('field,value', [('_COMM', ['cron']), ('_EXE', 123), ('_SYSTEMD_UNIT', {'name': 'cron.service'}),
                                        ('_COMM', None), ('_COMM', '')])
def test_malformed_trusted_identity_is_not_discarded_or_coerced(shape, field, value):
    events, skips = _events(_hit(shape, 'CRON', '(root) CMD (/bin/true)', {field: value}))
    assert not events and sum(skips.values()) == 1
    assert 'writer identity mismatch' in next(iter(skips)).lower()


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('writer,unit', [('sshd', 'ssh.service'), ('sshd-session', 'sshd@instance.service'),
                                       ('sshd-auth', 'sshd.service')])
def test_real_ssh_pam_uses_actual_writer_and_helpers_stay_generic(shape, writer, unit):
    events, skips = _events(_hit(shape, writer, SESSION if writer == 'sshd' else PAM,
                                                   {'_COMM': writer, '_EXE': '/usr/sbin/' + writer,
                                                    '_SYSTEMD_UNIT': unit}))
    assert not skips and len(events) == 1
    event = events[0]
    assert event.get('auth.service') == writer
    assert event.get('auth.phase') == ('session_open' if writer == 'sshd' else 'authentication')
    assert UNVERIFIABLE not in event.caveats
    ssh = SshPasswordGuessing()
    ssh.consume([event])
    assert ssh.evaluated == 0
    if writer != 'sshd':
        generic = ServicePasswordGuessing()
        assert generic.accept(event)
        generic.release_state()


@pytest.mark.parametrize('shape', SHAPES)
def test_trusted_helper_comm_wins_over_sshd_identifier(shape):
    events, skips = _events(_hit(shape, 'sshd', PAM, {'_COMM': 'sshd-session',
        '_EXE': '/usr/libexec/openssh/sshd-session', '_SYSTEMD_UNIT': 'sshd.service'}))
    assert not skips and len(events) == 1
    assert events[0].get('auth.service') == 'sshd-session'


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('identifier,trusted', [
    ('sshd[42]', {'_COMM': 'sshd-session', '_EXE': '/usr/libexec/openssh/sshd-session'}),
    ('sshd', {'_EXE': '/usr/libexec/openssh/sshd-session'}),
    ('sshd', {'_COMM': 'sshd', '_EXE': '/usr/libexec/openssh/sshd-session'}),
])
def test_helper_identity_cannot_be_lost_before_auth_is_parsed(shape, identifier, trusted):
    events, skips = _events(_hit(shape, identifier, PAM, trusted))
    assert not skips and len(events) == 1
    assert events[0].get('auth.service') == 'sshd-session'
    ssh = SshPasswordGuessing()
    ssh.consume(events)
    assert ssh.evaluated == 0


@pytest.mark.parametrize('message', [PAM, ACCEPTED])
def test_unverified_uppercase_identifier_does_not_expand_the_ssh_boundary(message):
    events, skips = _events(_hit('text', 'SSHD', message))
    assert not events and sum(skips.values()) == 1


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('program,message,family', [('CRON', '(root) CMD (/bin/true)', 'process_observed'),
                                                   ('crontab', '(root) REPLACE (root)', 'service_change')])
def test_matching_cron_writers_remain_typed(shape, program, message, family):
    events, skips = _events(_hit(shape, program, message, {'_COMM': program.lower(),
        '_EXE': '/usr/bin/' + program.lower()}))
    assert not skips and len(events) == 1 and events[0].family == family
    assert UNVERIFIABLE not in events[0].caveats


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('writer', ['sshd', 'sshd-session', 'sshd-auth'])
def test_unverified_ssh_writer_is_caveated_and_helper_is_not_an_sshd_event(shape, writer):
    events, skips = _events(_hit(shape, writer, SESSION if writer == 'sshd' else PAM))
    assert not skips and len(events) == 1
    assert events[0].get('auth.service') == writer
    assert UNVERIFIABLE in events[0].caveats
    ssh = SshPasswordGuessing()
    ssh.consume(events)
    assert ssh.evaluated == 0


@pytest.mark.parametrize('writer', ['x', 'logger', 'CRON', 'sshd-fake'])
def test_pam_sshd_service_cannot_promote_another_program(writer):
    assert parse_auth(writer, PAM) is None
    events, skips = _events(_hit('text', writer, PAM))
    assert not events and sum(skips.values()) == 1


@pytest.mark.parametrize('shape,normalizer', [('json', normalize_journal), ('fields', normalize_journal_fields),
                                           ('system', normalize_syslog)])
@pytest.mark.parametrize('program,message', [
    ('sshd', ACCEPTED), ('sudo', 'alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/true'),
    ('systemd', 'Started example.service.'),
])
def test_preexisting_successful_normalizer_result_is_unchanged(shape, normalizer, program, message):
    hit = _hit(shape, program, message, {'_COMM': program, '_EXE': '/usr/sbin/' + program})
    expected = normalizer(hit)
    events, skips = _events(hit)
    assert not skips and len(events) == 1
    assert events[0].model_dump() == expected.model_dump()
    assert UNVERIFIABLE not in events[0].caveats


def test_native_service_aliases_and_instance_units_agree():
    events, skips = _events(_hit('json', 'dovecot',
        'imap-login: Login: user=<alice>, method=PLAIN, rip=192.0.2.1',
        {'_COMM': 'imap-login', '_EXE': '/usr/lib/dovecot/imap-login', '_SYSTEMD_UNIT': 'dovecot@tenant.service'}))
    assert not skips and len(events) == 1
    assert events[0].get('auth.service') == 'dovecot'


def test_raw_text_cannot_drop_indexed_trusted_writer_for_existing_ssh_grammar():
    events, skips = _events(_hit('text', 'sshd', ACCEPTED, {'_COMM': 'logger', '_EXE': '/usr/bin/logger'}))
    assert not events and sum(skips.values()) == 1
    assert 'writer identity mismatch' in next(iter(skips)).lower()


@pytest.mark.parametrize('attempts', [3, 5])
def test_native_ssh_and_pam_pairs_cannot_inflate_success_after_failures(attempts):
    start = datetime(2026, 11, 10, 12, tzinfo=UTC)
    hits = []
    native_hits = []
    for index in range(attempts):
        for offset, message in enumerate((PAM, f'Failed password for root from 192.0.2.1 port {4400 + index} ssh2')):
            hit = _hit('json', 'sshd', message, {'_COMM': 'sshd', '_EXE': '/usr/sbin/sshd',
                                                '_SYSTEMD_UNIT': 'sshd.service'})
            hit['_id'] = f'{index}-{offset}'
            hit['_source']['@timestamp'] = (start + timedelta(seconds=index * 30 + offset)).isoformat()
            hits.append(hit)
            if offset:
                native_hits.append(hit)
    accepted = _hit('json', 'sshd', 'Accepted password for root from 192.0.2.1 port 5000 ssh2',
                    {'_COMM': 'sshd', '_EXE': '/usr/sbin/sshd', '_SYSTEMD_UNIT': 'sshd.service'})
    accepted['_id'] = 'accepted'
    accepted['_source']['@timestamp'] = (start + timedelta(seconds=attempts * 30 + 10)).isoformat()
    native_hits.append(accepted)
    events, skips, errors = normalize_hits([*hits, accepted])
    assert not errors
    rule = SshSuccessAfterFailures()
    assert rule.consume(events) == []
    matches = rule.finalize()
    rule.release_state()
    if attempts == 3:
        assert matches == []
    else:
        assert len(matches) == 1 and matches[0].proposed_lane == 'high'
        assert 'after 5 failed attempt(s)' in matches[0].claim
    native_events, native_skips, native_errors = normalize_hits(native_hits)
    assert not native_skips and not native_errors
    assert [event.model_dump() for event in events] == [event.model_dump() for event in native_events]
    assert sum(skips.values()) == attempts
