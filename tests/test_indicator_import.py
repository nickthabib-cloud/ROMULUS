import json
from datetime import UTC, datetime

import pytest

from romulus.content.indicator_import import parse_indicator_file
from romulus.content.indicator_values import normalize_value


def document(tmp_path, body, suffix='.json'):
    path = tmp_path / ('indicators' + suffix)
    path.write_text(json.dumps(body) if not isinstance(body, str) else body, encoding='utf-8')
    return path


def parsed(path, **kwargs):
    result = parse_indicator_file(path, **kwargs)
    return list(result.rows), result.summary()


@pytest.mark.parametrize(('kind', 'value', 'expected'), [
    ('ip', '2001:0DB8::1', '2001:db8::1'),
    ('cidr', '192.0.2.91/24', '192.0.2.0/24'),
    ('domain', 'Example.COM.', 'example.com'),
    ('program_name', 'Tool.EXE', 'tool.exe'),
    ('md5', 'A' * 32, 'a' * 32),
    ('sha1', 'A' * 40, 'a' * 40),
    ('sha256', 'A' * 64, 'a' * 64),
    ('x509_sha1', ':'.join(['AB'] * 20), 'ab' * 20),
    ('x509_sha256', ':'.join(['AB'] * 32), 'ab' * 32),
    ('ja3', 'A' * 32, 'a' * 32),
    ('hassh', 'B' * 32, 'b' * 32),
    ('ja4', 't13d1516h2_8daaf6152771_02713d6af862', 't13d1516h2_8daaf6152771_02713d6af862'),
    ('url', 'HTTPS://Example.COM:443/A%2fb?Q=%2F&a=1', 'https://example.com/A%2fb?Q=%2F&a=1'),
    ('url', 'http://[2001:DB8::1]:80/a?', 'http://[2001:db8::1]/a?'),
])
def test_kind_validation_normalizes_only_defined_parts(kind, value, expected):
    assert normalize_value(kind, value) == expected


@pytest.mark.parametrize(('kind', 'value'), [
    ('', 'abc'), ('guess', 'abc'), ('ip', '999.2.3.4'), ('ip', 'fe80::1%eth0'),
    ('cidr', 'example.com/24'), ('domain', 'https://example.com'), ('domain', '-bad.example'),
    ('program_name', '/bin/tool'), ('program_name', 'bad\nname'),
    ('md5', 'ab'), ('sha1', 'z' * 40), ('sha256', 'a' * 63),
    ('x509_sha1', 'a' * 64), ('ja3', 'a' * 31), ('ja4', 'arbitrary'),
    ('url', 'example.com/path'), ('url', 'https://user:SECRET_SENTINEL@example.com'),
    ('url', 'https://example.com/?access_token=SECRET_SENTINEL'),
    ('url', 'https://example.com/\nsecret'), ('url', 'https://example.com:99999/'),
])
def test_invalid_values_reject_without_echoing_input(kind, value):
    with pytest.raises(ValueError) as error:
        normalize_value(kind, value)
    assert 'SECRET_SENTINEL' not in str(error.value)
    assert value not in str(error.value) or not value


def test_csv_requires_kind_and_reports_invalid_values(tmp_path):
    rows, summary = parsed(document(tmp_path, 'kind,value,label,attack\nmd5,' + 'A' * 32 +
                                    ',sample,T1059;T1059.001\nip,bad,,\n,192.0.2.1,,\n', '.csv'))
    assert [(row.kind, row.value, row.label, row.attack) for row in rows] == [
        ('md5', 'a' * 32, 'sample', ('T1059', 'T1059.001'))]
    assert summary['accepted'] == 1
    assert summary['counts_by_kind'] == {'md5': 1}
    assert summary['skipped_count'] == 2
    assert sum(summary['skipped_by_reason'].values()) == 2
    assert summary['details_truncated'] == 0


def indicator(pattern, **extra):
    return {'type': 'indicator', 'spec_version': '2.1', 'pattern_type': 'stix', 'pattern': pattern, **extra}


def bundle(*objects):
    return {'type': 'bundle', 'objects': list(objects)}


def test_stix_or_compares_each_value_and_preserves_expiry(tmp_path):
    payload = bundle(indicator("[file:hashes.'SHA-256' = '" + 'A' * 64 +
                               "' OR ipv4-addr:value = '192.0.2.7']", name='test',
                               valid_until='2027-01-01T00:00:00Z'))
    rows, summary = parsed(document(tmp_path, payload))
    assert [(row.kind, row.value) for row in rows] == [('sha256', 'a' * 64), ('ip', '192.0.2.7')]
    assert all(row.expires_at == datetime(2027, 1, 1, tzinfo=UTC) for row in rows)
    assert summary['accepted'] == 2


@pytest.mark.parametrize('pattern', [
    "[ipv4-addr:value = '192.0.2.1' AND domain-name:value = 'example.com']",
    "[ipv4-addr:value = '192.0.2.1'] FOLLOWEDBY [domain-name:value = 'example.com']",
    "[ipv4-addr:value = '192.0.2.1'] REPEATS 2 TIMES",
    "[ipv4-addr:value = '192.0.2.1' OR domain-name:value = 'bad/name']",
    "[ipv4-addr:value = '192.0.2.1' OR file:name = 'test']",
    "[ipv4-addr:value != '192.0.2.1']",
])
def test_stix_rejects_whole_object_without_partial_or_import(tmp_path, pattern):
    rows, summary = parsed(document(tmp_path, bundle(indicator(pattern))))
    assert rows == []
    assert summary['skipped_count'] == 1
    assert summary['skipped'][0]['reason']


def test_stix_reports_revoked_other_objects_and_wrong_types(tmp_path):
    rows, summary = parsed(document(tmp_path, bundle(
        indicator("[domain-name:value = 'example.com']", revoked=True),
        {'type': 'malware', 'name': 'test'},
        indicator(37), indicator("[domain-name:value = 'example.com']", valid_until='not-a-time'),
    )))
    assert not rows
    assert summary['skipped_count'] == 4


@pytest.mark.parametrize(('path', 'kind', 'value'), [
    ("file:hashes.'MD5'", 'md5', 'a' * 32),
    ("file:hashes.'SHA-1'", 'sha1', 'a' * 40),
    ('ipv6-addr:value', 'ip', '2001:db8::1'),
    ('domain-name:value', 'domain', 'example.com'),
    ('url:value', 'url', 'https://example.com/Case'),
    ("x509-certificate:hashes.'SHA-1'", 'x509_sha1', 'a' * 40),
    ("x509-certificate:hashes.'SHA-256'", 'x509_sha256', 'a' * 64),
    ("network-traffic:extensions.'ja3-ext'.ja3_hash", 'ja3', 'a' * 32),
])
def test_stix_supported_exact_paths(tmp_path, path, kind, value):
    rows, summary = parsed(document(tmp_path, bundle(indicator(f"[{path} = '{value}']"))))
    assert [(row.kind, row.value) for row in rows] == [(kind, value)]
    assert summary['skipped_count'] == 0


def test_misp_event_mapping_and_explicit_non_ids_opt_in(tmp_path):
    path = document(tmp_path, {'Event': {'Attribute': [
        {'type': 'ip-src|port', 'value': '2001:db8::1|443', 'to_ids': True, 'comment': 'source'},
        {'type': 'x509-fingerprint-sha256', 'value': 'a' * 64, 'to_ids': True},
        {'type': 'hostname', 'value': 'Example.COM', 'to_ids': False},
        {'type': 'email-src', 'value': 'person@example.com', 'to_ids': True},
        {'type': 'ip-dst', 'value': 'bad', 'to_ids': True},
    ]}})
    rows, summary = parsed(path)
    assert [(row.kind, row.value) for row in rows] == [('ip', '2001:db8::1'), ('x509_sha256', 'a' * 64)]
    assert summary['skipped_count'] == 3
    rows, summary = parsed(path, include_non_ids=True)
    assert len(rows) == 3
    assert rows[-1].value == 'example.com'
    assert summary['skipped_count'] == 2


@pytest.mark.parametrize('payload', [
    [{'type': 'md5', 'value': 'a' * 32, 'to_ids': True}],
    {'Attribute': [{'type': 'md5', 'value': 'a' * 32, 'to_ids': True}]},
    {'response': {'Attribute': [{'type': 'md5', 'value': 'a' * 32, 'to_ids': True}]}},
])
def test_misp_attribute_list_shapes(tmp_path, payload):
    rows, summary = parsed(document(tmp_path, payload))
    assert rows[0].kind == 'md5'
    assert summary['accepted'] == 1


@pytest.mark.parametrize('body', [
    '{"type":"bundle","type":"bundle","objects":[]}',
    '{"type":"bundle","objects":[],"n":NaN}',
    '{"type":"bundle","objects":"wrong"}',
    '{"Event":{"Attribute":false}}', '42', 'null', '["wrong"]',
    '[' * 34 + '0' + ']' * 34, '{unclosed',
])
def test_hostile_malformed_json_fails_file(tmp_path, body):
    with pytest.raises(ValueError):
        parsed(document(tmp_path, body))


@pytest.mark.parametrize('suffix', ['.csv', '.json'])
def test_file_size_caps_fail_before_parsing(tmp_path, suffix):
    path = tmp_path / ('large' + suffix)
    with path.open('wb') as stream:
        stream.truncate((128 if suffix == '.csv' else 16) * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match='size'):
        parsed(path)


def test_csv_streams_and_bounds_report_without_exposing_credentials(tmp_path):
    path = document(tmp_path, 'kind,value\n' +
                    'url,https://user:SECRET_SENTINEL@example.com\n' * 1100 +
                    'ip,192.0.2.5\n', '.csv')
    result = parse_indicator_file(path)
    assert result.summary()['accepted'] == 0  # CSV is consumed only by the caller.
    assert [row.value for row in result.rows] == ['192.0.2.5']
    summary = result.summary()
    assert summary['skipped_count'] == 1100
    assert len(summary['skipped']) <= 1000
    assert summary['details_truncated'] == 1100 - len(summary['skipped'])
    assert 'SECRET_SENTINEL' not in json.dumps(summary)
    assert list(result.rows) == []


@pytest.mark.parametrize('body', ['value\n192.0.2.1\n', 'kind,value,unknown\nip,192.0.2.1,x\n',
                                  'kind,value\nip,"unterminated\n'])
def test_csv_malformed_structure_is_fatal(tmp_path, body):
    with pytest.raises(ValueError):
        parsed(document(tmp_path, body, '.csv'))


def test_per_field_and_row_limits_are_reported(tmp_path):
    rows, summary = parsed(document(tmp_path, 'kind,value,label\nip,192.0.2.1,' + 'x' * 17000 + '\n', '.csv'))
    assert not rows
    assert summary['skipped_count'] == 1


def test_json_numeric_overflow_is_rejected_even_in_unused_metadata(tmp_path):
    with pytest.raises(ValueError):
        parsed(document(tmp_path, '{"type":"bundle","objects":[],"value":1e400}'))


def test_domain_rejects_multiple_root_dots():
    with pytest.raises(ValueError):
        normalize_value('domain', 'example.com..')


@pytest.mark.parametrize('pattern', [
    "[ipv4-addr:value = '192.0.2.1'] OR ipv4-addr:value = '192.0.2.2'",
    "[ipv4-addr:value = '192.0.2.1' OR [ipv4-addr:value = '192.0.2.2']]",
    "[[ipv4-addr:value = '192.0.2.1']]",
])
def test_stix_malformed_brackets_do_not_turn_into_supported_patterns(tmp_path, pattern):
    rows, summary = parsed(document(tmp_path, bundle(indicator(pattern))))
    assert not rows
    assert summary['skipped_count'] == 1


def test_misp_event_object_attributes_are_not_silently_lost(tmp_path):
    payload = {'Event': {'Attribute': [{'type': 'domain', 'value': 'example.com'}], 'Object': [
        {'name': 'file', 'Attribute': [{'type': 'md5', 'value': 'a' * 32, 'to_ids': True}]},
    ]}}
    rows, summary = parsed(document(tmp_path, payload))
    assert [(row.kind, row.value) for row in rows] == [('domain', 'example.com'), ('md5', 'a' * 32)]
    assert summary['accepted'] == 2


@pytest.mark.parametrize(('misp_type', 'value', 'kind', 'normalized'), [
    ('ip-src', '192.0.2.1', 'ip', '192.0.2.1'),
    ('ip-dst', '192.0.2.2', 'ip', '192.0.2.2'),
    ('ip-dst|port', '192.0.2.2|443', 'ip', '192.0.2.2'),
    ('domain', 'Example.COM.', 'domain', 'example.com'),
    ('url', 'HTTPS://Example.COM:443/X?a=%2f', 'url', 'https://example.com/X?a=%2f'),
    ('md5', 'A' * 32, 'md5', 'a' * 32), ('sha1', 'A' * 40, 'sha1', 'a' * 40),
    ('sha256', 'A' * 64, 'sha256', 'a' * 64),
    ('ja3-fingerprint-md5', 'A' * 32, 'ja3', 'a' * 32),
    ('x509-fingerprint-sha1', 'AB:' * 19 + 'AB', 'x509_sha1', 'ab' * 20),
])
def test_all_misp_mapped_types_validate_values(tmp_path, misp_type, value, kind, normalized):
    rows, summary = parsed(document(tmp_path, [{'type': misp_type, 'value': value, 'to_ids': True}]))
    assert [(row.kind, row.value) for row in rows] == [(kind, normalized)]
    assert summary['skipped_count'] == 0


@pytest.mark.parametrize('attribute', [
    {'type': 'ip-src|port', 'value': '192.0.2.1|70000'},
    {'type': 'ip-src|port', 'value': '192.0.2.1|abc'},
    {'type': 'ip-src|port', 'value': '192.0.2.1|443|80'},
    {'type': 'domain', 'value': 'example.com', 'to_ids': 'false'},
    {'type': 'domain', 'value': ['example.com']},
])
def test_invalid_misp_types_and_composites_are_reported(tmp_path, attribute):
    rows, summary = parsed(document(tmp_path, [attribute]))
    assert not rows
    assert summary['skipped_count'] == 1


def test_stix_or_and_quoted_operator_text_are_not_confused(tmp_path):
    rows, summary = parsed(document(tmp_path, bundle(indicator(
        "([url:value = 'https://example.com/AND?x=OR'] OR [domain-name:value = 'example.net'])"))))
    assert [(row.kind, row.value) for row in rows] == [
        ('url', 'https://example.com/AND?x=OR'), ('domain', 'example.net')]
    assert summary['skipped_count'] == 0


@pytest.mark.parametrize('kind', ['program_name', 'url', 'domain'])
def test_unpaired_surrogates_are_invalid_values(kind):
    with pytest.raises(ValueError):
        normalize_value(kind, '\ud800')


def test_credential_url_in_label_is_not_stored(tmp_path):
    rows, summary = parsed(document(tmp_path,
        'kind,value,label\nip,192.0.2.1,https://user:SECRET_SENTINEL@example.com\n', '.csv'))
    assert not rows
    assert summary['skipped_count'] == 1
    assert 'SECRET_SENTINEL' not in json.dumps(summary)


def test_network_file_paths_are_refused_before_access(monkeypatch):
    from pathlib import Path

    def refuse_access(*args, **kwargs):
        raise AssertionError('network file access attempted')

    with pytest.raises(ValueError, match='local'), monkeypatch.context() as access:
        access.setattr(Path, 'stat', refuse_access)
        parse_indicator_file(Path('//unreachable.invalid/share/indicators.csv'))
