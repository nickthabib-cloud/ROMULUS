"""Request authority and coverage counts follow the typed HTTP observation."""
import pytest

from romulus.report.manifest import coverage_for_hunt
from tests.fixtures import zeek_logs as zl
from tests.test_indicator_content_matching import rule
from tests.test_indicators import net_event, run
from tests.test_network_normalizers import eve, one
from tests.test_report import _repo_with_finding
from tests.test_zeek_windows_protocols import normalize


@pytest.mark.parametrize('shape', [*zl.WRITERS, 'suricata'])
@pytest.mark.parametrize('port,listed,matched', [
    (8080, 'http://example.test:8080/Keep', True),
    (8080, 'http://example.test/Keep', False),
    (80, 'http://example.test/Keep', True),
])
def test_typed_destination_port_is_part_of_reconstructed_http_authority(shape, port, listed, matched):
    event = (one(eve('port', {'event_type': 'http', 'dest_port': port,
                            'http': {'hostname': 'example.test', 'url': '/Keep'}})) if shape == 'suricata' else
             normalize(zl.WRITERS[shape](zl.HTTP.with_(host='example.test', uri='/Keep', **{'id.resp_p': port}), 'port')))
    owner = rule('url', listed)
    try:
        matches = run(owner, event)
        assert bool(matches) is matched
        if matched and port == 8080:
            assert any(field.field == 'destination.port' and field.value == 8080 for field in matches[0].predicate)
    finally:
        owner.release_state()


def test_url_gap_counts_only_families_that_can_type_a_url():
    owner = rule('url', 'http://example.test/Keep')
    try:
        owner.consume([net_event(family, family) for family in ('dns_query', 'net_flow', 'auth')] + [
            net_event('http_tx', 'missing-host', url__original='/Keep'),
            net_event('http_access', 'relative-access', url__original='/Keep'),
            net_event('http_tx', 'complete', url__original='http://example.test/Other')])
        [note] = owner.partition_coverage_notes()
        assert '2 delivered record(s)' in note
    finally:
        owner.release_state()


def test_two_thousand_partitions_render_one_summed_gap_per_target_and_kind():
    repo, _ = _repo_with_finding()
    try:
        def note(count):
            return f'Indicator kind url cannot be searched in {count} delivered record(s): no complete typed value was available; no negative result is asserted.'
        cells = [{'rule_id': 'ioc.indicator_match', 'version': 'test', 'target': 'idx' if index % 2 == 0 else 'other',
                  'partition': f'p{index}', 'state': 'positive_only', 'matched': 0, 'evaluated': index + 1,
                  'detail': {'reasons': [note(index + 1)]}} for index in range(2000)]
        cells.append({'rule_id': 'ioc.indicator_match', 'version': 'test', 'target': '*', 'partition': 'window',
                      'state': 'positive_only', 'matched': 0, 'evaluated': 2001000,
                      'detail': {'reasons': [note(2001000)]}})
        repo.set_rule_cells('h1', cells)
        [row] = [row for row in coverage_for_hunt(repo, 'h1')['rules'] if row['rule_id'] == 'ioc.indicator_match']
        text = row['search_result']
        assert text.count('Indicator kind url cannot be searched') == 2
        assert '1000000 delivered record(s)' in text and '1001000 delivered record(s)' in text
        assert 'idx' in text and 'other' in text
    finally:
        repo.engine.dispose()
