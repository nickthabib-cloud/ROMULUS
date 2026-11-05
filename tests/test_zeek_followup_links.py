"""Bounded host witness wording and known-start interim connection lookback."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import PivotCoverage
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotEventBatch
from romulus.sources.profile import contract_from_types
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_link_regressions import real_pivot
from tests.test_zeek_links import NativePivot, fetch, normalize


@pytest.mark.parametrize('returned', [0, 7, 10])
def test_completed_host_probe_names_only_the_actual_nearest_sample(returned):
    lease = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name='workstation', lease_time=1800)
    conn = zf.malcolm(replace(zf.Conn(), ts=lease.ts+60), 'anchor')
    pivot = NativePivot('malcolm', [zl.malcolm(lease, 'lease'), conn])
    pivot.contracts['hosts'] = contract_from_types('hosts', {'@timestamp': 'date', 'event.dataset': 'keyword',
        'host.name': 'keyword'}, role='host', os_family='linux', hosts=('workstation',))
    original = pivot.fetch_intents
    def sampled(owner, key, intents, retain, **options):
        if any(intent.purpose == 'expansion:host-witness' for intent in intents):
            pivot.source_queries += 3
            coverage = PivotCoverage(target='hosts', dataset='linux.audit', start=intents[0].window.start,
                end=intents[0].window.end, status='complete', returned=returned)
            return PivotEventBatch('complete', ['witness'], [], {}, [coverage], [], 0)
        return original(owner, key, intents, retain, **options)
    pivot.fetch_intents = sampled
    result = fetch(pivot, normalize('malcolm', conn), 'address_host')
    assert any(f'no matching host record among the {returned} nearest sampled' in reason for reason in result.reasons)
    assert not any('matches no host' in reason for reason in result.reasons)
    assert result.status == 'partial'


def test_known_old_conn_start_is_used_to_find_final_and_late_analyzer(tmp_path):
    start = zf.T0 - 3*86400
    interim = zf.malcolm(replace(zf.Conn(), uid=zl.UID_HTTP, ts=start, duration=3*86400+1800),
                         'interim', interim=True)
    final = zf.malcolm(replace(zf.Conn(), uid=zl.UID_HTTP, ts=start, duration=4*86400), 'final')
    late = zl.malcolm(replace(zl.HTTP, ts=zf.T0+3600), 'late')
    root = normalize('malcolm', interim)
    anchor_time = datetime.fromtimestamp(zf.T0, UTC)
    anchor = LinkAnchor(finding_id='finding', ts=anchor_time, events=[root], event_ids=[root.id])
    window = LinkWindow(label='test', start=anchor_time-timedelta(minutes=5), end=anchor_time+timedelta(minutes=5))
    with real_pivot(tmp_path, [interim, final, late]) as (_repo, pivot, backend):
        result = LinkFetcher(pivot, window.start, window.end).fetch(anchor, 'zeek_uid', window)
        assert normalize('malcolm', final).id in result.event_ids
        assert normalize('malcolm', late).id in result.event_ids
        assert result.status == 'complete', result.reasons
        assert backend.queries
