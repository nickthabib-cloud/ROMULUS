"""Resume spends the same examined-row, hop-key and query limits as one worker."""
from datetime import timedelta

from romulus.agent.models import PivotCoverage
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkResult, LinkWindow
from romulus.hunt.pivot import PivotEventBatch
from romulus.hunt.zeek_links import ZeekLink
from tests.fixtures import zeek_logs as zl
from tests.test_expansion_engine import repo_with_anchor
from tests.test_zeek_links import NativePivot


def join(repo, *, row_count=1):
    pivot = NativePivot('malcolm', [zl.malcolm(zl.HTTP, 'root')])
    pivot.repo, pivot.hunt_id, pivot.owner_token = repo, 'h1', None
    root = pivot.events[0]
    anchor = LinkAnchor(finding_id='F-anchor', ts=root.ts, events=[root], event_ids=[root.id])
    window = LinkWindow(label='narrow', start=root.ts-timedelta(minutes=5), end=root.ts+timedelta(minutes=5))
    def fetch(*args, **kwargs):
        pivot.source_queries += 3
        return PivotEventBatch('complete', [], [], {}, [PivotCoverage(
            target='network', dataset='zeek.http', start=window.start, end=window.end,
            status='complete', returned=row_count, total=row_count)], [], 1)
    pivot.fetch_intents = fetch
    return ZeekLink(LinkFetcher(pivot, window.start, window.end), anchor, 'zeek_uid', window, 128)


def publish(join, name):
    engine = ExpansionEngine.__new__(ExpansionEngine)
    engine.repo, engine.hunt_id, engine.owner_token = join.executor.repo, 'h1', None
    result = LinkResult(id=name, anchor_id=join.anchor.finding_id, link_type=join.kind,
        window=join.window, strength='observed', key=join.key, status='complete',
        zeek_budget={**join.shared, 'keys': sorted(join.shared['keys'])})
    engine._persist_link(result)
    return result


def test_completed_probe_checkpoints_rejected_records_queries_and_hop_keys():
    repo = repo_with_anchor()
    first = join(repo, row_count=9999)
    first.query([], (), ['old-key'], first.window, lambda event: False, intents=[object()])
    publish(first, 'link-one')
    resumed = join(repo, row_count=1)
    assert resumed.shared == first.shared == {'rows': 9999, 'keys': {'old-key'}, 'queries': 3}
    resumed.query([], (), ['new-key'], resumed.window, lambda event: False, intents=[object()])
    publish(resumed, 'link-two')
    exhausted = join(repo)
    assert exhausted.shared == {'rows': 10000, 'keys': {'old-key', 'new-key'}, 'queries': 6}
    exhausted.query([], (), ['third-key'], exhausted.window, lambda event: False, intents=[object()])
    assert not exhausted.batches
    assert any('shared row/query limit' in reason for reason in exhausted.reasons)


def test_query_budget_and_key_caps_are_shared_after_recreation(monkeypatch):
    from romulus.hunt import zeek_links
    monkeypatch.setattr(zeek_links, 'MAX_QUERIES', 3)
    repo = repo_with_anchor()
    first = join(repo)
    first.query([], (), ['key'], first.window, lambda event: False, intents=[object()])
    publish(first, 'link-one')
    resumed = join(repo)
    resumed.query([], (), ['key'], resumed.window, lambda event: False, intents=[object()])
    assert not resumed.batches
    assert resumed.shared['queries'] == 3


def test_unpublished_and_duplicate_results_do_not_charge_a_checkpoint():
    repo = repo_with_anchor()
    first = join(repo)
    first.query([], (), ['one'], first.window, lambda event: False, intents=[object()])
    assert join(repo).shared == {'rows': 0, 'keys': set(), 'queries': 0}
    publish(first, 'same-link')
    first.query([], (), ['two'], first.window, lambda event: False, intents=[object()])
    publish(first, 'same-link')
    assert join(repo).shared == {'rows': 1, 'keys': {'one'}, 'queries': 3}


def test_production_result_carries_a_snapshot_independent_of_later_mutation():
    repo = repo_with_anchor()
    first = join(repo)
    result = first.run()
    assert result.zeek_budget == {'rows': 2, 'keys': [zl.UID_HTTP], 'queries': 6}
    first.shared['keys'].add('later')
    assert result.zeek_budget['keys'] == [zl.UID_HTTP]


def test_restored_hop_cap_never_sends_more_new_keys(monkeypatch):
    from romulus.hunt import zeek_links
    monkeypatch.setattr(zeek_links, 'MAX_KEYS', 2)
    repo = repo_with_anchor()
    first = join(repo)
    first.query([], (), ['one', 'two'], first.window, lambda event: False, intents=[object()])
    publish(first, 'link-one')
    resumed = join(repo)
    resumed.query([], (), ['third'], resumed.window, lambda event: False, intents=[object()])
    assert not resumed.batches
    assert resumed.shared['keys'] == {'one', 'two'}
    assert any('hop-key limit 2' in reason for reason in resumed.reasons)
