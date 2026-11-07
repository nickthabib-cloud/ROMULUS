"""Local rule pins do not alter curated scheduling or infer budget cuts from text."""
from romulus.hunt.expansion import ExpansionEngine
from romulus.store import schema as t
from tests.test_expansion_engine import WINDOW, add_anchor, repo_with_anchor
from tests.test_expansion_lane_budget import SteadyFetcher, set_lane, urgent_and_later_highs
from tests.test_imported_anchor_priority import _imported


def _unused_pin(repo):
    manifest = repo.get_hunt('h1')['manifest']
    manifest['sigma_rules'] = {'digest': 'set', 'applied': [
        {'id': 'a' * 64, 'digest': 'a' * 64, 'title': 'Unmatched local rule', 'lane': 'high', 'tags': []}]}
    with repo.engine.begin() as connection:
        connection.execute(t.hunt.update().where(t.hunt.c.id == 'h1').values(manifest=manifest))


def test_unused_pinned_rule_keeps_exact_curated_fetch_order_and_budget_results():
    results = []
    for pinned in (False, True):
        repo = urgent_and_later_highs(highs=2, leads=0)
        try:
            if pinned:
                _unused_pin(repo)
            fetcher = SteadyFetcher(repo)
            summary = ExpansionEngine(repo, 'h1', WINDOW, fetcher, max_source_queries=24).run()
            anchors = [{key: value for key, value in row.items() if key not in {'created_at', 'updated_at'}}
                       for row in repo.expansion_anchors('h1')]
            results.append((fetcher.calls, anchors, summary))
        finally:
            repo.engine.dispose()
    assert results[0] == results[1]


def test_imported_slots_move_inside_their_lane_positions_without_regrouping_other_lanes():
    repo = urgent_and_later_highs(highs=2, leads=0)
    try:
        _imported(repo, 'F-high-0')
        engine = ExpansionEngine(repo, 'h1', WINDOW, SteadyFetcher(repo), max_source_queries=200)
        engine._seed_anchors()
        rows = repo.expansion_anchors('h1')
        ordered = [row for lane in ('urgent', 'high') for row in engine._ordered_anchors(
            [row for row in rows if row['lane'] == lane])]
        reasons = {row['id']: [] for row in rows}
        imported = engine._imported_rule_ids
        engine._imported_rule_ids = set()
        baseline = engine._tier_slots(ordered, reasons, 200)
        engine._imported_rule_ids = imported
        current = engine._tier_slots(ordered, reasons, 200)
        assert [slot.row['lane'] for slot in current] == [slot.row['lane'] for slot in baseline]
        high = [slot.row['id'] for slot in current if slot.row['lane'] == 'high']
        first_imported = high.index('F-high-0')
        assert all(item == 'F-high-1' for item in high[:first_imported])
        assert all(item == 'F-high-0' for item in high[first_imported:])
    finally:
        repo.engine.dispose()


def test_host_diagnostic_containing_budget_does_not_claim_an_imported_budget_cut():
    repo = repo_with_anchor(candidate_id='curated', host='budget-db')
    try:
        add_anchor(repo, 'imported', 'other')
        for item in ('curated', 'imported'):
            set_lane(repo, item, 'high')
        _imported(repo, 'imported')

        class DiagnosticFetcher(SteadyFetcher):
            def fetch(self, anchor, link_type, window, *, query_cap=None):
                result = super().fetch(anchor, link_type, window, query_cap=query_cap)
                if anchor.finding_id == 'curated':
                    result.status = 'partial'
                    result.reasons = ['host budget-db has incomplete telemetry']
                return result

        ExpansionEngine(repo, 'h1', WINDOW, DiagnosticFetcher(repo), max_source_queries=2000).run()
        [curated] = [row for row in repo.expansion_anchors('h1') if row['id'] == 'curated']
        assert 'host budget-db has incomplete telemetry' in curated['reasons']
        assert not any(reason.startswith('budget spent on') for reason in curated['reasons'])
    finally:
        repo.engine.dispose()
