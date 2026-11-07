"""Imported folds share expansion budgets without displacing curated peers."""
from datetime import timedelta

from romulus.hunt.expansion import ExpansionEngine
from romulus.store import schema as t
from tests.test_expansion_engine import T0, WINDOW, add_anchor, repo_with_anchor
from tests.test_expansion_lane_budget import SteadyFetcher, set_lane

SIGMA = 'sigma.' + 'a' * 64


def _imported(repo, candidate_id):
    manifest = dict(repo.get_hunt('h1')['manifest'])
    manifest['sigma_rules'] = {'digest': 'set', 'applied': [
        {'id': 'a' * 64, 'digest': 'a' * 64, 'title': 'Imported process', 'lane': 'high', 'tags': []}]}
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().where(t.candidate.c.id == candidate_id).values(rule_id=SIGMA))
        connection.execute(t.hunt.update().where(t.hunt.c.id == 'h1').values(manifest=manifest))


def test_all_curated_slots_in_a_tier_precede_same_lane_imported_slots_across_hosts():
    repo = repo_with_anchor(candidate_id='curated-one', host='same-host')
    add_anchor(repo, 'curated-two', 'same-host', ts=T0 + timedelta(seconds=1))
    add_anchor(repo, 'imported', 'other-host', ts=T0 - timedelta(minutes=1))
    for item in ('curated-one', 'curated-two', 'imported'):
        set_lane(repo, item, 'high', severity='critical' if item == 'imported' else 'low')
    _imported(repo, 'imported')
    fetcher = SteadyFetcher(repo)
    engine = ExpansionEngine(repo, 'h1', WINDOW, fetcher, max_source_queries=200)
    engine._seed_anchors()
    ordered = engine._ordered_anchors(repo.expansion_anchors('h1'))
    assert [row['id'] for row in ordered] == ['curated-one', 'curated-two', 'imported']
    slots = engine._tier_slots(ordered, {row['id']: [] for row in ordered}, 200)
    imported_at = next(index for index, slot in enumerate(slots) if slot.row['id'] == 'imported')
    assert all(slot.row['id'] != 'imported' for slot in slots[:imported_at])
    assert all(slot.row['id'] == 'imported' for slot in slots[imported_at:])
    assert {slot.row['id'] for slot in slots[:imported_at]} == {'curated-one', 'curated-two'}


def test_a_curated_anchor_discovered_after_imported_spend_names_that_consumer_at_the_cut():
    repo = repo_with_anchor(candidate_id='imported')
    set_lane(repo, 'imported', 'high')
    _imported(repo, 'imported')
    fetcher = SteadyFetcher(repo)
    inserted = False

    def discover(_result):
        nonlocal inserted
        if not inserted:
            inserted = True
            add_anchor(repo, 'curated-later', 'new-host')
            set_lane(repo, 'curated-later', 'high', source_anchor_id='imported')

    ExpansionEngine(repo, 'h1', WINDOW, fetcher, max_source_queries=4, after_link=discover).run()
    row = next(row for row in repo.expansion_anchors('h1') if row['id'] == 'curated-later')
    assert row['status'] in {'unexpanded', 'expanded_partial'}
    assert 'budget spent on 1 imported-rule anchors' in row['reasons']
