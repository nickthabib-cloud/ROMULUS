"""Imported network observations do not authorize execution-only context claims."""
import pytest

from romulus.hunt.context import finalize_context
from romulus.store import schema as t
from tests.test_context_catalog import _seed_link, exec_event
from tests.test_hunt_rule_metadata import sigma_hunt


@pytest.mark.parametrize('imported_network', [True, False])
def test_context_uses_the_pinned_logsource_anchor_class(tmp_path, imported_network):
    repo, candidate_id, _store, _rule_id, _pins = sigma_hunt(tmp_path)
    try:
        if not imported_network:
            with repo.engine.begin() as connection:
                connection.execute(t.candidate.update().where(t.candidate.c.id == candidate_id).values(
                    rule_id='host.web_shell'))
        _seed_link(repo, 'h1', 'discovery-link', candidate_id, [
            exec_event('discovery-id', ['id'], executable='/usr/bin/id'),
            exec_event('discovery-uname', ['uname', '-a'], executable='/usr/bin/uname')])
        finalize_context(repo, 'h1')
        findings = [item for item in repo.candidates('h1') if item['rule_id'] == 'context.post_access_discovery']
        assert bool(findings) is not imported_network
    finally:
        repo.engine.dispose()


def test_uncited_pinned_network_anchor_does_not_pad_execution_only_context(tmp_path):
    repo, candidate_id, _store, _rule_id, _pins = sigma_hunt(tmp_path)
    try:
        with repo.engine.begin() as connection:
            connection.execute(t.candidate.update().where(t.candidate.c.id == candidate_id).values(
                event_ids=[], gate_results={'_citation_unavailable': True}))
        finalize_context(repo, 'h1')
        assert not any(cell['rule_id'] == 'context.post_access_discovery'
                       for cell in repo.rule_cells('h1'))
    finally:
        repo.engine.dispose()
