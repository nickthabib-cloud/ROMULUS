"""Only the declared normal DC-to-DC policy lowers the replication notice lane."""
import pytest

from romulus.detect.registry import bind_windows_site
from romulus.detect.zeek_alerts import ZeekAlerts
from romulus.evidence.typed import RawRef
from romulus.site import COLLECTION_SCHEMA, validate_site_content
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import normalize


@pytest.mark.parametrize('declared,source,destination,lane,caveat', [
    (['10.0.0.1', '10.0.0.2'], '10.0.0.1', '10.0.0.2', 'lead', 'declared domain controllers'),
    (['10.0.0.1', '10.0.0.2'], '10.0.0.9', '10.0.0.2', 'high', None),
    ([], '10.0.0.1', '10.0.0.2', 'high', 'domain controller addresses not declared'),
])
def test_bzar_credential_notice_uses_frozen_address_roles_in_all_four_shapes(declared, source, destination, lane, caveat):
    facts = validate_site_content({'schema': COLLECTION_SCHEMA, 'domain_controller_addresses': declared})
    summaries = []
    for shape in zl.WRITERS:
        row = zl.NOTICE.with_(note='ATTACK::Credential_Access', msg='Replication-call heuristic', sub=None,
            src=source, dst=destination, **{'id.orig_h': source, 'id.resp_h': destination})
        event = normalize(zl.WRITERS[shape](row, 'notice'))
        rule = bind_windows_site([ZeekAlerts()], facts)[0]
        rule.consume([event])
        staged = {e.id: e for e in rule.drain_staged()}
        rule.bind_loader(lambda ids, staged=staged: [staged[i] for i in ids if i in staged])
        try:
            [match] = rule.finalize()
            assert match.proposed_lane == lane
            if caveat:
                assert any(caveat in note for note in match.notes)
            summaries.append((match.proposed_lane, match.claim, sorted(match.notes)))
        finally:
            rule.release_state()
    assert all(summary == summaries[0] for summary in summaries)


def test_bzar_policy_does_not_lower_other_attack_notices():
    source, destination = '10.0.0.1', '10.0.0.2'
    facts = validate_site_content({'schema': COLLECTION_SCHEMA, 'domain_controller_addresses': [source, destination]})
    row = zl.NOTICE.with_(note='ATTACK::Defense_Evasion', src=source, dst=destination,
                          **{'id.orig_h': source, 'id.resp_h': destination})
    rule = bind_windows_site([ZeekAlerts()], facts)[0]
    event = normalize(zl.malcolm(row, 'notice'))
    rule.consume([event])
    rule.bind_loader(lambda ids: [event] if event.id in ids else [])
    try:
        assert rule.finalize()[0].proposed_lane == 'high'
    finally:
        rule.release_state()


def test_notice_totals_count_raw_references_instead_of_canonical_events():
    event = normalize(zl.malcolm(zl.NOTICE, 'notice'))
    extra = RawRef(target=event.raw[0].target, native_id='second-notice')
    event = event.model_copy(update={'raw': [*event.raw, extra, *event.raw]})
    rule = ZeekAlerts()
    rule.consume([event])
    rule.bind_loader(lambda ids: [event] if event.id in ids else [])
    try:
        [match] = rule.finalize()
        assert '2 raw reference(s)' in match.claim
    finally:
        rule.release_state()


def test_notice_with_an_unavailable_span_boundary_names_the_missing_evidence():
    from dataclasses import replace
    events = [normalize(zl.malcolm(replace(zl.NOTICE.with_(uid=f'Cnotice{n:010d}'), ts=zl.T0+n), f'n{n}'))
              for n in range(21)]
    rule = ZeekAlerts()
    rule.consume(events)
    rule.drain_staged()
    available = {event.id: event for event in events[:-1]}
    rule.bind_loader(lambda ids: [available[i] for i in ids if i in available])
    try:
        [match] = rule.finalize()
        assert 'record that ends this interval was not kept for citation' in match.claim
        assert 'interval is computed from every record' in match.claim
    finally:
        rule.release_state()
