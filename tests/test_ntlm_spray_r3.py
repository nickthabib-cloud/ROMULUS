"""Native NTLM spray successes use episode timing and same-account source history."""
import re
from dataclasses import replace

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.zeek_rates import NtlmPasswordSpray
from tests.fixtures import zeek_logs as zl
from tests.test_sweep import _repo
from tests.test_windows_auth_round5 import publish
from tests.test_zeek_windows_protocols import normalize

SHAPES = tuple(zl.WRITERS)
HIT = "victim15"


def ntlm(identity, offset, account, *, success):
    return replace(zl.NTLM.with_(uid="Cn3" + identity, username=account, success=success),
                   ts=zl.T0 + offset)


def failures(label, start=0, *, omit_hit=False):
    accounts = [f"victim{number}" for number in range(41 if omit_hit else 40)
                if not omit_hit or number != 15]
    assert len(accounts) == 40
    return [ntlm(f"{label}{number}", start + number, account, success=False)
            for number, account in enumerate(accounts)]


def persisted_spray(rows, shape, reverse):
    """Normalize native rows and publish actual revisions through the candidate store."""
    events = [normalize(zl.WRITERS[shape](row, f"n3-{number}")) for number, row in enumerate(rows)]
    by_id = {event.id: event for event in events}
    rule, repo = NtlmPasswordSpray(), _repo()
    rule.load = lambda ids: [by_id[identity] for identity in ids if identity in by_id]
    try:
        ordered = sorted(events, key=lambda event: (event.ts, event.id))
        for event in reversed(ordered) if reverse else ordered:
            for match in rule.consume([event]):
                publish(repo, rule, match)
            rule.drain_staged()
            rule.drain_bounds()
        for match in rule.finalize():
            publish(repo, rule, match)
        [candidate] = repo.candidates("h1")
        assert candidate["rule_id"] == NtlmPasswordSpray.id
        assert candidate["group_key"]
        return candidate, events
    finally:
        rule.release_state()
        repo.engine.dispose()


def details(candidate):
    return "\n".join([candidate["claim"], *candidate["gate_results"].get("_notes", [])]).casefold()


def assert_named_hit(candidate, events):
    assert candidate["lane"] == "high"
    assert HIT in candidate["claim"].casefold()
    assert "success" in candidate["claim"].casefold()
    assert "unrelated" not in details(candidate)
    assert any(event.get("ntlm.username") == HIT and event.get("ntlm.success") is True
               and event.id in candidate["event_ids"] for event in events)
    assert {"ntlm.username", "ntlm.success"} <= {field["field"] for field in candidate["predicate_fields"]}


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("success_offset", [39, 40])
def test_single_pass_hit_has_no_failed_membership_and_names_success(shape, reverse, success_offset):
    # At t=9 the source first qualifies. A t=39 success is later than that
    # start, even though another failure has the same timestamp.
    rows = [*failures("single", omit_hit=True), ntlm("singleHit", success_offset, HIT, success=True)]
    candidate, events = persisted_spray(rows, shape, reverse)
    assert sum(event.get("ntlm.success") is False for event in events) == 40
    assert [event.get("ntlm.success") for event in events if event.get("ntlm.username") == HIT] == [True]
    assert_named_hit(candidate, events)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_second_round_hit_stays_high_after_earlier_failure_expires(shape, reverse):
    rows = [*failures("first"), *failures("second", 700, omit_hit=True),
            ntlm("secondHit", 740, HIT, success=True)]
    candidate, events = persisted_spray(rows, shape, reverse)
    old_failure = next(event for event in events if event.get("ntlm.username") == HIT
                       and event.get("ntlm.success") is False)
    hit = next(event for event in events if event.get("ntlm.username") == HIT
               and event.get("ntlm.success") is True)
    assert (hit.ts - old_failure.ts).total_seconds() > NtlmPasswordSpray.seconds
    assert_named_hit(candidate, events)
    assert "2 qualifying episodes" in candidate["claim"]


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_same_account_success_before_first_attempt_keeps_shared_source_lead(shape, reverse):
    rows = [*failures("shared", 100), ntlm("sharedPrior", 90, HIT, success=True),
            ntlm("sharedHit", 140, HIT, success=True)]
    candidate, _ = persisted_spray(rows, shape, reverse)
    assert candidate["lane"] == "lead"
    text = details(candidate)
    assert HIT in text and re.search(r"\b(?:shared|nat)\b", text)
    assert "before" in text or "prior" in text
    assert "unrelated" not in text


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_another_accounts_prior_success_cannot_demote_the_hit(shape, reverse):
    rows = [ntlm("otherPrior", -1, "ordinaryuser", success=True),
            *failures("other"), ntlm("otherHit", 40, HIT, success=True)]
    candidate, events = persisted_spray(rows, shape, reverse)
    assert_named_hit(candidate, events)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_spray_without_success_does_not_claim_a_later_success_association(shape, reverse):
    candidate, events = persisted_spray(failures("noSuccess"), shape, reverse)
    assert candidate["lane"] == "lead"
    assert all(event.get("ntlm.success") is False for event in events)
    text = details(candidate)
    assert "later success is temporally associated" not in text
    assert "later recorded authentication success" not in text
    assert "unrelated" not in text


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_same_account_success_inside_episode_does_not_demote_a_later_hit(shape, reverse):
    rows = [*failures("inside"), ntlm("insideFirst", 20.5, HIT, success=True),
            ntlm("insideLater", 41, HIT, success=True)]
    candidate, events = persisted_spray(rows, shape, reverse)
    assert_named_hit(candidate, events)
    text = details(candidate)
    assert not (re.search(r"\b(?:shared|nat)\b", text) and re.search(r"\b(?:before|prior)\b", text))


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_success_at_first_attempt_is_not_strictly_later(shape, reverse):
    rows = [*failures("boundary", omit_hit=True), ntlm("boundaryHit", 0, HIT, success=True)]
    candidate, _ = persisted_spray(rows, shape, reverse)
    assert candidate["lane"] == "lead"
    assert "later recorded authentication success for" not in candidate["claim"].casefold()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("reverse", [False, True])
def test_blank_success_account_cannot_create_a_named_high(shape, reverse):
    rows = [*failures("blank"), ntlm("blankHit", 40, "", success=True)]
    candidate, _ = persisted_spray(rows, shape, reverse)
    assert candidate["lane"] == "lead"
    assert "later recorded authentication success for" not in candidate["claim"].casefold()


@pytest.mark.parametrize('shape',SHAPES)
def test_shared_source_caveat_cites_the_same_accounts_prior_and_current_success(shape):
    rows=[ntlm('alicePrior',-2,'alice',success=True),ntlm('bobPrior',-1,'bob',success=True),
          *failures('pair'),ntlm('aliceCurrent',40,'alice',success=True),
          ntlm('bobCurrent',41,'bob',success=True)]
    candidate,events=persisted_spray(rows,shape,False)
    assert candidate['lane']=='lead' and 'alice' in details(candidate)
    alice=[row for row in events if row.get('ntlm.username')=='alice' and row.get('ntlm.success') is True]
    assert len(alice)==2 and {row.id for row in alice}<={*candidate['event_ids']}
    assert len(candidate['event_ids'])<=4


@pytest.mark.parametrize('shape',SHAPES)
def test_late_bridge_preserves_published_bounds_without_hiding_a_new_high_and_peak(shape):
    initial=[*failures('bridgeFirst'),*failures('bridgeSecond',800)]
    late=[ntlm(f'bridge{n}',n,f'bridge{n}',success=False) for n in range(60,800,30)]
    late.append(ntlm('bridgeHit',300,'singlehit',success=True))
    all_rows=[*initial,*late]
    events=[normalize(zl.WRITERS[shape](row,f'late-bridge-{n}')) for n,row in enumerate(all_rows)]
    rule,repo=NtlmPasswordSpray(),_repo()
    try:
        for match in rule.consume(events[:len(initial)]):
            publish(repo,rule,match)
        [before]=repo.candidates('h1')
        assert before['lane']=='lead'
        assert before['gate_results']['aggregate_summary']['episodes']==2
        assert before['gate_results']['aggregate_summary']['peak']==40
        for match in [*rule.consume(events[len(initial):]),*rule.finalize()]:
            publish(repo,rule,match)
        [after]=repo.candidates('h1')
        assert after['id']==before['id'] and after['lane']=='high'
        assert after['gate_results']['aggregate_summary']['episodes']>=2
        assert after['gate_results']['aggregate_summary']['peak']==59
        assert 'singlehit' in after['claim'].casefold()
        assert any(word in details(after) for word in ('connect','continuity','merged'))
        hit=next(event for event in events if event.get('ntlm.username')=='singlehit')
        assert hit.id in after['event_ids']
    finally:
        rule.release_state();repo.engine.dispose()


def test_late_shared_source_history_is_cited_without_rolling_back_a_published_high():
    initial=[*failures('backfill'),ntlm('backfillHit',40,HIT,success=True)]
    later=[ntlm('backfillPrior',-1,HIT,success=True)]
    later += [ntlm(f'new{n}',41+n,f'new{n}',success=False) for n in range(20)]
    events=[normalize(zl.WRITERS['elastic'](row,f'backfill-{n}')) for n,row in enumerate([*initial,*later])]
    rule,repo=NtlmPasswordSpray(),_repo()
    try:
        for match in rule.consume(events[:len(initial)]):
            publish(repo,rule,match)
        assert repo.candidates('h1')[0]['lane']=='high'
        for match in [*rule.consume(events[len(initial):]),*rule.finalize()]:
            publish(repo,rule,match)
        [candidate]=repo.candidates('h1')
        assert candidate['lane']=='high' and candidate['gate_results']['aggregate_summary']['peak']==60
        prior=events[len(initial)]
        assert prior.id in candidate['event_ids']
        assert 'pre-episode' in details(candidate) and 'previously published high' in details(candidate)
    finally:
        rule.release_state();repo.engine.dispose()


@pytest.mark.parametrize('shape',SHAPES)
def test_optional_peak_save_refusal_cannot_delay_a_later_smaller_episodes_high(shape,monkeypatch):
    initial=failures('partial')
    later=[*failures('small',800)[:10],ntlm('smallHit',810,'singlehit',success=True)]
    events=[normalize(zl.WRITERS[shape](row,f'partial-{n}')) for n,row in enumerate([*initial,*later])]
    rule,repo=NtlmPasswordSpray(),_repo()
    try:
        for match in rule.consume(events[:39]):
            publish(repo,rule,match)
        original=rule._save_episode
        def refused(*args):
            raise StateExhausted('injected optional peak summary refusal')
        with monkeypatch.context() as context:
            context.setattr(rule,'_save_episode',refused)
            for match in rule.consume(events[39:40]):
                publish(repo,rule,match)
        assert rule._save_episode==original
        assert repo.candidates('h1')[0]['gate_results']['aggregate_summary']['peak']==40
        for match in rule.consume(events[40:]):
            publish(repo,rule,match)
        [candidate]=repo.candidates('h1')
        assert candidate['lane']=='high' and candidate['gate_results']['aggregate_summary']['peak']==40
        assert 'singlehit' in candidate['claim'].casefold()
        assert events[39].id in candidate['event_ids'] and events[-1].id in candidate['event_ids']
    finally:
        rule.release_state();repo.engine.dispose()


def test_retained_high_looks_up_its_own_backfilled_prior_after_another_shared_account():
    initial=[ntlm('otherPrior',-2,'bob',success=True),*failures('twoback'),
             ntlm('otherCurrent',20.5,'bob',success=True),ntlm('aliceHit',40,'alice',success=True)]
    later=[ntlm('alicePrior',-1,'alice',success=True)]
    later += [ntlm(f'twonew{n}',41+n,f'new{n}',success=False) for n in range(20)]
    events=[normalize(zl.WRITERS['elastic'](row,f'two-back-{n}')) for n,row in enumerate([*initial,*later])]
    rule,repo=NtlmPasswordSpray(),_repo()
    try:
        for match in rule.consume(events[:len(initial)]):
            publish(repo,rule,match)
        for match in [*rule.consume(events[len(initial):]),*rule.finalize()]:
            publish(repo,rule,match)
        [candidate]=repo.candidates('h1')
        assert candidate['lane']=='high' and 'alice' in candidate['claim'].casefold()
        assert events[len(initial)].id in candidate['event_ids']
        assert 'pre-episode' in details(candidate) and 'previously published high' in details(candidate)
    finally:
        rule.release_state();repo.engine.dispose()
