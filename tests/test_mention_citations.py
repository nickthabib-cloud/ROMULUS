"""A mention whose source record a finding also cites (a typed event made from it, or an AI finding citing the raw
record) is shown once, in the mention lane, with those findings named beside it: never dropped, never merged into the
finding, never changing a lane."""
from __future__ import annotations

from tests.test_mention_coverage import CONTRACT, SHELL, T0, TARGET, _hex, _record, _scanner


def _finding(repo, cid: str, lane: str, *, events=(), raw_records=(), priority: float = 1.0) -> None:
    from romulus.store import schema as t
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert().values(
            id=cid, hunt_id="h1", rule_id=f"rule.{cid}", rule_version="1", claim="c", claim_type="observed_action",
            event_ids=list(events), predicate_fields=[], entities=[], ts=T0, severity="high", confidence="high",
            lane=lane, priority=priority, priority_reasons=[], benign_alternatives=[], next_checks=[],
            gate_results={"_agent_raw_records": list(raw_records)} if raw_records else {},
            provenance="agent" if raw_records else "deterministic", created_at=T0))


def test_a_mention_whose_record_a_finding_cites_is_shown_once_beside_it(tmp_path):
    from romulus.report import markdown
    from romulus.report.mentions import mentions_view
    from romulus.store import schema as t
    from romulus.store.repo import raw_id
    from tests.test_mention_sweep import _repo
    repo = _repo()
    line = f"type=PROCTITLE msg=audit(1731938400.123:77): proctitle={_hex(SHELL)}"
    hits = [_record(1, {"message": line}), _record(2, {"message": "MIMIKATZ elsewhere"}, host="db1")]
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(hits[0], "x", False, ("proctitle",)), (hits[1], "x")], None)
    scanner.publish(repo)
    scanner.close()
    shell, other = repo.mentions("h1")
    # a typed event made from the same record, and a finding on it; an AI finding citing the raw record itself
    with repo.engine.begin() as connection:
        connection.execute(t.typed_event.insert().values(
            id="ev1", hunt_id="h1", family="net_socket", ts=T0, host="web1", event={}, normalizer="test",
            raw_ids=[raw_id(TARGET, "c1"), raw_id(TARGET, "unrelated")]))
    _finding(repo, "typed1", "high", events=["ev1"])
    _finding(repo, "agent1", "lead", raw_records=[shell["raw_id"]])
    _finding(repo, "unrelated", "urgent", events=["missing-event"])
    before = {row["id"]: row["lane"] for row in repo.candidates("h1")}
    view = mentions_view(repo, "h1")
    items = {item["id"]: item for item in view["items"]}
    assert items[shell["id"]]["cited_by"]["count"] == 2
    assert [(f["id"], f["lane"]) for f in items[shell["id"]]["cited_by"]["findings"]] == [
        ("typed1", "high"), ("agent1", "lead")]
    assert items[other["id"]]["cited_by"] == {"count": 0, "findings": []}
    # the mention is still listed once, in its own lane; the findings are unchanged by it
    assert view["total"] == 2 and all(item["lane"] == "mention" for item in view["items"])
    assert {row["id"]: row["lane"] for row in repo.candidates("h1")} == before
    text = "\n".join(markdown._mentions_section({"mentions": view}))
    assert "same record cited by 2 finding(s): typed1 (high), agent1 (lead)" in text


def test_the_store_reads_ai_findings_cited_raw_records_under_admissions_key():
    from romulus.evidence.raw_citation import RAW_GATE
    from romulus.store.repo import AGENT_RAW_GATE
    assert AGENT_RAW_GATE == RAW_GATE
