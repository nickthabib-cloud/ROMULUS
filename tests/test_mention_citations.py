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


def test_the_link_reads_only_the_shown_records_neighbourhood_at_scale(tmp_path):
    """100,000 findings on other records: the page's lookup stays bounded by the page (index probes), never by the
    hunt."""
    import time

    from romulus.store import schema as t
    from romulus.store.repo import raw_id
    from tests.test_mention_sweep import _repo
    repo = _repo(tmp_path / "h.sqlite")
    hits = [_record(n, {"message": f"MIMIKATZ {n}"}, host=f"web{n}") for n in range(50)]
    scanner = _scanner(tmp_path / "s")
    scanner.scan(TARGET, CONTRACT, [(hit, "x") for hit in hits], None)
    scanner.publish(repo)
    scanner.close()
    count, per = 100_000, 5
    with repo.engine.begin() as connection:
        connection.execute(t.typed_event.insert(), [{
            "id": f"ev{i}", "hunt_id": "h1", "family": "x", "ts": T0, "host": f"other{i % 997}", "event": {}, "normalizer": "n",
            "raw_ids": [raw_id("logs", f"r{i}")]} for i in range(count * per)])
        # the one event made from one mention's record
        connection.execute(t.typed_event.insert().values(
            id="own", hunt_id="h1", family="x", ts=T0, host="web7", event={}, normalizer="n",
            raw_ids=[raw_id(TARGET, "c7")]))
        connection.execute(t.candidate.insert(), [{
            "id": f"c{i}", "hunt_id": "h1", "rule_id": "r", "rule_version": "1", "claim": "c", "claim_type": "observed_action",
            "event_ids": [f"ev{i * per + j}" for j in range(per)], "predicate_fields": [], "entities": [], "ts": T0,
            "severity": "high", "confidence": "high", "lane": "lead", "priority": 1.0, "priority_reasons": [],
            "benign_alternatives": [], "next_checks": [], "gate_results": {}, "provenance": "deterministic", "created_at": T0}
            for i in range(count)])
    _finding(repo, "linked", "high", events=["own"])
    mentions = repo.mentions("h1", limit=50)
    began = time.perf_counter()
    out = repo.mention_citations("h1", mentions)
    took = time.perf_counter() - began
    linked = next(row["id"] for row in mentions if row["native_id"] == "c7")
    assert out == {linked: {"count": 1, "findings": [{"id": "linked", "rule_id": "rule.linked", "lane": "high"}]}}
    assert took < 0.25, took


def test_a_socket_finding_on_a_real_audit_group_links_the_process_title_mention(tmp_path):
    """Through the real normalizer and store: the socket event cites the PROCTITLE record the mention keeps."""
    from romulus.evidence.normalize import normalize_hits
    from romulus.report.mentions import mentions_view
    from tests.test_lineage_observations import SADDR_EXT_554, _syscall
    from tests.test_mention_coverage import _audit_hit
    from tests.test_mention_sweep import _repo
    repo = _repo()
    when = T0.timestamp() + 5
    title = chr(0).join(["python3", "-c", SHELL])
    hits = [_audit_hit("s1", _syscall(when, 1, nr=42, name="connect", pid=50, ppid=40, exe="/usr/bin/python3",
                                      comm="python3", a2="10", success="no", exit_code="-115"), when),
            _audit_hit("s2", f"type=SOCKADDR msg=audit({when:.3f}:1): saddr={SADDR_EXT_554}", when),
            _audit_hit("s3", f"type=PROCTITLE msg=audit({when:.3f}:1): proctitle={_hex(title)}", when)]
    unread: list = []
    events, _skips, errors = normalize_hits(hits, unread=unread)
    assert errors == [] and [event.family for event in events] == ["net_socket"]
    repo.save_evidence("h1", events, {f"{hit['_index']}/{hit['_id']}": hit["_source"] for hit in hits}, None)
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, unread, None)
    scanner.publish(repo)
    scanner.close()
    _finding(repo, "socket1", "high", events=[events[0].id])
    item = mentions_view(repo, "h1")["items"][0]
    assert item["cited_by"]["findings"] == [{"id": "socket1", "rule_id": "rule.socket1", "lane": "high"}]
