"""Deterministic expansion controller: accounting, budgets and resume."""
import copy
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import PivotCoverage
from romulus.config import Settings
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import run as hunt_run
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkResult
from romulus.report.manifest import build_manifest
from romulus.sources.models import Window
from romulus.store.db import digest, make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=3))


def event(event_id: str, *, host="web1", ts=T0, argv=None):
    fields = {"process.executable": fv((argv or ["/bin/sh"])[0], f"{event_id}:exe")}
    if argv is not None:
        fields["process.argv"] = fv(argv, f"{event_id}:argv")
    return TypedEvent(
        id=event_id, family="process_exec", ts=ts, host=host, outcome=Outcome.success,
        fields=fields, raw=[RawRef(target="host-x", native_id=event_id, digest="d")],
        normalizer="test@1",
    )


def repo_with_anchor(*, host="web1", candidate_id="F-anchor"):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "style": "broad", "hypothesis": "", "original_input": {}, "targets": [],
        "pack": {"version": "test", "playbooks": []}, "normalizer": "test", "policy": "test",
        "model": {}, "romulus_version": "test", "agent_mode": "off",
        "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    anchor = event("anchor-event", host=host)
    repo.save_evidence("h1", [anchor], {}, None)
    repo.save_candidate({
        "id": candidate_id, "hunt_id": "h1", "rule_id": "host.web_shell",
        "rule_version": "1", "claim": "web service spawned a shell",
        "claim_type": "observed_action", "event_ids": [anchor.id],
        "predicate_fields": [], "entities": [["host", host, "host"]], "ts": anchor.ts,
        "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    return repo


class ScriptedFetcher:
    def __init__(self, repo, *, linked=None, strength="observed", linked_type="host_after_anchor"):
        self.repo = repo
        self.linked = linked
        self.strength = strength
        self.linked_type = linked_type
        self.calls = []

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        assert anchor.ts.tzinfo is not None and anchor.ts.utcoffset() == timedelta(0)
        self.calls.append((anchor.finding_id, link_type, window.label))
        event_ids = [self.linked.id] if self.linked is not None and link_type == self.linked_type else []
        return LinkResult(
            id=f"L-{anchor.finding_id}-{link_type}-{window.label}", anchor_id=anchor.finding_id,
            link_type=link_type, window=window, strength=self.strength,
            key={"host": anchor.host, "type": link_type}, status="complete",
            event_ids=event_ids, evidence_ids=sorted(anchor.event_ids + event_ids),
            task_ids=[f"T-{len(self.calls)}"], coverage=[PivotCoverage(
                target="host-x", dataset="linux.audit", start=window.start, end=window.end,
                status="complete", returned=len(event_ids), total=len(event_ids),
            )],
            query_spend=1,
        )


class BudgetedFetcher(ScriptedFetcher):
    def __init__(self, repo):
        super().__init__(repo)
        self.executor = type("Counter", (), {"source_queries": 0})()
        self.query_caps = []

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        self.query_caps.append(query_cap)
        self.executor.source_queries += query_cap or 0
        result = super().fetch(anchor, link_type, window, query_cap=query_cap)
        result.query_spend = query_cap or 0
        return result


def add_anchor(repo, candidate_id, host, *, ts=T0):
    anchor = event(f"{candidate_id}-event", host=host, ts=ts)
    repo.save_evidence("h1", [anchor], {}, None)
    repo.save_candidate({
        "id": candidate_id, "hunt_id": "h1", "rule_id": "host.web_shell",
        "rule_version": "1", "claim": "web service spawned a shell",
        "claim_type": "observed_action", "event_ids": [anchor.id],
        "predicate_fields": [], "entities": [["host", host, "host"]], "ts": anchor.ts,
        "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })


def repo_with_aggregate_anchor(events, *, candidate_id="F-aggregate"):
    repo = repo_with_anchor(candidate_id=candidate_id)
    repo.save_evidence("h1", events, {}, None)
    with repo.engine.begin() as connection:
        from romulus.store import schema as tables
        connection.execute(tables.candidate.update().where(
            tables.candidate.c.id == candidate_id,
        ).values(event_ids=[item.id for item in events], ts=events[0].ts))
    return repo


def test_resume_seed_does_not_promote_agent_published_candidate_to_deterministic_anchor():
    repo = repo_with_anchor()
    add_anchor(repo, "F-agent-published", "web2")
    with repo.engine.begin() as connection:
        from romulus.store import schema as tables
        connection.execute(tables.candidate.update().where(
            tables.candidate.c.id == "F-agent-published",
        ).values(source_case_id="case-1", source_anchor_id="F-anchor", source_link_id="L-agent"))

    ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo))._seed_anchors()

    assert {row["candidate_id"] for row in repo.expansion_anchors("h1")} == {"F-anchor"}


class KeyRecordingFetcher(ScriptedFetcher):
    def result_id(self, anchor, link_type, window):
        pid = anchor.events[0].get("process.pid") if anchor.events else None
        return "L-" + digest({
            "anchor": anchor.finding_id, "link": link_type, "window": window.label, "pid": pid,
        })[:20]

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        result = super().fetch(anchor, link_type, window, query_cap=query_cap)
        pid = anchor.events[0].get("process.pid") if anchor.events else None
        result.id = self.result_id(anchor, link_type, window)
        result.key = {"host": anchor.host, "pid": pid}
        return result


class DurableBudgetFetcher(ScriptedFetcher):
    def __init__(self, repo, budget=180):
        super().__init__(repo)
        self.executor = type("Counter", (), {"source_queries": 0, "source_query_budget": budget})()
        self.queries_executed = 0

    def result_id(self, anchor, link_type, window):
        return f"L-{anchor.finding_id}-{link_type}-{window.label}"

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        remaining = self.executor.source_query_budget - self.executor.source_queries
        spent = min(query_cap or 0, max(0, remaining))
        self.executor.source_queries += spent
        self.queries_executed += spent
        task_id = f"T-durable-{len(self.calls) + 1}"
        self.repo.upsert_task(
            task_id, "h1", "expansion_link", anchor.finding_id,
            {"link_type": link_type, "window": window.label}, f"fp-{task_id}",
        )
        for _ in range(spent):
            self.repo.record_task_source_query(task_id)
        result = super().fetch(anchor, link_type, window, query_cap=query_cap)
        result.query_spend = spent
        result.task_ids = [task_id]
        return result


def stable_state(repo):
    return {
        "anchors": [{k: row[k] for k in ("id", "candidate_id", "depth", "parent_anchor_id", "status", "reasons")}
                    for row in repo.expansion_anchors("h1")],
        "links": [{k: row[k] for k in ("id", "anchor_id", "link_type", "window_label", "strength",
                                                     "status", "event_ids", "evaluated")}
                  for row in repo.expansion_links("h1")],
    }


def seed_agent_reach(repo, *, query_spend=170, status="partial"):
    ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo))._seed_anchors()
    repo.upsert_task(
        "T-agent", "h1", "agent_follow_link", "agent-session",
        {"link_type": "process_lineage"}, "fp-agent",
    )
    with repo.engine.begin() as connection:
        from romulus.store import schema as tables
        connection.execute(tables.task.update().where(
            tables.task.c.id == "T-agent",
        ).values(source_queries=query_spend))
    repo.save_expansion_link({
        "id": "L-agent", "hunt_id": "h1", "anchor_id": "F-anchor",
        "link_type": "agent_follow_process_lineage", "window_label": "agent requested",
        "window_start": WINDOW.start, "window_end": WINDOW.end,
        "strength": "agent_hypothesis", "key": {"agent_tool": "follow_link"},
        "status": status, "event_ids": [], "evidence_ids": ["anchor-event"],
        "task_ids": ["T-agent"], "coverage": [],
        "reasons": ["agent query cap"] if status != "complete" else [],
        "duration_ms": 1, "query_spend": query_spend, "evaluated": 1,
    })


def without_timing(manifest):
    cleaned = copy.deepcopy(manifest)
    cleaned["hunt"]["started_at"] = None
    cleaned["hunt"]["ended_at"] = None
    for finding in cleaned["findings"]:
        for disposition in finding["disposition_history"]:
            disposition["at"] = None
    return cleaned


def test_two_runs_have_identical_deterministic_expansion_state():
    states = []
    manifests = []
    for _ in range(2):
        repo = repo_with_anchor()
        result = ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo)).run()
        assert result["stop_reason"] == "fixpoint"
        states.append(stable_state(repo))
        manifests.append(build_manifest(repo, "h1", "test"))

    assert states[0] == states[1]
    assert without_timing(manifests[0]) == without_timing(manifests[1])


def test_budget_exhaustion_lists_every_unworked_anchor():
    repo = repo_with_anchor()

    result = ExpansionEngine(
        repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0,
    ).run()

    assert result["stop_reason"].startswith("budget; anchors not fully expanded: 1 unexpanded")
    assert result["unexpanded"] == ["F-anchor"]
    anchor = repo.expansion_anchors("h1")[0]
    assert anchor["status"] == "unexpanded"
    assert "source query budget exhausted" in anchor["reasons"]


def test_tier_scheduler_gives_each_host_a_fetch_before_dense_anchor_can_starve_it():
    repo = repo_with_anchor(host="web1", candidate_id="F-one")
    add_anchor(repo, "F-two", "web2", ts=T0 + timedelta(seconds=1))
    fetcher = BudgetedFetcher(repo)

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=8).run()

    assert [call[0] for call in fetcher.calls[:2]] == ["F-one", "F-two"]
    assert fetcher.query_caps[:2] == [2, 2]


def test_aggregate_anchor_expands_each_distinct_process_id():
    first = event("aggregate-one")
    first.fields["process.pid"] = fv(100, "aggregate-one:pid")
    second = event("aggregate-two", ts=T0 + timedelta(seconds=1))
    second.fields["process.pid"] = fv(200, "aggregate-two:pid")
    repo = repo_with_aggregate_anchor([first, second])
    fetcher = KeyRecordingFetcher(repo)

    ExpansionEngine(repo, "h1", WINDOW, fetcher).run()

    lineage_keys = {
        row["key"]["pid"] for row in repo.expansion_links("h1")
        if row["link_type"] == "process_lineage"
    }
    assert lineage_keys == {100, 200}


def test_network_anchor_has_no_host_identity_and_never_uses_an_ip_or_the_sensor():
    network_event = TypedEvent(
        id="network-anchor", family="net_alert", ts=T0, host="sensor1", outcome=Outcome.success,
        fields={
            "source.ip": fv("203.0.113.8", "network-anchor:src"),
            "destination.ip": fv("10.0.0.8", "network-anchor:dst"),
        },
        raw=[RawRef(target="network-x", native_id="network-anchor", digest="d")],
        normalizer="test@1",
    )
    repo = repo_with_aggregate_anchor([network_event], candidate_id="F-network")

    ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0).run()

    anchor_row = repo.expansion_anchors("h1")[0]
    assert anchor_row["host"] is None                      # an address is not a host identity
    assert ExpansionEngine._victim_ips([network_event]) == ["10.0.0.8"]


def test_network_anchor_without_internal_endpoint_never_uses_sensor_host():
    network_event = TypedEvent(
        id="public-network-anchor", family="net_alert", ts=T0, host="sensor1",
        fields={
            "source.ip": fv("203.0.113.8", "public-network-anchor:src"),
            "destination.ip": fv("198.51.100.9", "public-network-anchor:dst"),
        },
        raw=[RawRef(target="network-x", native_id="public-network-anchor", digest="d")],
        normalizer="test@1",
    )
    repo = repo_with_aggregate_anchor([network_event], candidate_id="F-public-network")

    ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0).run()

    assert repo.expansion_anchors("h1")[0]["host"] is None


def test_dropped_aggregate_keys_make_anchor_partial_and_list_the_keys():
    events = []
    for pid in range(100, 109):
        item = event(f"aggregate-{pid}", ts=T0 + timedelta(seconds=pid - 100))
        item.fields["process.pid"] = fv(pid, f"aggregate-{pid}:pid")
        events.append(item)
    repo = repo_with_aggregate_anchor(events)

    ExpansionEngine(repo, "h1", WINDOW, KeyRecordingFetcher(repo)).run()

    anchor_row = repo.expansion_anchors("h1")[0]
    assert anchor_row["status"] == "expanded_partial"
    assert any(reason.startswith("keys_not_expanded:") for reason in anchor_row["reasons"])
    assert any('"process.pid":108' in reason for reason in anchor_row["reasons"])


def test_resume_continues_after_crash_without_repeating_evaluated_links():
    repo = repo_with_anchor()
    first_fetcher = ScriptedFetcher(repo)
    calls = 0

    def crash_after_first(_link):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        ExpansionEngine(repo, "h1", WINDOW, first_fetcher, after_link=crash_after_first).run()
    first_key = first_fetcher.calls[0]
    assert repo.expansion_links("h1")[0]["evaluated"] == 1

    resumed_fetcher = ScriptedFetcher(repo)
    result = ExpansionEngine(repo, "h1", WINDOW, resumed_fetcher).run()

    assert result["stop_reason"] == "fixpoint"
    assert first_key not in resumed_fetcher.calls
    assert repo.expansion_anchors("h1")[0]["status"] == "expanded_complete"


def test_resume_after_fetch_before_evaluation_matches_uninterrupted_state_and_keeps_citations():
    linked = event("linked-event", ts=T0 + timedelta(seconds=1), argv=["/usr/bin/id"])

    class CitingFetcher(ScriptedFetcher):
        def fetch(self, anchor, link_type, window, *, query_cap=None):
            result = super().fetch(anchor, link_type, window, query_cap=query_cap)
            if result.event_ids:
                self.repo.save_evidence(
                    "h1", [linked], {linked.raw[0].key: {"marker": linked.id}}, None,
                )
            return result

    def prepared_repo():
        repo = repo_with_anchor()
        anchor_event = event("anchor-event")
        repo.merge_evidence_raw(
            "h1", [anchor_event], {anchor_event.raw[0].key: {"marker": anchor_event.id}},
        )
        return repo

    uninterrupted = prepared_repo()
    uninterrupted_summary = ExpansionEngine(
        uninterrupted, "h1", WINDOW,
        CitingFetcher(uninterrupted, linked=linked, linked_type="login_session"),
    ).run()

    resumed = prepared_repo()
    first_fetcher = CitingFetcher(resumed, linked=linked, linked_type="login_session")
    crashing = ExpansionEngine(
        resumed, "h1", WINDOW, first_fetcher,
    )

    def crash_before_evaluation(_candidate, _result):
        raise RuntimeError("simulated crash before evaluation")

    crashing._evaluate = crash_before_evaluation
    with pytest.raises(RuntimeError, match="simulated crash before evaluation"):
        crashing.run()
    [fetched_link] = resumed.expansion_links("h1")
    first_key = first_fetcher.calls[0]
    assert fetched_link["evaluated"] == 0
    assert fetched_link["event_ids"] == [linked.id]

    resumed_fetcher = CitingFetcher(resumed, linked=linked, linked_type="login_session")
    resumed_summary = ExpansionEngine(resumed, "h1", WINDOW, resumed_fetcher).run()

    assert first_key not in resumed_fetcher.calls
    assert stable_state(resumed) == stable_state(uninterrupted)
    assert {key: resumed_summary[key] for key in ("status", "stop_reason", "source_queries")} == {
        key: uninterrupted_summary[key] for key in ("status", "stop_reason", "source_queries")
    }
    cited = {
        event_id
        for row in [*resumed.candidates("h1"), *resumed.expansion_links("h1")]
        for field in ("event_ids", "evidence_ids")
        for event_id in row.get(field) or []
    }
    stored = {row["id"]: row for row in resumed.citation_events("h1", sorted(cited))}
    assert set(stored) == cited
    assert all(row["raw_ids"] for row in stored.values())
    assert {
        raw_id for row in stored.values() for raw_id in row["raw_ids"]
    } == {
        row["id"] for row in resumed.raw_records(sorted({
            raw_id for event_row in stored.values() for raw_id in event_row["raw_ids"]
        }))
    }


def test_resume_seeds_budget_from_persisted_query_spend_and_uses_only_remainder():
    repo = repo_with_anchor()
    first = DurableBudgetFetcher(repo)
    engine = ExpansionEngine(repo, "h1", WINDOW, first, max_source_queries=180)
    engine._seed_anchors()
    with repo.engine.begin() as connection:
        from romulus.store import schema as tables
        connection.execute(tables.expansion_anchor.update().where(
            tables.expansion_anchor.c.id == "F-anchor",
        ).values(depth=1))
    repo.upsert_task(
        "T-crash", "h1", "expansion_link", "F-anchor",
        {"purpose": "crash checkpoint"}, "fp-crash",
    )
    with repo.engine.begin() as connection:
        from romulus.store import schema as tables
        connection.execute(tables.task.update().where(
            tables.task.c.id == "T-crash",
        ).values(source_queries=170))
    repo.save_expansion_link({
        "id": "L-crash-checkpoint", "hunt_id": "h1", "anchor_id": "F-anchor",
        "link_type": "login_session", "window_label": "crash checkpoint",
        "window_start": WINDOW.start, "window_end": WINDOW.end,
        "strength": "observed", "key": {"checkpoint": True}, "status": "partial",
        "event_ids": [], "evidence_ids": [], "task_ids": ["T-crash"], "coverage": [],
        "reasons": ["link checkpoint lagged physical query 170"], "duration_ms": 1,
        "query_spend": 168, "evaluated": 1,
    })
    resumed = DurableBudgetFetcher(repo)

    result = ExpansionEngine(
        repo, "h1", WINDOW, resumed, max_source_queries=180,
    ).run()

    assert resumed.executor.source_queries == 180
    assert 170 + resumed.queries_executed == 180
    assert result["source_queries"] == 180
    assert repo.expansion_source_queries("h1") == 180


def test_agent_spend_and_reach_do_not_consume_or_taint_resumed_deterministic_expansion():
    repo = repo_with_anchor()
    seed_agent_reach(repo)

    assert repo.expansion_source_queries("h1") == 0

    fetcher = ScriptedFetcher(repo)
    result = ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=180).run()

    assert fetcher.calls
    assert result["expanded_complete"] == 1
    assert result["expanded_partial"] == 0
    assert repo.expansion_anchors("h1")[0]["status"] == "expanded_complete"
    assert not [cell for cell in repo.rule_cells("h1") if cell["target"].startswith("link:agent_")]


def test_expansion_failure_ignores_agent_reach_when_classifying_unworked_anchor(tmp_path, monkeypatch):
    repo = repo_with_anchor()
    seed_agent_reach(repo, query_spend=1, status="complete")
    monkeypatch.setattr(hunt_run, "_run_expansion", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("source unavailable"),
    ))

    summary = hunt_run._run_expansion_safely(
        Settings(home=tmp_path), repo, object(), repo.get_hunt("h1"), {}, WINDOW, None,
    )

    assert summary["status"] == "failed"
    assert repo.expansion_anchors("h1")[0]["status"] == "unexpanded"


def test_inferred_link_context_candidate_is_lead_and_keeps_provenance():
    repo = repo_with_anchor()
    discovery = event("discovery", ts=T0 + timedelta(minutes=1), argv=["whoami"])
    repo.save_evidence("h1", [discovery], {}, None)
    fetcher = ScriptedFetcher(
        repo, linked=discovery, strength="inferred", linked_type="process_lineage",
    )

    ExpansionEngine(repo, "h1", WINDOW, fetcher).run()

    candidates = [row for row in repo.candidates("h1") if row["id"] != "F-anchor"]
    assert len(candidates) == 1
    assert candidates[0]["lane"] == "lead"
    assert candidates[0]["source_anchor_id"] == "F-anchor"
    assert candidates[0]["source_link_id"].startswith("L-F-anchor-process_lineage")


def test_inferred_link_keeps_a_direct_finding_lane_and_labels_only_the_relation_a_hypothesis():
    repo = repo_with_anchor()
    credential_read = event(
        "credential-read", ts=T0 + timedelta(minutes=1),
        argv=["/usr/bin/cat", "/etc/shadow"],
    )
    repo.save_evidence("h1", [credential_read], {}, None)

    ExpansionEngine(
        repo, "h1", WINDOW,
        ScriptedFetcher(
            repo, linked=credential_read, strength="inferred",
            linked_type="host_after_anchor",
        ),
    ).run()

    finding = next(
        candidate for candidate in repo.candidates("h1")
        if candidate["rule_id"] == "host.credential_store_read"
    )
    # strong indicators are reported on their own: the inferred link never lowers the lane
    assert finding["lane"] in ("urgent", "high")
    assert "relation to f-anchor" in finding["claim"].lower() and "hypothesis" in finding["claim"].lower()
    assert any("relation to the anchor is a hypothesis" in note
               for note in finding["gate_results"]["_notes"])


def test_nested_windows_each_evaluate_the_event_but_publish_one_context_finding():
    repo = repo_with_anchor()
    discovery = event("discovery", ts=T0 + timedelta(minutes=1), argv=["/usr/bin/whoami"])
    repo.save_evidence("h1", [discovery], {}, None)

    ExpansionEngine(
        repo, "h1", WINDOW,
        ScriptedFetcher(repo, linked=discovery, linked_type="process_lineage"),
    ).run()

    context_candidates = [
        row for row in repo.candidates("h1")
        if row["rule_id"] == "context.post_access_discovery"
    ]
    cells = [
        row for row in repo.rule_cells("h1")
        if row["rule_id"] == "context.post_access_discovery"
        and row["target"] == "link:process_lineage"
        and row["partition"].startswith("anchor:F-anchor|")
    ]
    assert len(context_candidates) == 1
    assert len(cells) == 3
    assert all(row["evaluated"] == 1 and row["matched"] == 1 for row in cells)


def test_anchor_at_maximum_depth_is_not_expanded():
    repo = repo_with_anchor()
    fetcher = ScriptedFetcher(repo)
    engine = ExpansionEngine(repo, "h1", WINDOW, fetcher, max_depth=3)
    engine._seed_anchors()
    with repo.engine.begin() as connection:
        from romulus.store import schema as tables
        connection.execute(tables.expansion_anchor.update().values(depth=3))

    engine.run()

    anchor_row = repo.expansion_anchors("h1")[0]
    assert fetcher.calls == []
    assert anchor_row["status"] == "unexpanded"
    assert anchor_row["reasons"] == ["maximum expansion depth 3 reached"]


def test_budget_stop_after_some_links_marks_anchor_expanded_partial():
    repo = repo_with_anchor()

    ExpansionEngine(
        repo, "h1", WINDOW, BudgetedFetcher(repo), max_source_queries=4,
    ).run()

    anchor_row = repo.expansion_anchors("h1")[0]
    assert repo.expansion_links("h1")
    assert anchor_row["status"] == "expanded_partial"
    assert any("budget" in reason for reason in anchor_row["reasons"])


def test_root_anchor_preserves_query_reserve_for_newly_discovered_anchor():
    repo = repo_with_anchor()
    fetcher = BudgetedFetcher(repo)
    inserted = False

    def discover_child(_result):
        nonlocal inserted
        if inserted:
            return
        inserted = True
        add_anchor(repo, "F-child", "web2", ts=T0 + timedelta(minutes=1))
        with repo.engine.begin() as connection:
            from romulus.store import schema as tables
            connection.execute(tables.candidate.update().where(
                tables.candidate.c.id == "F-child",
            ).values(source_anchor_id="F-anchor"))

    ExpansionEngine(
        repo, "h1", WINDOW, fetcher, max_source_queries=4, after_link=discover_child,
    ).run()

    assert fetcher.executor.source_queries <= 4
    assert sum(cap for call, cap in zip(fetcher.calls, fetcher.query_caps, strict=True)
               if call[0] == "F-anchor") <= 3
    assert any(call[0] == "F-child" for call in fetcher.calls)


def test_new_anchor_discovered_in_tier_two_receives_tier_one_links():
    repo = repo_with_anchor()
    fetcher = ScriptedFetcher(repo)
    inserted = False

    def discover_after_tier_two(result):
        nonlocal inserted
        if inserted or result.link_type != "host_after_anchor" or result.window.label != "anchor ±5 min":
            return
        inserted = True
        add_anchor(repo, "F-child", "web2", ts=T0 + timedelta(minutes=1))
        with repo.engine.begin() as connection:
            from romulus.store import schema as tables
            connection.execute(tables.candidate.update().where(
                tables.candidate.c.id == "F-child",
            ).values(source_anchor_id="F-anchor"))

    ExpansionEngine(repo, "h1", WINDOW, fetcher, after_link=discover_after_tier_two).run()

    assert any(
        finding_id == "F-child" and link_type == "login_session"
        and label == "anchor ±5 min"
        for finding_id, link_type, label in fetcher.calls
    )


def test_resume_runs_expansion_before_optional_agent_without_rerunning_sweep(tmp_path, monkeypatch):
    settings = __import__("romulus.config", fromlist=["Settings"]).Settings(home=tmp_path, agent_mode="model")
    repo = hunt_run.open_repo(settings)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "targets": [], "source_profiles": {}, "agent_mode": "model", "expansion": {"enabled": True},
        "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    repo.claim_hunt("h1", 1, now=T0 - timedelta(hours=2))
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True, "stats": {}})
    repo.set_hunt_state("h1", "partial", stop_reason="interrupted expansion")
    order = []
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args: {})
    monkeypatch.setattr(hunt_run, "_run_expansion", lambda *_args, **_kwargs: order.append("expansion") or {
        "status": "completed", "stop_reason": "fixpoint", "unexpanded": [],
    })
    monkeypatch.setattr(hunt_run, "_run_investigator", lambda *_args, **_kwargs: order.append("agent") or {
        "status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0,
    })

    hunt_run.resume_hunt(settings, "h1")

    assert order == ["expansion", "agent"]


def test_rerun_keeps_a_budget_stopped_unexpanded_anchor_unexpanded_with_its_reason():
    repo = repo_with_anchor()
    ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0).run()
    recorded = repo.expansion_anchors("h1")[0]
    assert recorded["status"] == "unexpanded"
    assert "source query budget exhausted" in recorded["reasons"]

    resumed = ScriptedFetcher(repo)
    summary = ExpansionEngine(repo, "h1", WINDOW, resumed).run()

    anchor = repo.expansion_anchors("h1")[0]
    assert resumed.calls == []                     # left as recorded, not re-attempted
    assert anchor["status"] == "unexpanded"
    assert anchor["reasons"] == recorded["reasons"]
    assert summary["unexpanded"] == ["F-anchor"] and summary["expanded_complete"] == 0
    # the run itself reached a fixpoint, but the hunt's expansion is still incomplete, and says why
    assert summary["status"] == "partial"
    assert "fixpoint" not in summary["stop_reason"]
    assert "source query budget exhausted" in summary["stop_reason"]


def test_budget_stop_makes_the_expansion_summary_partial_with_the_recorded_reason():
    repo = repo_with_anchor()

    summary = ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0).run()

    assert summary["status"] == "partial"
    assert summary["stop_reason"].startswith("budget")
    assert "1 unexpanded" in summary["stop_reason"]
    assert "source query budget exhausted" in summary["stop_reason"]


def test_resumed_hunt_with_recorded_unexpanded_anchor_stays_partial(tmp_path, monkeypatch):
    settings = __import__("romulus.config", fromlist=["Settings"]).Settings(home=tmp_path, agent_mode="off")
    repo = hunt_run.open_repo(settings)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "targets": [], "source_profiles": {}, "agent_mode": "off", "expansion": {"enabled": True},
        "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    add_anchor(repo, "F-anchor", "web1")
    token = repo.claim_hunt("h1", 600)["lease_owner"]
    sweep_summary = {"finished": True, "complete": True, "partial_reasons": [], "stats": {}}
    repo.audit("system", "hunt.sweep_summary", "h1", sweep_summary, owner_token=token)
    repo.audit("system", "hunt.packet_summary", "h1", {"finished": True}, owner_token=token)
    # the first run's tail: expansion stops on budget, then the hunt finishes
    first = ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0,
                            owner_token=token).run()
    hunt_run._finish(repo, "h1", {"status": "disabled", "stop_reason": "agent off"}, sweep_summary,
                     expansion_summary=first, owner_token=token)
    assert repo.get_hunt("h1")["execution_state"] == "partial"

    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args: {})
    monkeypatch.setattr(
        hunt_run, "_run_expansion",
        lambda _s, repo, _client, hunt, _contracts, window, owner_token: ExpansionEngine(
            repo, hunt["id"], window, ScriptedFetcher(repo), owner_token=owner_token).run(),
    )

    result = hunt_run.resume_hunt(settings, "h1")

    hunt = hunt_run.open_repo(settings).get_hunt("h1")
    assert result["execution_state"] == "partial" and hunt["execution_state"] == "partial"
    assert "source query budget exhausted" in hunt["stop_reason"]
    assert hunt_run.open_repo(settings).expansion_anchors("h1")[0]["status"] == "unexpanded"


def test_rerun_keeps_an_expanded_partial_anchor_partial_with_its_reasons():
    repo = repo_with_anchor()
    ExpansionEngine(repo, "h1", WINDOW, BudgetedFetcher(repo), max_source_queries=4).run()
    recorded = repo.expansion_anchors("h1")[0]
    assert recorded["status"] == "expanded_partial"
    assert any("budget" in reason for reason in recorded["reasons"])

    resumed = ScriptedFetcher(repo)
    summary = ExpansionEngine(repo, "h1", WINDOW, resumed).run()

    anchor = repo.expansion_anchors("h1")[0]
    assert resumed.calls == []
    assert anchor["status"] == "expanded_partial"
    assert anchor["reasons"] == recorded["reasons"]
    assert summary["expanded_partial"] == 1 and summary["expanded_complete"] == 0


def test_rerun_still_completes_a_pending_anchor_beside_recorded_ones():
    repo = repo_with_anchor()
    ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0).run()
    add_anchor(repo, "F-two", "web2", ts=T0 + timedelta(seconds=1))

    resumed = ScriptedFetcher(repo)
    summary = ExpansionEngine(repo, "h1", WINDOW, resumed).run()

    by_id = {row["id"]: row for row in repo.expansion_anchors("h1")}
    assert {call[0] for call in resumed.calls} == {"F-two"}
    assert by_id["F-two"]["status"] == "expanded_complete" and by_id["F-two"]["reasons"] == []
    assert by_id["F-anchor"]["status"] == "unexpanded"
    assert "source query budget exhausted" in by_id["F-anchor"]["reasons"]
    assert summary["unexpanded"] == ["F-anchor"] and summary["expanded_complete"] == 1


def test_rerun_over_recorded_anchors_is_deterministic():
    outcomes = []
    for _ in range(2):
        repo = repo_with_anchor()
        add_anchor(repo, "F-two", "web2", ts=T0 + timedelta(seconds=1))
        ExpansionEngine(repo, "h1", WINDOW, BudgetedFetcher(repo), max_source_queries=4).run()
        first = stable_state(repo)
        summary = ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo)).run()
        summary.pop("source_queries")
        outcomes.append((stable_state(repo), summary))
        assert outcomes[-1][0]["anchors"] == first["anchors"]
    assert outcomes[0] == outcomes[1]


def test_roots_use_half_the_reserve_only_while_no_discovered_anchor_waits():
    repo = repo_with_anchor()
    fetcher = BudgetedFetcher(repo)
    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=20).run()
    root_share, reserve = 16, 4                      # 20 minus the 20% reserve for discovered anchors
    assert root_share < fetcher.executor.source_queries <= root_share + reserve // 2
