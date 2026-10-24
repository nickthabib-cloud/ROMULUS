"""Slow synthetic measurements for expansion planning and the final context pass."""
from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

import pytest

from romulus.agent.models import PivotCoverage
from romulus.hunt import context as context_module
from romulus.hunt import expansion as expansion_module
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkResult
from tests import expansion_reference
from tests.expansion_reference import ReferenceExpansionEngine
from tests.test_bounded_context import _noise
from tests.test_context_catalog import _repo, _seed_anchor, _seed_link, exec_event
from tests.test_expansion_engine import T0, WINDOW, event


class _MemoryRepo:
    def __init__(self, anchors: int):
        self.rows = {}
        self.candidate_rows = {}
        self.events = {}
        self.links = {}
        self.added = []
        self.candidate_reads = 0
        self.event_reads = 0
        for index in range(anchors):
            self._add_anchor(f"F-{index:05d}", index, depth=0, parent=None, queued=False)

    def _add_anchor(self, candidate_id, index, *, depth, parent, queued):
        anchor_event = event(f"E-{candidate_id}", host=f"host{index % 100}", ts=T0)
        self.events[anchor_event.id] = anchor_event
        self.candidate_rows[candidate_id] = {
            "id": candidate_id, "rule_id": "host.web_shell", "group_key": f"g-{index}",
            "event_ids": [anchor_event.id], "ts": T0, "lane": "high", "severity": "high",
            "source_case_id": None, "source_anchor_id": parent,
        }
        row = {
            "id": candidate_id, "hunt_id": "h1", "candidate_id": candidate_id, "depth": depth,
            "parent_anchor_id": parent, "host": anchor_event.host, "lane": "high", "severity": "high",
            "ts": T0, "status": "pending", "reasons": [],
        }
        self.rows[candidate_id] = row
        if queued:
            self.added.append(row)

    def discover(self, index):
        self._add_anchor(f"F-found-{index:04d}", index, depth=1, parent="F-00000", queued=True)

    def take_added(self):
        added, self.added = self.added, []
        return added

    def expansion_anchors(self, _hunt_id):
        return sorted(self.rows.values(), key=lambda row: (row["depth"], row["ts"], row["id"]))

    def expansion_source_queries(self, _hunt_id):
        return 0

    def candidate(self, candidate_id):
        self.candidate_reads += 1
        return self.candidate_rows.get(candidate_id)

    def citation_events(self, _hunt_id, ids):
        self.event_reads += 1
        return [{"event": self.events[event_id].model_dump(mode="json")} for event_id in ids]

    def expansion_link(self, link_id):
        return self.links.get(link_id)

    def expansion_links(self, _hunt_id):
        return list(self.links.values())

    def update_expansion_anchor(self, anchor_id, status, reasons, **_kwargs):
        self.rows[anchor_id]["status"] = status
        self.rows[anchor_id]["reasons"] = reasons

    def audit(self, *_args, **_kwargs):
        return None


class _MemoryFetcher:
    def __init__(self):
        self.calls = []

    @staticmethod
    def result_id(anchor, link_type, window):
        return f"L-{anchor.finding_id}-{link_type}-{window.label}"

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        self.calls.append((anchor.finding_id, link_type, window.label, query_cap))
        return LinkResult(
            id=self.result_id(anchor, link_type, window), anchor_id=anchor.finding_id,
            link_type=link_type, window=window, strength="observed", key={"host": anchor.host},
            status="complete", event_ids=[], evidence_ids=anchor.event_ids, task_ids=[],
            coverage=[PivotCoverage(target="host-x", start=window.start, end=window.end,
                                    status="complete", returned=0, total=0)],
            query_spend=1,
        )


class _MeasuredMixin:
    def _seed_anchors(self):
        return self.repo.take_added()

    def _persist_link(self, result):
        self.repo.links[result.id] = {
            "id": result.id, "anchor_id": result.anchor_id, "link_type": result.link_type,
            "window_label": result.window.label, "window_start": result.window.start,
            "window_end": result.window.end, "strength": result.strength, "key": result.key,
            "status": result.status, "event_ids": result.event_ids, "evidence_ids": result.evidence_ids,
            "task_ids": result.task_ids, "coverage": [], "reasons": result.reasons,
            "duration_ms": result.duration_ms, "query_spend": result.query_spend, "evaluated": 0,
        }

    def _evaluate(self, _candidate, result):
        self.repo.links[result.id]["evaluated"] = 1
        return []


class _MeasuredEngine(_MeasuredMixin, ExpansionEngine):
    pass


class _ReferenceMeasuredEngine(_MeasuredMixin, ReferenceExpansionEngine):
    pass


@dataclass(frozen=True)
class _Timing:
    seconds: float
    fetches: int
    anchors: int
    candidate_reads: int
    event_reads: int

    @property
    def seconds_per_fetch(self):
        return self.seconds / self.fetches


def _planning_time(anchors: int, discoveries: int, engine_cls=_MeasuredEngine) -> _Timing:
    repo = _MemoryRepo(anchors)
    fetcher = _MemoryFetcher()

    def discover(_result):
        if len(fetcher.calls) <= discoveries:
            repo.discover(len(fetcher.calls) - 1)

    started = perf_counter()
    engine_cls(
        repo, "h1", WINDOW, fetcher, max_depth=2, max_source_queries=100_000,
        after_link=discover,
    ).run()
    elapsed = perf_counter() - started
    return _Timing(elapsed, len(fetcher.calls), len(repo.rows), repo.candidate_reads, repo.event_reads)


@pytest.mark.slow
def test_planning_cost_per_fetch_stays_near_constant_at_five_thousand_anchors(monkeypatch):
    one_link = (("T1", ("network_flow",), "anchor ±5 min"),)
    monkeypatch.setattr(expansion_module, "TIER_PLAN", one_link)
    monkeypatch.setattr(expansion_reference, "TIER_PLAN", one_link)
    monkeypatch.setattr(expansion_module, "finalize_context", lambda *_args, **_kwargs: None)

    small = _planning_time(1_000, 1_000)
    mission = _planning_time(5_000, 1_000)
    print(f"planning small={small.seconds:.3f}s/{small.fetches} "
          f"mission={mission.seconds:.3f}s/{mission.fetches}")

    assert mission.anchors == 6_000 and mission.fetches == 6_000
    assert mission.candidate_reads == mission.anchors
    assert mission.event_reads == mission.anchors
    assert mission.seconds_per_fetch <= small.seconds_per_fetch * 2.5


def _context_time(links: int, monkeypatch) -> tuple[float, int]:
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [
        exec_event("fa", ["/bin/sh"], process__pid=9),
    ])
    discovery = [
        exec_event("id", ["id"], executable="/usr/bin/id"),
        exec_event("uname", ["uname", "-a"], executable="/usr/bin/uname"),
        exec_event("ps", ["ps", "aux"], executable="/usr/bin/ps"),
    ]
    for link in range(links):
        _seed_link(repo, "h1", f"L-{link:04d}", "F-A", discovery + [
            _noise(link * 20 + index) for index in range(20)
        ])
    peak = {"held": 0}
    add = context_module._RuleReaches.add

    def watching(self, anchor, context_link, link_events, held):
        add(self, anchor, context_link, link_events, held)
        peak["held"] = max(peak["held"], len(held))

    with monkeypatch.context() as scoped:
        scoped.setattr(context_module._RuleReaches, "add", watching)
        started = perf_counter()
        context_module.finalize_context(repo, "h1")
        elapsed = perf_counter() - started
    assert peak["held"] <= len(discovery)
    return elapsed, len(discovery) + links * (len(discovery) + 20)


@pytest.mark.slow
def test_context_pass_is_linear_and_keeps_its_held_bound_at_ten_times_the_links(monkeypatch):
    small_seconds, small_records = _context_time(30, monkeypatch)
    large_seconds, large_records = _context_time(300, monkeypatch)
    print(f"context 1x={small_seconds:.3f}s/{small_records} records "
          f"10x={large_seconds:.3f}s/{large_records} records")

    assert large_records / small_records > 9
    assert large_seconds <= small_seconds * 15
