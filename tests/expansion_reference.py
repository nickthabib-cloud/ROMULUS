"""Frozen pre-cache expansion planner used as a behavioral oracle."""
import json
from collections import defaultdict

from romulus.decide.policy import LANE_ORDER
from romulus.hunt.context import finalize_context
from romulus.hunt.expansion import (
    BUDGET_TO_SEVERE_REASON,
    HOST_SIDE_LINKS,
    RESERVED_REASON,
    ExpansionEngine,
    _utc,
    expansion_windows,
)
from romulus.hunt.expansion_plan import TIER_PLAN
from romulus.hunt.links import LinkAnchor, is_agent_reach


class ReferenceExpansionEngine(ExpansionEngine):
    """The planner from main before per-run anchor caching and incremental discovery planning."""

    def _tier_slots(self, ordered, anchor_reasons, root_cap):
        for _tier, link_types, window_label in TIER_PLAN:
            tier_slots = []
            for link_type in link_types:
                for anchor_row in ordered:
                    candidate = self.repo.candidate(anchor_row["candidate_id"])
                    candidate_ts = _utc(candidate["ts"])
                    anchor_events = self._events(candidate["event_ids"])
                    base_anchor = LinkAnchor(
                        finding_id=candidate["id"], ts=candidate_ts, host=anchor_row["host"],
                        event_ids=candidate["event_ids"], events=anchor_events,
                    )
                    window = next(
                        item for item in expansion_windows(candidate_ts, self.window)
                        if item.label == window_label
                    )
                    variants, dropped = self._link_anchors(base_anchor, link_type)
                    if link_type in HOST_SIDE_LINKS and not base_anchor.host:
                        cap = root_cap if anchor_row["depth"] == 0 else self.max_source_queries
                        variants, dropped_ips, notes = self._victim_variants(
                            candidate["id"], variants, anchor_events, query_cap=cap,
                        )
                        anchor_reasons[anchor_row["id"]].extend(
                            note for note in notes if note not in anchor_reasons[anchor_row["id"]]
                        )
                        if dropped_ips:
                            anchor_reasons[anchor_row["id"]].append(
                                "keys_not_expanded:" + json.dumps(
                                    [{"victim_ip": ip} for ip in dropped_ips],
                                    sort_keys=True, separators=(",", ":"),
                                )
                            )
                    if dropped:
                        anchor_reasons[anchor_row["id"]].append(
                            "keys_not_expanded:" + json.dumps(
                                dropped, sort_keys=True, separators=(",", ":"),
                            )
                        )
                    for variant in variants:
                        if hasattr(self.fetcher, "result_id"):
                            stored = self.repo.expansion_link(
                                self.fetcher.result_id(variant, link_type, window)
                            )
                        else:
                            stored = self.repo.expansion_link_for(
                                candidate["id"], link_type, window.label, window.start, window.end
                            )
                        if not (stored and stored["evaluated"]):
                            tier_slots.append((
                                anchor_row, candidate, variant, link_type, window, stored,
                            ))
            if tier_slots:
                return tier_slots
        return []

    def run(self):
        self._seed_anchors()
        query_count = self.repo.expansion_source_queries(self.hunt_id)
        executor = getattr(self.fetcher, "executor", None)
        if executor is not None and hasattr(executor, "source_queries"):
            executor.source_queries = query_count
        anchor_reasons = defaultdict(list)
        blocked_anchors = set()
        stop_reason = "fixpoint"
        source_failed = False
        budget_blocked = {}
        while True:
            self._seed_anchors()
            all_rows = self.repo.expansion_anchors(self.hunt_id)
            self.budget = self._budget_for(all_rows)
            eligible = []
            for row in all_rows:
                if row["status"] != "pending" or row["id"] in blocked_anchors:
                    continue
                if row["depth"] >= self.max_depth:
                    reason = f"maximum expansion depth {self.max_depth} reached"
                    anchor_reasons[row["id"]].append(reason)
                    blocked_anchors.add(row["id"])
                    stop_reason = "depth_limit"
                    continue
                eligible.append(row)
            ranks = sorted({LANE_ORDER.get(row["lane"], 9) for row in eligible})
            ordered = [
                anchor_row
                for rank in ranks
                for anchor_row in self._ordered_anchors(
                    [row for row in eligible if LANE_ORDER.get(row["lane"], 9) == rank]
                )
            ]
            if not ranks:
                break
            root_cap = self._root_cap(all_rows, blocked_anchors, ranks[0])
            depths = {row["id"]: row["depth"] for row in all_rows}
            released = False
            for anchor_id, (limit, added) in list(budget_blocked.items()):
                if (root_cap if depths[anchor_id] == 0 else self.budget) > limit:
                    del budget_blocked[anchor_id]
                    blocked_anchors.discard(anchor_id)
                    for reason in added:
                        anchor_reasons[anchor_id].remove(reason)
                    released = True
            if released:
                continue
            slots = self._tier_slots(ordered, anchor_reasons, root_cap)
            if not slots:
                break
            spent = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
            if isinstance(spent, int):
                query_count = max(query_count, spent)
            made_progress = False
            known_anchor_ids = {row["id"] for row in all_rows}
            for slot_index, (anchor_row, candidate, anchor, link_type, window, stored) in enumerate(slots):
                budget_reason = None if stored else self._budget_reason(query_count)
                if budget_reason:
                    stop_reason = "budget"
                    added = [budget_reason]
                    if budget_reason == "source query budget exhausted" and any(
                        LANE_ORDER.get(row["lane"], 9) < LANE_ORDER.get(anchor_row["lane"], 9)
                        for row in all_rows
                    ):
                        added.append(BUDGET_TO_SEVERE_REASON)
                    anchor_reasons[anchor_row["id"]].extend(added)
                    if budget_reason == "source query budget exhausted":
                        budget_blocked[anchor_row["id"]] = (self.budget, added)
                    blocked_anchors.add(anchor_row["id"])
                    continue
                allowed_budget = root_cap if anchor_row["depth"] == 0 and not stored else self.budget
                remaining = allowed_budget - query_count
                if not stored and remaining < 2:
                    stop_reason = "budget"
                    reason = (
                        RESERVED_REASON
                        if anchor_row["depth"] == 0 and root_cap < self.budget
                        else "source query budget exhausted"
                    )
                    budget_blocked[anchor_row["id"]] = (allowed_budget, [reason])
                    anchor_reasons[anchor_row["id"]].append(reason)
                    blocked_anchors.add(anchor_row["id"])
                    continue
                remaining_slots = len(slots) - slot_index
                query_cap = min(12, max(2, remaining // max(1, remaining_slots)))
                self.heartbeat()
                result = (
                    self._stored_result(stored)
                    if stored
                    else self.fetcher.fetch(anchor, link_type, window, query_cap=query_cap)
                )
                if not stored:
                    self._persist_link(result)
                    actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                    query_count = (
                        actual_queries if actual_queries is not None else query_count + result.query_spend
                    )
                self._evaluate(candidate, result)
                made_progress = True
                if result.status != "complete":
                    anchor_reasons[anchor_row["id"]].extend(
                        result.reasons or [f"{link_type} {result.status}"]
                    )
                if result.status == "failed":
                    stop_reason = "source_failure"
                    source_failed = True
                if self.after_link:
                    self.after_link(result)
                self._seed_anchors()
                if {row["id"] for row in self.repo.expansion_anchors(self.hunt_id)} - known_anchor_ids:
                    break
            if not made_progress:
                continue

        final_links = [
            link for link in self.repo.expansion_links(self.hunt_id)
            if not is_agent_reach(link["link_type"], link["strength"])
        ]
        for row in self.repo.expansion_anchors(self.hunt_id):
            if row["status"] != "pending":
                continue
            links = [link for link in final_links if link["anchor_id"] == row["id"]]
            reasons = sorted(set(anchor_reasons[row["id"]] + [
                reason for link in links if link["status"] != "complete"
                for reason in (link["reasons"] or [f"{link['link_type']} {link['status']}"])
            ]))
            if row["id"] in blocked_anchors:
                status = "expanded_partial" if links else "unexpanded"
            else:
                status = "expanded_partial" if reasons else "expanded_complete"
            self.repo.update_expansion_anchor(row["id"], status, reasons, owner_token=self.owner_token)
        finalize_context(self.repo, self.hunt_id, owner_token=self.owner_token)
        anchors = self.repo.expansion_anchors(self.hunt_id)
        if source_failed and stop_reason != "source_failure":
            stop_reason = f"{stop_reason}; source_failure"
        status = (
            "completed"
            if not source_failed and stop_reason in {"fixpoint", "depth_limit", "budget"}
            else "partial"
        )
        unfinished = [row for row in anchors if row["status"] in {"unexpanded", "expanded_partial"}]
        if unfinished:
            status = "partial"
            kinds = sorted({
                "keys not expanded" if reason.startswith("keys_not_expanded:") else reason
                for row in unfinished for reason in row["reasons"]
            })
            shown = "; ".join(kinds[:5]) + (f"; +{len(kinds) - 5} more" if len(kinds) > 5 else "")
            unexpanded_count = sum(row["status"] == "unexpanded" for row in unfinished)
            accounting = (
                f"anchors not fully expanded: {unexpanded_count} unexpanded, "
                f"{len(unfinished) - unexpanded_count} partial" + (f" ({shown})" if shown else "")
            )
            stop_reason = accounting if stop_reason == "fixpoint" else f"{stop_reason}; {accounting}"
        summary = {
            "status": status,
            "stop_reason": stop_reason,
            "anchors": len(anchors),
            "expanded_complete": sum(row["status"] == "expanded_complete" for row in anchors),
            "expanded_partial": sum(row["status"] == "expanded_partial" for row in anchors),
            "unexpanded": [row["id"] for row in anchors if row["status"] == "unexpanded"],
            "source_queries": query_count,
            "budget": {
                "per_anchor_source_queries": self.per_anchor_source_queries,
                "max_source_queries": self.max_source_queries,
                "source_query_budget": self._budget_for(anchors),
                "ceiling_reached": self._budget_for(anchors) >= self.max_source_queries,
            },
        }
        self.repo.audit("system", "hunt.expansion_summary", self.hunt_id, summary,
                        owner_token=self.owner_token)
        return summary
