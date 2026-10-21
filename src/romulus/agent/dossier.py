"""Deterministic, paged JSON dossier assembled only from persisted hunt state."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from romulus.agent.aliases import AliasBook
from romulus.agent.provider.base import estimate_tokens
from romulus.agent.provider.budget import AgentBudget, BudgetLimits
from romulus.agent.safety import injection_flags
from romulus.decide.policy import LANE_ORDER
from romulus.hunt.expansion import TIER_PLAN
from romulus.report.incidents import build_incident_graph
from romulus.store.db import digest
from romulus.store.repo import Repo

DOSSIER_SCHEMA = "agent-dossier@1"
REPORTABLE_LANES = ("urgent", "high", "lead")
CLAIM_LIMIT = 180
_GAP_STATES = frozenset({
    "planned", "executed_failed", "evaluated_partial", "match_on_partial", "positive_only_partial",
})


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Dossier:
    """The first model page plus every deterministic findings-index page."""

    payload: dict[str, Any]
    pages: tuple[dict[str, Any], ...]

    def page(self, number: int) -> dict[str, Any]:
        if number < 1 or number > len(self.pages):
            raise IndexError(f"dossier page {number} is outside 1..{len(self.pages)}")
        return self.pages[number - 1]

    def json_bytes(self, page: int = 1) -> bytes:
        return _canonical(self.page(page)).encode("utf-8")


def _candidate_key(row: dict) -> tuple:
    return (LANE_ORDER.get(row["lane"], 99), -float(row["priority"]), row["ts"], row["id"])


def _entity_value(entities: list, kind: str) -> str | None:
    for item in entities or []:
        if isinstance(item, dict):
            item_kind, value = item.get("kind"), item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            item_kind, value = item[0], item[1]
        else:
            continue
        if item_kind == kind and value not in (None, ""):
            return str(value)
    return None


def _claim(text: str, alias: str) -> str:
    if len(text) <= CLAIM_LIMIT:
        return text
    return f"{text[:CLAIM_LIMIT]}…[+{len(text) - CLAIM_LIMIT} chars: get_finding {alias}]"


def _findings(repo: Repo, hunt_id: str, aliases: AliasBook) -> tuple[list[dict], Counter]:
    counts: Counter = Counter()
    out = []
    for row in sorted(repo.candidates(hunt_id), key=_candidate_key):
        counts[row["lane"]] += 1
        if row["lane"] not in REPORTABLE_LANES:
            continue
        alias = aliases.alias_for("F", row["id"])
        out.append({
            "alias": alias,
            "lane": row["lane"],
            "rule_id": row["rule_id"],
            "claim": _claim(row["claim"], alias),
            "host": _entity_value(row.get("entities") or [], "host"),
            "account": _entity_value(row.get("entities") or [], "account"),
            "time": str(row["ts"]),
        })
    return out, counts


def _coverage(repo: Repo, hunt_id: str, manifest: dict) -> dict:
    cells = sorted(repo.rule_cells(hunt_id), key=lambda row: (
        row["rule_id"], row["target"], row["partition"], row["rule_version"],
    ))
    gaps = [{
        "rule_id": row["rule_id"], "rule_version": row["rule_version"],
        "target": row["target"], "partition": row["partition"], "status": "partial",
        "state": row["state"], "detail": _jsonable(row.get("detail") or {}),
    } for row in cells if row["state"] in _GAP_STATES]
    rules = sorted({str(item["id"]) for item in (manifest.get("pack") or {}).get("playbooks", [])
                    if isinstance(item, dict) and item.get("id")})
    targets = sorted(str(target) for target in manifest.get("targets") or [])
    assessed = {(row["rule_id"], row["target"]) for row in cells if row["target"] != "*"}
    for rule_id in rules:
        for target in targets:
            if (rule_id, target) not in assessed:
                gaps.append({
                    "rule_id": rule_id, "rule_version": None, "target": target, "partition": "*",
                    "status": "unassessed", "state": "missing", "detail": {},
                })
    gaps.sort(key=lambda row: (row["rule_id"], row["target"], row["partition"], row["status"]))
    return {
        "summary": {
            "recorded_cells": len(cells),
            "partial_cells": sum(gap["status"] == "partial" for gap in gaps),
            "unassessed_cells": sum(gap["status"] == "unassessed" for gap in gaps),
        },
        "gaps": gaps,
    }


def _budget(repo: Repo, hunt_id: str, manifest: dict) -> dict:
    configured = ((manifest.get("ai_agent") or {}).get("budgets") or {})
    required = {"max_calls", "max_tokens", "max_wall_seconds"}
    if not required <= configured.keys():
        return {"configured": False, "spent": {}, "remaining": {}}
    limits = BudgetLimits(
        max_calls=int(configured["max_calls"]),
        max_tokens=int(configured["max_tokens"]),
        max_wall_seconds=int(configured["max_wall_seconds"]),
        max_cost_usd=float(configured.get("max_cost_usd") or 0.0),
        price_input_per_mtok=float(configured.get("price_input_per_mtok") or 0.0),
        price_output_per_mtok=float(configured.get("price_output_per_mtok") or 0.0),
    )
    usage = repo.agent_usage(hunt_id)
    budget = AgentBudget.from_usage(
        limits, usage, wall_seconds_before=repo.agent_elapsed_ms(hunt_id) / 1000.0, clock=lambda: 0.0,
    )
    spent = budget.snapshot()
    remaining = {
        "calls": max(0, limits.max_calls - budget.calls),
        "tokens": max(0, limits.max_tokens - budget.tokens),
        "wall_seconds": max(0.0, limits.max_wall_seconds - budget.wall_seconds()),
        "cost_usd": (max(0.0, limits.max_cost_usd - budget.cost_usd) if limits.max_cost_usd else None),
    }
    return {"configured": True, "spent": spent, "remaining": remaining}


def _incidents(repo: Repo, hunt_id: str, candidates: list[dict], aliases: AliasBook) -> list[dict]:
    graph_findings = [{
        "id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
        "observed_at": str(row["ts"]), "entities": row.get("entities") or [],
        "event_ids": row.get("event_ids") or [], "citations": [],
        "source_link_id": row.get("source_link_id"),
    } for row in candidates]
    graph = build_incident_graph(repo, hunt_id, graph_findings)
    links = {row["id"]: row for row in graph["links"]}
    out = []
    for incident in graph["incidents"]:
        members = [aliases.alias_for("F", target) for target in incident["finding_ids"]]
        incident_links = []
        for link_id in sorted(incident["link_ids"]):
            link = links[link_id]
            incident_links.append({
                "alias": aliases.alias_for("L", link_id),
                "link_type": link["link_type"], "strength": link["style"], "status": link["status"],
                "anchor": aliases.alias_for("F", link["anchor_finding_id"]),
                "targets": [aliases.alias_for("F", target) for target in link["target_finding_ids"]],
            })
        # A singleton with no link adds no investigative hypothesis beyond the
        # findings index. Keep only correlated incidents so the bounded dossier
        # spends its prompt budget on actual relationships.
        if len(members) > 1 or incident_links:
            out.append({"alias": aliases.alias_for("I", incident["id"]), "members": members,
                        "links": incident_links})
    return out


def _expansion(repo: Repo, hunt_id: str, aliases: AliasBook) -> dict:
    links = repo.expansion_links(hunt_id)
    by_anchor: dict[str, list[dict]] = {}
    for link in links:
        by_anchor.setdefault(link["anchor_id"], []).append(link)
    unfinished = []
    not_reached = []
    partial_links = []
    for row in repo.expansion_anchors(hunt_id):
        if row["status"] not in {"pending", "unexpanded", "expanded_partial"}:
            continue
        anchor_alias = aliases.alias_for("F", row["candidate_id"])
        reasons = sorted(str(reason) for reason in row.get("reasons") or [])
        unfinished.append({"anchor": anchor_alias, "status": row["status"], "reasons": reasons})
        existing = {(link["link_type"], link["window_label"]) for link in by_anchor.get(row["id"], [])}
        for tier, link_types, label in TIER_PLAN:
            for link_type in link_types:
                if (link_type, label) not in existing:
                    not_reached.append({
                        "anchor": anchor_alias, "tier": tier, "link_type": link_type,
                        "window": label,
                        "reasons": reasons or ["not reached before deterministic expansion stopped"],
                    })
        for link in by_anchor.get(row["id"], []):
            if link["status"] != "complete":
                partial_links.append({
                    "alias": aliases.alias_for("L", link["id"]), "anchor": anchor_alias,
                    "link_type": link["link_type"], "status": link["status"],
                    "reasons": sorted(str(reason) for reason in link.get("reasons") or []),
                })
    return {"unfinished_anchors": unfinished, "link_tiers_not_reached": not_reached,
            "partial_links": partial_links}


def _entity_refs(repo: Repo, candidates: list[dict], aliases: AliasBook) -> list[dict]:
    wanted = {(str(item[0]), str(item[1])) for row in candidates for item in row.get("entities") or []
              if isinstance(item, (list, tuple)) and len(item) >= 2}
    return [{
        "alias": aliases.alias_for("N", row["id"]), "kind": row["kind"], "value": row["value"],
    } for row in repo.entities(aliases.hunt_id) if (row["kind"], row["value"]) in wanted]


def _page_payload(base: dict, findings: list[dict], page: int, pages: int, cursor: str) -> dict:
    if page < pages:
        message = (f"index page {page} of {pages}; call list_findings(page={page + 1},"
                   f"cursor={cursor}) for the rest")
    else:
        message = f"index page {page} of {pages}; all findings in the index have been included"
    payload = {**base, "header": {**base["header"], "index": {
        "page": page, "pages": pages, "cursor": cursor, "message": message,
    }}, "findings": findings}
    return _jsonable(payload)


def _paginate(base: dict, findings: list[dict], token_budget: int, cursor: str) -> tuple[dict, ...]:
    one = _page_payload(base, findings, 1, 1, cursor)
    if estimate_tokens(_canonical(one)) <= token_budget:
        return (one,)
    continuation = {"schema": base["schema"], "header": base["header"]}
    chunks: list[list[dict]] = []
    remaining = list(findings)
    while remaining or not chunks:
        page_base = base if not chunks else continuation
        current: list[dict] = []
        while remaining:
            trial = current + [remaining[0]]
            # Six digits reserves more header room than any realistic page count.
            if estimate_tokens(_canonical(_page_payload(
                    page_base, trial, 999999, 999999, cursor))) > token_budget:
                break
            current.append(remaining.pop(0))
        if not current and remaining:
            if chunks:
                raise ValueError("token_budget is too small for one dossier finding")
            # The context envelope can consume a small budget by itself. Emit it
            # once, then use compact continuation pages for the findings index.
            if estimate_tokens(_canonical(_page_payload(
                    page_base, [], 999999, 999999, cursor))) > token_budget:
                raise ValueError("token_budget is too small for the dossier context")
        chunks.append(current)
        if not remaining:
            break
    total = len(chunks)
    return tuple(_page_payload(base if index == 1 else continuation, chunk, index, total, cursor)
                 for index, chunk in enumerate(chunks, 1))


def build_dossier(repo: Repo, hunt_id: str, *, token_budget: int) -> Dossier:
    """Build a canonical JSON dossier without querying a source or calling a model."""
    if token_budget < 1:
        raise ValueError("token_budget must be positive")
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    manifest = hunt.get("manifest") or {}
    aliases = AliasBook(repo, hunt_id)
    finding_rows, lane_counts = _findings(repo, hunt_id, aliases)
    reportable = sorted(
        (row for row in repo.candidates(hunt_id) if row["lane"] in REPORTABLE_LANES),
        key=_candidate_key,
    )
    context_counts = Counter(row["rule_id"] for row in repo.candidates(hunt_id) if row["lane"] == "context")
    profiles = manifest.get("source_profiles") or {}
    source_targets = sorted(set(manifest.get("targets") or []) | set(profiles))
    base = {
        "schema": DOSSIER_SCHEMA,
        "header": {"finding_counts": {
            "urgent": lane_counts["urgent"], "high": lane_counts["high"], "lead": lane_counts["lead"],
            "total": sum(lane_counts[lane] for lane in REPORTABLE_LANES),
        }},
        "scope": {
            "window": {**_jsonable(manifest.get("window") or {}), "semantics": "[start, end) UTC"},
            "sources": [{"target": target, "profile": _jsonable(profiles.get(target) or {})}
                        for target in source_targets],
            "coverage": _coverage(repo, hunt_id, manifest),
        },
        "context_counts": [{"rule_id": rule_id, "count": count}
                           for rule_id, count in sorted(context_counts.items())],
        "entities": _entity_refs(repo, reportable, aliases),
        "incidents": _incidents(repo, hunt_id, reportable, aliases),
        "expansion": _expansion(repo, hunt_id, aliases),
        "agent_budget": _budget(repo, hunt_id, manifest),
    }
    base["safety"] = {"flags": injection_flags({
        "findings": finding_rows,
        "scope": base["scope"],
        "entities": base["entities"],
        "incidents": base["incidents"],
        "expansion": base["expansion"],
    })}
    cursor = "D" + digest({
        "hunt_id": hunt_id, "token_budget": token_budget, "context": base,
        "findings": finding_rows,
    })[:16]
    pages = _paginate(base, finding_rows, token_budget, cursor)
    repo.save_agent_dossier_page_plan(
        hunt_id, cursor, [[finding["alias"] for finding in page["findings"]] for page in pages],
    )
    return Dossier(payload=pages[0], pages=pages)
