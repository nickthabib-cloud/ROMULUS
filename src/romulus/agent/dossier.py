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
from romulus.hunt.expansion_plan import TIER_PLAN
from romulus.report.incidents import build_incident_graph
from romulus.report.manifest import coverage_for_hunt
from romulus.store.db import digest
from romulus.store.repo import Repo

DOSSIER_SCHEMA = "agent-dossier@1"
REPORTABLE_LANES = ("urgent", "high", "lead")
CLAIM_LIMIT = 180
DATA_TEXT_LIMIT = 180
DATA_COLLECTION_LIMIT = 50
INCIDENT_MEMBER_PREVIEW_LIMIT = 25
INCIDENT_LINK_PREVIEW_LIMIT = 8
INCIDENT_TARGET_PREVIEW_LIMIT = 10


def _bounded_text(value: Any, limit: int = DATA_TEXT_LIMIT) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…[{len(text) - limit} chars omitted]"


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _bounded_data(value: Any) -> Any:
    """Return persisted input data without an unbounded scalar/container."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: str(item[0]))
        bounded = {
            _bounded_text(key): _bounded_data(item)
            for key, item in items[:DATA_COLLECTION_LIMIT]
        }
        if len(items) > DATA_COLLECTION_LIMIT:
            bounded["_omitted"] = f"{len(items) - DATA_COLLECTION_LIMIT} entries omitted"
        return bounded
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        bounded = [_bounded_data(item) for item in items[:DATA_COLLECTION_LIMIT]]
        if len(items) > DATA_COLLECTION_LIMIT:
            bounded.append(f"…[{len(items) - DATA_COLLECTION_LIMIT} entries omitted]")
        return bounded
    if isinstance(value, str):
        return _bounded_text(value)
    return _jsonable(value)


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
            return _bounded_text(value)
    return None


def _claim(text: str, alias: str) -> str:
    if len(text) <= CLAIM_LIMIT:
        return text
    return f"{text[:CLAIM_LIMIT]}…[+{len(text) - CLAIM_LIMIT} chars: get_finding {alias}]"


def _findings(repo: Repo, hunt_id: str,
              aliases: AliasBook) -> tuple[list[dict], Counter, list[dict]]:
    counts = Counter(repo.lane_counts(hunt_id))
    out = []
    rows = sorted(repo.candidates(hunt_id, lanes=list(REPORTABLE_LANES)), key=_candidate_key)
    for row in rows:
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
    return out, counts, rows


def _coverage(repo: Repo, hunt_id: str) -> dict:
    canonical = coverage_for_hunt(repo, hunt_id)
    coverage = {
        key: [_bounded_data(item) for item in canonical[key]]
        for key in ("rules", "gaps", "not_assessed")
    }
    cells = repo.rule_cells(hunt_id)
    coverage["summary"] = {
        "recorded_cells": len(cells),
        "gap_count": len(coverage["gaps"]),
        "not_assessed_count": len(coverage["not_assessed"]),
    }
    return coverage


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
        member_ids = incident["finding_ids"]
        link_ids = sorted(incident["link_ids"])
        if len(member_ids) <= 1 and not link_ids:
            continue
        incident_alias = aliases.alias_for("I", incident["id"])
        members = [aliases.alias_for("F", target)
                   for target in member_ids[:INCIDENT_MEMBER_PREVIEW_LIMIT]]
        incident_links = []
        for link_id in link_ids[:INCIDENT_LINK_PREVIEW_LIMIT]:
            link = links[link_id]
            target_ids = link["target_finding_ids"]
            link_header = {
                "alias": aliases.alias_for("L", link_id),
                "link_type": _bounded_text(link["link_type"]),
                "strength": _bounded_text(link["style"]), "status": _bounded_text(link["status"]),
                "anchor": aliases.alias_for("F", link["anchor_finding_id"]),
                "targets": [aliases.alias_for("F", target)
                            for target in target_ids[:INCIDENT_TARGET_PREVIEW_LIMIT]],
                "target_count": len(target_ids),
            }
            if len(target_ids) > len(link_header["targets"]):
                link_header["targets_page"] = {
                    "omitted": len(target_ids) - len(link_header["targets"]),
                    "fetch": f"get_incident incident={incident_alias} page=1",
                }
            incident_links.append(link_header)
        # A singleton with no link adds no investigative hypothesis beyond the
        # findings index. Keep only correlated incidents so the bounded dossier
        # spends its prompt budget on actual relationships.
        header = {
            "alias": incident_alias, "members": members, "member_count": len(member_ids),
            "link_count": len(link_ids), "links": incident_links,
            "open_ends": {key: len(values) for key, values in sorted(
                incident.get("open_ends", {}).items()
            )},
        }
        if len(member_ids) > len(members):
            header["members_page"] = {
                "omitted": len(member_ids) - len(members),
                "fetch": f"get_incident incident={incident_alias} page=1",
            }
        if len(link_ids) > len(incident_links):
            header["links_page"] = {
                "omitted": len(link_ids) - len(incident_links),
                "fetch": f"get_incident incident={incident_alias} page=1",
            }
        out.append(header)
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
        reasons = _bounded_data(sorted(str(reason) for reason in row.get("reasons") or []))
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
                    "reasons": _bounded_data(sorted(str(reason) for reason in link.get("reasons") or [])),
                })
    return {"unfinished_anchors": unfinished, "link_tiers_not_reached": not_reached,
            "partial_links": partial_links}


def _entity_refs(repo: Repo, candidates: list[dict], aliases: AliasBook) -> list[dict]:
    wanted = {(str(item[0]), str(item[1])) for row in candidates for item in row.get("entities") or []
              if isinstance(item, (list, tuple)) and len(item) >= 2}
    return [{
        "alias": aliases.alias_for("N", row["id"]), "kind": _bounded_text(row["kind"]),
        "value": _bounded_text(row["value"]),
    } for row in repo.entities(aliases.hunt_id) if (row["kind"], row["value"]) in wanted]


def _page_payload(payload: dict, page: int, pages: int, cursor: str) -> dict:
    if page < pages:
        message = (f"index page {page} of {pages}; call list_findings(page={page + 1},"
                   f"cursor={cursor}) for the rest")
    else:
        message = f"index page {page} of {pages}; all findings in the index have been included"
    payload = {**payload, "header": {**payload["header"], "index": {
        "page": page, "pages": pages, "cursor": cursor, "message": message,
    }, "dossier": {
        "page": page, "pages": pages,
        "message": f"dossier page {page} of {pages}",
    }}}
    return _jsonable(payload)


def _append_detail(payload: dict, section: str, item: dict) -> None:
    if section in {"findings", "context_counts", "entities", "incidents"}:
        payload.setdefault(section, []).append(item)
    elif section == "sources":
        payload.setdefault("scope", {}).setdefault("sources", []).append(item)
    elif section == "coverage_gaps":
        payload.setdefault("scope", {}).setdefault("coverage", {}).setdefault("gaps", []).append(item)
    elif section == "coverage_rules":
        payload.setdefault("scope", {}).setdefault("coverage", {}).setdefault("rules", []).append(item)
    elif section == "coverage_not_assessed":
        payload.setdefault("scope", {}).setdefault("coverage", {}).setdefault(
            "not_assessed", [],
        ).append(item)
    elif section.startswith("expansion."):
        key = section.partition(".")[2]
        payload.setdefault("expansion", {}).setdefault(key, []).append(item)
    elif section == "safety_flags":
        payload.setdefault("safety", {}).setdefault("flags", []).append(item)
    else:  # pragma: no cover - internal programming guard
        raise ValueError(f"unknown dossier section {section}")


def _paginate(base: dict, details: list[tuple[str, dict]], token_budget: int,
              cursor: str) -> tuple[dict, ...]:
    continuation = {"schema": base["schema"], "header": base["header"], "findings": []}
    current = _jsonable(base)
    pages: list[dict] = []
    item_count = 0

    if estimate_tokens(_canonical(_page_payload(current, 999999, 999999, cursor))) > token_budget:
        current = {
            "schema": base["schema"], "header": base["header"], "findings": [],
            "omissions": [{
                "section": "fixed_summary", "reason": "fixed summary exceeded this page budget",
                "fetch": "use the paged toolbox reads for findings, coverage, incidents, and entities",
            }],
        }

    for section, item in details:
        trial = _jsonable(current)
        _append_detail(trial, section, item)
        if estimate_tokens(_canonical(_page_payload(trial, 999999, 999999, cursor))) <= token_budget:
            current = trial
            item_count += 1
            continue
        if item_count:
            pages.append(current)
            current = _jsonable(continuation)
            item_count = 0
        trial = _jsonable(current)
        _append_detail(trial, section, item)
        if estimate_tokens(_canonical(_page_payload(trial, 999999, 999999, cursor))) > token_budget:
            omission = {
                "omitted": True, "reason": f"one {section} item exceeded this page budget",
                "fetch": _detail_fetch(section, item),
            }
            trial = _jsonable(current)
            _append_detail(trial, section, omission)
            if estimate_tokens(_canonical(_page_payload(trial, 999999, 999999, cursor))) > token_budget:
                pages.append({
                    "schema": base["schema"], "header": base["header"], "findings": [],
                    "omissions": [{"section": section, **omission}],
                })
                current = _jsonable(continuation)
                item_count = 0
                continue
        current = trial
        item_count = 1
    pages.append(current)

    total = len(pages)
    output = tuple(_page_payload(payload, index, total, cursor)
                   for index, payload in enumerate(pages, 1))
    return output


def _detail_fetch(section: str, item: dict) -> str:
    alias = item.get("alias") or item.get("anchor")
    if section == "findings" and alias:
        return f"get_finding finding={alias}"
    if section == "incidents" and alias:
        return f"get_incident incident={alias} page=1"
    if section.startswith("coverage_"):
        return "list_coverage page=1"
    return "use the corresponding paged toolbox read with a narrower page"


def build_dossier(repo: Repo, hunt_id: str, *, token_budget: int) -> Dossier:
    """Build a canonical JSON dossier without querying a source or calling a model."""
    if token_budget < 1:
        raise ValueError("token_budget must be positive")
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    manifest = hunt.get("manifest") or {}
    aliases = AliasBook(repo, hunt_id)
    finding_rows, lane_counts, reportable = _findings(repo, hunt_id, aliases)
    context_counts = repo.candidate_rule_counts(hunt_id, lane="context")
    profiles = manifest.get("source_profiles") or {}
    source_targets = sorted(set(manifest.get("targets") or []) | set(profiles))
    coverage = _coverage(repo, hunt_id)
    sources = [{"target": _bounded_text(target), "profile": _bounded_data(profiles.get(target) or {})}
               for target in source_targets]
    context_rows = [{"rule_id": _bounded_text(rule_id), "count": count}
                    for rule_id, count in sorted(context_counts.items())]
    entities = _entity_refs(repo, reportable, aliases)
    incidents = _incidents(repo, hunt_id, reportable, aliases)
    expansion = _expansion(repo, hunt_id, aliases)
    base = {
        "schema": DOSSIER_SCHEMA,
        "header": {"finding_counts": {
            "urgent": lane_counts["urgent"], "high": lane_counts["high"], "lead": lane_counts["lead"],
            "total": sum(lane_counts[lane] for lane in REPORTABLE_LANES),
        }},
        "scope": {
            "window": {**_bounded_data(manifest.get("window") or {}), "semantics": "[start, end) UTC"},
            "sources": [],
            "coverage": {"summary": coverage["summary"], "rules": [], "gaps": [],
                         "not_assessed": []},
        },
        "context_counts": [],
        "entities": [],
        "incidents": [],
        "expansion": {key: [] for key in expansion},
        "agent_budget": _budget(repo, hunt_id, manifest),
        "safety": {"flags": []},
        "findings": [],
    }
    safety_flags = injection_flags({
        "findings": finding_rows,
        "scope": {"sources": sources, "coverage": coverage},
        "entities": entities,
        "incidents": incidents,
        "expansion": expansion,
    })
    details: list[tuple[str, dict]] = [("findings", item) for item in finding_rows]
    details.extend(("sources", item) for item in sources)
    details.extend(("context_counts", item) for item in context_rows)
    details.extend(("entities", item) for item in entities)
    details.extend(("incidents", item) for item in incidents)
    for key, values in expansion.items():
        details.extend((f"expansion.{key}", item) for item in values)
    details.extend(("coverage_rules", item) for item in coverage["rules"])
    details.extend(("coverage_gaps", item) for item in coverage["gaps"])
    details.extend(("coverage_not_assessed", item) for item in coverage["not_assessed"])
    details.extend(("safety_flags", item) for item in safety_flags)
    cursor = "D" + digest({
        "hunt_id": hunt_id, "token_budget": token_budget, "context": base,
        "details": details,
    })[:16]
    pages = _paginate(base, details, token_budget, cursor)
    repo.save_agent_dossier_page_plan(
        hunt_id, cursor, [[finding["alias"] for finding in page["findings"]] for page in pages],
    )
    return Dossier(payload=pages[0], pages=pages)
