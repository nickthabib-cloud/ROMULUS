"""Strict model-facing read tools over persisted hunt state.

The agent package never constructs source queries. Every argument is an alias,
registered rule identifier, lane, or page number, and all telemetry is returned
under the result's ``data`` member.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from romulus.agent import tools as pivot_tools
from romulus.agent.aliases import (
    AliasBook,
    AliasFromOtherHunt,
    AliasKindMismatch,
    UnknownAlias,
)
from romulus.agent.models import EntityRef, PivotResult
from romulus.agent.provider.base import Tool
from romulus.agent.safety import injection_flags
from romulus.decide.policy import LANE_ORDER
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import TypedEvent
from romulus.report.incidents import build_incident_graph
from romulus.report.manifest import coverage_for_hunt
from romulus.store.repo import Repo

READ_PAGE_SIZE = 25
ENTITY_EVENT_LIMIT = 50
COVERAGE_PAGE_SIZE = 25
COVERAGE_GAP_PREVIEW_LIMIT = 10
INCIDENT_PAGE_SIZE = 25
INCIDENT_TARGET_PREVIEW_LIMIT = 10
TOOL_TEXT_LIMIT = 180
_RULE_IDS = frozenset(playbook.id for playbook in ALL_PLAYBOOKS)
_ALIAS_PATTERN = r"^[FIENL][1-9][0-9]*$"
AliasArg = Annotated[str, Field(pattern=_ALIAS_PATTERN)]


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListFindingsArgs(_Args):
    lane: Literal["urgent", "high", "lead", "context"] | None = None
    rule: str | None = None
    entity: AliasArg | None = None
    page: int = Field(default=1, ge=1)
    cursor: str | None = Field(default=None, pattern=r"^D[0-9a-f]{16}$")

    @field_validator("rule")
    @classmethod
    def _registered_rule(cls, value: str | None) -> str | None:
        if value is not None and value not in _RULE_IDS:
            raise ValueError("rule must be an identifier from the loaded detector registry")
        return value


class GetFindingArgs(_Args):
    finding: AliasArg


class ListCoverageArgs(_Args):
    page: int = Field(default=1, ge=1)
    cursor: str | None = Field(default=None, pattern=r"^C[0-9a-f]{20}$")


class GetEvidenceArgs(_Args):
    evidence: list[AliasArg] = Field(min_length=1, max_length=20)


class GetIncidentArgs(_Args):
    incident: AliasArg
    page: int = Field(default=1, ge=1)
    cursor: str | None = Field(default=None, pattern=r"^G[0-9a-f]{20}$")


class EntityProfileArgs(_Args):
    entity: AliasArg
    page: int = Field(default=1, ge=1)
    cursor: str | None = Field(default=None, pattern=r"^R[0-9a-f]{20}$")


class _WindowedArgs(_Args):
    anchor: AliasArg
    start: datetime | None = None
    end: datetime | None = None
    page: int = Field(default=1, ge=1)
    cursor: str | None = Field(default=None, pattern=r"^P[0-9a-f]{20}$")

    @field_validator("start", "end")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("window bounds must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _ordered(self):
        if self.start is not None and self.end is not None and self.start >= self.end:
            raise ValueError("start must be before end")
        return self


class EntityTimelineToolArgs(_WindowedArgs):
    entity: AliasArg


class AuthActivityToolArgs(_WindowedArgs):
    entity: AliasArg


class ProcessTreeToolArgs(_WindowedArgs):
    process: AliasArg


class IdsAlertsToolArgs(_WindowedArgs):
    entity: AliasArg


class FollowLinkArgs(_Args):
    anchor: AliasArg
    link_type: Literal[
        "process_lineage", "login_session", "network_flow", "flow_host_side",
        "source_ip", "account", "host_after_anchor",
    ]
    window: Literal["anchor ±5 min", "anchor ±30 min", "anchor ±2 h"] | None = None
    page: int = Field(default=1, ge=1)
    cursor: str | None = Field(default=None, pattern=r"^P[0-9a-f]{20}$")


class InvestigationExecutor(Protocol):
    """Hunt-layer source boundary injected into the source-free agent package."""

    def run(self, session_id: str, anchor_id: str, request, *, anchor_ts: datetime) -> PivotResult: ...

    def follow_link(self, session_id: str, anchor_id: str, link_type: str,
                    window_label: str | None) -> PivotResult: ...


def _strict_schema(model: type[BaseModel]) -> dict:
    schema = model.model_json_schema()

    def visit(value):
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                value["additionalProperties"] = False
                value["required"] = list(properties)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)
    return schema


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    description: str
    arguments: type[BaseModel]
    handler: Callable[[BaseModel], dict]

    def provider_tool(self) -> Tool:
        return Tool(name=self.name, description=self.description, parameters=_strict_schema(self.arguments))


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _bounded_text(value: Any, limit: int = TOOL_TEXT_LIMIT) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…[{len(text) - limit} chars omitted]"


def _candidate_key(row: dict) -> tuple:
    return (LANE_ORDER.get(row["lane"], 99), -float(row["priority"]), row["ts"], row["id"])


def _result(status: str, *, coverage: dict | None = None, counts: dict | None = None,
            data: dict | None = None, more: bool = False) -> dict:
    if status not in {"complete", "partial", "unsupported", "failed", "refused"}:
        raise ValueError(f"invalid tool result status {status}")
    result_data = data or {}
    flags = injection_flags(result_data, "$.data")
    if flags:
        result_data = {**result_data, "safety_flags": flags}
    return {
        "status": status,
        "coverage": coverage or {"status": "complete", "gaps": []},
        "counts": counts or {"returned": 0, "total": 0},
        "data": result_data,
        "more": bool(more),
    }


class Toolbox:
    """Registry and exception boundary for all model-facing investigator tools."""

    def __init__(self, repo: Repo, hunt_id: str, *, executor: InvestigationExecutor | None = None,
                 session_id: str | None = None):
        self.repo = repo
        self.hunt_id = hunt_id
        self.executor = executor
        self.session_id = session_id
        self.aliases = AliasBook(repo, hunt_id)
        self.registry = {
            item.name: item for item in (
                RegisteredTool(
                    "list_findings", "List persisted findings using only typed filters and deterministic pages.",
                    ListFindingsArgs, self._list_findings,
                ),
                RegisteredTool(
                    "list_coverage", "Page the complete persisted coverage ledger and unresolved gaps.",
                    ListCoverageArgs, self._list_coverage,
                ),
                RegisteredTool(
                    "get_finding", "Read one finding and its persisted evidence aliases.",
                    GetFindingArgs, self._get_finding,
                ),
                RegisteredTool(
                    "get_evidence", "Read one to twenty retained evidence records by alias.",
                    GetEvidenceArgs, self._get_evidence,
                ),
                RegisteredTool(
                    "get_incident", "Read one deterministic incident and its observed or inferred links.",
                    GetIncidentArgs, self._get_incident,
                ),
                RegisteredTool(
                    "entity_profile", "Summarize retained events for one dossier entity alias.",
                    EntityProfileArgs, self._entity_profile,
                ),
                RegisteredTool(
                    "entity_timeline", "Retrieve a cited host or IP timeline inside the hunt window.",
                    EntityTimelineToolArgs, self._entity_timeline,
                ),
                RegisteredTool(
                    "auth_activity", "Retrieve authentication activity for a cited host or account.",
                    AuthActivityToolArgs, self._auth_activity,
                ),
                RegisteredTool(
                    "process_tree", "Retrieve process records using a cited evidence event's typed process ID.",
                    ProcessTreeToolArgs, self._process_tree,
                ),
                RegisteredTool(
                    "ids_alerts", "Retrieve IDS alerts for a cited IP entity.",
                    IdsAlertsToolArgs, self._ids_alerts,
                ),
                RegisteredTool(
                    "follow_link", "Follow one deterministic expansion link from a cited finding.",
                    FollowLinkArgs, self._follow_link,
                ),
            )
        }

    def provider_tools(self) -> list[Tool]:
        return [self.registry[name].provider_tool() for name in sorted(self.registry)]

    def execute(self, name: str, arguments: dict | None) -> dict:
        tool = self.registry.get(name)
        if tool is None:
            return _result("unsupported", data={"error": {
                "code": "unknown_tool", "message": "the requested tool is not registered",
            }})
        try:
            parsed = tool.arguments.model_validate(arguments if isinstance(arguments, dict) else {})
            return tool.handler(parsed)
        except ValidationError as exc:
            return _result("refused", data={"error": {
                "code": "invalid_arguments", "message": "tool arguments failed strict validation",
                "details": exc.errors(include_url=False, include_input=False),
            }})
        except AliasKindMismatch as exc:
            return _result("refused", data={"error": {"code": "alias_kind", "message": str(exc)}})
        except UnknownAlias as exc:
            return _result("refused", data={"error": {"code": "unknown_alias", "message": str(exc)}})
        except AliasFromOtherHunt as exc:
            return _result("refused", data={"error": {"code": "other_hunt_alias", "message": str(exc)}})
        except Exception as exc:  # noqa: BLE001 -- tool boundary must turn every handler failure into data
            return _result("failed", data={"error": {
                "code": "handler_failed", "message": str(exc), "type": type(exc).__name__,
            }})

    def _coverage(self, rule_ids: set[str]) -> dict:
        canonical = coverage_for_hunt(self.repo, self.hunt_id)
        rules = [row for row in canonical["rules"] if row["rule_id"] in rule_ids]
        gaps = []
        for gap in canonical["gaps"]:
            selected = {rule: state for rule, state in gap["rules"].items() if rule in rule_ids}
            if selected:
                gaps.append({**gap, "rules": selected,
                             "every_requested_rule_there": set(selected) == set(rule_ids)})
        not_assessed = canonical["not_assessed"]
        unresolved = any(
            row["negative_claim"].startswith("unresolved:")
            or "coverage incomplete:" in row["negative_claim"]
            for row in rules
        )
        return {
            "status": "partial" if gaps or not_assessed or unresolved else "complete",
            "rules": rules, "gaps": gaps, "not_assessed": not_assessed,
        }

    @staticmethod
    def _coverage_view(coverage: dict, relevant_rules: set[str]) -> dict:
        relevant = []
        for gap in coverage["gaps"]:
            selected = {rule: state for rule, state in gap["rules"].items()
                        if rule in relevant_rules}
            if not selected:
                continue
            reasons = [_bounded_text(reason) for reason in gap.get("reasons", [])[:3]]
            item = {
                "target": _bounded_text(gap["target"]),
                "partition": _bounded_text(gap["partition"]),
                "rules": selected, "reasons": reasons,
                "every_rule_there": bool(gap.get("every_rule_there")),
                "every_requested_rule_there": bool(gap.get("every_requested_rule_there")),
            }
            if len(gap.get("reasons", [])) > len(reasons):
                item["reasons_omitted"] = len(gap["reasons"]) - len(reasons)
            relevant.append(item)
        shown = relevant[:COVERAGE_GAP_PREVIEW_LIMIT]
        counts = {
            "rules": len(coverage["rules"]), "gaps": len(coverage["gaps"]),
            "not_assessed": len(coverage["not_assessed"]),
        }
        more = len(relevant) > len(shown) or bool(coverage["not_assessed"])
        return {
            "status": coverage["status"], "counts": counts, "gaps": shown, "more": more,
            "fetch": "list_coverage page=1" if more else None,
        }

    @staticmethod
    def _coverage_entries(coverage: dict) -> Iterator[dict]:

        def text_parts(kind: str, base: dict, field: str, value: Any) -> None:
            text = str(value)
            chunks = [text[index:index + TOOL_TEXT_LIMIT]
                      for index in range(0, len(text), TOOL_TEXT_LIMIT)] or [""]
            for number, chunk in enumerate(chunks, 1):
                yield {
                    "kind": kind, **base, "field": field, "text": chunk,
                    "part": number, "parts": len(chunks),
                }

        for row in coverage["rules"]:
            base = {"rule_id": _bounded_text(row["rule_id"])}
            yield {
                "kind": "rule", **base, "states": _jsonable(row["states"]),
                "records_evaluated": row["records_evaluated"],
            }
            yield from text_parts("rule_text", base, "negative_claim", row["negative_claim"])
        for gap_number, gap in enumerate(coverage["gaps"], 1):
            base = {
                "gap": gap_number, "target": _bounded_text(gap["target"]),
                "partition": _bounded_text(gap["partition"]),
            }
            yield {
                "kind": "gap", **base, "every_rule_there": bool(gap.get("every_rule_there")),
                "every_requested_rule_there": bool(gap.get("every_requested_rule_there")),
            }
            yield from ({
                "kind": "gap_rule", **base, "rule_id": _bounded_text(rule),
                "state": _bounded_text(state),
            } for rule, state in sorted(gap["rules"].items()))
            for reason_number, reason in enumerate(gap.get("reasons", []), 1):
                yield from text_parts("gap_text", {**base, "reason": reason_number}, "reason", reason)
        for item_number, row in enumerate(coverage["not_assessed"], 1):
            base = {"item": item_number, "records": row.get("records")}
            for field in ("target", "dataset", "count_scope", "reason"):
                yield from text_parts("not_assessed_text", base, field, row.get(field, ""))

    def _list_coverage(self, args: ListCoverageArgs) -> dict:
        identity = {"kind": "coverage"}
        cursor = args.cursor
        if cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the coverage cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different tool request",
                )
            stored = plan["summary"]
        else:
            if args.page != 1:
                return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
            manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
            rules = {str(item["id"]) for item in (manifest.get("pack") or {}).get("playbooks", [])
                     if isinstance(item, dict) and item.get("id")}
            coverage = self._coverage(rules)
            counts = {
                "rules": len(coverage["rules"]), "gaps": len(coverage["gaps"]),
                "not_assessed": len(coverage["not_assessed"]),
            }
            stored = {"status": coverage["status"], "coverage_counts": counts}
            cursor = "C" + uuid4().hex[:20]
            plan = self.repo.create_agent_page_plan(
                self.hunt_id, cursor, identity, stored, self._coverage_entries(coverage),
            )
        total = int(plan["item_count"])
        entries = self.repo.agent_page_items(
            self.hunt_id, cursor, offset=(args.page - 1) * COVERAGE_PAGE_SIZE,
            limit=COVERAGE_PAGE_SIZE,
        )
        coverage = {
            "status": stored["status"], "counts": stored["coverage_counts"], "gaps": [],
        }
        return _result(
            stored["status"], coverage=coverage, counts={"returned": len(entries), "total": total},
            data={"entries": entries, "page": args.page, "cursor": cursor},
            more=args.page * COVERAGE_PAGE_SIZE < total,
        )

    @staticmethod
    def _matches_entity(candidate: dict, entity: dict) -> bool:
        return any(isinstance(item, (list, tuple)) and len(item) >= 2
                   and item[0] == entity["kind"] and item[1] == entity["value"]
                   for item in candidate.get("entities") or [])

    def _candidate_entities(self, candidate: dict) -> list[dict]:
        out = []
        for item in candidate.get("entities") or []:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            entity = self.repo.entity_for(self.hunt_id, str(item[0]), str(item[1]))
            if entity is None:
                continue
            alias = self.aliases.alias_for("N", entity["id"])
            value = str(entity["value"])
            summary = {
                "alias": alias, "kind": _bounded_text(entity["kind"]),
                "value": _bounded_text(value),
                "role": _bounded_text(item[2]) if len(item) > 2 else None,
            }
            if len(value) > TOOL_TEXT_LIMIT:
                summary["value_omitted_chars"] = len(value) - TOOL_TEXT_LIMIT
                summary["fetch"] = f"entity_profile entity={alias} page=1 returns the same safe preview"
            out.append(summary)
        return out

    def _finding_summary(self, candidate: dict) -> dict:
        alias = self.aliases.alias_for("F", candidate["id"])
        claim = candidate["claim"]
        if len(claim) > 180:
            claim = f"{claim[:180]}…[+{len(claim) - 180} chars: get_finding {alias}]"
        return {
            "alias": alias, "lane": candidate["lane"], "rule_id": candidate["rule_id"],
            "claim": claim, "time": str(candidate["ts"]),
            "entities": self._candidate_entities(candidate),
        }

    def _list_findings(self, args: ListFindingsArgs) -> dict:
        identity = {"kind": "findings", "lane": args.lane, "rule": args.rule, "entity": args.entity}
        stored = self.repo.agent_page_plan(self.hunt_id, args.cursor) if args.cursor else None
        if args.cursor is not None and stored is None:
            return self._semantic_refusal("unknown_cursor", "the findings cursor is not valid for this hunt")
        if stored is not None:
            if stored["identity"].get("kind") == "dossier":
                rows = self.repo.agent_page_items(
                    self.hunt_id, args.cursor, offset=args.page - 1, limit=1,
                )
                finding_items = (rows[0]["page"].get("findings", []) if rows else [])
                page = []
                for item in finding_items:
                    target = self.aliases.resolve(item["alias"], {"F"})
                    candidate = self.repo.candidate(target)
                    if candidate is not None:
                        page.append(candidate)
                total = int(stored["summary"]["finding_count"])
                more = args.page < int(stored["item_count"])
                cursor = args.cursor
                identity = {"kind": "findings", "lane": None, "rule": None, "entity": None}
            else:
                requested = identity
                if args.lane is None and args.rule is None and args.entity is None:
                    requested = stored["identity"]
                if stored["identity"] != requested:
                    return self._semantic_refusal(
                        "cursor_request_mismatch", "the cursor belongs to a different findings request",
                    )
                identity = stored["identity"]
                rows = self.repo.agent_page_items(
                    self.hunt_id, args.cursor, offset=(args.page - 1) * READ_PAGE_SIZE,
                    limit=READ_PAGE_SIZE,
                )
                page = [candidate for item in rows
                        if (candidate := self.repo.candidate(item["candidate_id"])) is not None]
                total = int(stored["item_count"])
                more = args.page * READ_PAGE_SIZE < total
                cursor = args.cursor
        else:
            if args.page != 1:
                return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
            entity_key = None
            if args.entity is not None:
                entity_id = self.aliases.resolve(args.entity, {"N"})
                entity = self.repo.entity(entity_id)
                if entity is None or entity["hunt_id"] != self.hunt_id:
                    raise UnknownAlias(f"unknown entity alias {args.entity!r} in hunt {self.hunt_id}")
                entity_key = (str(entity["kind"]), str(entity["value"]))
            cursor = "D" + uuid4().hex[:16]
            stored = self.repo.create_candidate_page_plan(
                self.hunt_id, cursor, identity, {}, lane=args.lane, rule_id=args.rule,
                entity=entity_key,
            )
            rows = self.repo.agent_page_items(
                self.hunt_id, cursor, offset=0, limit=READ_PAGE_SIZE,
            )
            page = [candidate for item in rows
                    if (candidate := self.repo.candidate(item["candidate_id"])) is not None]
            total = int(stored["item_count"])
            more = READ_PAGE_SIZE < total
        selected_rule = identity.get("rule")
        rule_ids = {selected_rule} if selected_rule is not None else {
            str(item["id"]) for item in ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
            .get("pack", {}).get("playbooks", []) if isinstance(item, dict) and item.get("id")
        }
        coverage = self._coverage(rule_ids)
        relevant_rules = {str(row["rule_id"]) for row in page}
        if not relevant_rules and selected_rule is not None:
            relevant_rules.add(selected_rule)
        coverage_view = self._coverage_view(coverage, relevant_rules)
        return _result(
            coverage["status"], coverage=coverage_view,
            counts={"returned": len(page), "total": total},
            data={"findings": [self._finding_summary(row) for row in page],
                  "page": args.page, "cursor": cursor},
            more=more,
        )

    def _get_finding(self, args: GetFindingArgs) -> dict:
        finding_id = self.aliases.resolve(args.finding, {"F"})
        candidate = self.repo.candidate(finding_id)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            raise UnknownAlias(f"unknown finding alias {args.finding!r} in hunt {self.hunt_id}")
        evidence = [self.aliases.alias_for("E", event_id) for event_id in candidate["event_ids"]]
        coverage = self._coverage({candidate["rule_id"]})
        finding = {
            **self._finding_summary(candidate),
            "claim": candidate["claim"], "claim_type": candidate["claim_type"],
            "severity": candidate["severity"], "confidence": candidate["confidence"],
            "priority": candidate["priority"], "evidence": evidence,
            "predicate_fields": _jsonable(candidate.get("predicate_fields") or []),
            "benign_alternatives": _jsonable(candidate.get("benign_alternatives") or []),
            "next_checks": _jsonable(candidate.get("next_checks") or []),
        }
        return _result(coverage["status"], coverage=self._coverage_view(
            coverage, {candidate["rule_id"]},
        ), counts={"returned": 1, "total": 1},
                       data={"finding": finding})

    def _get_evidence(self, args: GetEvidenceArgs) -> dict:
        resolved = [(alias, self.aliases.resolve(alias, {"E"})) for alias in args.evidence]
        rows = {row["id"]: row for row in self.repo.events_by_ids([target for _alias, target in resolved])}
        data = []
        missing = []
        for alias, event_id in resolved:
            row = rows.get(event_id)
            if row is None:
                missing.append(alias)
                continue
            raw_records = self.repo.raw_records(row.get("raw_ids") or [])
            data.append({
                "alias": alias, "family": row["family"], "time": str(row["ts"]), "host": row["host"],
                "event": _jsonable(row["event"]),
                "raw_records": [{
                    "target": raw["target"], "native_id": raw["native_id"],
                    "digest": raw["digest"], "source": _jsonable(raw["source"]),
                } for raw in raw_records],
            })
        coverage = {"status": "partial" if missing else "complete", "gaps": [
            {"evidence": alias, "reason": "the aliased typed event is no longer retained"} for alias in missing
        ]}
        return _result(coverage["status"], coverage=coverage,
                       counts={"returned": len(data), "total": len(resolved)},
                       data={"evidence": data}, more=False)

    def _incident_graph(self) -> tuple[dict, dict[str, dict]]:
        candidates = sorted(
            (row for row in self.repo.candidates(self.hunt_id) if row["lane"] in {"urgent", "high", "lead"}),
            key=_candidate_key,
        )
        findings = [{
            "id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
            "observed_at": str(row["ts"]), "entities": row.get("entities") or [],
            "event_ids": row.get("event_ids") or [], "citations": [],
            "source_link_id": row.get("source_link_id"),
        } for row in candidates]
        graph = build_incident_graph(self.repo, self.hunt_id, findings)
        by_target = {}
        for incident in graph["incidents"]:
            alias = self.aliases.alias_for("I", incident["id"])
            by_target[incident["id"]] = {**incident, "alias": alias}
        return graph, by_target

    def _get_incident(self, args: GetIncidentArgs) -> dict:
        initial_graph = self._incident_graph() if args.cursor is None else None
        incident_id = self.aliases.resolve(args.incident, {"I"})
        identity = {"kind": "incident", "incident_id": incident_id}
        cursor = args.cursor
        if cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the incident cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different incident",
                )
            stored = plan["summary"]
        else:
            if args.page != 1:
                return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
            graph, incidents = initial_graph
            incident = incidents.get(incident_id)
            if incident is None:
                raise UnknownAlias(f"unknown incident alias {args.incident!r} in hunt {self.hunt_id}")
            links_by_id = {link["id"]: link for link in graph["links"]}
            items = []
            for link_id in sorted(incident["link_ids"]):
                link = links_by_id[link_id]
                targets = list(link["target_finding_ids"])
                chunks = [targets[index:index + INCIDENT_TARGET_PREVIEW_LIMIT]
                          for index in range(0, len(targets), INCIDENT_TARGET_PREVIEW_LIMIT)] or [[]]
                for chunk_number, chunk in enumerate(chunks, 1):
                    items.append({"kind": "link", "value": {
                        "alias": self.aliases.alias_for("L", link_id),
                        "link_type": _bounded_text(link["link_type"]),
                        "strength": _bounded_text(link["style"]),
                        "status": _bounded_text(link["status"]),
                        "anchor": self.aliases.alias_for("F", link["anchor_finding_id"]),
                        "targets": [self.aliases.alias_for("F", target) for target in chunk],
                        "target_count": len(targets), "target_part": chunk_number,
                        "target_parts": len(chunks),
                        "targets_omitted": max(
                            0, len(targets) - chunk_number * INCIDENT_TARGET_PREVIEW_LIMIT,
                        ),
                        "fetch": (f"get_incident incident={args.incident} with this cursor until "
                                  "all target_parts are returned") if len(chunks) > 1 else None,
                    }})
            members = [self.aliases.alias_for("F", target) for target in incident["finding_ids"]]
            rules = {candidate["rule_id"] for target in incident["finding_ids"]
                     if (candidate := self.repo.candidate(target)) is not None}
            coverage = self._coverage(rules)
            items.extend({"kind": "member", "value": alias} for alias in members)
            items.extend({"kind": "host", "value": _bounded_text(value)}
                         for value in incident["hosts"])
            items.extend({"kind": "account", "value": _bounded_text(value)}
                         for value in incident["accounts"])
            kind_counts = {kind: sum(item["kind"] == kind for item in items)
                           for kind in ("link", "member", "host", "account")}
            stored = {
                "member_count": len(members), "link_count": len(incident["link_ids"]),
                "host_count": len(incident["hosts"]), "account_count": len(incident["accounts"]),
                "kind_counts": kind_counts,
                "coverage": self._coverage_view(coverage, rules), "status": coverage["status"],
            }
            cursor = "G" + uuid4().hex[:20]
            self.repo.create_agent_page_plan(self.hunt_id, cursor, identity, stored, items)
        start = (args.page - 1) * INCIDENT_PAGE_SIZE
        page = {kind: [item["value"] for item in self.repo.agent_page_items_by_kind(
            self.hunt_id, cursor, kind, offset=start, limit=INCIDENT_PAGE_SIZE,
        )] for kind in ("member", "link", "host", "account")}
        page_count = max(1, *(
            (int(count) + INCIDENT_PAGE_SIZE - 1) // INCIDENT_PAGE_SIZE
            for count in stored["kind_counts"].values()
        ))
        data = {
            "alias": args.incident, "members": page["member"], "member_count": stored["member_count"],
            "links": page["link"], "link_count": stored["link_count"],
            "hosts": page["host"], "host_count": stored["host_count"],
            "hosts_omitted": max(0, stored["host_count"] - start - len(page["host"])),
            "accounts": page["account"], "account_count": stored["account_count"],
            "accounts_omitted": max(0, stored["account_count"] - start - len(page["account"])),
            "page": args.page,
        }
        if data["hosts_omitted"]:
            data["hosts_fetch"] = f"get_incident incident={args.incident} page={args.page + 1} cursor={cursor}"
        if data["accounts_omitted"]:
            data["accounts_fetch"] = f"get_incident incident={args.incident} page={args.page + 1} cursor={cursor}"
        return _result(
            stored["status"], coverage=stored["coverage"],
            counts={"returned": len(page["link"]), "total": stored["kind_counts"]["link"]},
            data={"cursor": cursor, "incident": data}, more=args.page < page_count,
        )

    def _entity_profile(self, args: EntityProfileArgs) -> dict:
        entity_id = self.aliases.resolve(args.entity, {"N"})
        entity = self.repo.entity(entity_id)
        if entity is None or entity["hunt_id"] != self.hunt_id:
            raise UnknownAlias(f"unknown entity alias {args.entity!r} in hunt {self.hunt_id}")
        identity = {"kind": "entity_profile", "entity_id": entity_id}
        if args.cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, args.cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the entity cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different entity",
                )
            cursor = args.cursor
            total = int(plan["item_count"])
            families = plan["summary"]["families"]
        else:
            if args.page != 1:
                return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
            cursor = "R" + uuid4().hex[:20]
            plan = self.repo.create_entity_event_page_plan(
                self.hunt_id, cursor, identity, entity_id,
            )
            total = int(plan["item_count"])
            families = plan["summary"]["families"]
        start = (args.page - 1) * ENTITY_EVENT_LIMIT
        page_ids = [item["event_id"] for item in self.repo.agent_page_items(
            self.hunt_id, cursor, offset=start, limit=ENTITY_EVENT_LIMIT,
        )]
        by_id = {row["id"]: row for row in self.repo.events_by_ids(page_ids)}
        exemplars = [by_id[event_id] for event_id in page_ids if event_id in by_id]
        data = {
            "alias": args.entity, "kind": _bounded_text(entity["kind"]),
            "value": _bounded_text(entity["value"]),
            "first_seen": str(entity["first_seen"]) if entity["first_seen"] is not None else None,
            "last_seen": str(entity["last_seen"]) if entity["last_seen"] is not None else None,
            "page": args.page,
            "families": families, "cursor": cursor,
            "events": [{
                "alias": self.aliases.alias_for("E", row["id"]), "family": row["family"],
                "time": str(row["ts"]), "host": row["host"], "event": _jsonable(row["event"]),
            } for row in exemplars],
        }
        manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
        rules = {str(item["id"]) for item in (manifest.get("pack") or {}).get("playbooks", [])
                 if isinstance(item, dict) and item.get("id")}
        coverage = self._coverage(rules)
        return _result(coverage["status"], coverage=self._coverage_view(coverage, set()),
                       counts={"returned": len(exemplars), "total": total}, data={"entity": data},
                       more=start + len(exemplars) < total)

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def _window(self, args: _WindowedArgs) -> tuple[datetime, datetime] | None:
        manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
        stored = manifest.get("window") or {}
        hunt_start = self._utc(datetime.fromisoformat(str(stored["start"])))
        hunt_end = self._utc(datetime.fromisoformat(str(stored["end"])))
        requested_start = self._utc(args.start) if args.start is not None else hunt_start
        requested_end = self._utc(args.end) if args.end is not None else hunt_end
        if requested_end <= hunt_start or requested_start >= hunt_end:
            return None
        return max(requested_start, hunt_start), min(requested_end, hunt_end)

    def _anchor(self, alias: str) -> dict:
        finding_id = self.aliases.resolve(alias, {"F"})
        candidate = self.repo.candidate(finding_id)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            raise UnknownAlias(f"unknown finding alias {alias!r} in hunt {self.hunt_id}")
        return candidate

    def _entity_ref(self, alias: str) -> EntityRef:
        entity_id = self.aliases.resolve(alias, {"N"})
        entity = self.repo.entity(entity_id)
        if entity is None or entity["hunt_id"] != self.hunt_id:
            raise UnknownAlias(f"unknown entity alias {alias!r} in hunt {self.hunt_id}")
        roles = {"host": "host", "account": "actor", "ip": "src", "domain": "subject"}
        return EntityRef(kind=entity["kind"], value=entity["value"], role=roles.get(entity["kind"], ""))

    @staticmethod
    def _semantic_refusal(code: str, message: str) -> dict:
        return _result("refused", data={"error": {"code": code, "message": message}})

    def _run_pivot(self, anchor: dict, request, *, page: int, cursor: str | None) -> dict:
        identity = _jsonable({
            "kind": "pivot", "session_id": self.session_id, "anchor": anchor["id"],
            "request": request.model_dump(mode="json"),
        })
        if cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the tool cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different tool request",
                )
            return self._pivot_plan_result(plan, page=page, cursor=cursor)
        if page != 1:
            return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
        if self.executor is None or self.session_id is None:
            return _result("unsupported", data={"error": {
                "code": "pivot_unavailable", "message": "the hunt layer did not provide a pivot executor",
            }})
        anchor_ts = self._utc(anchor["ts"])
        result = self.executor.run(self.session_id, anchor["id"], request, anchor_ts=anchor_ts)
        return self._pivot_result(result, page=1, identity=identity)

    @staticmethod
    def _persisted_event_summary(row: dict) -> dict:
        event = TypedEvent.model_validate(row["event"])
        return {
            "id": event.id, "family": event.family, "ts": event.ts.isoformat(), "host": event.host,
            "outcome": str(event.outcome),
            "fields": {name: field.value for name, field in sorted(event.fields.items())[:16]},
            "caveats": event.caveats[:5],
        }

    def _pivot_result(self, result: PivotResult, *, page: int, identity: dict,
                      cursor: str | None = None, persist: bool = True) -> dict:
        event_ids = list(dict.fromkeys(result.reach_event_ids or result.event_ids))
        if cursor is None:
            cursor = "P" + uuid4().hex[:20]
        if persist:
            counts = {
                "event": len(event_ids), "candidate": len(result.candidate_ids),
                "entity": len(result.entities), "coverage": len(result.coverage),
                "reason": len(result.reasons),
            }
            summary = {
                "status": result.status, "task_count": len(result.task_ids),
                "duration_ms": result.duration_ms,
                "matched_event_count": result.matched_event_count, "kind_counts": counts,
            }

            def items() -> Iterator[dict]:
                yield from ({"kind": "event", "value": event_id} for event_id in event_ids)
                yield from ({"kind": "candidate", "value": candidate_id}
                            for candidate_id in result.candidate_ids)
                yield from ({"kind": "entity", "value": item.model_dump(mode="json")}
                            for item in result.entities)
                yield from ({"kind": "coverage", "value": item.model_dump(mode="json")}
                            for item in result.coverage)
                yield from ({"kind": "reason", "value": _bounded_text(reason)}
                            for reason in result.reasons)

            plan = self.repo.create_agent_page_plan(
                self.hunt_id, cursor, identity, summary, items(),
            )
        else:
            plan = self.repo.agent_page_plan(self.hunt_id, cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the tool cursor is not valid for this hunt")
        return self._pivot_plan_result(plan, page=page, cursor=cursor)

    def _pivot_plan_result(self, plan: dict, *, page: int, cursor: str) -> dict:
        summary = plan["summary"]
        start = (page - 1) * ENTITY_EVENT_LIMIT
        values = {kind: [item["value"] for item in self.repo.agent_page_items_by_kind(
            self.hunt_id, cursor, kind, offset=start, limit=ENTITY_EVENT_LIMIT,
        )] for kind in ("event", "candidate", "entity", "coverage", "reason")}
        page_ids = values["event"]
        cells = values["coverage"]
        control_cells = []
        for cell in cells:
            control_cells.append({
                key: ([{range_key: range_value for range_key, range_value in item.items()
                        if range_key != "reason"} for item in value]
                      if key in {"covered_ranges", "unresolved_ranges"} else value)
                for key, value in cell.items() if key != "reasons"
            })
        gaps = [cell for cell in control_cells if cell["status"] != "complete"]
        if not cells and summary["status"] != "complete" and summary["kind_counts"]["reason"]:
            gaps = [{"status": "unresolved"}]
        coverage = {
            "status": "complete" if summary["status"] == "complete" else "partial",
            "cells": control_cells, "gaps": gaps,
            "counts": {"returned": len(cells), "total": summary["kind_counts"]["coverage"]},
        }
        evidence = []
        event_aliases = {}
        for event_id in page_ids:
            alias = self.aliases.alias_for("E", event_id)
            evidence.append(alias)
            event_aliases[event_id] = alias
        candidates = [self.aliases.alias_for("F", candidate_id) for candidate_id in values["candidate"]]
        entities = []
        for item in values["entity"]:
            entity = self.repo.entity_for(self.hunt_id, item["kind"], item["value"])
            entities.append({
                "alias": self.aliases.alias_for("N", entity["id"]) if entity is not None else None,
                "kind": _bounded_text(item["kind"]), "value": _bounded_text(item["value"]),
                "role": _bounded_text(item["role"]),
            })
        persisted = {row["id"]: self._persisted_event_summary(row)
                     for row in self.repo.events_by_ids(page_ids)}
        summaries = []
        for event_id in page_ids:
            event_summary = persisted.get(event_id)
            if event_summary is None:
                continue
            item = _jsonable(event_summary)
            if item.get("id") in event_aliases:
                item["alias"] = event_aliases[item.pop("id")]
            summaries.append(item)
        data = {
            "result": {
                "evidence": evidence, "candidates": candidates, "entities": entities,
                "event_summaries": summaries, "task_count": summary["task_count"],
                "coverage": cells, "reasons": values["reason"],
                "duration_ms": summary["duration_ms"],
                "page": page, "cursor": cursor,
            }
        }
        total = max(summary["matched_event_count"], summary["kind_counts"]["event"])
        pages = max(1, *(
            (int(count) + ENTITY_EVENT_LIMIT - 1) // ENTITY_EVENT_LIMIT
            for count in summary["kind_counts"].values()
        ))
        return _result(
            summary["status"], coverage=coverage,
            counts={"returned": len(evidence), "total": total}, data=data,
            more=page < pages,
        )

    def _entity_timeline(self, args: EntityTimelineToolArgs) -> dict:
        anchor = self._anchor(args.anchor)
        entity = self._entity_ref(args.entity)
        if entity.kind not in {"host", "ip"}:
            return self._semantic_refusal("entity_kind", "entity_timeline requires a host or IP alias")
        window = self._window(args)
        if window is None:
            return self._semantic_refusal("outside_hunt_window", "the requested window is outside hunt scope")
        request = pivot_tools.EntityTimelineRequest(tool="entity_timeline", arguments=pivot_tools.EntityTimelineArgs(
            entity=entity, start=window[0], end=window[1],
        ))
        return self._run_pivot(anchor, request, page=args.page, cursor=args.cursor)

    def _auth_activity(self, args: AuthActivityToolArgs) -> dict:
        anchor = self._anchor(args.anchor)
        entity = self._entity_ref(args.entity)
        if entity.kind not in {"host", "account"}:
            return self._semantic_refusal("entity_kind", "auth_activity requires a host or account alias")
        window = self._window(args)
        if window is None:
            return self._semantic_refusal("outside_hunt_window", "the requested window is outside hunt scope")
        request = pivot_tools.AuthActivityRequest(tool="auth_activity", arguments=pivot_tools.AuthActivityArgs(
            entity=entity, start=window[0], end=window[1],
        ))
        return self._run_pivot(anchor, request, page=args.page, cursor=args.cursor)

    def _process_tree(self, args: ProcessTreeToolArgs) -> dict:
        anchor = self._anchor(args.anchor)
        event_id = self.aliases.resolve(args.process, {"E"})
        if event_id not in set(anchor.get("event_ids") or []):
            return self._semantic_refusal(
                "evidence_not_in_anchor", "process_tree evidence must be cited by the anchor finding",
            )
        rows = self.repo.events_by_ids([event_id])
        if not rows:
            raise UnknownAlias(f"unknown evidence alias {args.process!r} in hunt {self.hunt_id}")
        event = TypedEvent.model_validate(rows[0]["event"])
        pid = event.get("process.pid")
        if event.family != "process_exec" or not isinstance(pid, int) or not event.host:
            return self._semantic_refusal(
                "missing_typed_field", "process_tree needs cited process evidence with host and process.pid",
            )
        window = self._window(args)
        if window is None:
            return self._semantic_refusal("outside_hunt_window", "the requested window is outside hunt scope")
        request = pivot_tools.ProcessTreeRequest(tool="process_tree", arguments=pivot_tools.ProcessTreeArgs(
            host=event.host, process_id=pid, start=window[0], end=window[1],
        ))
        return self._run_pivot(anchor, request, page=args.page, cursor=args.cursor)

    def _ids_alerts(self, args: IdsAlertsToolArgs) -> dict:
        anchor = self._anchor(args.anchor)
        entity = self._entity_ref(args.entity)
        if entity.kind != "ip":
            return self._semantic_refusal("entity_kind", "ids_alerts requires an IP alias")
        window = self._window(args)
        if window is None:
            return self._semantic_refusal("outside_hunt_window", "the requested window is outside hunt scope")
        request = pivot_tools.IdsAlertsRequest(tool="ids_alerts", arguments=pivot_tools.IdsAlertsArgs(
            entity=entity, start=window[0], end=window[1],
        ))
        return self._run_pivot(anchor, request, page=args.page, cursor=args.cursor)

    def _follow_link(self, args: FollowLinkArgs) -> dict:
        anchor = self._anchor(args.anchor)
        identity = _jsonable({
            "kind": "follow_link", "session_id": self.session_id, "anchor": anchor["id"],
            "link_type": args.link_type, "window": args.window,
        })
        if args.cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, args.cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the tool cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different tool request",
                )
            return self._pivot_plan_result(plan, page=args.page, cursor=args.cursor)
        if args.page != 1:
            return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
        if self.executor is None or self.session_id is None:
            return _result("unsupported", data={"error": {
                "code": "pivot_unavailable", "message": "the hunt layer did not provide a link fetcher",
            }})
        result = self.executor.follow_link(
            self.session_id, anchor["id"], args.link_type, args.window,
        )
        return self._pivot_result(result, page=1, identity=identity)
