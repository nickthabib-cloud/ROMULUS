"""Strict model-facing read tools over persisted hunt state.

The agent package never constructs source queries. Every argument is an alias,
registered rule identifier, lane, or page number, and all telemetry is returned
under the result's ``data`` member.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol

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
from romulus.store.repo import Repo

READ_PAGE_SIZE = 25
ENTITY_EVENT_LIMIT = 50
_RULE_IDS = frozenset(playbook.id for playbook in ALL_PLAYBOOKS)
_PARTIAL_STATES = frozenset({
    "planned", "executed_failed", "evaluated_partial", "match_on_partial", "positive_only_partial",
})
_ALIAS_PATTERN = r"^[FIENL][1-9][0-9]*$"
AliasArg = Annotated[str, Field(pattern=_ALIAS_PATTERN)]


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListFindingsArgs(_Args):
    lane: Literal["urgent", "high", "lead", "context"] | None = None
    rule: str | None = None
    entity: AliasArg | None = None
    page: int = Field(default=1, ge=1)

    @field_validator("rule")
    @classmethod
    def _registered_rule(cls, value: str | None) -> str | None:
        if value is not None and value not in _RULE_IDS:
            raise ValueError("rule must be an identifier from the loaded detector registry")
        return value


class GetFindingArgs(_Args):
    finding: AliasArg


class GetEvidenceArgs(_Args):
    evidence: list[AliasArg] = Field(min_length=1, max_length=20)


class GetIncidentArgs(_Args):
    incident: AliasArg


class EntityProfileArgs(_Args):
    entity: AliasArg


class _WindowedArgs(_Args):
    anchor: AliasArg
    start: datetime | None = None
    end: datetime | None = None

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
        hunt = self.repo.get_hunt(self.hunt_id) or {}
        manifest = hunt.get("manifest") or {}
        targets = sorted(str(target) for target in manifest.get("targets") or [])
        cells = [row for row in self.repo.rule_cells(self.hunt_id) if row["rule_id"] in rule_ids]
        gaps = [{
            "rule_id": row["rule_id"], "target": row["target"], "partition": row["partition"],
            "reason": f"rule cell state is {row['state']}",
        } for row in cells if row["state"] in _PARTIAL_STATES]
        assessed = {(row["rule_id"], row["target"]) for row in cells if row["target"] != "*"}
        for rule_id in sorted(rule_ids):
            for target in targets:
                if (rule_id, target) not in assessed:
                    gaps.append({
                        "rule_id": rule_id, "target": target, "partition": "*",
                        "reason": "no rule cell was recorded for this source",
                    })
        sweep = self.repo.latest_audit(self.hunt_id, "hunt.sweep_summary")
        detail = (sweep or {}).get("detail") or {}
        if not (detail.get("finished") or detail.get("complete")):
            for rule_id in sorted(rule_ids):
                gaps.append({
                    "rule_id": rule_id, "target": "*", "partition": "*",
                    "reason": "the deterministic sweep did not finish",
                })
        gaps.sort(key=lambda item: (item["rule_id"], item["target"], item["partition"], item["reason"]))
        return {"status": "partial" if gaps else "complete", "gaps": gaps}

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
            out.append({
                "alias": self.aliases.alias_for("N", entity["id"]), "kind": entity["kind"],
                "value": entity["value"], "role": str(item[2]) if len(item) > 2 else None,
            })
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
        candidates = sorted(self.repo.candidates(self.hunt_id), key=_candidate_key)
        if args.lane is not None:
            candidates = [row for row in candidates if row["lane"] == args.lane]
        if args.rule is not None:
            candidates = [row for row in candidates if row["rule_id"] == args.rule]
        if args.entity is not None:
            entity_id = self.aliases.resolve(args.entity, {"N"})
            entity = self.repo.entity(entity_id)
            if entity is None or entity["hunt_id"] != self.hunt_id:
                raise UnknownAlias(f"unknown entity alias {args.entity!r} in hunt {self.hunt_id}")
            candidates = [row for row in candidates if self._matches_entity(row, entity)]
        start = (args.page - 1) * READ_PAGE_SIZE
        page = candidates[start:start + READ_PAGE_SIZE]
        rule_ids = {args.rule} if args.rule is not None else {
            str(item["id"]) for item in ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
            .get("pack", {}).get("playbooks", []) if isinstance(item, dict) and item.get("id")
        }
        coverage = self._coverage(rule_ids)
        return _result(
            coverage["status"], coverage=coverage,
            counts={"returned": len(page), "total": len(candidates)},
            data={"findings": [self._finding_summary(row) for row in page], "page": args.page},
            more=start + len(page) < len(candidates),
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
        return _result(coverage["status"], coverage=coverage, counts={"returned": 1, "total": 1},
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
        graph, incidents = self._incident_graph()
        incident_id = self.aliases.resolve(args.incident, {"I"})
        incident = incidents.get(incident_id)
        if incident is None:
            raise UnknownAlias(f"unknown incident alias {args.incident!r} in hunt {self.hunt_id}")
        links_by_id = {link["id"]: link for link in graph["links"]}
        links = [{
            "alias": self.aliases.alias_for("L", link_id),
            "link_type": links_by_id[link_id]["link_type"], "strength": links_by_id[link_id]["style"],
            "status": links_by_id[link_id]["status"],
            "anchor": self.aliases.alias_for("F", links_by_id[link_id]["anchor_finding_id"]),
            "targets": [self.aliases.alias_for("F", target)
                        for target in links_by_id[link_id]["target_finding_ids"]],
        } for link_id in sorted(incident["link_ids"])]
        members = [self.aliases.alias_for("F", target) for target in incident["finding_ids"]]
        rules = {self.repo.candidate(target)["rule_id"] for target in incident["finding_ids"]}
        coverage = self._coverage(rules)
        data = {"alias": incident["alias"], "members": members, "links": links,
                "hosts": incident["hosts"], "accounts": incident["accounts"]}
        return _result(coverage["status"], coverage=coverage,
                       counts={"returned": len(members), "total": len(members)},
                       data={"incident": data})

    def _entity_profile(self, args: EntityProfileArgs) -> dict:
        entity_id = self.aliases.resolve(args.entity, {"N"})
        entity = self.repo.entity(entity_id)
        if entity is None or entity["hunt_id"] != self.hunt_id:
            raise UnknownAlias(f"unknown entity alias {args.entity!r} in hunt {self.hunt_id}")
        events = self.repo.events_for_entity(entity_id)
        exemplars = events[:ENTITY_EVENT_LIMIT]
        data = {
            "alias": args.entity, "kind": entity["kind"], "value": entity["value"],
            "first_seen": str(entity["first_seen"]) if entity["first_seen"] is not None else None,
            "last_seen": str(entity["last_seen"]) if entity["last_seen"] is not None else None,
            "families": dict(sorted(Counter(row["family"] for row in events).items())),
            "events": [{
                "alias": self.aliases.alias_for("E", row["id"]), "family": row["family"],
                "time": str(row["ts"]), "host": row["host"], "event": _jsonable(row["event"]),
            } for row in exemplars],
        }
        manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
        rules = {str(item["id"]) for item in (manifest.get("pack") or {}).get("playbooks", [])
                 if isinstance(item, dict) and item.get("id")}
        coverage = self._coverage(rules)
        return _result(coverage["status"], coverage=coverage,
                       counts={"returned": len(exemplars), "total": len(events)}, data={"entity": data},
                       more=len(events) > len(exemplars))

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

    def _run_pivot(self, anchor: dict, request) -> dict:
        if self.executor is None or self.session_id is None:
            return _result("unsupported", data={"error": {
                "code": "pivot_unavailable", "message": "the hunt layer did not provide a pivot executor",
            }})
        anchor_ts = self._utc(anchor["ts"])
        result = self.executor.run(self.session_id, anchor["id"], request, anchor_ts=anchor_ts)
        return self._pivot_result(result)

    def _pivot_result(self, result: PivotResult) -> dict:
        cells = [item.model_dump(mode="json") for item in result.coverage]
        gaps = [cell for cell in cells if cell["status"] != "complete"]
        if not cells and result.status != "complete" and result.reasons:
            gaps = [{"reason": reason} for reason in result.reasons]
        coverage = {"status": "complete" if result.status == "complete" else "partial",
                    "cells": cells, "gaps": gaps}
        evidence = []
        event_aliases = {}
        for event_id in result.event_ids:
            alias = self.aliases.alias_for("E", event_id)
            evidence.append(alias)
            event_aliases[event_id] = alias
        candidates = [self.aliases.alias_for("F", candidate_id) for candidate_id in result.candidate_ids]
        entities = []
        for item in result.entities:
            entity = self.repo.entity_for(self.hunt_id, item.kind, item.value)
            entities.append({
                "alias": self.aliases.alias_for("N", entity["id"]) if entity is not None else None,
                "kind": item.kind, "value": item.value, "role": item.role,
            })
        summaries = []
        for summary in result.event_summaries:
            item = _jsonable(summary)
            if item.get("id") in event_aliases:
                item["alias"] = event_aliases[item.pop("id")]
            summaries.append(item)
        data = {
            "result": {
                "evidence": evidence, "candidates": candidates, "entities": entities,
                "event_summaries": summaries, "task_count": len(result.task_ids),
                "reasons": list(result.reasons), "duration_ms": result.duration_ms,
            }
        }
        return _result(
            result.status, coverage=coverage,
            counts={"returned": len(evidence), "total": result.matched_event_count}, data=data,
            more=result.matched_event_count > len(evidence),
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
        return self._run_pivot(anchor, request)

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
        return self._run_pivot(anchor, request)

    def _process_tree(self, args: ProcessTreeToolArgs) -> dict:
        anchor = self._anchor(args.anchor)
        event_id = self.aliases.resolve(args.process, {"E"})
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
        return self._run_pivot(anchor, request)

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
        return self._run_pivot(anchor, request)

    def _follow_link(self, args: FollowLinkArgs) -> dict:
        anchor = self._anchor(args.anchor)
        if self.executor is None or self.session_id is None:
            return _result("unsupported", data={"error": {
                "code": "pivot_unavailable", "message": "the hunt layer did not provide a link fetcher",
            }})
        result = self.executor.follow_link(
            self.session_id, anchor["id"], args.link_type, args.window,
        )
        return self._pivot_result(result)
