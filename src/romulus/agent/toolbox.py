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
from typing import Annotated, Any, Literal, Protocol, get_args
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from romulus.agent import tools as pivot_tools
from romulus.agent.aliases import (
    AliasBook,
    AliasFromOtherHunt,
    AliasKindMismatch,
    UnknownAlias,
)
from romulus.agent.dossier import (
    MATERIALIZE_COVERAGE_LIMIT,
    MATERIALIZE_ENTITY_LIMIT,
    MATERIALIZE_FINDING_LIMIT,
    MATERIALIZE_LINK_BYTES_LIMIT,
    MATERIALIZE_LINK_LIMIT,
    REPORTABLE_LANES,
    rank_label,
)
from romulus.agent.models import EntityRef, PivotResult
from romulus.agent.provider.base import Tool
from romulus.agent.refusals import reason as refusal_reason
from romulus.agent.refusals import validation_reasons
from romulus.agent.safety import injection_flags
from romulus.decide.policy import LANE_ORDER
from romulus.detect.metadata import is_sigma_id, pinned_rule_ids
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import TypedEvent
from romulus.report.incidents import build_incident_graph
from romulus.report.manifest import EVALUATED_SKIPS, coverage_for_rules
from romulus.store.db import digest
from romulus.store.repo import FINAL_RANK_PASS, Repo

READ_PAGE_SIZE = 25
ENTITY_EVENT_LIMIT = 50
COVERAGE_PAGE_SIZE = 25
COVERAGE_GAP_PREVIEW_LIMIT = 10
INCIDENT_PAGE_SIZE = 25
INCIDENT_TARGET_PREVIEW_LIMIT = 10
TOOL_TEXT_LIMIT = 180
# Fifty entity exemplars must each receive a non-empty chunk inside the shared
# response budget. Metadata is outside this telemetry-text allowance.
TELEMETRY_CHUNK_BYTES = 384
TELEMETRY_RESPONSE_BYTES = 24_000
RAW_RECORDS_PER_EVIDENCE_PAGE = 2
# how many derived cursors a search that keeps failing is retried under before it is no longer deduplicated
SEARCH_RETRY_KEYS = 4
# how many gaps and caveats a search result names; the rest are counted
SEARCH_REASONS_SHOWN = 10
_RULE_IDS = frozenset(playbook.id for playbook in ALL_PLAYBOOKS)
_ALIAS_PATTERN = r"^[FIENL][1-9][0-9]*$"
AliasArg = Annotated[str, Field(pattern=_ALIAS_PATTERN)]


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


_PAGE = "1 for the first page; a later page also needs the cursor the first page returned."
_CURSOR = "The cursor the first page of this same request returned; omit (or null) for page 1."
_CHUNK = "Which chunk of long telemetry text to return, from 1; a result names the next chunk when there is one."


class ListFindingsArgs(_Args):
    lane: Literal["urgent", "high", "lead", "context"] | None = Field(
        default=None, description="Only findings in this lane; omit (or null) for every lane.")
    rule: str | None = Field(default=None, description=(
        "Only findings of this rule: an identifier from the hunt's detector registry or a Sigma rule pinned in "
        "this hunt, as findings show it in rule_id; omit (or null) for every rule."))
    entity: AliasArg | None = Field(default=None, description="Only findings naming this entity alias (N...).")
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^D[0-9a-f]{16}$", description=(
        _CURSOR + " A dossier page cursor also pages the dossier's findings."))

    @field_validator("rule")
    @classmethod
    def _registered_rule(cls, value: str | None) -> str | None:
        if value is not None and value not in _RULE_IDS and not is_sigma_id(value):
            raise ValueError("rule must be an identifier from the loaded detector registry")
        return value


class GetFindingArgs(_Args):
    finding: AliasArg = Field(description="A finding alias (F...) issued in this hunt.")


class ListCoverageArgs(_Args):
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^C[0-9a-f]{20}$", description=_CURSOR)


class GetEvidenceArgs(_Args):
    evidence: list[AliasArg] = Field(min_length=1, max_length=20,
                                     description="One to twenty evidence aliases (E...) issued in this hunt.")
    chunk_index: int = Field(default=1, ge=1, description=_CHUNK)
    raw_page: int = Field(default=1, ge=1, description=(
        "Which page of each record's raw source records to return, from 1 (two per page)."))


class GetIncidentArgs(_Args):
    incident: AliasArg = Field(description=(
        "An incident alias (I...) issued in this hunt: from list_incidents, the dossier's incidents, or a hypothesis "
        "that names one. Not a list position or index number."))
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^G[0-9a-f]{20}$", description=_CURSOR)


class ListIncidentsArgs(_Args):
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^J[0-9a-f]{20}$", description=_CURSOR)


class EntityProfileArgs(_Args):
    entity: AliasArg = Field(description="An entity alias (N...) issued in this hunt.")
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^R[0-9a-f]{20}$", description=_CURSOR)
    chunk_index: int = Field(default=1, ge=1, description=_CHUNK)


class _WindowedArgs(_Args):
    anchor: AliasArg = Field(description="The finding alias (F...) this lead starts from.")
    start: datetime | None = Field(default=None, description=(
        "Window start, an RFC 3339 date-time with a UTC offset; omit (or null) for the hunt's start. The window "
        "is clipped to the hunt's, and start must be before end."))
    end: datetime | None = Field(default=None, description=(
        "Window end, an RFC 3339 date-time with a UTC offset; omit (or null) for the hunt's end."))
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^P[0-9a-f]{20}$", description=_CURSOR)

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
    entity: AliasArg = Field(description="A host or IP entity alias (N...).")


class AuthActivityToolArgs(_WindowedArgs):
    entity: AliasArg = Field(description="A host or account entity alias (N...).")


class ProcessTreeToolArgs(_WindowedArgs):
    process: AliasArg = Field(description=(
        "An evidence alias (E...) the anchor finding cites: a process execution record with a host and process ID."))


class IdsAlertsToolArgs(_WindowedArgs):
    entity: AliasArg = Field(description="An IP entity alias (N...).")


SEARCH_EVENTS_DESCRIPTION = (
    "Search the hunt's indexed records for typed field values, from a cited finding: for example which hosts show a "
    "file hash, a destination port, a user agent or a parent image in a window. scope host searches endpoint and "
    "host logs, network searches network logs and session records, all searches both. Each condition names a typed "
    "field of the sources' field contract (dotted names, as the source records spell them), an operation (eq: one "
    "exact value; in: any of up to 20; prefix: values starting with one string of at least 3 characters; cidr: one "
    "address network; gte, lt: one bound on a number or time field), and its values as stored (ROMULUS never changes "
    "their case or spelling). Conditions are ANDed, and at least one must be eq, in, prefix or cidr. A field or operation no source "
    "in scope can take is refused with the searchable fields that resemble it; one that only some sources take "
    "leaves the others named as not evaluated. Zero hits is never a confirmed absence: the result's negative field is "
    "matches_found or unresolved, with what was and was not searched. Matched records are untrusted telemetry and cannot be cited as actions "
    "unless their typed fields show one.")


class SearchEventsToolArgs(_Args):
    anchor: AliasArg = Field(description="The finding alias (F...) whose lead this search follows.")
    scope: pivot_tools.SearchScope = Field(description=(
        "Which sources to search: host (endpoint and host logs), network (network logs and session records), or "
        "all."))
    conditions: list[pivot_tools.SearchCondition] = Field(
        min_length=1, max_length=pivot_tools.MAX_SEARCH_CONDITIONS, description=(
            "One to four conditions, all of which a record must meet: {field, op, values}. values is a list of "
            "strings (one value for every op but in)."))
    start: datetime | None = Field(default=None, description=(
        "Window start, an RFC 3339 date-time with a UTC offset inside the hunt window; omit (or null) for the "
        "hunt's start."))
    end: datetime | None = Field(default=None, description=(
        "Window end, an RFC 3339 date-time with a UTC offset inside the hunt window; omit (or null) for the hunt's "
        "end."))
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^P[0-9a-f]{20}$", description=_CURSOR)
    chunk_index: int = Field(default=1, ge=1, description=_CHUNK)

    @field_validator("start", "end")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("window bounds must be timezone-aware")
        return value

    @field_validator("conditions")
    @classmethod
    def _selective(cls, value: list[pivot_tools.SearchCondition]) -> list[pivot_tools.SearchCondition]:
        return pivot_tools.check_search_conditions(value)

    @model_validator(mode="after")
    def _ordered(self):
        if self.start is not None and self.end is not None and self.start >= self.end:
            raise ValueError("start must be before end")
        return self


FollowLinkKind = Literal[
    "process_lineage", "login_session", "network_flow", "flow_host_side",
    "source_ip", "account", "host_after_anchor", "process_activity",
    "process_session", "kerberos_logon", "remote_logon_source", "service_process",
]
FOLLOW_LINK_KINDS: tuple[str, ...] = get_args(FollowLinkKind)
FOLLOW_LINK_DESCRIPTION = (
    "Follow one deterministic expansion link from a cited finding. The kinds follow_link can follow are "
    + ", ".join(FOLLOW_LINK_KINDS) + ". A kind can be followed only from an anchor whose cited records carry its "
    "typed key (a process ID, logon session, flow, source address or account): get_finding lists the kinds a "
    "finding supports in follow_link_kinds, and any other kind is refused. Link types shown on links already "
    "recorded (zeek_uid, zeek_file, certificate, address_host, agent_*, cited_evidence) describe those links; they "
    "are not kinds to follow.")


class FollowLinkArgs(_Args):
    anchor: AliasArg = Field(description="The finding alias (F...) whose expansion link to follow.")
    link_type: FollowLinkKind = Field(description=(
        "The kind of deterministic link to follow from the anchor: one get_finding lists in follow_link_kinds."))
    window: Literal["anchor ±5 min", "anchor ±30 min", "anchor ±2 h"] | None = Field(
        default=None, description="The time window around the anchor; omit (or null) for anchor ±5 min.")
    page: int = Field(default=1, ge=1, description=_PAGE)
    cursor: str | None = Field(default=None, pattern=r"^P[0-9a-f]{20}$", description=_CURSOR)


class InvestigationExecutor(Protocol):
    """Hunt-layer source boundary injected into the source-free agent package."""

    def run(self, session_id: str, anchor_id: str, request, *, anchor_ts: datetime) -> PivotResult: ...

    def follow_link(self, session_id: str, anchor_id: str, link_type: str,
                    window_label: str | None) -> PivotResult: ...

    # optional: the follow_link kinds an anchor finding's cited records carry the typed key for, decided without
    # any source query. An executor without it lets every kind through to follow_link, which reports the outcome.
    def followable_links(self, anchor_id: str) -> tuple[str, ...]: ...

    # optional: why a search_events request cannot run on the hunt's sources (no target of its scope takes every
    # condition), decided without any source query; None when it can run. Without it the search runs and its
    # result reports what was not evaluated.
    def search_refusal(self, request) -> dict | None: ...


# the JSON-schema keywords an argument model's schema keeps: every one its validator enforces, and descriptions
SCHEMA_KEYS = frozenset({"type", "properties", "required", "additionalProperties", "items", "enum", "const", "anyOf",
                         "allOf", "$ref", "description", "format", "pattern", "default", "minLength", "maxLength",
                         "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minItems", "maxItems",
                         "$defs"})


def argument_schema(model: type[BaseModel]) -> dict:
    """The JSON schema of exactly the arguments `model` accepts: its required and optional properties, their
    defaults, bounds, patterns and enums, and its field descriptions (titles dropped). Every object is closed.
    Rules a schema cannot state (an alias of the right kind, a registered rule, an ordered window) are in the
    descriptions, and the model's own validation still decides every call."""
    schema = model.model_json_schema(by_alias=True)

    def defaults(node: dict, cls: type[BaseModel]) -> None:
        # a default_factory leaves no default in pydantic's schema; state it, so the model knows what omission means
        # (top-level fields: no argument model nests an optional model)
        for name, field in cls.model_fields.items():
            prop = (node.get("properties") or {}).get(field.alias or name)
            if prop is not None and not field.is_required() and "default" not in prop:
                prop["default"] = field.get_default(call_default_factory=True)

    def visit(value):
        if isinstance(value, dict):
            for key in [k for k in value if k not in SCHEMA_KEYS]:
                value.pop(key)
            if isinstance(value.get("properties"), dict):
                value["additionalProperties"] = False
                value.setdefault("required", [])
                for child in value["properties"].values():
                    visit(child)
            for key, child in value.items():
                if key not in ("properties", "$defs", "default", "enum", "const"):
                    visit(child)
            for child in (value.get("$defs") or {}).values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    defaults(schema, model)
    visit(schema)
    return schema


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    description: str
    arguments: type[BaseModel]
    handler: Callable[[BaseModel], dict]
    # whether the arguments' shape should be enforced by the model server where it can: worth its cost for the
    # tools that write (hypotheses, proposals, the session's end); read tools are validated here alone
    strict: bool = False

    def provider_tool(self) -> Tool:
        return Tool(name=self.name, description=self.description, parameters=argument_schema(self.arguments),
                    strict=self.strict)


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _bounded_text(value: Any, limit: int = TOOL_TEXT_LIMIT) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…[{len(text) - limit} chars omitted]"


class _TelemetryBudget:
    """Bound untrusted telemetry while keeping every omitted chunk explicitly retrievable."""

    def __init__(self, chunk_index: int):
        self.chunk_index = chunk_index
        self.remaining = TELEMETRY_RESPONSE_BYTES

    def project(self, value: Any, route: str) -> Any:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        encoded = serialized.encode("utf-8")
        if len(encoded) <= TELEMETRY_CHUNK_BYTES and len(encoded) <= self.remaining:
            self.remaining -= len(encoded)
            return _jsonable(value)
        chunks = max(1, (len(encoded) + TELEMETRY_CHUNK_BYTES - 1) // TELEMETRY_CHUNK_BYTES)
        start = (self.chunk_index - 1) * TELEMETRY_CHUNK_BYTES
        take = min(TELEMETRY_CHUNK_BYTES, self.remaining)
        text = (encoded[start:start + take].decode("utf-8", errors="replace")
                if start < len(encoded) and take else "")
        self.remaining = max(0, self.remaining - len(text.encode("utf-8")))
        next_index = self.chunk_index + 1 if self.chunk_index < chunks else None
        return {
            "encoding": "json", "text": text, "chunk_index": self.chunk_index,
            "chunk_count": chunks, "omitted": self.chunk_index < chunks,
            "fetch": f"{route} chunk_index={next_index}" if next_index is not None else None,
        }


def _candidate_key(row: dict) -> tuple:
    return (LANE_ORDER.get(row["lane"], 99), -float(row["priority"]), row["ts"] is None, row["ts"], row["id"])


def _result(status: str, *, coverage: dict | None = None, counts: dict | None = None,
            data: dict | None = None, more: bool = False) -> dict:
    if status not in {"complete", "partial", "unsupported", "failed", "refused"}:
        raise ValueError(f"invalid tool result status {status}")
    result_data = data or {}
    flags = injection_flags(result_data, "$.data")
    if flags:
        result_data = {**result_data, "safety_flags": flags}
    result = {
        "status": status,
        "coverage": coverage or {"status": "complete", "gaps": []},
        "counts": counts or {"returned": 0, "total": 0},
        "data": result_data,
        "more": bool(more),
    }
    if status == "refused":
        error = result_data.get("error") if isinstance(result_data, dict) else None
        result["errors"] = [str(error.get("message", "tool action refused"))] if isinstance(error, dict) else ["tool action refused"]
    return result


class Toolbox:
    """Registry and exception boundary for all model-facing investigator tools."""

    def __init__(self, repo: Repo, hunt_id: str, *, executor: InvestigationExecutor | None = None,
                 session_id: str | None = None, owner_token: str | None = None):
        self.repo = repo
        self.hunt_id = hunt_id
        self.executor = executor
        self.session_id = session_id
        self.owner_token = owner_token
        self.aliases = AliasBook(repo, hunt_id, owner_token=owner_token)
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
                    "list_incidents", "Page deterministic incident headers and aliases for follow-up.",
                    ListIncidentsArgs, self._list_incidents,
                ),
                RegisteredTool(
                    "get_incident", ("Read one deterministic incident and its observed or inferred links, by its "
                                     "incident alias (I...); list_incidents need not be called first."),
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
                    "follow_link", FOLLOW_LINK_DESCRIPTION,
                    FollowLinkArgs, self._follow_link,
                ),
                # Not strict: it is a read tool, validated here like the other pivots, and the product refuses each
                # condition a source cannot take. Strict tools share a small grammar budget that the seven write
                # tools fill, and this tool's nested condition objects would only widen the compiled grammar.
                RegisteredTool(
                    "search_events", SEARCH_EVENTS_DESCRIPTION,
                    SearchEventsToolArgs, self._search_events,
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
                "reasons": validation_reasons(exc.errors(include_url=False, include_input=False,
                                                         include_context=False)),
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
        canonical = coverage_for_rules(self.repo, self.hunt_id, rule_ids)
        rules = canonical["rules"]
        gaps = []
        for gap in canonical["gaps"]:
            selected = {rule: state for rule, state in gap["rules"].items() if rule in rule_ids}
            if selected:
                gaps.append({**gap, "rules": selected,
                             "every_requested_rule_there": set(selected) == set(rule_ids)})
        not_assessed = canonical["not_assessed"]
        unresolved = any(
            row["search_result"].startswith("searched in part:")
            or "coverage incomplete:" in row["search_result"]
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
            yield from text_parts("rule_text", base, "search_result", row["search_result"])
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
            rules = pinned_rule_ids(manifest)
            coverage = self._coverage(rules)
            counts = {
                "rules": len(coverage["rules"]), "gaps": len(coverage["gaps"]),
                "not_assessed": len(coverage["not_assessed"]),
            }
            stored = {"status": coverage["status"], "coverage_counts": counts}
            cursor = "C" + digest({
                "identity": identity,
                "rule_cells": self.repo.rule_cell_fingerprint(self.hunt_id),
                "manifest": manifest,
                "sweep": self.repo.latest_audit(self.hunt_id, "hunt.sweep_summary"),
            })[:20]
            plan = self.repo.create_agent_page_plan(
                self.hunt_id, cursor, identity, stored, self._coverage_entries(coverage),
             owner_token=self.owner_token)
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
            "claim": claim, "time": str(candidate["ts"]) if candidate["ts"] is not None else None,
            "entities": self._candidate_entities(candidate), **rank_label(candidate),
        }

    def _list_findings(self, args: ListFindingsArgs) -> dict:
        if args.rule is not None and is_sigma_id(args.rule):
            manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get('manifest') or {})
            pinned = {'sigma.' + pin['id'] for pin in (manifest.get('sigma_rules') or {}).get('applied', [])}
            if args.rule not in pinned:
                return self._semantic_refusal('invalid_arguments', 'rule must be pinned in this hunt')
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
                if self.repo.has_rank_pass(self.hunt_id, FINAL_RANK_PASS):
                    ranks = self.repo.finding_ranks_for(self.hunt_id, FINAL_RANK_PASS, [row["id"] for row in page])
                    page = [{**row, "_rank_section": (ranks[row["id"]]["section"] if row["id"] in ranks else None)}
                            for row in page]
                total = int(stored["summary"]["finding_count"])
                more = args.page < int(stored["item_count"])
                cursor = args.cursor
                identity = {"kind": "findings", "lane": None, "rule": None, "entity": None}
            elif stored["identity"].get("kind") == "dossier_large":
                page_size = int(stored["summary"]["dossier_page_size"])
                page = self.repo.candidate_page_plan_rows(
                    self.hunt_id, args.cursor, offset=(args.page - 1) * page_size,
                    limit=page_size,
                )
                total = int(stored["item_count"])
                more = args.page * page_size < total
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
                page = self.repo.candidate_page_plan_rows(
                    self.hunt_id, args.cursor, offset=(args.page - 1) * READ_PAGE_SIZE,
                    limit=READ_PAGE_SIZE,
                )
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
            cursor = "D" + digest({
                "identity": identity, "snapshot": self.repo.candidate_fingerprint(self.hunt_id),
                "rank_state": self.repo.rank_state(self.hunt_id),
            })[:16]
            stored = self.repo.create_candidate_page_plan(
                self.hunt_id, cursor, identity, {}, lane=args.lane, rule_id=args.rule,
                entity=entity_key,
             owner_token=self.owner_token)
            page = self.repo.candidate_page_plan_rows(
                self.hunt_id, cursor, offset=0, limit=READ_PAGE_SIZE,
            )
            total = int(stored["item_count"])
            more = READ_PAGE_SIZE < total
        selected_rule = identity.get("rule")
        relevant_rules = {str(row["rule_id"]) for row in page}
        if not relevant_rules and selected_rule is not None:
            relevant_rules.add(selected_rule)
        coverage = self._coverage(relevant_rules)
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
        followable = self.followable_kinds(candidate["id"])
        if followable is not None:
            finding["follow_link_kinds"] = list(followable)
        return _result(coverage["status"], coverage=self._coverage_view(
            coverage, {candidate["rule_id"]},
        ), counts={"returned": 1, "total": 1},
                       data={"finding": finding})

    def _get_evidence(self, args: GetEvidenceArgs) -> dict:
        resolved = [(alias, self.aliases.resolve(alias, {"E"})) for alias in args.evidence]
        rows = {row["id"]: row for row in self.repo.citation_events(
            self.hunt_id, [target for _alias, target in resolved],
        )}
        data = []
        missing = []
        budget = _TelemetryBudget(args.chunk_index)
        for alias, event_id in resolved:
            row = rows.get(event_id)
            if row is None:
                missing.append(alias)
                continue
            raw_ids = row.get("raw_ids") or []
            raw_start = (args.raw_page - 1) * RAW_RECORDS_PER_EVIDENCE_PAGE
            selected_raw_ids = raw_ids[raw_start:raw_start + RAW_RECORDS_PER_EVIDENCE_PAGE]
            raw_by_id = {raw["id"]: raw for raw in self.repo.raw_records(selected_raw_ids)}
            raw_records = [raw_by_id[raw_id] for raw_id in selected_raw_ids if raw_id in raw_by_id]
            raw_more = raw_start + len(raw_records) < len(raw_ids)
            data.append({
                "alias": alias, "family": row["family"], "time": str(row["ts"]), "host": row["host"],
                "event": budget.project(row["event"], f"get_evidence evidence={alias}"),
                "raw_records": [{
                    "target": raw["target"], "native_id": raw["native_id"],
                    "digest": raw["digest"], "source": budget.project(
                        raw["source"],
                        f"get_evidence evidence={alias} raw_page={args.raw_page}",
                    ),
                } for raw in raw_records],
                "raw_records_count": len(raw_ids), "raw_records_page": args.raw_page,
                "raw_records_more": raw_more,
                "raw_records_fetch": (
                    f"get_evidence evidence={alias} raw_page={args.raw_page + 1}"
                    if raw_more else None
                ),
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
            "observed_at": str(row["ts"]) if row["ts"] is not None else None, "entities": row.get("entities") or [],
            "event_ids": row.get("event_ids") or [], "citations": [],
            "source_link_id": row.get("source_link_id"),
        } for row in candidates]
        graph = build_incident_graph(self.repo, self.hunt_id, findings)
        by_target = {}
        for incident in graph["incidents"]:
            alias = self.aliases.alias_for("I", incident["id"])
            by_target[incident["id"]] = {**incident, "alias": alias}
        return graph, by_target

    def _list_incidents(self, args: ListIncidentsArgs) -> dict:
        identity = {"kind": "incident_index"}
        if args.cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, args.cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the incident cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different incident request",
                )
            cursor = args.cursor
        else:
            if args.page != 1:
                return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
            plan, capped = self._incident_index()
            if capped is not None:
                return capped
            cursor = plan["cursor"]
        total = int(plan["item_count"])
        rows = self.repo.agent_page_items(
            self.hunt_id, cursor, offset=(args.page - 1) * INCIDENT_PAGE_SIZE,
            limit=INCIDENT_PAGE_SIZE,
        )
        headers = [row["header"] for row in rows]
        return _result(
            plan["summary"]["status"], counts={"returned": len(headers), "total": total},
            data={"incidents": headers, "page": args.page, "cursor": cursor},
            more=args.page * INCIDENT_PAGE_SIZE < total,
        )

    def _incident_index(self) -> tuple[dict | None, dict | None]:
        """The hunt's incident index as a stored page plan (the same snapshot for the same graph), or, past the
        bounded materialization cap, None and the partial result that says incident correlation is unassessed."""
        identity = {"kind": "incident_index"}
        counts = {
            "reportable_findings": self.repo.candidate_count_lanes(self.hunt_id, REPORTABLE_LANES),
            "expansion_links": self.repo.expansion_link_count(self.hunt_id),
            "coverage_cells": self.repo.rule_cell_count(self.hunt_id),
            "entities": self.repo.entity_count(self.hunt_id),
            "expansion_link_payload_bytes": self.repo.expansion_link_payload_bytes(self.hunt_id),
        }
        over_cap = (
            counts["reportable_findings"] > MATERIALIZE_FINDING_LIMIT
            or counts["expansion_links"] > MATERIALIZE_LINK_LIMIT
            or counts["coverage_cells"] > MATERIALIZE_COVERAGE_LIMIT
            or counts["entities"] > MATERIALIZE_ENTITY_LIMIT
            or counts["expansion_link_payload_bytes"] > MATERIALIZE_LINK_BYTES_LIMIT
        )
        if over_cap:
            return None, _result(
                "partial", coverage={"status": "partial", "gaps": [{
                    "reason": "incident correlation exceeded the bounded materialization cap",
                }]}, counts={"returned": 0, "total": None}, data={"incidents": [],
                    "assessment": {
                        "status": "unassessed_at_materialization_cap", "counts": counts,
                        "omission": "incident membership and links were not materialized",
                        "fetch": ("use list_findings page=1 for the complete finding index; "
                                  "incident correlation remains explicitly unassessed"),
                    }}, more=False,
            )
        graph, incidents = self._incident_graph()
        links_by_id = {link["id"]: link for link in graph["links"]}
        items = []
        for incident in incidents.values():
            header = {
                "alias": incident["alias"],
                "member_count": len(incident["finding_ids"]),
                "link_count": len(incident["link_ids"]),
                "host_count": len(incident["hosts"]),
                "account_count": len(incident["accounts"]),
                "open_end_count": sum(
                    len(values) for values in incident.get("open_ends", {}).values()
                ),
                "fetch": f"get_incident incident={incident['alias']} page=1",
            }
            items.append({
                "header": header, "incident": incident,
                "links": [links_by_id[link_id] for link_id in incident["link_ids"]],
            })
        items.sort(key=lambda item: item["header"]["alias"])
        cursor = "J" + digest({
            "identity": identity, "items": items,
        })[:20]
        plan = self.repo.create_agent_page_plan(
            self.hunt_id, cursor, identity, {"status": "complete"}, items, owner_token=self.owner_token)
        return plan, None

    def _get_incident(self, args: GetIncidentArgs) -> dict:
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
            indexed = self.repo.agent_incident_index_item(self.hunt_id, args.incident)
            if indexed is None or indexed["incident"]["id"] != incident_id:
                # an incident alias from the dossier or a hypothesis: index the hunt's incidents now, as
                # list_incidents would, and read it from that snapshot
                _plan, capped = self._incident_index()
                if capped is not None:
                    return capped
                indexed = self.repo.agent_incident_index_item(self.hunt_id, args.incident)
            if indexed is None or indexed["incident"]["id"] != incident_id:
                return _result("refused", data={"error": {
                    "code": "incident_not_in_index",
                    "message": "this alias names no incident in the hunt's current incident index; call "
                               "list_incidents page=1 for the current incidents",
                    "reasons": [refusal_reason("incident", "not_in_incident_index")],
                }})
            incident = indexed["incident"]
            links_by_id = {link["id"]: link for link in indexed["links"]}
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
            rules = {candidate["rule_id"] for candidate in self.repo.candidates_by_ids(
                incident["finding_ids"],
            )}
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
            cursor = "G" + digest({
                "identity": identity, "summary": stored, "items": items,
            })[:20]
            self.repo.create_agent_page_plan(self.hunt_id, cursor, identity, stored, items, owner_token=self.owner_token)
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
            cursor = "R" + digest({
                "identity": identity, "snapshot": self.repo.entity_event_fingerprint(entity_id),
            })[:20]
            plan = self.repo.create_entity_event_page_plan(
                self.hunt_id, cursor, identity, entity_id,
             owner_token=self.owner_token)
            total = int(plan["item_count"])
            families = plan["summary"]["families"]
        start = (args.page - 1) * ENTITY_EVENT_LIMIT
        page_ids = self.repo.entity_event_page_plan_ids(
            self.hunt_id, cursor, offset=start, limit=ENTITY_EVENT_LIMIT,
        )
        by_id = {row["id"]: row for row in self.repo.citation_events(self.hunt_id, page_ids)}
        exemplars = [by_id[event_id] for event_id in page_ids if event_id in by_id]
        budget = _TelemetryBudget(args.chunk_index)
        data = {
            "alias": args.entity, "kind": _bounded_text(entity["kind"]),
            "value": _bounded_text(entity["value"]),
            "first_seen": str(entity["first_seen"]) if entity["first_seen"] is not None else None,
            "last_seen": str(entity["last_seen"]) if entity["last_seen"] is not None else None,
            "page": args.page,
            "families": families, "cursor": cursor,
            "events": [{
                "alias": self.aliases.alias_for("E", row["id"]), "family": row["family"],
                "time": str(row["ts"]), "host": row["host"], "event": budget.project(
                    row["event"],
                    f"entity_profile entity={args.entity} page={args.page} cursor={cursor}",
                ),
            } for row in exemplars],
        }
        manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
        rules = pinned_rule_ids(manifest)
        targets = {str(target) for target in manifest.get("targets") or []}
        counts = self.repo.rule_cell_coverage_counts(self.hunt_id, rules, targets)
        counts["missing_rule_targets"] = max(
            0, counts["expected_rule_targets"] - counts["present_rule_targets"],
        )
        sweep = self.repo.latest_audit(self.hunt_id, "hunt.sweep_summary")
        detail = (sweep or {}).get("detail") or {}
        finished = bool(sweep and detail.get("finished", detail.get("complete")))
        stats = detail.get("stats") or {}
        profiles = manifest.get("source_profiles") or {}
        # a reason about records that were evaluated leaves nothing unassessed
        not_assessed = sum(1 for reason, count in (stats.get("skips") or {}).items()
                           if count and reason not in EVALUATED_SKIPS)
        for target, retrieved in (stats.get("dataset_filter") or {}).items():
            inventory = (profiles.get(target) or {}).get("datasets")
            if not isinstance(inventory, dict):
                not_assessed += 1
            else:
                not_assessed += len(set(inventory) - set(retrieved))
                not_assessed += not (profiles.get(target) or {}).get("datasets_complete", True)
        not_assessed += sum(len(rows) for rows in (stats.get("dataset_reconciliation") or {}).values())
        counts["not_assessed"] = not_assessed
        counts["sweep_finished"] = int(finished)
        incomplete = counts["incomplete"] + counts["missing_rule_targets"] + not_assessed
        coverage = {
            "status": "partial" if incomplete or not finished else "complete",
            "counts": counts,
            "gaps": [], "more": bool(incomplete or not finished),
            "fetch": "list_coverage page=1" if incomplete or not finished else None,
        }
        return _result(coverage["status"], coverage=coverage,
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

    def followable_kinds(self, finding_id: str) -> tuple[str, ...] | None:
        """The follow_link kinds the executor can follow from this finding, in the order the tool lists them; None
        when no executor says (every kind then goes to follow_link, which reports its own outcome)."""
        decide = getattr(self.executor, "followable_links", None)
        if decide is None:
            return None
        kinds = set(decide(finding_id))
        return tuple(kind for kind in FOLLOW_LINK_KINDS if kind in kinds)

    @staticmethod
    def _semantic_refusal(code: str, message: str) -> dict:
        return _result("refused", data={"error": {"code": code, "message": message}})

    def _run_pivot(self, anchor: dict, request, *, page: int, cursor: str | None,
                   chunk_index: int | None = None) -> dict:
        identity = _jsonable({
            "kind": "pivot", "session_id": self.session_id, "anchor": anchor["id"],
            "request": request.model_dump(mode="json"),
        })
        search = request.tool == "search_events"
        if cursor is not None:
            plan = self.repo.agent_page_plan(self.hunt_id, cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the tool cursor is not valid for this hunt")
            if plan["identity"] != identity:
                return self._semantic_refusal(
                    "cursor_request_mismatch", "the cursor belongs to a different tool request",
                )
            return self._pivot_plan_result(plan, page=page, cursor=cursor, chunk_index=chunk_index)
        if page != 1:
            return self._semantic_refusal("cursor_required", "a continuation page requires its cursor")
        if self.executor is None or self.session_id is None:
            return _result("unsupported", data={"error": {
                "code": "pivot_unavailable", "message": "the hunt layer did not provide a pivot executor",
            }})
        stable = None
        if search:
            # One identity per canonical search in this session: a repeated search reads its stored result again
            # and spends no source query. A failed search is stored too, and may be tried again under the next
            # derived cursor, so a later repeat finds the try that succeeded; past the last try the last failure is
            # returned, never run again.
            plan = None
            for attempt in range(SEARCH_RETRY_KEYS):
                stable = "P" + digest({"identity": identity, "attempt": attempt})[:20]
                plan = self.repo.agent_page_plan(self.hunt_id, stable)
                if plan is None or plan["identity"] != identity:
                    break
                if plan["summary"].get("status") != "failed":
                    return self._pivot_plan_result(plan, page=1, cursor=stable, chunk_index=chunk_index,
                                                   repeated=True)
            else:
                return self._pivot_plan_result(plan, page=1, cursor=stable, chunk_index=chunk_index, repeated=True)
        if anchor["ts"] is None:
            return self._semantic_refusal("observation_time_unavailable", "the finding has no recorded observation time")
        if search:
            refuse = getattr(self.executor, "search_refusal", None)
            refusal = refuse(request) if refuse is not None else None
            if refusal is not None:
                return _result("refused", data={"error": refusal})
            # the result must fit the session's stored page items: checked before any source query is spent
            bound = getattr(self.executor, "search_item_bound", None)
            needed = bound(request) if bound is not None else 0
            plans_left, items_left = self.repo.agent_page_headroom(self.hunt_id, identity)
            if plans_left < 1 or items_left < needed:
                return _result("refused", data={"error": {
                    "code": "page_quota",
                    "message": (f"this session's stored tool results leave {items_left} page items and "
                                f"{plans_left} result pages, and a search may need up to {needed} items; nothing "
                                "was searched. Finish the session, or rely on results already returned."),
                    "reasons": [refusal_reason("$", "page_quota")],
                }})
        anchor_ts = self._utc(anchor["ts"])
        if search:
            try:
                result = self.executor.run(self.session_id, anchor["id"], request, anchor_ts=anchor_ts)
            except Exception as exc:  # noqa: BLE001 -- a failed search is stored, so a repeat does not spend again
                result = PivotResult(status="failed", reasons=[
                    _bounded_text(f"search failed: {type(exc).__name__}: {exc}")])
        else:
            result = self.executor.run(self.session_id, anchor["id"], request, anchor_ts=anchor_ts)
        if not search:
            return self._pivot_result(result, page=1, identity=identity, cursor=stable, chunk_index=chunk_index)
        try:
            return self._pivot_result(result, page=1, identity=identity, cursor=stable,
                                      extra=self._search_summary(request, result), chunk_index=chunk_index)
        except ValueError as exc:
            # the result could not be stored (the session's page quota): stored as a failure, so a repeat does not
            # spend again; when even that cannot be stored, it is returned as a failure
            failed = PivotResult(status="failed", reasons=[_bounded_text(f"search result not stored: {exc}")])
            try:
                return self._pivot_result(failed, page=1, identity=identity, cursor=stable,
                                          extra=self._search_summary(request, failed), chunk_index=chunk_index)
            except ValueError:
                return _result("failed", data={"error": {"code": "result_not_stored", "message": str(exc)}})

    @staticmethod
    def _search_summary(request, result: PivotResult) -> dict:
        """What a search asked and what its hits mean, stored with its result so every page says the same."""
        args = request.arguments
        # A search finds what is there. Typed values can be derived from what is stored (case, canonical forms, short
        # host names, text), so zero hits is never a confirmed absence: it is unresolved, with what was searched and
        # what was not.
        found = bool(result.matched_event_count or result.reach_event_ids or result.event_ids)
        why = [*result.not_searched, *result.zero_caveats, *result.reasons]
        return {
            "scope": args.scope,
            "conditions": [item.model_dump(mode="json") for item in args.conditions],
            "window": {"start": args.start.isoformat(), "end": args.end.isoformat()},
            "negative": "matches_found" if found else "unresolved",
            "statement": (None if found else
                          "no records matched in the sources searched; this is not a confirmed absence"),
            "gaps_and_caveats": [_bounded_text(reason) for reason in why[:SEARCH_REASONS_SHOWN]],
            "gaps_and_caveats_omitted": max(0, len(why) - SEARCH_REASONS_SHOWN),
            "not_searched": [_bounded_text(item) for item in result.not_searched],
            "discarded": result.discarded,
            "match_semantics": ("the source matched each condition on its stored field; on fields sent in a special "
                                "form (a name without case, a Windows host by its short name, an account by its "
                                "short name) each hit was re-checked on its typed value, and rows that value refuted "
                                "are counted in discarded, never shown as matches"),
        }

    @staticmethod
    def _persisted_event_summary(row: dict, first: tuple[str, ...] = ()) -> dict:
        """A retained event's bounded summary: sixteen typed fields, those named in `first` (a search's own fields)
        before the rest, so a summary never cuts them."""
        event = TypedEvent.model_validate(row["event"])
        ordered = sorted(event.fields.items(), key=lambda item: (item[0] not in first, item[0]))
        return {
            "id": event.id, "family": event.family, "ts": event.ts.isoformat(), "host": event.host,
            "outcome": str(event.outcome),
            "fields": {name: field.value for name, field in ordered[:16]},
            "caveats": event.caveats[:5],
        }

    def _pivot_result(self, result: PivotResult, *, page: int, identity: dict,
                      cursor: str | None = None, persist: bool = True, extra: dict | None = None,
                      chunk_index: int | None = None) -> dict:
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
            if extra is not None:
                summary["search"] = extra

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
             owner_token=self.owner_token)
        else:
            plan = self.repo.agent_page_plan(self.hunt_id, cursor)
            if plan is None:
                return self._semantic_refusal("unknown_cursor", "the tool cursor is not valid for this hunt")
        return self._pivot_plan_result(plan, page=page, cursor=cursor, chunk_index=chunk_index)

    def _pivot_plan_result(self, plan: dict, *, page: int, cursor: str, chunk_index: int | None = None,
                           repeated: bool = False) -> dict:
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
        search = summary.get("search")
        first = tuple(item["field"] for item in (search or {}).get("conditions", []))
        persisted = {row["id"]: self._persisted_event_summary(row, first)
                     for row in self.repo.citation_events(self.hunt_id, page_ids)}
        # a search's records carry any telemetry text: their field values share one bounded, chunked allowance
        budget = _TelemetryBudget(chunk_index or 1) if search is not None else None
        summaries = []
        for event_id in page_ids:
            event_summary = persisted.get(event_id)
            if event_summary is None:
                continue
            item = _jsonable(event_summary)
            if item.get("id") in event_aliases:
                item["alias"] = event_aliases[item.pop("id")]
            if budget is not None:
                # the searched fields first and on their own, so neither the field limit nor a chunk cuts them
                fields = item.get("fields") or {}
                searched = {name: fields.pop(name) for name in first if name in fields}
                route = f"search_events page={page} cursor={cursor}"
                item["searched_fields"] = budget.project(searched, route)
                item["fields"] = budget.project(fields, route)
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
        if search is not None:
            data["result"]["search"] = {**search, "repeated": repeated}
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
        rows = self.repo.citation_events(self.hunt_id, [event_id])
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

    def _search_events(self, args: SearchEventsToolArgs) -> dict:
        anchor = self._anchor(args.anchor)
        manifest = ((self.repo.get_hunt(self.hunt_id) or {}).get("manifest") or {})
        stored = manifest.get("window") or {}
        hunt_start = self._utc(datetime.fromisoformat(str(stored["start"])))
        hunt_end = self._utc(datetime.fromisoformat(str(stored["end"])))
        start = self._utc(args.start) if args.start is not None else hunt_start
        end = self._utc(args.end) if args.end is not None else hunt_end
        if start < hunt_start or end > hunt_end or start >= end:
            # never clipped: the window searched is the window asked for
            return _result("refused", data={"error": {
                "code": "outside_hunt_window",
                "message": (f"the search window must lie inside the hunt window {hunt_start.isoformat()} to "
                            f"{hunt_end.isoformat()}, with start before end"),
                "reasons": [refusal_reason("start" if start < hunt_start else "end", "outside_hunt_window")],
            }})
        request = pivot_tools.SearchEventsRequest(tool="search_events", arguments=pivot_tools.SearchEventsArgs(
            scope=args.scope, conditions=args.conditions, start=start, end=end,
        ))
        return self._run_pivot(anchor, request, page=args.page, cursor=args.cursor, chunk_index=args.chunk_index)

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
        followable = self.followable_kinds(anchor["id"])
        if followable is not None and args.link_type not in followable:
            # the anchor's records carry no typed key for this kind: refused before any source query
            return _result("refused", data={"error": {
                "code": "link_not_followable",
                "message": ("this anchor's cited records carry no typed key for that link kind; the kinds it "
                            "supports are " + (", ".join(followable) or "none")),
                "follow_link_kinds": list(followable),
                "reasons": [refusal_reason("link_type", "not_followable")],
            }})
        result = self.executor.follow_link(
            self.session_id, anchor["id"], args.link_type, args.window,
        )
        return self._pivot_result(result, page=1, identity=identity)
