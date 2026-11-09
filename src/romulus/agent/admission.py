"""Validation and bounded persistence for model-proposed hypotheses and outputs."""
from __future__ import annotations

import re
import uuid
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from romulus.agent.aliases import AliasBook, AliasError
from romulus.agent.claims import supports_claim_kind
from romulus.agent.safety import injection_flags
from romulus.agent.toolbox import RegisteredTool, Toolbox, _result
from romulus.catalog.attack import ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256, load_attack_bundle
from romulus.evidence.typed import TypedEvent
from romulus.store.db import digest, utcnow

Alias = Annotated[str, Field(pattern=r"^[FIENLHA][1-9][0-9]*$")]
ShortText = Annotated[str, Field(min_length=1, max_length=1000)]
Question = Annotated[str, Field(min_length=1, max_length=300)]


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OpenHypothesisArgs(_Args):
    statement: Annotated[str, Field(min_length=10, max_length=600)]
    techniques: list[Annotated[str, Field(min_length=2, max_length=16)]] = Field(default_factory=list, max_length=20)
    entities: list[Alias] = Field(default_factory=list, max_length=40)
    supporting: list[Alias] = Field(default_factory=list, max_length=40)
    questions: list[Question] = Field(default_factory=list, max_length=8)


class UpdateHypothesisArgs(_Args):
    hypothesis: Alias
    status: Literal["open", "supported", "weakened", "refuted", "abandoned"] | None = None
    confidence: Literal["low", "medium", "high"] | None = None
    add_support: list[Alias] = Field(default_factory=list, max_length=20)
    add_contradiction: list[Alias] = Field(default_factory=list, max_length=20)
    questions: list[Question] | None = Field(default=None, max_length=8)
    note: Annotated[str, Field(min_length=1, max_length=600)]


class ProposeFindingArgs(_Args):
    claim: Annotated[str, Field(min_length=10, max_length=400)]
    claim_kind: Literal["execution", "network", "auth", "file", "account_change", "mention"]
    cites: list[Alias] = Field(min_length=1, max_length=20)
    lane: Literal["urgent", "high", "lead", "context"]
    techniques: list[Annotated[str, Field(min_length=2, max_length=16)]] = Field(default_factory=list, max_length=20)
    rationale: Annotated[str, Field(max_length=1000)] = ""
    hypothesis: Alias | None = None


class ProposeLinkArgs(_Args):
    from_: Alias = Field(alias="from")
    to: Alias
    relation: Literal["same_actor", "precedes", "enabled", "lateral_movement", "same_campaign", "related"]
    cites: list[Alias] = Field(min_length=1, max_length=20)
    rationale: Annotated[str, Field(min_length=1, max_length=1000)]


class AddNoteArgs(_Args):
    target: Alias
    text: Annotated[str, Field(min_length=1, max_length=1000)]
    cites: list[Alias] = Field(default_factory=list, max_length=20)


class RequestRuleArgs(_Args):
    pattern_description: Annotated[str, Field(min_length=20, max_length=1000)]
    cites: list[Alias] = Field(min_length=1, max_length=20)


class FinishSessionArgs(_Args):
    summary: Annotated[str, Field(min_length=20, max_length=2000)]


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _ok(data: dict) -> dict:
    return _result("complete", counts={"returned": 1, "total": 1}, data=data)


def _refused(message: str, *, code: str = "validation") -> dict:
    result = _result("refused", data={"error": {"code": code, "message": message}})
    result["errors"] = [message]
    return result


@lru_cache(maxsize=1)
def _technique_index() -> dict[str, tuple[object, object]]:
    enterprise = load_attack_bundle()
    ics = load_attack_bundle(ICS_ATTACK_BUNDLE, expected_sha256=ICS_PINNED_JSON_SHA256)
    return {item.id: (item, enterprise) for item in enterprise.techniques} | {
        item.id: (item, ics) for item in ics.techniques
    }


_ALIAS_VALUE = re.compile(r"^[FIENLHA][1-9][0-9]*$")
# These are producer-owned paths, never arbitrary recursively discovered key names.
_FINDING_PATHS = ("alias", "evidence.*", "entities.*.alias")
_INCIDENT_PATHS = ("alias", "members.*", "links.*.alias", "links.*.anchor", "links.*.targets.*")
_PIVOT_PATHS = ("result.evidence.*", "result.candidates.*", "result.entities.*.alias",
                "result.event_summaries.*.alias")
_TOOL_ALIAS_PATHS = {
    "list_findings": tuple("findings.*." + p for p in _FINDING_PATHS),
    "get_finding": tuple("finding." + p for p in _FINDING_PATHS),
    "get_evidence": ("evidence.*.alias",),
    "list_incidents": ("incidents.*.alias",),
    "get_incident": tuple("incident." + p for p in _INCIDENT_PATHS),
    "entity_profile": ("entity.alias", "entity.events.*.alias"),
    "entity_timeline": _PIVOT_PATHS, "auth_activity": _PIVOT_PATHS,
    "process_tree": _PIVOT_PATHS, "ids_alerts": _PIVOT_PATHS, "follow_link": _PIVOT_PATHS,
    "open_hypothesis": ("hypothesis",), "update_hypothesis": ("hypothesis",),
    "propose_finding": ("finding", "duplicate"), "propose_link": ("link",),
}
_ARGUMENT_ALIAS_PATHS = {
    "list_findings": ("entity",), "get_finding": ("finding",), "get_evidence": ("evidence.*",),
    "get_incident": ("incident",), "entity_profile": ("entity",),
    "entity_timeline": ("anchor", "entity"), "auth_activity": ("anchor", "entity"),
    "process_tree": ("anchor", "process"), "ids_alerts": ("anchor", "entity"),
    "follow_link": ("anchor",), "open_hypothesis": ("entities.*", "supporting.*"),
    "update_hypothesis": ("hypothesis", "add_support.*", "add_contradiction.*"),
    "propose_finding": ("cites.*", "hypothesis"), "propose_link": ("from", "to", "cites.*"),
    "add_note": ("target", "cites.*"), "request_rule": ("cites.*",),
}


def _path_aliases(value: object, paths: tuple[str, ...]) -> set[str]:
    def at(item, keys):
        if not keys:
            if isinstance(item, str) and _ALIAS_VALUE.fullmatch(item):
                yield item
        elif keys[0] == "*" and isinstance(item, (list, tuple)):
            for child in item:
                yield from at(child, keys[1:])
        elif isinstance(item, dict) and keys[0] in item:
            yield from at(item[keys[0]], keys[1:])
    return {alias for path in paths for alias in at(value, path.split("."))}


def typed_alias_arguments(tool_name: str, arguments: object) -> set[str]:
    """Read only the registered tools' alias argument positions, never their prose."""
    return _path_aliases(arguments, _ARGUMENT_ALIAS_PATHS.get(tool_name, ()))


def collect_issued_aliases(value: object, *, source: str = "tool", tool_name: str | None = None) -> set[str]:
    """Collect explicitly typed aliases in a prompt or tool payload shown to a session."""
    if source == "hypothesis":
        return _path_aliases(value, ("alias", "entities.*", "cites.*.alias"))
    if source == "dossier":
        paths = ("findings.*.alias", "entities.*.alias", "expansion.unfinished_anchors.*.anchor",
                 "expansion.link_tiers_not_reached.*.anchor", "expansion.partial_links.*.alias",
                 "expansion.partial_links.*.anchor") + tuple("incidents.*." + p for p in _INCIDENT_PATHS)
        return _path_aliases(value, paths)
    if source != "tool":
        raise ValueError(f"unknown alias source {source}")
    # Direct scalar/root inputs are an explicit controller/test issuance interface.
    if isinstance(value, str):
        return {value} if _ALIAS_VALUE.fullmatch(value) else set()
    if isinstance(value, (list, tuple)):
        return {alias for alias in value if isinstance(alias, str) and _ALIAS_VALUE.fullmatch(alias)}
    if not isinstance(value, dict):
        return set()
    data = value.get("data", value)
    if tool_name is not None:
        return _path_aliases(data, _TOOL_ALIAS_PATHS.get(tool_name, ()))
    paths = tuple(p for values in _TOOL_ALIAS_PATHS.values() for p in values)
    return _path_aliases(data, paths + ("finding", "evidence", "entity", "hypothesis", "link", "duplicate"))


class AgentAdmission:
    """A session-scoped admission boundary; rejected actions have no persistence side effects."""

    def __init__(self, settings, repo, hunt_id: str, session_id: str, *, hypothesis_id: str | None = None,
                 owner_token: str | None = None, purpose: str = "investigate",
                 issued_aliases: set[str] | None = None):
        self.settings = settings
        self.repo = repo
        self.hunt_id = hunt_id
        self.session_id = session_id
        self.hypothesis_id = hypothesis_id
        self.owner_token = owner_token
        self.purpose = purpose
        self.issued_aliases = set(issued_aliases or ())
        self.aliases = AliasBook(repo, hunt_id, owner_token=owner_token)
        self.limits_hit: set[str] = set()

    def register(self, toolbox: Toolbox) -> None:
        tools = (
            ("open_hypothesis", "Open a typed, cited investigation hypothesis.", OpenHypothesisArgs,
             self.open_hypothesis),
            ("update_hypothesis", "Update a hypothesis with cited support or contradiction.", UpdateHypothesisArgs,
             self.update_hypothesis),
            ("propose_finding", "Propose one cited AI finding for review; it cannot alter deterministic findings.",
             ProposeFindingArgs, self.propose_finding),
            ("propose_link", "Propose a non-joining relationship hypothesis between findings or entities.",
             ProposeLinkArgs, self.propose_link),
            ("add_note", "Attach a bounded, cited AI note to a hunt object.", AddNoteArgs, self.add_note),
            ("request_rule", "Describe a detection pattern for analyst review.", RequestRuleArgs, self.request_rule),
            ("finish_session", "Finish this session with a concise summary.", FinishSessionArgs, self.finish_session),
        )
        for name, description, model, handler in tools:
            if self.purpose == "orient" and name not in {"open_hypothesis", "finish_session"}:
                continue
            toolbox.registry[name] = RegisteredTool(name, description, model, handler)

    def _check_techniques(self, ids: list[str]) -> list[str]:
        index = _technique_index()
        accepted = []
        for attack_id in ids:
            entry = index.get(attack_id)
            if entry is None:
                raise ValueError(f"unknown ATT&CK technique {attack_id}")
            technique, knowledge = entry
            if technique.revoked or technique.deprecated:
                replacement = knowledge.replacement(attack_id)
                suffix = f"; use replacement {replacement}" if replacement else ""
                raise ValueError(f"ATT&CK technique {attack_id} is revoked or deprecated{suffix}")
            accepted.append(attack_id)
        return list(dict.fromkeys(accepted))

    def _resolve_many(self, aliases: list[str], kinds: set[str]) -> list[tuple[str, str]]:
        resolved = []
        for alias in aliases:
            if alias not in self.issued_aliases:
                raise ValueError(f"alias {alias!r} was not issued to this session")
            row = self.repo.agent_alias(self.hunt_id, alias)
            if row is None:
                raise ValueError(f"unknown alias {alias!r} in this hunt")
            if row["kind"] not in kinds:
                raise ValueError(f"alias {alias!r} has kind {row['kind']}; expected {', '.join(sorted(kinds))}")
            resolved.append((row["kind"], self.aliases.resolve(alias, {row["kind"]})))
        return resolved

    def issue_aliases(self, value: object, *, source: str = "tool", tool_name: str | None = None) -> None:
        """Issue only aliases in trusted producer fields shown to this model session."""
        for alias in collect_issued_aliases(value, source=source, tool_name=tool_name):
            if self.repo.agent_alias(self.hunt_id, alias) is not None:
                self.issued_aliases.add(alias)

    def _count(self, table: str) -> int:
        return self.repo.agent_cap_count(self.hunt_id, table)

    def _hypothesis_id(self, alias: str | None) -> str | None:
        if alias is None:
            return self.hypothesis_id
        if alias not in self.issued_aliases:
            raise ValueError(f"alias {alias!r} was not issued to this session")
        return self.aliases.resolve(alias, {"H"})

    def _event_cites(self, aliases: list[str]) -> tuple[list[str], list[dict]]:
        resolved = self._resolve_many(aliases, {"E"})
        ids = list(dict.fromkeys(target for _, target in resolved))
        rows = self.repo.citation_events(self.hunt_id, ids)
        by_id = {row["event"]["id"]: row for row in rows}
        if len(by_id) != len(ids):
            raise ValueError("one or more evidence aliases are not retained by this hunt")
        return ids, [by_id[item] for item in ids]

    def _save_note(self, target_kind: str, target_id: str, text: str, cites: list[str], suspicious: bool) -> str:
        if self._count("agent_note") >= self.settings.agent_max_notes:
            self.limits_hit.add("cap:notes")
            raise ValueError("agent note limit reached")
        note_id = _id("an")
        row = {
            "id": note_id, "hunt_id": self.hunt_id, "session_id": self.session_id,
            "target_kind": target_kind, "target_id": target_id, "text": text,
            "cites": cites, "suspicious_content": bool(suspicious), "created_at": utcnow(),
        }
        try:
            if target_kind == "hypothesis":
                self.repo.save_agent_hypothesis_note(row, {
                    "id": _id("he"), "hunt_id": self.hunt_id, "hypothesis_id": target_id,
                    "session_id": self.session_id, "kind": "note",
                    "payload": {"note": text, "cites": cites}, "created_at": utcnow(),
                }, max_count=self.settings.agent_max_notes, owner_token=self.owner_token)
            else:
                self.repo.save_agent_output("agent_note", row, max_count=self.settings.agent_max_notes,
                                            owner_token=self.owner_token)
        except ValueError as exc:
            if "agent note limit reached" in str(exc):
                self.limits_hit.add("cap:notes")
            raise
        return note_id

    def open_hypothesis(self, args: OpenHypothesisArgs) -> dict:
        try:
            if self._count("agent_hypothesis") >= self.settings.agent_max_hypotheses:
                self.limits_hit.add("cap:hypotheses")
                return _refused("hypothesis limit reached; update an existing one", code="cap")
            if self.purpose == "orient":
                opened_here = sum(row.get("created_session_id") == self.session_id
                                  for row in self.repo.agent_hypotheses(self.hunt_id))
                if opened_here >= self.settings.agent_max_initial_hypotheses:
                    self.limits_hit.add("cap:initial_hypotheses")
                    return _refused("initial hypothesis limit reached", code="cap")
            techniques = self._check_techniques(args.techniques)
            entities = self._resolve_many(args.entities, {"N"})
            supporting = self._resolve_many(args.supporting, {"F", "E", "L", "A"})
            statement = args.statement.strip()
            support_key = {(kind, target) for kind, target in supporting}
            for existing in self.repo.agent_hypotheses(self.hunt_id):
                if existing["statement"].strip().casefold() != statement.casefold():
                    continue
                existing_support = {(row["target_kind"], row["target_id"])
                                    for row in self.repo.agent_hypothesis_cites(hypothesis_id=existing["id"])
                                    if row["role"] == "support"}
                mapped_support = {("finding" if kind == "F" else "evidence" if kind == "E" else
                                   "link" if kind == "L" else "agent_link", target)
                                  for kind, target in support_key}
                if mapped_support <= existing_support:
                    alias = self.aliases.alias_for("H", existing["id"])
                    return _ok({"hypothesis": alias, "status": existing["status"], "duplicate": True})
            now = utcnow()
            hypothesis_id = _id("hyp")
            row = {
                "id": hypothesis_id, "hunt_id": self.hunt_id, "statement": statement,
                "techniques": techniques, "entity_ids": list(dict.fromkeys(value for _, value in entities)),
                "status": "open", "confidence": "low", "questions": [q.strip() for q in args.questions],
                "created_session_id": self.session_id, "sessions_run": 0, "created_at": now, "updated_at": now,
            }
            event = {"id": _id("he"), "hunt_id": self.hunt_id, "hypothesis_id": hypothesis_id,
                     "session_id": self.session_id, "kind": "opened",
                     "payload": {"by": "agent", "statement": row["statement"], "techniques": techniques,
                                 "entity_ids": row["entity_ids"], "questions": row["questions"]},
                     "created_at": now}
            cites = [{"hunt_id": self.hunt_id, "hypothesis_id": hypothesis_id, "role": "support",
                      "target_kind": {"F": "finding", "E": "evidence", "L": "link", "A": "agent_link"}[kind],
                      "target_id": value} for kind, value in supporting]
            self.repo.create_agent_hypothesis(row, event, cites,
                                              max_count=self.settings.agent_max_hypotheses,
                                              owner_token=self.owner_token)
            alias = self.aliases.alias_for("H", hypothesis_id)
            return _ok({"hypothesis": alias, "status": "open"})
        except (ValueError, AliasError) as exc:
            if "hypothesis limit reached" in str(exc):
                self.limits_hit.add("cap:hypotheses")
            return _refused(str(exc))

    def create_controller_hypothesis(self, statement: str, *, finding_id: str, alias: str) -> str:
        now = utcnow()
        hypothesis_id = _id("hyp")
        row = {"id": hypothesis_id, "hunt_id": self.hunt_id, "statement": statement[:600],
               "techniques": [], "entity_ids": [], "status": "open", "confidence": "low", "questions": [],
               "created_session_id": self.session_id, "sessions_run": 0, "created_at": now, "updated_at": now}
        event = {"id": _id("he"), "hunt_id": self.hunt_id, "hypothesis_id": hypothesis_id,
                 "session_id": self.session_id, "kind": "opened",
                 "payload": {"by": "controller", "finding_id": finding_id}, "created_at": now}
        cite = {"hunt_id": self.hunt_id, "hypothesis_id": hypothesis_id, "role": "support",
                "target_kind": "finding", "target_id": finding_id}
        try:
            self.repo.create_agent_hypothesis(row, event, [cite], max_count=self.settings.agent_max_hypotheses,
                                              owner_token=self.owner_token)
        except ValueError:
            self.limits_hit.add("cap:hypotheses")
            raise
        return self.aliases.alias_for("H", hypothesis_id)

    def update_hypothesis(self, args: UpdateHypothesisArgs) -> dict:
        try:
            if not args.note.strip():
                raise ValueError("note must contain non-whitespace text")
            hypothesis_id = self._hypothesis_id(args.hypothesis)
            current = self.repo.agent_hypothesis(self.hunt_id, hypothesis_id)
            if current is None:
                raise ValueError("hypothesis is not in this hunt")
            support = self._resolve_many(args.add_support, {"F", "E", "L", "A"})
            contradiction = self._resolve_many(args.add_contradiction, {"F", "E", "L", "A"})
            existing = self.repo.agent_hypothesis_cites(hypothesis_id=hypothesis_id)
            supports_after = any(row["role"] == "support" for row in existing) or bool(support)
            contradictions_after = any(row["role"] == "contradiction" for row in existing) or bool(contradiction)
            status = args.status or current["status"]
            if status == "supported" and not supports_after:
                raise ValueError("supported requires at least one support citation")
            if status == "refuted" and not contradictions_after:
                raise ValueError("refuted requires at least one contradiction citation")
            changes = {"updated_at": utcnow()}
            payload = {"note": args.note.strip()}
            if args.status is not None:
                changes["status"] = status
                payload["status"] = status
            if args.confidence is not None:
                changes["confidence"] = args.confidence
                payload["confidence"] = args.confidence
            if args.questions is not None:
                questions = [item.strip() for item in args.questions]
                changes["questions"] = questions
                payload["questions"] = questions
            new_cites = []
            for role, values in (("support", support), ("contradiction", contradiction)):
                for kind, target_id in values:
                    new_cites.append({"hunt_id": self.hunt_id, "hypothesis_id": hypothesis_id, "role": role,
                                      "target_kind": {"F": "finding", "E": "evidence", "L": "link", "A": "agent_link"}[kind],
                                      "target_id": target_id})
            if support:
                payload["add_support"] = [{"kind": {"F": "finding", "E": "evidence", "L": "link", "A": "agent_link"}[kind],
                                            "id": target} for kind, target in support]
            if contradiction:
                payload["add_contradiction"] = [{"kind": {"F": "finding", "E": "evidence", "L": "link", "A": "agent_link"}[kind],
                                                  "id": target} for kind, target in contradiction]
            if support and not contradiction:
                kind = "support_added"
            elif contradiction and not support:
                kind = "contradiction_added"
            else:
                kind = "updated"
            event = {"id": _id("he"), "hunt_id": self.hunt_id, "hypothesis_id": hypothesis_id,
                     "session_id": self.session_id, "kind": kind, "payload": payload, "created_at": utcnow()}
            self.repo.update_agent_hypothesis(hypothesis_id, self.hunt_id, changes, event, new_cites,
                                              owner_token=self.owner_token)
            return _ok({"hypothesis": args.hypothesis, "status": status, "added_support": len(support),
                        "added_contradiction": len(contradiction)})
        except (ValueError, AliasError) as exc:
            return _refused(str(exc))

    def propose_finding(self, args: ProposeFindingArgs) -> dict:
        try:
            if args.lane == "context":
                raise ValueError("agent findings cannot be context")
            if self._count("agent_finding") >= self.settings.agent_max_findings:
                self.limits_hit.add("cap:findings")
                raise ValueError("agent finding limit reached")
            evidence_ids, rows = self._event_cites(args.cites)
            events = [TypedEvent.model_validate(row["event"]) for row in rows]
            if not any(supports_claim_kind(event.family, args.claim_kind) for event in events):
                raise ValueError(f"cited event families do not support a {args.claim_kind} claim")
            techniques = self._check_techniques(args.techniques)
            hypothesis_id = self._hypothesis_id(args.hypothesis)
            claim_type = {"mention": "mention", "network": "network_observation"}.get(
                args.claim_kind, "observed_action")
            citations = set(evidence_ids)
            def same_claim_kind(candidate: dict) -> bool:
                stored_kind = (candidate.get("gate_results") or {}).get("_agent_claim_kind")
                if stored_kind:
                    return stored_kind == args.claim_kind
                if candidate.get("claim_type") != claim_type:
                    return False
                candidate_rows = self.repo.citation_events(self.hunt_id, candidate.get("event_ids") or [])
                candidate_families = {row["event"].get("family") for row in candidate_rows}
                return any(supports_claim_kind(family, args.claim_kind) for family in candidate_families)

            requested_lane = args.lane
            lane = "high" if requested_lane == "urgent" else requested_lane
            validation_notes = ["agent findings are capped at high"] if requested_lane == "urgent" else []
            if args.claim_kind == "mention" and lane in {"urgent", "high"}:
                lane = "lead"
                validation_notes.append("mention claims are capped at lead")
            ranks = {"urgent": 3, "high": 2, "lead": 1}
            eligible_lanes = [value for value, rank in ranks.items() if rank >= ranks[lane]]
            duplicate = None
            # Keep only one bounded batch alive, including when all candidates overlap one cite.
            for batch in self.repo.candidate_duplicate_batches(self.hunt_id, evidence_ids, eligible_lanes):
                duplicate = next((candidate for candidate in batch
                                  if citations <= set(candidate.get("event_ids") or [])
                                  and same_claim_kind(candidate)), None)
                if duplicate is not None:
                    break
                del batch  # Release this batch before the generator fetches another one.
            if duplicate is not None:
                target_alias = self.aliases.alias_for("F", duplicate["id"])
                text = f"Agent proposal: {args.claim.strip()}"
                if args.rationale:
                    text += f" Rationale: {args.rationale.strip()}"
                note_cites = [{"kind": "E", "id": item} for item in evidence_ids]
                suspicious = any(injection_flags({"event": row["event"]}) for row in rows)
                note_id = self._save_note("finding", duplicate["id"], text[:1000], note_cites, suspicious)
                return _ok({"duplicate": target_alias, "note_id": note_id,
                            "message": "proposal recorded as a note on the existing finding"})
            entity_values = sorted({entity for event in events for entity in event.entities()})
            timestamps = [event.ts for event in events]
            candidate_id = "agent-" + digest({"hunt_id": self.hunt_id, "evidence": sorted(citations),
                                               "claim": args.claim.strip(), "kind": args.claim_kind})[:20]
            rationale = args.rationale.strip()
            candidate = {
                "id": candidate_id, "hunt_id": self.hunt_id, "rule_id": "agent.finding", "rule_version": "1",
                "claim": args.claim.strip(), "claim_type": claim_type, "event_ids": evidence_ids,
                "context_event_ids": [], "predicate_fields": [], "entities": [list(item) for item in entity_values],
                "ts": min(timestamps) if timestamps else None, "severity": "high" if lane == "high" else "medium",
                "confidence": "low", "lane": lane, "priority": 1.0 if lane == "high" else 0.25,
                "priority_reasons": ["AI-generated proposal; analyst confirmation required"],
                "gate_results": {"_attack": techniques, "_agent_claim_kind": args.claim_kind,
                                 "_agent_rationale": rationale,
                                 "_notes": validation_notes},
                "benign_alternatives": [], "next_checks": [],
                "group_key": digest({"evidence": sorted(citations), "kind": args.claim_kind}),
                "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
                "provenance": "agent", "agent_hypothesis_id": hypothesis_id,
            }
            self.repo.save_candidate(candidate, max_agent_findings=self.settings.agent_max_findings,
                                     owner_token=self.owner_token)
            finding_alias = self.aliases.alias_for("F", candidate_id)
            return _ok({"finding": finding_alias, "lane": lane, "claim_type": claim_type,
                        "validation_notes": validation_notes, "rationale": rationale})
        except (ValueError, AliasError) as exc:
            if "agent finding limit reached" in str(exc):
                self.limits_hit.add("cap:findings")
            return _refused(str(exc), code="cap" if "limit reached" in str(exc) else "validation")

    def propose_link(self, args: ProposeLinkArgs) -> dict:
        try:
            if self._count("agent_link") >= self.settings.agent_max_links:
                self.limits_hit.add("cap:links")
                raise ValueError("agent link limit reached")
            source_kind, source_id = self._resolve_many([args.from_], {"F", "N"})[0]
            target_kind, target_id = self._resolve_many([args.to], {"F", "N"})[0]
            cites = self._resolve_many(args.cites, {"E", "F", "L"})
            hypothesis_id = self.hypothesis_id
            link_id = _id("alink")
            self.repo.save_agent_output("agent_link", {
                "id": link_id, "hunt_id": self.hunt_id, "session_id": self.session_id,
                "hypothesis_id": hypothesis_id, "from_kind": "finding" if source_kind == "F" else "entity",
                "from_id": source_id, "to_kind": "finding" if target_kind == "F" else "entity",
                "to_id": target_id, "relation": args.relation,
                "cites": [{"kind": kind, "id": target} for kind, target in cites],
                "rationale": args.rationale.strip(), "created_at": utcnow(),
            }, max_count=self.settings.agent_max_links, owner_token=self.owner_token)
            alias = self.aliases.alias_for("A", link_id)
            return _ok({"link": alias, "relation": args.relation, "incident_role": "hypothesis"})
        except (ValueError, AliasError) as exc:
            if "agent link limit reached" in str(exc):
                self.limits_hit.add("cap:links")
            return _refused(str(exc), code="cap" if "limit reached" in str(exc) else "validation")

    def add_note(self, args: AddNoteArgs) -> dict:
        try:
            target_kind, target_id = self._resolve_many([args.target], {"F", "I", "N", "H", "A"})[0]
            resolved_cites = self._resolve_many(args.cites, {"E", "F", "L", "A", "H"})
            citations = [{"kind": kind, "id": target} for kind, target in resolved_cites]
            evidence_ids = [target for kind, target in resolved_cites if kind == "E"]
            finding_ids = [target for kind, target in resolved_cites if kind == "F"]
            for finding in self.repo.candidates_by_ids(self.hunt_id, finding_ids):
                evidence_ids.extend(finding.get("event_ids") or [])
            evidence_ids = list(dict.fromkeys(evidence_ids))
            evidence_rows = self.repo.citation_events(self.hunt_id, evidence_ids) if evidence_ids else []
            suspicious = any(injection_flags({"event": row["event"]}) for row in evidence_rows)
            note_id = self._save_note({"F": "finding", "I": "incident", "N": "entity", "H": "hypothesis",
                                       "A": "agent_link"}[target_kind], target_id, args.text.strip(),
                                      citations, suspicious)
            return _ok({"note_id": note_id, "suspicious_content": suspicious})
        except (ValueError, AliasError) as exc:
            return _refused(str(exc), code="cap" if "limit reached" in str(exc) else "validation")

    def request_rule(self, args: RequestRuleArgs) -> dict:
        try:
            if self._count("agent_rule_request") >= 50:
                self.limits_hit.add("cap:rule_requests")
                raise ValueError("agent rule request limit reached")
            resolved = self._resolve_many(args.cites, {"E", "F"})
            row = {"id": _id("arr"), "hunt_id": self.hunt_id, "session_id": self.session_id,
                   "hypothesis_id": self.hypothesis_id, "pattern_description": args.pattern_description.strip(),
                   "cites": [{"kind": kind, "id": target} for kind, target in resolved], "created_at": utcnow()}
            self.repo.save_agent_output("agent_rule_request", row, max_count=50, owner_token=self.owner_token)
            return _ok({"request_id": row["id"], "status": "analyst review requested"})
        except (ValueError, AliasError) as exc:
            if "agent rule request limit reached" in str(exc):
                self.limits_hit.add("cap:rule_requests")
            return _refused(str(exc), code="cap" if "limit reached" in str(exc) else "validation")

    @staticmethod
    def finish_session(args: FinishSessionArgs) -> dict:
        return _ok({"finished": True, "summary": args.summary.strip()})
