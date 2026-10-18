"""Hunt-layer execution of validated, source-neutral investigator pivots."""
from __future__ import annotations

from time import perf_counter

from romulus.agent.models import EntityRef, PivotResult
from romulus.agent.tools import (
    AuthActivityRequest,
    EntityTimelineRequest,
    IdsAlertsRequest,
    ProcessTreeRequest,
    ToolRequest,
)
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import TypedEvent
from romulus.hunt.publish import publish_match
from romulus.sources.es import ElasticClient
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import FieldContract
from romulus.store.db import digest
from romulus.store.repo import Repo

MAX_PIVOT_RECORDS = 10_000
MAX_EVENT_SUMMARIES = 50
MAX_SUMMARY_FIELDS = 16


def _is_network(target: str) -> bool:
    return "network" in target.lower()


def _supports(contract: FieldContract, field: str) -> bool:
    return contract.supports(field, "eq")


def _event_entities(event: TypedEvent) -> list[EntityRef]:
    return [EntityRef(kind=kind, value=value, role=role) for kind, value, role in event.entities()]


def _summary(event: TypedEvent) -> dict:
    fields = {
        name: field.value
        for name, field in sorted(event.fields.items())[:MAX_SUMMARY_FIELDS]
    }
    return {
        "id": event.id, "family": event.family, "ts": event.ts.isoformat(), "host": event.host,
        "outcome": str(event.outcome), "fields": fields, "caveats": event.caveats[:5],
    }


class PivotExecutor:
    """Translate accepted tools to safe intents, then normalize and directly detect results."""

    def __init__(self, repo: Repo, client: ElasticClient, hunt_id: str,
                 contracts: dict[str, FieldContract]):
        self.repo = repo
        self.client = client
        self.hunt_id = hunt_id
        self.contracts = contracts

    def _intents(self, request: ToolRequest) -> list[SearchIntent]:
        args = request.arguments
        window = Window(start=args.start, end=args.end)
        intents: list[SearchIntent] = []
        for target, contract in self.contracts.items():
            network = _is_network(target)
            filters: list[Predicate] = []
            any_of: list[list[Predicate]] = []

            if isinstance(request, EntityTimelineRequest):
                entity = args.entity
                if entity.kind == "ip" and network:
                    if not (_supports(contract, "source.ip") and _supports(contract, "destination.ip")):
                        continue
                    any_of = [
                        [Predicate(field="source.ip", op="eq", value=entity.value)],
                        [Predicate(field="destination.ip", op="eq", value=entity.value)],
                    ]
                elif entity.kind == "ip" and not network:
                    if not _supports(contract, "event.dataset"):
                        continue
                    filters = [Predicate(field="event.dataset", op="eq", value="systemd.journal")]
                elif entity.kind == "host" and not network and _supports(contract, "host.name"):
                    filters = [Predicate(field="host.name", op="eq", value=entity.value)]
                else:
                    continue
            elif isinstance(request, AuthActivityRequest):
                if network or not _supports(contract, "event.dataset"):
                    continue
                filters = [Predicate(field="event.dataset", op="eq", value="systemd.journal")]
                if args.entity.kind == "host":
                    if not _supports(contract, "host.name"):
                        continue
                    filters.append(Predicate(field="host.name", op="eq", value=args.entity.value))
            elif isinstance(request, ProcessTreeRequest):
                if network or not (_supports(contract, "event.dataset") and _supports(contract, "host.name")):
                    continue
                filters = [
                    Predicate(field="event.dataset", op="eq", value="linux.audit"),
                    Predicate(field="host.name", op="eq", value=args.host),
                ]
            elif isinstance(request, IdsAlertsRequest):
                if not network:
                    continue
                if args.entity.kind == "ip":
                    if not (_supports(contract, "source.ip") and _supports(contract, "destination.ip")):
                        continue
                    any_of = [
                        [Predicate(field="source.ip", op="eq", value=args.entity.value)],
                        [Predicate(field="destination.ip", op="eq", value=args.entity.value)],
                    ]
                elif _supports(contract, "host.name"):
                    filters = [Predicate(field="host.name", op="eq", value=args.entity.value)]
                else:
                    continue

            intents.append(SearchIntent(
                kind="raw", target=target, window=window, filters=filters, any_of=any_of,
                max_records=MAX_PIVOT_RECORDS, purpose=f"agent:{request.tool}",
            ))
        return intents

    @staticmethod
    def _retain(request: ToolRequest, event: TypedEvent) -> bool:
        args = request.arguments
        if isinstance(request, EntityTimelineRequest):
            entity = args.entity
            return any(item.kind == entity.kind and item.value == entity.value for item in _event_entities(event))
        if isinstance(request, AuthActivityRequest):
            if event.family not in {"auth", "privilege_use"}:
                return False
            entity = args.entity
            return (event.host == entity.value if entity.kind == "host" else
                    any(item.kind == "account" and item.value == entity.value for item in _event_entities(event)))
        if isinstance(request, ProcessTreeRequest):
            return (event.family == "process_exec" and event.host == args.host
                    and args.process_id in {event.get("process.pid"), event.get("process.ppid")})
        if isinstance(request, IdsAlertsRequest):
            if event.family != "net_alert":
                return False
            entity = args.entity
            return (event.host == entity.value if entity.kind == "host" else
                    any(item.kind == "ip" and item.value == entity.value for item in _event_entities(event)))
        return False

    def run(self, case_id: str, request: ToolRequest) -> PivotResult:
        started = perf_counter()
        intents = self._intents(request)
        if not intents:
            return PivotResult(status="unsupported", reasons=["no compatible source contract"])

        task_ids: list[str] = []
        retained: list[TypedEvent] = []
        raw_sources: dict[str, dict] = {}
        reasons: list[str] = []
        successful_outcomes = 0
        incomplete = False

        for intent in intents:
            fingerprint = digest({
                "case_id": case_id,
                "tool": request.model_dump(mode="json"),
                "target": intent.target,
            })
            task_id = "t-" + fingerprint[:20]
            task_ids.append(task_id)
            self.repo.upsert_task(
                task_id, self.hunt_id, "pivot", case_id, intent.model_dump(mode="json"), fingerprint,
            )
            self.repo.update_task(task_id, "leased", attempt=True)
            outcome = execute(self.client, intent, self.contracts[intent.target])
            outcome_digest = {
                "completeness": str(outcome.completeness), "reasons": outcome.reasons,
                "total": outcome.total, "returned": outcome.returned,
            }
            if outcome.completeness == Completeness.failed:
                incomplete = True
                reasons.extend(outcome.reasons or [outcome.error or "source execution failed"])
                self.repo.update_task(task_id, "failed", outcome=outcome_digest, error=outcome.error)
                continue

            successful_outcomes += 1
            incomplete |= outcome.completeness != Completeness.complete
            reasons.extend(outcome.reasons)
            self.repo.update_task(task_id, "executed", outcome=outcome_digest)
            events, _skips, errors = normalize_hits(outcome.records)
            if errors:
                incomplete = True
                reasons.append(f"normalization_errors:{len(errors)}")
            selected = [event for event in events if self._retain(request, event)]
            sources = {f"{record['_index']}/{record['_id']}": record["_source"] for record in outcome.records}
            raw_sources.update(sources)
            self.repo.save_evidence(self.hunt_id, selected, sources, task_id)
            retained.extend(selected)
            self.repo.update_task(task_id, "evaluated")

        candidate_ids: list[str] = []
        for playbook in fresh_direct_pack():
            for match in playbook.consume(retained):
                row = publish_match(
                    self.repo, self.hunt_id, playbook, match, task_ids[0] if task_ids else None,
                    raw_sources, source_case_id=case_id,
                )
                if row is not None:
                    candidate_ids.append(row["id"])

        unique_events = {event.id: event for event in retained}
        unique_entities = {
            (entity.kind, entity.value, entity.role): entity
            for event in unique_events.values() for entity in _event_entities(event)
        }
        if successful_outcomes == 0:
            status = "failed"
        elif incomplete:
            status = "partial"
        else:
            status = "complete"
        duration_ms = int((perf_counter() - started) * 1000)
        return PivotResult(
            status=status,
            task_ids=task_ids,
            event_ids=list(unique_events),
            candidate_ids=candidate_ids,
            entities=list(unique_entities.values()),
            event_summaries=[_summary(event) for event in list(unique_events.values())[:MAX_EVENT_SUMMARIES]],
            reasons=sorted(set(reasons)),
            duration_ms=duration_ms,
        )
