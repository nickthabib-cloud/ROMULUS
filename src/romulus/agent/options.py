"""Pure, deterministic menus for investigator-v2 decisions."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from romulus.agent.cases import seed_candidate_ids
from romulus.agent.models import AgentDecision, EntityRef

_TOOL_ENTITY_KINDS = {
    "entity_timeline": {"host", "ip"},
    "auth_activity": {"host", "account"},
    "ids_alerts": {"ip"},
}
_ENTITY_RANK = {"host": 0, "account": 1, "ip": 2, "domain": 3}
DEFAULT_MENU_CAP = 12


class MenuOption(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    description: str
    decision: AgentDecision
    rule_template: bool = False
    window_label: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    entity_kind: str | None = None
    entity_value: str | None = None
    process_id: int | None = None


class Menu(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    options: list[MenuOption]
    hidden_count: int = Field(ge=0)

    @property
    def pivot_options(self) -> list[MenuOption]:
        return [option for option in self.options if option.decision.action == "pivot"]


def _utc(value: datetime | str) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _entity_refs(raw_entities: list[Any]) -> list[EntityRef]:
    refs: dict[tuple[str, str, str], EntityRef] = {}
    for raw in raw_entities:
        if isinstance(raw, (list, tuple)) and len(raw) >= 3:
            ref = EntityRef(kind=raw[0], value=str(raw[1]), role=str(raw[2]))
        elif isinstance(raw, dict):
            ref = EntityRef.model_validate(raw)
        else:
            continue
        refs[(ref.kind, ref.value, ref.role)] = ref
    return sorted(refs.values(), key=lambda item: (_ENTITY_RANK[item.kind], item.value, item.role))


def _field_value(fields: dict, name: str):
    value = fields.get(name)
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def _named_windows(
    evidence: list[dict], seed_candidates: list[dict], hunt_start: datetime, hunt_end: datetime,
) -> list[tuple[str, datetime, datetime]]:
    timestamps = sorted(_utc(item["ts"]) for item in evidence if item.get("ts") is not None)
    if not timestamps:
        return []
    anchor = timestamps[-1]
    raw = [
        ("anchor ±5 min", anchor - timedelta(minutes=5), anchor + timedelta(minutes=5)),
        ("anchor ±30 min", anchor - timedelta(minutes=30), anchor + timedelta(minutes=30)),
        ("anchor ±2 h", anchor - timedelta(hours=2), anchor + timedelta(hours=2)),
    ]
    seed_evidence_ids = {
        str(event_id)
        for candidate in seed_candidates for event_id in candidate.get("event_ids") or []
    }
    seed_times = sorted(
        _utc(item["ts"])
        for item in evidence
        if item.get("ts") is not None and str(item.get("id")) in seed_evidence_ids
    )
    if len(seed_times) >= 2 and seed_times[0] < seed_times[-1]:
        raw.append(("seed-cluster span", seed_times[0], seed_times[-1]))

    windows: list[tuple[str, datetime, datetime]] = []
    seen: set[tuple[datetime, datetime]] = set()
    for label, start, end in raw:
        clipped = (max(start, hunt_start), min(end, hunt_end))
        if clipped[0] >= clipped[1] or clipped in seen:
            continue
        seen.add(clipped)
        windows.append((label, *clipped))
    return windows


def _executed_keys(steps: list[dict]) -> set[tuple]:
    keys: set[tuple] = set()
    for step in steps:
        decision = step.get("decision") or {}
        if not step.get("accepted") or step.get("result_digest") is None or decision.get("action") != "pivot":
            continue
        arguments = decision.get("arguments") or {}
        try:
            window = (_utc(arguments["start"]), _utc(arguments["end"]))
        except (KeyError, TypeError, ValueError):
            continue
        entity = arguments.get("entity")
        if isinstance(entity, dict):
            keys.add((decision.get("tool"), window, entity.get("kind"), str(entity.get("value"))))
        elif arguments.get("host") and isinstance(arguments.get("process_id"), int):
            keys.add((decision.get("tool"), window, str(arguments["host"]), arguments["process_id"]))
    return keys


def _pivot_option(
    *, tool: str, label: str, start: datetime, end: datetime,
    entity: EntityRef | None = None, host: str | None = None, process_id: int | None = None,
    rule_template: bool,
) -> MenuOption:
    if entity is not None:
        target = f"{entity.kind} {entity.value}"
        arguments = {"entity": entity.model_dump(mode="json"), "start": start, "end": end}
        entity_kind, entity_value = entity.kind, entity.value
    else:
        target = f"host {host} pid {process_id}"
        arguments = {"host": host, "process_id": process_id, "start": start, "end": end}
        entity_kind, entity_value = "host", host
    return MenuOption(
        id="",
        description=f"{tool} for {target}, {label}",
        decision=AgentDecision(
            action="pivot", tool=tool, arguments=arguments,
            hypothesis=f"Related {tool.replace('_', ' ')} evidence exists for {target} in {label}.",
            expected_true=f"The pivot returns related evidence for {target}.",
            expected_false=f"The pivot returns no related evidence for {target}.",
        ),
        rule_template=rule_template,
        window_label=label, window_start=start, window_end=end,
        entity_kind=entity_kind, entity_value=entity_value, process_id=process_id,
    )


def _investigation_rank(option: MenuOption) -> tuple:
    if option.decision.action == "pivot":
        duration = (option.window_end - option.window_start).total_seconds()  # type: ignore[operator]
        return (
            0 if option.rule_template else 1,
            duration,
            _ENTITY_RANK.get(option.entity_kind or "domain", 9),
            option.decision.tool or "",
            option.entity_value or "",
            option.process_id or 0,
            option.window_start,
            option.window_end,
        )
    return (2, 0, _ENTITY_RANK.get(option.entity_kind or "domain", 9), "", option.entity_value or "", 0,
            datetime.min.replace(tzinfo=UTC), datetime.min.replace(tzinfo=UTC))


def generate_options(
    *,
    case: dict,
    evidence: list[dict],
    candidates: list[dict],
    steps: list[dict],
    hunt_window: Any,
    existing_case_entities: set[tuple[str, str]],
    max_cases: int,
    case_count: int,
    cap: int = DEFAULT_MENU_CAP,
) -> Menu:
    """Return the legal next moves derivable from durable case state."""
    hunt_start, hunt_end = _utc(hunt_window.start), _utc(hunt_window.end)
    seed_ids = set(seed_candidate_ids(steps))
    seed_candidates = sorted(
        (candidate for candidate in candidates if candidate.get("id") in seed_ids),
        key=lambda item: (-float(item.get("priority", 0)), str(item.get("id"))),
    )
    raw_entities = (
        list(case.get("entities") or [])
        + [entity for candidate in candidates for entity in candidate.get("entities") or []]
    )
    entities = _entity_refs(raw_entities)
    entities = [entity for entity in entities if not (entity.kind == "host" and entity.role == "observer")]
    known_hosts = {entity.value for entity in entities if entity.kind == "host"}
    template_tools = {
        tool
        for candidate in seed_candidates
        for check in candidate.get("next_checks") or []
        for tool in set(_TOOL_ENTITY_KINDS) | {"process_tree"}
        if tool in str(check)
    }
    windows = _named_windows(evidence, seed_candidates, hunt_start, hunt_end)
    executed = _executed_keys(steps)
    investigations: list[MenuOption] = []

    for tool, kinds in _TOOL_ENTITY_KINDS.items():
        for entity in entities:
            if entity.kind not in kinds:
                continue
            for label, start, end in windows:
                key = (tool, (start, end), entity.kind, entity.value)
                if key in executed:
                    continue
                investigations.append(_pivot_option(
                    tool=tool, label=label, start=start, end=end, entity=entity,
                    rule_template=tool in template_tools,
                ))

    process_pairs: set[tuple[str, int]] = set()
    for item in evidence:
        host = item.get("host")
        if not host or str(host) not in known_hosts:
            continue
        fields = item.get("fields") or {}
        for name in ("process.pid", "process.ppid"):
            process_id = _field_value(fields, name)
            if isinstance(process_id, int) and process_id > 0:
                process_pairs.add((str(host), process_id))
    for host, process_id in sorted(process_pairs):
        for label, start, end in windows:
            key = ("process_tree", (start, end), host, process_id)
            if key in executed:
                continue
            investigations.append(_pivot_option(
                tool="process_tree", label=label, start=start, end=end,
                host=host, process_id=process_id, rule_template="process_tree" in template_tools,
            ))

    if case_count < max_cases:
        discoveries = _entity_refs([
            entity
            for step in steps
            for entity in (step.get("result_digest") or {}).get("entities") or []
        ])
        for entity in discoveries:
            if entity.kind == "host" and entity.role == "observer":
                continue
            if (entity.kind, entity.value) in existing_case_entities:
                continue
            investigations.append(MenuOption(
                id="", description=f"spawn a case for {entity.kind} {entity.value}",
                decision=AgentDecision(action="spawn", entity=entity),
                entity_kind=entity.kind, entity_value=entity.value,
            ))

    investigations.sort(key=_investigation_rank)
    escalations: list[MenuOption] = []
    for candidate in seed_candidates:
        escalations.append(MenuOption(
            id="", description=f"escalate {candidate['id']}: {candidate['claim']}",
            decision=AgentDecision(
                action="escalate", candidate_id=str(candidate["id"]),
                claim=str(candidate["claim"]), proposed_lane=candidate["lane"],
            ),
        ))
    terminal_options = [
        MenuOption(
            id="", description="park this case as a lead",
            decision=AgentDecision(action="park_as_lead", resolution_needed="Analyst review is still required."),
        ),
        MenuOption(id="", description="close this case", decision=AgentDecision(action="close")),
    ]

    reserved_investigation = int(bool(investigations))
    required = len(escalations) + len(terminal_options) + reserved_investigation
    if required > cap:
        raise ValueError(
            f"seed cluster has {len(escalations)} conclusions; menu cap {cap} supports at most "
            f"{max(0, cap - len(terminal_options) - reserved_investigation)}"
        )
    conclusions = escalations + terminal_options
    available_slots = max(0, cap - len(conclusions))
    visible_investigations = investigations[:available_slots]
    visible = visible_investigations + conclusions
    hidden_count = len(investigations) - len(visible_investigations)
    numbered = [option.model_copy(update={"id": f"O{index}"}) for index, option in enumerate(visible, 1)]
    return Menu(options=numbered, hidden_count=hidden_count)
