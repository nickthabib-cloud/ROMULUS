"""Join the public catalog to the private, gitignored research register."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from romulus.catalog import Catalog, CoverageStrength

MAX_RESEARCH_FILE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class ResearchRegister:
    backlog: tuple[dict[str, Any], ...]
    tools: tuple[dict[str, Any], ...]
    lotl: tuple[dict[str, Any], ...]
    telemetry: tuple[dict[str, Any], ...]
    attack: tuple[dict[str, Any], ...]


def _yaml(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_RESEARCH_FILE_BYTES:
        raise ValueError(f"research file exceeds byte limit ({MAX_RESEARCH_FILE_BYTES}): {path}")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"research file must contain a mapping: {path}")
    return value


def load_research(root: Path) -> ResearchRegister:
    """Load the private register from explicit, bounded YAML files."""
    root = Path(root)
    backlog = _yaml(root / "backlog.yaml")
    tools = _yaml(root / "tools.yaml")
    lotl = _yaml(root / "lotl_linux.yaml")
    telemetry = _yaml(root / "telemetry_families.yaml")
    attack: list[dict[str, Any]] = []
    for path in sorted((root / "attack" / "enterprise").glob("*.yaml")):
        attack.extend(_yaml(path).get("entries", ()))
    if not attack:
        raise ValueError(f"no private ATT&CK register entries under {root}")
    return ResearchRegister(
        backlog=tuple(backlog.get("backlog", ())),
        tools=tuple(tools.get("tools", ())),
        lotl=tuple(lotl.get("binaries", ())),
        telemetry=tuple(telemetry.get("families", ())),
        attack=tuple(attack),
    )


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _attack_link(attack_id: str) -> str:
    path = attack_id.replace(".", "/")
    return f"[`{attack_id}`](https://attack.mitre.org/techniques/{path}/)"


def _as_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _priority(value: object) -> tuple[int, str]:
    text = str(value)
    match = re.fullmatch(r"P(\d+)", text)
    return (int(match.group(1)), text) if match else (10_000, text)


class _Join:
    def __init__(self, catalog: Catalog, research: ResearchRegister):
        self.catalog = catalog
        self.research = research
        self.coverage = {item.technique.id: item for item in catalog.coverage_by_technique}
        self.rules = {rule.id: rule for rule in catalog.rules}
        self.attack = {str(item.get("id")): item for item in research.attack if item.get("id")}
        self.lab = {str(item.get("id")): str(item.get("lab", "unknown")) for item in research.telemetry}

    def rules_for(self, attack_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    rule_id
                    for attack_id in attack_ids
                    for rule_id in getattr(self.coverage.get(attack_id), "rule_ids", ())
                }
            )
        )

    def telemetry_for(self, attack_ids: tuple[str, ...], extra: tuple[str, ...] = ()) -> tuple[str, ...]:
        families = set(extra)
        for attack_id in attack_ids:
            for item in self.attack.get(attack_id, {}).get("telemetry", ()) or ():
                if isinstance(item, dict) and item.get("family"):
                    families.add(str(item["family"]))
        return tuple(sorted(families))

    def telemetry_label(self, families: tuple[str, ...]) -> str:
        return (
            "<br>".join(f"{_esc(family)} ({_esc(self.lab.get(family, 'unknown'))})" for family in families)
            or "—"
        )

    def backlog_matches(self, item: dict[str, Any]) -> tuple[str, ...]:
        explicit: set[str] = set()
        for field in ("rule_id", "rule_ids", "rules"):
            explicit.update(_as_strings(item.get(field)))
        matched = {rule_id for rule_id in explicit if rule_id in self.rules}
        title = " ".join(str(item.get("title", "")).casefold().split())
        matched.update(
            rule.id
            for rule in self.catalog.rules
            if title and " ".join(rule.title.casefold().split()) == title
        )
        return tuple(sorted(matched))


def _prioritized_gaps(join: _Join) -> list[str]:
    gaps = []
    for item in join.research.attack:
        attack_id = str(item.get("id", ""))
        coverage = join.coverage.get(attack_id)
        if not item.get("priority") or coverage is None or coverage.strength is not CoverageStrength.NONE:
            continue
        gaps.append(item)
    gaps.sort(key=lambda item: (_priority(item.get("priority")), str(item.get("id", ""))))
    lines = [
        "## Prioritized technique gaps",
        "",
        "Only register priorities are shown; no priority is inferred for an unranked entry.",
        "",
        "| Priority | Technique | Name | Register disposition | Catalog | Telemetry and lab availability |",
        "|---|---|---|---|---|---|",
    ]
    for item in gaps:
        attack_ids = (str(item["id"]),)
        disposition = item.get("disposition", {}) or {}
        status = disposition.get("status", "—") if isinstance(disposition, dict) else disposition
        families = join.telemetry_for(attack_ids)
        lines.append(
            f"| {_esc(item['priority'])} | {_attack_link(attack_ids[0])} | {_esc(item.get('name', ''))} "
            f"| {_esc(status)} | not covered | {join.telemetry_label(families)} |"
        )
    return lines + [""]


def _backlog(join: _Join) -> list[str]:
    items = sorted(
        join.research.backlog,
        key=lambda item: (int(item.get("rank", 10_000)), str(item.get("id", ""))),
    )
    lines = [
        "## Backlog status",
        "",
        "Built means an explicit rule id or an exact rule title matched the active pack.",
        "",
        "| Rank | Item | Status | Matched rule(s) | Techniques | Telemetry and lab availability |",
        "|---:|---|---|---|---|---|",
    ]
    unmatched: list[dict[str, Any]] = []
    for item in items:
        attack_ids = tuple(sorted(_as_strings(item.get("techniques"))))
        matched = join.backlog_matches(item)
        status = "built" if matched else "planned"
        if not matched:
            unmatched.append(item)
        rules = "<br>".join(f"`{_esc(rule_id)}`" for rule_id in matched) or "—"
        techniques = "<br>".join(_attack_link(attack_id) for attack_id in attack_ids) or "—"
        families = join.telemetry_for(attack_ids)
        lines.append(
            f"| {_esc(item.get('rank', '—'))} | `{_esc(item.get('id', ''))}` | {status} | {rules} "
            f"| {techniques} | {join.telemetry_label(families)} |"
        )
    lines += ["", "## Unmatched backlog items", ""]
    lines += [f"- `{_esc(item.get('id', ''))}` — {_esc(item.get('title', ''))}" for item in unmatched]
    if not unmatched:
        lines.append("None.")
    return lines + [""]


def _uncovered_tools(join: _Join) -> list[str]:
    rows = []
    for item in sorted(join.research.tools, key=lambda value: str(value.get("id", ""))):
        attack_ids = tuple(sorted(_as_strings(item.get("techniques"))))
        if join.rules_for(attack_ids):
            continue
        extra = tuple(
            sorted(
                {
                    family
                    for behavior in item.get("behaviors", ()) or ()
                    for family in _as_strings(behavior.get("telemetry") if isinstance(behavior, dict) else ())
                }
            )
        )
        rows.append((item, attack_ids, join.telemetry_for(attack_ids, extra)))
    lines = [
        "## Tools with no covering rule",
        "",
        "This section is unranked because the tool register declares no priority.",
        "",
        "| Tool | Name | Techniques | Telemetry and lab availability |",
        "|---|---|---|---|",
    ]
    for item, attack_ids, families in rows:
        techniques = "<br>".join(_attack_link(attack_id) for attack_id in attack_ids) or "—"
        lines.append(
            f"| `{_esc(item.get('id', ''))}` | {_esc(item.get('name', ''))} | {techniques} "
            f"| {join.telemetry_label(families)} |"
        )
    return lines + [""]


def _uncovered_lotl(join: _Join) -> list[str]:
    rows = []
    for entry in sorted(join.research.lotl, key=lambda value: str(value.get("id", ""))):
        for pattern in entry.get("patterns", ()) or ():
            if not isinstance(pattern, dict):
                continue
            attack_ids = tuple(sorted(_as_strings(pattern.get("techniques"))))
            if not join.rules_for(attack_ids):
                rows.append((entry, pattern, attack_ids, join.telemetry_for(attack_ids)))
    rows.sort(key=lambda row: (str(row[0].get("id", "")), str(row[1].get("pattern", ""))))
    lines = [
        "## LOTL patterns with no covering rule",
        "",
        "This section is unranked because the LOTL register declares no priority.",
        "",
        "| Entry | Pattern | Techniques | Telemetry and lab availability |",
        "|---|---|---|---|",
    ]
    for entry, pattern, attack_ids, families in rows:
        techniques = "<br>".join(_attack_link(attack_id) for attack_id in attack_ids) or "—"
        lines.append(
            f"| `{_esc(entry.get('id', ''))}` | {_esc(pattern.get('pattern', ''))} | {techniques} "
            f"| {join.telemetry_label(families)} |"
        )
    return lines + [""]


def render_private(catalog: Catalog, research: ResearchRegister) -> str:
    """Render local-only gaps without feeding private data into the public matrix."""
    join = _Join(catalog, research)
    lines = [
        "# Private ATT&CK coverage gaps",
        "",
        f"Local-only join of ATT&CK Enterprise {catalog.attack_version}, ROMULUS `{catalog.pack_version}`, and the",
        "gitignored research register. Do not publish this file.",
        "",
    ]
    lines += _prioritized_gaps(join)
    lines += _backlog(join)
    lines += _uncovered_tools(join)
    lines += _uncovered_lotl(join)
    return "\n".join(lines).rstrip() + "\n"
