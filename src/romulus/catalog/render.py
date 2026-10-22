"""Human-readable rendering for the public ATT&CK coverage catalog."""

from __future__ import annotations

import re
from collections import defaultdict

from .build import strength_for_rule
from .models import (
    COVERAGE_STRENGTH_LEGEND,
    TECHNIQUE_STRENGTH_POLICY,
    Catalog,
    CoverageStrength,
    RuleMetadata,
    TechniqueCoverage,
)


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _technique_link(attack_id: str) -> str:
    path = attack_id.replace(".", "/")
    return f"[`{attack_id}`](https://attack.mitre.org/techniques/{path}/)"


def _rule_link(rule_id: str) -> str:
    return f"[{_esc(rule_id)}](#rule-{_slug(rule_id)})"


def _join(values: tuple[str, ...] | list[str]) -> str:
    return "<br>".join(_esc(value) for value in values) if values else "—"


def _rule_links(rule_ids: tuple[str, ...], catalog: Catalog) -> str:
    return (
        "<br>".join(
            f"{_rule_link(rule_id)} ({strength_for_rule(catalog.rule(rule_id)).value})"
            for rule_id in rule_ids
        )
        if rule_ids
        else "—"
    )


def _strength_legend() -> list[str]:
    lines = ["## Strength legend", ""]
    lines.extend(
        f"- **{strength.value}** — {_esc(description)}"
        for strength, description in COVERAGE_STRENGTH_LEGEND
    )
    lines += [
        "",
        TECHNIQUE_STRENGTH_POLICY,
        (
            "Each row therefore shows the strongest covering rule's strength; the covering-rules "
            "cell shows every rule's own strength."
        ),
        "",
    ]
    return lines


def _summary(catalog: Catalog) -> list[str]:
    lines = [
        "## Coverage summary",
        "",
        "Counts include active parent techniques and sub-techniques in every tactic where ATT&CK places them.",
        "A technique is covered only by a rule that explicitly declares that ATT&CK id.",
        "",
        "| Tactic | Name | Covered / total | Negative-capable | Positive-only | Context-only | Not covered |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for rollup in catalog.tactic_rollups:
        counts = rollup.strength_counts
        uncovered = counts[CoverageStrength.NONE]
        lines.append(
            f"| {rollup.tactic.id} | {_esc(rollup.tactic.name)} | {rollup.total - uncovered} / {rollup.total} "
            f"| {counts[CoverageStrength.NEGATIVE_CAPABLE]} | {counts[CoverageStrength.POSITIVE_ONLY]} "
            f"| {counts[CoverageStrength.CONTEXT_ONLY]} | {uncovered} |"
        )
    return lines + [""]


def _subtechnique_cell(
    children: list[TechniqueCoverage],
) -> str:
    collapsed = [item for item in children if item.strength is CoverageStrength.NONE]
    separate = [item for item in children if item.strength is not CoverageStrength.NONE]
    parts: list[str] = []
    if collapsed:
        parts.append(
            "<br>".join(
                f"{_technique_link(item.technique.id)} {_esc(item.technique.name)} — not covered"
                for item in collapsed
            )
        )
    if separate:
        links = ", ".join(_technique_link(item.technique.id) for item in separate)
        parts.append(f"{len(separate)} covered sub-technique(s) listed separately: {links}")
    return "<br>".join(parts) if parts else "—"


def _technique_row(item: TechniqueCoverage, subtechniques: str, catalog: Catalog) -> str:
    return (
        f"| {_technique_link(item.technique.id)} | {_esc(item.technique.name)} | {subtechniques} "
        f"| {item.strength.value} | {_rule_links(item.rule_ids, catalog)} | {_join(item.telemetry_families)} |"
    )


def _tactic_tables(catalog: Catalog) -> list[str]:
    children: dict[str, list[TechniqueCoverage]] = defaultdict(list)
    for item in catalog.coverage_by_technique:
        if item.technique.parent_id:
            children[item.technique.parent_id].append(item)
    for group in children.values():
        group.sort(key=lambda item: item.technique.id)

    lines = ["## Techniques by tactic", ""]
    for rollup in catalog.tactic_rollups:
        tactic = rollup.tactic
        lines += [
            f"### {tactic.id} — {_esc(tactic.name)}",
            "",
            "| Technique | Name | Sub-techniques | Strength | Covering rules | Telemetry families |",
            "|---|---|---|---|---|---|",
        ]
        parents = [
            item
            for item in catalog.coverage_by_technique
            if not item.technique.is_subtechnique and tactic.shortname in item.technique.tactics
        ]
        for parent in parents:
            in_tactic = [
                item
                for item in children.get(parent.technique.id, ())
                if tactic.shortname in item.technique.tactics
            ]
            lines.append(_technique_row(parent, _subtechnique_cell(in_tactic), catalog))
            for child in in_tactic:
                if child.strength is not CoverageStrength.NONE:
                    lines.append(
                        _technique_row(
                            child,
                            f"sub-technique of {_technique_link(parent.technique.id)}",
                            catalog,
                        )
                    )
        lines.append("")
    return lines


def _metadata_issues(catalog: Catalog) -> list[str]:
    lines = ["## Metadata validation", ""]
    if catalog.missing_attack_ids:
        lines += [
            "Active rules without an ATT&CK mapping or an explicit exemption:",
            "",
            *[f"- `{rule_id}`" for rule_id in catalog.missing_attack_ids],
            "",
        ]
    else:
        lines += ["All active rules declare an ATT&CK mapping or an explicit exemption.", ""]
    if catalog.invalid_attack_ids:
        lines += [
            "Invalid mappings are excluded from coverage:",
            "",
            *[
                f"- `{issue.rule_id}` → `{issue.attack_id}` ({issue.reason}"
                f"{' → use `' + issue.replacement_id + '`' if issue.replacement_id else ''})"
                for issue in catalog.invalid_attack_ids
            ],
            "",
        ]
    else:
        lines += ["All declared ATT&CK ids are active in the vendored Enterprise bundle.", ""]
    return lines


def _rule_card(rule: RuleMetadata) -> list[str]:
    attack = ", ".join(_technique_link(attack_id) for attack_id in rule.attack_ids) or "—"
    strength = strength_for_rule(rule)
    lines = [
        f'<a id="rule-{_slug(rule.id)}"></a>',
        f"### `{_esc(rule.id)}` — {_esc(rule.title)}",
        "",
        f"- Version: `{_esc(rule.version)}`; status: `{_esc(rule.status)}`",
        f"- Kind: `{_esc(rule.kind)}`; lane: `{_esc(rule.lane)}`; severity: `{_esc(rule.severity)}`",
        f"- Coverage strength: **{strength.value}**",
        f"- ATT&CK: {attack}",
        f"- Telemetry families: {_join(rule.families)}",
        f"- Required typed fields: {_join(rule.required_fields)}",
    ]
    if rule.required_by_family:
        by_family = "; ".join(
            f"`{_esc(family)}`: {_join(fields)}"
            for family, fields in rule.required_by_family.items()
        )
        lines.append(f"- Required typed fields by family: {by_family}")
    if rule.behavior:
        lines.append(f"- Behavior: {_esc(rule.behavior)}")
    if rule.positive_only_reason:
        lines.append(f"- Positive-only reason: {_esc(rule.positive_only_reason)}")
    return lines + [""]


def render_public(catalog: Catalog) -> str:
    """Render the complete public matrix without consulting private research data."""
    collapsed = sum(
        item.technique.is_subtechnique and item.strength is CoverageStrength.NONE
        for item in catalog.coverage_by_technique
    )
    lines = [
        "# ATT&CK Enterprise detection coverage",
        "",
        f"Generated from vendored ATT&CK Enterprise {catalog.attack_version} and ROMULUS `{catalog.pack_version}`.",
        "This file is generated by `python scripts/coverage_matrix.py`; do not edit it by hand.",
        "",
        "Coverage is based only on explicit typed rule metadata. Parent mappings do not imply sub-technique coverage.",
        "Negative-capable rules can support a complete negative only when their runtime coverage is complete; the",
        "matrix describes rule capability, not the completeness of any hunt.",
        "",
        f"To keep the matrix readable, {collapsed} uncovered sub-techniques are collapsed under their parent rows.",
        "Every collapsed id and name remains listed and is marked not covered.",
        "",
    ]
    lines += _strength_legend()
    lines += _summary(catalog)
    lines += _tactic_tables(catalog)
    lines += _metadata_issues(catalog)
    lines += ["## Rule card summaries", ""]
    for rule in catalog.rules:
        lines += _rule_card(rule)
    return "\n".join(lines).rstrip() + "\n"
