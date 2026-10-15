#!/usr/bin/env python3
"""Build concise operator documents from authoritative intelligence inputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = Path("docs/research/indicator-priority-inventory.md")
PRIORITY_ORDER = ("critical", "high", "medium", "low")


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _status_indexes(root: Path) -> tuple[dict[str, tuple[str, dict[str, Any]]], dict[str, Any]]:
    pack_dir = root / "romulus/intelligence/behavior_packs"
    manifest = _read(pack_dir / "manifest.json")
    records: dict[str, tuple[str, dict[str, Any]]] = {}
    for pack_name in ("direct", "sequences", "aggregates", "baselines"):
        for row in _read(pack_dir / f"{pack_name}.json")["records"]:
            records[str(row["id"])] = (pack_name, row)
    return records, manifest


def _runtime_label(pack_name: str, row: dict[str, Any]) -> str:
    if pack_name == "direct":
        return "active direct rule" if row.get("activation_mode") == "active" else "observe-only direct rule"
    execution = row.get("execution") if isinstance(row.get("execution"), dict) else {}
    if execution.get("status") == "executable":
        primitive = execution.get("primitive") or execution.get("execution_kind") or pack_name.rstrip("s")
        return f"executable {pack_name.rstrip('s')} ({str(primitive).replace('_', ' ')})"
    return f"reference only ({execution.get('reason_code', 'missing executable semantics').replace('_', ' ')})"


def build_priority_inventory(root: Path = ROOT) -> str:
    corpus = _read(root / "docs/research/common-indicator-corpus.json")
    index, manifest = _status_indexes(root)
    rows = [row for row in corpus["entries"] if row.get("record_type") == "curated_behavioral_indicator"]
    execution = manifest["execution_states"]
    activation = manifest["curated_activation"]
    lines = [
        "# ROMULUS Intelligence Priority Inventory",
        "",
        "**Generated from the authoritative corpus and behavior packs on 2026-10-15.**",
        "",
        "This is the plain-language list of all 902 curated behaviors. It omits query JSON and predicate details. "
        "Research priority says how quickly a matching behavior deserves review; runtime status says how ROMULUS currently uses it.",
        "",
        "## Runtime summary",
        "",
        f"- {execution['curated_executable']} executable curated behaviors: "
        f"{activation['active']} active and {activation['observe']} observe only.",
        f"- {execution['curated_reference_only']} reference only curated behaviors with a named missing-semantics reason.",
        f"- {execution['capability_references']} capability references provide bounded context and never create or score findings.",
        "- ATT&CK references provide planning and mapping context and never count as observed behavior.",
        "- Loaded, executable, executed, matched, partial, and reference only are separate states. A live hunt reports actual execution and source completeness.",
        "",
        "## Status terms",
        "",
        "- **Active:** executable and eligible for normal candidate priority.",
        "- **Observe only:** executable with a score ceiling; it cannot become customer visible by itself.",
        "- **Executable sequence or aggregate:** evaluated against complete normalized evidence with its declared joins or thresholds.",
        "- **Executable baseline:** evaluated after warm up against history learned only from completed hunts.",
        "- **Reference only:** retained research that lacks enough exact semantics to run safely.",
        "",
        "## All curated behaviors",
        "",
    ]
    for priority in PRIORITY_ORDER:
        selected = [row for row in rows if row.get("priority") == priority]
        lines.extend([f"### {priority.title()} priority ({len(selected)})", ""])
        domains = sorted({str(row.get("domain") or "other") for row in selected})
        for domain in domains:
            domain_rows = sorted((row for row in selected if str(row.get("domain") or "other") == domain),
                                 key=lambda row: str(row["id"]))
            lines.extend([f"#### {domain}", ""])
            for row in domain_rows:
                pack_name, runtime = index[str(row["id"])]
                lines.append(f"- `{row['id']}` {row['title']} — {priority}; {_runtime_label(pack_name, runtime)}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / INVENTORY_PATH
    content = build_priority_inventory(ROOT)
    if args.write:
        target.write_text(content, encoding="utf-8", newline="\n")
        print(json.dumps({"status": "written", "path": str(target), "curated_behaviors": 902}, indent=2))
        return 0
    if not target.is_file() or target.read_text(encoding="utf-8") != content:
        parser.error(f"{target}: generated contents differ; run with --write")
    print(json.dumps({"status": "matches", "path": str(target), "curated_behaviors": 902}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
