"""Generated public ATT&CK coverage matrix contracts."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from romulus.catalog import CoverageStrength, build_catalog
from romulus.catalog.render import render_public

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "coverage_matrix.py"
PUBLIC_DOC = ROOT / "docs" / "detection" / "ATTACK_COVERAGE.md"


def _run_generator(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_public_matrix_contains_versions_tactic_rollups_and_rule_card_links():
    catalog = build_catalog()
    text = render_public(catalog)

    from romulus.detect.registry import PACK_VERSION

    assert "ATT&CK Enterprise 20.0" in text
    assert f"ROMULUS `{PACK_VERSION}`" in text
    for rollup in catalog.tactic_rollups:
        assert f"| {rollup.tactic.id} | {rollup.tactic.name} |" in text
    assert "[host.ssh_password_guessing](#rule-host-ssh-password-guessing)" in text
    assert '<a id="rule-host-ssh-password-guessing"></a>' in text
    assert "## Rule card summaries" in text
    assert "| Context-only | Not covered |" in text
    assert "Lead-capped" not in text
    fingerprint_card = text.split(
        "### `net.rare_client_fingerprint`", maxsplit=1
    )[1].split("\n### `", maxsplit=1)[0]
    assert "Coverage strength: **context-only**" in fingerprint_card


def test_public_matrix_explains_strength_and_labels_each_covering_rule():
    text = render_public(build_catalog())

    assert "## Strength legend" in text
    assert "record every occurrence it looks for" in text
    assert "never that the ATT&CK technique is absent" in text
    assert (
        "A covering rule provides investigation context around other findings."
        in text
    )
    assert "strongest covering rule's strength" in text
    assert (
        "[net.rare_client_fingerprint](#rule-net-rare-client-fingerprint) (context-only)"
        in text
    )


def test_public_matrix_explains_non_enterprise_and_replaced_attack_ids():
    text = render_public(build_catalog())

    assert "`T0815` (ATT&CK for ICS id (not in the Enterprise bundle))" in text
    assert "`T1562.004` (revoked → use `T1686`)" in text


def test_public_matrix_keeps_every_active_technique_visible_when_subtechniques_collapse():
    catalog = build_catalog()
    text = render_public(catalog)
    collapsed = [
        item
        for item in catalog.coverage_by_technique
        if item.technique.is_subtechnique and item.strength is CoverageStrength.NONE
    ]

    assert f"{len(collapsed)} uncovered sub-techniques are collapsed" in text
    assert all(f"`{item.technique.id}`" in text for item in catalog.coverage_by_technique)
    assert "— not covered" in text
    assert re.search(r"\| none \| — \| — \|", text)


def test_public_matrix_excludes_private_register_and_lab_history_language():
    text = render_public(build_catalog())
    forbidden = (
        "content/research",
        "BX-PRIVATE",
        "lab profile",
        "lab availability",
        "milestone",
        "private run marker",
    )
    assert all(value not in text for value in forbidden)


def test_generator_writes_lf_bytes_and_check_detects_staleness(tmp_path):
    output = tmp_path / "ATTACK_COVERAGE.md"

    stale = _run_generator("--check", "--output", str(output))
    assert stale.returncode == 1
    assert "stale" in stale.stdout

    written = _run_generator("--output", str(output))
    assert written.returncode == 0
    first = output.read_bytes()
    assert first == render_public(build_catalog()).encode("utf-8")
    assert b"\r\n" not in first

    again = _run_generator("--output", str(output))
    assert again.returncode == 0
    assert output.read_bytes() == first
    current = _run_generator("--check", "--output", str(output))
    assert current.returncode == 0


def test_tracked_public_matrix_is_current():
    result = _run_generator("--check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert PUBLIC_DOC.read_text(encoding="utf-8") == render_public(build_catalog())
