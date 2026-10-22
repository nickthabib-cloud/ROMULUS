"""Private research-register coverage gap generation contracts."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "coverage_matrix.py"
PRIVATE_DOC = Path("docs/project/COVERAGE_GAPS.md")


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


def _research_fixture(root: Path) -> None:
    (root / "attack" / "enterprise").mkdir(parents=True)
    (root / "backlog.yaml").write_text(
        """schema_version: 1
backlog:
  - id: BL-01
    rank: 1
    title: Password guessing rule
    rule_id: host.ssh_password_guessing
    techniques: [T1110.001]
  - id: BL-02
    rank: 2
    title: Pipeline poisoning
    techniques: [T1677]
next_candidates: []
v1_ports: []
""",
        encoding="utf-8",
        newline="",
    )
    (root / "tools.yaml").write_text(
        """schema_version: 1
tools:
  - id: tool.example
    name: Example Builder
    techniques: [T1677]
    behaviors:
      - telemetry: [win_security]
    leads: []
""",
        encoding="utf-8",
        newline="",
    )
    (root / "lotl_linux.yaml").write_text(
        """schema_version: 1
binaries:
  - id: lotl.example
    binaries: [builder]
    patterns:
      - pattern: Poison a build pipeline
        techniques: [T1677]
        signals: [lineage]
""",
        encoding="utf-8",
        newline="",
    )
    (root / "telemetry_families.yaml").write_text(
        """schema_version: 1
families:
  - id: auth
    title: Authentication
    lab: present
  - id: win_security
    title: Windows Security log
    lab: absent
""",
        encoding="utf-8",
        newline="",
    )
    (root / "attack" / "enterprise" / "04-execution.yaml").write_text(
        """attack_version: 20.0
primary_tactic: execution
entries:
  - id: T1677
    name: Poisoned Pipeline Execution
    tactics: [execution]
    telemetry:
      - family: win_security
        fields: [process.command_line]
    rules: []
    disposition: {status: planned, reason: needs a rule}
    priority: P1
  - id: T1110.001
    name: Password Guessing
    tactics: [credential-access]
    telemetry:
      - family: auth
        fields: [source.ip]
    rules: [host.ssh_password_guessing]
    disposition: {status: covered, reason: implemented}
    priority: P2
""",
        encoding="utf-8",
        newline="",
    )


def test_private_output_path_is_ignored_and_not_tracked():
    ignored = subprocess.run(["git", "check-ignore", "-q", PRIVATE_DOC.as_posix()], cwd=ROOT, check=False)
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", PRIVATE_DOC.as_posix()],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert ignored.returncode == 0
    assert tracked.returncode != 0


def test_private_generator_joins_ranked_gaps_backlog_tools_lotl_and_lab_state(tmp_path):
    research = tmp_path / "research"
    output = tmp_path / "COVERAGE_GAPS.md"
    _research_fixture(research)

    result = _run_generator("--private", "--research-root", str(research), "--output", str(output))
    assert result.returncode == 0, result.stdout + result.stderr
    text = output.read_text(encoding="utf-8")
    assert "# Private ATT&CK coverage gaps" in text
    assert "| P1 | [`T1677`]" in text
    assert "| planned | not covered | win_security (absent) |" in text
    assert "| 1 | `BL-01` | built | `host.ssh_password_guessing` |" in text
    assert "| 2 | `BL-02` | planned | — |" in text
    assert "## Unmatched backlog items" in text and "`BL-02` — Pipeline poisoning" in text
    assert "## Tools with no covering rule" in text and "`tool.example`" in text
    assert "## LOTL patterns with no covering rule" in text and "Poison a build pipeline" in text
    assert "win_security (absent)" in text


def test_private_generator_is_byte_stable_and_has_a_check_gate(tmp_path):
    research = tmp_path / "research"
    output = tmp_path / "COVERAGE_GAPS.md"
    _research_fixture(research)
    args = ("--private", "--research-root", str(research), "--output", str(output))

    assert _run_generator(*args).returncode == 0
    first = output.read_bytes()
    assert b"\r\n" not in first
    assert _run_generator(*args).returncode == 0
    assert output.read_bytes() == first
    assert _run_generator("--check", *args).returncode == 0
