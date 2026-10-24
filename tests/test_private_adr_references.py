"""Tracked public files explain behavior without depending on private decision-record identifiers."""

import re
import subprocess
from pathlib import Path

PRIVATE_REFERENCE = re.compile(
    r"(?:"
    r"\bdocs[\\/]+adr[\\/]"
    r"|\bADR(?:[-_ ]?\d{1,3}|[-_ ][a-z][a-z0-9_-]*)\b"
    r"|\b(?:CLAUDE|ENGINEERING[_ -]MASTER[_ -]PROMPT|STATUS|TEAM|MILESTONES)\.md\b"
    r"|\bm\d+[\\/][a-z][a-z0-9-]*\b"
    r"|\b(?:thin[-_ ]slice|windows[-_ ]w\d+)\b"
    r"|\b(?:bounded[-_ ]state|site[-_ ]networks)[-_ ](?:branch|slice)\b"
    r"|\bwindows[-_ ]negatives[-_ ]under[-_ ]attestation\b"
    r")",
    re.IGNORECASE,
)


def test_private_reference_pattern_covers_paths_ids_design_notes_and_slice_names():
    samples = (
        "docs/adr/ADR-12-example.md",
        "ADR7",
        "ENGINEERING_MASTER_PROMPT.md",
        "docs/project/MILESTONES.md",
        "m1/thin-slice",
        "Windows W0",
        "the bounded-state branch",
        "the site-networks slice",
    )

    assert all(PRIVATE_REFERENCE.search(sample) for sample in samples)
    private_slug = "-".join(("windows", "negatives", "under", "attestation"))  # noqa: FLY002
    assert private_slug not in Path(__file__).read_text(encoding="utf-8")


def test_tracked_public_files_do_not_reference_private_decision_records():
    root = Path(__file__).parents[1]
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True,
    ).stdout.decode().split("\0")
    offenders = []
    for relative in tracked:
        if not relative or relative in {".gitignore", "tests/test_private_adr_references.py"}:
            continue
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if PRIVATE_REFERENCE.search(text):
            offenders.append(relative)
    assert offenders == []
