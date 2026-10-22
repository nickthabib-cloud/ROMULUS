"""Tracked public files explain behavior without depending on private decision-record identifiers."""

import re
import subprocess
from pathlib import Path


def test_tracked_public_files_do_not_reference_private_decision_records():
    root = Path(__file__).parents[1]
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True,
    ).stdout.decode().split("\0")
    pattern = re.compile(
        r"\b(?:ADR(?:[-_ ]?\d{3}|[-_ ][a-z])|windows-negatives-under-attestation)",
        re.IGNORECASE,
    )
    offenders = []
    for relative in tracked:
        if not relative or relative == "tests/test_private_adr_references.py":
            continue
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(text):
            offenders.append(relative)
    assert offenders == []
