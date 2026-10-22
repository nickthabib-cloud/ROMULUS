"""Production code explains behavior without depending on private decision-record identifiers."""

from pathlib import Path


def test_production_code_does_not_reference_private_windows_decision_records():
    source_root = Path(__file__).parents[1] / "src"
    banned = ("ADR" + "-010", "ADR" + " 010", "windows-negatives-under-attestation")
    offenders = []
    for path in source_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(value in text for value in banned):
            offenders.append(path.relative_to(source_root).as_posix())
    assert offenders == []

