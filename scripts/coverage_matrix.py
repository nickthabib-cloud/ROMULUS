"""Generate or check the public ATT&CK coverage matrix."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from romulus.catalog import build_catalog
from romulus.catalog.render import render_public

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_OUTPUT = ROOT / "docs" / "detection" / "ATTACK_COVERAGE.md"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="exit non-zero if the generated document is stale"
    )
    parser.add_argument("--output", type=Path, default=PUBLIC_OUTPUT, help=argparse.SUPPRESS)
    return parser


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expected = render_public(build_catalog())
    output = args.output.resolve()
    if args.check:
        current = output.read_bytes() if output.exists() else b""
        if current != expected.encode("utf-8"):
            print(f"coverage matrix is stale: run `python scripts/coverage_matrix.py` ({output})")
            return 1
        print(f"coverage matrix is current: {output}")
        return 0
    _write(output, expected)
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
