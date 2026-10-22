"""Generate or check the public ATT&CK coverage matrix."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from romulus.catalog import build_catalog
from romulus.catalog.render import render_public

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_OUTPUT = ROOT / "docs" / "detection" / "ATTACK_COVERAGE.md"
PRIVATE_OUTPUT = ROOT / "docs" / "project" / "COVERAGE_GAPS.md"
PRIVATE_RESEARCH = ROOT / "content" / "research"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="exit non-zero if the generated document is stale"
    )
    parser.add_argument("--private", action="store_true", help="generate the local research gap register")
    parser.add_argument("--output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--research-root", type=Path, default=PRIVATE_RESEARCH, help=argparse.SUPPRESS)
    return parser


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    catalog = build_catalog()
    if args.private:
        from coverage_research import load_research, render_private

        expected = render_private(catalog, load_research(args.research_root.resolve()))
        output = (args.output or PRIVATE_OUTPUT).resolve()
    else:
        expected = render_public(catalog)
        output = (args.output or PUBLIC_OUTPUT).resolve()
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
