"""Side-by-side table for two aggregate results (model-on vs model-off, or run-to-run).

Usage: python -m eval.compare A.json B.json --labels "model-on" "model-off"
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval.report import compare


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval.compare")
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--labels", nargs=2, default=("A", "B"))
    x = ap.parse_args(argv)
    a, b = (json.loads(Path(p).read_text(encoding="utf-8")) for p in (x.a, x.b))
    print(compare(a, b, *x.labels))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
