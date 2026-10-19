"""Agent-mode ablation table (PROTOCOL §8 item 10) from scored runs.

Usage (VM; reads the private per-opportunity outputs, writes aggregate Markdown only):
    python -m eval.ablation --gold DIR --off OFF.json --off-private OFF.private.json
        --on ON.json --on-private ON.private.json [--out-md FILE]
    python -m eval.ablation --gold DIR --run LABEL RESULT.json PRIVATE.json [--run ...] [--out-md FILE]
        (N-way: the first --run is the base; deltas and only-in sets are against it)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval import gold as gold_mod
from eval.report import ablation, ablation_n, agent_section, leak_check


def _load(p: str) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval.ablation")
    ap.add_argument("--gold", required=True)
    for k in ("--off", "--off-private", "--on", "--on-private"):
        ap.add_argument(k)
    ap.add_argument("--run", nargs=3, action="append", metavar=("LABEL", "RESULT", "PRIVATE"))
    ap.add_argument("--out-md")
    a = ap.parse_args(argv)
    g = gold_mod.load(a.gold)
    classes = {o.opp_id: o.behavior_class for o in g.opportunities.values()}
    if a.run:
        runs = [(lab, _load(r), _load(p)) for lab, r, p in a.run]
        if len({json.dumps(r["gold"]["files_sha256"], sort_keys=True) for _, r, _ in runs}) != 1:
            raise SystemExit("refusing to compare runs scored against different gold versions")
        parts = [ablation_n(runs[0], runs[1:], classes), ""]
        for lab, r, _ in runs[1:]:
            parts += [f"## Agent effectiveness: {lab}", ""] + agent_section(r.get("agent"))[1:]
        md = "\n".join(parts)
    else:
        off, on, offp, onp = (_load(p) for p in (a.off, a.on, a.off_private, a.on_private))
        if off["gold"]["files_sha256"] != on["gold"]["files_sha256"]:
            raise SystemExit("refusing to compare runs scored against different gold versions")
        md = "\n".join([ablation(off, on, offp, onp, classes), ""] + agent_section(on.get("agent")))
    leak_check(md, g.forbidden_strings())
    if a.out_md:
        Path(a.out_md).write_text(md + "\n", encoding="utf-8", newline="\n")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
