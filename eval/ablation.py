"""Model-on vs model-off ablation table (PROTOCOL §8 item 10) from two scored runs.

Usage (VM; reads the private per-opportunity outputs, writes aggregate Markdown only):
    python -m eval.ablation --gold DIR --off OFF.json --off-private OFF.private.json
        --on ON.json --on-private ON.private.json [--out-md FILE]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval import gold as gold_mod
from eval.report import ablation, agent_section, leak_check


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval.ablation")
    for k in ("--gold", "--off", "--off-private", "--on", "--on-private"):
        ap.add_argument(k, required=True)
    ap.add_argument("--out-md")
    a = ap.parse_args(argv)
    g = gold_mod.load(a.gold)
    off, on, offp, onp = (json.loads(Path(p).read_text(encoding="utf-8"))
                          for p in (a.off, a.on, a.off_private, a.on_private))
    if off["gold"]["files_sha256"] != on["gold"]["files_sha256"]:
        raise SystemExit("refusing to compare runs scored against different gold versions")
    classes = {o.opp_id: o.behavior_class for o in g.opportunities.values()}
    md = "\n".join([ablation(off, on, offp, onp, classes), ""] + agent_section(on.get("agent")))
    leak_check(md, g.forbidden_strings())
    if a.out_md:
        Path(a.out_md).write_text(md + "\n", encoding="utf-8", newline="\n")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
