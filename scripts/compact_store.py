"""Rebuild a legacy ROMULUS database without LangGraph checkpoint history.

Run only while no hunt is active. Durable investigation records, unique
evidence, and findings are preserved. Graph context in investigation state is
bounded and normalized; legacy checkpoint/writes tables are intentionally not
copied because current releases keep them in data/checkpoints.sqlite3.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3

from romulus.config import Settings
from romulus.investigation.workflow import _context_raw


SCHEMA = """
CREATE TABLE investigations(id TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE evidence(id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, item TEXT NOT NULL);
CREATE TABLE findings(id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, item TEXT NOT NULL);
"""


def _compact_event(item: dict) -> dict:
    return {
        "evidence_id": item.get("evidence_id"),
        "source": item.get("source"),
        "observed_at": item.get("observed_at", ""),
        "observation": str(item.get("observation", ""))[:1200],
        "asset": str(item.get("asset", ""))[:300],
        "provenance": item.get("provenance", {}) if isinstance(item.get("provenance"), dict) else {},
        "raw": _context_raw(item.get("raw", {})),
    }


def _compact_state(state: dict, per_source: int) -> dict:
    referenced={
        evidence_id
        for finding in state.get("findings", []) if isinstance(finding, dict)
        for evidence_id in finding.get("evidence_ids", []) if isinstance(evidence_id, str)
    }
    counts: dict[str, int] = {}
    original={"host":len(state.get("host", [])),"network":len(state.get("network", []))}
    for collection in ("host", "network"):
        retained=[]
        for item in state.get(collection, []):
            if not isinstance(item, dict): continue
            provenance=item.get("provenance", {}) if isinstance(item.get("provenance"), dict) else {}
            phase="pivot" if provenance.get("lead_id") else "baseline"
            bucket=f"{item.get('source','unknown')}:{phase}"
            required=item.get("evidence_id") in referenced
            if not required and counts.get(bucket, 0) >= per_source: continue
            counts[bucket]=counts.get(bucket, 0)+1
            retained.append(_compact_event(item))
        state[collection]=retained
    state["evidence"]=[]
    state.setdefault("coverage", {})["store_compaction"]={
        "original_context":original,
        "retained_context":{"host":len(state.get("host", [])),"network":len(state.get("network", []))},
        "per_source_phase_limit":per_source,
        "durable_evidence_table_preserved":True,
    }
    return state


def compact(data_dir: Path, per_source: int, keep_backup: bool) -> tuple[int, int]:
    data_dir=data_dir.expanduser().resolve()
    source=data_dir / "romulus.sqlite3"
    temporary=data_dir / "romulus.sqlite3.compact.tmp"
    backup=data_dir / "romulus.sqlite3.precompact"
    if not source.is_file(): raise FileNotFoundError(source)
    for stale in (temporary, backup):
        if stale.exists(): stale.unlink()

    with sqlite3.connect(source, timeout=60) as old:
        old.execute("PRAGMA busy_timeout=60000")
        old.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        expected={table:int(old.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                  for table in ("investigations", "evidence", "findings")}
        states=list(old.execute("SELECT id,state,updated_at FROM investigations"))

    with sqlite3.connect(temporary, timeout=60) as new:
        new.executescript(SCHEMA)
        new.execute("ATTACH DATABASE ? AS legacy",(str(source),))
        new.execute("INSERT INTO evidence SELECT id,investigation_id,item FROM legacy.evidence")
        new.execute("INSERT INTO findings SELECT id,investigation_id,item FROM legacy.findings")
        for hunt_id, encoded, updated_at in states:
            state=_compact_state(json.loads(encoded), per_source)
            new.execute("INSERT INTO investigations VALUES(?,?,?)",(hunt_id,json.dumps(state),updated_at))
        new.commit()
        actual={table:int(new.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("investigations", "evidence", "findings")}
        integrity=str(new.execute("PRAGMA integrity_check").fetchone()[0])
        if actual != expected or integrity.lower() != "ok":
            raise RuntimeError(f"Compaction verification failed: expected={expected}, actual={actual}, integrity={integrity}")

    before=source.stat().st_size
    os.replace(source, backup)
    try:
        os.replace(temporary, source)
    except Exception:
        os.replace(backup, source)
        raise
    after=source.stat().st_size
    for suffix in ("-wal", "-shm"):
        sidecar=Path(str(backup)+suffix)
        if sidecar.exists(): sidecar.unlink()
    if not keep_backup: backup.unlink()
    return before, after


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Settings.from_env().data_dir)
    parser.add_argument("--context-per-source", type=int, default=1000)
    parser.add_argument("--keep-backup", action="store_true")
    args=parser.parse_args()
    limit=max(100,min(args.context_per_source,5000))
    before,after=compact(args.data_dir,limit,args.keep_backup)
    print(f"Compacted {before:,} bytes to {after:,} bytes; reclaimed {before-after:,} bytes")


if __name__ == "__main__":
    main()
