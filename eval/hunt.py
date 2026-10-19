"""Read-only access to a ROMULUS hunt database (SQLite opened with a ``mode=ro`` URI).

The scorer never writes to the hunt store. Rows are returned as plain dicts with JSON columns decoded and
timestamps parsed as UTC.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from eval.gold import locator_key, norm_entity, parse_ts
from romulus.store.repo import raw_id

LANE_ORDER = {"urgent": 0, "urgent validation": 0, "high": 1, "lead": 2, "context": 3, "suppressed": 4, "benign": 4}
REPORTED_LANES = frozenset({"urgent", "urgent validation", "high"})
SURFACED_LANES = REPORTED_LANES | {"lead"}
MENTIONED_LANES = frozenset({"context"})


def connect_ro(db_path: str | Path) -> sqlite3.Connection:
    p = Path(db_path).resolve()
    if not p.exists():
        raise FileNotFoundError(p)
    conn = sqlite3.connect(f"{p.as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _j(v):
    if v is None or isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (TypeError, json.JSONDecodeError):
        return v


def _dt(v) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    return parse_ts(str(v))


@dataclass
class Item:
    """One ROMULUS candidate as the analyst would see it, with resolved raw locators."""
    id: str
    lane: str
    rule_id: str
    rule_version: str
    priority: float
    severity: str
    claim_type: str
    observed_at: datetime | None
    created_at: datetime | None
    source_case_id: str | None
    entities: set[str]
    locators: list[dict]                 # {key, target, native_id, digest, retained, digest_ok, family}
    t_min: datetime | None
    t_max: datetime | None
    predicate_fields: list
    event_fields: list[dict]             # typed-event field maps (for citation field checks)
    missing_events: int = 0

    @property
    def keys(self) -> set[tuple]:
        return {c["key"] for c in self.locators if c["key"] is not None}

    @property
    def review_sort(self):
        return (LANE_ORDER.get(self.lane, 9), -self.priority, str(self.observed_at))


@dataclass
class Hunt:
    id: str
    manifest: dict
    started_at: datetime | None
    ended_at: datetime | None
    execution_state: str
    detection_result: str | None
    items: list[Item]
    tasks: list[dict]
    rule_cells: list[dict]
    audit: list[dict]
    model_calls: list[dict]
    cases: list[dict]
    report_order: list[str] | None
    report_coverage: list[dict] | None = None
    gaps: list[str] = field(default_factory=list)  # product data the scorer needed but did not find


def target_to_key(target: str, native_id: str) -> tuple | None:
    """Map a stored raw reference to a gold locator key.

    ES: target is the index name and native_id the document _id. Arkime and PCAP adapters do not exist
    yet (M3); the assumed forms 'arkime[:node]' / 'pcap:<sha256-or-basename>' must be re-checked when they land.
    """
    if target.startswith("arkime"):
        return locator_key("arkime", native_id)
    if target.startswith("pcap:"):
        try:
            return locator_key("pcap", target.split(":", 1)[1], int(native_id))
        except ValueError:
            return None
    return locator_key("es", target, native_id)


def _interval_values(fields: dict) -> list[datetime]:
    out = []
    for k in ("flow.start", "flow.end"):
        v = (fields.get(k) or {}).get("value") if isinstance(fields.get(k), dict) else None
        d = _dt(v) if v else None
        if d:
            out.append(d)
    return out


def load_hunt(conn: sqlite3.Connection, hunt_id: str) -> Hunt:
    h = conn.execute("SELECT * FROM hunt WHERE id = ?", (hunt_id,)).fetchone()
    if h is None:
        raise KeyError(f"hunt {hunt_id} not found")
    gaps: list[str] = []
    cands = [dict(r) for r in conn.execute("SELECT * FROM candidate WHERE hunt_id = ?", (hunt_id,))]
    ev_ids = sorted({e for c in cands for e in (_j(c["event_ids"]) or [])})
    events: dict[str, dict] = {}
    for i in range(0, len(ev_ids), 500):
        chunk = ev_ids[i:i + 500]
        q = f"SELECT id, family, ts, host, event, raw_ids FROM typed_event WHERE id IN ({','.join('?' * len(chunk))})"
        for r in conn.execute(q, chunk):
            events[r["id"]] = {"family": r["family"], "ts": _dt(r["ts"]), "host": r["host"], "event": _j(r["event"]),
                               "raw_ids": _j(r["raw_ids"])}
    raw_ids = sorted({rid for e in events.values() for rid in (e["raw_ids"] or [])})
    raws: dict[str, dict] = {}
    for i in range(0, len(raw_ids), 500):
        chunk = raw_ids[i:i + 500]
        q = f"SELECT id, target, native_id, digest FROM raw_record WHERE id IN ({','.join('?' * len(chunk))})"
        for r in conn.execute(q, chunk):
            raws[r["id"]] = dict(r)
    items = []
    for c in cands:
        ents = {norm_entity(e[1]) for e in (_j(c["entities"]) or []) if isinstance(e, list) and len(e) >= 2}
        locs, times, efields, missing = [], [], [], 0
        for eid in _j(c["event_ids"]) or []:
            ev = events.get(eid)
            if ev is None:
                missing += 1
                continue
            if ev["host"]:
                ents.add(norm_entity(ev["host"]))
            if ev["ts"]:
                times.append(ev["ts"])
            fields = (ev["event"] or {}).get("fields") or {}
            times += _interval_values(fields)
            efields.append(fields)
            for ref in (ev["event"] or {}).get("raw") or []:
                rid = raw_id(ref["target"], ref["native_id"])
                r = raws.get(rid)
                locs.append({"key": target_to_key(ref["target"], ref["native_id"]), "target": ref["target"],
                             "native_id": ref["native_id"], "digest": ref.get("digest"), "family": ev["family"],
                             "retained": r is not None, "digest_ok": bool(r and r["digest"] == ref.get("digest"))})
        items.append(Item(id=c["id"], lane=c["lane"], rule_id=c["rule_id"], rule_version=str(c["rule_version"]),
                          priority=float(c["priority"]), severity=c["severity"], claim_type=c["claim_type"],
                          observed_at=_dt(c["ts"]), created_at=_dt(c["created_at"]),
                          source_case_id=c.get("source_case_id"), entities=ents, locators=locs,
                          t_min=min(times) if times else _dt(c["ts"]), t_max=max(times) if times else _dt(c["ts"]),
                          predicate_fields=_j(c["predicate_fields"]) or [], event_fields=efields, missing_events=missing))
    if any(i.missing_events for i in items):
        gaps.append("some candidates cite typed events that are not retained")
    tasks = []
    for r in conn.execute("SELECT * FROM task WHERE hunt_id = ?", (hunt_id,)):
        d = dict(r)
        d["intent"], d["outcome"] = _j(d["intent"]), _j(d["outcome"])
        d["created_at"], d["updated_at"] = _dt(d["created_at"]), _dt(d["updated_at"])
        tasks.append(d)
    cells = []
    for r in conn.execute("SELECT * FROM rule_run WHERE hunt_id = ?", (hunt_id,)):
        d = dict(r)
        d["detail"] = _j(d["detail"])
        cells.append(d)
    audit = []
    for r in conn.execute("SELECT * FROM audit_event WHERE hunt_id = ? ORDER BY id", (hunt_id,)):
        d = dict(r)
        d["detail"], d["at"] = _j(d["detail"]), _dt(d["at"])
        audit.append(d)
    calls = [dict(r) for r in conn.execute("SELECT * FROM model_call WHERE hunt_id = ?", (hunt_id,))]
    cases = []
    for r in conn.execute('SELECT * FROM "case" WHERE hunt_id = ?', (hunt_id,)):
        d = dict(r)
        d["entities"] = _j(d["entities"])
        cases.append(d)
    order = coverage = None
    rm = conn.execute("SELECT manifest FROM report_manifest WHERE hunt_id = ? ORDER BY revision DESC LIMIT 1",
                      (hunt_id,)).fetchone()
    if rm is not None:
        m = _j(rm["manifest"]) or {}
        order = [f["id"] for f in m.get("findings", [])]
        coverage = (m.get("coverage") or {}).get("rules")
    return Hunt(id=hunt_id, manifest=_j(h["manifest"]) or {}, started_at=_dt(h["started_at"]),
                ended_at=_dt(h["ended_at"]), execution_state=h["execution_state"],
                detection_result=h["detection_result"], items=items, tasks=tasks, rule_cells=cells, audit=audit,
                model_calls=calls, cases=cases, report_order=order, report_coverage=coverage, gaps=gaps)
