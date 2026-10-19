"""Load a gold inventory directory (schema gold-opportunity/1) into lookup structures.

The directory is given at run time and is never part of the repo. Expected files:
``gold_opportunities.v1.jsonl``, ``gold_evidence.v1.jsonl`` and, optionally, ``aliases.v1.json``
(host name -> list of IP addresses that denote the same asset).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

SCHEMA = "gold-opportunity/1"
DIRECT_ROLES = frozenset({"action", "outcome"})
SOURCES = ("host_index", "network_index", "arkime", "pcap")


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    from datetime import UTC
    d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T"))
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def norm_entity(v: str) -> str:
    """Canonical entity token: lower-case; 'host\\account' becomes 'account'."""
    v = str(v).strip().lower()
    return v.rsplit("\\", 1)[-1]


@dataclass
class Opportunity:
    opp_id: str
    behavior_class: str
    severity: str
    attack: list[str]
    observability: str                  # observable | inferable_only | not_observable
    start: datetime | None
    end: datetime | None
    time_position: str | None
    entities: set[str]
    source_status: dict[str, str]       # source -> direct | indirect | none
    derived: bool
    not_observable_reason: str | None

    @property
    def critical_high(self) -> bool:
        return self.severity in ("critical", "high")


@dataclass
class Gold:
    dataset: str
    version: str
    files_sha256: dict[str, str]
    opportunities: dict[str, Opportunity]
    # locator key -> list of (opp_id, role, source)
    evidence: dict[tuple, list[tuple[str, str, str]]] = field(default_factory=dict)
    # (opp_id, source) -> list of (key, role, ts, dataset) for ES rows (funnel replay)
    es_rows: dict[tuple[str, str], list[tuple[tuple, str, datetime | None, str | None]]] = field(default_factory=dict)
    aliases: dict[str, set[str]] = field(default_factory=dict)

    def expand(self, ents: set[str]) -> set[str]:
        out = set(ents)
        for host, ips in self.aliases.items():
            group = {host} | ips
            if out & group:
                out |= group
        return out

    def forbidden_strings(self) -> set[str]:
        """Strings that must never appear in an aggregate output (leak guard)."""
        bad = set(self.opportunities)
        for k in self.evidence:
            bad.add(str(k[-1]) if k[0] != "pcap" else f"{k[1]}#{k[2]}")
        return {b for b in bad if len(b) >= 3}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def locator_key(kind: str, a: str, b: str | int | None = None) -> tuple:
    """Canonical locator key shared by gold rows and ROMULUS citations.

    es:     ("es", index, _id)
    arkime: ("arkime", session_id)
    pcap:   ("pcap", file_sha256_or_basename, frame)
    """
    if kind == "es":
        return ("es", a, str(b))
    if kind == "arkime":
        return ("arkime", str(a))
    if kind == "pcap":
        return ("pcap", str(a), int(b))
    raise ValueError(f"unknown locator kind {kind!r}")


def load(gold_dir: str | Path) -> Gold:
    d = Path(gold_dir)
    opp_path, ev_path = d / "gold_opportunities.v1.jsonl", d / "gold_evidence.v1.jsonl"
    opps: dict[str, Opportunity] = {}
    dataset = None
    for line in opp_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("schema") != SCHEMA:
            raise ValueError(f"unexpected gold schema {r.get('schema')!r}")
        dataset = dataset or r["dataset"]
        ents = set()
        for k in ("hosts", "ips", "accounts"):
            ents |= {norm_entity(x) for x in r["entities"].get(k, [])}
        w = r.get("window_utc") or {}
        opps[r["opp_id"]] = Opportunity(
            opp_id=r["opp_id"], behavior_class=r["behavior_class"], severity=r["severity"], attack=list(r["attack"]),
            observability=r["observability"], start=parse_ts(w.get("start")), end=parse_ts(w.get("end")),
            time_position=(r.get("time_position") or {}).get("hunt_window"), entities=ents,
            source_status={s: (r["sources"].get(s) or {}).get("status", "none") for s in SOURCES},
            derived=bool(r.get("derived_from")), not_observable_reason=r.get("not_observable_reason"))
    g = Gold(dataset=dataset or "unknown", version="v1", files_sha256={}, opportunities=opps)
    g.files_sha256 = {p.name: _sha(p) for p in (opp_path, ev_path)}
    with ev_path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            oid, role, src = r["opp_id"], r["role"], r["source"]
            if r["kind"] == "es":
                key = locator_key("es", r["index"], r["id"])
                g.evidence.setdefault(key, []).append((oid, role, src))
                g.es_rows.setdefault((oid, src), []).append((key, role, parse_ts(r.get("ts")), r.get("dataset")))
            elif r["kind"] == "arkime":
                g.evidence.setdefault(locator_key("arkime", r["session_id"]), []).append((oid, role, src))
            elif r["kind"] == "pcap":
                ident = r.get("file_sha256") or Path(r["file"]).name
                for fr in r["frames"]:
                    g.evidence.setdefault(locator_key("pcap", ident, fr), []).append((oid, role, src))
                    if r.get("file_sha256"):
                        g.evidence.setdefault(locator_key("pcap", Path(r["file"]).name, fr), []).append((oid, role, src))
    al = d / "aliases.v1.json"
    if al.exists():
        raw = json.loads(al.read_text(encoding="utf-8"))
        g.aliases = {norm_entity(h): {norm_entity(i) for i in ips} for h, ips in raw.get("hosts", {}).items()}
        g.files_sha256[al.name] = _sha(al)
    return g
