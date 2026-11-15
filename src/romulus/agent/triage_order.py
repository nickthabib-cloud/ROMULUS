"""The deterministic report order and its finding groups, staged on disk, for the AI triage order.

The report lists a hunt's surfaced findings (urgent, high and lead lanes) in three sections. With the final evidence
ranking: confirmed (lane urgent), then the other reported findings, then the ranked pool, each by rank (score
descending, then observation time, then id); a finding stored after the pass is scored from the stored entity scores,
as the report does. Without it: urgent, high, then lead, each by priority descending, then time, then id. Each finding
gets its ordinal in that order.

A group is the findings of one rule on one primary target within one section: the finding's listed entity from the
final ranking, else its first typed host, service, address or account, else `unattributed`. Findings the AI agent
proposed form groups of their own, which the model never triages (it must not promote its own claims).

Everything is staged in a temporary SQLite file, so memory stays bounded by one page of findings and one card
whatever the hunt's size. The triage order is finding-level: within each section, the promoted groups' findings come
first (group by group, each in deterministic order), then every other finding in its deterministic order. No finding
moves down by more than the number of groups promoted ahead of it, and nothing is ever removed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Iterator
from typing import Self

from romulus.decide import rank as rank_model
from romulus.detect.metadata import finding_attack, hunt_rule_metadata
from romulus.hunt.rank import PASS_FINAL, rank_unranked
from romulus.store.repo import Repo

GROUPING_VERSION = "triage-groups@1"
SECTIONS_RANKED = ("Confirmed", "Reported entities", "Ranked findings (not reported)")
SECTIONS_LANES = ("Urgent", "High", "Investigative leads")
LANE_SECTION = {"urgent": 0, "high": 1, "lead": 2}
PAGE = 1000
# What a card holds, bounded whatever a group's size: claim excerpts, entities listed (with the distinct count),
# tactics, and characters of any one telemetry-derived string.
MAX_EXCERPTS = 3
MAX_CARD_ENTITIES = 8
MAX_ENTITIES_PER_FINDING = 8
MAX_TACTICS = 14
MAX_TEXT = 240
MAX_ENTITY_TEXT = 160
# The order a finding's primary target is chosen from its typed entities when the ranking names none.
TARGET_KINDS = ("host", "service", "ip", "account", "user")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def clip(value, limit: int = MAX_TEXT) -> str:
    """A telemetry-derived string as a card carries it: control and direction characters removed, length-capped."""
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _entities(raw) -> list[tuple[str, str, str]]:
    out = []
    for item in raw or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and item[1] is not None:
            out.append((str(item[0]), str(item[1]), str(item[2]) if len(item) > 2 else ""))
    return out


def derived_target(entities) -> tuple[str, str]:
    """A finding's primary target from its typed entities (the network sensor that observed a flow is never one)."""
    typed = [item for item in _entities(entities) if item[2] != rank_model.OBSERVER_ROLE]
    for kind in TARGET_KINDS:
        for item in typed:
            if item[0] == kind:
                return kind, clip(item[1], MAX_ENTITY_TEXT)
    if typed:
        kind, value, _role = min(typed)
        return kind, clip(value, MAX_ENTITY_TEXT)
    return rank_model.UNATTRIBUTED, ""


def group_key(section: int, provenance: str, rule_id: str, kind: str, value: str) -> str:
    return json.dumps([section, provenance, rule_id, kind, value], ensure_ascii=False, separators=(",", ":"))


class OrderWorkspace:
    """The hunt's deterministic report order and groups in a temporary SQLite file."""

    def __init__(self, repo: Repo, hunt_id: str, *, directory: str | None = None,
                 heartbeat: Callable[[], None] = lambda: None, page: int = PAGE):
        self.repo, self.hunt_id, self.heartbeat, self.page = repo, hunt_id, heartbeat, page
        if directory is not None:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="romulus-triage-", dir=directory)
        self.db = sqlite3.connect(os.path.join(self.dir, "order.db"))
        self.db.executescript("""
            PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA temp_store = FILE;
            CREATE TABLE f (finding_id TEXT PRIMARY KEY, section INTEGER, k1 INTEGER, k2 REAL, k3 INTEGER,
                            k4 TEXT, gkey TEXT, rule_id TEXT, lane TEXT, ts TEXT, claim TEXT, provenance TEXT,
                            kind TEXT, value TEXT, tactics TEXT);
            CREATE TABLE e (gkey TEXT, finding_id TEXT, kind TEXT, value TEXT);
            CREATE TABLE v (group_no INTEGER PRIMARY KEY, status TEXT, reason TEXT, assessment TEXT,
                            incident_label TEXT, rationale TEXT, cites TEXT, shown TEXT);
        """)
        self.ranked = repo.has_rank_pass(hunt_id, PASS_FINAL)
        self.findings = 0
        self.order_digest = ""

    # -- lifecycle --------------------------------------------------------------------------------------------------
    def close(self) -> None:
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def section_titles(self) -> tuple[str, ...]:
        return SECTIONS_RANKED if self.ranked else SECTIONS_LANES

    # -- staging ----------------------------------------------------------------------------------------------------
    def build(self) -> OrderWorkspace:
        hunt = self.repo.get_hunt(self.hunt_id)
        if hunt is None:
            raise KeyError(self.hunt_id)
        rules = hunt_rule_metadata(self.repo, manifest=hunt["manifest"] or {})
        tactics_of: dict[tuple, list[str]] = {}

        def tactics(rule_id: str, attack: list) -> list[str]:
            key = (rule_id, tuple(str(item) for item in attack))
            if key not in tactics_of:
                tactics_of[key] = list(finding_attack(list(key[1]), rules.get(rule_id))[1])[:MAX_TACTICS]
            return tactics_of[key]

        after = ""
        while page := self.repo.reportable_page(self.hunt_id, after_id=after, limit=self.page):
            self.heartbeat()
            ranks = (self.repo.finding_ranks_for(self.hunt_id, PASS_FINAL, [row["id"] for row in page])
                     if self.ranked else {})
            late = (rank_unranked(self.repo, self.hunt_id, [row for row in page if row["id"] not in ranks])
                    if self.ranked else {})
            findings, entities = [], []
            for row in page:
                provenance = "agent" if row.get("provenance") == rank_model.AGENT_PROVENANCE else "deterministic"
                ts = str(row["ts"]) if row["ts"] is not None else None
                if self.ranked:
                    rank = ranks.get(row["id"]) or late[row["id"]]
                    section = (0 if row["lane"] == rank_model.CONFIRMED_LANE else 1 if rank["reported"] else 2)
                    keys = (0, -float(rank["score"]), int(ts is None), ts or "")
                    kind, value = rank["entity_kind"], rank["entity"]
                    target = ((kind, clip(value, MAX_ENTITY_TEXT)) if value is not None
                              and kind != rank_model.UNATTRIBUTED else derived_target(row["entities"]))
                else:
                    section = LANE_SECTION[row["lane"]]
                    # the report's rule-estimate order compares the time as text, an unknown time as "None"
                    keys = (0, -float(row["priority"]), 0, str(row["ts"]))
                    target = derived_target(row["entities"])
                gkey = group_key(section, provenance, row["rule_id"], *target)
                findings.append((row["id"], section, *keys, gkey, row["rule_id"], row["lane"], ts,
                                 clip(row.get("claim") or ""), provenance, target[0], target[1],
                                 json.dumps(tactics(row["rule_id"], row.get("attack") or []))))
                typed = [item for item in _entities(row["entities"]) if item[2] != rank_model.OBSERVER_ROLE]
                for kind, value in sorted({(kind, clip(value, MAX_ENTITY_TEXT)) for kind, value, _r in typed})[
                        :MAX_ENTITIES_PER_FINDING]:
                    entities.append((gkey, row["id"], kind, value))
            self.db.executemany("INSERT INTO f VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", findings)
            self.db.executemany("INSERT INTO e VALUES (?,?,?,?)", entities)
            self.db.commit()
            after = page[-1]["id"]
        self.heartbeat()
        self.db.executescript("""
            CREATE TABLE o AS SELECT ROW_NUMBER() OVER (ORDER BY section, k1, k2, k3, k4, finding_id) AS ordinal,
                finding_id, section, gkey, rule_id, lane, ts, claim, provenance, kind, value, tactics FROM f;
            DROP TABLE f;
            CREATE UNIQUE INDEX o_ordinal ON o (ordinal);
            CREATE INDEX o_group ON o (gkey, ordinal);
            CREATE INDEX o_section ON o (section, ordinal);
            CREATE INDEX e_group ON e (gkey, kind, value);
            CREATE TABLE g AS SELECT ROW_NUMBER() OVER (ORDER BY MIN(ordinal)) AS group_no, gkey,
                MIN(ordinal) AS best, COUNT(*) AS n, MIN(section) AS section, MIN(rule_id) AS rule_id,
                MIN(provenance) AS provenance, MIN(kind) AS kind, MIN(value) AS value,
                MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM o GROUP BY gkey;
            CREATE UNIQUE INDEX g_no ON g (group_no);
            CREATE UNIQUE INDEX g_key ON g (gkey);
        """)
        self.db.commit()
        digest = hashlib.sha256()
        for finding_id in self.deterministic():
            digest.update(finding_id.encode())
            digest.update(b"\n")
            self.findings += 1
        self.order_digest = digest.hexdigest()
        return self

    # -- reads --------------------------------------------------------------------------------------------------------
    def deterministic(self) -> Iterator[str]:
        """Every surfaced finding id in the deterministic report order."""
        after = 0
        while rows := self.db.execute("SELECT ordinal, finding_id FROM o WHERE ordinal > ? ORDER BY ordinal LIMIT ?",
                                      (after, self.page)).fetchall():
            yield from (finding_id for _ordinal, finding_id in rows)
            after = rows[-1][0]

    def group_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM g").fetchone()[0])

    def groups(self) -> Iterator[dict]:
        """Every group by its best deterministic position (group numbers follow it)."""
        after = 0
        columns = ("group_no", "gkey", "best", "n", "section", "rule_id", "provenance", "kind", "value",
                   "first_ts", "last_ts")
        while rows := self.db.execute(f"SELECT {', '.join(columns)} FROM g WHERE group_no > ? ORDER BY group_no "
                                      "LIMIT ?", (after, self.page)).fetchall():
            yield from (dict(zip(columns, row, strict=True)) for row in rows)
            after = rows[-1][0]

    def group_by_key(self, gkey: str) -> dict | None:
        row = self.db.execute("SELECT group_no FROM g WHERE gkey = ?", (gkey,)).fetchone()
        return {"group_no": row[0]} if row else None

    def card_detail(self, group: dict) -> dict:
        """The bounded detail of one group's card: lanes, tactics, entities with counts, claim excerpts."""
        gkey = group["gkey"]
        lanes = [row[0] for row in self.db.execute("SELECT DISTINCT lane FROM o WHERE gkey = ? ORDER BY lane",
                                                   (gkey,))]
        tactics: set[str] = set()
        for (value,) in self.db.execute("SELECT DISTINCT tactics FROM o WHERE gkey = ? LIMIT 64", (gkey,)):
            tactics.update(json.loads(value or "[]"))
        distinct = int(self.db.execute("SELECT COUNT(*) FROM (SELECT DISTINCT kind, value FROM e WHERE gkey = ?)",
                                       (gkey,)).fetchone()[0])
        top = [{"kind": kind, "value": value, "findings": count} for kind, value, count in self.db.execute(
            "SELECT kind, value, COUNT(DISTINCT finding_id) AS c FROM e WHERE gkey = ? GROUP BY kind, value "
            "ORDER BY c DESC, kind, value LIMIT ?", (gkey, MAX_CARD_ENTITIES))]
        excerpts = [{"finding": finding_id, "text": claim} for finding_id, claim in self.db.execute(
            "SELECT finding_id, claim FROM o WHERE gkey = ? ORDER BY ordinal LIMIT ?", (gkey, MAX_EXCERPTS))]
        return {"lanes": lanes, "tactics": sorted(tactics)[:MAX_TACTICS], "entities_distinct": distinct,
                "entities": top, "excerpts": excerpts}

    # -- verdicts -----------------------------------------------------------------------------------------------------
    def set_verdict(self, group_no: int, *, status: str, reason: str | None = None, assessment: str | None = None,
                    incident_label: str | None = None, rationale: str | None = None, cites=(), shown=()) -> None:
        self.db.execute("INSERT OR REPLACE INTO v VALUES (?,?,?,?,?,?,?,?)",
                        (group_no, status, reason, assessment, incident_label, rationale, json.dumps(list(cites)),
                         json.dumps(list(shown))))

    def commit(self) -> None:
        self.db.commit()

    def not_triaged_reasons(self) -> dict[str, int]:
        return {str(reason): int(count) for reason, count in self.db.execute(
            "SELECT reason, COUNT(*) FROM v WHERE status = 'not_triaged' GROUP BY reason ORDER BY reason")}

    def promote(self, per_section: int, tiers: tuple[str, ...]) -> dict[int, list[int]]:
        """Choose the promoted groups: in each section at most `per_section` deterministic groups the model assessed in
        one of `tiers`, the stronger tier first, then by best deterministic position. Returns section -> group numbers
        in promoted order. Chunk order and the model's own ordering never decide it."""
        promoted: dict[int, list[int]] = {}
        if per_section <= 0 or not tiers:
            return promoted
        order = " ".join(f"WHEN '{tier}' THEN {index}" for index, tier in enumerate(tiers))
        for section in range(3):
            rows = self.db.execute(
                f"SELECT g.group_no FROM g JOIN v ON v.group_no = g.group_no WHERE g.section = ? AND "
                f"g.provenance = 'deterministic' AND v.status = 'assessed' AND v.assessment IN "
                f"({', '.join('?' for _ in tiers)}) ORDER BY CASE v.assessment {order} END, g.best LIMIT ?",
                (section, *tiers, per_section)).fetchall()
            promoted[section] = [row[0] for row in rows]
            self.db.executemany("UPDATE v SET status = 'promoted' WHERE group_no = ?", rows)
        self.db.commit()
        return promoted

    def view_rows(self, promoted: dict[int, list[int]]) -> Iterator[dict]:
        """Every group with its verdict in triage-view order: by section, promoted groups first, then the rest by best
        deterministic position."""
        position = 0
        columns = ("group_no", "gkey", "best", "n", "section", "rule_id", "provenance", "kind", "value",
                   "status", "reason", "assessment", "incident_label", "rationale", "cites", "shown")
        select = ("SELECT g.group_no, g.gkey, g.best, g.n, g.section, g.rule_id, g.provenance, g.kind, g.value, "
                  "v.status, v.reason, v.assessment, v.incident_label, v.rationale, v.cites, v.shown "
                  "FROM g LEFT JOIN v ON v.group_no = g.group_no")
        for section in range(3):
            first = promoted.get(section) or []
            for group_no in first:
                position += 1
                row = self.db.execute(f"{select} WHERE g.group_no = ?", (group_no,)).fetchone()
                yield {**dict(zip(columns, row, strict=True)), "position": position}
            skip = set(first)
            after = 0
            while rows := self.db.execute(f"{select} WHERE g.section = ? AND g.best > ? ORDER BY g.best LIMIT ?",
                                          (section, after, self.page)).fetchall():
                for row in rows:
                    item = dict(zip(columns, row, strict=True))
                    if item["group_no"] not in skip:
                        position += 1
                        yield {**item, "position": position}
                after = rows[-1][2]

    def triage_order(self, promoted_keys: dict[int, list[str]]) -> Iterator[str]:
        """Every surfaced finding id in the triage order: per section, each promoted group's findings in deterministic
        order, then every other finding in deterministic order. With nothing promoted it is the deterministic order."""
        for section in range(3):
            keys = [key for key in promoted_keys.get(section) or []
                    if self.db.execute("SELECT 1 FROM g WHERE gkey = ? AND section = ?", (key, section)).fetchone()]
            for key in keys:
                after = 0
                while rows := self.db.execute("SELECT ordinal, finding_id FROM o WHERE gkey = ? AND ordinal > ? "
                                              "ORDER BY ordinal LIMIT ?", (key, after, self.page)).fetchall():
                    yield from (finding_id for _ordinal, finding_id in rows)
                    after = rows[-1][0]
            skip = set(keys)
            after = 0
            while rows := self.db.execute("SELECT ordinal, finding_id, gkey FROM o WHERE section = ? AND ordinal > ? "
                                          "ORDER BY ordinal LIMIT ?", (section, after, self.page)).fetchall():
                yield from (finding_id for _ordinal, finding_id, gkey in rows if gkey not in skip)
                after = rows[-1][0]
