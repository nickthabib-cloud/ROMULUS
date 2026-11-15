"""The deterministic report order and its finding groups, staged on disk, for the AI triage order.

The report lists a hunt's surfaced findings (urgent, high and lead lanes) in three sections. With the final evidence
ranking: confirmed (lane urgent), then the other reported findings, then the ranked pool, each by rank (score
descending, then observation time, then id); a finding stored after the pass is scored from the stored entity scores,
as the report does. Without it: urgent, high, then lead, each by priority descending, then time, then id. Each finding
gets its ordinal in that order.

A group is the findings of one rule on one primary target within one section: the finding's listed entity from the
final ranking, else its first typed host, service, address or account, else `unattributed`. Findings the AI agent
proposed form groups of their own, which the model never triages (it must not promote its own claims). Findings an
investigator case discovered stay in their rule's groups and are counted on the card.

Everything is staged in a temporary SQLite file under the hunt's stage directory, so memory stays bounded by one page
of findings and one card whatever the hunt's size; the file is held to the site's stage byte budget, and a refusal is
an honest failure that keeps the deterministic order. The triage order is finding-level: within each section, the
findings the model was shown for each promoted group (its claim excerpts, at most MAX_EXCERPTS, the only ones it could
cite) come first, group by group; every other finding, including the rest of a promoted group, keeps its
deterministic place. No finding moves down by more than promote-per-lane x MAX_EXCERPTS findings, and nothing is ever
removed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Iterable, Iterator
from typing import Self

from romulus.decide import rank as rank_model
from romulus.detect.metadata import finding_attack, hunt_rule_metadata
from romulus.hunt.rank import PASS_FINAL, rank_unranked
from romulus.store.repo import Repo

GROUPING_VERSION = "triage-groups@2"
SECTIONS_RANKED = ("Confirmed", "Reported entities", "Ranked findings (not reported)")
SECTIONS_LANES = ("Urgent", "High", "Investigative leads")
LANE_SECTION = {"urgent": 0, "high": 1, "lead": 2}
PAGE = 1000
# What a card holds, bounded whatever a group's size: claim excerpts (the findings a promotion moves), entities listed
# (with the distinct count), tactics, and characters of any one telemetry-derived string.
MAX_EXCERPTS = 3
MAX_CARD_ENTITIES = 8
MAX_ENTITIES_PER_FINDING = 8
MAX_TACTICS = 14
MAX_TEXT = 240
MAX_ENTITY_TEXT = 160
# The order a finding's primary target is chosen from its typed entities when the ranking names none.
TARGET_KINDS = ("host", "service", "ip", "account", "user")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


class StageRefused(RuntimeError):
    """The triage stage would exceed the site's stage byte budget or the volume's reserve."""


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


GROUP_COLUMNS = ("group_no", "best", "n", "cases", "section", "provenance", "rule_id", "kind", "value", "first_ts",
                 "last_ts")
_GROUP_SELECT = ("SELECT g.group_no, g.best, g.n, g.cases, g.section, k.provenance, k.rule_id, k.kind, k.value, "
                 "g.first_ts, g.last_ts FROM g JOIN k ON k.gid = g.gid")


class OrderWorkspace:
    """The hunt's deterministic report order, groups, cards and verdicts in a temporary SQLite file."""

    def __init__(self, repo: Repo, hunt_id: str, *, directory: str | None = None,
                 heartbeat: Callable[[], None] = lambda: None, page: int = PAGE,
                 max_bytes: int | None = None, reserve_bytes: int = 0):
        self.repo, self.hunt_id, self.heartbeat, self.page = repo, hunt_id, heartbeat, page
        self.max_bytes, self.reserve_bytes = max_bytes, reserve_bytes
        if directory is not None:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="romulus-triage-", dir=directory)
        self.path = os.path.join(self.dir, "order.db")
        self.db = sqlite3.connect(self.path)
        self.db.executescript("""
            PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA temp_store = FILE;
            CREATE TABLE k (gid INTEGER PRIMARY KEY, gkey TEXT UNIQUE, section INTEGER, provenance TEXT,
                            rule_id TEXT, kind TEXT, value TEXT);
            CREATE TABLE f (fid INTEGER PRIMARY KEY, finding_id TEXT, section INTEGER, k1 INTEGER, k2 REAL,
                            k3 INTEGER, k4 TEXT, gid INTEGER, lane TEXT, ts TEXT, claim TEXT, is_case INTEGER,
                            tactics TEXT);
            CREATE TABLE e (gid INTEGER, fid INTEGER, kind TEXT, value TEXT);
            CREATE TABLE c (group_no INTEGER PRIMARY KEY, card TEXT, ids TEXT, size INTEGER);
            CREATE TABLE v (group_no INTEGER PRIMARY KEY, status TEXT, reason TEXT, assessment TEXT,
                            incident_label TEXT, rationale TEXT, cites TEXT, shown TEXT);
            CREATE TABLE vr (position INTEGER PRIMARY KEY, row TEXT);
        """)
        self.ranked = repo.has_rank_pass(hunt_id, PASS_FINAL)
        self.findings = 0
        self.order_digest = ""
        self._fid = 0

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

    def check_space(self) -> None:
        """Refuse to grow past the site's stage byte budget or into the stage volume's reserve."""
        size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        if self.max_bytes is not None and size > self.max_bytes:
            raise StageRefused(f"the triage stage reached {size} bytes, over its {self.max_bytes}-byte budget")
        if self.reserve_bytes:
            free = shutil.disk_usage(self.dir).free
            if free < self.reserve_bytes:
                raise StageRefused(f"the stage volume has {free} bytes free, under its {self.reserve_bytes}-byte "
                                   "reserve")

    def size(self) -> int:
        return os.path.getsize(self.path) if os.path.exists(self.path) else 0

    # -- staging ----------------------------------------------------------------------------------------------------
    def _gids(self, keys: dict[str, tuple]) -> dict[str, int]:
        """Integer group ids for one page's group keys (the key text is stored once per group)."""
        self.db.executemany("INSERT OR IGNORE INTO k (gkey, section, provenance, rule_id, kind, value) "
                            "VALUES (?,?,?,?,?,?)", [(key, *fields) for key, fields in keys.items()])
        out: dict[str, int] = {}
        ordered = list(keys)
        for start in range(0, len(ordered), 500):
            chunk = ordered[start:start + 500]
            out.update((key, gid) for gid, key in self.db.execute(
                f"SELECT gid, gkey FROM k WHERE gkey IN ({', '.join('?' for _ in chunk)})", chunk))
        return out

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
            staged, keys = [], {}
            for row in page:
                agent = row.get("provenance") == rank_model.AGENT_PROVENANCE
                provenance = "agent" if agent else "deterministic"
                ts = str(row["ts"]) if row["ts"] is not None else None
                if self.ranked:
                    rank = ranks.get(row["id"]) or late[row["id"]]
                    section = (0 if row["lane"] == rank_model.CONFIRMED_LANE else 1 if rank["reported"] else 2)
                    order = (0, -float(rank["score"]), int(ts is None), ts or "")
                    kind, value = rank["entity_kind"], rank["entity"]
                    target = ((kind, clip(value, MAX_ENTITY_TEXT)) if value is not None
                              and kind != rank_model.UNATTRIBUTED else derived_target(row["entities"]))
                else:
                    section = LANE_SECTION[row["lane"]]
                    # the report's rule-estimate order compares the time as text, an unknown time as "None"
                    order = (0, -float(row["priority"]), 0, str(row["ts"]))
                    target = derived_target(row["entities"])
                key = group_key(section, provenance, row["rule_id"], *target)
                keys[key] = (section, provenance, row["rule_id"], *target)
                staged.append((row, section, order, key, ts, agent))
            gids = self._gids(keys)
            findings, entities = [], []
            for row, section, order, key, ts, agent in staged:
                self._fid += 1
                gid = gids[key]
                findings.append((self._fid, row["id"], section, *order, gid, row["lane"], ts,
                                 clip(row.get("claim") or ""),
                                 int(row.get("source_case_id") is not None and not agent),
                                 json.dumps(tactics(row["rule_id"], row.get("attack") or []))))
                typed = [item for item in _entities(row["entities"]) if item[2] != rank_model.OBSERVER_ROLE]
                for kind, value in sorted({(kind, clip(value, MAX_ENTITY_TEXT)) for kind, value, _r in typed})[
                        :MAX_ENTITIES_PER_FINDING]:
                    entities.append((gid, self._fid, kind, value))
            self.db.executemany("INSERT INTO f VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", findings)
            self.db.executemany("INSERT INTO e VALUES (?,?,?,?)", entities)
            self.db.commit()
            self.check_space()
            after = page[-1]["id"]
        self.heartbeat()
        self.db.executescript("""
            CREATE TABLE o (ordinal INTEGER PRIMARY KEY, fid INTEGER, finding_id TEXT, section INTEGER,
                            gid INTEGER, lane TEXT, ts TEXT, claim TEXT, is_case INTEGER, tactics TEXT);
            INSERT INTO o SELECT ROW_NUMBER() OVER (ORDER BY section, k1, k2, k3, k4, finding_id), fid, finding_id,
                section, gid, lane, ts, claim, is_case, tactics FROM f;
            DROP TABLE f;
            CREATE INDEX o_group ON o (gid, ordinal);
            CREATE INDEX o_section ON o (section, ordinal);
            CREATE UNIQUE INDEX o_finding ON o (finding_id);
            CREATE INDEX e_group ON e (gid, kind, value);
            CREATE TABLE g (group_no INTEGER PRIMARY KEY, gid INTEGER UNIQUE, best INTEGER, n INTEGER,
                            cases INTEGER, section INTEGER, first_ts TEXT, last_ts TEXT);
            INSERT INTO g SELECT ROW_NUMBER() OVER (ORDER BY MIN(ordinal)), gid, MIN(ordinal), COUNT(*),
                SUM(is_case), MIN(section), MIN(ts), MAX(ts) FROM o GROUP BY gid;
            CREATE UNIQUE INDEX g_section_best ON g (section, best);
        """)
        self.db.commit()
        self.check_space()
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
        while rows := self.db.execute(f"{_GROUP_SELECT} WHERE g.group_no > ? ORDER BY g.group_no LIMIT ?",
                                      (after, self.page)).fetchall():
            yield from (dict(zip(GROUP_COLUMNS, row, strict=True)) for row in rows)
            after = rows[-1][0]

    def card_detail(self, group: dict) -> dict:
        """The bounded detail of one group's card: lanes, tactics, entities with counts, claim excerpts (its first
        MAX_EXCERPTS findings in deterministic order)."""
        gid = self.db.execute("SELECT gid FROM g WHERE group_no = ?", (group["group_no"],)).fetchone()[0]
        lanes = [row[0] for row in self.db.execute("SELECT DISTINCT lane FROM o WHERE gid = ? ORDER BY lane",
                                                   (gid,))]
        tactics: set[str] = set()
        for (value,) in self.db.execute("SELECT DISTINCT tactics FROM o WHERE gid = ? LIMIT 64", (gid,)):
            tactics.update(json.loads(value or "[]"))
        distinct = int(self.db.execute("SELECT COUNT(*) FROM (SELECT DISTINCT kind, value FROM e WHERE gid = ?)",
                                       (gid,)).fetchone()[0])
        top = [{"kind": kind, "value": value, "findings": count} for kind, value, count in self.db.execute(
            "SELECT kind, value, COUNT(DISTINCT fid) AS c FROM e WHERE gid = ? GROUP BY kind, value "
            "ORDER BY c DESC, kind, value LIMIT ?", (gid, MAX_CARD_ENTITIES))]
        excerpts = [{"finding": finding_id, "text": claim} for finding_id, claim in self.db.execute(
            "SELECT finding_id, claim FROM o WHERE gid = ? ORDER BY ordinal LIMIT ?", (gid, MAX_EXCERPTS))]
        return {"lanes": lanes, "tactics": sorted(tactics)[:MAX_TACTICS], "entities_distinct": distinct,
                "entities": top, "excerpts": excerpts}

    # -- cards: built once, read by the digest and the calls ----------------------------------------------------------
    def store_cards(self, cards: Iterable[tuple[int, str, list[str], int]]) -> None:
        batch = []
        for group_no, card, ids, size in cards:
            batch.append((group_no, card, json.dumps(ids), size))
            if len(batch) >= self.page:
                self.db.executemany("INSERT INTO c VALUES (?,?,?,?)", batch)
                self.db.commit()
                self.check_space()
                self.heartbeat()
                batch = []
        if batch:
            self.db.executemany("INSERT INTO c VALUES (?,?,?,?)", batch)
        self.db.commit()
        self.check_space()

    def cards(self) -> Iterator[tuple[int, str, list[str], int]]:
        after = 0
        while rows := self.db.execute("SELECT group_no, card, ids, size FROM c WHERE group_no > ? ORDER BY group_no "
                                      "LIMIT ?", (after, self.page)).fetchall():
            yield from ((group_no, card, json.loads(ids), size) for group_no, card, ids, size in rows)
            after = rows[-1][0]

    def card_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM c").fetchone()[0])

    # -- verdicts -----------------------------------------------------------------------------------------------------
    def set_verdict(self, group_no: int, *, status: str, reason: str | None = None, assessment: str | None = None,
                    incident_label: str | None = None, rationale: str | None = None, cites=(), shown=()) -> None:
        self.db.execute("INSERT OR REPLACE INTO v VALUES (?,?,?,?,?,?,?,?)",
                        (group_no, status, reason, assessment, incident_label, rationale, json.dumps(list(cites)),
                         json.dumps(list(shown))))

    def mark_rest(self, reason: str) -> int:
        """Every carded group with no verdict yet is not triaged, for `reason` (one statement, no card is rebuilt)."""
        cursor = self.db.execute(
            "INSERT INTO v (group_no, status, reason, cites, shown) SELECT c.group_no, 'not_triaged', ?, '[]', c.ids "
            "FROM c LEFT JOIN v ON v.group_no = c.group_no WHERE v.group_no IS NULL", (reason,))
        self.db.commit()
        return cursor.rowcount

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
                f"SELECT g.group_no FROM v JOIN g ON g.group_no = v.group_no JOIN k ON k.gid = g.gid "
                f"WHERE g.section = ? AND k.provenance = 'deterministic' AND v.status = 'assessed' AND v.assessment IN "
                f"({', '.join('?' for _ in tiers)}) ORDER BY CASE v.assessment {order} END, g.best LIMIT ?",
                (section, *tiers, per_section)).fetchall()
            promoted[section] = [row[0] for row in rows]
            self.db.executemany("UPDATE v SET status = 'promoted' WHERE group_no = ?", rows)
        self.db.commit()
        return promoted

    VIEW_SELECT = (f"{_GROUP_SELECT.replace('FROM g JOIN k', ', v.status, v.reason, v.assessment, v.incident_label, '
                                            'v.rationale, v.cites, v.shown FROM g JOIN k')} "
                   "LEFT JOIN v ON v.group_no = g.group_no")
    VIEW_COLUMNS = (*GROUP_COLUMNS, "status", "reason", "assessment", "incident_label", "rationale", "cites", "shown")

    def view_page_query(self) -> str:
        """One page of a section's groups by best position: an index search on (section, best), never a scan."""
        return f"{self.VIEW_SELECT} WHERE g.section = ? AND g.best > ? ORDER BY g.best LIMIT ?"

    def materialize_view(self, promoted: dict[int, list[int]], to_row: Callable[[dict], dict]) -> int:
        """Write every group's stored row, in triage-view order (by section, promoted groups first, then the rest by
        best deterministic position), into the stage, so publishing only copies finished rows."""
        position = 0
        batch: list[tuple[int, str]] = []

        def add(item: dict) -> None:
            nonlocal position, batch
            position += 1
            batch.append((position, json.dumps(to_row({**item, "position": position}))))
            if len(batch) >= self.page:
                self.db.executemany("INSERT INTO vr VALUES (?,?)", batch)
                self.db.commit()
                self.check_space()
                self.heartbeat()
                batch = []

        for section in range(3):
            first = promoted.get(section) or []
            for group_no in first:
                row = self.db.execute(f"{self.VIEW_SELECT} WHERE g.group_no = ?", (group_no,)).fetchone()
                add(dict(zip(self.VIEW_COLUMNS, row, strict=True)))
            skip = set(first)
            after = 0
            while rows := self.db.execute(self.view_page_query(), (section, after, self.page)).fetchall():
                for row in rows:
                    item = dict(zip(self.VIEW_COLUMNS, row, strict=True))
                    if item["group_no"] not in skip:
                        add(item)
                after = rows[-1][1]
        if batch:
            self.db.executemany("INSERT INTO vr VALUES (?,?)", batch)
        self.db.commit()
        self.check_space()
        return position

    def view_rows(self) -> Iterator[dict]:
        """The materialized rows, in position order: indexed pages, nothing computed."""
        after = 0
        while rows := self.db.execute("SELECT position, row FROM vr WHERE position > ? ORDER BY position LIMIT ?",
                                      (after, self.page)).fetchall():
            yield from (json.loads(row) for _position, row in rows)
            after = rows[-1][0]

    def shown_of(self, group_numbers: list[int]) -> list[list[str]]:
        out = []
        for group_no in group_numbers:
            row = self.db.execute("SELECT shown FROM v WHERE group_no = ?", (group_no,)).fetchone()
            out.append(json.loads(row[0]) if row and row[0] else [])
        return out

    def triage_order(self, promoted: dict[int, list[list[str]]]) -> Iterator[str]:
        """Every surfaced finding id in the triage order. Per section: the shown findings of each promoted group (at
        most MAX_EXCERPTS each, in that group's deterministic order), then every other finding of the section in
        deterministic order, the rest of each promoted group included. With nothing promoted it is the deterministic
        order. Ids no longer in that section (a store changed after the pass) are ignored."""
        for section in range(3):
            moved: list[str] = []
            for ids in promoted.get(section) or []:
                for finding_id in ids[:MAX_EXCERPTS]:
                    row = self.db.execute("SELECT section FROM o WHERE finding_id = ?", (finding_id,)).fetchone()
                    if row is not None and row[0] == section and finding_id not in moved:
                        moved.append(finding_id)
            yield from moved
            skip = set(moved)
            after = 0
            while rows := self.db.execute("SELECT ordinal, finding_id FROM o WHERE section = ? AND ordinal > ? "
                                          "ORDER BY ordinal LIMIT ?", (section, after, self.page)).fetchall():
                yield from (finding_id for _ordinal, finding_id in rows if finding_id not in skip)
                after = rows[-1][0]
