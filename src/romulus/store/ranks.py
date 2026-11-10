"""Staging and publication of one evidence-ranking pass.

A pass is computed on one connection in temporary tables, which SQLite keeps on disk once they outgrow its page
cache, so per-entity state never lives in one Python structure however many hosts, accounts or findings a hunt has.
Python only ever holds one keyset page of rows. The pass is published with one write transaction that replaces the
hunt's previous rows for that pass, so a reader sees the old pass or the new one, never a mixture.

The store knows nothing about how ranks are scored: it stages the rows the caller computes, aggregates them with SQL
and pages them back in a fixed order.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import Connection, Engine, text

from romulus.store.db import _write_lock

_TEMP_TABLES = ("rk_finding", "rk_member", "rk_tactic", "rk_pair", "rk_entity", "rk_rule_host", "rk_host",
                "rk_address", "rk_fleet")
# A counted (deterministic, non-case) candidate, and one of the lanes a rule's prevalence is read from.
_COUNTED = "c.provenance = 'deterministic' AND c.source_case_id IS NULL"
_RANKED_LANES = "c.lane IN ('urgent', 'high', 'lead')"
_CREATE = (
    # one row per ranked finding (confirmed and pool, agent findings included)
    """CREATE TEMP TABLE rk_finding (
        candidate_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, ts TEXT, lane TEXT NOT NULL, prior REAL NOT NULL,
        provenance TEXT NOT NULL, fleet TEXT, score REAL, reported INTEGER, entity_kind TEXT, entity TEXT,
        reasons TEXT)""",
    # one row per (entity, ranked finding)
    """CREATE TEMP TABLE rk_member (
        entity_kind TEXT NOT NULL, entity TEXT NOT NULL, candidate_id TEXT NOT NULL, rule_id TEXT NOT NULL, ts TEXT,
        confirmed INTEGER NOT NULL, contributes INTEGER NOT NULL, fleet INTEGER NOT NULL DEFAULT 0,
        prior REAL NOT NULL, PRIMARY KEY (entity_kind, entity, candidate_id)) WITHOUT ROWID""",
    "CREATE INDEX temp.rk_member_time ON rk_member (entity_kind, entity, ts, rule_id, candidate_id)",
    "CREATE INDEX temp.rk_member_candidate ON rk_member (candidate_id)",
    "CREATE INDEX temp.rk_member_rule ON rk_member (rule_id)",
    # the tactics each counted finding gives its entities, by rule (a recurring fleet-wide rule's are dropped later)
    """CREATE TEMP TABLE rk_tactic (
        entity_kind TEXT NOT NULL, entity TEXT NOT NULL, rule_id TEXT NOT NULL, tactic TEXT NOT NULL,
        PRIMARY KEY (entity_kind, entity, rule_id, tactic)) WITHOUT ROWID""",
    # the bounded input of each entity's tactic matching
    """CREATE TEMP TABLE rk_pair (
        entity_kind TEXT NOT NULL, entity TEXT NOT NULL, rule_id TEXT NOT NULL, tactic TEXT NOT NULL,
        PRIMARY KEY (entity_kind, entity, rule_id, tactic)) WITHOUT ROWID""",
    """CREATE TEMP TABLE rk_entity (
        entity_kind TEXT NOT NULL, entity TEXT NOT NULL, confirmed INTEGER NOT NULL, rules INTEGER NOT NULL,
        findings INTEGER NOT NULL, max_prior REAL, fleet_rules TEXT NOT NULL, tactics TEXT NOT NULL,
        cooccur INTEGER NOT NULL DEFAULT 0, score REAL, reported INTEGER, reasons TEXT,
        PRIMARY KEY (entity_kind, entity)) WITHOUT ROWID""",
    # the hosts each rule's counted ranked-lane candidates were seen on, for the fleet-wide condition
    """CREATE TEMP TABLE rk_rule_host (rule_id TEXT NOT NULL, host TEXT NOT NULL,
        PRIMARY KEY (rule_id, host)) WITHOUT ROWID""",
    # the hosts with any counted candidate (any lane): the fleet condition's denominator
    "CREATE TEMP TABLE rk_host (host TEXT PRIMARY KEY) WITHOUT ROWID",
    # addresses exactly one host's own telemetry carries in the hunt window
    "CREATE TEMP TABLE rk_address (address TEXT PRIMARY KEY, host TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TEMP TABLE rk_fleet (rule_id TEXT PRIMARY KEY, reason TEXT NOT NULL) WITHOUT ROWID",
)


def stored_time(value: datetime | None) -> str | None:
    """A UTC time as fixed-width text, so text order is time order."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")


def parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class RankWorkspace:
    """One ranking pass's staging area. `queries` counts the statements it ran and `peak_rows` the most rows any one
    page held in Python, so a caller (and a test) can see that the work is bounded by its page size."""

    def __init__(self, connection: Connection, hunt_id: str, pass_no: int,
                 fence: Callable[[Connection, str, str | None], None]):
        self.connection, self.hunt_id, self.pass_no, self._fence = connection, hunt_id, pass_no, fence
        self.queries = 0
        self.peak_rows = 0

    # -- statements ----------------------------------------------------------------------------------------------
    def _run(self, sql: str, params: dict | None = None):
        self.queries += 1
        return self.connection.execute(text(sql), params or {})

    def _many(self, sql: str, rows: list[dict]) -> None:
        if rows:
            self.queries += 1
            self.connection.execute(text(sql), rows)

    def _page(self, rows: list) -> list:
        self.peak_rows = max(self.peak_rows, len(rows))
        return rows

    def commit(self) -> None:
        self.connection.commit()

    def _population(self) -> str:
        """The candidates a pass ranks. Pass 1 runs before expansion and ranks what the sweep, packet and baseline
        stages found; restricting it to those (no expansion, case or agent discovery) keeps a resumed hunt's pass 1
        the same pass expansion was seeded from. Pass 2 ranks everything."""
        where = "c.hunt_id = :hunt"
        if self.pass_no == 1:
            where += (" AND c.provenance = 'deterministic' AND c.source_anchor_id IS NULL"
                      " AND c.source_link_id IS NULL AND c.source_case_id IS NULL")
        return where

    # -- the address map -------------------------------------------------------------------------------------------
    def stage_addresses(self, start: datetime, end: datetime, network_families: tuple[str, ...]) -> None:
        """Addresses that exactly one host's own telemetry (never a network sensor's) carries as its host address in
        the hunt window. An address two hosts carried (reassigned, shared, or a NAT) is left out: kept apart, not
        guessed."""
        families = ", ".join(f"'{family}'" for family in network_families)
        events = f"""
            SELECT e.host AS host, a.value AS address FROM typed_event e,
                   json_each(e.event, '$.fields."host.ip".value') a
            WHERE e.hunt_id = :hunt AND e.host IS NOT NULL AND e.family NOT IN ({families})
              AND e.ts >= :start AND e.ts < :end AND a.type = 'text'
            UNION
            SELECT e.host, a.value FROM event_observation o JOIN typed_event e ON e.id = o.event_id,
                   json_each(e.event, '$.fields."host.ip".value') a
            WHERE o.hunt_id = :hunt AND e.host IS NOT NULL AND e.family NOT IN ({families})
              AND e.ts >= :start AND e.ts < :end AND a.type = 'text'"""
        self._run(f"INSERT INTO rk_address (address, host) SELECT address, MIN(host) FROM ({events}) "
                  f"GROUP BY address HAVING COUNT(DISTINCT host) = 1",
                  {"hunt": self.hunt_id, "start": stored_time(start), "end": stored_time(end)})

    def addresses(self, addresses: set[str]) -> dict[str, str]:
        if not addresses:
            return {}
        names = sorted(addresses)
        out: dict[str, str] = {}
        for offset in range(0, len(names), 500):
            chunk = names[offset:offset + 500]
            marks = ", ".join(f":a{index}" for index in range(len(chunk)))
            out.update(self._run(f"SELECT address, host FROM rk_address WHERE address IN ({marks})",
                                 {f"a{index}": value for index, value in enumerate(chunk)}).all())
        return out

    # -- staging --------------------------------------------------------------------------------------------------
    def population_page(self, after: str, limit: int) -> list[dict]:
        """The next page of the pass's candidates (every lane) in id order (keyset)."""
        rows = self._run(
            f"SELECT c.id, c.rule_id, c.ts, c.lane, c.priority, c.provenance, c.source_case_id, c.entities, "
            f"json_extract(c.gate_results, '$._attack') AS attack FROM candidate c "
            f"WHERE {self._population()} AND c.id > :after ORDER BY c.id LIMIT :limit",
            {"hunt": self.hunt_id, "after": after, "limit": limit}).mappings().all()
        out = []
        for row in rows:
            item = dict(row)
            item["entities"] = _json(item["entities"]) or []
            item["attack"] = _json(item["attack"]) or []
            item["ts"] = _as_time(item["ts"])
            out.append(item)
        return self._page(out)

    def stage(self, findings: list[dict], members: list[dict], tactics: list[dict], rule_hosts: list[dict],
              hosts: list[dict]) -> None:
        self._many("INSERT OR IGNORE INTO rk_host (host) VALUES (:host)", hosts)
        self._many("INSERT INTO rk_finding (candidate_id, rule_id, ts, lane, prior, provenance) "
                   "VALUES (:candidate_id, :rule_id, :ts, :lane, :prior, :provenance)", findings)
        self._many("INSERT OR IGNORE INTO rk_member (entity_kind, entity, candidate_id, rule_id, ts, confirmed, "
                   "contributes, prior) VALUES (:entity_kind, :entity, :candidate_id, :rule_id, :ts, "
                   ":confirmed, :contributes, :prior)", members)
        self._many("INSERT OR IGNORE INTO rk_tactic (entity_kind, entity, rule_id, tactic) "
                   "VALUES (:entity_kind, :entity, :rule_id, :tactic)", tactics)
        self._many("INSERT OR IGNORE INTO rk_rule_host (rule_id, host) VALUES (:rule_id, :host)", rule_hosts)

    def stage_fleet_hosts(self) -> None:
        """The full host lists of fleet-grouped findings (one finding standing for many hosts)."""
        joined = (f"FROM candidate c JOIN candidate_host h ON h.candidate_id = c.id "
                  f"WHERE {self._population()} AND {_COUNTED}")
        self._run(f"INSERT OR IGNORE INTO rk_host (host) SELECT h.host {joined}", {"hunt": self.hunt_id})
        self._run(f"INSERT OR IGNORE INTO rk_rule_host (rule_id, host) SELECT c.rule_id, h.host {joined} "
                  f"AND {_RANKED_LANES}", {"hunt": self.hunt_id})

    # -- rule statistics (SQL aggregates) -----------------------------------------------------------------------
    def hunt_hosts(self) -> int:
        """Distinct hosts with any counted candidate in the pass (any lane)."""
        return int(self._run("SELECT COUNT(*) FROM rk_host").scalar_one())

    def rule_spread(self) -> Iterator[tuple[str, int, datetime | None, datetime | None]]:
        """Per rule: distinct hosts and the first and last observation time of its counted candidates in the ranked
        lanes. One row per rule, so the result is bounded by the rule catalog, not by the hunt."""
        hosts = dict(self._run("SELECT rule_id, COUNT(*) FROM rk_rule_host GROUP BY rule_id").all())
        spans = {rule_id: (first, last) for rule_id, first, last in self._run(
            f"SELECT c.rule_id, MIN(c.ts), MAX(c.ts) FROM candidate c WHERE {self._population()} "
            f"AND {_COUNTED} AND {_RANKED_LANES} AND c.ts IS NOT NULL GROUP BY c.rule_id",
            {"hunt": self.hunt_id}).all()}
        for rule_id in sorted(set(hosts) | set(spans)):
            first, last = spans.get(rule_id, (None, None))
            yield rule_id, int(hosts.get(rule_id, 0)), _as_time(first), _as_time(last)

    def mark_fleet(self, reasons: dict[str, str]) -> None:
        """Record the recurring fleet-wide rules and flag their memberships and findings."""
        self._many("INSERT INTO rk_fleet (rule_id, reason) VALUES (:rule_id, :reason)",
                   [{"rule_id": rule_id, "reason": reason} for rule_id, reason in sorted(reasons.items())])
        if reasons:
            self._run("UPDATE rk_member SET fleet = 1 WHERE rule_id IN (SELECT rule_id FROM rk_fleet)")
            self._run("UPDATE rk_finding SET fleet = (SELECT reason FROM rk_fleet f WHERE f.rule_id = "
                      "rk_finding.rule_id) WHERE rule_id IN (SELECT rule_id FROM rk_fleet)")

    def aggregate_entities(self) -> None:
        """Each entity's confirmed findings, distinct counted rules, findings, strongest counted prior, recurring
        fleet-wide rules and counted tactics, in one SQL aggregate."""
        self._run("""
            INSERT INTO rk_entity (entity_kind, entity, confirmed, rules, findings, max_prior, fleet_rules, tactics)
            SELECT m.entity_kind, m.entity,
                   SUM(CASE WHEN m.contributes = 1 AND m.confirmed = 1 THEN 1 ELSE 0 END),
                   COUNT(DISTINCT CASE WHEN m.contributes = 1 AND m.fleet = 0 THEN m.rule_id END),
                   COUNT(*),
                   MAX(CASE WHEN m.contributes = 1 THEN m.prior END),
                   (SELECT json_group_array(rule_id) FROM (
                        SELECT DISTINCT f.rule_id FROM rk_member f
                        WHERE f.entity_kind = m.entity_kind AND f.entity = m.entity
                          AND f.contributes = 1 AND f.fleet = 1)),
                   (SELECT json_group_array(tactic) FROM (
                        SELECT DISTINCT x.tactic FROM rk_tactic x
                        WHERE x.entity_kind = m.entity_kind AND x.entity = m.entity
                          AND x.rule_id NOT IN (SELECT rule_id FROM rk_fleet)))
            FROM rk_member m GROUP BY m.entity_kind, m.entity""")

    def timeline_page(self, after: tuple | None, limit: int) -> list[dict]:
        """The next page of counted, timed memberships in entity then time order (keyset)."""
        where = "contributes = 1 AND fleet = 0 AND ts IS NOT NULL"
        params: dict = {"limit": limit}
        if after is not None:
            where += " AND (entity_kind, entity, ts, rule_id, candidate_id) > (:kind, :entity, :ts, :rule, :cid)"
            params.update(kind=after[0], entity=after[1], ts=after[2], rule=after[3], cid=after[4])
        rows = self._run(
            f"SELECT entity_kind, entity, ts, rule_id, candidate_id FROM rk_member WHERE {where} "
            f"ORDER BY entity_kind, entity, ts, rule_id, candidate_id LIMIT :limit", params).mappings().all()
        return self._page([dict(row) for row in rows])

    def set_cooccurrence(self, rows: list[dict]) -> None:
        self._many("UPDATE rk_entity SET cooccur = :cooccur WHERE entity_kind = :entity_kind AND entity = :entity",
                   rows)

    def entity_page(self, after: tuple[str, str] | None, limit: int) -> list[dict]:
        where, params = "1 = 1", {"limit": limit}
        if after is not None:
            where = "(entity_kind, entity) > (:kind, :entity)"
            params.update(kind=after[0], entity=after[1])
        rows = self._run(
            f"SELECT entity_kind, entity, confirmed, rules, findings, max_prior, fleet_rules, tactics, cooccur "
            f"FROM rk_entity WHERE {where} ORDER BY entity_kind, entity LIMIT :limit", params).mappings().all()
        out = []
        for row in rows:
            item = dict(row)
            item["fleet_rules"] = tuple(sorted(_json(item["fleet_rules"]) or []))
            item["tactics"] = tuple(sorted(_json(item["tactics"]) or []))
            out.append(item)
        return self._page(out)

    def stage_matching_pairs(self, per_tactic: int) -> None:
        """The counted (rule, tactic) pairs each entity's tactic matching reads: recurring fleet-wide rules dropped,
        and at most `per_tactic` rules per tactic of each entity (the lowest rule ids)."""
        self._run("""
            INSERT INTO rk_pair (entity_kind, entity, rule_id, tactic)
            SELECT entity_kind, entity, rule_id, tactic FROM (
                SELECT entity_kind, entity, rule_id, tactic,
                       ROW_NUMBER() OVER (PARTITION BY entity_kind, entity, tactic ORDER BY rule_id) AS n
                FROM rk_tactic WHERE rule_id NOT IN (SELECT rule_id FROM rk_fleet))
            WHERE n <= :per_tactic""", {"per_tactic": per_tactic})

    def pair_page(self, after: tuple | None, limit: int) -> list[dict]:
        """The next page of matching pairs in entity order (keyset)."""
        where, params = "1 = 1", {"limit": limit}
        if after is not None:
            where = "(entity_kind, entity, rule_id, tactic) > (:kind, :entity, :rule, :tactic)"
            params.update(kind=after[0], entity=after[1], rule=after[2], tactic=after[3])
        rows = self._run(
            f"SELECT entity_kind, entity, rule_id, tactic FROM rk_pair WHERE {where} "
            f"ORDER BY entity_kind, entity, rule_id, tactic LIMIT :limit", params).mappings().all()
        return self._page([dict(row) for row in rows])

    def set_entity_scores(self, rows: list[dict]) -> None:
        self._many("UPDATE rk_entity SET score = :score, reported = :reported, reasons = :reasons, tactics = :tactics "
                   "WHERE entity_kind = :entity_kind AND entity = :entity", rows)

    def finding_page(self, after: str, limit: int) -> list[dict]:
        rows = self._run(
            "SELECT candidate_id, rule_id, lane, prior, provenance, fleet FROM rk_finding "
            "WHERE candidate_id > :after ORDER BY candidate_id LIMIT :limit",
            {"after": after, "limit": limit}).mappings().all()
        return self._page([dict(row) for row in rows])

    def finding_entities(self, first: str, last: str) -> list[dict]:
        """Every (finding, entity score) pair for the findings of one page, by their id range."""
        rows = self._run(
            "SELECT m.candidate_id, m.entity_kind, m.entity, e.score, e.reported FROM rk_member m "
            "JOIN rk_entity e ON e.entity_kind = m.entity_kind AND e.entity = m.entity "
            "WHERE m.candidate_id >= :first AND m.candidate_id <= :last "
            "ORDER BY m.candidate_id, m.entity_kind, m.entity", {"first": first, "last": last}).mappings().all()
        return self._page([dict(row) for row in rows])

    def set_finding_ranks(self, rows: list[dict]) -> None:
        self._many("UPDATE rk_finding SET score = :score, reported = :reported, entity_kind = :entity_kind, "
                   "entity = :entity, reasons = :reasons WHERE candidate_id = :candidate_id", rows)

    def counts(self) -> dict[str, int]:
        findings, reported = self._run("SELECT COUNT(*), COALESCE(SUM(reported), 0) FROM rk_finding").one()
        entities, reported_entities = self._run(
            "SELECT COUNT(*), COALESCE(SUM(reported), 0) FROM rk_entity").one()
        return {"ranked_findings": int(findings), "reported_findings": int(reported),
                "entities": int(entities), "reported_entities": int(reported_entities)}

    # -- publication ----------------------------------------------------------------------------------------------
    def publish(self, owner_token: str | None) -> None:
        """Replace the hunt's rows for this pass with the staged ones, in one write transaction, proving the lease."""
        connection = self.connection
        connection.commit()
        with _write_lock:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                self._fence(connection, self.hunt_id, owner_token)
                params = {"hunt": self.hunt_id, "pass": self.pass_no}
                self._run('DELETE FROM finding_rank WHERE hunt_id = :hunt AND "pass" = :pass', params)
                self._run('DELETE FROM entity_rank WHERE hunt_id = :hunt AND "pass" = :pass', params)
                self._run("""
                    INSERT INTO finding_rank (hunt_id, "pass", candidate_id, position, score, reported, entity_kind,
                                              entity, reasons, section)
                    SELECT :hunt, :pass, candidate_id,
                           ROW_NUMBER() OVER (ORDER BY score DESC, ts IS NULL, ts, candidate_id),
                           score, reported, entity_kind, entity, reasons,
                           CASE WHEN lane = 'urgent' THEN 0 WHEN reported THEN 1 ELSE 2 END
                    FROM rk_finding""", params)
                self._run("""
                    INSERT INTO entity_rank (hunt_id, "pass", entity_kind, entity, position, score, tactics, rules,
                                             cooccur, confirmed, findings, reported, reasons)
                    SELECT :hunt, :pass, entity_kind, entity,
                           ROW_NUMBER() OVER (ORDER BY score DESC, entity_kind, entity),
                           score, tactics, rules, cooccur, confirmed, findings, reported, reasons
                    FROM rk_entity""", params)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise


@contextmanager
def rank_workspace(engine: Engine, hunt_id: str, pass_no: int,
                   fence: Callable[[Connection, str, str | None], None]) -> Iterator[RankWorkspace]:
    """A connection with empty staging tables for one pass; they are dropped when the block ends."""
    with engine.connect() as connection:
        _drop(connection)
        for statement in _CREATE:
            connection.exec_driver_sql(statement)
        connection.commit()
        try:
            yield RankWorkspace(connection, hunt_id, pass_no, fence)
        finally:
            try:
                connection.rollback()
                _drop(connection)
                connection.commit()
            except Exception:  # noqa: BLE001, S110 - the next workspace on this connection drops them first
                pass


def _drop(connection: Connection) -> None:
    for name in _TEMP_TABLES:
        connection.exec_driver_sql(f"DROP TABLE IF EXISTS temp.{name}")


def _json(value):
    if value is None or isinstance(value, (list, dict)):
        return value
    return json.loads(value)


def _as_time(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return parse_time(str(value))
