"""Persistent baseline segments, frozen snapshots, and lossless window observations."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta, timezone

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import event, inspect, select, text
from sqlalchemy.exc import IntegrityError

from romulus.store import repo as repo_module
from romulus.store import schema
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _repo() -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    return Repo(engine)


def _segment(segment_id: str = "seg-b", **overrides) -> dict:
    row = {
        "id": segment_id,
        "site": "site-a",
        "target": "host-index",
        "spec_id": "bl.exec_path",
        "spec_version": "1",
        "key_version": "1",
        "normalizer": "linux-audit@8",
        "start": T0,
        "end": T0 + timedelta(hours=1),
        "bucket": "day",
        "origin": "lookback",
        "source_hunt_id": None,
        "built_by_hunt_id": None,
        "exclusion_digest": "none",
        "excluded_keys": [],
        "hunted": 0,
        "events_total": 3,
        "status": "active",
        "created_at": T0 + timedelta(days=1),
    }
    row.update(overrides)
    return row


def _count(segment_id: str = "seg-b", **overrides) -> dict:
    row = {
        "segment_id": segment_id,
        "scope_kind": "host",
        "scope": "host:web01",
        "key_id": "id-b",
        "key_digest": "key-b",
        "key": {"executable": "/bin/sh"},
        "bucket": T0,
        "count": 3,
        "first_ts": T0 + timedelta(minutes=1),
        "last_ts": T0 + timedelta(minutes=2),
    }
    row.update(overrides)
    return row


def _scope_hour(segment_id: str = "seg-b", **overrides) -> dict:
    row = {"segment_id": segment_id, "scope_kind": "host", "scope": "host:web01", "hour": T0, "events": 3}
    row.update(overrides)
    return row


def _snapshot(hunt_id: str, **overrides) -> dict:
    row = {
        "hunt_id": hunt_id,
        "plan": {"history_days": 7},
        "store_cut": {"created_before": "2026-01-02T00:00:00Z"},
        "segment_ids": ["seg-b"],
        "coverage": {"host-index": {"gaps": []}},
        "status": "resolved",
        "digest": "snap-one",
    }
    row.update(overrides)
    return row


def _observation(hunt_id: str, key_digest: str = "key-b", **overrides) -> dict:
    row = {
        "hunt_id": hunt_id,
        "spec_id": "bl.exec_path",
        "spec_version": "1",
        "scope_kind": "host",
        "scope": "host:web01",
        "key_id": f"id-{key_digest}",
        "key_digest": key_digest,
        "key": {"executable": "/bin/sh"},
        "window_count": 1,
        "first_ts": T0,
        "last_ts": T0,
        "first_event_id": "event-1",
        "history_count": 9,
        "history_decayed": 7.5,
        "peer_scopes_with_key": 2,
        "peer_scopes": 6,
        "threshold": None,
        "mean": None,
        "sigma": None,
        "n_hours": None,
        "verdict": "common",
        "reason": None,
        "candidate_id": None,
    }
    row.update(overrides)
    return row


def _alembic_config(connection) -> Config:
    from romulus.store import db

    cfg = Config()
    cfg.set_main_option("script_location", str(db.Path(db.__file__).resolve().parent / "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


def test_0009_upgrade_and_downgrade_preserve_existing_data(tmp_path):
    engine = make_engine(tmp_path / "migration.db")
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0008")
        conn.exec_driver_sql(
            "INSERT INTO hunt (id, created_at, created_by, manifest, manifest_digest, execution_state) "
            "VALUES ('h1', '2026-01-01', 'test', '{}', 'd', 'planned')"
        )
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0009")
    names = set(inspect(engine).get_table_names())
    assert {"baseline_segment", "baseline_count", "baseline_scope_hour",
            "baseline_snapshot", "baseline_observation"} <= names
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO baseline_segment "
            "(id, site, target, spec_id, spec_version, key_version, normalizer, start, end, bucket, origin, "
            "exclusion_digest, excluded_keys, hunted, events_total, rows_digest, status, created_at) VALUES "
            "('s1', 'site', 'idx', 'bl.exec_path', '1', '1', 'n@1', '2026-01-01', '2026-01-02', 'day', "
            "'lookback', 'none', '[]', 0, 1, 'd', 'active', '2026-01-03')"
        )
    with engine.begin() as conn:
        command.downgrade(_alembic_config(conn), "0008")
        assert conn.exec_driver_sql("SELECT id FROM hunt").scalar_one() == "h1"
    assert "baseline_segment" not in set(inspect(engine).get_table_names())


def test_0013_backfills_snapshot_membership_and_downgrades_without_losing_snapshot(tmp_path):
    engine = make_engine(tmp_path / "membership-migration.db")
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0009")
        conn.exec_driver_sql(
            "INSERT INTO hunt (id, created_at, created_by, manifest, manifest_digest, execution_state) "
            "VALUES ('h1', '2026-01-01', 'test', '{}', 'd', 'planned')"
        )
        conn.exec_driver_sql(
            "INSERT INTO baseline_segment "
            "(id, site, target, spec_id, spec_version, key_version, normalizer, start, end, bucket, origin, "
            "exclusion_digest, excluded_keys, hunted, events_total, rows_digest, status, created_at) VALUES "
            "('s1', 'site', 'idx', 'bl.exec_path', '1', '1', 'n@1', '2026-01-01', '2026-01-02', 'day', "
            "'lookback', 'none', '[]', 0, 1, 'd', 'active', '2026-01-03')"
        )
        conn.exec_driver_sql(
            "INSERT INTO baseline_snapshot "
            "(hunt_id, plan, store_cut, segment_ids, coverage, status, digest) VALUES "
            "('h1', '{}', '{}', '[\"s1\"]', '{}', 'resolved', 'd')"
        )
        conn.exec_driver_sql(
            "INSERT INTO baseline_count "
            "(segment_id, scope_kind, scope, key_id, key_digest, key, bucket, count, first_ts, last_ts) "
            "VALUES ('s1', 'host', 'host:h', 'k', 'd', '{}', '2026-01-01', 1, "
            "'2026-01-01 01:00:00', '2026-01-01 01:00:00')"
        )
        conn.exec_driver_sql(
            "INSERT INTO baseline_scope_hour (segment_id, scope_kind, scope, hour, events) "
            "VALUES ('s1', 'host', 'host:h', '2026-01-01 01:00:00', 1)"
        )
        command.upgrade(_alembic_config(conn), "0013")
        assert conn.exec_driver_sql(
            "SELECT hunt_id || ':' || segment_id FROM baseline_snapshot_segment"
        ).scalar_one() == "h1:s1"
        assert conn.exec_driver_sql("SELECT count(*) FROM baseline_count").scalar_one() == 1
        assert conn.exec_driver_sql("SELECT count(*) FROM baseline_scope_hour").scalar_one() == 1
        command.downgrade(_alembic_config(conn), "0009")
        assert conn.exec_driver_sql("SELECT segment_ids FROM baseline_snapshot").scalar_one() == '["s1"]'
        assert conn.exec_driver_sql("SELECT count(*) FROM baseline_count").scalar_one() == 1


def test_0010_through_0012_round_trip_agent_link_without_prior_scheduler_anchor(tmp_path):
    engine = make_engine(tmp_path / "agent-migrations.db")
    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "0012")
        connection.execute(schema.hunt.insert().values(
            id="h1", created_at=T0, created_by="test", manifest={}, manifest_digest="d",
            execution_state="planned",
        ))
        connection.execute(schema.candidate.insert().values(
            id="finding-agent", hunt_id="h1", rule_id="host.test", rule_version="1",
            claim="agent-found direct match", claim_type="observed_action", event_ids=[],
            predicate_fields=[], entities=[], ts=T0, severity="high", confidence="high",
            lane="high", priority=80.0, priority_reasons=[], gate_results={},
            benign_alternatives=[], next_checks=[], group_key="", source_case_id="case-1",
            source_anchor_id=None, source_link_id="link-agent", created_at=T0,
        ))
        connection.execute(schema.expansion_link.insert().values(
            id="link-agent", hunt_id="h1", anchor_id="finding-agent",
            link_type="agent_process_lineage", window_label="case window",
            window_start=T0, window_end=T0 + timedelta(minutes=5), strength="agent_hypothesis",
            key={}, status="complete", event_ids=[], evidence_ids=[], task_ids=[], coverage=[],
            reasons=[], duration_ms=1, query_spend=1, evaluated=1, created_at=T0, updated_at=T0,
        ))
        connection.execute(schema.agent_alias.insert().values(
            hunt_id="h1", alias="F1", kind="F", target_id="finding-agent", created_at=T0,
        ))
        connection.execute(schema.agent_page_plan.insert().values(
            hunt_id="h1", cursor="D0000000000000001", identity={"kind": "findings"},
            summary={}, item_count=0, created_at=T0,
        ))

    with engine.begin() as connection:
        command.downgrade(_alembic_config(connection), "0009")
        assert connection.exec_driver_sql(
            "SELECT candidate_id FROM expansion_anchor WHERE id='finding-agent'",
        ).scalar_one() == "finding-agent"
        assert connection.exec_driver_sql(
            "SELECT anchor_id FROM expansion_link WHERE id='link-agent'",
        ).scalar_one() == "finding-agent"
    assert "agent_alias" not in set(inspect(engine).get_table_names())
    assert "agent_page_plan" not in set(inspect(engine).get_table_names())

    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection), "0012")
        assert connection.exec_driver_sql(
            "SELECT anchor_id FROM expansion_link WHERE id='link-agent'",
        ).scalar_one() == "finding-agent"


def test_segment_is_insert_only_except_for_status_and_children_are_stable():
    repo = _repo()
    assert repo.save_baseline_segment(_segment(), [_count()], [_scope_hour()]) is True
    # the same content again (a later writer run: new created_at) is a no-op
    assert repo.save_baseline_segment(
        _segment(created_at=T0 + timedelta(days=9)), [_count()], [_scope_hour()],
    ) is False
    for changed in (
        (_segment(events_total=999), [_count()], [_scope_hour()]),
        (_segment(), [_count(count=999)], [_scope_hour()]),
        (_segment(), [_count()], [_scope_hour(events=999)]),
        (_segment(), [_count()], []),
        (_segment(), [_count(), _count(key_digest="key-c", key_id="id-c")], [_scope_hour()]),
    ):
        with pytest.raises(ValueError, match="different content"):
            repo.save_baseline_segment(*changed)
    assert repo.baseline_segments()[0]["events_total"] == 3
    assert next(repo.baseline_counts("seg-b"))["count"] == 3
    assert next(repo.baseline_scope_hours("seg-b"))["events"] == 3
    assert repo.set_baseline_segment_status("seg-b", "stale") is True
    assert repo.baseline_segments()[0]["status"] == "stale"
    with pytest.raises(ValueError, match="baseline segment status"):
        repo.set_baseline_segment_status("seg-b", "deleted")


def test_segment_requires_hour_aligned_nonempty_span():
    repo = _repo()
    with pytest.raises(ValueError, match="hour-aligned"):
        repo.save_baseline_segment(_segment(start=T0 + timedelta(minutes=1)), [], [])
    with pytest.raises(ValueError, match="start before end"):
        repo.save_baseline_segment(_segment(end=T0), [], [])


def test_snapshot_is_write_once_and_resume_reuses_original():
    repo = _repo()
    repo.create_hunt("h1", {}, "d", "test")
    repo.save_baseline_segment(_segment(), [], [])
    assert repo.save_baseline_snapshot(_snapshot("h1")) is True
    assert repo.save_baseline_snapshot(_snapshot("h1", digest="changed", segment_ids=[])) is False
    stored = repo.baseline_snapshot("h1")
    assert stored["digest"] == "snap-one" and stored["segment_ids"] == ["seg-b"]
    assert repo.baseline_snapshot_segments("h1") == ["seg-b"]


def test_observation_upsert_uses_full_window_key_and_keeps_every_key():
    repo = _repo()
    repo.create_hunt("h1", {}, "d", "test")
    repo.upsert_baseline_observation(_observation("h1", "key-b"))
    repo.upsert_baseline_observation(_observation(
        "h1", "key-b", window_count=2, verdict="rare", candidate_id="candidate-1",
    ))
    repo.upsert_baseline_observation(_observation("h1", "key-a", scope="host:web02"))
    rows = list(repo.baseline_observations("h1"))
    assert [(row["scope"], row["key_digest"]) for row in rows] == [
        ("host:web01", "key-b"), ("host:web02", "key-a"),
    ]
    assert rows[0]["window_count"] == 2 and rows[0]["candidate_id"] == "candidate-1"


def test_delete_hunt_drops_its_snapshot_and_observations_and_revokes_derived_segments():
    repo = _repo()
    for hunt_id in ("h1", "h2"):
        repo.create_hunt(hunt_id, {}, "d", "test")
        repo.set_hunt_state(hunt_id, "canceled")
    for row in (
        _segment("seg-source", source_hunt_id="h1"),
        _segment("seg-built", built_by_hunt_id="h1"),
        _segment("seg-other", built_by_hunt_id="h2"),
    ):
        repo.save_baseline_segment(row, [], [])
    for hunt_id in ("h1", "h2"):
        repo.save_baseline_snapshot(_snapshot(
            hunt_id, digest=f"snap-{hunt_id}", segment_ids=["seg-other"],
        ))
        repo.upsert_baseline_observation(_observation(hunt_id))

    counts = repo.delete_hunt("h1", actor="test")

    assert counts["baseline_snapshots"] == 1 and counts["baseline_observations"] == 1
    assert repo.baseline_snapshot("h1") is None and list(repo.baseline_observations("h1")) == []
    status = {row["id"]: row["status"] for row in repo.baseline_segments()}
    assert status == {"seg-built": "revoked", "seg-other": "active", "seg-source": "revoked"}
    assert repo.baseline_snapshot("h2")["digest"] == "snap-h2"


def test_baseline_listings_are_deterministically_sorted():
    repo = _repo()
    for segment_id, target, start in (
        ("seg-z", "z-index", T0),
        ("seg-b", "a-index", T0 + timedelta(hours=1)),
        ("seg-a", "a-index", T0),
    ):
        repo.save_baseline_segment(
            _segment(segment_id, target=target, start=start, end=start + timedelta(hours=1)),
            [_count(segment_id, scope="host:z", key_digest="z", first_ts=start, last_ts=start),
             _count(segment_id, scope="host:a", key_digest="a", first_ts=start, last_ts=start)],
            [_scope_hour(segment_id, scope="host:z", hour=start), _scope_hour(segment_id, scope="host:a", hour=start)],
        )
    assert [row["id"] for row in repo.baseline_segments()] == ["seg-a", "seg-b", "seg-z"]
    assert [(row["scope"], row["key_digest"]) for row in list(repo.baseline_counts("seg-a"))] == [
        ("host:a", "a"), ("host:z", "z"),
    ]
    assert [row["scope"] for row in list(repo.baseline_scope_hours("seg-a"))] == ["host:a", "host:z"]


BASELINE_TABLES = ("baseline_segment", "baseline_count", "baseline_scope_hour", "baseline_snapshot",
                   "baseline_snapshot_segment", "baseline_parent_host_boot", "baseline_parent_carry",
                   "baseline_observation")


def _shape(engine) -> dict:
    inspector = inspect(engine)
    shape = {}
    for table in BASELINE_TABLES:
        shape[table] = {
            "columns": sorted((col["name"], type(col["type"]).__name__, col["nullable"])
                              for col in inspector.get_columns(table)),
            "pk": inspector.get_pk_constraint(table)["constrained_columns"],
            "indexes": sorted((index["name"], tuple(index["column_names"]))
                              for index in inspector.get_indexes(table)),
        }
    return shape


def test_migration_and_metadata_define_the_same_baseline_tables(tmp_path):
    migrated = make_engine(tmp_path / "migrated.db")
    migrate(migrated)
    assert _shape(migrated) == _shape(_repo().engine)


def test_redundant_baseline_indexes_are_gone_and_the_key_id_index_exists():
    indexes = {table: {name for name, _ in shape["indexes"]} for table, shape in _shape(_repo().engine).items()}
    assert indexes["baseline_count"] == {"ix_baseline_count_key"}
    assert indexes["baseline_observation"] == {"ix_baseline_observation_first_event"}
    assert dict(_shape(_repo().engine)["baseline_count"]["indexes"])["ix_baseline_count_key"] == (
        "key_id", "scope_kind", "scope", "segment_id",
    )


def _seed_prevalence(repo: Repo) -> None:
    rows = {
        "seg-1": [("host", "host:a", "shared"), ("host", "host:b", "shared"), ("account", "account:x", "shared"),
                  ("host", "host:a", "other")],
        "seg-2": [("host", "host:a", "shared"), ("host", "host:c", "shared")],
        "seg-3": [("host", "host:d", "shared")],
    }
    for segment_id, keys in rows.items():
        repo.save_baseline_segment(
            _segment(segment_id),
            [_count(segment_id, scope_kind=kind, scope=scope, key_id=key_id, key_digest=f"{scope}|{key_id}")
             for kind, scope, key_id in keys],
            [_scope_hour(segment_id, scope_kind=kind, scope=scope) for kind, scope, key_id in keys
             if key_id == "shared"],
        )


def _snapshot_members(repo: Repo, hunt_id: str, segment_ids: list[str]) -> None:
    repo.create_hunt(hunt_id, {}, "d", "test")
    repo.save_baseline_snapshot(_snapshot(hunt_id, segment_ids=segment_ids, digest=f"snapshot-{hunt_id}"))


def test_prevalence_counts_distinct_scopes_of_one_kind_holding_a_key_id_in_the_given_segments():
    repo = _repo()
    _seed_prevalence(repo)
    _snapshot_members(repo, "two", ["seg-1", "seg-2"])
    _snapshot_members(repo, "three", ["seg-3"])
    _snapshot_members(repo, "all", ["seg-1", "seg-2", "seg-3"])
    _snapshot_members(repo, "empty", [])
    assert repo.baseline_key_prevalence("shared", "host", "two") == 3
    assert repo.baseline_key_prevalence("shared", "account", "two") == 1
    assert repo.baseline_key_prevalence("shared", "host", "three") == 1
    assert repo.baseline_key_prevalence("missing", "host", "two") == 0
    assert repo.baseline_key_prevalence("shared", "host", "empty") == 0
    assert repo.baseline_peer_scopes("host", "two") == 3
    history = repo.baseline_key_history("shared", "host", "host:a", "all")
    assert sorted(row["segment_id"] for row in history) == ["seg-1", "seg-2"]
    assert all(row["count"] == 3 for row in history)


def _plan(engine, statement) -> str:
    compiled = statement.compile(dialect=engine.dialect, compile_kwargs={"literal_binds": True})
    with engine.connect() as connection:
        return " | ".join(row[-1] for row in connection.execute(text(f"EXPLAIN QUERY PLAN {compiled}")))


def test_query_plans_serve_the_baseline_probes_from_indexes_without_temp_btrees(tmp_path):
    engine = make_engine(tmp_path / "plans.db")
    migrate(engine)
    hunt_id = "snapshot"
    plans = {
        "prevalence": _plan(engine, repo_module.baseline_prevalence_query("k", "host", hunt_id)),
        "peers": _plan(engine, repo_module.baseline_peer_scopes_query("host", hunt_id)),
        "history": _plan(engine, repo_module.baseline_key_history_query("k", "host", "host:a", hunt_id)),
        "scope_hours": _plan(engine, repo_module.baseline_scope_series_query("host", "host:a", hunt_id)),
    }
    assert "COVERING INDEX ix_baseline_count_key (key_id=? AND scope_kind=?)" in plans["prevalence"]
    assert "INDEX ix_baseline_count_key (key_id=? AND scope_kind=? AND scope=?)" in plans["history"]
    assert "COVERING INDEX ix_baseline_scope_hour_lookup (scope_kind=?)" in plans["peers"]
    assert "INDEX ix_baseline_scope_hour_lookup (scope_kind=? AND scope=?)" in plans["scope_hours"]
    for plan in plans.values():
        assert "COVERING INDEX sqlite_autoindex_baseline_snapshot_segment_1 (hunt_id=? AND segment_id=?)" in plan
        assert "TEMP B-TREE" not in plan and "SCAN" not in plan


class _Counted:
    """An input stream that records how far it has been consumed."""

    def __init__(self, rows):
        self.rows, self.consumed = rows, 0

    def __iter__(self):
        for row in self.rows:
            self.consumed += 1
            yield row


def _capture(engine) -> list[tuple[str, int]]:
    seen: list[tuple[str, int]] = []

    @event.listens_for(engine, "before_cursor_execute")
    def _record(_conn, _cursor, statement, parameters, _context, executemany):
        seen.append((statement, len(parameters) if executemany else 1))

    return seen


def _many_counts(segment_id: str, n: int, start: int = 0):
    for index in range(start, start + n):
        yield _count(segment_id, scope=f"host:h{index % 7}", key_digest=f"k{index:07d}", key_id=f"id{index}")


def test_segment_rows_stream_in_bounded_chunks_inside_one_transaction():
    repo = _repo()
    seen = _capture(repo.engine)
    counts, hours = _Counted(_many_counts("seg-b", 25)), _Counted([_scope_hour()])
    consumed_at_first_insert = []

    @event.listens_for(repo.engine, "before_cursor_execute")
    def _first(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("INSERT INTO baseline_count") and not consumed_at_first_insert:
            consumed_at_first_insert.append(counts.consumed)

    assert repo.save_baseline_segment(_segment(), counts, hours, chunk_size=10) is True
    batches = [size for statement, size in seen if statement.startswith("INSERT INTO baseline_count")]
    assert batches == [10, 10, 5]
    assert consumed_at_first_insert[0] <= 11       # the first chunk was written before the stream was drained
    assert len(list(repo.baseline_counts("seg-b"))) == 25


def test_a_bad_row_late_in_the_stream_rolls_back_the_whole_segment():
    repo = _repo()

    def counts():
        yield from _many_counts("seg-b", 30)
        yield _count(first_ts=T0 + timedelta(minutes=5), last_ts=T0 + timedelta(minutes=4), key_digest="late")

    with pytest.raises(ValueError, match="first_ts"):
        repo.save_baseline_segment(_segment(), counts(), [_scope_hour()], chunk_size=10)
    assert repo.baseline_segments() == [] and list(repo.baseline_counts("seg-b")) == []


def test_reads_are_keyset_paginated_generators():
    repo = _repo()
    repo.save_baseline_segment(_segment(), _many_counts("seg-b", 23), [_scope_hour()])
    seen = _capture(repo.engine)
    rows = repo.baseline_counts("seg-b", page_size=5)
    assert not isinstance(rows, list)
    listed = list(rows)
    assert len(listed) == 23 and len({row["key_digest"] for row in listed}) == 23
    assert [(row["scope"], row["key_digest"], row["bucket"]) for row in listed] == sorted(
        (row["scope"], row["key_digest"], row["bucket"]) for row in listed)
    selects = [statement for statement, _ in seen if statement.startswith("SELECT")]
    assert len(selects) == 5 and all("LIMIT" in statement for statement in selects)
    assert listed[0]["bucket"].tzinfo is not None and listed[0]["first_ts"].utcoffset() == timedelta(0)

    repo.create_hunt("h1", {}, "d", "test")
    repo.upsert_baseline_observations(_observation("h1", f"k{index:02d}") for index in range(12))
    pages = repo.baseline_observations("h1", page_size=5)
    assert [row["key_digest"] for row in pages] == [f"k{index:02d}" for index in range(12)]
    hours = [_scope_hour("seg-c", scope=f"host:{index:02d}") for index in range(7)]
    repo.save_baseline_segment(_segment("seg-c"), [], hours)
    assert [row["scope"] for row in repo.baseline_scope_hours("seg-c", page_size=3)] == [
        f"host:{index:02d}" for index in range(7)]


def test_observation_batch_upsert_is_one_transaction_and_never_clears_a_candidate():
    repo = _repo()
    repo.create_hunt("h1", {}, "d", "test")
    assert repo.upsert_baseline_observations([
        _observation("h1", "key-a", candidate_id="cand-a"), _observation("h1", "key-b"),
    ]) == 2
    repo.upsert_baseline_observations([_observation("h1", "key-a", window_count=5, candidate_id=None)])
    stored = {row["key_digest"]: row for row in repo.baseline_observations("h1")}
    assert stored["key-a"]["window_count"] == 5 and stored["key-a"]["candidate_id"] == "cand-a"
    repo.upsert_baseline_observation(_observation("h1", "key-a", candidate_id=None))
    assert next(repo.baseline_observations("h1"))["candidate_id"] == "cand-a"
    with pytest.raises(IntegrityError):
        repo.upsert_baseline_observations([
            _observation("h1", "key-c"), _observation("h1", "key-d", verdict="bogus"),
        ])
    assert {row["key_digest"] for row in repo.baseline_observations("h1")} == {"key-a", "key-b"}


@pytest.mark.parametrize(
    ("segment", "counts", "hours", "message"),
    [
        (_segment(start=T0.replace(tzinfo=None)), [], [], "timezone"),
        (_segment(created_at=(T0 + timedelta(days=1)).replace(tzinfo=None)), [], [], "timezone"),
        (_segment(bucket="week"), [], [], "bucket"),
        (_segment(), [_count(bucket=T0 + timedelta(days=1))], [], "bucket"),
        (_segment(), [_count(bucket=T0 + timedelta(hours=1))], [], "bucket"),
        (_segment(bucket="hour", end=T0 + timedelta(hours=2)), [_count(bucket=T0 + timedelta(hours=2))], [],
         "bucket"),
        (_segment(), [_count(first_ts=T0 - timedelta(minutes=1))], [], "first_ts"),
        (_segment(), [_count(last_ts=T0 + timedelta(hours=1))], [], "last_ts"),
        (_segment(), [_count(first_ts=T0 + timedelta(minutes=3))], [], "first_ts"),
        (_segment(), [_count(first_ts=T0.replace(tzinfo=None))], [], "timezone"),
        (_segment(), [_count(count=0)], [], "count"),
        (_segment(), [_count(scope_kind="")], [], "scope_kind"),
        (_segment(), [_count(segment_id="other")], [], "different segment"),
        (_segment(), [{**_count(), "unexpected": 1}], [], "column"),
        (_segment(), [{k: v for k, v in _count().items() if k != "key_id"}], [], "column"),
        (_segment(), [], [_scope_hour(hour=T0 + timedelta(minutes=30))], "hour-aligned"),
        (_segment(), [], [_scope_hour(hour=T0 + timedelta(hours=1))], "inside"),
        (_segment(), [], [_scope_hour(hour=T0 - timedelta(hours=1))], "inside"),
        (_segment(), [], [_scope_hour(events=-1)], "events"),
        ({**_segment(), "rows_digest": "x"}, [], [], "column"),
    ],
)
def test_segment_validation_rejects_bad_rows(segment, counts, hours, message):
    repo = _repo()
    with pytest.raises(ValueError, match=message):
        repo.save_baseline_segment(segment, counts, hours)
    assert repo.baseline_segments() == []


def test_non_utc_aware_times_are_stored_as_utc():
    repo = _repo()
    plus_two = timezone(timedelta(hours=2))
    repo.save_baseline_segment(
        _segment(start=T0.astimezone(plus_two), end=(T0 + timedelta(hours=1)).astimezone(plus_two)),
        [_count(first_ts=(T0 + timedelta(minutes=1)).astimezone(plus_two))], [_scope_hour()],
    )
    stored = repo.baseline_segments()[0]
    assert stored["start"] == T0 and stored["start"].utcoffset() == timedelta(0)
    assert next(repo.baseline_counts("seg-b"))["first_ts"] == T0 + timedelta(minutes=1)


@pytest.mark.slow
def test_one_million_count_rows_stream_through_the_api_and_probes_stay_indexed(tmp_path):
    repo = Repo(make_engine(tmp_path / "volume.db"))
    migrate(repo.engine)
    total, scopes, day = 1_000_000, 1000, T0

    def counts():
        for index in range(total):
            scope = index % scopes
            yield {
                "segment_id": "seg-volume", "scope_kind": "host", "scope": f"host:h{scope:04d}",
                "key_id": f"id{index // scopes:06d}", "key_digest": f"d{index:07d}", "key": {"k": index // scopes},
                "bucket": day, "count": 1 + index % 5, "first_ts": day + timedelta(seconds=index % 3600),
                "last_ts": day + timedelta(seconds=index % 3600),
            }

    started = time.perf_counter()
    assert repo.save_baseline_segment(
        _segment("seg-volume", start=day, end=day + timedelta(days=1), events_total=total), counts(),
        ({"segment_id": "seg-volume", "scope_kind": "host", "scope": f"host:h{scope:04d}", "hour": day,
          "events": 1} for scope in range(scopes)),
    )
    written = time.perf_counter() - started
    _snapshot_members(repo, "volume", ["seg-volume"])
    started = time.perf_counter()
    prevalence = repo.baseline_key_prevalence("id000500", "host", "volume")
    history = repo.baseline_key_history("id000500", "host", "host:h0007", "volume")
    peers = repo.baseline_peer_scopes("host", "volume")
    probed = time.perf_counter() - started
    print(f"wrote {total} baseline_count rows in {written:.1f}s; three probes in {probed * 1000:.1f}ms")
    assert prevalence == scopes and len(history) == 1 and peers == scopes
    assert written < 900 and probed < 2.0


def test_delete_hunt_keeps_an_event_another_hunts_observation_cites_as_its_first_event():
    repo = _repo()
    for hunt_id in ("h1", "h2"):
        repo.create_hunt(hunt_id, {}, "d", "test")
        repo.set_hunt_state(hunt_id, "canceled")
    with repo.engine.begin() as c:
        c.execute(schema.typed_event.insert(), [
            {"id": event_id, "hunt_id": "h1", "family": "process_exec", "ts": T0, "host": "web01",
             "event": {}, "raw_ids": [], "normalizer": "fixture@1"}
            for event_id in ("cited-by-h2", "only-h1")
        ])
    repo.upsert_baseline_observations([
        _observation("h1", "key-a", first_event_id="only-h1"),
        _observation("h2", "key-b", first_event_id="cited-by-h2"),
    ])

    repo.delete_hunt("h1", actor="test")

    with repo.engine.connect() as c:
        owners = dict(c.execute(select(schema.typed_event.c.id, schema.typed_event.c.hunt_id)).all())
    assert owners == {"cited-by-h2": "h2"}
    assert next(repo.baseline_observations("h2"))["first_event_id"] == "cited-by-h2"


def test_delete_hunt_observation_citation_lookup_is_index_served(tmp_path):
    engine = make_engine(tmp_path / "delete-plan.db")
    migrate(engine)
    plan = _plan(engine, repo_module.observation_citations_query("h1"))
    assert "ix_baseline_observation_first_event" in plan and "TEMP B-TREE" not in plan
    assert "SCAN baseline_observation" not in plan
