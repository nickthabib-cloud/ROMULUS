"""Persistent baseline segments, frozen snapshots, and lossless window observations."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from romulus.store import repo as repo_module
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


def test_0010_upgrade_and_downgrade_preserve_existing_data(tmp_path):
    engine = make_engine(tmp_path / "migration.db")
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0009")
        conn.exec_driver_sql(
            "INSERT INTO hunt (id, created_at, created_by, manifest, manifest_digest, execution_state) "
            "VALUES ('h1', '2026-01-01', 'test', '{}', 'd', 'planned')"
        )
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0010")
    names = set(inspect(engine).get_table_names())
    assert {"baseline_segment", "baseline_count", "baseline_scope_hour",
            "baseline_snapshot", "baseline_observation"} <= names
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO baseline_segment "
            "(id, site, target, spec_id, spec_version, key_version, normalizer, start, end, origin, "
            "exclusion_digest, excluded_keys, hunted, events_total, status, created_at) VALUES "
            "('s1', 'site', 'idx', 'bl.exec_path', '1', '1', 'n@1', '2026-01-01', '2026-01-02', "
            "'lookback', 'none', '[]', 0, 1, 'active', '2026-01-03')"
        )
    with engine.begin() as conn:
        command.downgrade(_alembic_config(conn), "0009")
        assert conn.exec_driver_sql("SELECT id FROM hunt").scalar_one() == "h1"
    assert "baseline_segment" not in set(inspect(engine).get_table_names())


def test_segment_is_insert_only_except_for_status_and_children_are_stable():
    repo = _repo()
    assert repo.save_baseline_segment(_segment(), [_count()], [_scope_hour()]) is True
    assert repo.save_baseline_segment(
        _segment(events_total=999),
        [_count(count=999)],
        [_scope_hour(events=999)],
    ) is False
    assert repo.baseline_segments()[0]["events_total"] == 3
    assert repo.baseline_counts("seg-b")[0]["count"] == 3
    assert repo.baseline_scope_hours("seg-b")[0]["events"] == 3
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
    assert repo.save_baseline_snapshot(_snapshot("h1")) is True
    assert repo.save_baseline_snapshot(_snapshot("h1", digest="changed", segment_ids=[])) is False
    stored = repo.baseline_snapshot("h1")
    assert stored["digest"] == "snap-one" and stored["segment_ids"] == ["seg-b"]


def test_observation_upsert_uses_full_window_key_and_keeps_every_key():
    repo = _repo()
    repo.create_hunt("h1", {}, "d", "test")
    repo.upsert_baseline_observation(_observation("h1", "key-b"))
    repo.upsert_baseline_observation(_observation(
        "h1", "key-b", window_count=2, verdict="rare", candidate_id="candidate-1",
    ))
    repo.upsert_baseline_observation(_observation("h1", "key-a", scope="host:web02"))
    rows = repo.baseline_observations("h1")
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
        repo.save_baseline_snapshot(_snapshot(hunt_id, digest=f"snap-{hunt_id}"))
        repo.upsert_baseline_observation(_observation(hunt_id))

    counts = repo.delete_hunt("h1", actor="test")

    assert counts["baseline_snapshots"] == 1 and counts["baseline_observations"] == 1
    assert repo.baseline_snapshot("h1") is None and repo.baseline_observations("h1") == []
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
            [_count(segment_id, scope="host:z", key_digest="z"),
             _count(segment_id, scope="host:a", key_digest="a")],
            [_scope_hour(segment_id, scope="host:z"), _scope_hour(segment_id, scope="host:a")],
        )
    assert [row["id"] for row in repo.baseline_segments()] == ["seg-a", "seg-b", "seg-z"]
    assert [(row["scope"], row["key_digest"]) for row in repo.baseline_counts("seg-a")] == [
        ("host:a", "a"), ("host:z", "z"),
    ]
    assert [row["scope"] for row in repo.baseline_scope_hours("seg-a")] == ["host:a", "host:z"]


BASELINE_TABLES = ("baseline_segment", "baseline_count", "baseline_scope_hour", "baseline_snapshot",
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


def test_prevalence_counts_distinct_scopes_of_one_kind_holding_a_key_id_in_the_given_segments():
    repo = _repo()
    _seed_prevalence(repo)
    assert repo.baseline_key_prevalence("shared", "host", ["seg-1", "seg-2"]) == 3
    assert repo.baseline_key_prevalence("shared", "account", ["seg-1", "seg-2"]) == 1
    assert repo.baseline_key_prevalence("shared", "host", ["seg-3"]) == 1
    assert repo.baseline_key_prevalence("missing", "host", ["seg-1"]) == 0
    assert repo.baseline_key_prevalence("shared", "host", []) == 0
    assert repo.baseline_peer_scopes("host", ["seg-1", "seg-2"]) == 3
    history = repo.baseline_key_history("shared", "host", "host:a", ["seg-1", "seg-2", "seg-3"])
    assert sorted(row["segment_id"] for row in history) == ["seg-1", "seg-2"]
    assert all(row["count"] == 3 for row in history)


def _plan(engine, statement) -> str:
    compiled = statement.compile(dialect=engine.dialect, compile_kwargs={"literal_binds": True})
    with engine.connect() as connection:
        return " | ".join(row[-1] for row in connection.execute(text(f"EXPLAIN QUERY PLAN {compiled}")))


def test_query_plans_serve_the_baseline_probes_from_indexes_without_temp_btrees(tmp_path):
    engine = make_engine(tmp_path / "plans.db")
    migrate(engine)
    segments = ["seg-1", "seg-2", "seg-3"]
    plans = {
        "prevalence": _plan(engine, repo_module.baseline_prevalence_query("k", "host", segments)),
        "peers": _plan(engine, repo_module.baseline_peer_scopes_query("host", segments)),
        "history": _plan(engine, repo_module.baseline_key_history_query("k", "host", "host:a", segments)),
        "scope_hours": _plan(engine, repo_module.baseline_scope_series_query("host", "host:a", segments)),
    }
    assert "COVERING INDEX ix_baseline_count_key (key_id=? AND scope_kind=?)" in plans["prevalence"]
    assert "INDEX ix_baseline_count_key (key_id=? AND scope_kind=? AND scope=? AND segment_id=?)" in plans["history"]
    assert "COVERING INDEX ix_baseline_scope_hour_lookup (scope_kind=?)" in plans["peers"]
    assert "INDEX ix_baseline_scope_hour_lookup (scope_kind=? AND scope=? AND segment_id=?)" in plans["scope_hours"]
    for plan in plans.values():
        assert "TEMP B-TREE" not in plan and "SCAN baseline" not in plan
