"""Finding pages keep priority order across opaque keyset cursors."""
import base64
import json
import re
from datetime import timedelta

import pytest
from alembic import command
from sqlalchemy import event

from romulus.store import schema as t
from romulus.store.db import make_engine
from romulus.store.repo import Repo
from romulus.web.finding_order import finding_order, finding_page
from tests import test_web_agent_a6
from tests.test_agent_store_r2 import NOW, _candidate, _repo
from tests.test_local_content_migration import config

web_setup = test_web_agent_a6.setup


def _seed(repo, rows):
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert(), [dict(row, created_at=NOW) for row in rows])


def test_urgent_findings_lead_the_default_and_filtered_pages(web_setup):
    client, repo, _, _, _, _ = web_setup
    test_web_agent_a6.run_row(repo)
    _seed(repo, [_candidate(f"aaa-lead-{i:03}") for i in range(400)] + [
        _candidate("zzz-urgent-1", lane="urgent"), _candidate("zzz-urgent-2", lane="urgent")])
    rows, remaining, cursor = finding_page(repo, "h1")
    assert [row["id"] for row in rows[:2]] == ["zzz-urgent-1", "zzz-urgent-2"]
    assert len(rows) == 50 and remaining == 353 and cursor
    page = client.get("/hunts/h1")
    assert page.status_code == 200
    visible = re.findall(r'data-finding-id="([^"]+)"', page.text)
    assert len(visible) == 50 and visible[:2] == ["zzz-urgent-1", "zzz-urgent-2"]
    filtered_page = client.get("/hunts/h1", params={"lane": "urgent"})
    assert re.findall(r'data-finding-id="([^"]+)"', filtered_page.text) == [
        "zzz-urgent-1", "zzz-urgent-2"]
    filtered, _, _ = finding_page(repo, "h1", predicates=(t.candidate.c.lane == "urgent",))
    assert [row["id"] for row in filtered] == ["zzz-urgent-1", "zzz-urgent-2"]


def test_thousand_equal_keys_page_without_gaps_or_duplicates():
    repo = _repo()
    ids = [f"f{i:04}" for i in range(1000)]
    _seed(repo, [_candidate(cid) for cid in reversed(ids)])
    seen, cursor = [], ""
    while True:
        rows, remaining, cursor = finding_page(repo, "h1", after=cursor)
        assert len(rows) <= 50
        seen.extend(row["id"] for row in rows)
        assert remaining == 1000 - len(seen)
        if not cursor:
            break
    assert seen == ids


def test_old_hunt_order_matches_lane_priority_time_with_id_tiebreak():
    repo = _repo()
    rows = [_candidate(f"f{i:02}", lane=("lead", "high", "urgent")[i % 3]) | {
        "priority": float(i % 4), "ts": NOW + timedelta(seconds=i % 5)} for i in range(47)]
    _seed(repo, reversed(rows))
    expected = sorted(rows, key=lambda row: (
        {"urgent": 0, "high": 1, "lead": 2}[row["lane"]], -row["priority"], row["ts"], row["id"]))
    actual, remaining, cursor = finding_page(repo, "h1")
    assert [row["id"] for row in actual] == [row["id"] for row in expected]
    assert remaining == 0 and cursor is None


def test_nullable_legacy_keys_sort_last_and_page_deterministically():
    engine = make_engine(":memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE candidate(id TEXT, hunt_id TEXT, lane TEXT, priority FLOAT, ts TEXT)")
        connection.exec_driver_sql("INSERT INTO candidate VALUES(?, 'h1', ?, ?, ?)", [
            ("a-null-priority", "urgent", None, "2030-01-01 00:00:00.000000"),
            ("b-null-time", "urgent", 2.0, None),
            ("c-time", "urgent", 2.0, "2030-01-01 00:00:00.000000"),
            ("g-max-time", "urgent", 2.0, "9999-12-31 23:59:59.999999"),
            ("d-both-null", "urgent", None, None),
            ("e-low-priority", "urgent", 1.0, "2030-01-01 00:00:00.000000"),
            ("f-high", "high", 100.0, "2030-01-01 00:00:00.000000"),
        ])
    columns = tuple(t.candidate.c[key] for key in ("id", "hunt_id", "lane", "priority", "ts"))
    seen, cursor = [], ""
    while True:
        rows, _, cursor = finding_page(Repo(engine), "h1", after=cursor, limit=1, columns=columns)
        seen.extend(row["id"] for row in rows)
        if not cursor:
            break
    assert seen == ["c-time", "g-max-time", "b-null-time", "e-low-priority", "a-null-priority",
                    "d-both-null", "f-high"]


def _cursor(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


BAD_CURSORS = ["not-a-cursor", "x" * 4097, _cursor(None), _cursor([]), _cursor([0, 1, None, "x", "extra"]),
    _cursor([True, 1, None, "x"]), _cursor([4, 1, None, "x"]), _cursor([0, "bad", None, "x"]),
    _cursor([0, float("nan"), None, "x"]), _cursor([0, float("inf"), None, "x"]),
    _cursor([0, 1, "not-a-time", "x"]), _cursor([0, 1, "0001-01-01T00:00:00+01:00", "x"]),
    _cursor([0, 1, "9999-12-31T23:59:59-01:00", "x"]),
    _cursor([0, 1, None, ""]), _cursor([0, 1, None, []])]


@pytest.mark.parametrize("cursor", BAD_CURSORS)
def test_malformed_cursor_is_rejected_before_querying(cursor):
    repo = _repo()
    statements = []
    event.listen(repo.engine, "before_cursor_execute", lambda *args: statements.append(args[2]))
    with pytest.raises(ValueError, match="cursor"):
        finding_page(repo, "h1", after=cursor)
    assert not statements


def test_malformed_cursor_has_http_400(web_setup):
    client = web_setup[0]
    test_web_agent_a6.run_row(web_setup[1])
    for cursor in BAD_CURSORS:
        response = client.get("/hunts/h1", params={"after": cursor})
        assert response.status_code == 400, (cursor, response.status_code)


SQL_UNSAFE_CURSORS = [
    _cursor([0, 9223372036854775808, None, "id"]),
    _cursor([0, -9223372036854775809, None, "id"]),
    _cursor([0, 1, None, "\ud800"]),
    _cursor([0, 1, None, "\udfff"]),
]


@pytest.mark.parametrize("cursor", SQL_UNSAFE_CURSORS,
                         ids=["integer-overflow", "integer-underflow", "high-surrogate", "low-surrogate"])
def test_sql_unsafe_cursor_is_rejected_before_querying(cursor):
    repo = _repo()
    statements = []
    event.listen(repo.engine, "before_cursor_execute", lambda *args: statements.append(args[2]))
    with pytest.raises(ValueError, match="cursor"):
        finding_page(repo, "h1", after=cursor)
    assert not statements


def test_sql_unsafe_cursors_have_http_400(web_setup):
    client = web_setup[0]
    test_web_agent_a6.run_row(web_setup[1])
    for cursor in SQL_UNSAFE_CURSORS:
        assert client.get("/hunts/h1", params={"after": cursor}).status_code == 400


def test_order_query_uses_covering_sort_index_and_bounded_seek():
    repo = _repo()
    _seed(repo, [_candidate(f"f{i:04}") for i in range(120)])
    statements = []
    event.listen(repo.engine, "before_cursor_execute", lambda _c, _x, sql, params, *_: statements.append((sql, params)))
    _, _, cursor = finding_page(repo, "h1")
    statements.clear()
    finding_page(repo, "h1", after=cursor)
    with repo.engine.connect() as connection:
        plans = [" ".join(str(row) for row in connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params))
                 for sql, params in list(statements)]
    assert plans and all("ix_candidate_finding_order" in plan for plan in plans)
    assert all("TEMP B-TREE" not in plan for plan in plans)
    assert "id>?" in plans[0]
    assert all("AND <expr>" in plan for plan in plans)
    order, keys, _ = finding_order(_candidate("f", lane="urgent"))
    assert len(order) == 4 and len(keys) == 4


@pytest.mark.parametrize("foreign_keys", [False, True])
def test_migration_order_indexes_upgrade_downgrade_reupgrade(tmp_path, foreign_keys):
    engine = make_engine(tmp_path / "order.sqlite")
    with engine.begin() as connection:
        connection.exec_driver_sql(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
        command.upgrade(config(connection), "0035")
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "test")
    _seed(repo, [_candidate("z", lane="urgent"), _candidate("a")])
    names = {"ix_candidate_finding_order", "ix_agent_change_row_seq"}
    for version in ("0036", "0035", "0036"):
        with engine.begin() as connection:
            (command.downgrade if version == "0035" else command.upgrade)(config(connection), version)
            indexes = set(connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='index'").scalars())
            assert (names <= indexes) if version == "0036" else not names.intersection(indexes)
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert connection.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
        if version == "0036":
            assert [row["id"] for row in finding_page(repo, "h1")[0]] == ["z", "a"]
    engine.dispose()
