"""Render cursors, terminal streams and housekeeping changes."""
import asyncio
import re
import threading
from datetime import timedelta

import pytest
from sqlalchemy import event as sql_event

from romulus.store import schema as t
from romulus.store.db import utcnow
from romulus.web.agent_views import live_events
from tests import test_web_agent_a6 as web_fixtures
from tests.test_web_agent_a6 import Connected, csrf, run_row, unpack

setup = web_fixtures.setup


async def no_sleep(_):
    pytest.fail("terminal streams must not sleep")


def collect(repo, after_seq=0, sleep=no_sleep):
    async def consume():
        return [unpack(value) async for value in live_events(
            repo, Connected(), "h1", sleep, after_seq=after_seq)]
    return asyncio.run(consume())


def test_terminal_page_and_render_cursor_do_not_replay_a_thousand_rows(setup):
    client, repo, cid, *_ = setup
    run_row(repo)
    row = repo.candidate(cid)
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert(), [{**row, "id": f"old-{i:04}"} for i in range(1000)])
    cursor = repo.agent_change_max_seq("h1")
    html = client.get("/hunts/h1").text
    assert 'id="live"' not in html
    assert f'data-stream-cursor="{cursor}"' in html
    assert not any(name in {"finding", "agent_run"} for name, _ in collect(repo, cursor))


def test_live_page_streams_only_post_render_rows_and_marks_existing_revisions(setup):
    client, repo, cid, *_ = setup
    run_row(repo, "running", lease_until=utcnow() + timedelta(minutes=10))
    html = client.get("/hunts/h1").text
    assert 'id="live"' in html
    cursor = int(re.search(r'data-stream-cursor="(\d+)"', html).group(1))
    assert f'/stream?after_seq={cursor}' in html
    old = repo.candidate(cid)
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().where(t.candidate.c.id == cid).values(claim="revised now"))
        connection.execute(t.candidate.insert().values(**{**old, "id": "new-after-render"}))
    run_row(repo, "completed")
    findings = {row["id"]: row for name, row in collect(repo, cursor) if name == "finding"}
    assert set(findings) == {cid, "new-after-render"}
    assert findings[cid]["revised"] and not findings["new-after-render"]["revised"]


def test_revision_of_finding_inserted_during_render_is_not_suppressed(setup, monkeypatch):
    client, repo, cid, *_ = setup
    run_row(repo, "running")
    original_max = repo.agent_change_max_seq
    inserted = False

    def insert_after_cursor(hunt_id):
        nonlocal inserted
        cursor = original_max(hunt_id)
        if not inserted:
            inserted = True
            row = repo.candidate(cid)
            with repo.engine.begin() as connection:
                connection.execute(t.candidate.insert().values(
                    **{**row, "id": "render-race", "claim": "Shown before revision"}))
        return cursor

    monkeypatch.setattr(repo, "agent_change_max_seq", insert_after_cursor)
    html = client.get("/hunts/h1").text
    assert 'data-finding-id="render-race"' in html and "Shown before revision" in html
    cursor = int(re.search(r'data-stream-cursor="(\d+)"', html).group(1))
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().where(t.candidate.c.id == "render-race").values(
            claim="Revised after render"))
    run_row(repo, "completed")
    findings = [row for name, row in collect(repo, cursor) if name == "finding"]
    assert len(findings) == 1
    assert findings[0]["claim"] == "Revised after render"
    assert findings[0]["revised"] is True  # The browser already knows this rendered ID.


@pytest.mark.parametrize("state", ["pending", "running"])
def test_expired_agent_is_terminal_only_for_stream(setup, state):
    client, repo, *_ = setup
    run_row(repo, state, lease_until=utcnow() - timedelta(seconds=1))
    assert 'id="live"' not in client.get("/hunts/h1").text
    assert collect(repo)[-1][0] == "end"
    assert repo.agent_run("h1")["state"] == state


def test_stream_database_work_is_off_event_loop_and_counts_only_when_drained(setup, monkeypatch):
    _, repo, cid, *_ = setup
    row = repo.candidate(cid)
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert(), [{**row, "id": f"bulk-{i:04}"} for i in range(410)])
    loop_thread = threading.get_ident()
    calls = []
    def check_thread(*_):
        assert threading.get_ident() != loop_thread, "database query on event loop"
    original = repo.lane_counts
    def counts(*args):
        calls.append(1)
        return original(*args)
    monkeypatch.setattr(repo, "lane_counts", counts)
    sql_event.listen(repo.engine, "before_cursor_execute", check_thread)
    try:
        events = collect(repo)
    finally:
        sql_event.remove(repo.engine, "before_cursor_execute", check_thread)
    assert len(calls) == 1
    assert sum(name == "state" for name, _ in events) == 1
    assert sum(name == "finding" for name, _ in events) == 411


def test_refusal_banner_accepts_only_server_codes_and_stream_rejects_invalid_cursor(setup):
    client, repo, *_ = setup
    assert "FAKE RESULT" not in client.get("/hunts/h1?agent_message=FAKE%20RESULT").text
    run_row(repo, "running", lease_until=utcnow() + timedelta(minutes=10))
    response = client.post("/hunts/h1/agent/reassess", data={"csrf": csrf(client)}, follow_redirects=False)
    assert response.headers["location"].endswith("?agent_message=busy")
    assert "active worker lease" in client.get(response.headers["location"]).text
    for cursor in ("bad", "-1", "1.5", "9" * 100):
        assert client.get(f"/hunts/h1/stream?after_seq={cursor}").status_code == 400


def test_actual_lease_heartbeat_writes_no_change_rows(setup):
    _, repo, *_ = setup
    run_row(repo, "running", lease_until=None)
    now = utcnow()
    lease = repo.claim_agent_lease("h1", 600, now=now)
    cursor = repo.agent_change_max_seq("h1")
    repo.heartbeat_agent_lease("h1", 600, now=now + timedelta(seconds=1), owner_token=lease["lease_owner"])
    assert repo.agent_change_max_seq("h1") == cursor
    repo.save_agent_run({"hunt_id": "h1", "state": "completed"})
    assert repo.agent_change_max_seq("h1") > cursor
