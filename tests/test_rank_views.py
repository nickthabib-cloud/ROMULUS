"""The web findings page, the agent dossier and the agent's finding index list findings in report order."""
from __future__ import annotations

import base64
import json
import re
from datetime import timedelta

import pytest
from alembic import command
from sqlalchemy import event, select

from romulus.agent import dossier as dossier_module
from romulus.agent.dossier import build_dossier
from romulus.agent.toolbox import Toolbox
from romulus.hunt.rank import PASS_BEFORE_EXPANSION, PASS_FINAL, compute_rank_pass, rank_unranked
from romulus.report.markdown import ranked_sections
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from romulus.web.finding_order import finding_page, ranked_finding_page
from tests import test_web_agent_a6
from tests.test_evidence_rank import END, START, _insert, _row
from tests.test_local_content_migration import config

web_setup = test_web_agent_a6.setup


def _repo(engine=None):
    """A hunt whose manifest a report can be built from."""
    if engine is None:
        engine = make_engine(":memory:")
        migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": START.isoformat(), "end": END.isoformat()}, "style": "sweep",
                            "original_input": "", "targets": []}, "d", "test")
    return repo


def _hunt_rows(hunt_id="h1", filler=0):
    """Confirmed, reported (two tactics on one host), ranked-not-reported, context and suppressed findings."""
    rows = [
        _row("c-urgent", "r.confirmed", lane="urgent", host="quiet", hunt_id=hunt_id),
        _row("t-exec", "r.exec", host="h-t", attack=["T1059"], hunt_id=hunt_id),
        _row("t-cred", "r.cred", lane="high", host="h-t", attack=["T1003"], ts=START + timedelta(hours=5),
             hunt_id=hunt_id),
        _row("p-single", "r.single", lane="high", host="lonely", hunt_id=hunt_id),
        _row("p-lead", "r.lead", host="other", ts=START + timedelta(hours=2), hunt_id=hunt_id),
        _row("x-context", "r.ctx", lane="context", host="h-t", hunt_id=hunt_id),
        _row("x-suppressed", "r.sup", lane="suppressed", host="h-t", hunt_id=hunt_id),
    ]
    rows += [_row(f"f-{index:04}", f"r.f{index % 5}", lane=("high", "lead")[index % 2], host=f"fill-{index % 9}",
                  ts=START + timedelta(minutes=7 * index), hunt_id=hunt_id) for index in range(filler)]
    return rows


def _ranked_repo(filler=0, *, agent=True):
    repo = _repo()
    _insert(repo, _hunt_rows(filler=filler))
    compute_rank_pass(repo, "h1", PASS_FINAL)
    if agent:
        # an AI agent's proposal stored after the pass: listed after every ranked finding
        _insert(repo, [_row("z-agent", "agent.proposal", host="h-t", provenance="agent")])
    return repo


def _walk(repo, limit):
    seen, cursor, remaining_seen = [], "", []
    while True:
        rows, remaining, cursor = ranked_finding_page(repo, "h1", pass_no=PASS_FINAL, after=cursor, limit=limit)
        seen.extend(rows)
        remaining_seen.append(remaining)
        if not cursor:
            return seen, remaining_seen


def _report_order(repo):
    """The report's own section order (`ranked_sections`) over the ranks the report reads."""
    rows = [row for row in repo.candidates("h1") if row["lane"] in ("urgent", "high", "lead")]
    stored = repo.finding_ranks_for("h1", PASS_FINAL, [row["id"] for row in rows])
    late = rank_unranked(repo, "h1", [row for row in rows if row["id"] not in stored])
    findings = [{"id": row["id"], "lane": row["lane"], "rank": (stored.get(row["id"]) or late[row["id"]])["score"],
                 "reported": bool((stored.get(row["id"]) or late[row["id"]])["reported"]),
                 "observed_at": str(row["ts"])} for row in rows]
    confirmed, reported, pool = ranked_sections({"findings": findings})
    return [finding["id"] for finding in (*confirmed, *reported, *pool)]


def _section(rows):
    return {row["id"]: row["section"] for row in rows}


# -- publication and migration --------------------------------------------------------------------------------------
@pytest.mark.parametrize("pass_no", [PASS_BEFORE_EXPANSION, PASS_FINAL])
def test_a_pass_publishes_each_findings_report_section(pass_no):
    repo = _repo()
    _insert(repo, _hunt_rows())
    compute_rank_pass(repo, "h1", pass_no)
    with repo.engine.connect() as connection:
        sections = dict(connection.execute(select(t.finding_rank.c.candidate_id, t.finding_rank.c.section).where(
            t.finding_rank.c["pass"] == pass_no)).all())
    assert sections == {"c-urgent": 0, "t-exec": 1, "t-cred": 1, "p-single": 2, "p-lead": 2}


@pytest.mark.parametrize("foreign_keys", [False, True])
def test_the_migration_backfills_sections_and_round_trips(tmp_path, foreign_keys):
    engine = make_engine(tmp_path / "sections.sqlite")
    with engine.begin() as connection:
        connection.exec_driver_sql(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
        command.upgrade(config(connection), "0038")
    _insert(_repo(engine), [_row(cid, "r", lane=lane) for cid, lane in (
        ("u", "urgent"), ("r", "high"), ("n", "lead"), ("gone", "lead"))])
    with engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM candidate WHERE id = 'gone'")
        for position, (cid, reported) in enumerate((("u", 1), ("r", 1), ("n", 0), ("gone", 1)), 1):
            connection.exec_driver_sql(
                "INSERT INTO finding_rank(hunt_id, \"pass\", candidate_id, position, score, reported, entity_kind, "
                "entity, reasons) VALUES('h1', 2, ?, ?, ?, ?, NULL, NULL, '[]')", (cid, position, 100.0 - position,
                                                                                      reported))
    names = {"ix_finding_rank_section", "ix_candidate_provenance_order"}
    for version in ("0039", "0038", "0039"):
        with engine.begin() as connection:
            (command.downgrade if version == "0038" else command.upgrade)(config(connection), version)
            indexes = set(connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='index'").scalars())
            columns = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(finding_rank)")}
            if version == "0039":
                assert names <= indexes and "section" in columns
                assert dict(connection.exec_driver_sql("SELECT candidate_id, section FROM finding_rank").all()) == {
                    "u": 0, "r": 1, "n": 2, "gone": 1}
            else:
                assert not names & indexes and "section" not in columns
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert connection.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
    engine.dispose()


# -- the web page ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("limit", [1, 3, 50])
def test_the_page_follows_the_report_order_then_lists_unranked_findings(limit):
    repo = _ranked_repo(filler=40)
    seen, remaining = _walk(repo, limit)
    ids = [row["id"] for row in seen]
    assert len(ids) == len(set(ids)) == 46
    report = _report_order(repo)
    assert ids[:-1] == [cid for cid in report if cid != "z-agent"]
    assert ids[-1] == "z-agent" and seen[-1]["section"] is None and seen[-1]["score"] is None
    assert "x-context" not in ids and "x-suppressed" not in ids
    sections = [row["section"] for row in seen[:-1]]
    assert sections == sorted(sections) and sections[0] == 0
    # each page's count is exactly what the following pages list
    assert remaining == [max(0, len(ids) - limit * (page + 1)) for page in range(len(remaining))]


def test_a_hunt_whose_findings_are_all_unranked_still_lists_every_one():
    repo = _repo()
    _insert(repo, _hunt_rows())
    compute_rank_pass(repo, "h1", PASS_FINAL)
    with repo.engine.begin() as connection:
        connection.execute(t.finding_rank.delete().where(t.finding_rank.c.candidate_id != "p-lead"))
    seen, remaining = _walk(repo, 2)
    # the unranked confirmed finding comes before the ranked unreported one, the other unranked ones after it
    assert [row["id"] for row in seen] == ["c-urgent", "p-lead", "p-single", "t-cred", "t-exec"]
    assert remaining == [3, 1, 0]


def test_an_inconsistent_count_never_hides_a_finding():
    repo = _ranked_repo()
    # a ranked row whose finding left the ranked lanes makes "ranked-lane findings less ranked rows" undercount
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().where(t.candidate.c.id == "p-lead").values(lane="context"))
    ids = [row["id"] for row in _walk(repo, 2)[0]]
    assert "z-agent" in ids and len(ids) == len(set(ids))


@pytest.mark.parametrize("values", [
    ["r", 3, 1], ["r", 0, 0], ["r", -1, 1], ["r", True, 1], ["r", 0, 2**63], ["r", 0], ["t", 0, 2, 1.0, None, "a"],
    ["t", 1, 2, 1.0, None], ["x", 0, 1], [], ["r", "0", 1],
])
def test_malformed_report_order_cursors_are_rejected(values):
    repo = _ranked_repo()
    after = base64.urlsafe_b64encode(json.dumps(values).encode()).decode().rstrip("=") if values else "W10"
    with pytest.raises(ValueError, match="invalid findings cursor"):
        ranked_finding_page(repo, "h1", pass_no=PASS_FINAL, after=after)


def _plans(repo, call):
    statements = []

    def record(_connection, _cursor, sql, params, *_):
        statements.append((sql, params))

    event.listen(repo.engine, "before_cursor_execute", record)
    try:
        call()
    finally:
        event.remove(repo.engine, "before_cursor_execute", record)
    with repo.engine.connect() as connection:
        return [(sql, " ".join(str(row) for row in connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params)))
                for sql, params in statements]


def test_report_order_pages_seek_the_section_index():
    repo = _ranked_repo(filler=200)
    _, _, cursor = ranked_finding_page(repo, "h1", pass_no=PASS_FINAL, limit=20)
    plans = _plans(repo, lambda: ranked_finding_page(repo, "h1", pass_no=PASS_FINAL, after=cursor, limit=20))
    ordered = [plan for sql, plan in plans if "ORDER BY" in sql]
    assert ordered and all("ix_finding_rank_section" in plan for plan in ordered)
    assert all("TEMP B-TREE" not in plan for plan in ordered)


def test_the_agent_findings_page_reads_the_provenance_index():
    repo = _ranked_repo(filler=200)
    plans = _plans(repo, lambda: finding_page(repo, "h1", predicates=(t.candidate.c.provenance == "agent",)))
    assert plans and all("ix_candidate_provenance_order (hunt_id=? AND provenance=?" in plan for _, plan in plans)
    assert all("TEMP B-TREE" not in plan for _, plan in plans)


def test_a_large_hunt_pages_completely_in_report_order():
    repo = _ranked_repo(filler=6_000)
    seen, remaining = _walk(repo, 200)
    ids = [row["id"] for row in seen]
    assert len(ids) == len(set(ids)) == 6_006 and ids[-1] == "z-agent"
    keys = [(row["section"], row["position"]) for row in seen[:-1]]
    assert keys == sorted(keys)
    assert remaining[0] == 6_006 - 200 and remaining[-1] == 0


def _visible(client, **params):
    page = client.get("/hunts/h1", params=params)
    assert page.status_code == 200
    return page.text, re.findall(r'data-finding-id="([^"]+)"', page.text)


def _copy_into(web_repo, repo):
    with repo.engine.connect() as read, web_repo.engine.begin() as write:
        write.execute(t.candidate.delete())
        for table in (t.candidate, t.finding_rank, t.entity_rank):
            rows = [dict(row) for row in read.execute(select(table)).mappings()]
            if rows:
                write.execute(table.insert(), rows)


def test_the_hunt_page_lists_report_order_with_sections_and_keeps_lane_views(web_setup):
    client, web_repo, _, _, _, _ = web_setup
    _copy_into(web_repo, _ranked_repo(filler=60))
    text, ids = _visible(client)
    assert len(ids) == 50 and ids[0] == "c-urgent"
    assert text.index(">confirmed<") < text.index(">reported<") < text.index(">ranked, not reported<")
    assert "report order" in text and "Rule estimate" in text and "host:h-t" in text
    cursor = re.search(r'href="\?lane=&amp;after=([^"]+)"', text).group(1)
    rest_text, rest = _visible(client, after=cursor)
    assert rest[-1] == "z-agent" and "not ranked (stored after the last ranking pass)" in rest_text
    assert len(set(ids + rest)) == 66
    # lanes keep the rule estimate's order, and context and suppressed records have their own views
    assert _visible(client, lane="urgent")[1] == ["c-urgent"]
    assert _visible(client, lane="suppressed")[1] == ["x-suppressed"]
    assert _visible(client, lane="context")[1] == ["x-context"]
    assert client.get("/hunts/h1", params={"after": "W10"}).status_code == 400
    # a lane cursor is not a report-order cursor
    lead_cursor = finding_page(web_repo, "h1", lane="lead", limit=1)[2]
    assert client.get("/hunts/h1", params={"after": lead_cursor}).status_code == 400


def test_a_hunt_without_ranking_or_agent_run_is_paged_in_the_rule_estimate_order(web_setup):
    client, web_repo, _, _, _, _ = web_setup
    unranked = _repo()
    _insert(unranked, _hunt_rows(filler=60))
    _copy_into(web_repo, unranked)
    text, ids = _visible(client)
    assert len(ids) == 50 and ids[0] == "c-urgent" and "report order" not in text
    cursor = re.search(r'href="\?lane=&amp;after=([^"]+)"', text).group(1)
    _, rest = _visible(client, after=cursor)
    assert len(set(ids + rest)) == 65 and "x-suppressed" not in ids + rest


# -- the agent dossier and its finding index ------------------------------------------------------------------------
def test_the_dossier_lists_findings_in_report_order_with_their_rank():
    repo = _ranked_repo(filler=10)
    dossier = build_dossier(repo, "h1", token_budget=200_000)
    findings = [item for page in dossier.pages for item in page.get("findings", [])]
    aliases = {item["alias"]: item for item in findings}
    order = [repo.candidate(dossier_alias_target(repo, alias))["id"] for alias in aliases]
    assert order[:-1] == [cid for cid in _report_order(repo) if cid != "z-agent"] and order[-1] == "z-agent"
    ranks = [item["rank"] for item in findings]
    assert ranks[0] == "confirmed" and ranks[-1] == "not_ranked"
    assert set(ranks) == {"confirmed", "reported", "ranked_not_reported", "not_ranked"}


def dossier_alias_target(repo, alias):
    with repo.engine.connect() as connection:
        return connection.execute(select(t.agent_alias.c.target_id).where(
            t.agent_alias.c.hunt_id == "h1", t.agent_alias.c.alias == alias)).scalar_one()


def test_a_dossier_without_ranking_keeps_the_rule_estimate_order_and_no_rank_field():
    repo = _repo()
    _insert(repo, _hunt_rows())
    findings = [item for page in build_dossier(repo, "h1", token_budget=200_000).pages
                for item in page.get("findings", [])]
    assert findings and all("rank" not in item for item in findings)
    assert findings[0]["lane"] == "urgent"


def test_the_large_dossier_pages_in_report_order(monkeypatch):
    monkeypatch.setattr(dossier_module, "MATERIALIZE_FINDING_LIMIT", 10)
    repo = _ranked_repo(filler=60)
    dossier = build_dossier(repo, "h1", token_budget=8_000)
    assert dossier.payload["header"]["status"] == "partial_at_materialization_cap"
    findings = [item for page in dossier.pages for item in page["findings"]]
    order = [dossier_alias_target(repo, item["alias"]) for item in findings]
    assert order[:-1] == [cid for cid in _report_order(repo) if cid != "z-agent"] and order[-1] == "z-agent"
    assert findings[0]["rank"] == "confirmed" and findings[-1]["rank"] == "not_ranked"
    # a ranking published again with other rows while the snapshot is paged is reported, not reordered silently
    with repo.engine.begin() as connection:
        connection.execute(t.finding_rank.delete().where(t.finding_rank.c.candidate_id == "p-lead"))
    with pytest.raises(ValueError, match="changed during paging"):
        dossier.pages[1]


def test_the_agent_finding_index_follows_report_order_filtered_or_not():
    repo = _ranked_repo(filler=30)
    toolbox = Toolbox(repo, "h1")
    listed, page, cursor = [], 1, None
    while True:
        result = toolbox.execute("list_findings", {"page": page, **({"cursor": cursor} if cursor else {})})
        listed.extend(result["data"]["findings"])
        cursor = result["data"]["cursor"]
        if not result.get("more"):
            break
        page += 1
    ids = [dossier_alias_target(repo, item["alias"]) for item in listed]
    report = [cid for cid in _report_order(repo) if cid != "z-agent"]
    assert ids[:len(report)] == report
    assert set(ids[len(report):]) == {"z-agent", "x-context", "x-suppressed"}
    assert {item.get("rank") for item in listed if dossier_alias_target(repo, item["alias"]).startswith("x-")} == {
        None}
    high = toolbox.execute("list_findings", {"page": 1, "lane": "high"})["data"]["findings"]
    high_ids = [dossier_alias_target(repo, item["alias"]) for item in high]
    assert high_ids == [cid for cid in report if repo.candidate(cid)["lane"] == "high"][:len(high_ids)]
    assert all(item["rank"] in {"reported", "ranked_not_reported"} for item in high)


# -- findings stored after the final pass ---------------------------------------------------------------------------
def _late_urgent_repo(filler=30):
    repo = _ranked_repo(filler=filler)
    # an AI pivot's rule match stored after the pass, in the confirmed lane
    _insert(repo, [_row("zz-late-urgent", "r.dump", lane="urgent", host="second",
                        ts=START + timedelta(hours=6))])
    return repo


def test_a_confirmed_finding_stored_after_the_pass_stays_with_the_confirmed_findings_everywhere():
    repo = _late_urgent_repo()
    report = _report_order(repo)
    assert report[:2] == ["c-urgent", "zz-late-urgent"]
    # web
    seen, remaining = _walk(repo, 1)
    ids = [row["id"] for row in seen]
    assert ids[:2] == ["c-urgent", "zz-late-urgent"] and ids[-1] == "z-agent"
    assert ids[:-1] == [cid for cid in report if cid != "z-agent"]
    assert remaining == [len(ids) - page - 1 for page in range(len(ids))]
    # small dossier
    findings = [item for page in build_dossier(repo, "h1", token_budget=200_000).pages
                for item in page.get("findings", [])]
    assert [dossier_alias_target(repo, item["alias"]) for item in findings[:2]] == ["c-urgent", "zz-late-urgent"]
    assert [item["rank"] for item in findings[:2]] == ["confirmed", "confirmed"]
    # the agent's finding index, unfiltered and by lane
    toolbox = Toolbox(repo, "h1")
    listed = toolbox.execute("list_findings", {"page": 1})["data"]["findings"]
    assert [dossier_alias_target(repo, item["alias"]) for item in listed[:2]] == ["c-urgent", "zz-late-urgent"]
    urgent = toolbox.execute("list_findings", {"page": 1, "lane": "urgent"})["data"]["findings"]
    assert [item["rank"] for item in urgent] == ["confirmed", "confirmed"]


def test_the_large_dossier_keeps_a_late_confirmed_finding_with_the_confirmed_ones(monkeypatch):
    monkeypatch.setattr(dossier_module, "MATERIALIZE_FINDING_LIMIT", 10)
    repo = _late_urgent_repo(filler=60)
    dossier = build_dossier(repo, "h1", token_budget=8_000)
    order = [dossier_alias_target(repo, item["alias"]) for page in dossier.pages for item in page["findings"]]
    assert order[:2] == ["c-urgent", "zz-late-urgent"]
    assert order[:-1] == [cid for cid in _report_order(repo) if cid != "z-agent"] and order[-1] == "z-agent"


def test_the_web_page_lists_a_late_confirmed_finding_under_confirmed(web_setup):
    client, web_repo, _, _, _, _ = web_setup
    _copy_into(web_repo, _late_urgent_repo())
    text, ids = _visible(client)
    assert ids[:2] == ["c-urgent", "zz-late-urgent"]
    assert text.count(">confirmed<") == 1 and text.index("zz-late-urgent") < text.index(">reported<")


def test_a_pass_published_again_gives_the_agent_new_snapshots():
    repo = _ranked_repo(filler=30)
    toolbox = Toolbox(repo, "h1")
    first = toolbox.execute("list_findings", {"page": 1})["data"]["cursor"]
    compute_rank_pass(repo, "h1", PASS_FINAL)
    repo.audit("system", "hunt.rank_pass_2_summary", "h1", {"pass": 2, "status": "complete"})
    second = toolbox.execute("list_findings", {"page": 1})
    assert second["status"] in {"complete", "partial"} and second["data"]["cursor"] != first
    assert toolbox.execute("list_findings", {"page": 2, "cursor": second["data"]["cursor"]})["status"] in {
        "complete", "partial"}
