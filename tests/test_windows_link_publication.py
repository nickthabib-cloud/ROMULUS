"""Real repository publication for pairwise Windows link facts, without hunt-wide context holding."""
from datetime import timedelta
from types import SimpleNamespace

from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.windows_context import publish_windows_link_context
from romulus.sources.models import Window
from romulus.store.repo import raw_id
from tests.test_context_catalog import _repo, _seed_anchor
from tests.windows_link_support import START, event


def test_windows_link_fact_is_published_with_both_raw_records_and_is_idempotent():
    repo = _repo()
    process = event("process_exec", 4688, **{"process.subject_session_id": "0x44", "host.boot.id": "boot"})
    logon = event("auth", 4624, offset=-1, **{"auth.session_id": "68", "host.boot.id": "boot"})
    repo.save_evidence("h1", [process], {process.raw[0].key: {"source-marker": "process"}}, None)
    _seed_anchor(repo, "h1", "F-A", "win.script_host", [process], host=process.host)
    raw = {logon.raw[0].key: {"source-marker": "logon"}}
    repo.save_evidence("h1", [logon], raw, None)
    result = SimpleNamespace(id="L-win", link_type="process_session", strength="observed", status="complete",
                             key={"process.session_id": "0x44"}, reasons=[],
                             window=Window(start=START-timedelta(minutes=1), end=START+timedelta(minutes=1)),
                             event_ids=[logon.id], task_ids=[])
    candidate = repo.candidate("F-A")
    rows = publish_windows_link_context(repo, "h1", candidate, result, [logon])
    assert len(rows) == 1 and rows[0]["rule_id"] == "win.process_session_link"
    assert set(rows[0]["event_ids"]) == {process.id, logon.id}
    copies = repo.raw_records([raw_id(ref.target, ref.native_id) for item in (process, logon) for ref in item.raw])
    assert {item["source"]["source-marker"] for item in copies} == {"process", "logon"}
    again = publish_windows_link_context(repo, "h1", candidate, result, [logon])
    assert len(again) == 1 and again[0]["id"] == rows[0]["id"]
    assert sum(row["rule_id"] == "win.process_session_link" for row in repo.candidates("h1")) == 1
    assert any(cell["target"] == "link:process_session" for cell in repo.rule_cells("h1"))
    repo.save_expansion_link({
        "id": result.id, "hunt_id": "h1", "anchor_id": "F-A", "link_type": result.link_type,
        "window_label": "test", "window_start": result.window.start, "window_end": result.window.end,
        "strength": result.strength, "key": result.key, "status": result.status,
        "event_ids": result.event_ids, "evidence_ids": [process.id, logon.id], "task_ids": [], "coverage": [],
        "reasons": [], "duration_ms": 0, "query_spend": 0, "evaluated": 0,
    })
    engine = ExpansionEngine(repo, "h1", result.window, SimpleNamespace())
    emitted = engine._evaluate(candidate, result)
    assert any(row["id"] == rows[0]["id"] for row in emitted)


def test_pairwise_rules_do_not_enter_global_context_holding_or_direct_pivot_packs():
    from romulus.detect.registry import fresh_context_pack, fresh_direct_pack
    assert all(not getattr(rule, "per_link_evidence", False) for rule in fresh_context_pack())
    direct = fresh_direct_pack()
    assert all(rule.kind == "direct" for rule in direct)
    assert all(rule.id not in {"win.kerberos_tgt_context", "win.created_then_privileged", "win.password_spray",
                               "win.kerberos_logon_link", "win.process_session_link"} for rule in direct)
