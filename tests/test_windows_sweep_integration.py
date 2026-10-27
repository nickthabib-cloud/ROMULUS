"""Real sweep lifecycle for streaming Windows correlation finalizers."""
from datetime import timedelta

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_auth_events import WindowsPasswordSpray
from romulus.hunt import sweep as sweep_module
from romulus.hunt.sweep import Sweep
from romulus.sources.models import Window
from tests.test_sweep import _repo
from tests.windows_event_support import START, event


def test_real_sweep_publishes_late_streaming_burst_and_its_raw_witnesses(tmp_path, monkeypatch):
    rule = WindowsPasswordSpray()
    monkeypatch.setattr(sweep_module, "fresh_pack", lambda: [rule])
    repo = _repo()
    sweep = Sweep(repo, None, "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    for n in reversed(range(20)):
        item = event("auth", 4625, offset=n, outcome="failure", **{
            "source.ip": "203.0.113.5", "auth.target_account": f"name:example\\u{n}"})
        rule.bind_raw({item.raw[0].key: {"marker": item.id}})
        assert not rule.consume([item])
    sweep.finalize()
    candidates = repo.candidates("h1")
    assert len(candidates) == 1 and len(candidates[0]["event_ids"]) == 20
    citations = repo.citation_events("h1", candidates[0]["event_ids"])
    raw = repo.raw_records([rid for item in citations for rid in item["raw_ids"]])
    assert len(raw) == 20 and all(item["source"]["marker"] for item in raw)
    assert any(cell["partition"] == "window" for cell in repo.rule_cells("h1"))
    assert rule._spill is None


def test_streaming_finalize_failure_retains_published_evidence_and_names_partial_state(tmp_path, monkeypatch):
    rule = WindowsPasswordSpray()
    monkeypatch.setattr(sweep_module, "fresh_pack", lambda: [rule])
    repo = _repo()
    sweep = Sweep(repo, None, "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    for n in reversed(range(20)):
        item = event("auth", 4625, offset=n, outcome="failure", **{
            "source.ip": "203.0.113.5", "auth.target_account": f"name:example\\u{n}"})
        rule.bind_raw({item.raw[0].key: {"marker": item.id}})
        rule.consume([item])
    original = rule.finalize
    def fail_after_match():
        yield from original()
        raise StateExhausted("injected streaming failure")
    rule.finalize = fail_after_match
    sweep.finalize()
    assert len(repo.candidates("h1")) == 1
    [window] = [cell for cell in repo.rule_cells("h1") if cell["partition"] == "window"]
    assert window["state"] == "match_on_partial"
    assert any("injected streaming failure" in text for text in window["detail"]["reasons"])
    assert rule._spill is None
