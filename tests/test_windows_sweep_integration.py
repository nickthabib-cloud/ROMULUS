"""Real sweep lifecycle for streaming Windows correlation finalizers."""
from datetime import timedelta

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_auth_events import WindowsPasswordSpray
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from romulus.hunt import sweep as sweep_module
from romulus.hunt.sweep import Sweep
from romulus.sources.models import Window
from tests.test_sweep import _repo
from tests.test_windows_c_burst_review import START
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def _native(n):
    hit = windows_hit(LogicalWindowsEvent("Security", SECURITY, 4625, "dc01.example.test", 10000+n,
        (START+timedelta(seconds=n)).isoformat().replace("+00:00", "Z"),
        {"TargetUserName": f"u{n}", "TargetDomainName": "EXAMPLE", "IpAddress": "203.0.113.5",
         "Status": "0xc000006a", "LogonType": "3"}), "winlogbeat_8")
    return normalize_windows(hit), hit


class _Client:
    def __init__(self, pairs):
        self.hits = [hit for _, hit in pairs]

    def search(self, index, body):
        wanted = body["query"]["bool"]["filter"][0]["ids"]["values"]
        return {"hits": {"hits": [hit for hit in self.hits if hit["_index"] == index and hit["_id"] in wanted]}}


def _feed(sweep, rule, pairs):
    records = [event for event, _ in pairs]
    raw = {event.raw[0].key: hit["_source"] for event, hit in pairs}
    rule.bind_raw(raw)
    matches = rule.consume(records)
    staged, held, released = {}, [], []
    sweep._record_playbook_batch(rule, matches, raw, None, staged, held, released)
    sweep._stage_put(list(staged.values()), raw, held, released)
    assert not staged and not held
    return matches


def test_real_sweep_publishes_late_streaming_burst_and_its_raw_witnesses(tmp_path, monkeypatch):
    rule = WindowsPasswordSpray()
    monkeypatch.setattr(sweep_module, "fresh_pack", lambda: [rule])
    repo = _repo()
    pairs = [_native(n) for n in range(20)]
    sweep = Sweep(repo, _Client(pairs), "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    for pair in reversed(pairs):
        assert not _feed(sweep, rule, [pair])
    sweep.finalize()
    candidates = repo.candidates("h1")
    assert len(candidates) == 2 and all(len(item["event_ids"]) == 20 for item in candidates)
    citations = repo.citation_events("h1", candidates[0]["event_ids"])
    raw = repo.raw_records([rid for item in citations for rid in item["raw_ids"]])
    assert len(raw) == 20 and all(item["source"]["winlog"]["event_data"] for item in raw)
    assert any(cell["partition"] == "window" for cell in repo.rule_cells("h1"))
    assert rule._spill is None


def test_streaming_finalize_failure_retains_published_evidence_and_names_partial_state(tmp_path, monkeypatch):
    rule = WindowsPasswordSpray()
    monkeypatch.setattr(sweep_module, "fresh_pack", lambda: [rule])
    repo = _repo()
    pairs = [_native(n) for n in range(20)]
    sweep = Sweep(repo, _Client(pairs), "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    for pair in reversed(pairs):
        _feed(sweep, rule, [pair])
    original = rule.finalize
    def fail_after_match():
        yield from original()
        raise StateExhausted("injected streaming failure")
    rule.finalize = fail_after_match
    sweep.finalize()
    assert len(repo.candidates("h1")) == 2
    [window] = [cell for cell in repo.rule_cells("h1") if cell["partition"] == "window"]
    assert window["state"] == "match_on_partial"
    assert any("injected streaming failure" in text for text in window["detail"]["reasons"])
    assert rule._spill is None


def test_immediate_cross_batch_burst_fetches_native_refs_and_publishes_resolvable_raw(tmp_path, monkeypatch):
    rule = WindowsPasswordSpray()
    monkeypatch.setattr(sweep_module, "fresh_pack", lambda: [rule])
    repo = _repo()
    pairs = [_native(n) for n in range(20)]
    sweep = Sweep(repo, _Client(pairs), "h1", Window(start=START, end=START+timedelta(minutes=10)), {}, stage_dir=tmp_path)
    for start in (0, 10):
        matches = _feed(sweep, rule, pairs[start:start+10])
        assert len(matches) == (0 if start == 0 else 2)
    assert len(repo.candidates("h1")) == 2
    assert sweep._event_stage().count() == 0
    for candidate in repo.candidates("h1"):
        citations = repo.citation_events("h1", candidate["event_ids"])
        raw = repo.raw_records([rid for item in citations for rid in item["raw_ids"]])
        assert len(raw) == 20 and all(item["source"]["winlog"]["event_data"] for item in raw)
    sweep.finalize()
    assert len(repo.candidates("h1")) == 2 and not rule.limits and rule._spill is None
