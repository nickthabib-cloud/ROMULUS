"""The final context pass streams one link at a time: only records a context rule can read stay in memory, one
object per id, and a held record is never read or deserialized again."""
from collections import Counter

from romulus.evidence.typed import TypedEvent
from romulus.hunt import context as ctx
from tests.test_context_catalog import _discovery, _repo, _seed_anchor, _seed_link, exec_event


def _noise(i: int) -> TypedEvent:
    """A record no context rule reads (a web error line)."""
    event = exec_event(f"noise{i}", ["x"])
    return event.model_copy(update={"family": "web_error"})


def test_final_pass_holds_only_eligible_records_and_reads_each_held_record_once(monkeypatch):
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    discovery = [exec_event("id", ["id"], executable="/usr/bin/id"),
                 exec_event("uname", ["uname", "-a"], executable="/usr/bin/uname"),
                 exec_event("ps", ["ps", "aux"], executable="/usr/bin/ps")]
    links = 30
    for n in range(links):
        noise = [_noise(n * 200 + i) for i in range(200)]
        _seed_link(repo, "h1", f"L-{n:03d}", "F-A", discovery + noise)     # the same discovery records every link

    decoded: Counter = Counter()
    original = TypedEvent.model_validate.__func__

    def counting(cls, data, *args, **kwargs):
        event = original(cls, data, *args, **kwargs)
        decoded[event.id] += 1
        return event

    peak = {"held": 0}
    add = ctx._RuleReaches.add

    def watching(self, anchor, link, link_events, held):
        add(self, anchor, link, link_events, held)
        peak["held"] = max(peak["held"], len(held))

    monkeypatch.setattr(TypedEvent, "model_validate", classmethod(counting))
    monkeypatch.setattr(ctx._RuleReaches, "add", watching)
    ctx.finalize_context(repo, "h1")

    assert peak["held"] <= len(discovery)                   # never the 6,000 noise records
    assert all(decoded[e.id] == 1 for e in discovery)        # held: deserialized once, not once per link
    assert decoded["fa"] == 1                                # the anchor is built once
    final = _discovery(repo.candidates("h1"))
    assert len(final) == 1 and "3 command(s)" in final[0]["claim"]


def test_coverage_keeps_what_a_cell_needs_of_each_link_not_its_records(monkeypatch):
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    for n in range(5):
        _seed_link(repo, "h1", f"L-{n}", "F-A", [_noise(n * 10 + i) for i in range(10)])
    kept = []
    finalize_rule = ctx._finalize_rule

    def watching(repo, hunt_id, reaches, **kwargs):
        kept.extend(reaches.coverage)
        return finalize_rule(repo, hunt_id, reaches, **kwargs)

    monkeypatch.setattr(ctx, "_finalize_rule", watching)
    ctx.finalize_context(repo, "h1")
    assert kept and all(isinstance(anchor_id, str) and type(link) is ctx._CellLink
                        for anchor_id, link, *_counts in kept)
    cells = [c for c in repo.rule_cells("h1") if c["partition"].startswith("anchor:F-A|link:L-")]
    assert len(cells) == len(kept) and {c["detail"]["link_id"] for c in cells} == {f"L-{n}" for n in range(5)}
