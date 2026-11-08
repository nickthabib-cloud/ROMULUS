"""Expansion over records the sweep judged: regressions from review probes.

A rule runs once over all of a link's records; only a match whose every record the sweep is proven to have judged,
and whose group the sweep published, defers to the sweep. Folds keep the strongest lane and cite what raised it; one
anchor's discovery burst is never split below what that anchor saw.
"""
from datetime import timedelta

import romulus.hunt.expansion as ex
from romulus.detect.base import Match, Playbook, pf
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.context import finalize_context
from romulus.hunt.links import LinkResult, LinkWindow
from romulus.hunt.publish import FOLD_CITATIONS_ADDED, publish_match
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_context_playbooks import T0, _seed_anchor, _seed_link
from tests.test_expansion_engine import _SameGroupDirect, event, repo_with_anchor

# ---- B1: a multi-record match is judged over all of the link's records ----

def _exec(event_id, seconds, argv):
    values = {"process.executable": argv[0], "process.argv": argv, "process.pid": 100 + seconds,
              "process.ppid": 50, "host.boot.id": "b1"}
    return TypedEvent(id=event_id, family="process_exec", ts=T0 + timedelta(seconds=seconds), host="h",
                      fields={k: fv(v, f"{event_id}:{k}") for k, v in values.items()},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


class Pair(Playbook):
    """A two-record direct rule: a download followed by a shell."""
    id = "probe.pair"
    version = "1"
    title = "pair"
    kind = "direct"
    families = ("process_exec",)
    severity, lane = "high", "high"

    def consume(self, events):
        a = [e for e in events if e.get("process.argv")[0] == "/usr/bin/curl"]
        b = [e for e in events if e.get("process.argv")[0] == "/bin/bash"]
        return [Match(self.id, f"{x.id} then {y.id}", "observed_action", [x, y],
                      [pf(x, "process.argv"), pf(y, "process.argv")], x.ts, "high", "high", "high", x.entities(),
                      group_key=f"{x.id}|{y.id}") for x in a for y in b]


def _pair_hunt(monkeypatch, *, both_swept):
    monkeypatch.setattr(ex, "fresh_direct_pack", lambda: [Pair()])
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": T0.isoformat(), "end": (T0 + timedelta(hours=1)).isoformat()},
                            "targets": ["host-x"]}, "digest", "test")
    curl, bash = _exec("curl", 5, ["/usr/bin/curl", "http://x/a"]), _exec("bash", 20 if both_swept else 40,
                                                                          ["/bin/bash"])
    repo.upsert_task("T-sweep", "h1", "sweep", "sweep", {}, "T-sweep")
    # the sweep stored both (cited by other sweep findings) but never paired them
    swept = [curl, bash] if both_swept else [curl]
    repo.save_evidence("h1", swept, {f"host-x/{e.id}": {"doc": e.id} for e in swept}, "T-sweep")
    repo.set_rule_cell("h1", "probe.pair", "1", "host-x",
                       f"{T0.isoformat()}/{(T0 + timedelta(seconds=30)).isoformat()}", "no_match_complete", 1, 10)
    repo.save_candidate({"id": "F-anchor", "hunt_id": "h1", "rule_id": "host.web_shell", "rule_version": "1",
                         "claim": "an anchor", "claim_type": "observed_action", "event_ids": [],
                         "predicate_fields": [], "entities": [], "ts": T0, "severity": "high", "confidence": "high",
                         "lane": "high", "priority": 50.0, "priority_reasons": [], "gate_results": {},
                         "benign_alternatives": [], "next_checks": [], "source_case_id": None,
                         "source_anchor_id": None, "source_link_id": None})
    repo.save_evidence("h1", [bash], {}, None)
    eng = ex.ExpansionEngine(repo, "h1", Window(start=T0, end=T0 + timedelta(hours=1)), fetcher=object())
    result = LinkResult(id="L-reach", anchor_id="F-anchor", link_type="host_after_anchor",
                        window=LinkWindow(label="w", start=T0, end=T0 + timedelta(minutes=5)), strength="inferred",
                        key={}, status="complete", event_ids=[curl.id, bash.id])
    eng._persist_link(result)
    eng._evaluate(repo.candidate("F-anchor"), result)
    return [(row["lane"], sorted(row["event_ids"])) for row in repo.candidates("h1") if row["rule_id"] == Pair.id]


def test_a_swept_record_paired_with_a_late_one_still_publishes_the_pair(monkeypatch):
    assert _pair_hunt(monkeypatch, both_swept=False) == [("high", ["bash", "curl"])]


def test_two_swept_records_the_sweep_never_paired_publish_their_pair(monkeypatch):
    assert _pair_hunt(monkeypatch, both_swept=True) == [("high", ["bash", "curl"])]


# ---- B2: one anchor's burst across two of its links stays one burst ----

def _proc(event_id, seconds, pid, ppid, argv):
    values = {"process.executable": argv[0], "process.argv": list(argv), "process.pid": pid, "process.ppid": ppid,
              "process.uid": "0", "host.boot.id": "boot-1"}
    return TypedEvent(id=event_id, family="process_exec", ts=T0 + timedelta(seconds=seconds), host="web1",
                      fields={name: fv(value, f"{event_id}:{name}") for name, value in values.items()},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def _discovery(links):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    _seed_anchor(repo, "h1", "F-one", "host.credential_material_access",
                 [_proc("F-one-event", 0, 930, 912, ["/bin/cat", "/etc/shadow"])])
    for link_id, records in links:
        _seed_link(repo, "h1", link_id, "F-one", records, link_type="process_lineage", strength="observed")
    finalize_context(repo, "h1")
    return [c["lane"] for c in repo.candidates("h1") if c["rule_id"] == "context.post_access_discovery"]


def test_one_anchors_burst_over_two_lineage_links_is_not_split():
    a = [_proc("sh", 0, 910, 900, ["/bin/sh", "-c", "/opt/job.sh"]), _proc("w", 3, 920, 910, ["/usr/bin/whoami"])]
    b = [_proc("sh2", 100, 1910, 1900, ["/bin/sh", "-c", "/opt/other.sh"]),
         _proc("u", 103, 1920, 1910, ["/usr/bin/uname", "-a"]), _proc("s", 104, 1921, 1910, ["/usr/bin/ss", "-tunap"])]
    one_link = _discovery([("L-1", a + b)])
    two_links = _discovery([("L-1", a), ("L-2", b)])
    assert one_link == two_links == ["high"]


# ---- B3 and same-link folds ----

def _fold_rows(lanes, *, same_link=False):
    repo = repo_with_anchor(candidate_id="F-one")
    rule = _SameGroupDirect()
    events = [event(f"r-{n}", ts=T0 + timedelta(minutes=n + 1), argv=["/bin/sh", "-c", str(n)])
              for n in range(len(lanes))]
    for n, (record, lane) in enumerate(zip(events, lanes, strict=True)):
        anchor = "F-one" if same_link else f"F-{n}"
        link = "L-1" if same_link else f"L-{n}"
        match = Match(rule.id, f"part {n}", "observed_action", [record], [pf(record, "process.executable")],
                      record.ts, "high" if lane != "lead" else "medium", lane, "high", record.entities(),
                      group_key="g")
        publish_match(repo, "h1", rule, match, None, {}, source_anchor_id=anchor, source_link_id=link,
                      context_reach={"anchor_id": anchor, "link_id": link, "link_type": "host_after_anchor",
                                     "strength": "observed"})
    rows = [row for row in repo.candidates("h1") if row["rule_id"] == rule.id]
    assert len(rows) == 1
    return rows[0]


def test_a_lane_raising_reach_past_the_citation_cap_cites_its_record():
    row = _fold_rows(["lead"] * (FOLD_CITATIONS_ADDED + 2) + ["high"])
    raiser = f"r-{FOLD_CITATIONS_ADDED + 2}"
    assert row["lane"] == "high" and raiser in row["event_ids"]
    assert any(p["origin"].startswith(f"{raiser}:") for p in row["predicate_fields"])
    assert row["gate_results"]["_expansion_fold"]["raised_by"][0]["event_id"] == raiser
    assert "the record it rests on is cited" in row["claim"]


def test_three_matches_of_one_group_from_one_link_all_fold():
    row = _fold_rows(["lead", "lead", "urgent"], same_link=True)
    assert row["lane"] == "urgent" and row["event_ids"] == ["r-0", "r-1", "r-2"]
    assert row["gate_results"]["_expansion_fold"]["reaches_total"] == 2


def test_the_reach_list_is_bounded_with_a_total_count():
    from romulus.hunt.publish import FOLD_REACHES_LISTED
    row = _fold_rows(["lead"] * (FOLD_REACHES_LISTED + 6))
    assert len(row["gate_results"]["_context_reaches"]) == FOLD_REACHES_LISTED
    assert row["gate_results"]["_expansion_fold"]["reaches_total"] == FOLD_REACHES_LISTED + 5
