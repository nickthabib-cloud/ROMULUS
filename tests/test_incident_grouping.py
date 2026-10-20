"""Grouping findings are leaves in the incident graph (review I-3): an aggregate that cites events of two
unrelated processes must not merge the anchors that reached them."""
from romulus.report.incidents import build_incident_graph

BASE = {"window_label": "anchor ±5 min", "window_start": "s", "window_end": "e", "strength": "observed",
        "status": "complete", "coverage": [], "reasons": [], "evidence_ids": []}


class _Repo:
    def __init__(self, links):
        self.links = links

    def expansion_links(self, hunt_id):
        return self.links

    def expansion_anchors(self, hunt_id):
        return []


def _link(link_id, anchor, events, strength="observed"):
    return {**BASE, "id": link_id, "anchor_id": anchor, "link_type": "process_lineage", "key": {},
            "event_ids": events, "strength": strength}


def _finding(finding_id, events, rule="host.web_shell", second=0):
    return {"id": finding_id, "lane": "high", "observed_at": f"2024-01-01T00:00:0{second}", "rule_id": rule,
            "entities": [], "event_ids": events, "citations": []}


def _incidents(links, findings):
    return sorted(tuple(i["finding_ids"]) for i in build_incident_graph(_Repo(links), "h", findings)["incidents"])


def test_an_aggregate_reached_from_two_anchors_does_not_merge_them():
    links = [_link("L1", "A1", ["e1"]), _link("L2", "A2", ["e2"])]
    findings = [_finding("A1", ["a1"], second=1), _finding("A2", ["a2"], second=2),
                _finding("F3", ["e1", "e2"], rule="host.interpreter_external_connection", second=3)]
    assert _incidents(links, findings) == [("A1",), ("A2",), ("F3",)]
    graph = build_incident_graph(_Repo(links), "h", findings)
    assert {(e["from"], e["to"]) for e in graph["edges"]} == {("A1", "F3"), ("A2", "F3")}     # edges still shown


def test_an_aggregate_reached_from_one_incident_joins_it():
    links = [_link("L1", "A1", ["e1"]), _link("L2", "A1", ["e2"])]
    findings = [_finding("A1", ["a1"], second=1),
                _finding("F3", ["e1", "e2"], rule="ioc.indicator_match", second=3)]
    assert _incidents(links, findings) == [("A1", "F3")]


def test_an_aggregate_anchor_does_not_bridge_the_targets_of_its_keys():
    links = [_link("L1", "AGG", ["e1"]), _link("L2", "AGG", ["e2"])]
    findings = [_finding("AGG", ["x1", "x2"], rule="host.interpreter_external_connection", second=0),
                _finding("T1", ["e1"], second=1), _finding("T2", ["e2"], second=2)]
    assert _incidents(links, findings) == [("AGG",), ("T1",), ("T2",)]


def test_ordinary_findings_still_join_through_observed_edges():
    links = [_link("L1", "A1", ["e1"]), _link("L2", "A2", ["e2"])]
    findings = [_finding("A1", ["a1"], second=1), _finding("A2", ["a2"], second=2),
                _finding("D3", ["e1", "e2"], second=3)]                 # one direct finding citing both
    assert _incidents(links, findings) == [("A1", "A2", "D3")]


def test_inferred_edges_never_merge():
    links = [_link("L1", "A1", ["e1"], strength="inferred")]
    findings = [_finding("A1", ["a1"], second=1), _finding("T1", ["e1"], second=2)]
    assert _incidents(links, findings) == [("A1",), ("T1",)]
