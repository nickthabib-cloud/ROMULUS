"""Grouping findings are leaves in the incident graph: an aggregate that cites events of two
unrelated processes must not merge the anchors that reached them."""
from romulus.report.incidents import build_incident_graph

BASE = {"window_label": "anchor ±5 min", "window_start": "2023-12-31T23:55:00+00:00",
        "window_end": "2024-01-01T00:05:00+00:00", "strength": "observed",
        "status": "complete", "coverage": [], "reasons": [], "evidence_ids": []}


class _Repo:
    def __init__(self, links):
        self.links = links

    def expansion_links(self, hunt_id):
        return self.links

    def expansion_anchors(self, hunt_id):
        return []


def _link(link_id, anchor, events, strength="observed", *, link_type="process_lineage",
          window_start=None, window_end=None):
    return {**BASE, "id": link_id, "anchor_id": anchor, "link_type": link_type, "key": {},
            "event_ids": events, "strength": strength,
            **({"window_start": window_start} if window_start else {}),
            **({"window_end": window_end} if window_end else {})}


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


def test_claim_only_context_citation_does_not_make_a_finding_the_link_target():
    links = [_link("L1", "A1", ["context-only"])]
    findings = [_finding("A1", ["anchor"], second=1), _finding("T1", ["subject", "context-only"], second=2)]
    findings[1]["context_event_ids"] = ["context-only"]

    graph = build_incident_graph(_Repo(links), "h", findings)

    assert sorted(tuple(incident["finding_ids"]) for incident in graph["incidents"]) == [("A1",), ("T1",)]
    assert graph["edges"] == []


def test_inferred_edges_never_merge_and_remain_visible_hypotheses():
    links = [
        _link("L-observed", "A1", ["e1"]),
        _link("L-narrow", "T1", ["e2"], strength="inferred", link_type="host_after_anchor",
              window_start="2023-12-31T23:55:02+00:00", window_end="2024-01-01T00:05:02+00:00"),
        _link("L-wide", "T2", ["e3"], strength="inferred", link_type="host_after_anchor",
              window_start="2023-12-31T23:30:03+00:00", window_end="2024-01-01T00:30:03+00:00"),
    ]
    findings = [_finding("A1", ["a1"], second=1), _finding("T1", ["e1"], second=2),
                _finding("T2", ["e2"], second=3), _finding("T3", ["e3"], second=4)]

    graph = build_incident_graph(_Repo(links), "h", findings)

    assert sorted(tuple(i["finding_ids"]) for i in graph["incidents"]) == [
        ("A1", "T1"), ("T2",), ("T3",),
    ]
    roles = {edge["link_id"]: edge["incident_role"] for edge in graph["edges"]}
    assert roles == {"L-observed": "evidence", "L-narrow": "hypothesis", "L-wide": "hypothesis"}
    inferred = [link for link in graph["links"] if link["style"] == "inferred"]
    assert {link["id"] for link in inferred} == {"L-narrow", "L-wide"}
    assert all(link["incident_role"] == "hypothesis" for link in inferred)


def test_duplicate_pair_with_observed_and_wide_inferred_edges_joins_once_and_keeps_both_links():
    links = [
        _link("L-wide", "A1", ["e1"], strength="inferred", link_type="host_after_anchor",
              window_start="2023-12-31T22:00:01+00:00", window_end="2024-01-01T02:00:01+00:00"),
        _link("L-observed", "A1", ["e1"]),
    ]
    findings = [_finding("A1", ["a1"], second=1), _finding("T1", ["e1"], second=2)]

    graph = build_incident_graph(_Repo(links), "h", findings)

    assert [tuple(i["finding_ids"]) for i in graph["incidents"]] == [("A1", "T1")]
    assert {(edge["link_id"], edge["incident_role"]) for edge in graph["edges"]} == {
        ("L-observed", "evidence"), ("L-wide", "hypothesis"),
    }


def test_incident_grouping_is_deterministic_under_finding_and_link_order():
    links = [
        _link("L-narrow", "A1", ["e1"], strength="inferred", link_type="host_after_anchor",
              window_start="2023-12-31T23:55:01+00:00", window_end="2024-01-01T00:05:01+00:00"),
        _link("L-wide", "T1", ["e2"], strength="inferred", link_type="host_after_anchor",
              window_start="2023-12-31T23:30:02+00:00", window_end="2024-01-01T00:30:02+00:00"),
    ]
    findings = [_finding("A1", ["a1"], second=1), _finding("T1", ["e1"], second=2),
                _finding("T2", ["e2"], second=3)]

    forward = build_incident_graph(_Repo(links), "h", findings)
    reversed_input = build_incident_graph(_Repo(list(reversed(links))), "h", list(reversed(findings)))

    assert forward == reversed_input


def test_incident_narrative_is_templated_cited_and_labels_hypotheses_and_gaps():
    links = [_link("L1", "A1", ["e1"]), _link("L2", "A1", ["e9"], strength="inferred")]
    findings = [_finding("A1", ["a1"], rule="host.web_service_spawns_interpreter", second=1),
                _finding("T1", ["e1"], rule="host.credential_store_read", second=2),
                _finding("X9", ["e9"], second=3)]
    graph = build_incident_graph(_Repo(links), "h", findings)
    incident = next(i for i in graph["incidents"] if i["finding_ids"] == ["A1", "T1"])
    sentences = incident["narrative"]
    assert sentences[0]["text"].startswith("2 finding(s) on ") and sentences[0]["cites"] == ["A1", "T1"]
    assert sentences[1]["text"].startswith("The earliest finding is ") and sentences[1]["cites"] == ["A1"]
    then = next(s for s in sentences if s["text"].startswith("Then "))
    assert "reached from A1 by an observed process lineage link" in then["text"] and then["cites"] == ["T1", "A1"]
    hypo = next(s for s in sentences if s["kind"] == "hypothesis")
    assert "remain hypotheses" in hypo["text"] and "X9" in hypo["cites"]
    assert all(s["kind"] in ("observed", "mapping", "hypothesis", "gap") for s in sentences)


def test_narrative_follows_time_when_an_observed_link_reaches_back():
    # A login-session or same-process link can lead to an earlier record: the narrative must not say the
    # incident "begins" at the entry point and then step back in time.
    links = [_link("L1", "A1", ["e1"])]
    findings = [_finding("A1", ["a1"], rule="host.web_service_spawns_interpreter", second=5),
                _finding("T1", ["e1"], rule="host.credential_store_read", second=1)]
    incident = build_incident_graph(_Repo(links), "h", findings)["incidents"][0]
    sentences = incident["narrative"]
    assert incident["entry_point"] == "A1" and incident["timeline"] == ["T1", "A1"]
    assert sentences[1]["text"].startswith("The earliest finding is ") and sentences[1]["cites"] == ["T1", "A1"]
    assert "reached from A1" in sentences[1]["text"]
    assert "No observed link leads into" in sentences[2]["text"] and sentences[2]["cites"] == ["A1"]
    stamps = [s["text"].rsplit(" at ", 1)[1][:19] for s in sentences if s["text"].startswith(("The earliest", "Then"))]
    assert stamps == sorted(stamps)


def test_markdown_renders_narratives_for_multi_finding_incidents():
    from romulus.report.manifest import publish_revision
    from romulus.report.markdown import render
    from tests.test_report import _repo_with_reversed_scoped_expansion
    repo = _repo_with_reversed_scoped_expansion("hunt-md", "a-alpha", "z-beta", "a-link", "z-link")
    text = render(publish_revision(repo, "hunt-md", "test"))
    assert "**Incident narratives**" in text


def test_a_partly_expanded_anchor_is_a_gap_in_the_narrative():
    class PartialRepo(_Repo):
        def expansion_anchors(self, hunt_id):
            return [{"id": "A1", "status": "expanded_partial", "reasons": ["source query budget exhausted"]}]

    links = [_link("L1", "A1", ["e1"])]
    findings = [_finding("A1", ["a1"], second=1), _finding("T1", ["e1"], second=2)]
    incident = build_incident_graph(PartialRepo(links), "h", findings)["incidents"][0]
    assert incident["open_ends"]["partial_anchors"] == [{"anchor_id": "A1",
                                                         "reasons": ["source query budget exhausted"]}]
    gap = next(s for s in incident["narrative"] if s["kind"] == "gap")
    assert "1 were expanded only in part" in gap["text"]
