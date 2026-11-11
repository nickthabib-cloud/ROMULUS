"""What a sensor or rule ties to an attack is never filed as context: low-priority IDS alerts whose classtype names
attack activity, or whose signature metadata names an ATT&CK technique, stay leads in the alert rule and in the
process-network link; executable content moving between internal hosts over FTP is a lateral lead."""
from __future__ import annotations

import pytest

from romulus.detect import network
from romulus.detect.alert_lanes import alert_stack_lane, attack_tagged
from tests import test_network_correlation as corr
from tests.fixtures import zeek_logs as zl
from tests.test_playbooks import T0, _alert, ev, run
from tests.test_zeek_alerts import run as zeek_alerts
from tests.test_zeek_transfer import HTTP, PE
from tests.test_zeek_transfer import run as transfer


@pytest.mark.parametrize(("category", "severity", "tagged", "lane"), [
    ("Not Suspicious Traffic", 3, False, "context"),
    ("Not Suspicious Traffic", 3, True, "context"),        # the author marked it not suspicious
    ("Not Suspicious Traffic", 1, False, "context"),
    ("Generic Protocol Command Decode", 3, False, "context"),
    ("Misc activity", 3, False, "context"),
    ("Misc activity", 3, True, "lead"),
    ("A Network Trojan was detected", 4, False, "lead"),            # an attack classtype a site re-prioritized
    ("Attempted Administrator Privilege Gain", 5, False, "lead"),
    ("", 3, False, "lead"),                                         # a site rule with no classtype
    (None, 3, False, "lead"),
    ("Unknown Traffic", 3, False, "context"),
    ("Detection of a Network Scan", 3, False, "lead"),
    ("A suspicious string was detected", 3, False, "lead"),
    ("Web Application Attack", 1, False, "high"),
    ("Potentially Bad Traffic", 2, False, "lead"),
    ("A TCP connection was detected", 4, False, "context"),
    ("A TCP connection was detected", 4, True, "lead"),
])
def test_alert_lane(category, severity, tagged, lane):
    assert alert_stack_lane(category, severity, tagged)[0] == lane


def _low(cat, src, techniques=None, signature_severity=None):
    """A priority-3 alert; `techniques` and `signature_severity` are its signature's metadata."""
    extra = {"alert__mitre_technique_id": techniques} if techniques else {}
    if signature_severity:
        extra["alert__signature_severity"] = signature_severity
    return ev(family="net_alert", ts=T0, alert__signature="ET TEST sig", alert__signature_id=1, alert__severity=3,
              alert__category=cat, source__ip=src, destination__ip="192.0.2.10", **extra)


def test_low_priority_attack_alerts_are_leads_and_say_why():
    found = {m.group_key.split("|")[0]: m for m in run(network.SuricataAlertStack, [
        _low("Detection of a Network Scan", "198.51.100.7"),
        _low("Misc activity", "198.51.100.8", ["T1046"]),
        _low("Misc activity", "198.51.100.9"),
        _low("Not Suspicious Traffic", "198.51.100.6", ["T1046"]),
    ])}
    assert {src: m.proposed_lane for src, m in found.items()} == {
        "198.51.100.7": "lead", "198.51.100.8": "lead", "198.51.100.9": "context", "198.51.100.6": "context"}
    assert all(m.severity == "low" for m in found.values())
    assert any("not one of the benign low-priority classtypes" in note for note in found["198.51.100.7"].notes)
    assert any("ties it to an attack" in note for note in found["198.51.100.8"].notes)


def test_one_tagged_alert_keeps_its_whole_group_a_lead():
    matches = run(network.SuricataAlertStack, [
        _low("Misc activity", "198.51.100.8"),
        _low("Misc activity", "198.51.100.8", ["T1595.002"]),
        _low("Misc activity", "198.51.100.9"),
    ])
    lanes = {m.group_key.split("|")[0]: m.proposed_lane for m in matches}
    assert lanes == {"198.51.100.8": "lead", "198.51.100.9": "context"}
    tagged = next(m for m in matches if m.group_key.startswith("198.51.100.8"))
    assert any("ATT&CK technique" in note for note in tagged.notes)


@pytest.mark.parametrize(("category", "lane"), [("Detection of a Network Scan", "lead"),
                                                ("Generic Protocol Command Decode", "context"),
                                                ("Not Suspicious Traffic", "context")])
def test_the_process_network_link_gives_an_alert_the_alert_rules_lane(category, lane):
    m = corr.link([corr._sock(**corr.SSHD)] + corr._network(corr.flow(), corr.alert(severity=3, category=category)))[0]
    assert m.proposed_lane == lane


@pytest.mark.parametrize(("sender", "receiver", "lane", "category"), [
    (zl.SERVER, zl.CLIENT, "lead", "ingress"),
    ("10.0.0.9", zl.CLIENT, "lead", "lateral"),
    (zl.CLIENT, zl.SERVER, "context", None),
])
def test_ftp_executable_transfers(sender, receiver, lane, category):
    row = PE.without('uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'is_orig').with_(
        tx_hosts=[sender], rx_hosts=[receiver], source='FTP_DATA', filename='payload')
    [match] = transfer([row])
    assert match.proposed_lane == lane
    if category:
        assert f"; {category})" in match.claim
    if category == "lateral":
        assert "T1570" in " ".join(match.notes)


def _decided(**change):
    from romulus.decide.policy import decide
    from romulus.detect.base import PredicateField

    [match] = run(network.SuricataAlertStack, [_alert(1)])
    if change.get("lineage") is False:
        match.predicate = [PredicateField(p.field, p.value, "") for p in match.predicate]
    if change.get("raw") is False:
        match.events = [event.model_copy(update={"raw": []}) for event in match.events]
    return decide(match, "h1")


def test_a_positive_with_incomplete_admission_stays_a_lead_saying_what_is_missing():
    assert _decided().lane == "high" and _decided().admitted
    decision = _decided(lineage=False)
    assert not decision.admitted and decision.lane == "lead"
    assert any("Admission is incomplete: predicate_fields" in note for note in decision.notes)


def test_a_positive_with_nothing_citable_is_context():
    assert _decided(raw=False).lane == "context"


@pytest.mark.parametrize(("metadata", "tagged"), [
    ({"alert__signature_severity": "Major"}, True),
    ({"alert__signature_severity": ["Informational", "critical"]}, True),
    ({"alert__signature_severity": "Minor"}, False),
    ({"alert__signature_severity": "Informational"}, False),
    ({"alert__mitre_technique_id": ["T1046"]}, True),
    ({"alert__mitre_technique_id": []}, False),
    ({}, False),
])
def test_signature_metadata_that_ties_an_alert_to_an_attack(metadata, tagged):
    event = ev(family="net_alert", ts=T0, alert__signature="ET TEST sig", alert__severity=3,
               alert__category="Misc activity", source__ip="198.51.100.7", destination__ip="192.0.2.10", **metadata)
    assert attack_tagged(event) is tagged


def test_a_major_signature_severity_keeps_a_low_priority_alert_a_lead():
    [match] = run(network.SuricataAlertStack, [_low("Misc activity", "198.51.100.8", signature_severity="Major")])
    assert match.proposed_lane == "lead"


@pytest.mark.parametrize(("host", "lane"), [("10.0.0.9", "lead"), ("10.0.0.9:8000", "lead"),
                                           ("files.corp.test", "context")])
def test_internal_http_executable_transfer_from_an_ip_addressed_server_is_lateral(host, lane):
    internal = {"id.resp_h": "10.0.0.9"}
    [match] = transfer([PE.with_(**internal), HTTP.with_(host=host, **internal)])
    assert match.proposed_lane == lane
    if lane == "lead":
        assert "; lateral)" in match.claim and "T1570" in " ".join(match.notes)


@pytest.mark.parametrize(("name", "lane"), [("fragment_overlap", "lead"), ("TCP_christmas", "lead"),
                                            ("excessively_large_fragment", "lead"), ("bad_TCP_checksum", "context")])
def test_evasion_shaped_weirds_are_leads(name, lane):
    _rule, [match] = zeek_alerts([zl.WEIRD.with_(name=name)])
    assert match.proposed_lane == lane
    assert ("shape of IDS evasion" in match.claim) is (lane == "lead")


def _tagged_eve(metadata):
    import json

    hit = corr.alert(severity=3, category="Misc activity")
    eve = json.loads(hit["_source"]["event"]["original"])
    eve["alert"]["metadata"] = metadata
    hit["_source"]["event"]["original"] = json.dumps(eve)
    return hit


@pytest.mark.parametrize(("metadata", "lane"), [({"mitre_technique_id": ["T1046"]}, "lead"),
                                                ({"signature_severity": ["Major"]}, "lead"),
                                                ({"mitre_technique_id": [""]}, "context"),
                                                ({"mitre_technique_id": []}, "context"),
                                                ({}, "context")])
def test_the_process_network_link_reads_the_alerts_own_tag(metadata, lane):
    m = corr.link([corr._sock(**corr.SSHD)] + corr._network(corr.flow(), _tagged_eve(metadata)))[0]
    assert m.proposed_lane == lane


@pytest.mark.parametrize("techniques", [[""], [None], ["not-a-technique"]])
def test_empty_or_malformed_technique_metadata_is_not_a_tag(techniques):
    event = ev(family="net_alert", ts=T0, alert__signature="ET TEST sig", alert__severity=3,
               alert__category="Misc activity", source__ip="198.51.100.7", destination__ip="192.0.2.10",
               alert__mitre_technique_id=techniques)
    assert not attack_tagged(event)


def test_the_alert_that_raised_a_group_is_cited_and_its_technique_named():
    untagged = []
    for index in range(30):
        alert = _low("Misc activity", "198.51.100.8")
        alert.fields["alert.signature_id"].value = index % 11
        alert.fields["alert.signature"].value = f"ET INFO sig {index % 11}"
        untagged.append(alert)
    tagged = _low("Misc activity", "198.51.100.8", ["T1046"])
    tagged.fields["alert.signature_id"].value = 99
    tagged.fields["alert.signature"].value = "ET SCAN tagged sig"
    [match] = run(network.SuricataAlertStack, [*untagged, tagged])
    assert match.proposed_lane == "lead"
    assert tagged.id in {event.id for event in match.events}
    assert any("T1046" in note for note in match.notes)


def test_an_entity_only_admission_gap_is_a_medium_lead_and_publishable():
    from romulus.decide.policy import decide, publishable

    [match] = run(network.SuricataAlertStack, [_alert(1)])
    match.entities = []
    match.events = [event.model_copy(update={"host": None}) for event in match.events]
    decision = decide(match, "h1")
    assert not decision.admitted and decision.lane == "lead" and decision.severity == "medium"
    assert publishable(decision) and any("entity_time" in note for note in decision.notes)
    assert not publishable(_decided(raw=False))


def test_browser_javascript_from_an_ip_addressed_web_interface_is_not_lateral():
    internal = {"id.resp_h": "10.0.0.9"}
    script = PE.with_(mime_type="application/javascript", filename="app.js", **internal)
    [match] = transfer([script, HTTP.with_(host="10.0.0.9", uri="/app.js", **internal)])
    assert match.proposed_lane == "context"

