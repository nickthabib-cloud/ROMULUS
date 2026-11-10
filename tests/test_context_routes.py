"""What a sensor or rule ties to an attack is never filed as context: low-priority IDS alerts whose classtype names
attack activity, or whose signature metadata names an ATT&CK technique, stay leads in the alert rule and in the
process-network link; executable content moving between internal hosts over FTP is a lateral lead."""
from __future__ import annotations

import pytest

from romulus.detect import network
from romulus.detect.alert_lanes import alert_stack_lane
from tests import test_network_correlation as corr
from tests.fixtures import zeek_logs as zl
from tests.test_playbooks import T0, _alert, ev, run
from tests.test_zeek_transfer import PE
from tests.test_zeek_transfer import run as transfer


@pytest.mark.parametrize(("category", "severity", "tagged", "lane"), [
    ("Not Suspicious Traffic", 3, False, "context"),
    ("Not Suspicious Traffic", 3, True, "context"),        # the author marked it not suspicious
    ("Not Suspicious Traffic", 1, False, "context"),
    ("Generic Protocol Command Decode", 3, False, "context"),
    ("Misc activity", 3, False, "context"),
    ("Misc activity", 3, True, "lead"),
    ("Detection of a Network Scan", 3, False, "lead"),
    ("A suspicious string was detected", 3, False, "lead"),
    ("Web Application Attack", 1, False, "high"),
    ("Potentially Bad Traffic", 2, False, "lead"),
    ("Misc activity", 4, False, "lead"),
])
def test_alert_lane(category, severity, tagged, lane):
    assert alert_stack_lane(category, severity, tagged)[0] == lane


def _low(cat, src, techniques=None):
    """A priority-3 alert; `techniques` is its signature's ATT&CK metadata."""
    extra = {"alert__mitre_technique_id": techniques} if techniques else {}
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
    assert any("classtype names attack activity" in note for note in found["198.51.100.7"].notes)
    assert any("names an ATT&CK technique" in note for note in found["198.51.100.8"].notes)


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
