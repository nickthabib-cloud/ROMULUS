"""Partner outputs of a report revision: recommendations from ATT&CK mitigations, and the indicator export.

Recommendations come from the findings' techniques through the pinned ATT&CK release's mitigations; the indicator
export lists values from typed fields only, as STIX 2.1 and CSV, with credentials withheld and every count exact.
"""
import csv
import hashlib
import io
import json
import re
import time
import tracemalloc
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from romulus.catalog.mitigations import clean_text, index_from_objects, load_mitigations
from romulus.config import Settings
from romulus.report import bundle, executive, iocs, recommendations
from romulus.report.manifest import build_manifest, canonical_manifest, publish_revision
from romulus.report.markdown import render
from tests.test_report import _repo_with_finding
from tests.test_web import _csrf, _login, client  # noqa: F401

# ---- a fixture ATT&CK subset ------------------------------------------------------------------------------------


def _pattern(stix, attack_id, name, *, sub=False, revoked=False, source="mitre-attack"):
    return {"type": "attack-pattern", "id": f"attack-pattern--{stix}", "name": name, "revoked": revoked,
            "x_mitre_is_subtechnique": sub,
            "external_references": [{"source_name": source, "external_id": attack_id}]}


def _action(stix, mitigation_id, name, description, *, deprecated=False):
    return {"type": "course-of-action", "id": f"course-of-action--{stix}", "name": name, "description": description,
            "x_mitre_deprecated": deprecated, "external_references": [
                {"source_name": "mitre-attack", "external_id": mitigation_id,
                 "url": f"https://attack.mitre.org/mitigations/{mitigation_id}"}]}


def _rel(kind, source, target, description=""):
    return {"type": "relationship", "id": f"relationship--{source[-4:]}{target[-4:]}{kind}",
            "relationship_type": kind, "source_ref": source, "target_ref": target, "description": description}


def fixture_index():
    enterprise = [
        {"type": "x-mitre-collection", "x_mitre_version": "test"},
        _pattern("p1", "T1000", "Parent"), _pattern("p2", "T1000.001", "Child", sub=True),
        _pattern("p3", "T2000", "Unmitigable"), _pattern("p4", "T3000", "Old", revoked=True),
        _pattern("p5", "T3001", "New"), _pattern("p6", "T4000", "Bare"),
        _action("a1", "M1001", "Harden Things", "Harden the things. (Citation: X) More detail follows here.\n\nList:"),
        _action("a2", "M1002", "Retired", "Gone.", deprecated=True),
        _action("a3", "M1056", "Pre-compromise", "Not preventable."),
        _rel("subtechnique-of", "attack-pattern--p2", "attack-pattern--p1"),
        _rel("revoked-by", "attack-pattern--p4", "attack-pattern--p5"),
        _rel("mitigates", "course-of-action--a1", "attack-pattern--p1", "Harden the parent [link](http://x) "
             "(Citation: Y)."),
        _rel("mitigates", "course-of-action--a1", "attack-pattern--p5", "Harden the new one."),
        _rel("mitigates", "course-of-action--a2", "attack-pattern--p6", "Retired advice."),
        _rel("mitigates", "course-of-action--a3", "attack-pattern--p3", "Cannot be prevented."),
    ]
    ics = [
        {"type": "x-mitre-collection", "x_mitre_version": "test"},
        _pattern("i1", "T0800", "OT thing"),
        _action("b1", "M0916", "Vulnerability Scanning", "Scan devices."),
        _action("b2", "M0930", "Network Segmentation", "Segment the control network."),
        _action("b3", "M0937", "Filter Network Traffic", "Filter traffic."),
        _pattern("i2", "T0801", "OT scan-only"),
        _rel("mitigates", "course-of-action--b1", "attack-pattern--i1", "Scan."),
        _rel("mitigates", "course-of-action--b2", "attack-pattern--i1", "Segment."),
        _rel("mitigates", "course-of-action--b1", "attack-pattern--i2", "Scan only."),
    ]
    return index_from_objects({"enterprise": enterprise, "ics": ics})


def _finding(fid, lane="high", severity="high", **extra):
    return {"id": fid, "lane": lane, "severity": severity, "confidence": "high", "rule_id": extra.pop("rule", "r1"),
            "claim_type": extra.pop("claim_type", "observed_action"), "analyst_status": "new",
            "provenance": extra.pop("provenance", "deterministic"), "observed_at": "2024-11-18 15:19:00+00:00",
            "entities": extra.pop("entities", [["host", "web01", "host"]]), "predicate_fields": [],
            "next_checks": extra.pop("next_checks", ["auth_activity"]), "citations": [], **extra}


RULES = {"r1": SimpleNamespace(attack=("T1000.001",), attack_domain="enterprise"),
         "r2": SimpleNamespace(attack=(), attack_domain="enterprise"),
         "r3": SimpleNamespace(attack=("T2000", "T9999"), attack_domain="enterprise"),
         "ics": SimpleNamespace(attack=("T0800",), attack_domain="ics"),
         "ics2": SimpleNamespace(attack=("T0801",), attack_domain="ics")}


def _items(view):
    return {item["id"]: item for item in view["items"]}


def test_techniques_map_to_live_mitigations_through_parents_and_replacements():
    index = fixture_index()
    assert index.resolve("t3000") == ("enterprise", "T3001")
    assert index.mitigations_for("enterprise", "T1000.001") == (
        (("M1001", "Harden the parent link."),), "parent technique T1000")
    assert index.mitigations_for("enterprise", "T4000") == ((), "none")      # its only mitigation is deprecated
    assert ("enterprise", "M1002") not in index.mitigations
    assert index.mitigations[("enterprise", "M1001")].summary == "Harden the things. More detail follows here."
    view = recommendations.build([_finding("f1"), _finding("f2", attack=["T3000"], rule="r2")], RULES, index=index)
    item = _items(view)["rec-enterprise-M1001"]
    assert item["findings"]["ids"] == ["f1", "f2"] and item["findings"]["count"] == 2
    assert {row["id"]: row["basis"] for row in item["techniques"]["items"]} == {
        "T1000.001": "parent technique T1000", "T3001": "technique"}
    assert item["mitigation"]["url"].endswith("/M1001") and item["kind"] == "attack_mitigation"


def test_findings_without_an_actionable_mitigation_get_triage_and_none_is_dropped():
    findings = [_finding("f-none", rule="r2"), _finding("f-pre", rule="r3", lane="lead", severity="low"),
                _finding("f-ok"), _finding("f-ics", rule="ics"), _finding("f-scan", rule="ics2", lane="lead",
                                                                           severity="medium")]
    view = recommendations.build(findings, RULES, index=fixture_index())
    items = _items(view)
    listed = {fid for item in view["items"] for fid in item["findings"]["ids"]}
    assert listed == {finding["id"] for finding in findings}
    assert view["counts"]["with_mitigation"] + view["counts"]["triage"] == len(findings)
    assert items["rec-triage-immediate"]["reasons"] == {"no_technique": 1}
    assert items["rec-triage-longer_term"]["reasons"] == {
        "unknown_technique": 1, "not_actionable": 1, "passive_only": 1}
    assert view["unknown_techniques"] == {"T9999": 1}
    # ATT&CK for ICS: never a recommendation to scan or probe OT devices
    assert "rec-ics-M0930" in items and not any("M0916" in key for key in items)


@pytest.mark.parametrize("lane,severity,status,provenance,expected", [
    ("urgent", "medium", "new", "deterministic", "immediate"),
    ("high", "critical", "new", "deterministic", "immediate"),
    ("high", "high", "new", "deterministic", "immediate"),
    ("high", "medium", "new", "deterministic", "near_term"),
    ("lead", "high", "new", "deterministic", "near_term"),
    ("lead", "medium", "new", "deterministic", "longer_term"),
    ("lead", "low", "confirmed_malicious", "deterministic", "immediate"),
    ("urgent", "critical", "benign", "deterministic", "longer_term"),
    ("high", "high", "expected_activity", "deterministic", "longer_term"),
    ("urgent", "critical", "new", "agent", "near_term"),
    ("high", "high", "confirmed_malicious", "agent", "near_term"),
    ("lead", "medium", "new", "agent", "longer_term"),
])
def test_priority_rules(lane, severity, status, provenance, expected):
    finding = {"id": "f", "lane": lane, "severity": severity, "analyst_status": status, "provenance": provenance}
    level, reason = recommendations.finding_priority(finding)
    assert level == expected and reason
    if provenance == "agent":
        assert "AI agent" in reason


def test_a_recommendation_takes_the_priority_of_its_strongest_finding_and_counts_agent_findings():
    findings = [_finding("lead1", lane="lead", severity="low"), _finding("agent1", lane="urgent", provenance="agent"),
                _finding("high1", lane="high", severity="medium")]
    item = _items(recommendations.build(findings, RULES, index=fixture_index()))["rec-enterprise-M1001"]
    assert item["priority"] == "near_term" and item["findings"]["agent"] == 1
    assert item["priority_reason"].endswith("(agent1)")


def test_mentions_never_drive_a_recommendation():
    findings = [_finding("m1", claim_type="mention", attack=["T1000"]), _finding("m2", claim_type="mention")]
    view = recommendations.build(findings, RULES, index=fixture_index())
    assert view["items"] == [] and view["counts"]["mentions_not_recommended"] == 2
    assert view["mentions"]["finding_ids"] == ["m1", "m2"]


def test_bounded_lists_keep_exact_counts():
    findings = [_finding(f"f{i:03}", entities=[["ip", f"10.0.{i}.1", "src"], ["host", "web01", "host"]])
                for i in range(130)]
    item = _items(recommendations.build(findings, RULES, index=fixture_index()))["rec-enterprise-M1001"]
    assert item["findings"]["count"] == 130 and len(item["findings"]["ids"]) == recommendations.FINDING_IDS
    assert item["findings"]["more"] == 130 - recommendations.FINDING_IDS
    assert item["entities"]["count"] == 131 and item["entities"]["more"] == 131 - recommendations.ENTITIES


def test_unreadable_attack_data_leaves_every_finding_on_triage(monkeypatch):
    def broken():
        raise ValueError("digest mismatch")
    monkeypatch.setattr(recommendations, "load_mitigations", broken)
    view = recommendations.build([_finding("f1"), _finding("f2", lane="lead", severity="low")], RULES)
    assert view["status"] == "unavailable" and "digest mismatch" in view["reason"]
    assert sorted(fid for item in view["items"] for fid in item["findings"]["ids"]) == ["f1", "f2"]
    assert all(item["kind"] == "triage" for item in view["items"])


def test_the_pinned_release_maps_the_shipped_rules():
    index = load_mitigations()
    assert dict(index.version) == {"enterprise": "20.0", "ics": "20.0"}
    assert index.mitigations[("enterprise", "M1038")].name == "Execution Prevention"
    assert not index.mitigations[("enterprise", "M1056")].actionable
    assert "(Citation" not in clean_text("A (Citation: Z) b.")


# ---- the indicator export ---------------------------------------------------------------------------------------


class _Repo:
    """Only what the export reads: stored typed events by id."""

    def __init__(self, events=()):
        self.events = {event["id"]: event for event in events}

    def events_by_ids(self, ids):
        return [self.events[item] for item in ids if item in self.events]


def _event(eid, family, fields, host="web01"):
    return {"id": eid, "family": family, "host": host,
            "event": {"fields": {name: {"value": value, "origin": "test"} for name, value in fields.items()}}}


SHA = "a" * 64
EVENTS = [
    _event("e-net", "net_flow", {"source.ip": "10.1.2.3", "destination.ip": "203.0.113.7",
                                 "tls.ja3": "B" * 32, "tls.ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
                                 "ssh.hassh": "c" * 32, "x509.fingerprint": "D" * 64}, host="sensor1"),
    _event("e-dns", "dns_query", {"dns.question.name": "Evil.Example.COM.", "dns.question.names": ["a.example.org"],
                                  "url.full": "https://user:pw@evil.example.com/x",
                                  "url.original": "/relative/path"}, host="sensor1"),
    _event("e-exec", "process_exec", {"process.executable": "C:\\Windows\\Temp\\drop.exe", "file.hash.sha256": SHA,
                                      "process.argv": ["cmd", "/c", "whoami"], "user.name": "alice",
                                      "url.password": "hunter2", "file.name": "=cmd|' /C calc'!A0",
                                      "file.path": "/tmp/token=abcdef/x", "process.name": "-sum"}),
    _event("e-file", "file_change", {"file.hashes": {"md5": "e" * 32, "imphash": "f" * 32},
                                     "file.path": "/var/www/shell.php", "url.full": "http://198.51.100.9/a?q=1"}),
]
NETWORKS = {"source": "configured", "internal": ["10.0.0.0/8"], "external": []}


def _networks():
    from romulus.detect.netdef import SiteNetworks
    return SiteNetworks.from_lists(["10.0.0.0/8"]).record()


def _export_findings():
    return [
        _finding("F1", entities=[["host", "web01", "host"], ["ip", "203.0.113.7", "dst"]],
                 citations=[{"event_id": "e-net"}, {"event_id": "e-dns"}], observed_at="2024-11-18T10:00:00+00:00"),
        _finding("F2", lane="lead", severity="medium", citations=[{"event_id": "e-exec"}, {"event_id": "e-file"},
                                                                    {"event_id": "e-gone"}],
                 predicate_fields=[{"field": "process.argv", "value": ["nc", "198.51.100.200"], "origin": "x"},
                                   {"field": "destination.ip", "value": "198.51.100.200", "origin": "x"}],
                 observed_at="2024-11-18T12:00:00+00:00"),
        _finding("F3", provenance="agent", citations=[{"event_id": "e-net"}], observed_at=None),
        _finding("M1", claim_type="mention", entities=[["ip", "192.0.2.99", "dst"]],
                 citations=[{"event_id": "e-mention"}]),
    ]


def _export(findings=None, events=EVENTS, settings=None, manifest_extra=None):
    findings = _export_findings() if findings is None else findings
    manifest = {"hunt": {"id": "h1", "ended_at": "2024-11-18 17:30:00+00:00",
                         "window": {"start": "2024-11-18T10:00:00+00:00", "end": "2024-11-18T17:30:00+00:00"}},
                "revision": {"id": "h1-r1"}, **(manifest_extra or {})}
    with iocs.collect(_Repo(events), findings, _networks(), settings=settings) as table:
        summary = table.summary()
        stream = io.StringIO()
        iocs.write_csv(table, stream)
        stix = io.StringIO()
        iocs.write_stix(table, stix, manifest)
    return summary, stream.getvalue(), stix.getvalue()


def test_values_come_from_typed_fields_with_their_role_and_scope():
    summary, text, _stix = _export()
    rows = list(csv.DictReader(io.StringIO(text)))
    seen = {(row["kind"], row["value"]) for row in rows}
    assert ("ipv4", "203.0.113.7") in seen and ("ipv4", "10.1.2.3") in seen
    assert ("domain", "evil.example.com") in seen and ("domain", "a.example.org") in seen
    assert ("sha256", SHA) in seen and ("md5", "e" * 32) in seen and ("ja3", "b" * 32) in seen
    assert ("x509_sha256", "d" * 64) in seen and ("hassh", "c" * 32) in seen
    assert ("process_executable", "C:\\Windows\\Temp\\drop.exe") in seen and ("user_account", "alice") in seen
    assert ("url", "http://198.51.100.9/a?q=1") in seen and ("hostname", "sensor1") in seen
    scope = {(row["kind"], row["value"]): row["network_scope"] for row in rows}
    assert scope[("ipv4", "10.1.2.3")] == "internal" and scope[("ipv4", "203.0.113.7")] == "external"
    assert scope[("url", "http://198.51.100.9/a?q=1")] == "external" and scope[("domain", "a.example.org")] == "unknown"
    assert scope[("hostname", "web01")] == "internal" and scope[("sha256", SHA)] == "not_applicable"
    roles = {(row["kind"], row["value"], row["role"], row["field"]) for row in rows}
    assert ("ipv4", "203.0.113.7", "destination address", "destination.ip") in roles
    assert ("ipv4", "203.0.113.7", "destination address", "entity.ip") in roles
    assert ("sha256", SHA, "process image hash", "file.hash.sha256") in roles
    # the predicate's typed destination is exported; its argv (and every argv) is not
    assert ("ipv4", "198.51.100.200") in seen and not any("whoami" in row["value"] for row in rows)
    # the agent finding's values are labelled; it records no time, so the value's times come from the others
    agent_rows = [row for row in rows if row["finding_id"] == "F3"]
    assert agent_rows and {row["finding_provenance"] for row in agent_rows} == {"agent"}
    assert summary["counts"]["events_not_retained"] == 1 and summary["counts"]["findings"] == 4


def test_mentions_are_never_exported_as_indicators():
    events = [*EVENTS, _event("e-mention", "net_flow", {"destination.ip": "192.0.2.99"})]
    summary, text, stix = _export(events=events)
    assert "192.0.2.99" not in text and "192.0.2.99" not in stix and "M1" not in text
    assert summary["counts"]["mention_findings_skipped"] == 1


def test_credentials_and_secrets_are_withheld_never_exported_in_part(tmp_path):
    settings = Settings(home=tmp_path, es_password="Wh1spered-Pa55word")
    events = [*EVENTS, _event("e-secret", "file_change", {"file.path": "/srv/Wh1spered-Pa55word.txt"})]
    findings = _export_findings()
    findings[1]["citations"].append({"event_id": "e-secret"})
    summary, text, stix = _export(findings=findings, events=events, settings=settings)
    everything = text + stix + json.dumps(summary)
    for secret in ("hunter2", "user:pw", "Wh1spered-Pa55word", "token=abcdef"):
        assert secret not in everything
    withheld = summary["withheld"]
    assert withheld["url"] == {"holds a credential": 1, "not an absolute URL": 1}
    assert withheld["file_path"] == {"holds a configured secret": 1, "holds a credential": 1}
    assert summary["secrets_checked"] is True


def test_csv_cells_cannot_start_a_formula():
    _summary, text, _stix = _export()
    rows = list(csv.reader(io.StringIO(text)))
    values = [row[1] for row in rows[1:]]
    assert "'=cmd|' /C calc'!A0" in values and "'-sum" in values
    for row in rows:
        for value in row:
            assert not re.match(r"^\s*[=+\-@\t\r|%]", value), value
    assert iocs.csv_cell(" =1+1") == "' =1+1" and iocs.csv_cell("@SUM(A1)") == "'@SUM(A1)"


SCO_CONTRIBUTING = {"ipv4-addr": ("value",), "ipv6-addr": ("value",), "domain-name": ("value",), "url": ("value",),
                    "file": ("hashes", "name", "extensions", "parent_directory_ref"), "directory": ("path",),
                    "user-account": ("account_type", "user_id", "account_login"),
                    "x509-certificate": ("hashes", "serial_number")}
SDO_REQUIRED = {"identity": {"created", "modified", "name"},
                "observed-data": {"created", "modified", "first_observed", "last_observed", "number_observed",
                                  "object_refs"},
                "report": {"created", "modified", "name", "published", "object_refs", "report_types"}}
_ID = re.compile(r"^([a-z0-9-]+)--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


def validate_stix(document: dict) -> dict:
    """Structural STIX 2.1 checks: bundle shape, ids, required properties, timestamps and that every ref resolves."""
    assert document["type"] == "bundle" and _ID.match(document["id"]).group(1) == "bundle"
    assert "spec_version" not in document
    objects = document["objects"]
    ids = [item["id"] for item in objects]
    assert len(ids) == len(set(ids))
    known = set(ids)
    for item in objects:
        match = _ID.match(item["id"])
        assert match and match.group(1) == item["type"] and item["spec_version"] == "2.1"
        for key in item:
            assert re.fullmatch(r"[a-z0-9_]{3,250}", key) or key == "id", key
        if item["type"] in SDO_REQUIRED:
            assert SDO_REQUIRED[item["type"]] <= set(item)
            for key in ("created", "modified", "first_observed", "last_observed", "published"):
                if key in item:
                    assert _TIME.match(item[key]), (key, item[key])
            if item.get("created_by_ref"):
                assert item["created_by_ref"] in known
        else:
            contributing = SCO_CONTRIBUTING.get(item["type"])
            if contributing is None:          # a custom observable: identified by all its own properties
                assert item["type"].startswith("x-romulus-")
                contributing = tuple(key for key in item if key not in ("type", "id", "spec_version"))
            content = {key: item[key] for key in contributing if key in item}
            expected = uuid.uuid5(iocs.SCO_NAMESPACE, json.dumps(content, sort_keys=True, separators=(",", ":"),
                                                                 ensure_ascii=False))
            assert item["id"] == f"{item['type']}--{expected}"
            if "parent_directory_ref" in item:
                assert item["parent_directory_ref"] in known
        if item["type"] == "observed-data":
            assert 1 <= item["number_observed"] <= 999_999_999
            assert item["first_observed"] <= item["last_observed"]
            assert item["object_refs"] and set(item["object_refs"]) <= known
    reports = [item for item in objects if item["type"] == "report"]
    assert len(reports) == 1
    assert set(reports[0]["object_refs"]) == known - {reports[0]["id"]}
    return {item["id"]: item for item in objects}


def test_the_stix_bundle_is_valid_deterministic_and_resolves_every_reference():
    summary, _text, stix = _export()
    objects = validate_stix(json.loads(stix))
    observed = [item for item in objects.values() if item["type"] == "observed-data"]
    assert len(observed) == summary["counts"]["indicators"]
    exe = next(item for item in objects.values() if item["type"] == "file" and item.get("name") == "drop.exe")
    assert objects[exe["parent_directory_ref"]]["path"] == "C:\\Windows\\Temp"
    by_value = {objects[item["object_refs"][-1]].get("value"): item for item in observed}
    external = by_value["203.0.113.7"]
    assert external["x_romulus_network_scope"] == "external" and external["x_romulus_finding_ids"] == ["F1", "F3"]
    assert external["x_romulus_provenance"] == {"agent": 1, "deterministic": 1}
    assert external["first_observed"] == external["last_observed"] == "2024-11-18T10:00:00.000Z"
    # the same content gives the same bytes
    assert _export()[2] == stix


def test_observable_ids_agree_with_the_reference_stix_library():
    """The known answer the OASIS stix2 library's deterministic-id tests assert for a File observable."""
    contributing = {"name": "example.exe",
                    "hashes": {"SHA-256": "841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649"},
                    "extensions": {"windows-pebinary-ext": {"pe_type": "exe", "machine_hex": "014c", "sections": [
                        {"name": ".data", "size": 4096, "entropy": 7.980693, "hashes": {
                            "SHA-256": "6e3b6f3978e5cd96ba7abee35c24e867b7e64072e2ecb22d0ee7a6e6af6894d0"}}]}}}
    assert iocs.sco_id("file", contributing) == "file--ced31cd4-bdcb-537d-aefa-92d291bfc11d"


def test_a_value_no_finding_dated_takes_the_hunt_window_and_says_so():
    findings = [_finding("F9", entities=[["ip", "203.0.113.50", "dst"]], observed_at=None)]
    _summary, _text, stix = _export(findings=findings)
    observed = next(item for item in json.loads(stix)["objects"] if item["type"] == "observed-data"
                    and item["x_romulus_kind"] == "ipv4")
    assert observed["first_observed"] == "2024-11-18T10:00:00.000Z"
    assert observed["last_observed"] == "2024-11-18T17:30:00.000Z"
    assert "hunt window" in observed["x_romulus_time_basis"]


def test_an_unreadable_site_network_record_marks_addresses_unknown_never_external():
    with iocs.collect(_Repo(), [_finding("F1", entities=[["ip", "203.0.113.7", "dst"]])],
                      {"source": "unreadable"}) as table:
        summary = table.summary()
    assert summary["counts"]["by_kind"]["ipv4"] == {"indicators": 1, "rows": 1, "unknown": 1}
    assert summary["internal_networks"]["source"] == "unreadable"


class _Sink:
    def __init__(self):
        self.size, self.digest = 0, hashlib.sha256()

    def write(self, text):
        self.size += len(text)
        self.digest.update(text.encode("utf-8"))


def _synthetic(total):
    return [{"id": f"F{i:06}", "lane": "lead", "severity": "medium", "confidence": "medium", "rule_id": "r1",
             "claim_type": "observed_action", "provenance": "deterministic", "analyst_status": "new",
             "observed_at": f"2024-11-18T{10 + i % 7:02}:00:00+00:00", "predicate_fields": [], "citations": [],
             "next_checks": ["auth_activity"],
             "entities": [["ip", f"203.{i % 7}.{i // 256 % 256}.{i % 256}", "dst"], ["host", f"h{i % 500}", "host"],
                          ["account", f"u{i % 1000}", "actor"]]} for i in range(total)]


def _pipeline(findings):
    with iocs.collect(_Repo(), findings, _networks()) as table:
        summary = table.summary()
        rows = iocs.write_csv(table, _Sink())
        written = iocs.write_stix(table, _Sink(), {"hunt": {"id": "h"}, "revision": {"id": "h-r1"}})
    return summary, rows, written, recommendations.build(findings, RULES, index=fixture_index())


def test_a_hundred_thousand_findings_export_exactly():
    total = 100_000
    findings = _synthetic(total)
    distinct_ips = len({finding["entities"][0][1] for finding in findings})
    started = time.monotonic()
    summary, rows, written, view = _pipeline(findings)
    assert summary["counts"]["indicators"] == distinct_ips + 500 + 1000
    assert rows == summary["counts"]["rows"] == 3 * total
    assert written["observed_data"] == summary["counts"]["indicators"]
    item = _items(view)["rec-enterprise-M1001"]
    assert item["findings"]["count"] == total and item["entities"]["count"] == distinct_ips + 1500
    assert time.monotonic() - started < 240


def test_export_and_recommendation_memory_does_not_grow_with_the_findings():
    """The per-hunt state lives in scratch files: five times the findings leave the Python heap's peak flat."""
    peaks = []
    for total in (5_000, 25_000):
        findings = _synthetic(total)
        tracemalloc.start()
        _pipeline(findings)
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    assert peaks[1] < peaks[0] * 1.5 + 2 * 1024 * 1024, peaks


# ---- report integration -----------------------------------------------------------------------------------------


def test_the_manifest_carries_both_sections_and_renders_them():
    repo, finding_id = _repo_with_finding()
    m = publish_revision(repo, "h1", "test")
    assert m["schema"] in ("report-manifest@1", "report-manifest@2")
    assert m["recommendations"]["status"] == "complete" and m["indicators"]["status"] == "complete"
    item = m["recommendations"]["items"][0]
    assert finding_id in item["findings"]["ids"] and item["mitigation"]["id"].startswith("M")
    text = render(m)
    assert "## Recommendations" in text and "## Indicators (IOC export)" in text
    assert f"[{m['revision']['id']}-iocs.csv]" in text


def test_write_reports_writes_the_exports_atomically_beside_the_others(tmp_path):
    repo, _ = _repo_with_finding()
    m = publish_revision(repo, "h1", "test")
    paths = bundle.write_reports(repo, m, tmp_path)
    assert {"json", "md", "docx", "iocs_csv", "iocs_stix"} <= set(paths)
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(
        ["h1-r1.json", "h1-r1.md", "h1-r1.docx", "h1-r1-iocs.csv", "h1-r1-iocs-stix.json"])
    validate_stix(json.loads(paths["iocs_stix"].read_text(encoding="utf-8")))
    first = (paths["iocs_csv"].read_bytes(), paths["iocs_stix"].read_bytes())
    assert bundle.write_reports(repo, m, tmp_path)["iocs_csv"].read_bytes() == first[0]
    assert paths["iocs_stix"].read_bytes() == first[1]
    with zipfile.ZipFile(paths["docx"]) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
    assert "Indicator export" in document and "M1026" in document


@pytest.mark.parametrize("failure", ["writer", "digest", "unavailable"])
def test_an_export_failure_costs_no_other_output(tmp_path, monkeypatch, failure):
    repo, _ = _repo_with_finding()
    m = publish_revision(repo, "h1", "test")
    bundle.write_reports(repo, m, tmp_path)
    earlier = (tmp_path / "h1-r1-iocs.csv").read_bytes()
    if failure == "writer":
        def broken(*_args, **_kwargs):
            raise RuntimeError("disk full")
        monkeypatch.setattr(iocs, "write_stix", broken)
    elif failure == "digest":
        m = {**m, "indicators": {**m["indicators"], "digest": "0" * 64}}
    else:
        m = {**m, "indicators": {"label": iocs.LABEL, "status": "unavailable", "reason": "boom"}}
    paths = bundle.write_reports(repo, m, tmp_path)
    assert {"json", "md", "docx", "iocs_error"} <= set(paths) and "iocs_csv" not in paths
    note = paths["iocs_error"].read_text(encoding="utf-8")
    assert "was not written" in note and "h1-r1" in note
    assert (tmp_path / "h1-r1-iocs.csv").read_bytes() == earlier          # an earlier export is left as it was
    assert not [path for path in tmp_path.iterdir() if path.name.startswith(".")]
    # the next good write removes the note
    monkeypatch.undo()
    good = publish_revision(repo, "h1", "test")
    assert "iocs_error" not in bundle.write_reports(repo, {**good, "revision": m["revision"]}, tmp_path)
    assert not (tmp_path / "h1-r1.iocs-error.txt").exists()


def test_a_manifest_from_before_the_sections_renders_and_exports_nothing(tmp_path):
    repo, _ = _repo_with_finding()
    m = publish_revision(repo, "h1", "test")
    old = {key: value for key, value in m.items() if key not in ("recommendations", "indicators")}
    text = render(old)
    assert "## Recommendations" not in text and "## Indicators" not in text
    paths = bundle.write_reports(repo, old, tmp_path)
    assert set(paths) == {"json", "md", "docx"}
    with zipfile.ZipFile(paths["docx"]) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
    assert "No recommendation set is part of this report revision" in document


def test_canonical_sections_follow_the_deterministic_findings_by_content():
    repo, _ = _repo_with_finding()
    canonical = canonical_manifest(repo, "h1")
    item = canonical["recommendations"]["items"][0]
    assert all(fid.startswith("F-") for fid in item["findings"]["ids"])
    assert "digest" not in canonical["indicators"] and canonical["indicators"]["status"] == "complete"


def test_settings_reach_the_export_through_publication(tmp_path):
    repo, _ = _repo_with_finding()
    settings = Settings(home=tmp_path, es_password="Wh1spered-Pa55word")
    m = build_manifest(repo, "h1", "test", settings=settings)
    assert m["indicators"]["secrets_checked"] is True
    m = publish_revision(repo, "h1", "test", settings=settings)
    paths = bundle.write_reports(repo, m, tmp_path / "out", settings=settings)
    assert "iocs_csv" in paths
    # without the settings the rows are the same here (nothing holds the secret), so the digest check passes
    assert "iocs_csv" in bundle.write_reports(repo, m, tmp_path / "other")


def test_executive_document_lists_recommendations_by_priority(tmp_path):
    repo, _ = _repo_with_finding()
    m = publish_revision(repo, "h1", "test")
    path = Path(tmp_path) / "x.docx"
    executive.write(m, path, "technical.md")
    with zipfile.ZipFile(path) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
    assert "Immediate" in document and "Privileged Account Management (M1026)" in document
    assert "MITRE ATT&amp;CK" in document


def test_the_web_report_list_links_the_exports_and_serves_them(client):  # noqa: F811
    web, password, _ = client
    _login(web, password)
    page = web.get("/hunts/h1")
    assert web.post("/hunts/h1/report", data={"csrf": _csrf(page.text)}, follow_redirects=False).status_code == 303
    page = web.get("/hunts/h1")
    assert 'href="/reports/h1/h1-r1-iocs.csv"' in page.text and 'href="/reports/h1/h1-r1-iocs-stix.json"' in page.text
    served = web.get("/reports/h1/h1-r1-iocs.csv")
    assert served.status_code == 200 and served.headers["content-type"].startswith("text/csv")
    assert served.text.startswith("kind,value,role,field")
    stix = web.get("/reports/h1/h1-r1-iocs-stix.json")
    assert stix.status_code == 200
    validate_stix(stix.json())
    assert web.get("/reports/h1/other-iocs.csv").status_code == 404
