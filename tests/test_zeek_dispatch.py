"""Catalog dispatch changes only the newly supported Zeek logs.

The fixture holds native record groups and their producer-scoped baseline dumps. Its baseline metadata
identifies the source used for each group: core shapes, Windows records, and the six health inputs whose
recorded baseline still skipped them. The current catalog turns only newly supported shipped logs into
typed events; undeclared plain JSON and uncatalogued logs keep their named skips.

A producer epoch changes its event ids and producer tags. Those fields are rebased only after complete
native-output comparisons prove every typed value, origin, raw reference, skip and error unchanged.
The Windows dumps correspond to windows_baseline; the health inputs record unread output from
health_baseline. Reversing the Zeek identity replacements and removing the added health inputs and
their batch skips restores the entire previous golden. ICS inputs use the final pre-ICS baseline;
their shipped rows become transactions while undeclared plain JSON keeps its skip.
Credential-bearing raw digests are reconciled
separately with the credential masking boundary below.
"""
import json
from pathlib import Path

import pytest

from romulus.evidence.normalize import NORMALIZER_VERSION, normalize_hits, raw_digest
from romulus.evidence.windows import WINDOWS_NORMALIZER
from romulus.evidence.zeek import ZEEK_DUPLICATE, ZEEK_NORMALIZER, scrub_zeek_source, zeek_record
from romulus.evidence.zeek_catalog import ANALYZER_LOGS, HEALTH_LOGS, ICS_LOGS, WINDOWS_PROTOCOL_LOGS

GOLDEN = json.loads((Path(__file__).parent / "data" / "zeek_dispatch_golden.json").read_text(encoding="utf-8"))
RECORDS = GOLDEN["records"]


def _now_read(name: str):
    """The newly read protocol or health log recognized for this group; None for other groups."""
    recognized = {zeek_record(h["_source"]) for h in RECORDS[name]["hits"]} - {None}
    logs = {record.log for record in recognized}
    return next(iter(logs)) if len(logs) == 1 and next(iter(logs)) in (*WINDOWS_PROTOCOL_LOGS, *HEALTH_LOGS, *ICS_LOGS) else None


NEWLY_READ = sorted(name for name in RECORDS if _now_read(name) is not None)
UNCHANGED = sorted(set(RECORDS) - set(NEWLY_READ))


def _scrubbed_digests() -> dict[str, str]:
    """The digest each golden record has now that a Zeek record's digest is over its stored form, credentials masked
    (raw_digest), for each record whose stored form differs from its source: only those digests move."""
    out = {}
    for record in RECORDS.values():
        for hit in record["hits"]:
            if scrub_zeek_source(hit["_source"]) != hit["_source"]:
                out[f"{hit['_index']}/{hit['_id']}"] = raw_digest(hit["_source"])
    return out


SCRUBBED = _scrubbed_digests()


def rebased(dumps: list[dict]) -> list[dict]:
    """Golden event dumps with the digests of credential-bearing records as they are now computed."""
    return [{**e, "raw": [{**r, "digest": SCRUBBED.get(f"{r['target']}/{r['native_id']}", r["digest"])}
                          for r in e["raw"]]} for e in dumps]


def test_only_credential_bearing_records_change_their_digest():
    """The SNMP rows carry a community (a credential): their stored form masks it, so their digest moves."""
    assert SCRUBBED and {key.rsplit("/", 1)[1] for key in SCRUBBED} <= {
        h["_id"] for name in RECORDS if name.startswith("zeek-snmp-") for h in RECORDS[name]["hits"]} | {
        h["_id"] for name in NEWLY_READ for h in RECORDS[name]["hits"]}


def dumped(events, skips, errors) -> dict:
    return {"events": [json.loads(e.model_dump_json()) for e in events], "skips": dict(skips),
            "errors": [list(e) for e in errors]}


def test_the_golden_holds_the_baseline_of_every_shape():
    assert (GOLDEN["baseline"] == "b13fdfe" and GOLDEN["windows_baseline"] == "7dd3fe45728bc3d1ec27b54ba9a2f887d512822c"
            and GOLDEN["health_baseline"] == "48a6639fda2aa0b4dd57295cfc8530d9b8d566a9"
            and GOLDEN["ics_baseline"] == "d64b5caa37c22d76732bf63c9bf4154baf6d3cb4"
            and GOLDEN["zeek_producer"] == ZEEK_NORMALIZER)
    producers = {e["normalizer"] for record in RECORDS.values() for e in record["events"]}
    assert producers == {NORMALIZER_VERSION, WINDOWS_NORMALIZER, ZEEK_NORMALIZER}
    assert {"linux-audit-group", "systemd-journal-sshd", "apache-access", "windows-security-elastic_agent",
            "malcolm-suricata-ftp", "eve-fileinfo", "arkime-provider", "zeek-icmp", "zeek-conn-malcolm",
            "zeek-conn-security_onion-bare", "zeek-files-5.0-security_onion"} <= set(RECORDS)
    # every analyzer log in every shape that writes it
    for log in (*ANALYZER_LOGS, *HEALTH_LOGS, *ICS_LOGS):
        for shape in log.names:
            assert f"zeek-{log.name}-{shape}" in RECORDS, (log.name, shape)
    # exactly the Windows-protocol rows a shipper indexes (plain Zeek JSON is read only through a site declaration,
    # never by normalize_hits), their variants, and the conn-shaped rows that named smb_files at the baseline
    shipped = {f"zeek-{log.name}-{shape}" for log in (*WINDOWS_PROTOCOL_LOGS, *HEALTH_LOGS, *ICS_LOGS) for shape in set(log.names) - {"plain"}}
    variants = {"zeek-ldap-6.1-malcolm", "zeek-ldap-6.1-security_onion", "zeek-ldap_search-6.1-malcolm",
                "zeek-ldap_search-6.1-security_onion", "zeek-smb_cmd-no-file-malcolm", "zeek-smb_cmd-no-file-elastic",
                "zeek-smb_cmd-malcolm-text"}
    renamed = {f"zeek-uncatalogued-{shape}-smb_files" for shape in ("malcolm", "elastic", "security_onion")}
    assert set(NEWLY_READ) == shipped | variants | renamed
    # the core analyzer logs, conn, and a log still outside the catalog stay as they were
    assert {"zeek-dns-malcolm", "zeek-http-elastic", "zeek-conn-security_onion", "zeek-dns-plain",
            "zeek-uncatalogued-malcolm-opcua_binary", "zeek-uncatalogued-elastic-opcua_binary",
            "zeek-uncatalogued-security_onion-opcua_binary", "zeek-uncatalogued-security_onion-files"} <= set(UNCHANGED)


@pytest.mark.parametrize("name", UNCHANGED)
def test_a_record_normalizes_exactly_as_before(name):
    expected = {key: RECORDS[name][key] for key in ("events", "skips", "errors")}
    expected["events"] = rebased(expected["events"])
    assert dumped(*normalize_hits(RECORDS[name]["hits"])) == expected


@pytest.mark.parametrize("name", NEWLY_READ)
def test_a_newly_catalogued_zeek_log_changes_from_its_skip_to_typed_events(name):
    """At the baseline the group was one skip naming its dataset (a record no rule evaluated); now every row is an
    event of the log's family from the Zeek producer, with no skip or error."""
    before = RECORDS[name]
    hits = before["hits"]
    [reason] = before["skips"]
    assert before["events"] == [] and before["errors"] == [] and before["skips"][reason] == len(hits)
    assert reason.startswith("dataset:") and reason.endswith(" is not normalized")
    log = _now_read(name)
    events, skips, errors = normalize_hits(hits)
    assert (skips, errors) == ({}, []) and len(events) == len(hits)
    for event in events:
        assert (event.family, event.normalizer, event.get("zeek.log")) == (log.family, ZEEK_NORMALIZER, log.name)


def test_all_records_in_one_batch_normalize_as_before_apart_from_the_newly_read_rows():
    changed = {h["_id"] for name in NEWLY_READ for h in RECORDS[name]["hits"]}
    hits = [h for name in sorted(RECORDS) for h in RECORDS[name]["hits"]]
    events, skips, errors = normalize_hits(hits)
    batch = GOLDEN["batch"]

    def kept(dumps):
        return [e for e in dumps if not {r["native_id"] for r in e["raw"]} & changed]

    assert kept([json.loads(e.model_dump_json()) for e in events]) == kept(rebased(batch["events"]))
    expected_skips = dict(batch["skips"])
    for name in NEWLY_READ:
        for reason, count in RECORDS[name]["skips"].items():
            expected_skips[reason] -= count
    # copies among the newly read rows (one logical row written in several layouts for one sensor) merge, as copies
    # always have
    _, changed_skips, _ = normalize_hits([h for name in NEWLY_READ for h in RECORDS[name]["hits"]])
    assert set(changed_skips) <= {ZEEK_DUPLICATE}
    expected_skips[ZEEK_DUPLICATE] = expected_skips.get(ZEEK_DUPLICATE, 0) + changed_skips.get(ZEEK_DUPLICATE, 0)
    assert dict(skips) == {reason: n for reason, n in expected_skips.items() if n}
    assert [list(e) for e in errors] == batch["errors"]
