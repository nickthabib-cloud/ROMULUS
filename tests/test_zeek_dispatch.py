"""Reading the Windows-protocol Zeek logs changes nothing that normalized before: only their own rows change, from the
skip every unread dataset gets to typed events.

tests/data/zeek_dispatch_golden.json holds the record groups of `zeek_factory.dispatch_records()` and what
`normalize_hits` made of them, each group alone and all of them in one batch, produced by the sources at commit
b13fdfe (`git archive b13fdfe src`, run on the records the factory writes): the conn normalizer and the core analyzer
logs, before any Windows-protocol log was read. Among them: Filebeat EVE and Malcolm Suricata records of every event
type, Arkime sessions with and without a provider, an audit event's records, journal and Apache records, Windows events
in two shipper shapes, the Zeek ICMP shape, Zeek conn rows in every shape, rows of every analyzer log in every shape
that writes it, and rows of logs still outside the catalog. The golden is regenerated only when a baseline moves, never
to make a dispatch change pass; its non-Zeek groups equal those of the golden made before Zeek records were read at all
(commit 54bfa96), and its core analyzer groups those the core analyzer logs' own golden compared with that baseline.

Two classes, decided by the records themselves:
- every group whose rows' log the catalog now reads as a Windows-protocol log changes from that skip to events of the
  log's family, and nothing else about it;
- every other group normalizes exactly as before, typed values, ids, origins, skips and errors: every non-Zeek group,
  every conn and core analyzer group, and every row of a log still outside the catalog.
"""
import json
from pathlib import Path

import pytest

from romulus.evidence.normalize import NORMALIZER_VERSION, normalize_hits
from romulus.evidence.windows import WINDOWS_NORMALIZER
from romulus.evidence.zeek import ZEEK_DUPLICATE, ZEEK_NORMALIZER, zeek_record
from romulus.evidence.zeek_catalog import ANALYZER_LOGS, WINDOWS_PROTOCOL_LOGS

GOLDEN = json.loads((Path(__file__).parent / "data" / "zeek_dispatch_golden.json").read_text(encoding="utf-8"))
RECORDS = GOLDEN["records"]


def _now_read(name: str):
    """The Windows-protocol log the group's rows belong to, by today's recognition and catalog; None for any other
    group."""
    recognized = {zeek_record(h["_source"]) for h in RECORDS[name]["hits"]} - {None}
    logs = {record.log for record in recognized}
    return next(iter(logs)) if len(logs) == 1 and next(iter(logs)) in WINDOWS_PROTOCOL_LOGS else None


NEWLY_READ = sorted(name for name in RECORDS if _now_read(name) is not None)
UNCHANGED = sorted(set(RECORDS) - set(NEWLY_READ))


def dumped(events, skips, errors) -> dict:
    return {"events": [json.loads(e.model_dump_json()) for e in events], "skips": dict(skips),
            "errors": [list(e) for e in errors]}


def test_the_golden_holds_the_baseline_of_every_shape():
    assert GOLDEN["baseline"] == "b13fdfe"
    producers = {e["normalizer"] for record in RECORDS.values() for e in record["events"]}
    assert producers == {NORMALIZER_VERSION, WINDOWS_NORMALIZER, ZEEK_NORMALIZER}
    assert {"linux-audit-group", "systemd-journal-sshd", "apache-access", "windows-security-elastic_agent",
            "malcolm-suricata-ftp", "eve-fileinfo", "arkime-provider", "zeek-icmp", "zeek-conn-malcolm",
            "zeek-conn-security_onion-bare", "zeek-files-5.0-security_onion"} <= set(RECORDS)
    # every analyzer log in every shape that writes it
    for log in ANALYZER_LOGS:
        for shape in log.names:
            assert f"zeek-{log.name}-{shape}" in RECORDS, (log.name, shape)
    # exactly the Windows-protocol rows a shipper indexes (plain Zeek JSON is read only through a site declaration,
    # never by normalize_hits), their variants, and the conn-shaped rows that named smb_files at the baseline
    shipped = {f"zeek-{log.name}-{shape}" for log in WINDOWS_PROTOCOL_LOGS for shape in set(log.names) - {"plain"}}
    variants = {"zeek-ldap-6.1-malcolm", "zeek-ldap-6.1-security_onion", "zeek-ldap_search-6.1-malcolm",
                "zeek-ldap_search-6.1-security_onion", "zeek-smb_cmd-no-file-malcolm", "zeek-smb_cmd-no-file-elastic",
                "zeek-smb_cmd-malcolm-text"}
    renamed = {f"zeek-uncatalogued-{shape}-smb_files" for shape in ("malcolm", "elastic", "security_onion")}
    assert set(NEWLY_READ) == shipped | variants | renamed
    # the core analyzer logs, conn, and a log still outside the catalog stay as they were
    assert {"zeek-dns-malcolm", "zeek-http-elastic", "zeek-conn-security_onion", "zeek-dns-plain",
            "zeek-uncatalogued-malcolm-modbus", "zeek-uncatalogued-elastic-modbus",
            "zeek-uncatalogued-security_onion-modbus", "zeek-uncatalogued-security_onion-files"} <= set(UNCHANGED)


@pytest.mark.parametrize("name", UNCHANGED)
def test_a_record_normalizes_exactly_as_before(name):
    expected = {key: RECORDS[name][key] for key in ("events", "skips", "errors")}
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

    assert kept([json.loads(e.model_dump_json()) for e in events]) == kept(batch["events"])
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
