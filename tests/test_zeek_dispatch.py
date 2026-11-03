"""Reading the Zeek analyzer logs changes nothing that normalized before: only their own rows change, from the skip
every unread dataset gets to typed events.

tests/data/zeek_dispatch_golden.json holds the record groups of `zeek_factory.dispatch_records()` and what
`normalize_hits` made of them, each group alone and all of them in one batch, produced by the sources at commit
cae973f (`git archive cae973f src`, run on the records the factory writes): the conn normalizer, before any analyzer
log was read. Among them: Filebeat EVE and Malcolm Suricata records of every event type, Arkime sessions with and
without a provider, an audit event's records, journal and Apache records, Windows events in two shipper shapes, the
Zeek ICMP shape, Zeek conn rows in every shape, and rows of every analyzer log in every shape that writes it. The
golden is regenerated only when a baseline moves, never to make a dispatch change pass; its non-Zeek groups equal
those of the golden made before Zeek records were read at all (commit 54bfa96).

Three classes, decided by the records themselves:
- every group whose rows' log the catalog now reads as an analyzer log changes from that skip to events of the log's
  family, and nothing else about it;
- the conn record as Security Onion's pipelines index it (dataset ``zeek.conn``, which the baseline misread as an
  Elastic record) is now read as Security Onion's, with the fields only that shape writes;
- every other group normalizes exactly as before, typed values, ids, origins, skips and errors.
"""
import json
from pathlib import Path

import pytest

from romulus.evidence.normalize import NORMALIZER_VERSION, normalize_hits
from romulus.evidence.windows import WINDOWS_NORMALIZER
from romulus.evidence.zeek import ZEEK_DUPLICATE, ZEEK_NORMALIZER, zeek_record
from romulus.evidence.zeek_catalog import ANALYZER_LOGS, CONN

GOLDEN = json.loads((Path(__file__).parent / "data" / "zeek_dispatch_golden.json").read_text(encoding="utf-8"))
RECORDS = GOLDEN["records"]


def _now_read(name: str):
    """The analyzer log the group's rows belong to, by today's recognition and catalog; None for any other group."""
    recognized = {zeek_record(h["_source"]) for h in RECORDS[name]["hits"]} - {None}
    logs = {record.log for record in recognized}
    return next(iter(logs)) if len(logs) == 1 and next(iter(logs)) in ANALYZER_LOGS else None


def _so_conn(name: str) -> bool:
    """A conn group in Security Onion's indexed layout (module "zeek", data stream "zeek", dataset zeek.conn)."""
    records = [zeek_record(h["_source"]) for h in RECORDS[name]["hits"]]
    return all(r is not None and r.shape == "security_onion" and r.log is CONN and r.origin == "event.dataset"
               and h["_source"]["event"]["dataset"] == "zeek.conn" for r, h in zip(records, RECORDS[name]["hits"]))


NEWLY_READ = sorted(name for name in RECORDS if _now_read(name) is not None)
SECURITY_ONION_CONN = sorted(name for name in RECORDS if _so_conn(name))
UNCHANGED = sorted(set(RECORDS) - set(NEWLY_READ) - set(SECURITY_ONION_CONN))


def dumped(events, skips, errors) -> dict:
    return {"events": [json.loads(e.model_dump_json()) for e in events], "skips": dict(skips),
            "errors": [list(e) for e in errors]}


def test_the_golden_holds_the_baseline_of_every_shape():
    assert GOLDEN["baseline"] == "cae973f"
    producers = {e["normalizer"] for record in RECORDS.values() for e in record["events"]}
    assert producers == {NORMALIZER_VERSION, WINDOWS_NORMALIZER, ZEEK_NORMALIZER}
    assert {"linux-audit-group", "systemd-journal-sshd", "apache-access", "windows-security-elastic_agent",
            "malcolm-suricata-ftp", "eve-fileinfo", "arkime-provider", "zeek-icmp", "zeek-conn-malcolm",
            "zeek-conn-security_onion-bare"} <= set(RECORDS)
    # every analyzer log in every shape that writes it, and Zeek 5.0's files layout
    for log in ANALYZER_LOGS:
        for shape in log.names:
            assert f"zeek-{log.name}-{shape}" in RECORDS, (log.name, shape)
    assert SECURITY_ONION_CONN == ["zeek-conn-security_onion"]
    # exactly the analyzer rows a shipper indexes (plain Zeek JSON is read only through a site declaration, never by
    # normalize_hits), and the conn-shaped rows that named a now-catalogued log at the baseline
    shipped = {f"zeek-{log.name}-{shape}" for log in ANALYZER_LOGS for shape in set(log.names) - {"plain"}}
    files_50 = {f"zeek-files-5.0-{shape}" for shape in ("malcolm", "elastic", "security_onion")}
    renamed = {f"zeek-uncatalogued-{shape}-{log}" for shape in ("malcolm", "elastic", "security_onion")
               for log in ("dns", "http", "ssl", "x509", "files", "ssh", "notice", "weird")}
    # Security Onion names the files log "file": a row it would name "files" is no log of its catalog
    renamed.discard("zeek-uncatalogued-security_onion-files")
    assert set(NEWLY_READ) == shipped | files_50 | renamed
    assert {"zeek-uncatalogued-malcolm-smb_files", "zeek-uncatalogued-security_onion-files",
            "zeek-dns-plain"} <= set(UNCHANGED)


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


@pytest.mark.parametrize("name", SECURITY_ONION_CONN)
def test_security_onions_conn_record_is_read_as_its_pipelines_index_it(name):
    """The baseline took Security Onion's zeek.conn dataset for Elastic's: it found no sensor (observer.name) and no
    uid (log.id.uid), read its duration in seconds as nanoseconds, and none of the connection.* fields. Read as
    Security Onion's, the same record types them."""
    [before] = RECORDS[name]["events"]
    [after] = [json.loads(e.model_dump_json()) for e in normalize_hits(RECORDS[name]["hits"])[0]]
    for key in ("family", "ts", "normalizer"):
        assert after[key] == before[key], key
    assert before["host"] is None and after["host"] == "sensor-security_onion-conn"
    old = {k: v["value"] for k, v in before["fields"].items()}
    new = {k: v["value"] for k, v in after["fields"].items()}
    assert before["fields"]["observer.product"]["origin"].endswith(":event.dataset#producer")
    assert after["fields"]["observer.product"]["origin"].endswith(":event.module#producer")
    assert "zeek.uid" not in old and new["zeek.uid"] == "CHhAvVGS1DHFjwGM9"
    assert old["session.duration_s"] == pytest.approx(2.5e-9) and new["session.duration_s"] == 2.5
    assert {"conn.state", "conn.history", "flow.bytes_toserver", "source.bytes"} <= set(new) - set(old)
    shared = {k for k in old if k not in ("session.duration_s", "flow.end")}
    assert {k: new[k] for k in shared} == {k: old[k] for k in shared}


def test_all_records_in_one_batch_normalize_as_before_apart_from_the_newly_read_rows():
    changed = {h["_id"] for name in NEWLY_READ + SECURITY_ONION_CONN for h in RECORDS[name]["hits"]}
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
    _, changed_skips, _ = normalize_hits([h for name in NEWLY_READ + SECURITY_ONION_CONN
                                          for h in RECORDS[name]["hits"]])
    assert set(changed_skips) <= {ZEEK_DUPLICATE}
    expected_skips[ZEEK_DUPLICATE] = expected_skips.get(ZEEK_DUPLICATE, 0) + changed_skips.get(ZEEK_DUPLICATE, 0)
    assert dict(skips) == {reason: n for reason, n in expected_skips.items() if n}
    assert [list(e) for e in errors] == batch["errors"]
