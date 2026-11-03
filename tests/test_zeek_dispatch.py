"""Zeek dispatch leaves every record that normalized, or was counted as skipped, before exactly as it was.

tests/data/zeek_dispatch_golden.json holds the input records of `zeek_factory.previous_shapes()` and what
`normalize_hits` made of them, each group alone and all of them in one batch, produced by the normalizer before Zeek
dispatch existed (the sources of main at 54bfa96). Among them: Filebeat EVE and Malcolm Suricata records of every event
type, Arkime sessions with and without a provider, an audit event's records, journal and Apache records, Windows
events in two shipper shapes, the Zeek ICMP shape, and Zeek rows of logs outside the catalog in each shipper shape.
The file is the proof that the shared `lab-ecs` normalizer's output did not change; it is regenerated only with a
`lab-ecs` version bump, never to make a dispatch change pass. The Zeek ICMP rows moved to their own producer, so
their typed values are compared field by field.
"""
import json
from pathlib import Path

import pytest

from romulus.evidence.normalize import NORMALIZER_VERSION, normalize_hits
from romulus.evidence.zeek import ZEEK_NORMALIZER

GOLDEN = json.loads((Path(__file__).parent / "data" / "zeek_dispatch_golden.json").read_text(encoding="utf-8"))
RECORDS = GOLDEN["records"]
MOVED = sorted(name for name in RECORDS if name.startswith("zeek-icmp"))
UNCHANGED = sorted(name for name in RECORDS if name not in MOVED)
UNCATALOGUED = sorted(name for name in RECORDS if name.startswith("zeek-uncatalogued-"))
# what the Zeek producer adds to the ICMP shape: the sensor as a typed field, and the log the record belongs to
ZEEK_ADDED = {"observer.name", "zeek.log"}


def dumped(events, skips, errors) -> dict:
    return {"events": [json.loads(e.model_dump_json()) for e in events], "skips": dict(skips),
            "errors": [list(e) for e in errors]}


def test_the_golden_was_made_by_this_lab_ecs_version_and_covers_the_shapes():
    assert all(e["normalizer"] in (NORMALIZER_VERSION, "windows-ecs@4")
               for record in RECORDS.values() for e in record["events"])
    assert {"linux-audit-group", "systemd-journal-sshd", "apache-access", "windows-security-elastic_agent",
            "malcolm-suricata-ftp", "eve-fileinfo", "arkime-provider"} <= set(RECORDS)
    assert len(UNCATALOGUED) == 27 and MOVED


@pytest.mark.parametrize("name", UNCHANGED)
def test_a_record_normalizes_exactly_as_before(name):
    expected = {key: RECORDS[name][key] for key in ("events", "skips", "errors")}
    assert dumped(*normalize_hits(RECORDS[name]["hits"])) == expected


@pytest.mark.parametrize("name", UNCATALOGUED)
def test_a_zeek_log_outside_the_catalog_keeps_the_skip_every_unread_dataset_gets(name):
    """Until a log is normalized, the sweep must count its rows as records no rule evaluated: the skip names the
    dataset exactly as it did before Zeek records were read."""
    _events, skips, errors = normalize_hits(RECORDS[name]["hits"])
    assert errors == [] and skips == RECORDS[name]["skips"]
    [reason] = skips
    assert reason.startswith("dataset:") and reason.endswith(" is not normalized")


def test_all_previous_shapes_in_one_batch_normalize_as_before():
    moved_ids = {h["_id"] for name in MOVED for h in RECORDS[name]["hits"]}
    hits = [h for name in sorted(RECORDS) for h in RECORDS[name]["hits"]]
    events, skips, errors = normalize_hits(hits)
    batch = GOLDEN["batch"]

    def kept(dumps):
        return [e for e in dumps if not {r["native_id"] for r in e["raw"]} & moved_ids]

    assert kept([json.loads(e.model_dump_json()) for e in events]) == kept(batch["events"])
    assert (dict(skips), [list(e) for e in errors]) == (batch["skips"], batch["errors"])


@pytest.mark.parametrize("name", MOVED)
def test_the_zeek_icmp_shape_keeps_every_typed_value_under_its_own_producer(name):
    events, skips, errors = normalize_hits(RECORDS[name]["hits"])
    assert (dict(skips), errors) == (RECORDS[name]["skips"], [])
    [before] = RECORDS[name]["events"]
    [after] = [json.loads(e.model_dump_json()) for e in events]
    assert after["normalizer"] == ZEEK_NORMALIZER and after["id"] != before["id"]
    for key in ("family", "ts", "host", "outcome", "caveats", "raw"):
        assert after[key] == before[key], key
    old = {k: v["value"] for k, v in before["fields"].items()}
    new = {k: v["value"] for k, v in after["fields"].items()}
    assert {k: new.get(k) for k in old} == old
    assert set(new) - set(old) <= ZEEK_ADDED
