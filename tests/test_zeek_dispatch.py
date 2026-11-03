"""Zeek dispatch leaves every record that normalized before exactly as it was.

tests/data/zeek_dispatch_golden.json holds the output of `normalize_hits` for each record of
`zeek_factory.previous_shapes()` (Filebeat EVE, Malcolm Suricata, Arkime with and without a provider, the Zeek ICMP
shape, an Apache record and an unknown dataset), produced by the normalizer before Zeek dispatch existed (main at
54bfa96). It is the proof that the shared `lab-ecs` normalizer's output did not change; it is regenerated only with a
`lab-ecs` version bump, never to make a dispatch change pass. Zeek records moved to their own producer; their typed
values are compared field by field.
"""
import json
from pathlib import Path

import pytest

from romulus.evidence.normalize import NORMALIZER_VERSION, normalize_hits
from romulus.evidence.zeek import ZEEK_NORMALIZER
from tests.fixtures.zeek_factory import previous_shapes

GOLDEN = json.loads((Path(__file__).parent / "data" / "zeek_dispatch_golden.json").read_text(encoding="utf-8"))
SHAPES = previous_shapes()
ZEEK = sorted(name for name in SHAPES if name.startswith("zeek-"))
OTHERS = sorted(name for name in SHAPES if not name.startswith("zeek-"))
# what the Zeek producer adds to the ICMP shape: the sensor as a typed field, and the log the record belongs to
ZEEK_ADDED = {"observer.name", "zeek.log"}


def dumped(events, skips, errors) -> dict:
    return {"events": [json.loads(e.model_dump_json()) for e in events], "skips": skips,
            "errors": [list(e) for e in errors]}


def test_the_golden_covers_every_previous_shape():
    assert sorted(GOLDEN) == sorted(SHAPES)
    assert all(e["normalizer"] == NORMALIZER_VERSION for v in GOLDEN.values() for e in v["events"])


@pytest.mark.parametrize("name", OTHERS)
def test_a_record_that_normalized_before_normalizes_exactly_as_before(name):
    assert dumped(*normalize_hits([SHAPES[name]])) == GOLDEN[name]


def test_the_previous_shapes_in_one_batch_each_normalize_as_before():
    events, skips, errors = normalize_hits(list(SHAPES.values()))
    assert errors == []
    by_record = {e.raw[0].native_id: json.loads(e.model_dump_json()) for e in events}
    for name in OTHERS:
        for expected in GOLDEN[name]["events"]:
            assert by_record[name] == expected, name
    expected_skips: dict[str, int] = {}
    for name in SHAPES:
        for reason, count in GOLDEN[name]["skips"].items():
            expected_skips[reason] = expected_skips.get(reason, 0) + count
    assert skips == expected_skips


@pytest.mark.parametrize("name", ZEEK)
def test_the_zeek_icmp_shape_keeps_every_typed_value_under_its_own_producer(name):
    events, skips, errors = normalize_hits([SHAPES[name]])
    assert (skips, errors) == (GOLDEN[name]["skips"], [])
    [before] = GOLDEN[name]["events"]
    [after] = [json.loads(e.model_dump_json()) for e in events]
    assert after["normalizer"] == ZEEK_NORMALIZER and after["id"] != before["id"]
    for key in ("family", "ts", "host", "outcome", "caveats", "raw"):
        assert after[key] == before[key], key
    old = {k: v["value"] for k, v in before["fields"].items()}
    new = {k: v["value"] for k, v in after["fields"].items()}
    assert {k: new.get(k) for k in old} == old
    assert set(new) - set(old) <= ZEEK_ADDED
