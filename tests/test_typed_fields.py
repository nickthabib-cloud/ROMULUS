"""Typed fields are built without per-field validation; the events they make serialize exactly as validated ones.

`fv` builds a FieldValue directly when its origin is a str (every normalizer writes the origin as an f-string),
and falls back to the validating constructor otherwise, so an unexpected origin is still refused the same way.
These tests compare every event of every normalizer family built both ways.
"""
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from romulus.detect import correlation
from romulus.evidence import normalize, typed
from romulus.evidence.normalize import BootIntervals, normalize_hits
from romulus.evidence.typed import FieldValue, fv
from romulus.hunt import sweep
from tests import throughput_fixture as tf

VALUES = [None, 0, 7, -1, 2**70, 1.5, float("inf"), "", "text", "ünï\x1dcode", True, False, [], ["a", 1, None],
          {"k": [1, {"n": None}]}, [{"name": "x", "data": None}], datetime(2024, 11, 18, tzinfo=UTC)]


def _validated(value, origin):
    return FieldValue(value=value, origin=origin)


@pytest.mark.parametrize("value", VALUES, ids=repr)
def test_a_built_field_equals_a_validated_one(value):
    built, checked = fv(value, "doc-1:event.original#eve.src_ip"), _validated(value, "doc-1:event.original#eve.src_ip")
    assert built == checked and type(built) is FieldValue
    assert built.value is checked.value and type(built.origin) is str
    assert built.model_fields_set == checked.model_fields_set
    assert built.model_dump() == checked.model_dump()
    assert built.model_dump(mode="json") == checked.model_dump(mode="json")
    assert built.model_dump_json() == checked.model_dump_json()


def test_changing_one_built_field_leaves_every_other_field_as_it_was():
    one, other = fv(1, "a:x"), fv(2, "b:y")
    one.value = 5
    copied = other.model_copy(update={"value": 9})
    assert (one.value, one.origin, one.model_fields_set) == (5, "a:x", {"value", "origin"})
    assert other == _validated(2, "b:y") and other.model_fields_set == {"value", "origin"}
    assert copied.model_dump() == {"value": 9, "origin": "b:y"} and other.value == 2


class _Text(str):
    pass


@pytest.mark.parametrize("origin", [None, 12, b"bytes", ["a"], _Text("sub")], ids=repr)
def test_a_field_with_a_non_text_origin_is_validated_as_before(origin):
    def outcome(build):
        try:
            field = build("x", origin)
        except ValidationError as error:
            return "refused", [e["type"] for e in error.errors()]
        return "built", field.model_dump(), type(field.origin)

    assert outcome(fv) == outcome(_validated)
    if origin is None or isinstance(origin, (int, list)):
        assert outcome(fv)[0] == "refused"


def _every_family() -> list[dict]:
    """The fixture's records plus audit admin records the fixture's story does not write."""
    docs = tf.build(1)
    b = tf.Builder(3)
    at = tf.T0 + timedelta(minutes=50)
    b._audit("web1", at, 9001, "SERVICE_START",
             "pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=cron comm=\"systemd\" exe=\"/usr/lib/systemd/"
             "systemd\" hostname=? addr=? terminal=? res=success'")
    b._audit("web1", at, 9002, "SYSTEM_RUNLEVEL",
             "pid=5 uid=0 auid=4294967295 ses=4294967295 msg='old-level=N new-level=5 comm=\"systemd-update-utmp\" "
             "exe=\"/usr/lib/systemd/systemd-update-utmp\" hostname=? addr=? terminal=? res=success'")
    b._audit("web1", at, 9003, "CONFIG_CHANGE", "op=add_rule key=\"watch\" list=4 res=1")
    b._audit("web1", at, 9004, "CONFIG_CHANGE", "audit_backlog_limit=8192 old=64 auid=0 ses=4 res=1")
    return [record for records in docs.values() for record in records] + b.host


@pytest.fixture(scope="module")
def records():
    return _every_family()


def _dumps(records, monkeypatch=None):
    with pytest.MonkeyPatch.context() as patch:
        if monkeypatch:
            patch.setattr(normalize, "fv", _validated)
        events, skips, errors = normalize_hits(records, BootIntervals())
    return events, skips, errors


def test_every_family_serializes_identically_with_validated_fields(records):
    built, built_skips, built_errors = _dumps(records)
    checked, checked_skips, checked_errors = _dumps(records, monkeypatch=True)
    families = {event.family for event in built}
    assert families >= set().union(*sweep.LINUX_DATASET_FAMILIES.values()) | {"net_session"}
    assert (built_skips, built_errors) == (checked_skips, checked_errors)
    assert len(built) == len(checked)
    for one, other in zip(built, checked, strict=True):
        assert one.model_dump(mode="json") == other.model_dump(mode="json")
        assert one.model_dump_json() == other.model_dump_json()
        assert all(type(field.origin) is str and type(field) is FieldValue for field in one.fields.values())


def test_the_cached_address_helpers_answer_as_the_plain_ones():
    cases = ["10.0.0.1", "203.0.113.8", "::ffff:203.0.113.8", "2001:db8::1", "fe80::1", "255.255.255.255",
             "0.0.0.0", "127.0.0.1", "224.0.0.1", " 10.0.0.1", "not-an-ip", "", None, 42, "8.8.8.8", "100.64.0.1"]
    for value in cases * 2:                                     # the second pass answers from the cache
        assert correlation.canon_ip(value) == correlation._canon_ip_uncached(str(value))
        ip = correlation.canon_ip(value)
        if ip is not None:
            assert correlation.external(ip) == correlation._external_uncached(ip)
    assert correlation.external(None) is False
    assert correlation._canon_text.cache_info().maxsize == correlation.ADDRESS_CACHE
    assert correlation._external_text.cache_info().maxsize == correlation.ADDRESS_CACHE


def test_typed_module_still_exposes_the_field_model():
    assert typed.fv is fv and typed.FieldValue is FieldValue
