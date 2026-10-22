"""A pivot leaf parses each audit record once, however many steps (grouping, the raw-family prefilter,
normalization) read it; nothing is shared between leaves."""
import pytest

from romulus.evidence import normalize
from romulus.evidence.auditd import parse_record
from romulus.hunt import pivot
from romulus.hunt.pivot import PivotExecutor
from tests import throughput_fixture as tf


@pytest.fixture(scope="module")
def host_records():
    return tf.build(1)[tf.HOST_TARGET]


def _counting(monkeypatch) -> list[str]:
    calls: list[str] = []

    def counted(raw):
        calls.append(raw)
        return parse_record(raw)

    monkeypatch.setattr(pivot, "parse_record", counted)
    monkeypatch.setattr(normalize, "parse_record", counted)
    return calls


@pytest.mark.parametrize("families", [None, {"process_exec"}, {"net_socket"}, {"process_exec", "auth"}])
def test_each_audit_record_is_parsed_once_per_leaf(monkeypatch, host_records, families):
    audit = [r for r in host_records if r["_source"]["event"]["dataset"] == "linux.audit"]
    calls = _counting(monkeypatch)
    events, errors = PivotExecutor(None, None, "h1", {})._normalize_pivot_records(host_records, families)
    assert events and errors                                    # the fixture holds an unparseable record
    assert len(calls) == len(audit)


def test_a_second_leaf_parses_its_records_again(monkeypatch, host_records):
    calls = _counting(monkeypatch)
    executor = PivotExecutor(None, None, "h1", {})
    first, _ = executor._normalize_pivot_records(host_records, {"process_exec"})
    once = len(calls)
    second, _ = executor._normalize_pivot_records(host_records, {"process_exec"})
    assert len(calls) == 2 * once
    assert [e.model_dump(mode="json") for e in first] == [e.model_dump(mode="json") for e in second]
