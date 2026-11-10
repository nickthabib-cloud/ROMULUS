"""Synthetic source gaps remain visible without widening unrelated families."""
from datetime import timedelta

import pytest

from romulus.detect.base import Playbook
from romulus.detect.mail import MailOutboundBurst
from romulus.detect.service_auth import ServicePasswordGuessing
from romulus.evidence.linux_catalog import LOGICAL_FAMILIES, TEXT_FAMILIES
from romulus.evidence.normalize import normalize_hits
from romulus.hunt import sweep as sw
from romulus.report.manifest import _not_assessed
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests.test_linux_text_reporting import ProfileClient, _sample
from tests.test_sweep import START, FakeClient, _complete, _repo


def _hit(message="unrecognized application text", dataset="myapp", module=None):
    event = {"dataset": dataset}
    if module is not None:
        event["module"] = module
    return {"_index": "logs", "_id": "line", "_source": {
        "@timestamp": START.isoformat(), "host": {"name": "host"}, "event": event, "message": message}}


def _contract(role="host", os_family="linux"):
    return contract_from_types("logs", {"@timestamp": "date", "event.dataset": "keyword", "message": "text",
                                        "host.name": "keyword"}, role=role, os_family=os_family, linux_text_mixed=False)


@pytest.mark.parametrize("contract", [None, _contract()])
@pytest.mark.parametrize("message,prefix", [
    ("unrecognized application text", "text line in no recognized format:"),
    ("x" * 65537, "text line too long:"),
], ids=["unknown", "overlong"])
def test_unrecognized_linux_text_is_partial_only_for_text_families(contract, message, prefix):
    fed = {}
    events, skips, errors = normalize_hits([_hit(message)], contract=contract, skip_families=fed)
    assert events == [] and errors == []
    assert len(skips) == 1 and next(iter(skips)).startswith(prefix)
    assert list(fed.values()) == [TEXT_FAMILIES]
    assert sw.Sweep._unsupported_families(sw.Sweep._unsupported_skips(skips), fed) == (TEXT_FAMILIES, {})


@pytest.mark.parametrize("contract", [None, _contract(), _contract("network", "unknown"), _contract("host", "windows")])
def test_module_owned_unmatched_record_keeps_its_original_skip_and_families(contract):
    fed = {}
    events, skips, errors = normalize_hits([_hit(dataset="auditd.weird", module="auditd")],
                                          contract=contract, skip_families=fed)
    reason = "dataset:auditd.weird is not normalized"
    assert events == [] and errors == [] and skips == {reason: 1}
    assert fed == {reason: LOGICAL_FAMILIES["linux.audit"]}
    assert sw.Sweep._unsupported_families(sw.Sweep._unsupported_skips(skips), fed) == (
        LOGICAL_FAMILIES["linux.audit"], {})


@pytest.mark.parametrize("contract", [_contract("network", "unknown"), _contract("host", "windows")])
def test_unknown_dataset_on_other_targets_keeps_base_global_uncertainty(contract):
    fed = {}
    events, skips, errors = normalize_hits([_hit()], contract=contract, skip_families=fed)
    reason = "dataset:myapp is not normalized"
    assert events == [] and errors == [] and skips == {reason: 1}
    assert fed == {reason: None}
    assert sw.Sweep._unsupported_families(sw.Sweep._unsupported_skips(skips), fed) == (sw.ALL_FAMILIES, {})


def test_recognized_untyped_program_is_counted_without_partial_families():
    fed = {}
    events, skips, errors = normalize_hits([_hit("Nov 18 14:00:00 host custom-debug: ordinary diagnostic")],
                                          contract=_contract(), skip_families=fed)
    assert events == [] and errors == [] and sum(skips.values()) == 1
    assert "program 'custom-debug'" in next(iter(skips))
    assert fed == {} and sw.Sweep._unsupported_skips(skips) == {}


class _AuditProbe(Playbook):
    id, title, families = "test.audit", "Audit coverage", ("process_exec",)


class _WindowsProbe(Playbook):
    id, title, families = "test.windows", "Windows coverage", ("script_block",)


class _NetworkProbe(Playbook):
    id, title, families = "test.network", "Network coverage", ("net_session",)


def test_sweep_partition_and_window_keep_text_gaps_partial_without_other_families(monkeypatch):
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [_hit()]))
    repo = _repo()
    window = Window(start=START, end=START + timedelta(minutes=5))
    runner = sw.Sweep(repo, FakeClient(), "h1", window, {"logs": _contract()})
    runner.pack = [ServicePasswordGuessing(), MailOutboundBurst(), _AuditProbe(), _WindowsProbe(), _NetworkProbe()]
    runner._profiles = {"logs": {"role": "host", "os_family": "linux", "datasets": {"myapp": 1, "linux.text": 1}}}
    runner.run_partition("logs", _contract(), [], window, est=1)
    runner.finalize()
    cells = repo.rule_cells("h1")
    for rule in ("auth.password_guessing", "mail.outbound_burst"):
        relevant = [cell for cell in cells if cell["rule_id"] == rule]
        assert {cell["partition"] == "window" for cell in relevant} == {False, True}
        # Aggregate positive-only rules retain their stricter existing window state.
        assert all(cell["state"] == ("positive_only_partial" if cell["partition"] == "window"
                                     else "evaluated_partial") for cell in relevant), [
            (cell["rule_id"], cell["partition"], cell["state"], cell["detail"]) for cell in relevant]
        assert any("text line in no recognized format" in str(cell["detail"]) for cell in relevant)
    for cell in cells:
        if cell["rule_id"].startswith("test."):
            assert cell["state"] in {"no_match_complete", "not_applicable_no_events"}
            assert "unsupported_records" not in str(cell["detail"])


@pytest.mark.parametrize("payload,partial,expected", [
    (None, {}, "no text payload in sample"),
    (None, {"timed_out": True}, "sample incomplete"),
    ("unrecognized but present text", {}, None),
])
def test_only_text_payload_samples_mark_actual_dataset_retrieved(payload, partial, expected):
    from romulus.sources.profile import build_profile

    response = _sample([payload], "nginx.access", **partial)
    profile, contract = build_profile(ProfileClient({"nginx.access": 1}, [response]), "logs")
    runner = object.__new__(sw.Sweep)
    runner.stats = {"dataset_filter": {"logs": []}}
    runner._profiles = {"logs": profile.model_dump()}
    runner._note_linux_shapes("logs", ["linux.text"], [], contract)
    rows = _not_assessed({"source_profiles": runner._profiles}, {"stats": runner.stats})
    if expected is None:
        assert "nginx.access" in runner.stats["dataset_filter"]["logs"]
        assert not rows
    else:
        assert "nginx.access" not in runner.stats["dataset_filter"]["logs"]
        [row] = [row for row in rows if row["dataset"] == "nginx.access"]
        assert row["records"] == 1
        assert row["reason"] == "not retrieved: " + expected
