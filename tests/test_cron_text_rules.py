"""Cronie scheduler records stay distinct from kernel-confirmed execution and writes.

Synthetic records follow Cronie's log_it calls (not a captured/private corpus):
https://github.com/cronie-crond/cronie/blob/master/src/crontab.c
https://github.com/cronie-crond/cronie/blob/master/src/do_command.c
"""
import pytest

from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.kernel_files import PersistencePathChange
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, fv


def raw_event(message="(alice) REPLACE (root)", program="crontab", native_id="cron-1"):
    hit = {"_index": "scheduler-logs", "_id": native_id, "_source": {
        "@timestamp": "2026-11-09T12:00:00Z", "host": {"name": "scheduler01"},
        "event": {"dataset": "custom.log"},
        "message": f"Nov  9 12:00:00 origin {program}[42]: {message}",
    }}
    events, skips, errors = normalize_hits([hit])
    assert not skips and not errors and len(events) == 1
    return events[0]


@pytest.fixture
def rule():
    instance = PersistencePathChange()
    yield instance
    instance.close_spill()


@pytest.mark.parametrize("logged,action,limitation", [
    ("REPLACE", "replace", "does not establish the resulting commands"),
    ("BEGIN EDIT", "begin_edit", "does not establish that changes were saved"),
])
def test_raw_crontab_action_is_a_cited_lead_without_fabricated_kernel_facts(rule, logged, action, limitation):
    event = raw_event(f"(alice) {logged} (root)")
    matches = list(rule.consume_partition([event]))
    assert len(matches) == 1
    match = matches[0]
    assert match.proposed_lane == "lead" and match.severity == "medium"
    assert match.claim_type == "observed_action"
    assert "crontab manager logged " + logged in match.claim
    assert "'alice'" in match.claim and "'root'" in match.claim
    assert limitation in match.claim
    assert match.attack == ("T1053.003",)
    assert match.events == [event] and match.group_key
    assert {p.field: p.value for p in match.predicate} == {
        "service.name": "cron", "service.action": action,
        "user.name": "alice", "account.name": "root",
    }
    assert all(p.origin.startswith("cron-1:message") for p in match.predicate)
    assert event.outcome == Outcome.unknown
    assert not event.has("process.uid") and not event.has("file.path")
    assert rule.evaluated == 1 and rule.missing_required == 0
    assert rule.drain_staged() == [] and rule.finalize() == []


@pytest.mark.parametrize("field,value,evaluated", [
    ("service.name", "systemd", 0), ("service.name", "cron-lookalike", 0),
    ("service.action", "list", 1), ("service.action", "delete", 1), ("service.action", "replace_elsewhere", 1),
])
def test_only_exact_cron_edit_actions_are_leads(rule, field, value, evaluated):
    event = raw_event()
    event.fields[field] = fv(value, "fixture:" + field)
    event.fields["user.name"] = fv("BEGIN EDIT REPLACE root", "fixture:user.name")
    assert list(rule.consume_partition([event])) == []
    assert rule.finalize() == []
    assert rule.evaluated == evaluated and rule.missing_required == 0
    assert rule.os_applicable == evaluated


@pytest.mark.parametrize("field", ["service.name", "service.action", "user.name", "account.name"])
def test_missing_cron_fields_are_counted_unresolved(rule, field):
    event = raw_event()
    del event.fields[field]
    assert list(rule.consume_partition([event])) == []
    assert rule.finalize() == []
    assert rule.missing_required == 1 and rule.evaluated == 0
    assert rule.assures_negative is False


@pytest.mark.parametrize("value", ["", " ", None, 0, ["root"]])
def test_unusable_target_account_is_missing_evidence(rule, value):
    event = raw_event()
    event.fields["account.name"] = fv(value, "fixture:account.name")
    assert list(rule.consume_partition([event])) == []
    assert rule.missing_required == 1 and rule.evaluated == 0


def test_username_mention_of_replace_does_not_turn_edit_start_into_replacement(rule):
    event = raw_event("(REPLACE) BEGIN EDIT (root)")
    matches = list(rule.consume_partition([event]))
    assert len(matches) == 1
    assert "crontab manager logged BEGIN EDIT" in matches[0].claim
    assert "does not establish that changes were saved" in matches[0].claim
    assert "crontab replacement" not in matches[0].claim
    assert {p.field: p.value for p in matches[0].predicate}["user.name"] == "REPLACE"


def test_reread_is_not_a_second_lead_but_separate_native_records_are(rule):
    first = raw_event(native_id="cron-1")
    second = raw_event(native_id="cron-2")
    first_matches = list(rule.consume_partition([first]))
    assert len(first_matches) == 1
    assert list(rule.consume_partition([first])) == []
    second_matches = list(rule.consume_partition([second]))
    assert len(second_matches) == 1
    assert first_matches[0].group_key != second_matches[0].group_key
    assert rule.evaluated == 2


def test_cron_command_is_scheduler_observation_not_execution_or_persistence(rule):
    event = raw_event("(root) CMD (echo REPLACE >/etc/cron.d/evil)", program="CRON")
    assert event.family == "process_observed"
    assert event.get("scheduler.service") == "cron"
    assert not any(event.has(name) for name in ("process.uid", "process.pid", "process.argv", "file.path"))
    assert list(rule.consume_partition([event])) == [] and rule.finalize() == []
    write_run = NonRootWriteRootExecutedFile()
    try:
        assert list(write_run.consume_partition([event])) == [] and write_run.finalize() == []
        assert write_run.evaluated == 0
    finally:
        write_run.close_spill()


def test_windows_service_change_stays_outside_linux_rule(rule):
    event = raw_event()
    event.fields["host.os.family"] = fv("windows", "fixture:host.os.family")
    assert list(rule.consume_partition([event])) == []
    assert rule.evaluated == 0 and rule.missing_required == 0


@pytest.mark.parametrize("service", ["systemd", "session-9.scope", "sshd.service"])
@pytest.mark.parametrize("partition", [False, True])
def test_unrelated_service_changes_are_outside_persistence_evaluation(rule, service, partition):
    event = raw_event()
    event.fields = {"service.name": fv(service, "fixture:service.name")}
    consume = rule.consume_partition if partition else rule.consume
    assert list(consume([event])) == [] and rule.finalize() == []
    assert rule.evaluated == 0 and rule.missing_required == 0 and rule.os_applicable == 0


def test_persistence_partition_scope_keeps_cron_and_original_file_process_inputs(rule):
    from tests.test_kernel_files import change, pexec

    cron = raw_event()
    missing_identity = raw_event(native_id="missing-service")
    del missing_identity.fields["service.name"]
    other = raw_event(native_id="other-service")
    other.fields = {"service.name": fv("session-9.scope", "fixture")}
    file_change = change("/etc/cron.d/job")
    process = pexec("/usr/bin/dpkg", 12, 1)
    rows = [file_change, other, process, missing_identity, cron]
    assert rule.scope_partition(rows) == [file_change, process, missing_identity, cron]
