"""Adversarial Windows retrieval, attribution, and native-shape regressions."""
from datetime import UTC, datetime

import pytest

from romulus.detect.base import Playbook
from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows import EVENT_XML_MAX_BYTES, normalize_windows
from romulus.evidence.windows_catalog import EVENT_CLASSES, SECURITY, SYSMON, SYSMON_CHANNEL
from romulus.hunt import pivot as pivot_module
from romulus.hunt import sweep as sweep_module
from romulus.hunt.links import LinkFetcher
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.sweep import Sweep
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from tests.test_windows_links import END, START, FakePivot, anchor, event, window
from tests.test_windows_normalize_breadth import NOW, _hit
from tests.test_windows_script_pivot import FakeClient, TrackingAssembler, _contract, _intent, _repo
from tests.windows_fixtures import SHAPES, all_logical_events, windows_hit, windows_xml_hit


@pytest.mark.parametrize("event_id", [400, 403, 800])
@pytest.mark.parametrize("shape", [*SHAPES, "xml"])
def test_legacy_powershell_real_parameter_shapes_type_downgrade(event_id, shape):
    logical = next(item for item in all_logical_events()
                   if item.provider == "PowerShell" and item.event_id == event_id)
    hit = windows_xml_hit(logical) if shape == "xml" else windows_hit(logical, shape)
    result = normalize_windows(hit)
    assert result.get("script.engine_version") == "2.0"
    assert result.get("script.host_application") == "powershell.exe -NoProfile -File inventory.ps1"
    assert "#parsed" in result.fields["script.engine_version"].origin
    if shape == "xml":
        assert "#xml" in result.fields["script.engine_version"].origin


@pytest.mark.parametrize("field", ["UtcTime", "TimeCreated"])
def test_bad_native_timestamp_keeps_the_record_with_ingest_time(field):
    hit = _hit(1, {field: "not-a-date", "Image": r"C:\Windows\cmd.exe"},
               channel=SYSMON_CHANNEL, provider=SYSMON)
    result = normalize_windows(hit)
    assert result.ts == datetime.fromisoformat(NOW).astimezone(UTC)
    assert result.get("process.executable") == r"C:\Windows\cmd.exe"
    assert any("@timestamp used" in caveat for caveat in result.caveats)


@pytest.mark.parametrize("structured", [True, False])
def test_original_xml_limit_precedes_parsing_and_keeps_record(monkeypatch, structured):
    from romulus.evidence import windows

    hit = _hit(4624, {"LogonType": "3"} if structured else {})
    hit["_source"]["event"] = {"original": "<" + "x" * EVENT_XML_MAX_BYTES}
    monkeypatch.setattr(windows.ElementTree, "fromstring", lambda _xml: pytest.fail("parsed oversized XML"))
    result = normalize_windows(hit)
    assert result.get("event.code") == 4624
    assert any("event.original exceeds" in caveat for caveat in result.caveats)
    assert result.get("auth.logon_type") == (3 if structured else None)


@pytest.mark.parametrize("code,expected", [
    (2304, "error_during_logon"), (2305, "account_expired"), (2306, "netlogon_not_started"),
    (2307, "account_locked_out"), (2308, "logon_type_not_granted"), (2309, "password_expired"),
    (2310, "account_disabled"), (2311, "logon_time_restriction"), (2312, "workstation_restriction"),
    (2313, "unknown_user_name_or_bad_password"),
])
def test_failure_message_resource_codes(code, expected):
    result = normalize_windows(_hit(4625, {"FailureReason": f"%%{code}"}))
    assert result.get("auth.failure_reason") == expected


def test_registry_deletion_delegation_and_ds_control_access_codes():
    assert normalize_windows(_hit(4657, {"OperationType": "%%1906"})).get(
        "registry.operation_type") == "registry_value_deleted"
    assert normalize_windows(_hit(4624, {"ImpersonationLevel": "%%1840"})).get(
        "auth.impersonation_level") == "delegation"
    result = normalize_windows(_hit(4662, {"AccessList": "%%7688", "AccessMask": "0x100"}))
    assert result.get("directory.access.accesses") == ["control_access"]


@pytest.mark.parametrize("context", [True, False])
def test_explicit_classes_union_family_and_context_reads(monkeypatch, context):
    class Reader(Playbook):
        os_families = ("windows",)
        families = ("process_exec", "process_termination") if context else ()
        context_families = ("system_state",) if context else ()
        windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1), ("Security", SECURITY, 4688))

    contract = contract_from_types(
        "windows", {"@timestamp": "date", "winlog.channel": "keyword",
                    "winlog.provider_name": "keyword", "winlog.event_id": "keyword"},
        role="host", os_family="windows",
    )
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="inventory", started_at=START, ended_at=END,
        completeness=Completeness.complete, buckets=[{
            "key": {"event.channel": row.channel, "event.provider": row.provider, "event.code": row.event_id},
            "count": 1,
        } for row in EVENT_CLASSES],
    ))
    sweep = Sweep(None, object(), "h1", Window(start=START, end=END), {"windows": contract})
    sweep.pack = [Reader()]
    sweep._prepare_windows_inventory("windows", contract)
    groups = sweep._any_of_for("windows", contract)
    fetched = {(group[0].value, group[2].value) for group in groups}
    fences = {(SYSMON_CHANNEL, 5), ("Security", 4689), ("System", 12),
              ("System", 13), ("System", 6005), ("System", 6006)}
    if context:
        assert fences <= fetched
        assert not any(item.get("family") in {"process_termination", "system_state"}
                       for item in sweep.stats["windows_unassessed"]["windows"])
    else:
        assert not (fences - {("System", 6006)}) & fetched
        assert (SYSMON_CHANNEL, 1) in fetched and ("Security", 4688) in fetched


def test_victims_inbound_never_establishes_source_address_ownership():
    inbound = [event(f"in-{host}", "net_socket", host=host, source__ip="10.0.0.8",
                     network__direction="ingress") for host in ("ws01", "ws02", "ws03")]
    egress = event("attacker", "net_socket", host="client01", source__ip="10.0.0.8",
                   network__direction="egress")
    for host in ("ws01", "ws02", "ws03"):
        root = event(f"logon-{host}", "auth", host=host, event__code=4624,
                     auth__logon_type=3, source__ip="10.0.0.8")
        result = LinkFetcher(FakePivot(inbound), START, END).fetch(anchor(root), "remote_logon_source", window())
        assert result.status == "partial" and not result.event_ids
        assert any("no observed egress holder" in reason for reason in result.reasons)
        result = LinkFetcher(FakePivot([*inbound, egress]), START, END).fetch(
            anchor(root), "remote_logon_source", window())
        assert result.status == "complete" and result.event_ids == ["attacker"]


@pytest.mark.parametrize("link,fields,family", [
    ("process_activity", {"process__guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "process_exec"),
    ("process_session", {"process__session_id": "0x44"}, "process_exec"),
    ("service_process", {"event__code": 7045, "service__image_path": r"C:\service.exe"}, "service_change"),
])
def test_host_absent_from_truncated_inventory_is_partial(link, fields, family):
    pivot = FakePivot([], hosts=())
    pivot.contracts["windows"] = pivot.contracts["windows"].model_copy(update={"host_inventory_complete": False})
    result = LinkFetcher(pivot, START, END).fetch(anchor(event("root", family, **fields)), link, window())
    assert result.status == "partial"
    assert any("absent from truncated" in reason for reason in result.reasons)
    assert not pivot.calls


@pytest.mark.parametrize("operation", ["fetch", "run"])
def test_pivot_script_state_is_under_stage_and_closed_after_exception(tmp_path, monkeypatch, operation):
    from romulus.agent.models import EntityRef
    from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest

    TrackingAssembler.instances.clear()
    monkeypatch.setattr(pivot_module, "ScriptBlockAssembler", TrackingAssembler)
    executor = PivotExecutor(_repo(), FakeClient(), "h1", {"windows": _contract("windows")}, stage_dir=tmp_path)
    intent = _intent("windows", START, END)
    monkeypatch.setattr(executor, "_execute_partitions", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("injected retrieval failure")))
    with pytest.raises(RuntimeError, match="injected retrieval failure"):
        if operation == "fetch":
            executor.fetch_intents("finding", "key", [intent], lambda _event: True)
        else:
            monkeypatch.setattr(executor, "plan", lambda _request: ([intent], []))
            executor.run("case", EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
                entity=EntityRef(kind="host", value="ws01", role="host"), start=START, end=END)))
    [assembler] = TrackingAssembler.instances
    assert assembler.path.is_relative_to(tmp_path)
    assert assembler.db is None and not assembler.path.exists()
    assert not hasattr(executor, "_script_blocks")


@pytest.mark.parametrize("complete", [True, False])
def test_sweep_evaluates_every_fragment_and_keeps_all_raws_with_bounded_join_citations(
    tmp_path, monkeypatch, complete,
):
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START as sweep_start
    from tests.test_windows_coverage import WindowsProcessRule, WindowsScriptRule, _contract, _script_hit

    class Recording(WindowsScriptRule):
        assures_negative = False

        def __init__(self):
            super().__init__()
            self.seen = []

        def consume(self, events):
            self.seen.extend(self.applicable(events))
            return []

    total = 130 if complete else 131
    records = [_script_hit(number, 1, block="11111111-2222-3333-4444-555555555555",
                           number=number, total=total,
                           text="MIDDLE-PAYLOAD" if number == 65 else "x" * 20)
               for number in range(1, 131)]
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="script-truncation", started_at=sweep_start, ended_at=sweep_start,
        completeness=Completeness.complete, total=len(records), returned=len(records), records=records,
    ))
    contract, repo = _contract(), _repo()
    sweep = Sweep(repo, None, "h1", Window(start=sweep_start, end=sweep_start.replace(hour=1)),
                  {contract.target: contract}, stage_dir=tmp_path)
    rule = Recording()
    sweep.pack = [rule, WindowsProcessRule()]
    monkeypatch.setattr(sweep, "_windows_rule_reasons", lambda *_args: [])
    sweep._windows_script_blocks().text_cap = 20
    try:
        sweep.run_partition(contract.target, contract, [], sweep.window, est=len(records))
        if not complete:
            sweep._finalize_windows_script_blocks()
        parts = [item for item in rule.seen if item.has("script.part_number")]
        [joined] = [item for item in rule.seen if not item.has("script.part_number")]
        assert len(parts) == 130 and any(item.get("script.text") == "MIDDLE-PAYLOAD" for item in parts)
        assert not joined.get("script.complete") and joined.get("script.truncated")
        assert len(joined.raw) == 130
        stored = repo.events_by_ids(joined.get("script.part_event_ids"))
        assert len(stored) == 130
        raw_ids = {raw for row in stored for raw in row["raw_ids"]}
        assert len(raw_ids) == len(repo.raw_records(raw_ids)) == 130
        cells = repo.rule_cells("h1")
        assert any(cell["rule_id"] == rule.id and any(
            "joined text capped" in reason for reason in cell["detail"].get("reasons", [])
        ) for cell in cells)
        assert all(not any("joined text capped" in reason for reason in cell["detail"].get("reasons", []))
                   for cell in cells if cell["rule_id"] == WindowsProcessRule.id)
    finally:
        sweep.close_stage()


@pytest.mark.parametrize("complete", [True, False])
@pytest.mark.parametrize("operation", ["fetch", "run"])
def test_pivot_truncation_is_partial_and_keeps_fragment_text(tmp_path, monkeypatch, complete, operation):
    from romulus.agent.models import EntityRef
    from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
    from tests.test_windows_script_pivot import _complete_outcome, _part

    class TinyAssembler(TrackingAssembler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, text_cap=20, **kwargs)

    records = [_part("windows", number, 3 if complete else 4,
                     "MIDDLE-PAYLOAD" if number == 2 else "x" * 20) for number in (1, 2, 3)]
    monkeypatch.setattr(pivot_module, "ScriptBlockAssembler", TinyAssembler)
    monkeypatch.setattr(pivot_module, "execute", lambda _client, intent, _contract, *, pit=None:
                        _complete_outcome(intent, records[0]).model_copy(update={
                            "records": records, "returned": 3, "total": 3,
                        }))
    repo = _repo()
    executor = PivotExecutor(repo, FakeClient(), "h1", {"windows": _contract("windows")}, stage_dir=tmp_path)
    intent = _intent("windows", START, END)
    if operation == "fetch":
        result = executor.fetch_intents("finding", "key", [intent], lambda _event: True)
        events = result.events
    else:
        monkeypatch.setattr(executor, "plan", lambda _request: ([intent], []))
        result = executor.run("case", EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
            entity=EntityRef(kind="host", value="ws01", role="host"), start=START, end=END)))
        events = [TypedEvent.model_validate(row["event"]) for row in repo.events_by_ids(result.event_ids)]
    assert result.status == "partial"
    assert any("joined text capped" in reason for reason in result.reasons)
    assert any(item.get("script.text") == "MIDDLE-PAYLOAD" and item.has("script.part_number") for item in events)
    [joined] = [item for item in events if not item.has("script.part_number")]
    assert joined.get("script.complete") is False
