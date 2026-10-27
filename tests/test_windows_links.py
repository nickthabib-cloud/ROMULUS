"""Typed Windows cross-family links and bounded expansion coverage."""
import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from romulus.agent.models import PivotCoverage, PivotTimeRange
from romulus.agent.toolbox import FollowLinkArgs
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.expansion import MAX_ANCHOR_KEYS, ExpansionEngine
from romulus.hunt.expansion_plan import WINDOWS_TIER_ADDITIONS
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotEventBatch
from romulus.sources.compile import build_query
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types

START = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
END = START + timedelta(hours=1)


def event(event_id: str, family: str, *, host: str = "ws01", ts: datetime = START, **fields) -> TypedEvent:
    values = {
        "host.os.family": fv("windows", f"{event_id}:host.os.family"),
        **{
            name.replace("__", "."): fv(value, f"{event_id}:{name}")
            for name, value in fields.items()
        },
    }
    return TypedEvent(
        id=event_id,
        family=family,
        ts=ts,
        host=host,
        fields=values,
        raw=[RawRef(target="windows", native_id=event_id, digest="d")],
        normalizer="windows-ecs@3",
    )


def anchor(root: TypedEvent) -> LinkAnchor:
    return LinkAnchor(
        finding_id=f"finding-{root.id}", ts=root.ts, host=root.host,
        event_ids=[root.id], events=[root],
    )


def window() -> LinkWindow:
    return LinkWindow(label="case", start=START, end=END)


def windows_contract(*, hosts=("client01.example.test", "ws01")):
    return contract_from_types(
        "windows",
        {
            "@timestamp": "date",
            "winlog.channel": "keyword",
            "winlog.computer_name": "keyword",
            "winlog.event_id": "keyword",
            "winlog.event_data.ProcessGuid": "keyword",
            "winlog.event_data.SourceProcessGuid": "keyword",
            "winlog.event_data.TargetProcessGuid": "keyword",
            "winlog.event_data.LogonGuid": "keyword",
            "winlog.event_data.LogonId": "keyword",
            "winlog.event_data.SubjectLogonId": "keyword",
            "winlog.event_data.TargetLogonId": "keyword",
            "winlog.event_data.TargetUserSid": "keyword",
            "winlog.event_data.SourceIp": "ip",
            "winlog.event_data.IpAddress": "ip",
            "winlog.event_data.WorkstationName": "keyword",
            "winlog.event_data.ClientName": "keyword",
            "winlog.event_data.Image": "keyword",
            "winlog.event_data.NewProcessName": "keyword",
            "winlog.event_data.ParentImage": "keyword",
            "winlog.event_data.ImagePath": "keyword",
            "winlog.event_data.ServiceFileName": "keyword",
        },
        role="host", os_family="windows", hosts=hosts,
    )


class FakePivot:
    raw_family_prefilter = False

    def __init__(self, events, *, status="complete", hosts=("client01.example.test", "ws01")):
        self.events = list(events)
        self.status = status
        self.contracts = {"windows": windows_contract(hosts=hosts)}
        self.calls = []
        self.persisted = []
        self.source_queries = 0

    def system_log_attested(self, _host):
        return True

    def fetch_intents(
        self, owner, fetch_key, intents, retain, *, anchor_ts=None, query_cap=None,
        planning_coverage=None, persist=True, **_options,
    ):
        self.calls.append((owner, fetch_key, intents, anchor_ts, query_cap))
        self.source_queries += len(intents)
        selected = [item for item in self.events if retain(item)]
        reasons = [] if self.status == "complete" else ["cap:2<total:3"]
        unresolved = [] if self.status == "complete" else [PivotTimeRange(
            start=START.isoformat(), end=END.isoformat(), reason=reasons[0],
        )]
        coverage = [PivotCoverage(
            target="windows", dataset="windows", start=START, end=END,
            status=self.status, reasons=reasons, returned=len(selected),
            total=len(selected) if self.status == "complete" else len(selected) + 1,
            unresolved_ranges=unresolved,
        )]
        return PivotEventBatch(
            status=self.status, task_ids=["task-1"], events=selected, raw_sources={},
            coverage=[*(planning_coverage or []), *coverage], reasons=reasons, duration_ms=1,
        )

    def save_batch_selection(self, _batch, events):
        self.persisted.extend(item.id for item in events)


def test_process_activity_matches_actor_guid_across_families_but_never_parent_guid():
    root = event("root", "process_exec", process__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    socket = event("socket", "net_socket", process__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    source_access = event(
        "access", "process_access", source__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    target_thread = event(
        "thread", "remote_thread", target__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    parent_only = event(
        "parent", "process_exec", process__guid="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
        process__parent__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    plan = LinkFetcher(FakePivot([]), START, END)._process_activity(anchor(root), window())

    selected = plan[4]([socket, source_access, target_thread, parent_only])

    assert plan[1] == "observed"
    assert {item.id for item in selected} == {"socket", "access", "thread"}


def test_process_activity_preserves_query_cap_and_capped_coverage():
    root = event("root", "process_exec", process__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    socket = event("socket", "net_socket", process__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    pivot = FakePivot([root, socket], status="partial")

    result = LinkFetcher(pivot, START, END).fetch(
        anchor(root), "process_activity", window(), query_cap=3,
    )

    assert result.status == "partial"
    assert result.event_ids == ["socket"]
    assert result.strength == "observed"
    assert result.reasons == ["cap:2<total:3"]
    assert result.coverage[0].unresolved_ranges
    assert pivot.calls[0][-1] == 3


def test_host_bound_windows_link_pushes_the_inventory_full_name_for_a_short_host_key():
    root = event("root", "process_exec", process__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    pivot = FakePivot([], hosts=("ws01.branch.example",))

    [intent] = LinkFetcher(pivot, START, END)._process_activity(anchor(root), window())[2]

    assert intent.filters[0].field == "host.name"
    assert intent.filters[0].value == "ws01.branch.example"


def test_empty_dataset_inventory_uses_the_windows_contract_os():
    root = event("root", "process_exec", process__guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    pivot = FakePivot([])
    pivot.dataset_inventory = {"windows": set()}

    intents = LinkFetcher(pivot, START, END)._process_activity(anchor(root), window())[2]

    assert len(intents) == 1
    assert intents[0].target == "windows"


def test_process_session_requires_same_host_boot_and_4624_logon_id():
    root = event(
        "root", "process_exec", process__session_id="0x44", host__boot__id="boot-a",
    )
    matching = event(
        "matching", "auth", event__code=4624, auth__session_id="0x44", host__boot__id="boot-a",
    )
    wrong_boot = event(
        "wrong-boot", "auth", event__code=4624, auth__session_id="0x44", host__boot__id="boot-b",
    )
    wrong_code = event(
        "wrong-code", "auth", event__code=4625, auth__session_id="0x44", host__boot__id="boot-a",
    )
    other_host = event(
        "other-host", "auth", host="ws02", event__code=4624,
        auth__session_id="0x44", host__boot__id="boot-a",
    )
    plan = LinkFetcher(FakePivot([]), START, END)._process_session(anchor(root), window())

    selected = plan[4]([matching, wrong_boot, wrong_code, other_host])

    assert plan[1] == "observed"
    assert [item.id for item in selected.events] == ["matching"]
    assert selected.unresolved == []


def test_process_session_rejects_a_candidate_without_the_anchors_boot_id():
    root = event(
        "root", "process_exec", process__session_id="0x44", host__boot__id="boot-a",
    )
    missing_boot = event(
        "missing-boot", "auth", event__code=4624, auth__session_id="0x44",
    )

    selected = LinkFetcher(FakePivot([]), START, END)._process_session(anchor(root), window())[4]([
        missing_boot,
    ])

    assert selected.events == []


def test_process_session_uses_4688_subject_session_while_preserving_target_session():
    root = event(
        "root", "process_exec",
        process__session_id="0x45",
        windows__event_data__SubjectLogonId="0x44",
        windows__event_data__TargetLogonId="0x45",
    )
    subject_logon = event(
        "subject", "auth", event__code=4624, auth__session_id="0x44",
    )
    target_logon = event(
        "target", "auth", event__code=4624, auth__session_id="0x45",
    )

    plan = LinkFetcher(FakePivot([]), START, END)._process_session(anchor(root), window())
    selected = plan[4]([subject_logon, target_logon])

    assert plan[0]["process.session_id"] == "0x44"
    assert plan[0]["process.subject_session_id"] == "0x44"
    assert plan[0]["process.target_session_id"] == "0x45"
    assert [item.id for item in selected.events] == ["subject"]
    assert root.get("process.session_id") == "0x45"


def test_process_session_variants_link_distinct_4688_subject_and_target_logons():
    root = event(
        "root", "process_exec",
        event__code=4688,
        process__session_id="0x45",
        windows__event_data__SubjectLogonId="0x44",
        windows__event_data__TargetLogonId="0x45",
        host__boot__id="boot-a",
    )
    subject_logon = event(
        "subject", "auth", event__code=4624, auth__session_id="0x44",
        host__boot__id="boot-a",
    )
    target_logon = event(
        "target", "auth", event__code=4624, auth__session_id="0x45",
        host__boot__id="boot-a",
    )

    variants, dropped = ExpansionEngine._link_anchors(anchor(root), "process_session")
    selected_by_session = {}
    for variant in variants:
        plan = LinkFetcher(FakePivot([]), START, END)._process_session(variant, window())
        selected_by_session[plan[0]["process.session_id"]] = [
            item.id for item in plan[4]([subject_logon, target_logon]).events
        ]

    assert dropped == []
    assert selected_by_session == {"0x44": ["subject"], "0x45": ["target"]}


def test_process_session_anchor_scopes_are_distinct_and_bounded_when_planned():
    from tests.test_expansion_engine import repo_with_aggregate_anchor

    events = [
        event(
            f"process-{ordinal}", "process_exec", event__code=4688,
            windows__event_data__SubjectLogonId=f"0x{ordinal + 0x100:x}",
            windows__event_data__TargetLogonId=f"0x{ordinal + 0x200:x}",
        )
        for ordinal in range(MAX_ANCHOR_KEYS + 1)
    ]

    repo = repo_with_aggregate_anchor(events, candidate_id="F-many-sessions")
    hunt_window = Window(start=START, end=END)
    engine = ExpansionEngine(
        repo, "h1", hunt_window, LinkFetcher(FakePivot([]), hunt_window.start, hunt_window.end),
    )
    engine._seed_anchors()
    plan = engine._anchor_plan(repo.expansion_anchors("h1")[0])
    anchor_reasons = defaultdict(list)

    slots = engine._planned_slots(
        plan, "process_session", "anchor ±5 min", anchor_reasons, root_cap=1_000,
    )

    assert len(plan.links["process_session"].variants) == 1
    assert len(slots) == MAX_ANCHOR_KEYS
    assert len({slot.anchor.link_key["process.session_id"] for slot in slots}) == MAX_ANCHOR_KEYS
    assert any(reason.startswith("keys_not_expanded:") for reason in anchor_reasons[plan.row["id"]])


def test_event_keyed_variants_use_the_keyed_events_host_and_time():
    first = event(
        "first", "process_exec", host="ws01", ts=START + timedelta(minutes=5),
        process__guid="aaaaaaaa-bbbb-cccc-dddd-000000000001",
    )
    second = event(
        "second", "process_exec", host="ws02", ts=START + timedelta(minutes=45),
        process__guid="aaaaaaaa-bbbb-cccc-dddd-000000000002",
    )
    variants, dropped = ExpansionEngine._link_anchors(
        LinkAnchor(
            finding_id="F-multi-host", ts=START, host="wrong-host",
            event_ids=[first.id, second.id], events=[first, second],
        ),
        "process_activity",
    )

    assert dropped == []
    assert len(variants) == 2
    assert {(variant.host, variant.ts) for variant in variants} == {
        ("ws01", first.ts),
        ("ws02", second.ts),
    }


def test_event_keyed_variants_keep_the_same_key_on_distinct_hosts_and_windows():
    same_host_and_time = event(
        "duplicate", "process_exec", host="ws01", ts=START + timedelta(minutes=5),
        process__session_id="0x44",
    )
    events = [
        event(
            "first", "process_exec", host="ws01", ts=START + timedelta(minutes=5),
            process__session_id="0x44",
        ),
        same_host_and_time,
        event(
            "other-host", "process_exec", host="ws02", ts=START + timedelta(minutes=5),
            process__session_id="0x44",
        ),
        event(
            "later", "process_exec", host="ws01", ts=START + timedelta(minutes=45),
            process__session_id="0x44",
        ),
    ]

    variants, dropped = ExpansionEngine._link_anchors(
        LinkAnchor(
            finding_id="F-reused-session", ts=START, host="wrong-host",
            event_ids=[item.id for item in events], events=events,
        ),
        "process_session",
    )

    assert dropped == []
    assert len(variants) == 3
    assert {(variant.host, variant.ts) for variant in variants} == {
        ("ws01", START + timedelta(minutes=5)),
        ("ws02", START + timedelta(minutes=5)),
        ("ws01", START + timedelta(minutes=45)),
    }


def test_fetch_identity_includes_the_event_anchor_host():
    guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    first = event("first", "auth", host="dc01", event__code=4769, auth__logon_guid=guid)
    second = event("second", "auth", host="dc02", event__code=4769, auth__logon_guid=guid)
    fetcher = LinkFetcher(FakePivot([]), START, END)

    first_id = fetcher.result_id(
        LinkAnchor(
            finding_id="F-shared", ts=START, host="dc01", event_ids=[first.id], events=[first],
            link_key={"event.code": 4769, "auth.logon_guid": guid},
        ),
        "kerberos_logon",
        window(),
    )
    second_id = fetcher.result_id(
        LinkAnchor(
            finding_id="F-shared", ts=START, host="dc02", event_ids=[second.id], events=[second],
            link_key={"event.code": 4769, "auth.logon_guid": guid},
        ),
        "kerberos_logon",
        window(),
    )

    assert first_id != second_id


def test_same_key_and_host_with_the_same_effective_window_plans_one_slot():
    from tests.test_expansion_engine import T0, repo_with_aggregate_anchor

    events = [
        event(
            "first-window", "process_exec", host="ws01", ts=T0 + timedelta(minutes=5),
            process__session_id="0x44",
        ),
        event(
            "second-window", "process_exec", host="ws01", ts=T0 + timedelta(minutes=45),
            process__session_id="0x44",
        ),
    ]
    repo = repo_with_aggregate_anchor(events, candidate_id="F-effective-window")
    hunt_window = Window(start=T0, end=T0 + timedelta(hours=1))
    engine = ExpansionEngine(
        repo, "h1", hunt_window, LinkFetcher(FakePivot([]), hunt_window.start, hunt_window.end),
    )
    engine._seed_anchors()
    plan = engine._anchor_plan(repo.expansion_anchors("h1")[0])

    slots = engine._planned_slots(
        plan, "process_session", "anchor ±2 h", defaultdict(list), root_cap=1_000,
    )

    assert len(plan.links["process_session"].variants) == 1
    assert len(slots) == 1
    assert slots[0].window == LinkWindow(label="anchor ±2 h", start=hunt_window.start, end=hunt_window.end)


def test_effective_window_dedup_happens_before_the_windows_key_cap():
    from tests.test_expansion_engine import T0, repo_with_aggregate_anchor

    events = [
        event(
            f"same-scope-{ordinal}", "process_exec", host="ws01",
            ts=T0 + timedelta(minutes=ordinal), process__session_id="0x44",
        )
        for ordinal in range(1, MAX_ANCHOR_KEYS + 2)
    ]
    events.append(event(
        "distinct-scope", "process_exec", host="ws02", ts=T0 + timedelta(minutes=45),
        process__session_id="0x44",
    ))
    repo = repo_with_aggregate_anchor(events, candidate_id="F-cap-after-effective-window")
    hunt_window = Window(start=T0, end=T0 + timedelta(hours=1))
    engine = ExpansionEngine(
        repo, "h1", hunt_window, LinkFetcher(FakePivot([]), hunt_window.start, hunt_window.end),
    )
    engine._seed_anchors()
    plan = engine._anchor_plan(repo.expansion_anchors("h1")[0])

    slots = engine._planned_slots(
        plan, "process_session", "anchor ±2 h", defaultdict(list), root_cap=1_000,
    )

    assert len(slots) == 2
    assert {slot.anchor.host for slot in slots} == {"ws01", "ws02"}


def test_service_process_scopes_keep_distinct_forward_window_starts():
    from tests.test_expansion_engine import T0, repo_with_aggregate_anchor

    events = [
        event(
            "first-install", "service", host="ws01", ts=T0 + timedelta(minutes=5),
            event__code=7045, service__image_path=r"C:\Tools\agent.exe",
        ),
        event(
            "later-install", "service", host="ws01", ts=T0 + timedelta(minutes=45),
            event__code=7045, service__image_path=r"C:\Tools\agent.exe",
        ),
    ]
    repo = repo_with_aggregate_anchor(events, candidate_id="F-service-forward-windows")
    hunt_window = Window(start=T0, end=T0 + timedelta(hours=1))
    engine = ExpansionEngine(
        repo, "h1", hunt_window, LinkFetcher(FakePivot([]), hunt_window.start, hunt_window.end),
    )
    engine._seed_anchors()
    plan = engine._anchor_plan(repo.expansion_anchors("h1")[0])

    slots = engine._planned_slots(
        plan, "service_process", "anchor ±2 h", defaultdict(list), root_cap=1_000,
    )

    assert len(slots) == 2
    assert {slot.window.start for slot in slots} == {event.ts for event in events}


def test_windows_scope_planning_stays_bounded_for_many_duplicate_events():
    from tests.test_expansion_engine import T0, repo_with_aggregate_anchor

    events = [
        event(
            f"duplicate-{ordinal}", "process_exec", host="ws01",
            ts=T0 + timedelta(minutes=ordinal % 50), process__session_id="0x01",
        )
        for ordinal in range(2_000)
    ]
    events.extend(
        event(
            f"other-{ordinal}", "process_exec", host=f"ws{ordinal + 10:02d}",
            ts=T0 + timedelta(minutes=ordinal), process__session_id=f"0x{ordinal + 0x10:x}",
        )
        for ordinal in range(MAX_ANCHOR_KEYS + 2)
    )
    events.append(event(
        "distinct-duplicate-key", "process_exec", host="aa-distinct", ts=T0 + timedelta(minutes=45),
        process__session_id="0x01",
    ))
    repo = repo_with_aggregate_anchor(events, candidate_id="F-bounded-windows-scopes")
    hunt_window = Window(start=T0, end=T0 + timedelta(hours=1))
    engine = ExpansionEngine(
        repo, "h1", hunt_window, LinkFetcher(FakePivot([]), hunt_window.start, hunt_window.end),
    )
    engine._seed_anchors()
    plan = engine._anchor_plan(repo.expansion_anchors("h1")[0])
    anchor_reasons = defaultdict(list)

    slots = engine._planned_slots(
        plan, "process_session", "anchor ±2 h", anchor_reasons, root_cap=1_000,
    )

    assert len(plan.links["process_session"].variants) == 1
    assert len(slots) == MAX_ANCHOR_KEYS
    assert "aa-distinct" not in {slot.anchor.host for slot in slots}
    assert max(slot.anchor.ts for slot in slots) <= T0 + timedelta(minutes=6)
    [reason] = [
        item for item in anchor_reasons[plan.row["id"]] if item.startswith("keys_not_expanded:")
    ]
    detail = json.loads(reason.removeprefix("keys_not_expanded:"))
    assert detail["dropped_at_least"] == 4
    assert len(detail["examples"]) == 3
    assert detail["more"] is True
    assert all(set(example) == {"host", "key", "window"} for example in detail["examples"])
    assert len(reason) < 2_048


@pytest.mark.parametrize(
    "process_session,auth_session",
    [("0x00000044", "0x44"), ("68", "0x00000044")],
)
def test_process_session_compares_logon_ids_numerically_across_native_formats(
    process_session, auth_session,
):
    root = event(
        "root", "process_exec", process__session_id=process_session,
        host__boot__id="boot-a",
    )
    logon = event(
        "logon", "auth", event__code=4624, auth__session_id=auth_session,
        host__boot__id="boot-a",
    )

    plan = LinkFetcher(FakePivot([]), START, END)._process_session(anchor(root), window())
    selected = plan[4]([logon])

    assert plan[0]["process.session_id"] == "0x44"
    assert [item.id for item in selected.events] == ["logon"]
    assert plan[2]
    assert all(predicate.field != "auth.session_id"
               for intent in plan[2] for group in intent.any_of for predicate in group)


@pytest.mark.parametrize("session_id", ["0x3e4", "0x3e5", "0x3e7", "0x0", "0"])
def test_process_session_refuses_well_known_or_zero_logon_ids(session_id):
    root = event("root", "process_exec", process__session_id=session_id)

    plan = LinkFetcher(FakePivot([]), START, END)._process_session(anchor(root), window())

    assert plan[2] == []
    assert plan[5] == "required process logon session key is unusable"


def test_kerberos_logon_matches_4769_to_cross_host_4624_by_nonzero_logon_guid():
    root = event(
        "ticket", "auth", host="dc01", event__code=4769,
        auth__logon_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    member = event(
        "logon", "auth", host="ws01", event__code=4624,
        auth__logon_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    same_host = event(
        "same-host", "auth", host="dc01", event__code=4624,
        auth__logon_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    wrong_kind = event(
        "wrong-kind", "auth", host="ws01", event__code=4768,
        auth__logon_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    plan = LinkFetcher(FakePivot([]), START, END)._kerberos_logon(anchor(root), window())

    selected = plan[4]([member, same_host, wrong_kind])

    assert plan[1] == "observed"
    assert [item.id for item in selected] == ["logon", "same-host"]


def test_kerberos_logon_refuses_the_zero_guid():
    root = event(
        "ticket", "auth", host="dc01", event__code=4769,
        auth__logon_guid="00000000-0000-0000-0000-000000000000",
    )

    plan = LinkFetcher(FakePivot([]), START, END)._kerberos_logon(anchor(root), window())

    assert plan[2] == []
    assert plan[5] == "required nonzero logon GUID is unusable"


def test_remote_logon_source_uses_observed_sysmon_source_address_and_states_caveats():
    root = event(
        "logon", "auth", event__code=4624, auth__logon_type=10, source__ip="10.0.0.8",
    )
    proof = event("proof", "net_socket", host="client01", source__ip="10.0.0.8", network__direction="egress")
    result = LinkFetcher(FakePivot([proof]), START, END).fetch(
        anchor(root), "remote_logon_source", window(),
    )

    assert result.status == "complete"
    assert result.strength == "inferred"
    assert result.event_ids == ["proof"]
    assert any(all(word in reason for word in ("NAT", "VPN", "proxy", "DHCP"))
               for reason in result.reasons)


def test_remote_logon_source_marks_an_address_held_by_multiple_hosts_unresolved():
    root = event(
        "logon", "auth", event__code=4624, auth__logon_type=3, source__ip="10.0.0.8",
    )
    first = event("first", "net_socket", host="client01", source__ip="10.0.0.8", network__direction="egress")
    second = event("second", "net_socket", host="client02", source__ip="10.0.0.8", network__direction="egress")
    result = LinkFetcher(
        FakePivot([first, second], hosts=("client01", "client02", "ws01")), START, END,
    ).fetch(anchor(root), "remote_logon_source", window())

    assert result.status == "partial"
    assert result.event_ids == []
    assert any("multiple hosts" in reason for reason in result.reasons)


def test_remote_logon_source_uses_full_host_names_to_detect_short_label_collisions():
    root = event(
        "logon", "auth", event__code=4624, auth__logon_type=3, source__ip="10.0.0.8",
    )
    first = event(
        "first", "net_socket", host="client01", source__ip="10.0.0.8",
        host__full_name="client01.branch-a.example",
        network__direction="egress",
    )
    second = event(
        "second", "net_socket", host="client01", source__ip="10.0.0.8",
        host__full_name="client01.branch-b.example",
        network__direction="egress",
    )

    result = LinkFetcher(FakePivot([first, second]), START, END).fetch(
        anchor(root), "remote_logon_source", window(),
    )

    assert result.status == "partial"
    assert result.event_ids == []
    assert any("multiple hosts" in reason for reason in result.reasons)


def test_remote_logon_workstation_maps_by_canonical_first_label_and_is_labelled_weaker():
    root = event(
        "rdp", "remote_access", event__code=4778, source__hostname="CLIENT01.branch.example",
    )
    source_host = event("source-host", "process_exec", host="client01.example.test")
    result = LinkFetcher(FakePivot([source_host]), START, END).fetch(
        anchor(root), "remote_logon_source", window(),
    )

    assert result.status == "complete"
    assert result.event_ids == ["source-host"]
    assert result.key["identity_strength"] == "workstation_first_label"
    assert any("weaker" in reason for reason in result.reasons)


def test_remote_logon_workstation_refuses_two_full_hosts_with_the_same_first_label():
    root = event(
        "rdp", "remote_access", event__code=4778, source__hostname="CLIENT01",
    )
    result = LinkFetcher(
        FakePivot([], hosts=("client01.branch-a.example", "client01.branch-b.example")),
        START, END,
    ).fetch(anchor(root), "remote_logon_source", window())

    assert result.status == "unsupported"
    assert "not uniquely present" in result.reasons[0]


def test_remote_logon_workstation_inventory_cap_is_partial_not_unsupported():
    root = event(
        "rdp", "remote_access", event__code=4778, source__hostname="CLIENT01",
    )
    pivot = FakePivot([], hosts=())
    pivot.contracts["windows"] = pivot.contracts["windows"].model_copy(
        update={"host_inventory_complete": False},
    )

    result = LinkFetcher(pivot, START, END).fetch(
        anchor(root), "remote_logon_source", window(),
    )

    assert result.status == "partial"
    assert result.coverage[0].status == "partial"
    assert result.coverage[0].unresolved_ranges
    assert result.reasons == ["workstation host inventory is incomplete"]


@pytest.mark.parametrize("event_code,logon_type", [(4624, 2), (4625, 3), (9999, None)])
def test_remote_logon_source_refuses_ineligible_anchor_events(event_code, logon_type):
    fields = {"event__code": event_code, "source__ip": "10.0.0.8"}
    if logon_type is not None:
        fields["auth__logon_type"] = logon_type
    root = event("not-remote", "auth", **fields)

    plan = LinkFetcher(FakePivot([]), START, END)._remote_logon_source(anchor(root), window())

    assert plan[2] == []
    assert plan[5] == "anchor is not an eligible remote logon or share event"


def test_service_process_matches_safely_parsed_binary_under_services_parent():
    root = event(
        "install", "service_change", event__code=7045,
        service__image_path='"C:\\Program Files\\Acme\\svc.exe" --service',
    )
    process = event(
        "process", "process_exec", ts=START + timedelta(minutes=1),
        process__executable_key="c:\\program files\\acme\\svc.exe",
        process__parent__executable_key="c:\\windows\\system32\\services.exe",
    )
    wrong_parent = event(
        "wrong-parent", "process_exec", ts=START + timedelta(minutes=1),
        process__executable_key="c:\\program files\\acme\\svc.exe",
        process__parent__executable_key="c:\\windows\\system32\\cmd.exe",
    )
    plan = LinkFetcher(FakePivot([]), START, END)._service_process(anchor(root), window())

    selected = plan[4]([process, wrong_parent])

    assert plan[1] == "inferred"
    assert [item.id for item in selected] == ["process"]


@pytest.mark.parametrize("prefix", ["\\\\?\\", "\\??\\"])
def test_service_process_canonicalizes_extended_path_prefixes_on_both_sides(prefix):
    root = event(
        "install", "service_change", event__code=7045,
        service__image_path='"C:\\Program Files\\Acme\\svc.exe" --service',
    )
    process = event(
        "process", "process_exec", ts=START + timedelta(minutes=1),
        process__executable_key=prefix + r"C:\Program Files\Acme\svc.exe",
        process__parent__executable_key=prefix + r"C:\Windows\System32\services.exe",
    )

    selected = LinkFetcher(FakePivot([]), START, END)._service_process(
        anchor(root), window(),
    )[4]([process])

    assert [item.id for item in selected] == ["process"]


@pytest.mark.parametrize(
    "extended_path",
    [r"\\?\UNC\server\share\AcmeSvc.exe", r"\??\UNC\server\share\AcmeSvc.exe"],
)
def test_service_process_canonicalizes_extended_unc_to_ordinary_unc(extended_path):
    root = event(
        "install", "service_change", event__code=7045,
        service__image_path=f'"{extended_path}" --service',
    )
    process = event(
        "process", "process_exec", ts=START + timedelta(minutes=1),
        process__executable_key=r"\\server\share\AcmeSvc.exe",
        process__parent__executable_key=r"C:\Windows\System32\services.exe",
    )

    selected = LinkFetcher(FakePivot([]), START, END)._service_process(
        anchor(root), window(),
    )[4]([process])

    assert [item.id for item in selected] == ["process"]


def test_service_process_does_not_push_a_case_sensitive_native_path_equality():
    root = event(
        "install", "service_change", event__code=7045,
        service__image_path=r"C:\Tools\AcmeSvc.exe --service",
    )

    [intent] = LinkFetcher(
        FakePivot([], hosts=("ws01.branch.example",)), START, END,
    )._service_process(anchor(root), window())[2]

    assert intent.filters[0].field == "host.name"
    assert intent.filters[0].value == "ws01.branch.example"
    assert all(predicate.field != "process.executable" for group in intent.any_of for predicate in group)


def test_service_process_fetches_only_forward_from_the_install_before_applying_the_cap():
    root = event(
        "install", "service_change", ts=START + timedelta(minutes=20), event__code=7045,
        service__image_path=r"C:\Tools\AcmeSvc.exe --service",
    )
    pivot = FakePivot([])
    requested = LinkWindow(label="case", start=START, end=END)

    result = LinkFetcher(pivot, START, END).fetch(anchor(root), "service_process", requested)

    assert result.window.start == root.ts
    assert pivot.calls[0][2][0].window.start == root.ts


@pytest.mark.parametrize(
    "image_path,reason",
    [
        (r"C:\Windows\System32\svchost.exe -k netsvcs", "svchost service groups are not attributed to one service"),
        (r"C:\Program Files\Acme\svc.exe --service", "unquoted service image path with spaces is ambiguous"),
    ],
)
def test_service_process_refuses_svchost_groups_and_ambiguous_unquoted_paths(image_path, reason):
    root = event(
        "install", "service_change", event__code=4697, service__image_path=image_path,
    )

    plan = LinkFetcher(FakePivot([]), START, END)._service_process(anchor(root), window())

    assert plan[2] == []
    assert plan[5] == reason


def test_native_windows_aliases_make_new_link_keys_pushable():
    contract = windows_contract()

    for typed in (
        "source.guid", "target.guid", "process.session_id", "auth.session_id",
        "auth.logon_guid", "source.hostname", "service.image_path",
        "process.parent.executable", "event.code",
    ):
        assert contract.supports(typed, "eq"), typed


@pytest.mark.parametrize(
    "link_type",
    [
        "process_activity", "process_session", "kerberos_logon",
        "remote_logon_source", "service_process",
    ],
)
def test_agent_follow_link_validation_exposes_windows_link_types(link_type):
    args = FollowLinkArgs.model_validate({"anchor": "F1", "link_type": link_type})
    assert args.link_type == link_type


def test_agent_follow_link_still_rejects_unknown_link_type():
    with pytest.raises(ValidationError):
        FollowLinkArgs.model_validate({"anchor": "F1", "link_type": "windows_guess"})


def test_mixed_target_routes_host_links_by_the_anchor_dataset_os():
    contract = contract_from_types(
        "mixed",
        {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
            "winlog.channel": "keyword", "winlog.event_id": "keyword",
        },
        role="host", os_family="windows",
    )
    pivot = FakePivot([])
    pivot.contracts = {"mixed": contract}
    pivot.dataset_inventory = {"mixed": {"linux.audit", "windows.security"}}
    fetcher = LinkFetcher(pivot, START, END)

    linux = fetcher._host_intents(window(), {"process_exec"}, "linux01", "linux")
    windows = fetcher._host_intents(window(), {"process_exec"}, "ws01", "windows")

    assert len(linux) == 1
    assert [(predicate.field, predicate.value) for predicate in linux[0].filters] == [
        ("event.dataset", "linux.audit"), ("host.name", "linux01"),
    ]
    assert len(windows) == 1
    assert all(
        any(predicate.field in {"event.dataset", "event.channel"} for predicate in group)
        for group in windows[0].any_of
    )
    linux_query = build_query(linux[0], contract)
    assert "host.name" in str(linux_query)
    assert "winlog.computer_name" not in str(linux_query)


def test_account_link_routes_a_windows_anchor_only_to_windows_inventory():
    pivot = FakePivot([])
    pivot.contracts["linux"] = contract_from_types(
        "linux",
        {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
            "user.name": "keyword",
        },
        role="host", os_family="linux",
    )
    pivot.dataset_inventory = {
        "windows": {"windows.security"},
        "linux": {"linux.audit"},
    }
    root = event(
        "root", "auth", auth__target_account="sid:s-1-5-21-1-2-3-1100",
    )

    intents = LinkFetcher(pivot, START, END)._account(anchor(root), window())[2]

    assert intents
    assert {intent.target for intent in intents} == {"windows"}
    assert all(intent.any_of for intent in intents)


def test_windows_links_are_scheduled_in_bounded_expansion_tiers():
    from tests.test_expansion_engine import repo_with_aggregate_anchor

    scheduled = {link_type for _tier, link_types, _window in WINDOWS_TIER_ADDITIONS for link_type in link_types}
    assert {
        "process_activity", "process_session", "kerberos_logon",
        "remote_logon_source", "service_process",
    } <= scheduled

    events = [
        event(
            f"process-{ordinal}", "process_exec",
            process__guid=f"00000000-0000-0000-0000-{ordinal:012x}",
        )
        for ordinal in range(1, MAX_ANCHOR_KEYS + 3)
    ]
    repo = repo_with_aggregate_anchor(events, candidate_id="F-many")
    hunt_window = Window(start=START, end=END)
    engine = ExpansionEngine(
        repo, "h1", hunt_window, LinkFetcher(FakePivot([]), hunt_window.start, hunt_window.end),
    )
    engine._seed_anchors()
    plan = engine._anchor_plan(repo.expansion_anchors("h1")[0])
    slots = engine._planned_slots(
        plan, "process_activity", "anchor ±5 min", defaultdict(list), root_cap=1_000,
    )

    assert len(plan.links["process_activity"].variants) == 1
    assert len(slots) == MAX_ANCHOR_KEYS
    assert len({slot.anchor.link_key["process.guid"] for slot in slots}) == MAX_ANCHOR_KEYS
