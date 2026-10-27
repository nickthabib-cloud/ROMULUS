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
    assert correction.group_key.endswith(f"|correction|{child.id}")
    assert correction.proposed_lane == "lead"                       # the parent is no longer resolved
    assert "Correction" in correction.claim and "withdrawn" in correction.claim
    assert "terminated" in correction.claim                         # says what changed and why
    assert child.id in {e.id for e in correction.events}


def test_a_late_record_outside_the_childs_window_changes_nothing():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    later_term = security4689(image=WINWORD, pid=0x700, offset=20)  # after the child: the parent was live
    early, final = _drive(LureAppSpawnsCodeRunner(), [[parent, child], [later_term]])
    assert [m.proposed_lane for m in early] == ["high"] and final == []


def test_an_undecided_child_is_resolved_and_published_at_finalize():
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=10)
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    # the child's target is swept before the parent's: undecided when read, decided at finalize
    early, final = _drive(LureAppSpawnsCodeRunner(), [[child], [parent]])
    assert early == []
    assert [m.proposed_lane for m in final] == ["high"]


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
    claims = " ".join(c["claim"] for c in candidates)
    assert "Correction" in claims                                   # the late termination corrected one finding
    assert len(candidates) >= 5
    for candidate in candidates:
        with repo.engine.connect() as connection:
            rows = connection.execute(select(t.typed_event.c.id, t.typed_event.c.raw_ids).where(
                t.typed_event.c.id.in_(candidate["event_ids"]))).all()
        assert len(rows) == len(candidate["event_ids"]), candidate["claim"]
        raw_ids = [raw for row in rows for raw in (row.raw_ids or [])]
        assert raw_ids and len(repo.raw_records(raw_ids)) == len(raw_ids), candidate["claim"]
    sweep.close_stage()
