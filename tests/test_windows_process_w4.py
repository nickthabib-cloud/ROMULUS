"""Synthetic native process, module and registry observations; private until part B."""
import importlib
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from romulus.hunt import sweep as sw
from romulus.sources.models import Window
from tests.test_sweep import _complete, _repo
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

START = datetime(2026, 1, 2, tzinfo=UTC)


def native(data, n=1, *, code=1, host="host.example.test", offset=0, provider=SYSMON, channel=SYSMON_CHANNEL):
    record = LogicalWindowsEvent(channel, provider, code, host, n,
                                 (START + timedelta(seconds=offset)).isoformat(), data)
    hit = windows_hit(record, "winlogbeat_8")
    return normalize_windows(hit), hit


def rule_type(name):
    # Intentional feature-missing RED on the frozen part-A product.
    return getattr(importlib.import_module("romulus.detect.windows_process_w4"), name)


def sweep_run(tmp_path, monkeypatch, rule, batches, *, assert_raw=(), citation_source=None):
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START + timedelta(hours=1)), {}, stage_dir=tmp_path)
    if citation_source is not None:
        from romulus.hunt.publish import SourceCitationFetcher
        rule.citation_fetcher = SourceCitationFetcher(citation_source)
    try:
        for batch in batches:
            monkeypatch.setattr(sw, "execute", lambda _client, intent, _contract, batch=batch:
                                _complete(intent, [hit for _event, hit in batch]))
            sweep.run_partition(batch[0][1]["_index"], None, [], Window(start=START, end=START + timedelta(hours=1)), est=len(batch))
        sweep.finalize()
        if assert_raw:
            from romulus.store.repo import raw_id
            for event, hit in assert_raw:
                stored = sweep.repo.raw_records([raw_id(ref.target, ref.native_id) for ref in event.raw])
                assert len(stored) == len(event.raw)
                assert all(row["source"] == hit["_source"] for row in stored)
        return sweep.repo.candidates("h1"), rule
    finally:
        sweep.close_stage()


def process(image, user, guid, **extra):
    return {"Image": image, "User": user, "ProcessGuid": "{00000000-0000-0000-0000-" + f"{guid:012x}" + "}", **extra}


@pytest.mark.parametrize("late", [False, True])
def test_guid_account_transition_cites_both_records(tmp_path, monkeypatch, late):
    parent = native(process(r"C:\Users\alice\Downloads\service.exe", r"NT AUTHORITY\NETWORK SERVICE", 1), offset=0)
    child = native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", 2,
                           ParentProcessGuid=parent[0].get("process.guid")), 2, offset=1)
    rule = rule_type("ParentAccountTransition")()
    # R2: pending children retain compact facts; bounded native source retrieval
    # supplies the original citation body when the parent arrives later.
    class NativeSource:
        def search(self, index, body):
            wanted = body['query']['bool']['filter'][0]['ids']['values']
            return {'hits': {'hits': [hit for _, hit in (parent, child)
                                     if hit['_index'] == index and hit['_id'] in wanted]}}
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule, [[child], [parent]] if late else [[parent], [child]],
                                assert_raw=(parent, child), citation_source=NativeSource())
    assert len(findings) == 1 and findings[0]["lane"] == "high"
    assert {parent[0].id, child[0].id} <= set(findings[0]["event_ids"])
    assert "NETWORK SERVICE" in findings[0]["claim"] and "SYSTEM" in findings[0]["claim"]
    assert "token was stolen" not in findings[0]["claim"]


@pytest.mark.parametrize("kind", ["same_account", "wrong_host", "wrong_guid", "installed_parent", "parent_after", "missing_parent_user"])
def test_account_transition_requires_actual_correlated_evidence(tmp_path, monkeypatch, kind):
    user = r"NT AUTHORITY\SYSTEM" if kind == "same_account" else "" if kind == "missing_parent_user" else r"EXAMPLE\alice"
    image = r"C:\Windows\System32\services.exe" if kind == "installed_parent" else r"C:\Users\alice\parent.exe"
    parent = native(process(image, user, 1), host="other.example.test" if kind == "wrong_host" else "host.example.test", offset=2 if kind == "parent_after" else 0)
    child = native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", 2,
                           ParentProcessGuid="{00000000-0000-0000-0000-000000000009}" if kind == "wrong_guid" else parent[0].get("process.guid")), 2, offset=1)
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ParentAccountTransition")(), [[parent], [child]])
    assert not any(finding["lane"] == "high" for finding in findings)


@pytest.mark.parametrize("parent", ["w3wp.exe", "httpd.exe", "tomcat9.exe", "php-cgi.exe", "sqlservr.exe", "winlogon.exe", "osk.exe", "services.exe"])
def test_parent_binary_set_alone_is_lead(tmp_path, monkeypatch, parent):
    child = native(process(r"C:\Windows\System32\cmd.exe", r"EXAMPLE\alice", 2,
                           ParentImage="C:\\Windows\\System32\\" + parent))
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ServerOrBootProcessChild")(), [[child]])
    assert len(findings) == 1 and findings[0]["lane"] == "lead"


def test_writable_child_supplies_a_separate_raise_reason(tmp_path, monkeypatch):
    child = native(process(r"C:\Users\alice\Downloads\cmd.exe", r"EXAMPLE\alice", 2,
                           ParentImage=r"C:\Program Files\Server\httpd.exe"))
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ServerOrBootProcessChild")(), [[child]])
    assert len(findings) == 1 and findings[0]["lane"] == "high"
    assert "writable" in findings[0]["claim"]


@pytest.mark.parametrize("child", ["smss.exe", "autochk.exe", "csrss.exe", "wininit.exe", "winlogon.exe"])
def test_documented_smss_children_are_hard_negatives(tmp_path, monkeypatch, child):
    event = native(process("C:\\Windows\\System32\\" + child, r"NT AUTHORITY\SYSTEM", 2,
                           ParentImage=r"C:\Windows\System32\smss.exe"))
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ServerOrBootProcessChild")(), [[event]])
    assert findings == []


@pytest.mark.parametrize("data,lane", [
    ({"Image": r"C:\Users\alice\renamed.exe", "OriginalFileName": "REGSVR32.EXE", "CommandLine": "renamed.exe scrobj.dll"}, "high"),
    ({"Image": r"C:\Users\alice\svchost.exe"}, "high"),
    ({"Image": r"D:\Tools\svchost.exe"}, "lead"),
    ({"Image": r"C:\Users\alice\renamed.exe", "Description": "Microsoft(C) Register Server",
      "Product": "Microsoft� Windows� Operating System"}, "high"),
    ({"Image": r"C:\Users\alice\renamed.exe", "OriginalFileName": "CALC.EXE"}, "high"),
])
def test_renamed_and_relocated_native_evidence(tmp_path, monkeypatch, data, lane):
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("RenamedSystemBinary")(), [[native(data)]])
    assert len(findings) == 1 and findings[0]["lane"] == lane


@pytest.mark.parametrize("data", [
    {"Image": r"C:\Windows\System32\cmd.exe", "OriginalFileName": "Cmd.Exe"},
    {"Image": "svchost.exe"}, {"Image": r"C:\Tools\custom.exe", "Product": "Microsoft Windows Operating System"},
    {"Image": r"C:\Tools\custom.exe", "OriginalFileName": "UNKNOWN_FILE"},
    {"Image": r"C:\Tools\custom.exe", "Description": "Microsoft(C) Register Server", "Product": "Unrelated Windows Product"},
    {"Image": r"C:\Windows\SYSTEM~1\cmd.exe"}, {"Image": r"%UnknownRoot%\cmd.exe"},
    {"Image": {}},
])
def test_system_identity_hard_negatives_and_malformed_rows(tmp_path, monkeypatch, data):
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("RenamedSystemBinary")(), [[native(data)]])
    assert findings == []


@pytest.mark.parametrize("path", [r"%SystemRoot%\System32\cmd.exe", r"\\?\C:\Windows\System32\cmd.exe",
                                 r"\??\C:\Windows\System32\cmd.exe", r"D:\Windows\System32\cmd.exe",
                                 r"\Device\HarddiskVolume4\Windows\System32\cmd.exe"])
def test_known_system_directory_shapes_are_not_claimed_as_relocation(tmp_path, monkeypatch, path):
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("RenamedSystemBinary")(), [[native({"Image": path})]])
    assert findings == []


@pytest.mark.parametrize("original,lane", [(None, "lead"), ("CMD.EXE", "high")])
def test_relocation_only_needs_recorded_identity_or_writable_path_to_raise(tmp_path, monkeypatch, original, lane):
    data = {"Image": r"C:\Tools\cmd.exe"}
    if original:
        data["OriginalFileName"] = original
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("RenamedSystemBinary")(), [[native(data)]])
    assert len(findings) == 1 and findings[0]["lane"] == lane
    if not original:
        assert "recorded original identity" not in findings[0]["claim"]


@pytest.mark.parametrize("module", [r"C:\Windows\System32\consent.exe.local\comctl32.dll", r"C:\Users\alice\version.dll"])
def test_unsigned_dll_binding_raises_with_real_module_evidence(tmp_path, monkeypatch, module):
    from romulus.detect.windows_memory_events import WritableUnsignedDllLoad
    event = native({"Image": r"C:\Program Files\Example\loader.exe", "ImageLoaded": module,
                    "Signed": "false", "SignatureStatus": "Unavailable"}, code=7)
    findings, _rule = sweep_run(tmp_path, monkeypatch, WritableUnsignedDllLoad(), [[event]])
    assert len(findings) == 1 and findings[0]["lane"] == "high"


def test_run_key_writable_system_name_is_high(tmp_path, monkeypatch):
    from romulus.detect.windows_registry_events import RegistryRunKeys
    event = native({"Image": r"C:\Windows\regedit.exe", "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Example",
                    "Details": r"%AppData%\svchost.exe", "EventType": "SetValue"}, code=13)
    findings, _rule = sweep_run(tmp_path, monkeypatch, RegistryRunKeys(), [[event]])
    assert len(findings) == 1 and findings[0]["lane"] == "high"


@pytest.mark.parametrize("late_conflict", [False, True])
def test_conflicting_parent_guid_revises_high_to_unresolved_lead(tmp_path, monkeypatch, late_conflict):
    parent = native(process(r"C:\Users\alice\parent.exe", r"EXAMPLE\alice", 1))
    conflict = native(process(r"C:\Windows\System32\services.exe", r"NT AUTHORITY\SYSTEM", 1), 3)
    child = native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", 2,
                           ParentProcessGuid=parent[0].get("process.guid")), 2, offset=1)
    batches = [[parent], [child], [conflict]] if late_conflict else [[parent], [conflict], [child]]
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ParentAccountTransition")(), batches)
    assert len(findings) == 1 and findings[0]["lane"] == "lead"
    assert "conflicting" in findings[0]["claim"]


@pytest.mark.parametrize("parent_image,child_user", [
    (r"D:\Windows\System32\services.exe", r"NT AUTHORITY\SYSTEM"),
    (r"D:\Program Files\Example\parent.exe", r"NT AUTHORITY\SYSTEM"),
    (r"C:\Users\alice\parent.exe", "SYSTEM"),
])
def test_account_scope_does_not_infer_remote_roots_or_bare_system_identity(tmp_path, monkeypatch, parent_image, child_user):
    parent = native(process(parent_image, r"EXAMPLE\alice", 1))
    child = native(process(r"C:\Windows\System32\cmd.exe", child_user, 2,
                           ParentProcessGuid=parent[0].get("process.guid")), 2, offset=1)
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ParentAccountTransition")(), [[parent], [child]])
    assert not any(finding["lane"] == "high" for finding in findings)


@pytest.mark.parametrize("module,signed,status", [
    (r"C:\Users\alice\version.dll", "true", "Valid"),
    (r"C:\Windows\System32\consent.exe.local-backup\custom.dll", "false", "Unavailable"),
    ("version.dll", "false", "Unavailable"),
    (r"C:\Users\alice\version.dll", None, None),
])
def test_dll_raise_needs_exact_path_and_explicit_signature_evidence(tmp_path, monkeypatch, module, signed, status):
    from romulus.detect.windows_memory_events import WritableUnsignedDllLoad
    data = {"Image": r"C:\Program Files\Example\loader.exe", "ImageLoaded": module}
    if signed is not None:
        data.update(Signed=signed, SignatureStatus=status)
    findings, _rule = sweep_run(tmp_path, monkeypatch, WritableUnsignedDllLoad(), [[native(data, code=7)]])
    assert not any(finding["lane"] == "high" for finding in findings)


@pytest.mark.parametrize("value", [
    r'"C:\Program Files\Example\app.exe" "%AppData%\svchost.exe"',
    r"%AppData%\custom.exe svchost.exe", r"C:\Windows\System32\svchost.exe",
    r'"%AppData%\svchost.exe', "", {"binary": "uninterpreted"},
])
def test_run_key_raise_uses_only_valid_executable_operand(tmp_path, monkeypatch, value):
    from romulus.detect.windows_registry_events import RegistryRunKeys
    event = native({"Image": r"C:\Windows\regedit.exe", "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Example",
                    "Details": value, "EventType": "SetValue"}, code=13)
    findings, _rule = sweep_run(tmp_path, monkeypatch, RegistryRunKeys(), [[event]])
    assert not any(finding["lane"] == "high" for finding in findings)


@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("kind", ["termination", "boot"])
def test_known_native_fence_prevents_live_account_association(tmp_path, monkeypatch, kind, late):
    parent = native(process(r"C:\Users\alice\parent.exe", r"EXAMPLE\alice", 1))
    child = native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", 2,
                           ParentProcessGuid=parent[0].get("process.guid")), 2, offset=2)
    fence = (native({"Image": r"C:\Users\alice\parent.exe", "ProcessGuid": parent[0].get("process.guid")}, 3, code=5, offset=1)
             if kind == "termination" else native({}, 3, code=12, offset=1, provider="Microsoft-Windows-Kernel-General", channel="System"))
    assert fence[0].get("process.fence") in {"termination", "boot"}
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type("ParentAccountTransition")(),
                                [[parent], [child], [fence]] if late else [[parent], [fence], [child]])
    assert len(findings) == 1 and findings[0]["lane"] == "lead"
    assert "fence" in findings[0]["claim"] and fence[0].id in findings[0]["event_ids"]


def test_real_sqlite_full_retains_computed_live_account_positive(tmp_path):
    from romulus.detect.bounded import StateBudget
    rule = rule_type("ParentAccountTransition")()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=1024 * 1024, reserve=0)
    parent = native(process(r"C:\Users\alice\parent.exe", r"EXAMPLE\alice", 1))[0]
    child = native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", 2,
                           ParentProcessGuid=parent.get("process.guid"), CommandLine="cmd.exe " + "x" * 100000), 2, offset=1)[0]
    try:
        assert list(rule.consume([parent])) == []
        rule.rows.store().grew()
        rule.budget.disk_total = rule.budget.physical_used + 4096
        matches = list(rule.consume([child]))
        assert any(match.proposed_lane == "high" for match in matches)
        assert any("physical whole-hunt byte ceiling" in reason for reason in rule.limit_reasons())
        assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= rule.budget.disk_total
    finally:
        rule.release_state()


def test_account_rule_does_not_allocate_state_without_windows_records(tmp_path):
    rule = rule_type("ParentAccountTransition")()
    rule.spill_dir = tmp_path
    assert list(rule.consume([])) == [] and list(rule.finalize()) == []
    assert rule._spill is None and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name,data", [
    ("ServerOrBootProcessChild", {"Image": r"C:\Users\alice\cmd.exe", "ParentImage": r"C:\Program Files\Server\httpd.exe"}),
    ("RenamedSystemBinary", {"Image": r"C:\Users\alice\svchost.exe"}),
])
def test_each_host_keeps_first_code_finding(tmp_path, monkeypatch, name, data):
    records = [native(data, n + 1, host=f"host{n}.example.test") for n in range(2)]
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule_type(name)(), [records])
    assert len(findings) == 2 and all(finding["lane"] == "high" for finding in findings)
    assert {records[0][0].id, records[1][0].id} <= {identity for finding in findings for identity in finding["event_ids"]}


def test_pending_guid_lookup_only_replays_matching_children(tmp_path, monkeypatch):
    rule = rule_type("ParentAccountTransition")()
    parents = [native(process(r"C:\Users\alice\parent.exe", r"EXAMPLE\alice", n + 1), n + 1) for n in range(24)]
    children = [native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", n + 100,
                              ParentProcessGuid=parents[n][0].get("process.guid")), n + 100, offset=1) for n in range(24)]
    calls = []
    original = rule._match
    def counted(child, *args, **kwargs):
        calls.append(child.id)
        return original(child, *args, **kwargs)
    monkeypatch.setattr(rule, "_match", counted)
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule, [children, parents])
    assert len(findings) == 24 and all(finding["lane"] == "high" for finding in findings)
    assert len(calls) <= 4 * len(children)


def test_two_thousand_pending_children_replay_as_bounded_stream_through_sweep(tmp_path, monkeypatch):
    import tracemalloc
    rule = rule_type("ParentAccountTransition")()
    parent = native(process(r"C:\Users\alice\parent.exe", r"EXAMPLE\alice", 1))
    children = [native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", n + 2,
                              ParentProcessGuid=parent[0].get("process.guid")), n + 2, offset=1) for n in range(2000)]
    original = rule.consume
    observed = {"replayed": 0, "peak_per_next": 0}
    def streaming(events):
        iterator = original(events)
        assert iter(iterator) is iterator
        if not any(event.id == parent[0].id for event in events):
            yield from iterator
            return
        tracemalloc.start()
        try:
            while True:
                before = tracemalloc.get_traced_memory()[0]
                tracemalloc.reset_peak()
                try:
                    match = next(iterator)
                except StopIteration:
                    break
                observed["peak_per_next"] = max(observed["peak_per_next"], tracemalloc.get_traced_memory()[1] - before)
                observed["replayed"] += 1
                yield match
        finally:
            tracemalloc.stop()
    monkeypatch.setattr(rule, "consume", streaming)
    findings, _rule = sweep_run(tmp_path, monkeypatch, rule,
                                [children[start:start + 100] for start in range(0, len(children), 100)] + [[parent]])
    assert len(findings) == len(children) == observed["replayed"]
    assert all(finding["lane"] == "high" for finding in findings)
    assert observed["peak_per_next"] < 1024 * 1024


def seed_snapshot():
    import json
    import tempfile
    from pathlib import Path

    from pytest import MonkeyPatch
    parent = native(process(r"C:\Users\alice\parent.exe", r"EXAMPLE\alice", 1))
    children = [native(process(r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM", n + 2,
                              ParentProcessGuid=parent[0].get("process.guid")), n + 2, offset=n + 1) for n in range(4)]
    with tempfile.TemporaryDirectory() as directory, MonkeyPatch.context() as patch:
        findings, _rule = sweep_run(Path(directory), patch, rule_type("ParentAccountTransition")(), [children, [parent]])
        print(json.dumps(sorted(({key: item[key] for key in ("id", "claim", "lane", "event_ids", "group_key")}
                                 for item in findings), key=lambda item: item["id"]), sort_keys=True))


def test_guid_storage_result_is_hash_seed_independent():
    import os
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    outputs = []
    for seed in ("0", "2", "6"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=os.pathsep.join((str(root / "src"), str(root))))
        outputs.append(subprocess.check_output([sys.executable, str(Path(__file__).resolve()), "seed"], cwd=root,
                                              env=environment, text=True))
    assert outputs[0] == outputs[1] == outputs[2]


if __name__ == "__main__":
    import sys
    assert sys.argv[1:] == ["seed"]
    seed_snapshot()
