"""Account lanes and bounded housekeeping folds retain typed evidence."""
from __future__ import annotations

import pytest

from romulus.detect.windows_housekeeping import (
    BitsUnusualCreator,
    EventlogWerfault,
    HiddenFileAttribute,
    KerberosLoopbackLogon,
    UnexpectedPsRemoteServer,
)
from romulus.evidence.typed import fv
from romulus.evidence.windows_catalog import BITS_CHANNEL, BITS_PROVIDER, SECURITY
from tests.test_sweep import _repo
from tests.test_windows_auth_round5 import publish
from tests.test_windows_housekeeping import event, werfault
from tests.windows_process_support import run, sysmon1

SHAPES = ("winlogbeat_7", "winlogbeat_8", "elastic_agent")


def logon(name, sid, shape):
    return event(4624, {"LogonType": "3", "AuthenticationPackageName": "Kerberos",
                       "IpAddress": "::1", "TargetUserName": name, "TargetUserSid": sid},
                 channel="Security", provider=SECURITY, shape=shape)


def evaluate(rule, records):
    try:
        return run(rule, records)
    finally:
        rule.release_state()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("name,sid,lane", [
    ("DC01$", "S-1-5-21-1-2-3-1000", "lead"),
    ("Administrator", "S-1-5-18", None),
    ("DC01$", "S-1-5-21-1-2-3-500", "high"),
    ("Administrator", "S-1-5-21-1-2-3-500", "high"),
    ("renamed-admin", "S-1-5-21-4-5-6-500", "high"),
    ("Administrator", "S-1-5-21-1-2-3-1001", "lead"),
    ("analyst", "S-1-5-21-1-2-3-1500", "lead"),
    ("Administrator", "", "lead"),
    ("", "", "lead"),
])
def test_loopback_kerberos_account_identity_controls_lane(shape, name, sid, lane):
    result = evaluate(KerberosLoopbackLogon(), [logon(name, sid, shape)])
    assert [match.proposed_lane for match in result] == ([] if lane is None else [lane])
    if result:
        assert "privilege change" in " ".join(result[0].notes)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("parent,lane", [
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "lead"),
    (r"\??\C:\Program Files\PowerShell\7\PwSh.ExE", "lead"),
    (r"\\?\C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe", "lead"),
    (r"C:\Tools\client.exe", "high"),
    (r"C:\Tools\powershell.exe.evil.exe", "high"),
])
def test_powershell_job_parents_are_caveated_leads(shape, parent, lane):
    record = sysmon1(image="powershell.exe", command="powershell.exe -s -NoLogo -NoProfile",
                     parent_image=parent, shape=shape)
    [match] = evaluate(UnexpectedPsRemoteServer(), [record])
    assert match.proposed_lane == lane
    if lane == "lead":
        assert "Start-Job" in " ".join([match.claim, *match.notes])
    assert "outcome is not established" in " ".join(match.notes)


def test_powershell_jobs_fold_across_parent_pids_and_commands_without_losing_facts():
    records = []
    for index in range(50):
        record = sysmon1(image="powershell.exe", command="powershell.exe -s -NoLogo -NoProfile",
                         parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ppid=700 + index, offset=index)
        record.fields["process.parent.command_line"] = fv(f"powershell.exe -File job{index}.ps1", "test:parent")
        records.append(record)
    rule = UnexpectedPsRemoteServer()
    result = evaluate(rule, [records[:25], records[25:]])
    assert len(result) == 1
    [fleet] = [match for match in result if match.group_key]
    assert "50 Windows event record(s)" in fleet.claim
    assert "Start-Job" in fleet.claim and fleet.proposed_lane == "lead"
    assert len(fleet.events) <= 16
    facts = {predicate.field for predicate in result[0].predicate}
    assert {"process.ppid", "process.parent.command_line"} <= facts


def bits(path, index=0, shape="winlogbeat_8"):
    data = {"jobTitle": f"job-{index}", "jobId": f"id-{index}",
            "processId": str(900 + index), "jobOwner": f"DOMAIN\\user{index}"}
    if path is not None:
        data["processPath"] = path
    return event(3, data, channel=BITS_CHANNEL, provider=BITS_PROVIDER, shape=shape)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\svchost.exe", r"\??\C:\Windows\SysWOW64\bitsadmin.exe",
    r"\\?\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Program Files\PowerShell\7\pwsh.exe",
])
def test_usual_bits_clients_require_canonical_installed_paths(shape, path):
    assert not evaluate(BitsUnusualCreator(), [bits(path, shape=shape)])


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("path", [
    r"C:\ProgramData\svchost.exe", r"C:\Tools\bitsadmin.exe",
    r"D:\Windows\System32\svchost.exe", r"\Device\HarddiskVolume7\Windows\System32\svchost.exe",
    r"D:\Program Files\PowerShell\7\pwsh.exe",
    r"C:\ProgramData\Windows\System32\svchost.exe",
    r"C:\Windows\System32\powershell.exe", r"C:\Tools\pwsh.exe",
    r"\\server\share\Windows\System32\svchost.exe",
])
def test_basename_masquerades_are_never_quiet_bits_creators(shape, path):
    [match] = evaluate(BitsUnusualCreator(), [bits(path, shape=shape)])
    assert match.proposed_lane == "lead"


@pytest.mark.parametrize("path", [r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
    r"C:\Users\analyst\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"])
def test_installed_bits_updaters_fold_case_and_job_metadata(path):
    records = [bits(path if index % 2 else path.upper(), index) for index in range(50)]
    result = evaluate(BitsUnusualCreator(), [records[:25], records[25:]])
    assert len(result) == 1 and all(match.proposed_lane == "lead" for match in result)
    [fleet] = [match for match in result if match.group_key]
    assert "50 Windows event record(s)" in fleet.claim and len(fleet.events) <= 16
    assert "rarity" in " ".join([result[0].claim, *result[0].notes])


@pytest.mark.parametrize("shape", SHAPES)
def test_missing_win7_bits_creators_fold_with_named_limit(shape):
    rule = BitsUnusualCreator()
    result = evaluate(rule, [bits(None, index, shape) for index in range(50)])
    assert len(result) == 1
    [fleet] = [match for match in result if match.group_key]
    assert "50 Windows event record(s)" in fleet.claim
    assert all(match.proposed_lane == "lead" and "unresolved" in match.claim for match in result)
    assert "creator" in rule.limits and rule.limits["creator"].hits == 50


def test_bits_distinct_creators_and_hosts_remain_retrievable():
    records = [bits(r"C:\Tools\one.exe"), bits(r"C:\Tools\two.exe", 1)]
    other = bits(r"C:\Tools\one.exe", 2).model_copy(update={"host": "ws02.example.test"})
    result = evaluate(BitsUnusualCreator(), [*records, other])
    assert len(result) == 3 and len({match.group_key for match in result}) == 3
    assert {match.events[0].host for match in result} == {records[0].host, other.host}


def test_bits_canonical_creator_namespace_variants_share_one_identity():
    paths = [r"C:\Tools\client.exe", r"\??\C:\Tools\CLIENT.exe", r"\\?\C:\Tools\client.exe"]
    [match] = evaluate(BitsUnusualCreator(), [bits(path, index) for index, path in enumerate(paths)])
    assert "3 Windows event record(s)" in match.claim


@pytest.mark.parametrize("rule_class,image,other", [
    (HiddenFileAttribute, r"C:\Windows\System32\attrib.exe", r"C:\Tools\attrib.exe"),
    (EventlogWerfault, r"C:\Windows\System32\WerFault.exe", r"C:\Tools\WerFault.exe"),
])
def test_minor_folds_do_not_merge_distinct_images_or_hosts(rule_class, image, other):
    records = []
    for index, (path, host) in enumerate([(image, "ws01"), (other, "ws01"), (image, "ws02")]):
        record = (sysmon1(image=path, command="attrib.exe +h file.txt", host=host, offset=index)
                  if rule_class is HiddenFileAttribute else werfault())
        record = record.model_copy(update={"host": host, "fields": {**record.fields,
            "process.executable": fv(path, "test:image"),
            "process.executable_key": fv(path.casefold(), "test:image")}})
        records.append(record)
    result = evaluate(rule_class(), records)
    assert len(result) == 3 and len({match.group_key for match in result}) == 3


@pytest.mark.parametrize("rule_class", [HiddenFileAttribute, EventlogWerfault])
def test_minor_housekeeping_folds_varying_commands_by_image(rule_class):
    records = []
    for index in range(50):
        if rule_class is HiddenFileAttribute:
            record = sysmon1(image=r"C:\Windows\System32\attrib.exe",
                             command=f"attrib.exe +h file{index}.txt", ppid=700 + index, offset=index)
        else:
            record = werfault(ppid=700 + index, command=f"werfault.exe -u -p {700 + index} -s {index}")
        records.append(record)
    result = evaluate(rule_class(), [records[:25], records[25:]])
    assert len(result) == 1
    [fleet] = [match for match in result if match.group_key]
    assert "50 Windows event record(s)" in fleet.claim and fleet.proposed_lane == "lead"
    assert len(fleet.events) <= 16
    assert "process.command_line" in {predicate.field for predicate in result[0].predicate}


def test_bits_flood_revises_one_persisted_candidate_per_host_and_creator():
    repo, rule = _repo(), BitsUnusualCreator()
    path = r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe"
    records = [bits(path if index % 2 else path.upper(), index) for index in range(100)]
    staged = {}
    rule.load = lambda ids: [staged[key] for key in ids if key in staged]
    try:
        for index in range(0, len(records), 10):
            matches = rule.consume(records[index:index + 10])
            staged.update({record.id: record for record in rule.drain_staged()})
            for match in matches:
                publish(repo, rule, match)
        for match in rule.finalize():
            publish(repo, rule, match)
        [candidate] = repo.candidates("h1")
        assert "100 Windows event record(s)" in candidate["claim"]
        assert len(candidate["event_ids"]) <= 16
        assert candidate["lane"] == "lead"
    finally:
        rule.release_state()
