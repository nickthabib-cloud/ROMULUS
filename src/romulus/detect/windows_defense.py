"""Defense impairment and recovery inhibition recognised from command-line tokens (positive-only).

Each rule reads a known tool's arguments with its own grammar and claims only that the tool was run with those
arguments. The impairing change itself is recorded elsewhere (a service state change, a registry write, a cleared-log
event), not in the launching command line, so these rules are positive-only: a quiet window proves nothing,
and the same ends can be reached by the registry or service APIs directly.

Shapes: shadow-copy deletion (vssadmin/wmic/wbadmin/PowerShell), bcdedit recovery settings, Microsoft Defender
preference and exclusion changes (Set-MpPreference/Add-MpPreference and the registry path through reg.exe), host
firewall disable (netsh advfirewall / Set-NetFirewallProfile), stopping or reconfiguring a security service (sc/net),
unloading the Sysmon driver (fltmc/sc), and clearing event logs or audit policy (wevtutil cl, Clear-EventLog,
auditpol /clear).
"""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.windows_cmdline import (
    parse_powershell,
    parse_reg,
    ps_bool,
    ps_named_argument,
    ps_parameter_matches,
    ps_switch_argument,
    ps_tokens,
    split_argv,
    switch_name,
    switch_value,
)
from romulus.detect.windows_common import (
    Hit,
    Undecided,
    WindowsProcessRule,
    clip,
    image_name,
    parsed_field,
)
from romulus.evidence.typed import TypedEvent

_SECURITY_SERVICES = {
    "windefend", "wdnissvc", "wdfilter", "sense", "mpssvc", "securityhealthservice", "wscsvc", "sysmon",
    "sysmon64", "eventlog", "mpsdrv", "sophos", "csfalconservice", "cylancesvc", "sentinelagent",
    "mcafee", "savservice", "ekrn", "sepmasterservice", "xagt",
}

# Set-MpPreference/Add-MpPreference Disable* switches: (canonical, smallest unambiguous prefix, documented aliases).
# https://learn.microsoft.com/powershell/module/defender/set-mppreference
_DEFENDER_DISABLE = (
    ("disablerealtimemonitoring", "disabler", ("drtm",)),
    ("disablebehaviormonitoring", "disableb", ("dbm",)),
    ("disableioavprotection", "disablei", ("dioavp",)),
    ("disablescriptscanning", "disables", ("dscrptsc",)),
    ("disablearchivescanning", "disablea", ("darchsc",)),
    ("disableblockatfirstseen", "disableblock", ("dbafs",)),
    ("disableremovabledrivescanning", "disablerem", ()),
    ("disableintrusionpreventionsystem", "disablein", ("dips",)),
)
_DEFENDER_EXCLUSION = (
    ("exclusionpath", "exclusionpa", ()),
    ("exclusionprocess", "exclusionpr", ()),
    ("exclusionextension", "exclusione", ()),
    ("exclusionipaddress", "exclusioni", ()),
)
# Defender policy/registry paths (casefolded), compared as a path contains.
_DEFENDER_KEY_MARK = ("windows defender", "windows advanced threat protection")
_DEFENDER_DISABLE_VALUES = frozenset({"disableantispyware", "disablerealtimemonitoring", "disableantivirus",
                                      "disablebehaviormonitoring", "disableioavprotection",
                                      "disableonaccessprotection", "disablescanonrealtimeenable"})


def _argv(event: TypedEvent) -> list[str]:
    argv = split_argv(str(event.get("process.command_line")))
    if not argv:
        raise Undecided("command_line", "the command line did not parse into any argument")
    return argv


def _reg_bool(data: object) -> bool | None:
    """A REG_DWORD value's truthiness: non-zero -> True, zero -> False, None when it is not a plain integer."""
    text = str(data or "").strip().casefold()
    if not text:
        return None
    try:
        return int(text, 0) != 0
    except ValueError:
        return ps_bool(text)


def _registry_components(path: object) -> list[str]:
    """The casefolded path components of a registry key or path string, handling `\\`, `/` and a hive prefix."""
    text = str(path or "").strip().strip('"').strip("'").replace("/", "\\")
    text = text.removeprefix("registry::").removeprefix("microsoft.powershell.core\\registry::")
    return [part for part in text.casefold().split("\\") if part]


def _defender_key(path: object) -> tuple[bool, bool]:
    """(is a Windows Defender key, is one of its Exclusions sub-keys), by exact path-component comparison."""
    parts = _registry_components(path)
    is_defender = any(part in _DEFENDER_KEY_MARK for part in parts)
    is_exclusion = is_defender and "exclusions" in parts
    return is_defender, is_exclusion


class InhibitRecovery(WindowsProcessRule):
    id = "win.inhibit_system_recovery"
    version = "2"
    title = "shadow copies, backups or recovery settings were deleted or disabled"
    assures_negative = False
    positive_only_reason = ("the delete/disable request is read from argv; a window without a match proves nothing, "
                            "and the same state can be changed through the VSS or BCD APIs directly")
    severity, lane = "high", "high"
    attack = ("T1490",)
    benign = ("backup software pruning old shadow copies as part of retention (names its own policy, not /all)",
              "an administrator freeing disk space, confirmable against change tickets")
    next_checks = ("the host's backup and shadow-copy state after the command",
                   "other impact signals on the host (file encryption, mass renames)")
    card: ClassVar[dict] = {
        "behavior": "vssadmin/wmic delete shadows/shadowcopy, wbadmin delete catalog/systemstatebackup, or bcdedit "
                    "disabling recovery (recoveryenabled no, bootstatuspolicy ignoreallfailures)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show a recovery-inhibition request; positive-only (the change itself shows in "
                    "service/VSS state)",
        "benign_and_cost": "backup retention prunes shadow copies; the flagged shapes (delete all, disable recovery) "
                           "are specific, and this behaviour is a hallmark of ransomware, so lane high",
        "query_cost": "none beyond the sweep",
        "next_pivot": "other impact signals on the host and the backup state",
        "adds": "the recovery-inhibition command shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1490; CISA ransomware TTP tables (reimplemented)",
        "lanes": "high: inhibiting recovery is a pre-ransom impact step",
        "retrieval": "the sweep retrieves every process-creation record; this reads vssadmin/wmic/wbadmin/bcdedit "
                     "records",
    }

    # The smallest VSS allocation is ~320 MB; a resize of shadow storage below it forces Windows to delete the
    # existing shadow copies, so a tiny maxsize is a recovery-inhibition shape (a genuine resize uses GB or %).
    _MIN_SHADOW_STORAGE_BYTES = 320 * 1024 * 1024

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _argv(event)
        lowered = [token.casefold() for token in argv[1:]]
        if name == "vssadmin.exe" and "delete" in lowered and "shadows" in lowered:
            return [self._hit(event, argv, "vssadmin delete shadows", "vssadmin")]
        if name == "vssadmin.exe" and "resize" in lowered and "shadowstorage" in lowered:
            size = self._maxsize_bytes(argv[1:])
            if size is not None and size < self._MIN_SHADOW_STORAGE_BYTES:
                return [self._hit(event, argv, f"vssadmin resize shadowstorage to {size:,} bytes (below the minimum "
                                               f"allocation, which deletes existing shadow copies)", "vssadmin-resize")]
            return []
        if name == "wmic.exe" and any(token.casefold() in {"shadowcopy", "win32_shadowcopy"} for token in argv[1:]) \
                and "delete" in lowered:
            return [self._hit(event, argv, "wmic shadowcopy delete", "wmic")]
        if name == "wbadmin.exe" and "delete" in lowered and (
                "catalog" in lowered or "systemstatebackup" in lowered or "backup" in lowered):
            return [self._hit(event, argv, "wbadmin delete", "wbadmin")]
        if name == "bcdedit.exe" and (
                ("recoveryenabled" in lowered and "no" in lowered)
                or "ignoreallfailures" in lowered):
            return [self._hit(event, argv, "bcdedit disabling recovery", "bcdedit")]
        return []

    @staticmethod
    def _maxsize_bytes(args: list[str]) -> int | None:
        """The /maxsize= value in bytes, or None (UNBOUNDED, a percentage, or unparseable: not a deletion shape)."""
        raw = None
        for token in args:
            if token.casefold().startswith(("/maxsize", "-maxsize")):
                raw = switch_value(token)
                break
        if raw is None:
            return None
        text = raw.strip().strip('"').casefold()
        if text in {"unbounded", ""} or text.endswith("%"):
            return None
        units = {"kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
        multiplier = 1
        for suffix, factor in units.items():
            if text.endswith(suffix):
                multiplier = factor
                text = text[:-2]
                break
        try:
            return int(float(text) * multiplier)
        except ValueError:
            return None

    def _hit(self, event: TypedEvent, argv: list[str], label: str, shape: str) -> Hit:
        return Hit("inhibit_recovery", f"{label} was run (system recovery was being removed or disabled)", self.lane,
                   self.severity, self.attack, [parsed_field(event, clip(" ".join(argv[1:])))],
                   content=f"recovery:{shape}")


class PowerShellShadowCopyDeletion(WindowsProcessRule):
    id = "win.powershell_shadow_copy_deletion"
    version = "1"
    title = "PowerShell deleted shadow copies"
    assures_negative = False
    positive_only_reason = ("the cmdlet call is read from parsed script text, which can be obfuscated or built at run "
                            "time; a window without a match proves nothing")
    severity, lane = "high", "high"
    attack = ("T1490",)
    benign = ("a storage-management script removing shadow copies under a documented retention policy",)
    next_checks = ("the host's shadow-copy state", "other impact signals on the host")
    card: ClassVar[dict] = {
        "behavior": "powershell/pwsh whose command or script calls Get-WmiObject/Get-CimInstance Win32_ShadowCopy "
                    "piped to a Delete/Remove, or Remove-CimInstance of a shadow copy",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the parsed script shows the deletion call; positive-only",
        "benign_and_cost": "storage scripts can do this; lane high because it is a ransomware hallmark, merged per "
                           "shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the host's shadow-copy state and other impact signals",
        "adds": "the PowerShell shadow-copy-deletion shape (complements the native-tool rule)",
        "research_basis": "ATT&CK Enterprise 20.0 T1490; SigmaHQ shadow-copy deletion patterns (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads powershell/pwsh records",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"powershell.exe", "pwsh.exe"}:
            return []
        argv = _argv(event)
        call = parse_powershell(argv[1:])
        if call.script is None:
            return []
        tokens = ps_tokens(call.script)
        words = {token.text for token in tokens if token.kind in {"word", "string"}}
        members = {token.text for token in tokens if token.kind == "member"}
        shadow = "win32_shadowcopy" in words or any("shadowcopy" in token.text for token in tokens
                                                   if token.kind == "string")
        deletes = bool({"remove-ciminstance", "remove-wmiobject"} & words) or "delete" in members
        if shadow and deletes:
            value = parsed_field(event, clip(call.script))
            return [Hit("ps_shadow_delete", "a PowerShell script deleted shadow copies", self.lane, self.severity,
                        self.attack, [value], content="recovery:ps-shadow")]
        return []


class DefenderImpairment(WindowsProcessRule):
    id = "win.defender_impairment"
    version = "3"
    title = "Microsoft Defender was disabled or given an exclusion"
    assures_negative = False
    positive_only_reason = ("the preference change is read from PowerShell argv/script or reg.exe argv; a window "
                            "without a match proves nothing, as the same registry values can be set by other means")
    severity, lane = "high", "high"
    attack = ("T1685.007", "T1685")
    benign = ("endpoint-management tooling applying an approved exclusion or policy (confirm against the baseline)",)
    next_checks = ("Defender's own operational log (5001/5007) for the effective change",
                   "what ran in the excluded path or after protection was disabled")
    card: ClassVar[dict] = {
        "behavior": "Set-MpPreference/Add-MpPreference disabling real-time monitoring or adding an exclusion, or "
                    "reg.exe writing the Windows Defender policy keys (DisableAntiSpyware, Exclusions\\*)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the preference change was requested; positive-only (Defender's 5007 shows the "
                    "effective change)",
        "benign_and_cost": "management tooling applies exclusions legitimately; lane high, repeats merge, and the "
                           "discriminating pivot is what ran in the excluded path",
        "query_cost": "none beyond the sweep",
        "next_pivot": "Defender 5007/5001 and activity in the excluded path",
        "adds": "the Defender disable/exclusion shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1685.007 (v20 defense-impairment ids); Microsoft Defender "
                          "PowerShell and policy references (reimplemented)",
        "lanes": "high: disabling Defender or excluding a path is a common precursor to payload execution",
        "retrieval": "the sweep retrieves every process-creation record; this reads powershell/pwsh and reg.exe "
                     "records",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _argv(event)
        if name in {"powershell.exe", "pwsh.exe"}:
            return self._powershell(event, argv)
        if name in {"reg.exe", "reg1.exe"}:
            return self._reg(event, argv)
        return []

    def _powershell(self, event: TypedEvent, argv: list[str]) -> list[Hit]:
        call = parse_powershell(argv[1:])
        if call.script is None:
            return []
        tokens = ps_tokens(call.script)
        words = {token.text for token in tokens if token.kind == "word"}
        if words & {"set-mppreference", "add-mppreference"}:
            return self._mppreference(event, call.script, tokens)
        if words & {"set-itemproperty", "new-itemproperty"}:
            return self._itemproperty(event, call.script, tokens)
        return []

    def _mppreference(self, event: TypedEvent, script: str, tokens: list) -> list[Hit]:
        what = None
        for idx, token in enumerate(tokens):
            if token.kind != "parameter":
                continue
            if any(ps_parameter_matches(token, canon, small, aliases)
                   for canon, small, aliases in _DEFENDER_EXCLUSION):
                what = "an exclusion"
                break
            for canon, small, aliases in _DEFENDER_DISABLE:
                if ps_parameter_matches(token, canon, small, aliases):
                    value, _inline = ps_switch_argument(tokens, idx)
                    if value is True:                       # $false / 0 re-enables: never claimed as disabling
                        what = "real-time protection or a scanning component disabled"
                    break
            if what is not None:
                break
        if what is None:
            return []
        return [Hit("defender_impairment", f"a Defender preference command set {what}", self.lane, self.severity,
                    self.attack, [parsed_field(event, clip(script))],
                    content=f"defender:{'exclusion' if 'exclusion' in what else 'disable'}")]

    def _itemproperty(self, event: TypedEvent, script: str, tokens: list) -> list[Hit]:
        verb = "set" if any(t.kind == "word" and t.text == "set-itemproperty" for t in tokens) else "new"
        # -Path/-LiteralPath points at a key; -Name is the value name; -Value is the data (reg bool semantics).
        path_value = ps_named_argument(tokens, ("path", "p"), ("literalpath", "literalp"))
        name_value = ps_named_argument(tokens, ("name", "n"), ("propertyname", "propertyn"))
        data_value = ps_named_argument(tokens, ("value", "v"))
        # a key component may also appear as a bare string operand (Set-ItemProperty "HKLM:\...\Windows Defender")
        is_defender = is_exclusion = False
        for candidate in [path_value, *[t.text for t in tokens if t.kind == "string"]]:
            defender, exclusion = _defender_key(candidate)
            is_defender = is_defender or defender
            is_exclusion = is_exclusion or exclusion
        if not is_defender:
            return []
        if is_exclusion:
            what = "an exclusion"
        else:
            value_name = (name_value or "").strip().casefold()
            if value_name not in _DEFENDER_DISABLE_VALUES or _reg_bool(data_value) is not True:
                return []                                   # -Value 0 re-enables, or not a Defender disable value
            what = "a Defender policy value"
        return [Hit("defender_impairment",
                    f"a PowerShell registry write ({verb.capitalize()}-ItemProperty) set {what} under a Windows "
                    f"Defender key", self.lane, self.severity, self.attack, [parsed_field(event, clip(script))],
                    content=f"defender:ps-reg:{'exclusion' if is_exclusion else 'disable'}")]

    def _reg(self, event: TypedEvent, argv: list[str]) -> list[Hit]:
        reg = parse_reg(argv)
        if reg is None:
            return []
        is_defender, is_exclusion = _defender_key(reg.key)
        if not is_defender:
            return []
        if reg.verb in {"query", "export", "save", "copy"}:
            return []                                        # reading or exporting is not a change
        if reg.verb in {"import", "restore", "load"}:
            return [Hit("defender_impairment",
                        f"reg {reg.verb} applied a registry file ({reg.import_file or 'unnamed'}) touching a Windows "
                        f"Defender key; its contents are not in the command line", "lead", "medium", self.attack,
                        [parsed_field(event, clip(" ".join(argv[1:])))], content="defender:reg:import")]
        if reg.verb != "add":
            return []
        if is_exclusion:
            return [self._reg_hit(event, argv, "an exclusion", "exclusion")]
        value = (reg.value_name or "").strip().casefold()
        if value in _DEFENDER_DISABLE_VALUES and _reg_bool(reg.data) is True:  # /d 0 re-enables: never "disabled"
            return [self._reg_hit(event, argv, f"the Defender policy value '{reg.value_name}' to disabled", "disable")]
        return []

    def _reg_hit(self, event: TypedEvent, argv: list[str], what: str, shape: str) -> Hit:
        return Hit("defender_impairment", f"reg.exe set {what} under a Windows Defender policy key", self.lane,
                   self.severity, self.attack, [parsed_field(event, clip(" ".join(argv[1:])))],
                   content=f"defender:reg:{shape}")


class HostFirewallDisable(WindowsProcessRule):
    id = "win.host_firewall_disable"
    version = "2"
    title = "the Windows host firewall was turned off"
    assures_negative = False
    positive_only_reason = ("the firewall state change is read from argv; a window without a match proves nothing, "
                            "as the firewall can be reconfigured through the API or policy")
    severity, lane = "medium", "lead"
    attack = ("T1686.003", "T1686")
    benign = ("endpoint management or troubleshooting that disables a firewall profile under a change ticket",)
    next_checks = ("the firewall state after the command", "new inbound connections to the host afterwards")
    card: ClassVar[dict] = {
        "behavior": "netsh advfirewall set ... state off, netsh firewall set opmode disable, or "
                    "Set-NetFirewallProfile -Enabled False",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the firewall was turned off; positive-only",
        "benign_and_cost": "troubleshooting disables the firewall sometimes; lane lead, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "new inbound connections to the host after the change",
        "adds": "the host-firewall-disable shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1686.003; Microsoft netsh advfirewall reference (reimplemented)",
        "lanes": "lead",
        "retrieval": "the sweep retrieves every process-creation record; this reads netsh and powershell/pwsh records",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _argv(event)
        lowered = [token.casefold() for token in argv[1:]]
        if name == "netsh.exe" and (
                ("advfirewall" in lowered and "state" in lowered and "off" in lowered)
                or ("firewall" in lowered and "opmode" in lowered and "disable" in lowered)):
            return [Hit("firewall_disable", "netsh was run to turn the host firewall off", self.lane, self.severity,
                        self.attack, [parsed_field(event, clip(" ".join(argv[1:])))], content="firewall:netsh")]
        if name in {"powershell.exe", "pwsh.exe"}:
            call = parse_powershell(argv[1:])
            if call.script is not None:
                tokens = ps_tokens(call.script)
                words = {token.text for token in tokens if token.kind == "word"}
                if "set-netfirewallprofile" in words:
                    for idx, token in enumerate(tokens):
                        if token.kind == "parameter" and ps_parameter_matches(token, "enabled", "en"):
                            value, _inline = ps_switch_argument(tokens, idx)
                            if value is False:              # -Enabled False turns the profile off; True re-enables
                                return [Hit("firewall_disable", "Set-NetFirewallProfile was run with -Enabled False",
                                            self.lane, self.severity, self.attack,
                                            [parsed_field(event, clip(call.script))], content="firewall:ps")]
        return []


class SecurityServiceTampering(WindowsProcessRule):
    id = "win.security_service_tampering"
    version = "2"
    title = "a security service or the Sysmon driver was stopped or reconfigured"
    assures_negative = False
    positive_only_reason = ("the service and verb are read from argv; a window without a match proves nothing, as a "
                            "service can be stopped or disabled through the service-control API")
    severity, lane = "high", "high"
    attack = ("T1685.007", "T1685.001", "T1685")
    benign = ("vendor updaters that stop and restart their own agent during an upgrade",
              "an administrator reconfiguring a security product under a change ticket")
    next_checks = ("the service's state after the command (7036/7040)",
                   "whether telemetry from that host stops after the change")
    card: ClassVar[dict] = {
        "behavior": "sc stop/config/delete or net stop targeting a security or logging service (Defender, Sysmon, "
                    "EventLog, a third-party EDR), or fltmc unload of the Sysmon minifilter",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the service was stopped/reconfigured; positive-only (7036/7040 show the "
                    "effective state)",
        "benign_and_cost": "vendor updaters restart their own agents; lane high because stopping security telemetry "
                           "is a direct evasion, and repeats merge per shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the service's state change and whether that host's telemetry stops",
        "adds": "the security-service/Sysmon-driver tampering shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1685.007/.001 (v20 defense-impairment ids); Sysinternals Sysmon "
                          "and Microsoft sc/net references (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads sc/net/fltmc records",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _argv(event)
        rest = argv[1:]
        # sc may target a remote host: `sc \\host stop <svc>`. Drop a leading \\server operand.
        if name == "sc.exe" and rest and rest[0].startswith("\\\\"):
            rest = rest[1:]
        lowered = [token.casefold() for token in rest]
        if name == "sc.exe" and lowered[:1] and lowered[0] in {"stop", "config", "delete"}:
            service = next((token.casefold() for token in rest[1:2]), "")
            if self._is_security(service):
                return [self._hit(event, argv, f"sc {lowered[0]} on security service '{service}'", "sc")]
        if name in {"net.exe", "net1.exe"} and lowered[:1] == ["stop"]:
            service = " ".join(token for token in argv[2:] if not token.startswith("/")).strip('"').casefold()
            if self._is_security(service):
                return [self._hit(event, argv, f"net stop on security service '{service}'", "net")]
        if name == "fltmc.exe" and "unload" in lowered and any("sysmon" in token.casefold() for token in argv[2:]):
            return [self._hit(event, argv, "fltmc unload of the Sysmon minifilter", "fltmc")]
        return []

    @staticmethod
    def _is_security(service: str) -> bool:
        folded = service.strip().strip('"').casefold()
        return folded.replace(" ", "") in _SECURITY_SERVICES or folded in _SECURITY_SERVICES

    def _hit(self, event: TypedEvent, argv: list[str], label: str, shape: str) -> Hit:
        return Hit("security_service_tamper", f"{label} was run", self.lane, self.severity, self.attack,
                   [parsed_field(event, clip(" ".join(argv[1:])))], content=f"svc:{shape}")


class LogClearingByCommand(WindowsProcessRule):
    id = "win.log_clearing_command"
    version = "2"
    title = "an event log or the audit policy was cleared by command"
    assures_negative = False
    positive_only_reason = ("the clear request is read from argv; a window without a match proves nothing, and logs "
                            "can be cleared through the API. The cleared-log event (1102/104) is the OS record of it")
    severity, lane = "high", "high"
    attack = ("T1685.005", "T1685.001", "T1685")
    benign = ("a log-management routine that clears a channel after archiving it (should be known)",)
    next_checks = ("the 1102/104 cleared-log event for the effective clear",
                   "what happened on the host shortly before the clear")
    card: ClassVar[dict] = {
        "behavior": "wevtutil cl/clear-log of a channel, Clear-EventLog, wevtutil sl ... /e:false (disable a "
                    "channel), or auditpol /clear or /set removing auditing",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the clear/disable was requested; positive-only (1102/104 is the OS record of "
                    "an actual clear). The sweep also treats 1102/104/4719 as collection-change events for coverage.",
        "benign_and_cost": "archival routines clear channels; lane high because clearing logs during an intrusion is "
                           "direct evasion, and repeats merge per shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the 1102/104 event and the host's activity just before the clear",
        "adds": "the log-clearing and audit-policy-clearing command shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1685.005/.001 (v20 defense-impairment ids); Microsoft wevtutil "
                          "and auditpol references (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads wevtutil/auditpol/powershell "
                     "records",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _argv(event)
        lowered = [token.casefold() for token in argv[1:]]
        if name == "wevtutil.exe" and lowered[:1] and lowered[0] in {"cl", "clear-log"}:
            return [self._hit(event, argv, "wevtutil cleared an event log", "wevtutil-cl")]
        if name == "wevtutil.exe" and lowered[:1] and lowered[0] in {"sl", "set-log"}:
            # /e:<value> and /enabled:<value> enable (true/1) or disable (false/0) the channel: fire only on false.
            enabled = self._channel_enabled(argv[1:])
            if enabled is False:
                return [self._hit(event, argv, "wevtutil disabled an event-log channel", "wevtutil-sl")]
            return []
        if name == "auditpol.exe" and ("/clear" in lowered or "/remove" in lowered or (
                "/set" in lowered and any("success:disable" in token.casefold()
                                          or "failure:disable" in token.casefold() for token in argv[1:]))):
            return [self._hit(event, argv, "auditpol cleared, removed or disabled auditing", "auditpol")]
        if name in {"powershell.exe", "pwsh.exe"}:
            call = parse_powershell(argv[1:])
            if call.script is not None:
                tokens = ps_tokens(call.script)
                if any(token.kind == "word" and token.text == "clear-eventlog" for token in tokens):
                    return [Hit("log_clear", "a PowerShell script cleared an event log", self.lane, self.severity,
                                self.attack, [parsed_field(event, clip(call.script))], content="log:ps-clear")]
        return []

    @staticmethod
    def _channel_enabled(args: list[str]) -> bool | None:
        """The value of `/e:` or `/enabled:` (true/false/1/0, case-insensitive, quoted), or None when absent or not a
        boolean. `wevtutil sl <channel> /e:false` disables the channel; `/e:true` enables it and must not fire."""
        for token in args:
            if token[:1] not in "-/":
                continue
            flag = switch_name(token)
            if flag in {"e", "enabled"}:
                return ps_bool(switch_value(token))
        return None

    def _hit(self, event: TypedEvent, argv: list[str], label: str, shape: str) -> Hit:
        return Hit("log_clear", f"{label}", self.lane, self.severity, self.attack,
                   [parsed_field(event, clip(" ".join(argv[1:])))], content=f"log:{shape}")


WINDOWS_DEFENSE_PLAYBOOKS = [
    InhibitRecovery, PowerShellShadowCopyDeletion, DefenderImpairment, HostFirewallDisable,
    SecurityServiceTampering, LogClearingByCommand,
]
