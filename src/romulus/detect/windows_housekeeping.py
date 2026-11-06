"""Positive Windows account, remoting, transfer and housekeeping observations."""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit

from romulus.detect.site_roles import host_member
from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_cmdline import DASHES, SWITCH_STARTS, split_argv
from romulus.detect.windows_common import Undecided
from romulus.detect.windows_events import (
    WindowsEventRule,
    basename,
    components,
    integer,
    local_path_components,
    signal,
)
from romulus.detect.windows_path_data import installation_parts
from romulus.detect.windows_registry_events import _CU, _LM, _software, _system, _target
from romulus.evidence.windows import windows_path_key
from romulus.evidence.windows_catalog import (
    BITS_CHANNEL,
    BITS_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    WINRM_CHANNEL,
    WINRM_PROVIDER,
)

_SYSMON_DOC = "https://learn.microsoft.com/sysinternals/downloads/sysmon"
_PROCESS = ((SYSMON_CHANNEL, SYSMON, 1),)
_REGISTRY = ((SYSMON_CHANNEL, SYSMON, 12), (SYSMON_CHANNEL, SYSMON, 13))
_REG_FIELDS = ("registry.path_key", "registry.action", "registry.event_type", "registry.value_name", "registry.value")
_PROC_FIELDS = ("process.executable", "process.command_line", "process.parent.executable", "process.ppid",
                "process.parent.command_line")


def _folded(value):
    return value.casefold() if isinstance(value, str) else value


def _image_identity(value):
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.casefold() in {"", "?", "-", "null", "(null)", "(empty)", "unknown", "n/a", ".", ".."}:
        return None
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
    name = basename(text)
    if (not name or name in {".", ".."} or any(char in text for char in '<>"|?*')
            or ":" in name or any(ord(char) < 32 for char in text)):
        return None
    return text


def _arguments(event, field="process.command_line"):
    return [token.casefold() for token in split_argv(str(event.get(field) or ""))]


def _option_value(argv, option):
    positions = [index for index, token in enumerate(argv[1:], 1) if token == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        return None
    return argv[positions[0] + 1]


def _server_mode(argv):
    # ConsoleHost's MatchSwitch accepts a family prefix at least as long as its
    # smallest unambiguous spelling. Values and command/script payloads retain
    # their token roles; a mentioned server switch there is not a launch switch.
    no_value = (("nologo", "nol"), ("noprofile", "nop"), ("noninteractive", "noni"),
                ("noexit", "noe"), ("sta", "sta"), ("mta", "mta"), ("interactive", "i"), ("login", "l"),
                ("noprofileloadtime", "noprofileloadtime"))
    takes_value = (("executionpolicy", "ex"), ("ep", "ep"), ("windowstyle", "w"), ("inputformat", "inp"),
                   ("if", "if"), ("outputformat", "o"), ("of", "o"), ("configurationname", "config"),
                   ("configurationfile", "configurationfile"), ("custompipename", "cus"),
                   ("encodedarguments", "encodeda"), ("ea", "ea"), ("settingsfile", "settings"),
                   ("workingdirectory", "wo"), ("wd", "wd"), ("psconsolefile", "psconsolefile"))

    def matches(key, families):
        return any(len(key) >= len(minimum) and family.startswith(key) for family, minimum in families)

    index = 1
    while index < len(argv):
        token = argv[index].strip()
        if not token:
            index += 1
            continue
        if token[0] not in SWITCH_STARTS:
            return False
        key = token[1:]
        if token[0] in DASHES and key.startswith(token[0]):
            key = key[1:]
        if matches(key, (("servermode", "s"),)):
            return True
        if matches(key, no_value):
            index += 1
        elif matches(key, takes_value) and index + 1 < len(argv):
            index += 2
        else:
            # Includes -Command/-File/-EncodedCommand (and their prefixes),
            # -Version, and unknown switches: never read their operands as flags.
            return False
    return False


def _local_transfer(value):
    if not isinstance(value, str) or not value.strip() or any(ord(char) < 32 for char in value):
        return False
    text = value.strip()
    if text.casefold().startswith("file:"):
        try:
            parsed = urlsplit(text)
        except ValueError:
            return False
        return bool(parsed.scheme.casefold() == "file" and parsed.path.strip("/") and not parsed.query
                    and not parsed.fragment and (parsed.netloc or parsed.path.startswith("/")))
    extended = text.startswith(("\\\\?\\", "\\??\\"))
    if extended:
        text = text[4:]
        if text.casefold().startswith("unc\\"):
            text = "\\\\" + text[4:]
    if (extended or re.match(r"^[a-zA-Z]:[\\/]", text)) and local_path_components(text):
        return True
    if text.startswith("\\\\"):
        parts = components(text)
        return len(parts) >= 3 and parts[0] not in {"?", "."}
    return False


def _usual_bits_client(image):
    # Compare whole installed paths, without treating a familiar basename as
    # evidence that a copy elsewhere belongs to Windows or PowerShell.
    parts = installation_parts(image)
    if len(parts) == 3 and parts[:2] in {("windows", "system32"), ("windows", "syswow64")}:
        return parts[2] in {"svchost.exe", "bitsadmin.exe"}
    if (len(parts) == 5 and parts[:2] in {("windows", "system32"), ("windows", "syswow64")}
            and parts[2:] == ("windowspowershell", "v1.0", "powershell.exe")):
        return True
    return (len(parts) == 4 and parts[0] in {"program files", "program files (x86)"}
            and parts[1] == "powershell" and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", parts[2]) is not None
            and parts[3] == "pwsh.exe")


def _installed_powershell_parent(image):
    if basename(image) in {"powershell.exe", "pwsh.exe"} and _usual_bits_client(image):
        return True
    parts = installation_parts(image)
    if len(parts) == 4 and parts[-1] == "pwsh.exe":
        if parts[:3] == ("program files", "powershell", "7-preview"):
            return True
        if (parts[:2] == ("program files", "windowsapps")
                and re.fullmatch(r"microsoft\.powershell_[0-9]+(?:\.[0-9]+){3}_(?:x86|x64|arm64)__8wekyb3d8bbwe",
                                 parts[2]) is not None):
            return True
    return (len(parts) == 5 and parts[:2] in {("windows", "system32"), ("windows", "syswow64")}
            and parts[2:] == ("windowspowershell", "v1.0", "powershell_ise.exe"))


class _Housekeeping(WindowsEventRule):
    benign = ("Authorized administration and ordinary operating-system activity can produce these records.",)
    next_checks = ("Review the cited fields, authorization and independent evidence of the resulting state.",)
    research = (_SYSMON_DOC,)

    def judge(self, event):
        observed = (str(event.get("event.channel") or "").casefold(),
                    str(event.get("event.provider") or "").casefold(), event.get("event.code"))
        if observed not in {(channel.casefold(), provider.casefold(), code)
                            for channel, provider, code in self.windows_event_classes}:
            return []
        return self.observe(event)

    def report(self, event, text, fields, *, high=False, low=False, notes=(), fold=None):
        identity = [(field, _folded(event.get(field))) for field in fields] if fold is None else [event.host, *fold]
        content = json.dumps([self.id, *identity],
                             sort_keys=True, ensure_ascii=True)
        return [signal(event, self.id, text, self.attack, fields, lane="high" if high else "lead",
                       severity="high" if high else "low" if low else "medium", content=content, notes=notes)]


class _FoldedHousekeeping(_Housekeeping, BehaviorFleetRule):
    """Publish the first observation and bounded recurrence revisions under one key."""
    fold_caveat = ""

    def record_match(self, event, hit):
        match = super().record_match(event, hit)
        match.bounded_revision = True
        return match

    def _fleet_match(self, shape, group, *, final):
        match = super()._fleet_match(shape, group, final=final)
        if match is not None and self.fold_caveat:
            match.notes.append(self.fold_caveat)
        return match


class HiddenSamAccount(_Housekeeping):
    id = "win.hidden_sam_account"
    title = "A SAM account-name mapping ending in a dollar sign was created or written"
    families = ("registry_change",)
    windows_event_classes = _REGISTRY
    required_fields = ("registry.path_key",)
    attack = ("T1564.002",)
    severity = "high"
    lane = "high"
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1564/002/")

    def observe(self, event):
        target = _target(event)
        if (target is None or target.root != _LM or len(target.key) != 7
                or target.key[:6] != ("sam", "sam", "domains", "account", "users", "names")
                or not target.key[-1].endswith("$") or target.key[-1] == "$"):
            return []
        created = (event.get("event.code") == 12 and target.name is None
                   and str(event.get("registry.event_type") or "").casefold() == "createkey")
        written = event.get("event.code") == 13 and target.name == "" and target.action == "written"
        if not (created or written):
            return []
        action = "key was created" if created else "default value was written"
        return self.report(event, f"SAM account-name mapping '{self.describe(target.key[-1])}' {action}",
                           _REG_FIELDS, high=True,
                           notes=("The mapping change is recorded; completed account creation or usable credentials are not established.",))


class KerberosLoopbackLogon(_Housekeeping):
    id = "win.kerberos_loopback_logon"
    version = "3"
    title = "A Kerberos network logon names a loopback source"
    families = ("auth",)
    windows_event_classes = (("Security", SECURITY, 4624),)
    required_fields = ("auth.logon_type", "auth.package", "source.ip")
    attack = ("T1558",)
    severity = "high"
    lane = "high"
    research = ("https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624",)

    def observe(self, event):
        if integer(event.get("auth.logon_type")) != 3 or str(event.get("auth.package")).casefold() != "kerberos":
            return []
        account = str(event.get("auth.target_account") or "").casefold()
        name = str(event.get("account.name") or "").casefold()
        if not name and account.startswith("name:"):
            name = account[5:].rsplit("\\", 1)[-1]
        own_machine = name.endswith("$") and host_member(name[:-1], (event.get("host.full_name") or event.host,))
        if account == "sid:s-1-5-18" or own_machine:
            return []
        try:
            address = ipaddress.ip_address(str(event.get("source.ip")))
        except ValueError:
            raise Undecided("source_address", "Kerberos network logon source address is unresolved") from None
        if not (address.is_loopback or getattr(address, "ipv4_mapped", None) and address.ipv4_mapped.is_loopback):
            return []
        return self.report(event, "Windows recorded a Kerberos network logon naming a loopback source",
                           ("auth.logon_type", "auth.package", "source.ip", "auth.target_account", "account.name"),
                           high=re.fullmatch(r"sid:s-1-5-21-\d+-\d+-\d+-500", account) is not None,
                           notes=("The logon does not by itself establish ticket forgery, relay or a privilege change.",))


class UnexpectedPsRemoteServer(_FoldedHousekeeping):
    id = "win.unexpected_ps_remote_server"
    version = "4"
    title = "PowerShell server mode was launched by an unexpected parent"
    families = ("process_exec",)
    windows_event_classes = _PROCESS
    required_fields = ("process.executable", "process.command_line")
    reads_command_line = True
    attack = ("T1021.006",)
    severity = "high"
    lane = "high"
    research = ("https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.ConsoleHost/host/msh/CommandLineParameterParser.cs",)
    fold_caveat = "Server-mode startup is observed; a remote session or command outcome is not established."

    def observe(self, event):
        image = event.get("process.executable_key") or event.get("process.executable")
        if basename(image) not in {"powershell.exe", "pwsh.exe"} or not _server_mode(_arguments(event)):
            return []
        parent = _image_identity(event.get("process.parent.executable_key") or event.get("process.parent.executable"))
        if not parent:
            raise Undecided("parent", "PowerShell -s server mode was requested; its parent is unresolved")
        if basename(parent) in {"wsmprovhost.exe", "sshd.exe"}:
            return []
        job_parent = _installed_powershell_parent(parent)
        text = f"PowerShell server mode was requested by recorded parent '{self.describe(parent)}'"
        if job_parent:
            text += "; ordinary PowerShell Start-Job can launch this out-of-process job host"
        return self.report(event, text, _PROC_FIELDS, high=not job_parent, notes=(self.fold_caveat,),
                           fold=(windows_path_key(image), windows_path_key(parent),
                                 _folded(event.get("process.command_line"))))


class BitsLocalTransfer(_Housekeeping):
    id = "win.bits_local_transfer"
    title = "A BITS transfer record names a local or UNC source"
    families = ("remote_access",)
    windows_event_classes = ((BITS_CHANNEL, BITS_PROVIDER, 59), (BITS_CHANNEL, BITS_PROVIDER, 60))
    required_fields = ("bits.remote_url",)
    attack = ("T1197",)
    severity = "high"
    lane = "high"
    research = ("https://learn.microsoft.com/windows-server/administration/windows-commands/bitsadmin-addfile",)

    def observe(self, event):
        if not _local_transfer(event.get("bits.remote_url")):
            return []
        return self.report(event, "A BITS transfer record names a local-file or UNC source",
                           ("bits.remote_url", "bits.job_id", "bits.job_name", "remote.action"), high=True,
                           notes=("The recorded source does not establish API acceptance, transfer success, payload execution or unauthorized use.",))


class BitsUnusualCreator(_FoldedHousekeeping):
    id = "win.bits_unusual_creator"
    version = "2"
    title = "A BITS job names an unusual creator image or a writable-indicator location"
    families = ("remote_access",)
    windows_event_classes = ((BITS_CHANNEL, BITS_PROVIDER, 3),)
    attack = ("T1197",)
    research = ("https://learn.microsoft.com/windows/win32/bits/background-intelligent-transfer-service-portal",)
    fold_caveat = "This image-path heuristic does not measure rarity or establish malicious use; legitimate updaters also create BITS jobs."

    def observe(self, event):
        image = _image_identity(event.get("bits.process_path_key") or event.get("bits.process_path"))
        if not image:
            text = "The BITS job creator image is unresolved; no usable process path was recorded"
            self.note_limit("creator", text)
            return self.report(event, text, ("bits.process_path", "bits.owner", "bits.job_name", "bits.job_id"),
                               notes=(self.fold_caveat,), fold=("creator_missing",))
        if _usual_bits_client(image):
            return []
        image = windows_path_key(image)
        return self.report(event, f"A BITS job names creator image '{self.describe(image)}' outside the usual installed client paths",
                           ("bits.process_path", "bits.process_path_key", "bits.process_id", "bits.owner", "bits.job_name", "bits.job_id"),
                           notes=(self.fold_caveat,), fold=(image,))


class RunMruDeletion(_Housekeeping):
    id = "win.run_mru_deletion"
    title = "Explorer RunMRU history was deleted"
    families = ("registry_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 12),)
    required_fields = ("registry.path_key",)
    attack = ("T1070",)
    severity = "low"

    def observe(self, event):
        target = _target(event)
        if (target is None or target.root != _CU or target.action != "deleted"
                or _software(target) != ("microsoft", "windows", "currentversion", "explorer", "runmru")):
            return []
        return self.report(event, "An Explorer RunMRU history key or value was deleted", _REG_FIELDS, low=True,
                           notes=("Routine history cleanup can produce this observation; intent is not established.",))


class HiddenFileAttribute(_FoldedHousekeeping):
    id = "win.hidden_file_attribute"
    version = "2"
    title = "The attrib utility was asked to set the hidden attribute"
    families = ("process_exec",)
    windows_event_classes = _PROCESS
    required_fields = ("process.executable", "process.command_line")
    reads_command_line = True
    attack = ("T1564.001",)
    severity = "low"
    research = ("https://learn.microsoft.com/windows-server/administration/windows-commands/attrib",)
    fold_caveat = "The command request does not establish that any file attribute changed."

    def observe(self, event):
        image = event.get("process.executable_key") or event.get("process.executable")
        if basename(image) != "attrib.exe" or "+h" not in _arguments(event)[1:]:
            return []
        return self.report(event, "A recorded attrib command requested the hidden file attribute", _PROC_FIELDS, low=True,
                           notes=(self.fold_caveat,), fold=(windows_path_key(image),))


class ExecutionPolicyRegistry(_Housekeeping):
    id = "win.execution_policy_registry"
    title = "A permissive PowerShell execution-policy value was written"
    families = ("registry_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 13),)
    required_fields = ("registry.path_key", "registry.value")
    attack = ("T1059.001",)
    severity = "low"
    research = ("https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies",)

    def observe(self, event):
        target = _target(event)
        if (target is None or target.root not in {_CU, _LM} or target.action != "written"
                or target.name != "executionpolicy" or event.get("registry.details_truncated") is True
                or str(event.get("registry.value")).strip().casefold() not in {"unrestricted", "bypass"}):
            return []
        if _software(target) not in {("microsoft", "powershell", "1", "shellids", "microsoft.powershell"),
                                     ("policies", "microsoft", "windows", "powershell")}:
            return []
        return self.report(event, "A PowerShell execution-policy registry value was written as Unrestricted or Bypass",
                           _REG_FIELDS, low=True,
                           notes=("Execution policy is not a security boundary; this write does not prove the effective policy or script execution.",))


class NewServerShare(_Housekeeping):
    id = "win.new_server_share"
    title = "A Windows server-share configuration value was written"
    families = ("registry_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 13),)
    required_fields = ("registry.path_key",)
    attack = ("T1135",)
    severity = "low"

    def observe(self, event):
        target = _target(event)
        if (target is None or target.action != "written" or not target.name
                or _system(target) != ("services", "lanmanserver", "shares")):
            return []
        return self.report(event, f"A LanmanServer share configuration value named '{self.describe(target.name)}' was written",
                           _REG_FIELDS, low=True,
                           notes=("The write may create or update a share; a newly active share or enumeration is not established.",))


class EventlogWerfault(_FoldedHousekeeping):
    id = "win.eventlog_werfault"
    version = "2"
    title = "WerFault was launched to report the EventLog service host"
    families = ("process_exec",)
    windows_event_classes = _PROCESS
    required_fields = ("process.executable", "process.command_line")
    reads_command_line = True
    attack = ("T1685.001",)
    severity = "low"
    research = ("https://learn.microsoft.com/windows/win32/wer/", _SYSMON_DOC)
    fold_caveat = "Error reporting is observed; a service failure may be accidental, and deliberate logging interference is not established."

    def observe(self, event):
        image = event.get("process.executable_key") or event.get("process.executable")
        parent = event.get("process.parent.executable_key") or event.get("process.parent.executable")
        if basename(image) != "werfault.exe" or basename(parent) != "svchost.exe":
            return []
        if _option_value(_arguments(event, "process.parent.command_line"), "-s") != "eventlog":
            return []
        reported = integer(_option_value(_arguments(event), "-p"))
        parent_pid = integer(event.get("process.ppid"))
        if not reported or reported != parent_pid:
            return []
        return self.report(event, "WerFault was launched with the recorded EventLog service-host parent PID as its report target",
                           _PROC_FIELDS, low=True,
                           notes=(self.fold_caveat,), fold=(windows_path_key(image),))


class WinrmShellStart(_Housekeeping):
    id = "win.winrm_shell_start"
    title = "WinRM recorded a server shell start"
    families = ("remote_access",)
    windows_event_classes = ((WINRM_CHANNEL, WINRM_PROVIDER, 91),)
    attack = ("T1021.006",)
    severity = "low"
    research = ("https://learn.microsoft.com/windows/win32/winrm/windows-remote-management",)

    def observe(self, event):
        return self.report(event, "WinRM recorded creation of a WSMan shell on the server",
                           ("remote.action", "remote.resource", "remote.connection_activity", "remote.user"), low=True,
                           notes=("A shell-start record does not establish unauthorized use or which commands ran.",))


RULES = (HiddenSamAccount, KerberosLoopbackLogon, UnexpectedPsRemoteServer, BitsLocalTransfer, BitsUnusualCreator,
         RunMruDeletion, HiddenFileAttribute, ExecutionPolicyRegistry, NewServerShare, EventlogWerfault, WinrmShellStart)
