"""Positive observations of WMI, named pipes, share access and Defender event records."""
from __future__ import annotations

import json
import re

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_events import WindowsEventRule, basename, components, integer, signal
from romulus.detect.windows_path_data import path_class
from romulus.evidence.typed import Outcome, TypedEvent
from romulus.evidence.windows_catalog import (
    DEFENDER_CHANNEL,
    DEFENDER_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    WMI_CHANNEL,
    WMI_PROVIDER,
)

_SYSMON_DOC = "https://learn.microsoft.com/sysinternals/downloads/sysmon"
_SHARE_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-5145"
_DEFENDER_DOC = "https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus"
_SECURITY_5145 = (("Security", SECURITY, 5145),)


def _description(event: TypedEvent, fields: tuple[str, ...]) -> str:
    return "; ".join(f"{name}={WindowsEventRule.describe(event.get(name))}" for name in fields if event.has(name))


def _content(event, fields):
    return json.dumps({"outcome": event.outcome, "fields": {name: event.get(name) for name in fields}},
                      sort_keys=True, separators=(",", ":"))


_SHARE_FIELDS = ("share.name", "share.relative_target", "share.access_mask", "share.accesses", "source.ip",
                 "user.name", "user.key", "user.sid", "user.domain")


def _account_class(event):
    name = event.get("user.name")
    return "machine account" if name and str(name).endswith("$") else "user account" if name else "unresolved account class"


_WRITE_ACCESS_NAMES = frozenset({"writedata", "addfile", "appenddata", "addsubdirectory",
    "writedataoraddfile", "appenddataoraddsubdirectoryorcreatepipeinstance", "%%4417", "%%4418"})
_READ_ACCESS_NAMES = frozenset({"readdata", "listdirectory", "readdataorlistdirectory", "readcontrol",
    "synchronize", "readextendedattributes", "readattributes", "execute", "traverse", "executeortraverse",
    "%%4416", "%%4419", "%%4421", "%%4423", "%%1538", "%%1541", "(or", "or", "listdirectory)"})


def _share_access_names(event):
    accesses = event.get("share.accesses")
    tokens = accesses if isinstance(accesses, list) else [str(accesses or "")]
    return {re.sub(r"[\s_()]+", "", str(token)).casefold() for token in tokens if token}


class WmiSubscription(WindowsEventRule):
    id = "win.wmi_subscription"
    version = "2"
    title = "WMI permanent-subscription component activity"
    families = ("wmi_subscription",)
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (19, 20, 21)) + (
        (WMI_CHANNEL, WMI_PROVIDER, 5861),)
    attack = ("T1546.003",)
    benign = ("management and monitoring products install permanent WMI subscriptions",)
    next_checks = ("inspect the filter, consumer and binding separately", "identify the registering user and process")
    research = (_SYSMON_DOC, "https://learn.microsoft.com/windows/win32/wmisdk/receiving-events-at-all-times")

    def judge(self, event):
        code = integer(event.get("event.code"))
        fields = ("wmi.operation", "wmi.namespace", "wmi.name", "wmi.query", "wmi.type", "wmi.destination",
                  "wmi.consumer", "wmi.filter", "wmi.binding", "wmi.user")
        if code not in {19, 20, 21, 5861}:
            return []
        component = {19: "filter activity", 20: "consumer activity", 21: "filter-to-consumer binding activity",
                     5861: "permanent-subscription activity"}[code]
        # Sysmon's documented consumer Type values are Script and CommandLine. Class names are also seen
        # in structured WMI records; only the typed consumer kind and a recorded destination raise the lane.
        scripted = str(event.get("wmi.type") or "").casefold() in {
            "script", "command line", "commandline", "activescripteventconsumer", "commandlineeventconsumer"}
        high = (code in {20, 5861} and scripted and bool(event.get("wmi.destination"))
                and str(event.get("wmi.operation") or "").casefold() not in {"deleted", "delete"})
        detail = _description(event, fields)
        text = f"WMI recorded {component}" + (f": {detail}" if detail else "; component fields were not recorded")
        return [signal(event, f"wmi_{code}", text, self.attack, fields,
                       lane="high" if high else "lead", severity="high" if high else "medium",
                       content=_content(event, fields),
                       notes=("A component record does not establish execution or a complete working subscription.",))]


def _pipe_name(value: object) -> str:
    """Remove only recognized pipe namespace prefixes; never turn an arbitrary path into a pipe basename."""
    name = str(value or "").casefold()
    for prefix in ("\\\\.\\pipe\\", "\\??\\pipe\\", "\\device\\namedpipe\\", "\\pipe\\", "\\"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name if "\\" not in name and "/" not in name else ""


# Each # in Cobalt Strike's documented default templates expands to one hexadecimal character.
_COBALT_PIPE = re.compile(r"(?:msse-(?:[0-9]{1,4}|[0-9a-f]{3})-server|status_[0-9a-f]{2}|msagent_[0-9a-f]{2}|"
                          r"postex_[0-9a-f]{4}|postex_ssh_[0-9a-f]{4})")
_REMCOM_STREAM = re.compile(r"remcom_(?:stdin|stdout|stderr)[a-z]{4}[0-9]+")
_PSEXEC_STREAM = re.compile(r"psexesvc-[^\\/]+-[0-9]+-(?:stdin|stdout|stderr)")
_PAEXEC_PIPE = re.compile(r"paexec-[0-9]+-[^\\/]+(?:\.exe)?|paexec(?:in|out|err)[^\\/]+[0-9]+")


class ToolNamedPipe(WindowsEventRule):
    id = "win.tool_named_pipe"
    version = "2"
    title = "Named pipe matches a documented remote-tool default"
    families = ("pipe_event",)
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (17, 18))
    attack = ("T1021.002",)
    benign = ("authorized PsExec, Impacket or red-team use", "any process can choose these pipe names")
    next_checks = ("inspect the process creating or connecting to the pipe", "review remote service and SMB activity")
    research = (_SYSMON_DOC,
                "https://www.cobaltstrike.com/blog/learn-pipe-fitting-for-all-of-your-offense-projects",
                "https://blog.nviso.eu/2021/04/26/anatomy-of-cobalt-strike-dll-stagers/",
                "https://github.com/fortra/impacket/blob/master/examples/psexec.py",
                "https://github.com/poweradminllc/PAExec/blob/master/Remote.cpp",
                "https://github.com/poweradminllc/PAExec/blob/master/ConsoleRedir.cpp",
                "https://www.microsoft.com/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/")

    def judge(self, event):
        if integer(event.get("event.code")) not in {17, 18}:
            return []
        name = _pipe_name(event.get("pipe.name"))
        tool = ("PsExec" if name == "psexesvc" or _PSEXEC_STREAM.fullmatch(name) else
                "PAExec" if _PAEXEC_PIPE.fullmatch(name) else
                "Impacket RemCom" if name == "remcom_communicaton" or _REMCOM_STREAM.fullmatch(name) else
                "Cobalt Strike" if _COBALT_PIPE.fullmatch(name) else "")
        if not tool:
            return []
        # Template identity excludes random characters and embedded process IDs.
        if tool == "PsExec":
            template = name.rsplit("-", 1)[-1] if _PSEXEC_STREAM.fullmatch(name) else "control"
        elif tool == "Impacket RemCom":
            template = next((stream for stream in ("stdin", "stdout", "stderr") if name.startswith("remcom_" + stream)), "control")
        elif tool == "PAExec":
            template = next((stream for stream in ("in", "out", "err") if name.startswith("paexec" + stream)), "control")
        else:
            template = "msse-#-server" if name.startswith("msse-") else re.sub(r"[0-9a-f]{2,4}$", "#", name)
        return [signal(event, "tool_pipe", f"Named pipe {self.describe(event.get('pipe.name'))} matched a "
                       f"documented {tool} default name", self.attack, ("pipe.name", "pipe.action", "process.executable"),
                       content=json.dumps([tool, template, event.get("pipe.action"), event.get("process.executable")]),
                       common=f"Named pipes matched the documented {tool} default template {template}",
                       notes=("Pipe names are attacker-controllable; the name alone does not establish tool identity.",))]


def _share(event: TypedEvent) -> str:
    parts = components(event.get("share.name"))
    return parts[-1] if parts else ""


class AdminShareTransfer(WindowsEventRule):
    id = "win.admin_share_transfer"
    version = "3"
    title = "Write or unresolved access to a file through an administrative share"
    families = ("share_access",)
    windows_event_classes = _SECURITY_5145
    attack = ("T1021.002", "T1570")
    benign = ("software deployment and remote administration copy programs through administrative shares",)
    next_checks = ("find the resulting file and its hashes", "look for service, task or process execution of the file")
    research = (_SHARE_DOC, "https://attack.mitre.org/techniques/T1570/",
                "https://learn.microsoft.com/troubleshoot/windows-server/networking/remove-administrative-shares")

    def judge(self, event):
        share = _share(event)
        if integer(event.get("event.code")) != 5145 or not (share == "admin$" or re.fullmatch(r"[a-z]\$", share)):
            return []
        path = str(event.get("share.relative_target") or "")
        if not path:
            return []
        mask = integer(event.get("share.access_mask"))
        tokens = _share_access_names(event)
        writes = bool(tokens & _WRITE_ACCESS_NAMES)
        if mask is not None and not mask & 0x6 and not writes:
            return []
        if mask is None and tokens and tokens <= _READ_ACCESS_NAMES:
            return []
        qualifier = "write/append access" if writes or (mask is not None and mask & 0x6) else "access with unresolved rights"
        text = (f"Administrative share access check recorded {qualifier} for file "
                f"{self.describe(path)} on {self.describe(event.get('share.name'))}")
        if event.outcome == Outcome.failure:
            text += "; the access check failed"
        else:
            text += "; this is a transfer lead, and does not establish a completed file write"
        return [signal(event, "admin_share_write", text, self.attack,
                       (*_SHARE_FIELDS, "share.session_id"), content=_content(event, _SHARE_FIELDS))]


class RemoteManagementPipe(BehaviorFleetRule):
    id = "win.remote_management_pipe"
    version = "3"
    count_source_ips = True
    title = "IPC share access to a management RPC pipe"
    families = ("share_access",)
    windows_event_classes = _SECURITY_5145
    attack = ("T1021.002",)
    benign = ("normal Windows administration, account lookup and domain replication use these pipes",)
    next_checks = ("review the source account and host", "correlate service, task and directory access records")
    research = (_SHARE_DOC, "https://github.com/fortra/impacket/blob/master/examples/psexec.py")

    def judge(self, event):
        if integer(event.get("event.code")) != 5145 or _share(event) != "ipc$":
            return []
        name = _pipe_name(event.get("share.relative_target"))
        if name not in {"svcctl", "atsvc", "samr", "lsarpc", "drsuapi"}:
            return []
        mask = integer(event.get("share.access_mask"))
        if name in {"samr", "lsarpc"} and mask is not None and not mask & 0x6 and event.outcome != Outcome.failure:
            return []
        text = f"IPC$ access check named the {name} management RPC pipe"
        if event.outcome == Outcome.failure:
            text += "; the access check failed"
        account = _account_class(event)
        return [signal(event, "management_pipe", text, self.attack,
                       (*_SHARE_FIELDS, "share.session_id"), content=json.dumps([name, event.outcome, account]),
                       common=f"IPC$ access checks named the {name} management RPC pipe by {account}s with recorded outcome {event.outcome}",
                       notes=("Pipe access alone does not establish service execution or credential extraction.",))]


class GppPolicyFileAccess(BehaviorFleetRule):
    id = "win.gpp_policy_file_access"
    version = "3"
    count_source_ips = True
    title = "SYSVOL access names a Group Policy Preferences policy file"
    families = ("share_access",)
    windows_event_classes = _SECURITY_5145
    attack = ("T1552.006",)
    benign = ("Group Policy clients and administrators routinely access these policy files",)
    next_checks = ("inspect the policy file for credential-bearing fields", "review the accessing account and host")
    research = (_SHARE_DOC, "https://learn.microsoft.com/security-updates/securitybulletins/2014/ms14-025")

    def judge(self, event):
        if integer(event.get("event.code")) != 5145 or _share(event) != "sysvol":
            return []
        path = event.get("share.relative_target")
        if basename(path) not in {"groups.xml", "services.xml", "scheduledtasks.xml", "datasources.xml",
                                  "printers.xml", "drives.xml"}:
            return []
        parts = components(path)
        if not any(parts[i] == "policies" and len(parts[i:]) >= 6 and parts[i + 2] in {"machine", "user"}
                   and parts[i + 3] == "preferences" for i in range(len(parts))):
            return []
        text = f"SYSVOL access check named Group Policy Preferences file {self.describe(path)}"
        if event.outcome == Outcome.failure:
            text += "; the access check failed"
        account = _account_class(event)
        return [signal(event, "gpp_file", text, self.attack,
                       (*_SHARE_FIELDS, "share.session_id"), content=json.dumps([path_class(path), event.outcome, account]),
                       common=f"SYSVOL access checks named the same Group Policy Preferences file path class by {account}s with recorded outcome {event.outcome}",
                       notes=("The access record does not show file contents or whether credentials were present.",))]


class DefenderThreat(WindowsEventRule):
    id = "win.defender_threat"
    version = "2"
    title = "Defender recorded a threat detection or remediation result"
    families = ("defender_event",)
    windows_event_classes = tuple((DEFENDER_CHANNEL, DEFENDER_PROVIDER, code)
                                  for code in (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119))
    attack = ("T1204.002",)
    severity, lane = "high", "high"
    benign = ("antivirus false positives and approved security testing",)
    next_checks = ("inspect the threat name, path and process", "verify the remediation result and rescan")
    research = (_DEFENDER_DOC,)

    def judge(self, event):
        code = integer(event.get("event.code"))
        action = {1006: "detected a threat", 1007: "recorded an action on a detected threat",
                  1008: "recorded failed threat remediation", 1015: "detected suspicious behavior",
                  1116: "detected a threat", 1117: "recorded an action on a detected threat",
                  1118: "recorded a non-critical threat-remediation error",
                  1119: "recorded a critical threat-remediation error"}.get(code)
        if not action:
            return []
        fields = ("defender.threat.name", "defender.threat.id", "defender.severity", "defender.category", "defender.path", "defender.process",
                  "defender.recorded_action", "defender.error_code", "defender.error_description")
        detail = _description(event, fields)
        low = str(event.get("defender.severity") or "").casefold() in {"low", "informational", "1"}
        return [signal(event, f"defender_{code}", f"Defender {action}" + (f": {detail}" if detail else ""),
                       self.attack, fields, lane="lead" if low else "high", severity="low" if low else "high",
                       content=_content(event, fields),
                       notes=("An action record does not establish eradication or that the threat executed.",))]


_DISABLE_PATHS = frozenset({
    ("disableantispyware",), ("disableantivirus",),
    *(("real-time protection", name) for name in (
        "disablerealtimemonitoring", "disablebehaviormonitoring", "disableioavprotection",
        "disableonaccessprotection", "disablescriptscanning")),
    ("spynet", "disableblockatfirstseen"),
})
_DEFENDER_ROOTS = (
    ("hklm", "software", "microsoft", "windows defender"),
    ("hklm", "software", "policies", "microsoft", "windows defender"),
    ("hkey_local_machine", "software", "microsoft", "windows defender"),
    ("hkey_local_machine", "software", "policies", "microsoft", "windows defender"),
)


def _setting(value: object) -> tuple[tuple[str, ...], str] | None:
    if not isinstance(value, str) or "=" not in value:
        return None
    key, data = value.rsplit("=", 1)
    path = components(key.strip())
    for root in _DEFENDER_ROOTS:
        if path[:len(root)] == root and len(path) > len(root):
            return path[len(root):], data.strip()
    return None


def _dword(value: str) -> int | None:
    """Accept a bounded unsigned DWORD spelling, without Python's signs or numeric separators."""
    text = value.casefold()
    if text.startswith("dword (") and text.endswith(")"):
        text = text[7:-1]
    if not re.fullmatch(r"(?:0x[0-9a-f]{1,8}|[0-9]{1,10})", text):
        return None
    number = int(text, 16 if text.startswith("0x") else 10)
    return number if number <= 0xFFFFFFFF else None


class DefenderProtection(WindowsEventRule):
    id = "win.defender_protection"
    version = "2"
    title = "Defender protection state or configuration change"
    families = ("defender_event",)
    windows_event_classes = tuple((DEFENDER_CHANNEL, DEFENDER_PROVIDER, code)
                                  for code in (5001, 5004, 5007, 5010, 5012, 5013))
    attack = ("T1685",)
    benign = ("approved policy changes, maintenance, exclusions and blocked administrative changes",)
    next_checks = ("validate the old/new setting against policy", "identify the initiating account and process")
    research = (_DEFENDER_DOC, "https://learn.microsoft.com/powershell/module/defender/set-mppreference")

    def judge(self, event):
        code = integer(event.get("event.code"))
        fields = ("defender.old_value", "defender.new_value", "defender.process", "defender.user")
        direct = {5001: "Defender recorded real-time protection disabled",
                  5010: "Defender recorded malware and potentially unwanted software scanning disabled",
                  5012: "Defender recorded virus scanning disabled",
                  5013: "Defender tamper protection blocked a settings change"}
        if code in direct:
            return [signal(event, f"defender_{code}", direct[code], self.attack, fields,
                           lane="high", severity="high", content=_content(event, fields))]
        if code not in {5004, 5007}:
            return []
        new, old = _setting(event.get("defender.new_value")), _setting(event.get("defender.old_value"))
        unsafe, safe = "", ""
        if code == 5007 and new:
            path, data = new
            number = _dword(data)
            if path in _DISABLE_PATHS and number == 1:
                unsafe = "a known protection-disable value was set to 1"
            elif path in _DISABLE_PATHS and number == 0:
                restored = old is not None and old[0] == path and _dword(old[1]) == 1
                verb = "was restored to" if restored else "changed to"
                safe = f"a known protection setting {verb} its safe zero value"
            elif (len(path) >= 3 and path[0] == "exclusions"
                  and path[1] in {"paths", "processes", "extensions", "ipaddresses"}
                  and data and number == 0 and (old is None or old != new)):
                unsafe = "an exclusion entry was recorded with its enabled value"
        detail = _description(event, fields)
        effect = unsafe or safe
        text = "Defender configuration changed" + (f": {effect}" if effect else "; setting effect is unknown")
        if detail:
            text += f"; {detail}"
        return [signal(event, f"defender_{code}", text, self.attack, fields,
                       lane="high" if unsafe else "lead", severity="high" if unsafe else "medium",
                       content=_content(event, fields))]


WINDOWS_ENDPOINT_PLAYBOOKS = (WmiSubscription, ToolNamedPipe, AdminShareTransfer, RemoteManagementPipe,
                              GppPolicyFileAccess, DefenderThreat, DefenderProtection)
