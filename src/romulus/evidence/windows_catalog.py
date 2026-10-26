"""Authoritative Windows event classes keyed by channel, provider, and event id."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WindowsEventClass:
    channel: str
    provider: str
    event_id: int
    family: str
    name: str
    documentation_url: str

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.channel.casefold(), self.provider.casefold(), self.event_id)

    @property
    def token(self) -> str:
        return f"{self.channel}|{self.provider}|{self.event_id}".casefold()


SECURITY = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"
SYSMON = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
TASK_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
TASK_PROVIDER = "Microsoft-Windows-TaskScheduler"
WMI_CHANNEL = "Microsoft-Windows-WMI-Activity/Operational"
WMI_PROVIDER = "Microsoft-Windows-WMI-Activity"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_PROVIDER = "Microsoft-Windows-PowerShell"
LEGACY_POWERSHELL_CHANNEL = "Windows PowerShell"
LEGACY_POWERSHELL_PROVIDER = "PowerShell"
DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender"
RDP_RCM_CHANNEL = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
RDP_RCM_PROVIDER = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
RDP_LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP_LSM_PROVIDER = "Microsoft-Windows-TerminalServices-LocalSessionManager"
WINRM_CHANNEL = "Microsoft-Windows-WinRM/Operational"
WINRM_PROVIDER = "Microsoft-Windows-WinRM"
BITS_CHANNEL = "Microsoft-Windows-Bits-Client/Operational"
BITS_PROVIDER = "Microsoft-Windows-Bits-Client"

def _security(event_id: int, family: str, name: str) -> WindowsEventClass:
    return WindowsEventClass(
        "Security",
        SECURITY,
        event_id,
        family,
        name,
        f"https://learn.microsoft.com/windows/security/threat-protection/auditing/event-{event_id}",
    )


def _security_eventlog(event_id: int, family: str, name: str) -> WindowsEventClass:
    return WindowsEventClass(
        "Security",
        EVENTLOG,
        event_id,
        family,
        name,
        f"https://learn.microsoft.com/windows/security/threat-protection/auditing/event-{event_id}",
    )


def _sysmon(event_id: int, family: str, name: str) -> WindowsEventClass:
    return WindowsEventClass(
        SYSMON_CHANNEL,
        SYSMON,
        event_id,
        family,
        name,
        f"https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-{event_id}",
    )


def _system(provider: str, event_id: int, family: str, name: str, documentation: str) -> WindowsEventClass:
    return WindowsEventClass(
        "System",
        provider,
        event_id,
        family,
        name,
        f"{documentation}#event-id-{event_id}",
    )


def _operational(
    channel: str,
    provider: str,
    event_id: int,
    family: str,
    name: str,
    documentation: str,
) -> WindowsEventClass:
    return WindowsEventClass(
        channel,
        provider,
        event_id,
        family,
        name,
        f"{documentation}#event-id-{event_id}",
    )


_SYSTEM_EVENT_DOCS = (
    "https://learn.microsoft.com/troubleshoot/windows-server/performance/"
    "troubleshoot-unexpected-reboots-system-event-logs"
)
_SERVICE_DOCS = (
    "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/"
    "services-and-service-accounts-security-planning"
)
_TASK_DOCS = "https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-events-and-errors"
_WMI_DOCS = "https://learn.microsoft.com/windows/win32/wmisdk/tracing-wmi-activity"
_POWERSHELL_DOCS = (
    "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows"
)
_DEFENDER_DOCS = (
    "https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus"
)
_RDP_DOCS = (
    "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/"
    "rds-rdsh-audit-events"
)
_WINRM_DOCS = (
    "https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management"
)
_BITS_DOCS = "https://learn.microsoft.com/windows/win32/bits/bits-logging"


EVENT_CLASSES = (
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
    _security(4688, "process_exec", "process created"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4689
    _security(4689, "process_termination", "process terminated"),
    # https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-1-process-creation
    _sysmon(1, "process_exec", "process created"),
    # https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-3-network-connection
    _sysmon(3, "net_socket", "network connection"),
    # https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-5-process-terminated
    _sysmon(5, "process_termination", "process terminated"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
    _security(4624, "auth", "logon succeeded"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
    _security(4625, "auth", "logon failed"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4648
    _security(4648, "auth", "explicit credentials used"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4672
    _security(4672, "auth", "special privileges assigned"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4634
    _security(4634, "auth", "logoff completed"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4647
    _security(4647, "auth", "user initiated logoff"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4720
    _security(4720, "account_change", "account created"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4722
    _security(4722, "account_change", "account enabled"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4724
    _security(4724, "account_change", "password reset attempted"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4726
    _security(4726, "account_change", "account deleted"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4728
    _security(4728, "account_change", "member added to global group"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4732
    _security(4732, "account_change", "member added to local group"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4756
    _security(4756, "account_change", "member added to universal group"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4738
    _security(4738, "account_change", "account changed"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
    _security(4740, "account_change", "account locked out"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4697
    _security(4697, "service_change", "service installed"),
    # https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    _system("Service Control Manager", 7045, "service_change", "service installed", _SERVICE_DOCS),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4698
    _security(4698, "scheduled_task", "scheduled task created"),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4702
    _security(4702, "scheduled_task", "scheduled task updated"),
    # https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
    _security_eventlog(1102, "audit_config", "security log cleared"),
    # https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
    _system("Microsoft-Windows-Eventlog", 104, "audit_config", "event log cleared", _SYSTEM_EVENT_DOCS),
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4719
    _security(4719, "audit_config", "audit policy changed"),
    # https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    _system(
        "Microsoft-Windows-Kernel-General",
        12,
        "system_state",
        "operating system started",
        _SYSTEM_EVENT_DOCS,
    ),
    # https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    _system(
        "Microsoft-Windows-Kernel-General",
        13,
        "system_state",
        "operating system stopped",
        _SYSTEM_EVENT_DOCS,
    ),
    # https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    _system("EventLog", 6005, "system_state", "event log service started", _SYSTEM_EVENT_DOCS),
    # https://learn.microsoft.com/answers/questions/3864277/when-are-windows-events-6006-and-6005-logged-apart
    _system("EventLog", 6006, "system_state", "event log service stopped", _SYSTEM_EVENT_DOCS),
    _security(4768, "auth", "Kerberos ticket-granting ticket requested"),
    _security(4769, "auth", "Kerberos service ticket requested"),
    _security(4770, "auth", "Kerberos service ticket renewed"),
    _security(4771, "auth", "Kerberos pre-authentication failed"),
    _security(4776, "auth", "credentials validated"),
    _security(4778, "auth", "session reconnected"),
    _security(4779, "auth", "session disconnected"),
    _security(4964, "auth", "special groups assigned to a logon"),
    _security(4704, "account_change", "user right assigned"),
    _security(4705, "account_change", "user right removed"),
    _security(4725, "account_change", "account disabled"),
    _security(4729, "account_change", "member removed from global group"),
    _security(4733, "account_change", "member removed from local group"),
    _security(4741, "account_change", "computer account created"),
    _security(4742, "account_change", "computer account changed"),
    _security(4743, "account_change", "computer account deleted"),
    _security(4757, "account_change", "member removed from universal group"),
    _security(4765, "account_change", "SID history added"),
    _security(4766, "account_change", "SID history addition failed"),
    _security(4767, "account_change", "account unlocked"),
    _security(4781, "account_change", "account renamed"),
    _security(4794, "account_change", "directory services restore mode password set attempted"),
    _system("Service Control Manager", 7040, "service_change", "service start type changed", _SERVICE_DOCS),
    _security(4699, "scheduled_task", "scheduled task deleted"),
    _security(4700, "scheduled_task", "scheduled task enabled"),
    _security(4701, "scheduled_task", "scheduled task disabled"),
    _operational(TASK_CHANNEL, TASK_PROVIDER, 106, "scheduled_task", "task registered", _TASK_DOCS),
    _operational(TASK_CHANNEL, TASK_PROVIDER, 129, "scheduled_task", "task process created", _TASK_DOCS),
    _operational(TASK_CHANNEL, TASK_PROVIDER, 140, "scheduled_task", "task updated", _TASK_DOCS),
    _operational(TASK_CHANNEL, TASK_PROVIDER, 141, "scheduled_task", "task deleted", _TASK_DOCS),
    _operational(TASK_CHANNEL, TASK_PROVIDER, 200, "scheduled_task", "task action started", _TASK_DOCS),
    _operational(TASK_CHANNEL, TASK_PROVIDER, 201, "scheduled_task", "task action completed", _TASK_DOCS),
    _sysmon(2, "file_change", "file creation time changed"),
    _sysmon(11, "file_change", "file created"),
    _sysmon(15, "file_change", "file stream created"),
    _sysmon(23, "file_change", "file deleted and archived"),
    _sysmon(26, "file_change", "file delete detected"),
    _sysmon(10, "process_access", "process accessed"),
    _sysmon(6, "image_load", "driver loaded"),
    _sysmon(7, "image_load", "image loaded"),
    _sysmon(8, "remote_thread", "remote thread created"),
    _sysmon(25, "process_tampering", "process image changed"),
    _sysmon(12, "registry_change", "registry object created or deleted"),
    _sysmon(13, "registry_change", "registry value set"),
    _sysmon(14, "registry_change", "registry object renamed"),
    _security(4657, "registry_change", "registry value modified"),
    _security(4656, "object_access", "object handle requested"),
    _security(4663, "object_access", "object accessed"),
    _security(4670, "object_access", "object permissions changed"),
    _sysmon(17, "pipe_event", "named pipe created"),
    _sysmon(18, "pipe_event", "named pipe connected"),
    _sysmon(19, "wmi_subscription", "WMI event filter activity"),
    _sysmon(20, "wmi_subscription", "WMI event consumer activity"),
    _sysmon(21, "wmi_subscription", "WMI consumer binding activity"),
    _operational(
        WMI_CHANNEL,
        WMI_PROVIDER,
        5861,
        "wmi_subscription",
        "WMI subscription registered",
        _WMI_DOCS,
    ),
    _sysmon(22, "dns_lookup", "DNS query"),
    _operational(
        POWERSHELL_CHANNEL,
        POWERSHELL_PROVIDER,
        4103,
        "script_block",
        "PowerShell module logged",
        _POWERSHELL_DOCS,
    ),
    _operational(
        POWERSHELL_CHANNEL,
        POWERSHELL_PROVIDER,
        4104,
        "script_block",
        "PowerShell script block logged",
        _POWERSHELL_DOCS,
    ),
    _operational(
        LEGACY_POWERSHELL_CHANNEL,
        LEGACY_POWERSHELL_PROVIDER,
        400,
        "script_block",
        "PowerShell engine started",
        _POWERSHELL_DOCS,
    ),
    _operational(
        LEGACY_POWERSHELL_CHANNEL,
        LEGACY_POWERSHELL_PROVIDER,
        403,
        "script_block",
        "PowerShell engine stopped",
        _POWERSHELL_DOCS,
    ),
    _operational(
        LEGACY_POWERSHELL_CHANNEL,
        LEGACY_POWERSHELL_PROVIDER,
        800,
        "script_block",
        "PowerShell pipeline executed",
        _POWERSHELL_DOCS,
    ),
    _security(4662, "directory_access", "directory service object operation"),
    _security(5136, "directory_change", "directory service object modified"),
    _security(5137, "directory_change", "directory service object created"),
    _security(5138, "directory_change", "directory service object undeleted"),
    _security(5139, "directory_change", "directory service object moved"),
    _security(5141, "directory_change", "directory service object deleted"),
    _security(5140, "share_access", "network share accessed"),
    _security(5145, "share_access", "network share object checked"),
    *(
        _operational(DEFENDER_CHANNEL, DEFENDER_PROVIDER, event_id, "defender_event", name, _DEFENDER_DOCS)
        for event_id, name in (
            (1006, "malware detected"),
            (1007, "malware action taken"),
            (1008, "malware action failed"),
            (1015, "suspicious behavior detected"),
            (1116, "threat detected"),
            (1117, "threat action taken"),
            (1118, "threat action non-critical error"),
            (1119, "threat action critical error"),
            (5001, "real-time protection disabled"),
            (5004, "real-time protection configuration changed"),
            (5007, "configuration changed"),
            (5010, "malware scanning disabled"),
            (5012, "virus scanning disabled"),
            (5013, "tamper protection blocked a change"),
        )
    ),
    _operational(
        RDP_RCM_CHANNEL,
        RDP_RCM_PROVIDER,
        1149,
        "remote_access",
        "remote logon authenticated",
        _RDP_DOCS,
    ),
    *(
        _operational(RDP_LSM_CHANNEL, RDP_LSM_PROVIDER, event_id, "remote_access", name, _RDP_DOCS)
        for event_id, name in (
            (21, "remote session logon succeeded"),
            (22, "remote session shell started"),
            (24, "remote session disconnected"),
            (25, "remote session reconnected"),
        )
    ),
    _operational(WINRM_CHANNEL, WINRM_PROVIDER, 6, "remote_access", "WinRM activity started", _WINRM_DOCS),
    _operational(WINRM_CHANNEL, WINRM_PROVIDER, 91, "remote_access", "WinRM connection received", _WINRM_DOCS),
    _operational(BITS_CHANNEL, BITS_PROVIDER, 3, "remote_access", "BITS job created", _BITS_DOCS),
    _operational(BITS_CHANNEL, BITS_PROVIDER, 59, "remote_access", "BITS transfer started", _BITS_DOCS),
    _operational(BITS_CHANNEL, BITS_PROVIDER, 60, "remote_access", "BITS transfer completed", _BITS_DOCS),
    _security_eventlog(1100, "audit_config", "event logging service shut down"),
    _security_eventlog(1104, "audit_config", "security log full"),
    _security_eventlog(1108, "audit_config", "event logging error"),
    _sysmon(4, "audit_config", "Sysmon service state changed"),
    _sysmon(16, "audit_config", "Sysmon configuration changed"),
    _sysmon(255, "audit_config", "Sysmon error"),
)

_BY_KEY = {event_class.key: event_class for event_class in EVENT_CLASSES}
if len(_BY_KEY) != len(EVENT_CLASSES):  # pragma: no cover - import-time catalog invariant
    raise RuntimeError("duplicate Windows event class")

# Native events that end a clean collection interval. Event 4 is a break only when its State is not Started;
# callers retain that field-level condition while this table remains the single list of governing triples.
COLLECTION_CHANGE_EVENTS = {
    ("security", SECURITY.casefold(), 4719): "audit policy changed",
    ("security", EVENTLOG.casefold(), 1100): "event log service shut down",
    ("security", EVENTLOG.casefold(), 1102): "security log cleared",
    ("security", EVENTLOG.casefold(), 1104): "security log full",
    ("security", EVENTLOG.casefold(), 1108): "event logging error",
    ("system", EVENTLOG.casefold(), 104): "event log cleared",
    ("system", "eventlog", 6006): "event log service stopped",
    (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 4): "Sysmon service state changed",
    (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 16): "Sysmon configuration changed",
    (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 255): "Sysmon error",
}

WINDOWS_DATASETS = frozenset(
    {
        "system.security",
        "system.system",
        "windows.forwarded",
        "windows.powershell",
        "windows.powershell_operational",
        "windows.security",
        "windows.sysmon_operational",
        "windows.system",
        "windows.windows_defender",
        "winlog.winlog",
    }
)
WINDOWS_HOST_DATASETS = (
    "windows.sysmon_operational",
    "system.security",
    "windows.security",
    "system.system",
    "windows.system",
    "windows.powershell_operational",
    "windows.powershell",
    "windows.windows_defender",
    "winlog.winlog",
    "windows.forwarded",
)
WINDOWS_CHANNELS = tuple(dict.fromkeys(event.channel for event in EVENT_CLASSES))


def _families_for_channel(channel: str) -> frozenset[str]:
    wanted = channel.casefold()
    return frozenset(event.family for event in EVENT_CLASSES if event.channel.casefold() == wanted)


_SECURITY_FAMILIES = _families_for_channel("Security")
_SYSMON_FAMILIES = _families_for_channel(SYSMON_CHANNEL)
_SYSTEM_FAMILIES = _families_for_channel("System")
_POWERSHELL_FAMILIES = _families_for_channel(POWERSHELL_CHANNEL)
_LEGACY_POWERSHELL_FAMILIES = _families_for_channel(LEGACY_POWERSHELL_CHANNEL)
_DEFENDER_FAMILIES = _families_for_channel(DEFENDER_CHANNEL)
_ALL_FAMILIES = frozenset(event.family for event in EVENT_CLASSES)

WINDOWS_DATASET_FAMILIES = {
    "windows.sysmon_operational": _SYSMON_FAMILIES,
    "system.security": _SECURITY_FAMILIES,
    "windows.security": _SECURITY_FAMILIES,
    "system.system": _SYSTEM_FAMILIES,
    "windows.system": _SYSTEM_FAMILIES,
    "windows.powershell_operational": _POWERSHELL_FAMILIES,
    "windows.powershell": _LEGACY_POWERSHELL_FAMILIES,
    "windows.windows_defender": _DEFENDER_FAMILIES,
    "winlog.winlog": _ALL_FAMILIES,
    "windows.forwarded": _ALL_FAMILIES,
}


def datasets_for_families(families: set[str] | frozenset[str]) -> tuple[str, ...]:
    return tuple(
        dataset for dataset in WINDOWS_HOST_DATASETS
        if WINDOWS_DATASET_FAMILIES.get(dataset, frozenset()).intersection(families)
    )


def channels_for_families(families: set[str] | frozenset[str]) -> tuple[str, ...]:
    selected = {event.channel for event in EVENT_CLASSES if event.family in families}
    return tuple(channel for channel in WINDOWS_CHANNELS if channel in selected)


def event_classes_for_families(families: set[str] | frozenset[str]) -> tuple[WindowsEventClass, ...]:
    return tuple(event for event in EVENT_CLASSES if event.family in families)


_SECURITY_AUDIT: dict[int, tuple[tuple[str, str], ...]] = {
    4688: (("Process Creation", "success"),),
    4689: (("Process Termination", "success"),),
    **{event_id: (("Logon", "success"),) for event_id in (4624, 4648)},
    4625: (("Logon", "failure"),),
    **{event_id: (("Logoff", "success"),) for event_id in (4634, 4647)},
    **{event_id: (("Special Logon", "success"),) for event_id in (4672, 4964)},
    4768: (
        ("Kerberos Authentication Service", "success"),
        ("Kerberos Authentication Service", "failure"),
    ),
    4770: (("Kerberos Service Ticket Operations", "success"),),
    4771: (("Kerberos Authentication Service", "failure"),),
    4769: (
        ("Kerberos Service Ticket Operations", "success"),
        ("Kerberos Service Ticket Operations", "failure"),
    ),
    4776: (("Credential Validation", "success"), ("Credential Validation", "failure")),
    **{event_id: (("Other Logon/Logoff Events", "success"),) for event_id in (4778, 4779)},
    **{event_id: (("Authorization Policy Change", "success"),) for event_id in (4704, 4705)},
    **{
        event_id: (("User Account Management", "success"),)
        for event_id in (4720, 4722, 4725, 4726, 4738, 4740, 4765, 4767, 4781)
    },
    4724: (
        ("User Account Management", "success"),
        ("User Account Management", "failure"),
    ),
    4794: (
        ("User Account Management", "success"),
        ("User Account Management", "failure"),
    ),
    4766: (("User Account Management", "failure"),),
    **{
        event_id: (("Security Group Management", "success"),)
        for event_id in (4728, 4729, 4732, 4733, 4756, 4757)
    },
    **{
        event_id: (("Computer Account Management", "success"),)
        for event_id in (4741, 4742, 4743)
    },
    4697: (("Security System Extension", "success"),),
    **{
        event_id: (("Other Object Access Events", "success"),)
        for event_id in (4698, 4699, 4700, 4701, 4702)
    },
    4657: (("Registry", "success"),),
    4656: tuple(
        (subcategory, outcome)
        for subcategory in ("File System", "Kernel Object", "Registry", "Removable Storage")
        for outcome in ("success", "failure")
    ),
    4663: tuple(
        (subcategory, "success")
        for subcategory in ("File System", "Kernel Object", "Registry", "Removable Storage")
    ),
    4670: tuple(
        (subcategory, "success")
        for subcategory in (
            "File System",
            "Registry",
            "Authentication Policy Change",
            "Authorization Policy Change",
        )
    ),
    4662: (
        ("Directory Service Access", "success"),
        ("Directory Service Access", "failure"),
    ),
    **{
        event_id: (("Directory Service Changes", "success"),)
        for event_id in (5136, 5137, 5138, 5139, 5141)
    },
    5140: (("File Share", "success"),),
    5145: (
        ("Detailed File Share", "success"),
        ("Detailed File Share", "failure"),
    ),
    4719: (("Audit Policy Change", "success"),),
}
_OBJECT_ACCESS_SACL_EVENTS = frozenset({4656, 4657, 4663, 4670})
_DIRECTORY_SERVICE_SACL_EVENTS = frozenset({4662, 5136, 5137, 5138, 5139, 5141})


def _channel_requirement(event: WindowsEventClass) -> tuple[str, dict, str]:
    return (
        "event_channel",
        {"channel": event.channel},
        f"event channel {event.channel}",
    )


def collection_requirements(event: WindowsEventClass) -> tuple[tuple[str, dict, str], ...]:
    """Site facts required before absence of this event class can support a negative."""
    requirements: list[tuple[str, dict, str]] = []
    if event.provider.casefold() == SYSMON.casefold():
        requirements.append(("sysmon", {"event_id": event.event_id}, f"Sysmon event id {event.event_id}"))
    if (
        event.channel.casefold() == POWERSHELL_CHANNEL.casefold()
        and event.provider.casefold() == POWERSHELL_PROVIDER.casefold()
    ):
        if event.event_id == 4103:
            requirements.append(("powershell_module_logging", {}, "PowerShell module logging"))
        elif event.event_id == 4104:
            requirements.append(("powershell_script_block", {}, "PowerShell script-block logging"))
    if (
        event.channel.casefold().endswith("/operational")
        and event.provider.casefold() != SYSMON.casefold()
    ):
        requirements.append(_channel_requirement(event))
    if requirements:
        return tuple(requirements)

    if event.provider.casefold() == SECURITY.casefold():
        audit = _SECURITY_AUDIT.get(event.event_id)
        if audit is not None:
            requirements.extend(
                (
                    "audit_policy",
                    {"subcategory": subcategory, "outcome": outcome},
                    f"audit policy {subcategory} {outcome}",
                )
                for subcategory, outcome in audit
            )
            if event.event_id == 4688:
                requirements.append(
                    ("security_4688_command_line", {}, "Security 4688 command-line inclusion")
                )
            if event.event_id in _OBJECT_ACCESS_SACL_EVENTS:
                requirements.append(
                    (
                        "object_access_sacl",
                        {},
                        f"scoped SACL for Security {event.event_id} object or registry access",
                    )
                )
            elif event.event_id in _DIRECTORY_SERVICE_SACL_EVENTS:
                requirements.append(
                    (
                        "directory_service_sacl",
                        {},
                        f"scoped SACL for Security {event.event_id} directory service access or change",
                    )
                )
            return tuple(requirements)
        return (("security_event_log", {}, "Windows Security event log"),)

    if event.channel.casefold() == "security":
        return (("security_event_log", {}, "Windows Security event log"),)
    if event.channel.casefold() == "system":
        return (("system_event_log", {}, "Windows System event log"),)
    return (_channel_requirement(event),)


def lookup_event_class(channel: object, provider: object, event_id: object) -> WindowsEventClass | None:
    """Return a catalog row only when all three shipper-written type fields agree."""
    if not isinstance(channel, str) or not isinstance(provider, str):
        return None
    try:
        numeric_id = int(event_id)
    except (TypeError, ValueError):
        return None
    return _BY_KEY.get((channel.casefold(), provider.casefold(), numeric_id))
