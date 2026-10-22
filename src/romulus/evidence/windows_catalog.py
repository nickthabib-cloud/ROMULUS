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

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.channel.casefold(), self.provider.casefold(), self.event_id)

    @property
    def token(self) -> str:
        return f"{self.channel}|{self.provider}|{self.event_id}".casefold()


SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _security(event_id: int, family: str, name: str) -> WindowsEventClass:
    return WindowsEventClass("Security", SECURITY, event_id, family, name)


def _sysmon(event_id: int, family: str, name: str) -> WindowsEventClass:
    return WindowsEventClass(SYSMON_CHANNEL, SYSMON, event_id, family, name)


EVENT_CLASSES = (
    _security(4688, "process_exec", "process created"),
    _security(4689, "process_termination", "process terminated"),
    _sysmon(1, "process_exec", "process created"),
    _sysmon(3, "net_socket", "network connection"),
    _sysmon(5, "process_termination", "process terminated"),
    _security(4624, "auth", "logon succeeded"),
    _security(4625, "auth", "logon failed"),
    _security(4648, "auth", "explicit credentials used"),
    _security(4672, "auth", "special privileges assigned"),
    _security(4634, "auth", "logoff completed"),
    _security(4647, "auth", "user initiated logoff"),
    _security(4720, "account_change", "account created"),
    _security(4722, "account_change", "account enabled"),
    _security(4724, "account_change", "password reset attempted"),
    _security(4726, "account_change", "account deleted"),
    _security(4728, "account_change", "member added to global group"),
    _security(4732, "account_change", "member added to local group"),
    _security(4756, "account_change", "member added to universal group"),
    _security(4738, "account_change", "account changed"),
    _security(4740, "account_change", "account locked out"),
    _security(4697, "service_change", "service installed"),
    WindowsEventClass("System", "Service Control Manager", 7045, "service_change", "service installed"),
    _security(4698, "scheduled_task", "scheduled task created"),
    _security(4702, "scheduled_task", "scheduled task updated"),
    _security(1102, "audit_config", "security log cleared"),
    WindowsEventClass("System", "Microsoft-Windows-Eventlog", 104, "audit_config", "event log cleared"),
    _security(4719, "audit_config", "audit policy changed"),
    WindowsEventClass("System", "Microsoft-Windows-Kernel-General", 12, "system_state", "operating system started"),
    WindowsEventClass("System", "Microsoft-Windows-Kernel-General", 13, "system_state", "operating system stopped"),
    WindowsEventClass("System", "EventLog", 6005, "system_state", "event log service started"),
    WindowsEventClass("System", "EventLog", 6006, "system_state", "event log service stopped"),
)

_BY_KEY = {event_class.key: event_class for event_class in EVENT_CLASSES}
if len(_BY_KEY) != len(EVENT_CLASSES):  # pragma: no cover - import-time catalog invariant
    raise RuntimeError("duplicate Windows event class")

WINDOWS_DATASETS = frozenset(
    {
        "system.security",
        "system.system",
        "windows.forwarded",
        "windows.powershell_operational",
        "windows.security",
        "windows.sysmon_operational",
        "windows.system",
    }
)
WINDOWS_HOST_DATASETS = (
    "windows.sysmon_operational",
    "system.security",
    "windows.security",
    "system.system",
    "windows.system",
)
_SECURITY_FAMILIES = frozenset(
    {event.family for event in EVENT_CLASSES if event.channel.casefold() == "security"}
)
_SYSMON_FAMILIES = frozenset(
    {event.family for event in EVENT_CLASSES if event.channel.casefold() == SYSMON_CHANNEL.casefold()}
)
_SYSTEM_FAMILIES = frozenset(
    {event.family for event in EVENT_CLASSES if event.channel.casefold() == "system"}
)
WINDOWS_DATASET_FAMILIES = {
    "windows.sysmon_operational": _SYSMON_FAMILIES,
    "system.security": _SECURITY_FAMILIES,
    "windows.security": _SECURITY_FAMILIES,
    "system.system": _SYSTEM_FAMILIES,
    "windows.system": _SYSTEM_FAMILIES,
}


def datasets_for_families(families: set[str] | frozenset[str]) -> tuple[str, ...]:
    return tuple(
        dataset for dataset in WINDOWS_HOST_DATASETS
        if WINDOWS_DATASET_FAMILIES.get(dataset, frozenset()).intersection(families)
    )


def event_classes_for_families(families: set[str] | frozenset[str]) -> tuple[WindowsEventClass, ...]:
    return tuple(event for event in EVENT_CLASSES if event.family in families)


def collection_requirements(event: WindowsEventClass) -> tuple[tuple[str, dict, str], ...]:
    """Site facts required before absence of this event class can support a negative."""
    if event.provider == SYSMON:
        return (("sysmon", {"event_id": event.event_id}, f"Sysmon event id {event.event_id}"),)
    if event.event_id == 4688:
        return (
            ("audit_policy", {"subcategory": "Process Creation", "outcome": "success"},
             "audit policy Process Creation success"),
            ("security_4688_command_line", {}, "Security 4688 command-line inclusion"),
        )
    audit_subcategories = {
        4689: ("Process Termination", "success"),
        4624: ("Logon", "success"),
        4625: ("Logon", "failure"),
        4648: ("Logon", "success"),
        4672: ("Special Logon", "success"),
        4634: ("Logoff", "success"),
        4647: ("Logoff", "success"),
        4720: ("User Account Management", "success"),
        4722: ("User Account Management", "success"),
        4724: ("User Account Management", "success"),
        4726: ("User Account Management", "success"),
        4738: ("User Account Management", "success"),
        4740: ("User Account Management", "success"),
        4728: ("Security Group Management", "success"),
        4732: ("Security Group Management", "success"),
        4756: ("Security Group Management", "success"),
        4697: ("Security System Extension", "success"),
        4698: ("Other Object Access Events", "success"),
        4702: ("Other Object Access Events", "success"),
        1102: ("Audit Other System Events", "success"),
        4719: ("Audit Policy Change", "success"),
    }
    if event.event_id in audit_subcategories:
        subcategory, outcome = audit_subcategories[event.event_id]
        return (("audit_policy", {"subcategory": subcategory, "outcome": outcome},
                 f"audit policy {subcategory} {outcome}"),)
    # System-channel boot/service/log-clear records still require an explicit matching collection group.
    return (("host_group", {}, "host collection group"),)


def lookup_event_class(channel: object, provider: object, event_id: object) -> WindowsEventClass | None:
    """Return a catalog row only when all three shipper-written type fields agree."""
    if not isinstance(channel, str) or not isinstance(provider, str):
        return None
    try:
        numeric_id = int(event_id)
    except (TypeError, ValueError):
        return None
    return _BY_KEY.get((channel.casefold(), provider.casefold(), numeric_id))
