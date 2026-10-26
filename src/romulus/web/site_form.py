"""The Site setup form: the site file's document shown as form fields, and a submitted form read back as a
document. Validation is the site module's; this only maps fields, so the page can never accept what the file
loader would refuse."""
from __future__ import annotations

import re

from romulus.evidence.windows_catalog import (
    EVENT_CLASSES,
    SYSMON,
    SYSMON_CHANNEL,
    WINDOWS_CHANNELS,
    collection_requirements,
)
from romulus.site import COLLECTION_SCHEMA

AUDIT_SETTINGS = ("success", "failure", "both")
MAX_GROUPS = 200          # host groups one form may carry; far above a real site's
MAX_LINES = 5_000         # entries one list field may carry
_SPLIT = re.compile(r"[\r\n,]+")


def known_sysmon_ids() -> list[int]:
    return sorted({event.event_id for event in EVENT_CLASSES if event.provider == SYSMON})


def known_audit_subcategories() -> list[str]:
    """Every audit policy subcategory some catalogued event class needs, in a stable order."""
    names: dict[str, str] = {}
    for event in EVENT_CLASSES:
        for fact, arguments, _label in collection_requirements(event):
            if fact == "audit_policy":
                names.setdefault(arguments["subcategory"].casefold(), arguments["subcategory"])
    return [names[key] for key in sorted(names)]


def known_channels() -> list[str]:
    """Channels whose collection is attested by name. Sysmon's is attested through its own block."""
    return [channel for channel in WINDOWS_CHANNELS if channel.casefold() != SYSMON_CHANNEL.casefold()]


_NAMED_CHANNELS = {
    "security_event_log": "Security",
    "system_event_log": "System",
    "defender_operational": "Microsoft-Windows-Windows Defender/Operational",
    "task_scheduler_operational": "Microsoft-Windows-TaskScheduler/Operational",
}


def _lines(value: object) -> list[str]:
    if not isinstance(value, str):
        return []
    items = [item.strip() for item in _SPLIT.split(value) if item.strip()]
    if len(items) > MAX_LINES:
        raise ValueError(f"a list may hold at most {MAX_LINES} entries")
    return items


def group_view(group: dict) -> dict:
    """One host group as the form shows it. Values the known lists do not name are kept and shown."""
    hosts = group.get("hosts")
    sysmon = group.get("sysmon") or {}
    ids = [item for item in sysmon.get("event_ids") or [] if isinstance(item, int)]
    known_ids = set(known_sysmon_ids())
    policy = {str(key).casefold(): value for key, value in (group.get("audit_policy") or {}).items()}
    known = known_audit_subcategories()
    extra_policy = [(name, policy[name]) for name in sorted(policy) if name not in {k.casefold() for k in known}]
    listed = {str(item).casefold(): str(item) for item in group.get("event_channels") or []}
    for fact, channel in _NAMED_CHANNELS.items():
        if group.get(fact) is True:
            listed.setdefault(channel.casefold(), channel)
    known_folded = {channel.casefold() for channel in known_channels()}
    return {
        "hosts": "all" if hosts == "all" else "\n".join(hosts or []),
        "sysmon_installed": bool(sysmon.get("installed")),
        "sysmon_ids": set(ids) & known_ids,
        "sysmon_other": ", ".join(str(item) for item in sorted(set(ids) - known_ids)),
        "command_line": group.get("security_4688_command_line") is True,
        "script_block": group.get("powershell_script_block") is True,
        "audit": {name: policy.get(name.casefold(), "") for name in known},
        "audit_extra": extra_policy,
        "channels": {key for key in listed if key in known_folded},
        "channels_other": "\n".join(listed[key] for key in sorted(listed) if key not in known_folded),
    }


def view(content: dict) -> dict:
    return {
        "groups": [group_view(group) for group in content.get("collection") or []],
        "domain_controllers": "\n".join(content.get("domain_controllers") or []),
        "directory_sync_accounts": "\n".join(content.get("directory_sync_accounts") or []),
        "internal_networks": "\n".join(content.get("internal_networks") or []),
        "external_networks": "\n".join(content.get("external_networks") or []),
        "known_sysmon_ids": known_sysmon_ids(),
        "known_audit": known_audit_subcategories(),
        "known_channels": known_channels(),
        "audit_settings": AUDIT_SETTINGS,
    }


def _integers(text: str, label: str) -> list[int]:
    values = []
    for item in _lines(text):
        if not item.isdigit():
            raise ValueError(f"{label}: {item!r} is not an event id")
        values.append(int(item))
    return values


def parse_form(form) -> dict:
    """The document a submitted form describes. Raises ValueError for a form the page itself could not have
    produced (wrong counts, unknown settings); every other check is the site validator's."""
    try:
        count = int(form.get("group_count", "0"))
    except ValueError:
        raise ValueError("bad group count") from None
    if not 0 <= count <= MAX_GROUPS:
        raise ValueError(f"at most {MAX_GROUPS} host groups")
    known_audit = known_audit_subcategories()
    groups = []
    for index in range(count):
        prefix = f"g{index}."
        hosts_text = str(form.get(prefix + "hosts", "")).strip()
        is_new = form.get(prefix + "new") == "1"
        if form.get(prefix + "remove") == "1" or (is_new and not hosts_text):
            continue
        if not hosts_text:
            raise ValueError(f"host group {index + 1}: list its hosts, write 'all', or tick Remove")
        group: dict = {"hosts": "all" if hosts_text.casefold() == "all" else _lines(hosts_text)}
        ids = sorted({int(item) for item in form.getlist(prefix + "sysmon_ids") if str(item).isdigit()}
                     | set(_integers(str(form.get(prefix + "sysmon_other", "")), "other Sysmon event ids")))
        installed = form.get(prefix + "sysmon_installed") == "1"
        if installed or ids:
            group["sysmon"] = {"installed": installed, "event_ids": ids}
        group["security_4688_command_line"] = form.get(prefix + "command_line") == "1"
        group["powershell_script_block"] = form.get(prefix + "script_block") == "1"
        policy: dict[str, str] = {}
        rows = [(name, form.get(f"{prefix}audit.{position}", "")) for position, name in enumerate(known_audit)]
        extra_names = form.getlist(prefix + "audit_extra_name")
        extra_settings = form.getlist(prefix + "audit_extra_setting")
        if len(extra_names) != len(extra_settings):
            raise ValueError("bad audit policy rows")
        rows += list(zip(extra_names, extra_settings, strict=True))
        rows.append((str(form.get(prefix + "audit_new_name", "")).strip(), form.get(prefix + "audit_new_setting", "")))
        for name, setting in rows:
            if not setting:
                continue
            if setting not in AUDIT_SETTINGS:
                raise ValueError(f"bad audit setting {setting!r}")
            if not str(name).strip():
                raise ValueError("an audit policy setting needs a subcategory name")
            policy[str(name).strip()] = setting
        if policy:
            group["audit_policy"] = policy
        channels = {channel.casefold(): channel for channel in known_channels()}
        chosen = [channels[str(item).casefold()] for item in form.getlist(prefix + "channels")
                  if str(item).casefold() in channels]
        other = _lines(str(form.get(prefix + "channels_other", "")))
        if chosen or other:
            # Duplicates (a known channel also typed by hand) are the validator's to refuse, with its message.
            group["event_channels"] = [*chosen, *other]
        groups.append(group)
    document: dict = {"schema": COLLECTION_SCHEMA}
    if groups:
        document["collection"] = groups
    for key in ("domain_controllers", "directory_sync_accounts", "internal_networks", "external_networks"):
        values = _lines(form.get(key, ""))
        if values:
            document[key] = values
    return document


def describe_change(before: dict, after: dict) -> list[str]:
    """The top-level parts that changed, for the audit record and the confirmation line."""
    keys = ("collection", "domain_controllers", "directory_sync_accounts", "internal_networks", "external_networks")
    labels = {"collection": "collection groups", "domain_controllers": "domain controllers",
              "directory_sync_accounts": "directory sync accounts", "internal_networks": "internal networks",
              "external_networks": "external networks"}
    return [labels[key] for key in keys if (before.get(key) or []) != (after.get(key) or [])]
