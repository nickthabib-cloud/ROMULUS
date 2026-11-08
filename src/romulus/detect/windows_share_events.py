"""Typed share auditing; a share connection does not establish a file transfer."""

from __future__ import annotations

import json
import ntpath
import re

from romulus.detect.site_roles import declared_source
from romulus.detect.windows_events import (
    WindowsEventRule,
    components,
    local_path_components,
    signal,
    writable,
)
from romulus.evidence.windows_catalog import SECURITY

_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-"
_FIELDS = (
    "share.name",
    "share.local_path",
    "share.change",
    "share.security_descriptor.old",
    "share.security_descriptor.new",
    "user.entity_id",
    "user.name",
    "user.domain",
)


def broad_write_aces(descriptor):
    """Recorded broad write-capable allow bits by trustee and object scope.

    SDDL ACE order and deny rules can restrict effective access. This positive
    signal compares recorded allow bits, not effective permissions.
    https://learn.microsoft.com/windows/win32/secauthz/ace-strings
    https://learn.microsoft.com/windows/win32/secauthz/sid-strings
    https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
    """
    grants = {}
    if not isinstance(descriptor, str):
        return grants
    write_bits = 0x2 | 0x4 | 0x10 | 0x100 | 0x40000 | 0x80000
    rights_bits = {"GA": write_bits, "FA": write_bits, "GW": 0x116, "FW": 0x116,
                   "WD": 0x40000, "WO": 0x80000}
    trustees = {"WD": "S-1-1-0", "AU": "S-1-5-11", "AN": "S-1-5-7", "DU": "DU"}
    for body in re.findall(r"\(([^()]*)\)", descriptor):
        parts = body.split(";")
        if len(parts) != 6:
            continue
        kind, flags, rights, object_guid, inherit_guid, trustee = (part.upper() for part in parts)
        if kind not in {"A", "OA"} or "IO" in {flags[n : n + 2] for n in range(0, len(flags), 2)}:
            continue
        trustee = trustees.get(trustee, trustee)
        if trustee not in {"S-1-1-0", "S-1-5-11", "S-1-5-7", "DU"} and not re.fullmatch(
            r"S-1-5-21-\d+-\d+-\d+-513", trustee
        ):
            continue
        mask = 0
        if rights.startswith("0X") or re.fullmatch(r"[0-9A-F]{8}", rights):
            try:
                mask = int(rights, 16)
            except ValueError:
                pass
            if mask & 0x10000000:
                mask |= write_bits
            if mask & 0x40000000:
                mask |= 0x116
        else:
            for offset in range(0, len(rights), 2):
                mask |= rights_bits.get(rights[offset : offset + 2], 0)
        mask &= write_bits
        if mask:
            scope = trustee, kind, object_guid, inherit_guid
            grants[scope] = grants.get(scope, 0) | mask
    return grants


def broad_write_allow(descriptor):
    return bool(broad_write_aces(descriptor))


def system_path_parts(path):
    local = local_path_components(path)
    if local and local[0] == "windows":
        return local[1:]
    parts = components(ntpath.normpath(str(path or "").replace("/", "\\")))
    if parts and parts[0] in {"%systemroot%", "%windir%"}:
        return parts[1:]
    return None


# OS-created shares are recognized only by both the share name and its
# conventional system-root-relative path. A broad write grant is still HIGH.
_OS_SHARE_PATHS = {"print$": ("system32", "spool", "drivers"),
                   "sysvol": ("sysvol",), "netlogon": ("sysvol",)}


def os_share_path(name, path):
    names = components(name)
    prefix = _OS_SHARE_PATHS.get(names[-1] if names else "")
    parts = system_path_parts(path)
    return bool(prefix and parts is not None and (
        parts == prefix if names[-1] == "print$" else parts[:len(prefix)] == prefix
    ))


def exposed_path(path):
    text = str(path or "").replace("/", "\\").casefold()
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
    if re.fullmatch(
        r"(?:[a-z]:\\|%systemdrive%\\|\\device\\harddiskvolume\d+\\|volume\{[0-9a-f-]+\}\\)", text
    ):
        return True
    text = ntpath.normpath(text)
    local = local_path_components(text)
    return bool(
        local
        and local[0] == "windows"
        or text.split("\\", 1)[0] in {"%systemroot%", "%windir%"}
        or writable(ntpath.join(text, "_"))
    )


class ShareCreated(WindowsEventRule):
    id = "win.share_created"
    version = "2"
    title = "A network share was added, modified or deleted"
    families = ("share_change",)
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (5142, 5143, 5144))
    attack = ("T1135", "T1021.002")
    benign = ("Authorized file-server provisioning and share maintenance.",)
    next_checks = ("Review the share path, actor and effective permissions, then inspect access records.",)
    research = tuple(_DOC + str(code) for code in (5142, 5143, 5144))
    required_fields = ("share.name", "share.change")

    def judge(self, event):
        if event.get("event.code") not in {5142, 5143, 5144} or event.family != "share_change":
            return []
        change = event.get("share.change")
        if change not in {"added", "modified", "deleted"} or not event.get("share.name"):
            return []
        path = event.get("share.local_path.new") or event.get("share.local_path")
        old_path, new_path = event.get("share.local_path.old"), event.get("share.local_path.new")
        path_changed = bool(
            isinstance(old_path, str) and old_path and isinstance(new_path, str) and new_path
            and ntpath.normcase(ntpath.normpath(old_path.replace("/", "\\")))
            != ntpath.normcase(ntpath.normpath(new_path.replace("/", "\\")))
        )
        path_signal = (
            exposed_path(path) if change == "added"
            else path_changed and system_path_parts(new_path) is not None
        ) and not os_share_path(event.get("share.name"), path)
        old_sd, new_sd = event.get("share.security_descriptor.old"), event.get("share.security_descriptor.new")
        old_grants, new_grants = broad_write_aces(old_sd), broad_write_aces(new_sd)
        old_dacl_recorded = isinstance(old_sd, str) and "D:" in old_sd.upper()
        acl_signal = bool(new_grants) if change == "added" else (
            old_dacl_recorded and any(mask & ~old_grants.get(scope, 0) for scope, mask in new_grants.items())
        )
        lane = "context" if change == "deleted" else "high" if path_signal or acl_signal else "lead"
        reasons = []
        if path_signal and change != "deleted":
            reasons.append(
                "The recorded path is a drive root, system tree or conventional user-writable location; effective permissions were not inspected."
                if change == "added" else "The typed old and new paths record a change to a system path."
            )
        if acl_signal and change != "deleted":
            reasons.append(
                "The new descriptor records a broad write-capable allow ACE for Everyone, Authenticated Users, Domain Users or Anonymous; effective access depends on the complete ACL."
                if change == "added" else "The new descriptor adds broad write-capable allow bits that the old descriptor lacked; effective access depends on the complete ACL."
            )
        if not path:
            reasons.append("The share local path was not recorded.")
        if change == "modified" and not old_dacl_recorded:
            reasons.append("The old descriptor's DACL was not recorded; a newly added broad write grant cannot be established.")
        return [
            signal(
                event,
                "share_" + change,
                f"A network share was {change}: {self.describe(event.get('share.name'))}",
                self.attack,
                (*_FIELDS, "share.local_path.old", "share.local_path.new"),
                lane=lane,
                severity="high" if lane == "high" else "info" if lane == "context" else "medium",
                notes=tuple(reasons),
                content=json.dumps([event.host, *[event.get(k) for k in _FIELDS]], sort_keys=True),
            )
        ]


class AdminShareAccess(WindowsEventRule):
    id = "win.admin_share_access"
    version = "1"
    title = "A client connected to an administrative share"
    families = ("share_access",)
    windows_event_classes = (("Security", SECURITY, 5140),)
    attack = ("T1021.002",)
    benign = ("Authorized administration and deployment use administrative shares.",)
    next_checks = ("Inspect detailed share access and subsequent file or service activity.",)
    research = (_DOC + "5140",)
    required_fields = ("share.name",)

    def judge(self, event):
        parts = components(event.get("share.name"))
        share = parts[-1] if parts else ""
        if event.get("event.code") != 5140 or not (share == "admin$" or re.fullmatch(r"[a-z]\$", share)):
            return []
        declarations = getattr(getattr(self, "site_facts", None), "management_hosts", ())
        listed = declared_source(event, hosts=declarations, addresses=declarations)
        notes = ["A share connection does not establish a file write or successful remote execution."]
        if not event.get("source.ip") and not event.get("source.hostname"):
            notes.append("The source address and host name were not recorded; management role is unresolved.")
        if listed:
            notes.append("The source is a declared management host.")
        fields = ("share.name", "source.ip", "source.hostname", "user.entity_id", "user.name")
        return [
            signal(
                event,
                "admin_share_connection",
                f"A client connected to administrative share {self.describe(event.get('share.name'))}",
                self.attack,
                fields,
                lane="context" if listed else "lead",
                severity="info" if listed else "medium",
                notes=tuple(notes),
                content=json.dumps(
                    [event.get("source.ip") or event.get("source.hostname"), event.host, share]
                ),
            )
        ]


WINDOWS_SHARE_PLAYBOOKS = (ShareCreated, AdminShareAccess)
