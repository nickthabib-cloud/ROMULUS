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


def broad_write_allow(descriptor):
    """Read allow ACEs for Everyone/Authenticated Users, without asserting effective ACL access.

    SDDL ACE order and deny rules can restrict effective access. This positive signal
    names the recorded write-capable allow ACE, not an effective-permissions calculation.
    https://learn.microsoft.com/windows/win32/secauthz/ace-strings
    https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
    """
    if not isinstance(descriptor, str):
        return False
    for body in re.findall(r"\(([^()]*)\)", descriptor):
        parts = body.split(";")
        if len(parts) != 6:
            continue
        kind, flags, rights, _, _, trustee = (part.upper() for part in parts)
        if kind not in {"A", "OA"} or "IO" in {flags[n : n + 2] for n in range(0, len(flags), 2)}:
            continue
        if trustee not in {"WD", "AU", "S-1-1-0", "S-1-5-11"}:
            continue
        tokens = {rights[n : n + 2] for n in range(0, len(rights), 2)}
        if tokens & {"GA", "GW", "FA", "FW", "WD", "WO"}:
            return True
        try:
            mask = (
                int(rights, 16)
                if rights.lower().startswith("0x")
                else int(rights, 16)
                if re.fullmatch(r"[0-9A-F]{8}", rights)
                else 0
            )
        except ValueError:
            mask = 0
        if mask & (0x10000000 | 0x40000000 | 0x2 | 0x4 | 0x10 | 0x100 | 0x40000 | 0x80000):
            return True
    return False


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
    version = "1"
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
        path_signal = exposed_path(event.get("share.local_path"))
        acl_signal = broad_write_allow(event.get("share.security_descriptor.new"))
        lane = "context" if change == "deleted" else "high" if path_signal or acl_signal else "lead"
        reasons = []
        if path_signal and change != "deleted":
            reasons.append(
                "The recorded path is a drive root, system tree or conventional user-writable location; effective permissions were not inspected."
            )
        if acl_signal and change != "deleted":
            reasons.append(
                "The new descriptor contains a write-capable allow ACE for Everyone or Authenticated Users; effective access depends on the complete ACL."
            )
        if not event.get("share.local_path"):
            reasons.append("The share local path was not recorded.")
        return [
            signal(
                event,
                "share_" + change,
                f"A network share was {change}: {self.describe(event.get('share.name'))}",
                self.attack,
                _FIELDS,
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
