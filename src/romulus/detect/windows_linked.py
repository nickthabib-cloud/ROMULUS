"""Explicit Windows link claims backed by both records' GUID or session fields."""
from __future__ import annotations

import hashlib
import re
from typing import ClassVar
from uuid import UUID

from romulus.detect.base import ContextPlaybook, Match, PredicateField, pf
from romulus.detect.windows_events import WindowsEventRule
from romulus.detect.windows_rows import row_key
from romulus.evidence.typed import event_os_family
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL


def _guid(value):
    try:
        result = UUID(str(value))
        return str(result) if result.int else None
    except ValueError:
        return None


def _session(value):
    text = str(value or "").strip().casefold()
    if not re.fullmatch(r"(?:0x[0-9a-f]{1,16}|[0-9]{1,20})", text):
        return None
    number = int(text, 16 if text.startswith("0x") else 10)
    return hex(number) if 0 < number <= 0xffffffffffffffff and number not in {0x3e4, 0x3e5, 0x3e7} else None


class _Linked(WindowsEventRule, ContextPlaybook):
    kind, claim_type, lane = "context", "correlated_observation", "context"
    # These independent pair facts publish one bounded link at a time, outside session-wide accumulation.
    per_link_evidence = True
    direct_eligible = False
    families = ("auth", "process_exec")
    anchor_classes = ("*",)
    anchor_class = "execution"
    benign = ("ordinary authentication and application launches sharing the recorded key",)
    next_checks = ("inspect both cited records and the link's completeness before interpreting the relationship",)
    research = ("https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624",)
    attack = ("T1078",)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "id", None):
            cls.card.update(query_cost="Pairwise checks within one existing bounded link retrieval.",
                            retrieval="Reached through the rule's declared Windows typed link only.",
                            lanes="Context records cite both sides of recorded key equality.")

    def accepts(self, anchor, link):
        return (super().accepts(anchor, link) and any(event_os_family(item) == "windows" for item in anchor.events))

    def _match(self, anchor, link, first, second, text, parsed):
        fields = ("event.code", "host.boot.id", "auth.logon_guid", "auth.session_id", "process.subject_session_id",
                  "process.target_session_id", "process.session_id", "windows.event_data.SubjectLogonId",
                  "process.executable", "auth.target_account")
        predicate = [pf(item, name) for item in (first, second) for name in fields if item.has(name)]
        predicate.extend(parsed)
        identity = row_key(self.id, anchor.id, link.link_type, first.id, second.id)
        return Match(self.id, text, self.claim_type, [first, second], predicate, first.ts, "info", "context", "high",
                     first.entities(), [f"Reached through {link.link_type}; link status {link.status}.", *link.reasons,
                                        "Recorded key equality establishes this observation, not causal or malicious intent."],
                     group_key="windows-link:" + hashlib.sha256(identity.encode()).hexdigest(), context_ids={second.id})


class WindowsKerberosLogonLink(_Linked):
    version = "2"
    id, title = "win.kerberos_logon_link", "Service-ticket and logon records share a nonzero logon GUID"
    link_types = ("kerberos_logon",)
    families = ("auth",)
    required_by_family: ClassVar = {"auth": ("auth.logon_guid",)}
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4624, 4769))

    def consume_linked(self, anchor, link, events):
        if not self.accepts(anchor, link):
            return []
        out = []
        for other in events:
            if event_os_family(other) != "windows" or other.family != "auth" or other.get("event.code") not in {4624, 4769}:
                continue
            self.evaluated += 1
            guid = _guid(other.get("auth.logon_guid"))
            if not guid:
                self.missing_required += 1
                continue
            for subject in anchor.events:
                if (event_os_family(subject) != "windows" or subject.family != "auth"
                        or subject.get("event.code") not in {4624, 4769}
                        or subject.get("event.code") == other.get("event.code")
                        or _guid(subject.get("auth.logon_guid")) != guid or subject.id == other.id):
                    continue
                text = (f"The kerberos_logon link connects event {subject.get('event.code')} on {subject.host} at "
                        f"{subject.ts.isoformat()} with event {other.get('event.code')} on {other.host} at "
                        f"{other.ts.isoformat()}; both records carry nonzero logon GUID {guid}.")
                parsed = [PredicateField("auth.logon_guid", guid, item.fields["auth.logon_guid"].origin + "#parsed:uuid")
                          for item in (subject, other)]
                out.append(self._match(anchor, link, subject, other, text, parsed))
        return out


class WindowsProcessSessionLink(_Linked):
    version = "2"
    id, title = "win.process_session_link", "Process and logon records share a host and canonical session ID"
    link_types = ("process_session",)
    required_by_family: ClassVar = {"auth": ("auth.session_id",)}
    windows_event_classes = (("Security", SECURITY, 4624), ("Security", SECURITY, 4688), (SYSMON_CHANNEL, SYSMON, 1))

    def consume_linked(self, anchor, link, events):
        if not self.accepts(anchor, link):
            return []
        out = []
        for logon in events:
            if event_os_family(logon) != "windows" or logon.family != "auth" or logon.get("event.code") != 4624:
                continue
            self.evaluated += 1
            session = _session(logon.get("auth.session_id"))
            if not session:
                self.missing_required += 1
                continue
            for process in anchor.events:
                if (event_os_family(process) != "windows" or process.family != "process_exec"
                        or not process.host or process.host != logon.host or logon.ts > process.ts):
                    continue
                names = ("process.subject_session_id", "windows.event_data.SubjectLogonId",
                         "process.target_session_id", "process.session_id")
                requested = _session(link.key.get("process.session_id"))
                if requested and session != requested:
                    continue
                name = next((key for key in names if _session(process.get(key)) == session), None)
                if not name or _session(process.get(name)) != session:
                    continue
                pboot, lboot = process.get("host.boot.id"), logon.get("host.boot.id")
                if pboot and lboot and pboot != lboot:
                    continue
                same_boot = bool(pboot and lboot and pboot == lboot)
                qualifier = "both carry the same recorded boot ID" if same_boot else "their same-boot relationship is unresolved"
                text = (f"The process_session link connects a process record on {process.host} at {process.ts.isoformat()} "
                        f"with a 4624 logon record at {logon.ts.isoformat()}; both carry canonical logon session ID "
                        f"{session}, and {qualifier}.")
                parsed = [PredicateField(name, session, process.fields[name].origin + "#parsed:windows-logon-session"),
                          PredicateField("auth.session_id", session, logon.fields["auth.session_id"].origin + "#parsed:windows-logon-session")]
                out.append(self._match(anchor, link, process, logon, text, parsed))
        return out


WINDOWS_LINKED_PLAYBOOKS = (WindowsKerberosLogonLink, WindowsProcessSessionLink)
