"""Positive Windows event rules with content-keyed, immediately published fleet shapes."""
from __future__ import annotations

import hashlib
import json
import ntpath
import re
from typing import ClassVar

from romulus.detect.base import Match, pf
from romulus.detect.windows_common import Hit, Undecided, WindowsProcessRule, clip
from romulus.evidence.typed import TypedEvent


def basename(value: object) -> str:
    return ntpath.basename(str(value or "").replace("/", "\\")).casefold()


def components(value: object) -> tuple[str, ...]:
    return tuple(part for part in str(value or "").replace("/", "\\").casefold().split("\\") if part)


def local_path_components(value: object) -> tuple[str, ...]:
    """Components below a recorded local volume, resolving dot components but never guessing a UNC share's ACL."""
    text = ntpath.normpath(str(value or "").replace("/", "\\")).casefold()
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
    match = re.match(r"(?:[a-z]:\\|%systemdrive%\\|\\device\\harddiskvolume\d+\\|"
                     r"volume\{[0-9a-f-]+\}\\)", text)
    return components(text[match.end():]) if match else ()


def writable(value: object) -> bool:
    """Standard profile and temporary locations, rather than arbitrary folders with familiar basenames.

    These are path indicators, not an inspection of the site's effective filesystem permissions.
    """
    text = ntpath.normpath(str(value or "").replace("/", "\\"))
    parts = components(text)
    if len(parts) > 1 and parts[0] in {
        "%temp%", "%tmp%", "%appdata%", "%localappdata%", "%userprofile%", "%public%",
    }:
        return True
    local = local_path_components(text)
    return ((len(local) >= 3 and local[0] in {"users", "documents and settings"})
            or (len(local) >= 2 and local[0] in {"temp", "tmp"})
            or (len(local) >= 3 and local[:2] == ("windows", "temp"))
            or (len(parts) >= 3 and parts[:2] in {
                ("%systemroot%", "temp"), ("%windir%", "temp"), ("systemroot", "temp"),
            }))


def integer(value: object) -> int | None:
    """A nonnegative Windows DWORD, without accepting booleans or overflow as access bits."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 0xffffffff else None
    text = str(value).strip().casefold()
    if text.startswith("dword (") and text.endswith(")"):
        text = text[7:-1].strip()
    try:
        result = int(text, 16 if text.startswith("0x") else 10)
        return result if 0 <= result <= 0xffffffff else None
    except ValueError:
        return None


def signal(event: TypedEvent, behavior: str, text: str, attack: tuple[str, ...], fields: tuple[str, ...],
           *, lane: str = "lead", severity: str = "medium", notes: tuple[str, ...] = (), content: str = "",
           common: str = "") -> Hit:
    names = tuple(dict.fromkeys(("event.code", "event.channel", *fields)))
    predicate = [pf(event, name) for name in names if event.has(name)]
    return Hit(behavior, text, lane, severity, attack, predicate, content=content, common=common or text, notes=notes)


class WindowsEventRule(WindowsProcessRule):
    """Reuse the process rules' disk-backed membership, citation holds and in-place fleet revisions."""

    families: ClassVar[tuple[str, ...]] = ()
    windows_event_classes = ()
    reads_command_line = False
    kind = "aggregate"
    direct_eligible = True
    assures_negative = False
    positive_only_reason = "These recorded Windows signals show positive observations; absence cannot be confirmed."
    research: ClassVar[tuple[str, ...]] = ()
    one_shot = False

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "id", None):
            cls.card = {
                "behavior": cls.title,
                "telemetry": ", ".join(cls.families),
                "fidelity": "Positive-only observations of typed OS fields; technique mapping is context, not proof.",
                "benign_and_cost": "; ".join(cls.benign),
                "query_cost": "One selective sweep of the declared event families; bounded disk-backed fleet state.",
                "next_pivot": "; ".join(cls.next_checks),
                "adds": cls.title,
                "research_basis": "; ".join(cls.research) or "ATT&CK Enterprise 20.0; Microsoft event documentation",
                "lanes": "Each new content shape and host is published immediately at its evidence-supported lane.",
                "retrieval": "Declared families and event classes, with unrelated classes inventoried separately.",
            }

    def _checked_judge(self, event):
        return self.judge(event)

    def consume(self, events):
        out = []
        scoped = (event for event in events if event.family in self.families and self.event_in_os_scope(event))
        for event in sorted(scoped, key=lambda item: (item.ts, item.id)):
            if event.id in self._seen:
                continue
            self._seen.add(event.id)
            if not self._events_pre_scoped:
                self.os_applicable += 1
            if event.family in self.context_families:
                continue
            missing = [name for name in self.required_fields if event.get(name) in (None, "", [], {})]
            if missing:
                self.missing_required += 1
                self.note_coverage("required_fields", "Typed fields needed to judge these records were missing: "
                                   + ", ".join(missing))
                continue
            self.evaluated += 1
            try:
                hits = self.judge(event)
            except Undecided as undecided:
                self.note_limit(undecided.kind, undecided.text)
                hits = [signal(event, "unresolved", undecided.text, self.attack, ())]
            for hit in hits:
                if self.one_shot:
                    out.append(self.record_match(event, hit))
                else:
                    self._fold(event, hit, out)
        return out

    def _shape(self, event, hit):
        material = {"rule": self.id, "behavior": hit.behavior, "content": hit.content,
                    "lane": hit.lane}
        return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()[:32]

    def record_match(self, event, hit):
        claim = f"{hit.text} on {event.host} at {event.ts.isoformat()}."
        context = [item for item in hit.context if item.id != event.id]
        return Match(self.id, claim, self.claim_type, [event, *context], list(hit.predicate), event.ts,
                     hit.severity, hit.lane, hit.confidence, event.entities(),
                     [*hit.notes, f"ATT&CK context (not proof): {', '.join(hit.attack)}"],
                     raw_copies=dict(hit.raw_copies), context_ids={item.id for item in context})

    def _fleet_match(self, shape, group, *, final):
        result = super()._fleet_match(shape, group, final=final)
        if result is not None:
            result.claim = result.claim.replace("process-creation record(s)", "Windows event record(s)").replace(
                "Sysmon and Security can each record the same process, so records are not processes.",
                "Several channels may record one action; these are event-record counts.",
            )
        return result

    @staticmethod
    def describe(value):
        return clip(value)
