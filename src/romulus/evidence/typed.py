"""Typed events with field-level lineage. Unknown stays unknown; nothing is inferred from free text."""
from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

NETWORK_OBSERVER_FAMILIES = {
    "net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session", "net_session",
    "http_body",
}


class Outcome(StrEnum):
    success = "success"
    failure = "failure"
    unknown = "unknown"


class FieldValue(BaseModel):
    value: Any
    origin: str          # "<native field path>" or "<native>#parsed:<how>"


class RawRef(BaseModel):
    target: str
    native_id: str
    digest: str = ""

    @property
    def key(self) -> str:
        return f"{self.target}/{self.native_id}"


class TypedEvent(BaseModel):
    id: str
    family: str          # process_exec | auth | http_access | web_error | net_alert | net_flow | dns_query | http_tx
    ts: datetime
    host: str | None
    outcome: Outcome = Outcome.unknown
    fields: dict[str, FieldValue]
    raw: list[RawRef]
    normalizer: str
    caveats: list[str] = []

    def get(self, name: str, default=None):
        f = self.fields.get(name)
        return default if f is None else f.value

    def has(self, name: str) -> bool:
        return name in self.fields and self.fields[name].value is not None

    def entities(self) -> list[tuple[str, str, str]]:
        """(kind, value, role) for entity linking."""
        out = []
        if self.host:
            role = "observer" if self.family in NETWORK_OBSERVER_FAMILIES else "host"
            out.append(("host", self.host, role))
        if self.get("user.entity_id") or self.get("auth.target_account"):
            actor = self.get("user.entity_id")
            if actor:
                out.append(("account", str(actor), "actor"))
            subject = self.get("auth.target_account")
            if subject:
                out.append(("account", str(subject), "subject"))
            entity_fields = (("source.ip", "ip", "src"), ("destination.ip", "ip", "dst"),
                             ("dns.question.name", "domain", "subject"),
                             ("url.domain", "domain", "subject"))
        else:
            entity_fields = (("user.name", "account", "actor"), ("process.user", "account", "actor"),
                             ("source.ip", "ip", "src"), ("destination.ip", "ip", "dst"),
                             ("dns.question.name", "domain", "subject"),
                             ("url.domain", "domain", "subject"),
                             ("auth.target_user", "account", "subject"))
        for name, kind, role in entity_fields:
            v = self.get(name)
            if v:
                out.append((kind, str(v).lower() if kind == "domain" else str(v), role))
        # every DNS question name of a record that asked several (one when the scalar above already holds it)
        names = self.get("dns.question.names")
        for v in names if isinstance(names, list) else []:
            entity = ("domain", str(v).lower(), "subject")
            if v and entity not in out:
                out.append(entity)
        return out


def event_os_family(event: TypedEvent) -> str:
    """Return per-event OS scope; observer-network telemetry is not host Linux telemetry."""
    explicit = event.get("host.os.family")
    if explicit:
        return str(explicit).casefold()
    if event.normalizer.startswith("windows-"):
        return "windows"
    if event.family in NETWORK_OBSERVER_FAMILIES:
        return "unknown"
    return "linux"


# A typed event is one normalization's view of raw records, and the store keeps one row per event id. The id
# therefore carries the evidence version: a hunt run with improved normalization stores its own rows instead of
# silently reusing an older hunt's (stale rows missing a newly normalized field, such as process.session_id,
# would hide every link that depends on it). Bump on any change to how raw records become typed events; tests/test_evidence_version.py enforces it.
EVIDENCE_VERSION = 12


def event_id(family: str, refs: list[RawRef], producer: str = "") -> str:
    """Identity of one producer's typed view of raw records. `producer` names a normalizer outside this package
    (for example the packet stage's), so its own version bumps also give new rows."""
    h = hashlib.sha256((f"v{EVIDENCE_VERSION}|{producer}|" + family + "|"
                        + "|".join(sorted(r.key for r in refs))).encode()).hexdigest()
    return h[:24]


def raw_identity(event: TypedEvent) -> str:
    """A version-independent identity for grouping: the raw records the event views."""
    return "+".join(sorted(r.key for r in event.raw))


# A FieldValue's instance state, as pydantic's validating constructor leaves it: the field dict, the set of fields
# given, and no extra or private attributes (BaseModel keeps the last three in slots).
_new = object.__new__
_set_attr = object.__setattr__
try:
    _set_fields_set = BaseModel.__dict__["__pydantic_fields_set__"].__set__
    _set_extra = BaseModel.__dict__["__pydantic_extra__"].__set__
    _set_private = BaseModel.__dict__["__pydantic_private__"].__set__
    _SLOTS = True
except (KeyError, AttributeError):   # a pydantic release without these slots: use the validating constructor
    _SLOTS = False


# Every field sets both of its fields, so all fields share one fields-set: pydantic only adds a name to it when that
# field is assigned, and both names are already in it (it would otherwise be a 200-byte set per field).
_BOTH_SET = {"value", "origin"}


def _laid_out(value, origin: str) -> FieldValue:
    field = _new(FieldValue)
    _set_attr(field, "__dict__", {"value": value, "origin": origin})
    _set_fields_set(field, _BOTH_SET)
    _set_extra(field, None)
    _set_private(field, None)
    return field


def _same_layout() -> bool:
    built, checked = _laid_out([1, "x"], "o"), FieldValue(value=[1, "x"], origin="o")
    return (built.__dict__ == checked.__dict__ and built.model_fields_set == checked.model_fields_set
            and built.__pydantic_extra__ == checked.__pydantic_extra__
            and built.__pydantic_private__ == checked.__pydantic_private__
            and built.model_dump_json() == checked.model_dump_json() and built == checked)


# Checked once at import: a pydantic release that lays instances out differently gets the validating constructor.
_FAST = _SLOTS and _same_layout()


def fv(value, origin: str) -> FieldValue:
    """A typed field. Normalizers build millions, so with a str origin the instance is laid out directly instead
    of validated: `value` is Any (validation stores it as given) and `origin` is already a str. Any other origin
    goes through the validating constructor, which refuses or converts it as it always did."""
    if _FAST and type(origin) is str:
        return _laid_out(value, origin)
    return FieldValue(value=value, origin=origin)
