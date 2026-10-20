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
        for name, kind, role in (("user.name", "account", "actor"), ("process.user", "account", "actor"),
                                 ("source.ip", "ip", "src"), ("destination.ip", "ip", "dst"),
                                 ("dns.question.name", "domain", "subject"), ("url.domain", "domain", "subject"),
                                 ("auth.target_user", "account", "subject")):
            v = self.get(name)
            if v:
                out.append((kind, str(v).lower() if kind == "domain" else str(v), role))
        return out


def event_id(family: str, refs: list[RawRef]) -> str:
    h = hashlib.sha256((family + "|" + "|".join(sorted(r.key for r in refs))).encode()).hexdigest()
    return h[:24]


def fv(value, origin: str) -> FieldValue:
    return FieldValue(value=value, origin=origin)
