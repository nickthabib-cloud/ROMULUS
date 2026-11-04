"""Lossless compact normalized fields and native references, without source document bodies."""
from __future__ import annotations

import json
import zlib

from romulus.evidence.typed import TypedEvent

COMPACT_CITATION_NOTE = "Citation body not retained in the event stage; compact recorded fields and native references retained."


def compact_event(event: TypedEvent) -> bytes:
    body = event.model_dump(mode="json")
    row = [body[name] for name in ("id", "family", "ts", "host", "outcome", "normalizer", "caveats")]
    row.append([[name, item["value"], item["origin"]] for name, item in body["fields"].items()])
    row.append([[item["target"], item["native_id"], item["digest"]] for item in body["raw"]])
    return zlib.compress(json.dumps(row, separators=(",", ":")).encode(), 1)


def expand_event(blob: bytes) -> TypedEvent:
    row = json.loads(zlib.decompress(blob))
    body = dict(zip(("id", "family", "ts", "host", "outcome", "normalizer", "caveats"), row[:7], strict=True))
    body["fields"] = {name: {"value": value, "origin": origin} for name, value, origin in row[7]}
    body["raw"] = [{"target": target, "native_id": identity, "digest": digest} for target, identity, digest in row[8]]
    return TypedEvent.model_validate(body)
