"""Windows shipper dispatch and structured-field extraction."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from xml.etree import ElementTree

from romulus.evidence.typed import FieldValue, Outcome, RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows_catalog import WINDOWS_DATASETS, WindowsEventClass, lookup_event_class

WINDOWS_NORMALIZER = "windows-ecs@1"


class WindowsInputError(ValueError):
    """A marked Windows record is malformed or unsafe."""


class WindowsNotNormalized(Exception):
    """A marked Windows record names an event class outside the catalog."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class WindowsRecord:
    hit: dict
    event_class: WindowsEventClass
    data: dict[str, FieldValue]

    def value(self, name: str, default=None):
        field = self.data.get(name)
        return default if field is None else field.value

    def origin(self, name: str) -> str:
        return self.data[name].origin


def _get(source: dict, path: str):
    current = source
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def is_windows_source(source: dict) -> bool:
    """Require an Elastic Agent Windows dataset or Winlogbeat's own agent marker."""
    dataset = _get(source, "data_stream.dataset") or _get(source, "event.dataset")
    winlogbeat = str(_get(source, "agent.type") or "").casefold() == "winlogbeat"
    return (isinstance(dataset, str) and dataset.casefold() in WINDOWS_DATASETS) or (
        winlogbeat and isinstance(source.get("winlog"), dict)
    )


def _xml_data(original: str, native_id: str) -> dict[str, FieldValue]:
    upper = original.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise WindowsInputError("event.original XML may not contain DOCTYPE or ENTITY declarations")
    try:
        root = ElementTree.fromstring(original)
    except ElementTree.ParseError as exc:
        raise WindowsInputError(f"event.original is not valid XML: {exc}") from exc
    values: dict[str, FieldValue] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "Data" and element.attrib.get("Name"):
            name = element.attrib["Name"]
        elif element is not root and element.text and tag not in {"System", "EventData", "UserData"}:
            name = tag
        else:
            continue
        if name in values:
            raise WindowsInputError(f"event.original XML contains duplicate field {name!r}")
        values[name] = fv(element.text or "", f"{native_id}:event.original:{name}#xml")
    return values


def _structured_data(winlog: dict, native_id: str) -> dict[str, FieldValue]:
    values: dict[str, FieldValue] = {}
    for container in ("event_data", "user_data"):
        content = winlog.get(container)
        if content is None:
            continue
        if not isinstance(content, dict):
            raise WindowsInputError(f"winlog.{container} must be an object")
        for name, value in content.items():
            if name in values:
                raise WindowsInputError(f"duplicate Windows field {name!r} across structured copies")
            values[str(name)] = fv(value, f"{native_id}:winlog.{container}.{name}")
    return values


def _parsed_hashes(data: dict[str, FieldValue]) -> None:
    hashes = data.get("Hashes")
    if hashes is None or not isinstance(hashes.value, str):
        return
    for item in hashes.value.split(","):
        algorithm, separator, value = item.partition("=")
        algorithm = algorithm.strip().upper()
        value = value.strip().lower()
        if not separator or not algorithm or not value:
            continue
        data[f"Hashes.{algorithm}"] = fv(value, f"{hashes.origin}#parsed:sysmon-hashes")


def read_windows_event(hit: dict) -> WindowsRecord:
    source = hit.get("_source")
    if not isinstance(source, dict) or not is_windows_source(source):
        raise WindowsInputError("record has no authoritative Windows shipper marker")
    winlog = source.get("winlog")
    if not isinstance(winlog, dict):
        raise WindowsInputError("Windows record is missing winlog fields")
    channel, provider, native_event_id = (
        winlog.get("channel"),
        winlog.get("provider_name"),
        winlog.get("event_id"),
    )
    event_class = lookup_event_class(channel, provider, native_event_id)
    if event_class is None:
        raise WindowsNotNormalized(
            "Windows event class "
            f"({channel!r}, {provider!r}, {native_event_id!r}) is not normalized"
        )
    data = _structured_data(winlog, hit["_id"])
    original = _get(source, "event.original")
    if not data and original not in (None, ""):
        if not isinstance(original, str):
            raise WindowsInputError("event.original must be text")
        data = _xml_data(original, hit["_id"])
    _parsed_hashes(data)
    return WindowsRecord(hit, event_class, data)


def _raw_ref(hit: dict) -> RawRef:
    encoded = json.dumps(hit["_source"], sort_keys=True, separators=(",", ":")).encode()
    return RawRef(
        target=hit["_index"],
        native_id=hit["_id"],
        digest=hashlib.sha256(encoded).hexdigest(),
    )


def normalize_windows(hit: dict) -> TypedEvent:
    """Create the catalog-selected typed shell; family-specific fields are added by the semantic normalizer."""
    record = read_windows_event(hit)
    source, winlog = hit["_source"], hit["_source"]["winlog"]
    ref = _raw_ref(hit)
    fields = {
        "event.code": fv(record.event_class.event_id, f"{hit['_id']}:winlog.event_id"),
        "event.channel": fv(record.event_class.channel, f"{hit['_id']}:winlog.channel"),
        "event.provider": fv(record.event_class.provider, f"{hit['_id']}:winlog.provider_name"),
    }
    fields.update({f"windows.event_data.{name}": value for name, value in record.data.items()})
    timestamp = datetime.fromisoformat(str(source["@timestamp"])).astimezone(UTC)
    host = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold() or None
    return TypedEvent(
        id=event_id(record.event_class.family, [ref], WINDOWS_NORMALIZER),
        family=record.event_class.family,
        ts=timestamp,
        host=host,
        outcome=Outcome.unknown,
        fields=fields,
        raw=[ref],
        normalizer=WINDOWS_NORMALIZER,
    )

