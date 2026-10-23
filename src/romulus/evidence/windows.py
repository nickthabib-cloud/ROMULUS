"""Windows shipper dispatch and structured-field extraction."""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from xml.etree import ElementTree

from romulus.evidence.typed import FieldValue, Outcome, RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows_catalog import WINDOWS_DATASETS, WindowsEventClass, lookup_event_class

WINDOWS_NORMALIZER = "windows-ecs@1"
_GUID = re.compile(r"^\{?([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}?$")
_SID = re.compile(r"^S-\d+(?:-\d+)+$", re.IGNORECASE)
# Windows Security event schemas use these values when the logon has no network endpoint.
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
_ABSENT_FIELD_VALUES = {
    "IpAddress": frozenset({"-", "::", "0", "0.0.0.0"}),
    "IpPort": frozenset({"-", "0"}),
    "SubjectUserSid": frozenset({"-", "s-1-0-0"}),
    "TargetUserSid": frozenset({"-", "s-1-0-0"}),
    "SubjectDomainName": frozenset({"-"}),
    "TargetDomainName": frozenset({"-"}),
    "SubjectUserName": frozenset({"-"}),
    "TargetUserName": frozenset({"-"}),
}


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


class RecordIdContinuity:
    """Streaming gap state spilled to a SQLite temporary file.

    State remains one row per (target, computer, channel), never one entry per record. SQLite's empty filename
    creates an OS-backed temporary database that is removed on close, avoiding a fleet-size completeness cap
    without holding every host/channel key in Python memory.
    """

    def __init__(self) -> None:
        self._db = sqlite3.connect("")
        self._db.execute(
            "CREATE TABLE continuity ("
            "target TEXT NOT NULL, computer TEXT NOT NULL, channel TEXT NOT NULL, "
            "last_id INTEGER NOT NULL, samples INTEGER NOT NULL, signature TEXT NOT NULL, "
            "PRIMARY KEY (target, computer, channel)) WITHOUT ROWID"
        )

    @property
    def state_count(self) -> int:
        return int(self._db.execute("SELECT count(*) FROM continuity").fetchone()[0])

    def close(self) -> None:
        self._db.close()

    def observe(self, target: str, records: list[dict]) -> list[str]:
        gaps: dict[tuple[str, str], int] = {}
        unordered: set[tuple[str, str]] = set()
        malformed: set[tuple[str, str]] = set()
        reused: set[tuple[str, str]] = set()
        touched: set[tuple[str, str, str]] = set()
        for record in records:
            source = record.get("_source") or {}
            if not is_windows_source(source):
                continue
            winlog = source.get("winlog") or {}
            computer = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
            channel = str(winlog.get("channel") or "").strip()
            group = (computer or "<unknown-computer>", channel or "<unknown-channel>")
            value = winlog.get("record_id")
            if isinstance(value, bool):
                malformed.add(group)
                continue
            try:
                record_id = int(value)
            except (TypeError, ValueError):
                malformed.add(group)
                continue
            key = (target, *group)
            signature = windows_record_signature(record)
            row = self._db.execute(
                "SELECT last_id, samples, signature FROM continuity "
                "WHERE target = ? AND computer = ? AND channel = ?", key,
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO continuity VALUES (?, ?, ?, ?, ?, ?)",
                    (*key, record_id, 1, signature),
                )
                touched.add(key)
                continue
            prior, samples, prior_signature = row
            if record_id == prior:
                if prior_signature != signature:
                    reused.add(group)
                    self._db.execute(
                        "UPDATE continuity SET signature = ? "
                        "WHERE target = ? AND computer = ? AND channel = ?", (signature, *key),
                    )
                continue
            if record_id > prior:
                if record_id > prior + 1:
                    gaps[group] = gaps.get(group, 0) + record_id - prior - 1
                self._db.execute(
                    "UPDATE continuity SET last_id = ?, samples = ?, signature = ? "
                    "WHERE target = ? AND computer = ? AND channel = ?",
                    (record_id, min(2, samples + 1), signature, *key),
                )
                touched.add(key)
            else:
                # Time-ordered source results are not record-id ordered for this group. Refuse completeness
                # rather than retaining an event-count-sized set to reconstruct the sequence.
                unordered.add(group)
        reasons = [
            f"shipper gaps: {count} records missing on {channel} for {computer}"
            for (computer, channel), count in sorted(gaps.items())
        ]
        reasons += [
            f"record_id reused (log cleared or reverted) on {channel} for {computer}"
            for computer, channel in sorted(reused)
        ]
        reasons += [
            f"shipper gaps unresolved: record_id out of order on {channel} for {computer}"
            for computer, channel in sorted(unordered)
        ]
        reasons += [
            f"shipper gaps unresolved: non-numeric record_id on {channel} for {computer}"
            for computer, channel in sorted(malformed)
        ]
        reasons += [
            f"shipper gaps unresolved: fewer than two record_id samples on {channel} for {computer}"
            for _target, computer, channel in sorted(touched)
            if self._db.execute(
                "SELECT samples FROM continuity WHERE target = ? AND computer = ? AND channel = ?",
                (_target, computer, channel),
            ).fetchone()[0] < 2
        ]
        return reasons


def _get(source: dict, path: str):
    current = source
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def is_windows_source(source: dict) -> bool:
    """Require an Elastic Agent Windows dataset or Winlogbeat's own agent marker."""
    datasets = (_get(source, "data_stream.dataset"), _get(source, "event.dataset"))
    winlogbeat = str(_get(source, "agent.type") or "").casefold() == "winlogbeat"
    return any(isinstance(dataset, str) and dataset.casefold() in WINDOWS_DATASETS for dataset in datasets) or (
        winlogbeat and isinstance(source.get("winlog"), dict)
    )


def windows_record_key(hit: dict) -> tuple[str, str, str] | None:
    """Logical shipper identity used to deduplicate copies without trusting index or document ids."""
    source = hit.get("_source") or {}
    winlog = source.get("winlog") or {}
    computer = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
    channel = str(winlog.get("channel") or "").strip().casefold()
    record_id = winlog.get("record_id")
    if not computer or not channel or record_id in (None, "") or isinstance(record_id, bool):
        return None
    return computer, channel, str(record_id)


def windows_record_signature(hit: dict) -> str:
    """Stable content discriminator for copies that share a native record id.

    Shipper envelope fields such as index, document id, ingest time and agent metadata are deliberately
    excluded. Native event time is preferred; when it is unavailable the structured Windows payload is
    hashed so a log reset cannot collapse a different record onto an earlier event.
    """
    source = hit.get("_source") or {}
    winlog = source.get("winlog") or {}
    event_data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
    provider = str(winlog.get("provider_name") or "").strip().casefold()
    native_event_id = winlog.get("event_id")
    try:
        native_event_id = int(native_event_id)
    except (TypeError, ValueError):
        native_event_id = str(native_event_id or "").strip()
    native_time = (
        winlog.get("time_created")
        or event_data.get("TimeCreated")
        or event_data.get("SystemTime")
        or _get(source, "event.created")
    )
    if native_time not in (None, ""):
        identity = {"provider": provider, "event_id": native_event_id, "time_created": str(native_time)}
    else:
        identity = {
            "provider": provider,
            "event_id": native_event_id,
            "event_data": event_data,
            "user_data": winlog.get("user_data") if isinstance(winlog.get("user_data"), dict) else {},
            "event_original": _get(source, "event.original") or "",
        }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


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
        if tag == "TimeCreated" and element.attrib.get("SystemTime"):
            name = "TimeCreated"
            value = element.attrib["SystemTime"]
        elif tag == "Data" and element.attrib.get("Name"):
            name = element.attrib["Name"]
            value = element.text or ""
        elif element is not root and element.text and tag not in {"System", "EventData", "UserData"}:
            name = tag
            value = element.text
        else:
            continue
        if name in values:
            raise WindowsInputError(f"event.original XML contains duplicate field {name!r}")
        values[name] = fv(value, f"{native_id}:event.original:{name}#xml")
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
    time_created = winlog.get("time_created")
    if time_created not in (None, "") and "TimeCreated" not in data:
        data["TimeCreated"] = fv(time_created, f"{hit['_id']}:winlog.time_created")
    _parsed_hashes(data)
    return WindowsRecord(hit, event_class, data)


def _raw_ref(hit: dict) -> RawRef:
    encoded = json.dumps(hit["_source"], sort_keys=True, separators=(",", ":")).encode()
    return RawRef(
        target=hit["_index"],
        native_id=hit["_id"],
        digest=hashlib.sha256(encoded).hexdigest(),
    )


def windows_path_key(path: object) -> str:
    """Comparison form for a Windows path; display fields retain the source spelling."""
    return ntpath.normpath(str(path).replace("/", "\\")).casefold()


def _guid(value: object) -> str:
    match = _GUID.fullmatch(str(value).strip())
    if match is None:
        return ""
    normalized = match.group(1).casefold()
    return "" if normalized == "00000000-0000-0000-0000-000000000000" else normalized


def _integer(value: object) -> int:
    if isinstance(value, bool):
        raise WindowsInputError("boolean is not an integer event field")
    return int(str(value), 0)


def _event_time(value: object) -> datetime:
    text = str(value).strip().replace(" ", "T", 1)
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _native_value_is_absent(name: str, value: object) -> bool:
    if value in (None, ""):
        return True
    return str(value).strip().casefold() in _ABSENT_FIELD_VALUES.get(name, frozenset())


def _put(fields: dict[str, FieldValue], record: WindowsRecord, typed: str, *native: str, transform=None) -> None:
    for name in native:
        item = record.data.get(name)
        if item is None or _native_value_is_absent(name, item.value):
            continue
        try:
            value = transform(item.value) if transform else item.value
        except (TypeError, ValueError) as exc:
            raise WindowsInputError(f"{name} is malformed: {exc}") from exc
        if value in (None, ""):
            continue
        fields[typed] = fv(value, item.origin)
        return


def _account(record: WindowsRecord, prefix: str) -> tuple[str | None, str | None, str | None, str | None]:
    sid_field = f"{prefix}UserSid"
    domain_field = f"{prefix}DomainName"
    name_field = f"{prefix}UserName"
    sid = record.value(sid_field)
    domain = record.value(domain_field)
    name = record.value(name_field)
    sid = None if _native_value_is_absent(sid_field, sid) else str(sid).strip()
    domain = None if _native_value_is_absent(domain_field, domain) else str(domain).strip()
    name = None if _native_value_is_absent(name_field, name) else str(name).strip()
    sid_text = str(sid).strip() if sid is not None else ""
    if _SID.fullmatch(sid_text):
        key = f"sid:{sid_text.casefold()}"
        origin = record.origin(sid_field)
    elif name:
        joined = f"{domain}\\{name}" if domain and str(domain) not in {"-", "."} else str(name)
        key = f"name:{joined.casefold()}"
        origin = record.origin(name_field)
    else:
        key = None
        origin = None
    return key, str(domain).casefold() if domain else None, str(name).casefold() if name else None, origin


def _account_fields(fields: dict[str, FieldValue], record: WindowsRecord) -> None:
    subject, subject_domain, subject_name, subject_origin = _account(record, "Subject")
    target, target_domain, target_name, target_origin = _account(record, "Target")
    if subject:
        fields["user.entity_id"] = fv(subject, subject_origin)
    if subject_name:
        fields["user.name"] = fv(subject_name, record.origin("SubjectUserName"))
    if subject_domain:
        fields["user.domain"] = fv(subject_domain, record.origin("SubjectDomainName"))
    if not subject and record.value("User"):
        user = str(record.value("User")).strip()
        domain, separator, name = user.partition("\\")
        canonical = user.casefold()
        fields["user.entity_id"] = fv(f"name:{canonical}", record.origin("User"))
        fields["user.name"] = fv((name if separator else domain).casefold(), record.origin("User"))
        if separator:
            fields["user.domain"] = fv(domain.casefold(), record.origin("User"))
    if target:
        fields["auth.target_account"] = fv(target, target_origin)
        fields["auth.target_user"] = fv(target, target_origin)
    if target_name:
        fields["account.name"] = fv(target_name, record.origin("TargetUserName"))
    if target_domain:
        fields["account.domain"] = fv(target_domain, record.origin("TargetDomainName"))


def _process_fields(fields: dict[str, FieldValue], record: WindowsRecord, host: str) -> None:
    event_id = record.event_class.event_id
    _put(fields, record, "process.command_line", "CommandLine")
    _put(fields, record, "process.executable", "Image", "NewProcessName", "ProcessName")
    _put(fields, record, "process.parent.executable", "ParentImage")
    if event_id == 4688:
        _put(fields, record, "process.pid", "NewProcessId", transform=_integer)
        _put(fields, record, "process.ppid", "ProcessId", "CreatorProcessId", transform=_integer)
    else:
        _put(fields, record, "process.pid", "ProcessId", transform=_integer)
        if event_id == 1:
            _put(fields, record, "process.ppid", "ParentProcessId", transform=_integer)
    _put(fields, record, "process.guid", "ProcessGuid", transform=_guid)
    _put(fields, record, "process.parent.guid", "ParentProcessGuid", transform=_guid)
    guid = fields.get("process.guid")
    pid = fields.get("process.pid")
    if guid:
        fields["process.entity_id"] = fv(f"guid:{guid.value}", guid.origin)
        fields["process.id_kind"] = fv("guid", guid.origin)
    elif pid:
        fields["process.entity_id"] = fv(f"pid:{host}:{pid.value}", pid.origin)
        fields["process.id_kind"] = fv("fenced_pid", pid.origin)
    parent_guid = fields.get("process.parent.guid")
    if parent_guid:
        fields["process.parent.entity_id"] = fv(f"guid:{parent_guid.value}", parent_guid.origin)
    executable = fields.get("process.executable")
    if executable:
        fields["process.executable_key"] = fv(windows_path_key(executable.value), executable.origin)
    parent = fields.get("process.parent.executable")
    if parent:
        fields["process.parent.executable_key"] = fv(windows_path_key(parent.value), parent.origin)
    for algorithm in ("MD5", "SHA1", "SHA256", "IMPHASH"):
        _put(fields, record, f"file.hash.{algorithm.casefold()}", f"Hashes.{algorithm}")
    if event_id in {4689, 5}:
        fields["process.fence"] = fv("termination", fields.get("event.code", fv(event_id, "catalog")).origin)


_AUTH_ACTIONS = {
    4624: "logon",
    4625: "logon",
    4648: "explicit_credentials",
    4672: "special_privileges",
    4634: "logoff",
    4647: "logoff",
}
_ACCOUNT_ACTIONS = {
    4720: "create",
    4722: "enable",
    4724: "password_reset",
    4726: "delete",
    4728: "add_to_global_group",
    4732: "add_to_local_group",
    4756: "add_to_universal_group",
    4738: "modify",
    4740: "lockout",
}

# These identifiers belong to Windows itself, not portable user sessions.
_WELL_KNOWN_LOGON_IDS = {"0x3e4", "0x3e5", "0x3e7"}


def _semantic_fields(fields: dict[str, FieldValue], record: WindowsRecord, host: str) -> Outcome:
    event_id, family = record.event_class.event_id, record.event_class.family
    _account_fields(fields, record)
    if family in {"process_exec", "process_termination"}:
        _process_fields(fields, record, host)
        return Outcome.success
    if family == "net_socket":
        _process_fields(fields, record, host)
        for typed, native, transform in (
            ("source.ip", "SourceIp", None),
            ("source.port", "SourcePort", _integer),
            ("destination.ip", "DestinationIp", None),
            ("destination.port", "DestinationPort", _integer),
            ("network.transport", "Protocol", lambda value: str(value).casefold()),
            ("network.direction", "Initiated", lambda value: "egress" if str(value).casefold() == "true" else "ingress"),
        ):
            _put(fields, record, typed, native, transform=transform)
        return Outcome.success
    if family == "auth":
        fields["auth.action"] = fv(_AUTH_ACTIONS[event_id], fields["event.code"].origin)
        _put(fields, record, "auth.logon_type", "LogonType", transform=_integer)
        _put(fields, record, "source.ip", "IpAddress")
        _put(fields, record, "source.port", "IpPort", transform=_integer)
        session = record.data.get("TargetLogonId") or record.data.get("SubjectLogonId")
        if (session and str(session.value).casefold()
                not in {"", "0", "0x0", *_WELL_KNOWN_LOGON_IDS}):
            session_id = str(session.value).casefold()
            fields["auth.session_id"] = fv(session_id, session.origin)
            fields["auth.session_key"] = fv(f"{host}:{session_id}", session.origin)
        _put(fields, record, "auth.logon_guid", "LogonGuid", transform=_guid)
        return Outcome.failure if event_id == 4625 else Outcome.success
    if family == "account_change":
        fields["account.action"] = fv(_ACCOUNT_ACTIONS[event_id], fields["event.code"].origin)
        _put(fields, record, "account.member_id", "MemberSid")
        _put(fields, record, "account.member_name", "MemberName", transform=lambda value: str(value).casefold())
        _put(fields, record, "account.group_id", "TargetSid")
        _put(fields, record, "account.group_name", "TargetUserName", transform=lambda value: str(value).casefold())
        return Outcome.success
    if family == "service_change":
        _put(fields, record, "service.name", "ServiceName")
        _put(fields, record, "service.image_path", "ImagePath", "ServiceFileName")
        _put(fields, record, "service.start_type", "StartType", "ServiceStartType")
        _put(fields, record, "service.account", "AccountName", "ServiceAccount")
        _put(fields, record, "service.type", "ServiceType")
        return Outcome.success
    if family == "scheduled_task":
        fields["task.action"] = fv("created" if event_id == 4698 else "updated", fields["event.code"].origin)
        _put(fields, record, "task.name", "TaskName")
        _put(fields, record, "task.xml", "TaskContent")
        return Outcome.success
    if family == "audit_config":
        action = "audit_policy_changed" if event_id == 4719 else "log_cleared"
        fields["audit.config.action"] = fv(action, fields["event.code"].origin)
        _put(fields, record, "audit.config.subcategory_guid", "SubcategoryGuid", transform=_guid)
        _put(fields, record, "audit.config.changes", "AuditPolicyChanges")
        return Outcome.success
    if family == "system_state":
        state = "boot_start" if event_id in {12, 6005} else "boot_stop"
        fields["system.event"] = fv(state, fields["event.code"].origin)
        fields["process.fence"] = fv("boot", fields["event.code"].origin)
        return Outcome.success
    return Outcome.unknown


def normalize_windows(hit: dict) -> TypedEvent:
    """Normalize one cataloged Windows event from structured shipper fields only."""
    record = read_windows_event(hit)
    source, winlog = hit["_source"], hit["_source"]["winlog"]
    ref = _raw_ref(hit)
    computer = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
    if not computer:
        raise WindowsInputError("Windows record is missing winlog.computer_name")
    # Host keys intentionally use the short computer name so Windows events join the existing host-centric
    # detectors and pivots. This merges same-named computers from different DNS/AD domains; the full source name
    # remains in host.full_name and winlog.computer_name so the ambiguity is visible in cited evidence.
    host = computer.split(".", 1)[0]
    fields = {
        "event.code": fv(record.event_class.event_id, f"{hit['_id']}:winlog.event_id"),
        "event.channel": fv(record.event_class.channel, f"{hit['_id']}:winlog.channel"),
        "event.provider": fv(record.event_class.provider, f"{hit['_id']}:winlog.provider_name"),
        "host.os.family": fv("windows", f"{hit['_id']}:winlog.computer_name#known-os"),
        "host.name": fv(host, f"{hit['_id']}:winlog.computer_name#short-name"),
        "host.full_name": fv(computer, f"{hit['_id']}:winlog.computer_name"),
        "winlog.computer_name": fv(computer, f"{hit['_id']}:winlog.computer_name"),
    }
    record_id = winlog.get("record_id")
    if record_id is not None:
        try:
            fields["winlog.record_id"] = fv(int(record_id), f"{hit['_id']}:winlog.record_id")
        except (TypeError, ValueError) as exc:
            raise WindowsInputError(f"winlog.record_id is malformed: {exc}") from exc
    fields.update({f"windows.event_data.{name}": value for name, value in record.data.items()})
    timestamp = datetime.fromisoformat(str(source["@timestamp"])).astimezone(UTC)
    event_time = (
        record.data.get("UtcTime")
        or record.data.get("TimeCreated")
        or record.data.get("SystemTime")
    )
    if event_time:
        timestamp = _event_time(event_time.value)
        fields["event.created"] = fv(timestamp.isoformat(), event_time.origin)
    fields["event.ingested"] = fv(
        datetime.fromisoformat(str(source["@timestamp"])).astimezone(UTC).isoformat(),
        f"{hit['_id']}:@timestamp",
    )
    outcome = _semantic_fields(fields, record, host)
    logical_key = windows_record_key(hit)
    identity_refs = [ref] if logical_key is None else [RawRef(
        target=f"windows:{logical_key[0]}:{logical_key[1]}:{logical_key[2]}",
        native_id=windows_record_signature(hit),
    )]
    return TypedEvent(
        id=event_id(record.event_class.family, identity_refs, WINDOWS_NORMALIZER),
        family=record.event_class.family,
        ts=timestamp,
        host=host,
        outcome=outcome,
        fields=fields,
        raw=[ref],
        normalizer=WINDOWS_NORMALIZER,
    )
