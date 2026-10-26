"""Windows shipper dispatch and structured-field extraction."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import ntpath
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from xml.etree import ElementTree

from romulus.evidence.community import community_id
from romulus.evidence.typed import FieldValue, Outcome, RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows_catalog import WINDOWS_DATASETS, WindowsEventClass, lookup_event_class

if TYPE_CHECKING:
    from romulus.detect.bounded import Account, StateBudget

WINDOWS_NORMALIZER = "windows-ecs@3"
# This is already far beyond what the 64 MiB assembler can retain at normal 4104 chunk sizes, while bounding every
# completeness vector even when hostile metadata claims billions of parts.
SCRIPT_BLOCK_MAX_PARTS = 4_096
_GUID = re.compile(r"^\{?([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}?$")
_SID = re.compile(r"^S-\d+(?:-\d+)+$", re.IGNORECASE)
_GUID_IN_TEXT = re.compile(r"\{?([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}?")
_SHORT_PATH = re.compile(r"(?:^|\\)[^\\]*~\d(?:\\|$)", re.IGNORECASE)
_TASK_XML_MAX_BYTES = 1_048_576
_POWERSHELL_DATA_MAX_BYTES = 65_536
_DETAILS_MAX_CHARS = 32_768
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
    "WorkstationName": frozenset({"-"}),
    "SourceNetworkAddress": frozenset({"-", "::", "0", "0.0.0.0"}),
    "ClientAddress": frozenset({"-", "::", "0", "0.0.0.0"}),
    "ClientName": frozenset({"-"}),
}

_MESSAGE_CODES = {
    "%%14674": "value_added",
    "%%14675": "value_deleted",
    "%%1842": True,
    "%%1843": False,
    "%%1904": "new_registry_value_created",
    "%%1905": "existing_registry_value_modified",
    "%%1936": "default",
    "%%1937": "full",
    "%%1938": "limited",
    "%%1832": "identification",
    "%%1833": "impersonation",
    "%%2313": "unknown_user_name_or_bad_password",
}

# Security account-management events store changed UAC flags as message-resource ids. The named ids are
# documented by the UserAccountControl flag table and the 4720/4738/4741/4742 event schemas. Undefined bit ids
# are deliberately absent so they produce a caveat rather than an invented meaning.
_UAC_MESSAGE_CODES = {
    "%%2048": "account_enabled",
    "%%2049": "home_directory_required_disabled",
    "%%2050": "password_not_required_disabled",
    "%%2051": "temp_duplicate_account_disabled",
    "%%2052": "normal_account_disabled",
    "%%2053": "mns_logon_account_disabled",
    "%%2054": "interdomain_trust_account_disabled",
    "%%2055": "workstation_trust_account_disabled",
    "%%2056": "server_trust_account_disabled",
    "%%2057": "dont_expire_password_disabled",
    "%%2058": "account_unlocked",
    "%%2059": "encrypted_text_password_allowed_disabled",
    "%%2060": "smartcard_required_disabled",
    "%%2061": "trusted_for_delegation_disabled",
    "%%2062": "not_delegated_disabled",
    "%%2063": "use_des_key_only_disabled",
    "%%2064": "dont_require_preauth_disabled",
    "%%2065": "password_expired_disabled",
    "%%2066": "trusted_to_auth_for_delegation_disabled",
    "%%2067": "exclude_authorization_information_disabled",
    "%%2069": "protect_kerberos_service_tickets_with_aes_keys_disabled",
    "%%2080": "account_disabled",
    "%%2081": "home_directory_required_enabled",
    "%%2082": "password_not_required_enabled",
    "%%2083": "temp_duplicate_account_enabled",
    "%%2084": "normal_account_enabled",
    "%%2085": "mns_logon_account_enabled",
    "%%2086": "interdomain_trust_account_enabled",
    "%%2087": "workstation_trust_account_enabled",
    "%%2088": "server_trust_account_enabled",
    "%%2089": "dont_expire_password_enabled",
    "%%2090": "account_locked",
    "%%2091": "encrypted_text_password_allowed_enabled",
    "%%2092": "smartcard_required_enabled",
    "%%2093": "trusted_for_delegation_enabled",
    "%%2094": "not_delegated_enabled",
    "%%2095": "use_des_key_only_enabled",
    "%%2096": "dont_require_preauth_enabled",
    "%%2097": "password_expired_enabled",
    "%%2098": "trusted_to_auth_for_delegation_enabled",
    "%%2099": "exclude_authorization_information_enabled",
    "%%2101": "protect_kerberos_service_tickets_with_aes_keys_enabled",
}

_ACCESS_CODES = {
    "%%1537": "delete",
    "%%1538": "read_control",
    "%%1539": "write_dac",
    "%%1540": "write_owner",
    "%%1541": "synchronize",
    "%%1542": "access_system_security",
    "%%4416": "read_data_or_list_directory",
    "%%4417": "write_data_or_add_file",
    "%%4418": "append_data_or_add_subdirectory_or_create_pipe_instance",
    "%%4419": "read_extended_attributes",
    "%%4420": "write_extended_attributes",
    "%%4421": "execute_or_traverse",
    "%%4422": "delete_child",
    "%%4423": "read_attributes",
    "%%4424": "write_attributes",
}

_REGISTRY_ROOTS = {
    "hklm": "hkey_local_machine",
    "hkey_local_machine": "hkey_local_machine",
    r"\registry\machine": "hkey_local_machine",
    "hkcu": "hkey_current_user",
    "hkey_current_user": "hkey_current_user",
    "hkcr": "hkey_classes_root",
    "hkey_classes_root": "hkey_classes_root",
    "hku": "hkey_users",
    "hkey_users": "hkey_users",
    r"\registry\user": "hkey_users",
}

# Extended-right GUIDs are stable schema identifiers documented by Microsoft, not site-local guesses.
# https://learn.microsoft.com/windows/win32/adschema/extended-rights
_DIRECTORY_RIGHT_GUIDS = {
    "00299570-246d-11d0-a768-00aa006e0529": "user-force-change-password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "ds-replication-get-changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "ds-replication-get-changes-all",
    "89e95b76-444d-4c62-991a-0facbeda640c": "ds-replication-get-changes-filtered-set",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "user-change-password",
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
    caveats: list[str]

    def value(self, name: str, default=None):
        field = self.data.get(name)
        return default if field is None else field.value

    def origin(self, name: str) -> str:
        return self.data[name].origin


class RecordIdContinuity:
    """Streaming record-id and timestamp gap state spilled to a private SQLite file.

    State remains one row per (target, computer, channel), never one entry per record. A caller-owned directory
    puts the file under the hunt stage; standalone uses get its own private temporary directory.
    """

    def __init__(self, directory: str | Path | None = None, *, budget: StateBudget | None = None,
                 account: Account | None = None) -> None:
        self._tempdir = Path(tempfile.mkdtemp(prefix="romulus-windows-continuity-")) if directory is None else None
        root = self._tempdir if self._tempdir is not None else Path(directory)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self.path = root / "windows-continuity.db"
        self._db = sqlite3.connect(self.path)
        self.path.chmod(0o600)
        self._db.execute(
            "CREATE TABLE continuity ("
            "target TEXT NOT NULL, computer TEXT NOT NULL, channel TEXT NOT NULL, "
            "last_id INTEGER NOT NULL, samples INTEGER NOT NULL, signature TEXT NOT NULL, last_time TEXT, "
            "PRIMARY KEY (target, computer, channel)) WITHOUT ROWID"
        )
        self._db.commit()
        self._page = self._db.execute("PRAGMA page_size").fetchone()[0]
        self._size = 0
        self.budget = budget
        self.account = account
        self._charge_growth()

    def _cap(self) -> None:
        if self.budget is None:
            return
        headroom = self.budget.headroom()
        if headroom is None:
            return
        pages = self._db.execute("PRAGMA page_count").fetchone()[0]
        self._db.execute(f"PRAGMA max_page_count = {pages + headroom // self._page + 1}")

    def _charge_growth(self) -> None:
        size = self._db.execute("PRAGMA page_count").fetchone()[0] * self._page
        growth = size - self._size
        if growth > 0 and self.budget is not None and self.account is not None:
            self.budget.charge(self.account, growth)
            self.budget.grew(growth)
        self._size = size

    def _checkpoint(self) -> None:
        self._db.commit()
        self._charge_growth()
        self._cap()

    @property
    def state_count(self) -> int:
        return int(self._db.execute("SELECT count(*) FROM continuity").fetchone()[0])

    def close(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
            self._db = None
        if getattr(self, "_tempdir", None) is not None:
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()

    def observe(
        self,
        target: str,
        records: list[dict],
        *,
        liveness_tolerance=None,
    ) -> list[str]:
        gaps: dict[tuple[str, str], int] = {}
        time_gaps: dict[tuple[str, str], tuple[float, str, str]] = {}
        unordered: set[tuple[str, str]] = set()
        malformed: set[tuple[str, str]] = set()
        reused: set[tuple[str, str]] = set()
        # Refusal reasons are controlled state-budget text, so aggregate groups by reason and retain only a sample.
        # A 5,000-host outage must not manufacture a 5,000-line in-memory coverage report.
        refused: dict[tuple[str, str], list] = {}
        refused_groups: set[tuple[str, str, str]] = set()

        def record_refusal(group: tuple[str, str], reason: str) -> None:
            computer, channel = group
            group_key = (reason, channel, computer)
            if group_key in refused_groups:
                return
            refused_groups.add(group_key)
            state = refused.setdefault((reason, channel), [0, []])
            state[0] += 1
            if len(state[1]) < 10:
                state[1].append(computer)
        touched: set[tuple[str, str, str]] = set()
        new_rows = 0
        self._cap()
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
            raw_time = winlog.get("time_created") or source.get("@timestamp")
            try:
                when = datetime.fromisoformat(str(raw_time)).astimezone(UTC)
            except (TypeError, ValueError):
                when = None
            row = self._db.execute(
                "SELECT last_id, samples, signature, last_time FROM continuity "
                "WHERE target = ? AND computer = ? AND channel = ?", key,
            ).fetchone()
            if row is None:
                reason = (self.budget.new_key_reason(self.account)
                          if self.budget is not None and self.account is not None else "")
                if reason:
                    record_refusal(group, reason)
                    continue
                try:
                    self._db.execute(
                        "INSERT INTO continuity VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (*key, record_id, 1, signature, when.isoformat() if when is not None else None),
                    )
                except sqlite3.OperationalError as exc:
                    self._db.rollback()
                    reason = f"writing Windows continuity state failed ({exc})"
                    if self.budget is not None:
                        self.budget.fail(reason)
                    record_refusal(group, reason)
                    continue
                touched.add(key)
                new_rows += 1
                if new_rows % 128 == 0:
                    self._checkpoint()
                continue
            if self.budget is not None and self.budget.hard:
                record_refusal(group, self.budget.hard)
                continue
            prior, samples, prior_signature, prior_time_text = row
            prior_time = None
            if prior_time_text:
                try:
                    prior_time = datetime.fromisoformat(prior_time_text).astimezone(UTC)
                except ValueError:  # only this class writes the column; fail closed if storage is damaged
                    prior_time = None
            if when is not None and prior_time is not None and when > prior_time:
                elapsed = when - prior_time
                if liveness_tolerance is not None and elapsed > liveness_tolerance:
                    candidate = (elapsed.total_seconds(), prior_time.isoformat(), when.isoformat())
                    if group not in time_gaps or candidate[0] > time_gaps[group][0]:
                        time_gaps[group] = candidate
            latest_time = when if when is not None and (prior_time is None or when > prior_time) else prior_time
            if record_id == prior:
                if prior_signature != signature:
                    reused.add(group)
                self._db.execute(
                    "UPDATE continuity SET signature = ?, last_time = ? "
                    "WHERE target = ? AND computer = ? AND channel = ?",
                    (signature, latest_time.isoformat() if latest_time is not None else None, *key),
                )
                continue
            if record_id > prior:
                if record_id > prior + 1:
                    gaps[group] = gaps.get(group, 0) + record_id - prior - 1
                self._db.execute(
                    "UPDATE continuity SET last_id = ?, samples = ?, signature = ?, last_time = ? "
                    "WHERE target = ? AND computer = ? AND channel = ?",
                    (record_id, min(2, samples + 1), signature,
                     latest_time.isoformat() if latest_time is not None else None, *key),
                )
                touched.add(key)
            else:
                # Time-ordered source results are not record-id ordered for this group. Refuse completeness
                # rather than retaining an event-count-sized set to reconstruct the sequence.
                unordered.add(group)
        self._checkpoint()
        def mapped_by_channel(values: dict) -> dict[str, list[tuple[str, object]]]:
            grouped: dict[str, list[tuple[str, object]]] = {}
            for (computer, channel), value in sorted(values.items()):
                grouped.setdefault(channel, []).append((computer, value))
            return grouped

        def groups_by_channel(values: set[tuple[str, str]]) -> dict[str, list[str]]:
            grouped: dict[str, list[str]] = {}
            for computer, channel in sorted(values):
                grouped.setdefault(channel, []).append(computer)
            return grouped

        reasons: list[str] = []
        for channel, groups in sorted(mapped_by_channel(gaps).items()):
            if len(groups) <= 10:
                reasons += [
                    f"shipper gaps: {count} records missing on {channel} for {computer}"
                    for computer, count in groups
                ]
            else:
                sample = ", ".join(computer for computer, _count in groups[:10])
                reasons.append(
                    f"shipper gaps: {sum(int(count) for _computer, count in groups):,} records missing "
                    f"across {len(groups):,} hosts on {channel} (sample: {sample})"
                )
        for channel, groups in sorted(mapped_by_channel(time_gaps).items()):
            if len(groups) <= 10:
                reasons += [
                    f"no records from {computer}/{channel} between {gap[1]} and {gap[2]}"
                    for computer, gap in groups
                ]
            else:
                sample = "; ".join(
                    f"{computer} between {gap[1]} and {gap[2]}" for computer, gap in groups[:10]
                )
                reasons.append(
                    f"no-record time gaps for {len(groups):,} hosts on {channel} (sample: {sample})"
                )
        for channel, computers in sorted(groups_by_channel(reused).items()):
            if len(computers) <= 10:
                reasons += [
                    f"record_id reused (log cleared or reverted) on {channel} for {computer}"
                    for computer in computers
                ]
            else:
                reasons.append(
                    f"record_id reused (log cleared or reverted) for {len(computers):,} hosts on {channel} "
                    f"(sample: {', '.join(computers[:10])})"
                )
        for label, groups, detail in (
            ("record_id out of order", unordered, "shipper gaps unresolved: record_id out of order"),
            ("non-numeric record_id", malformed, "shipper gaps unresolved: non-numeric record_id"),
        ):
            for channel, computers in sorted(groups_by_channel(groups).items()):
                if len(computers) <= 10:
                    reasons += [f"{detail} on {channel} for {computer}" for computer in computers]
                else:
                    reasons.append(
                        f"shipper gaps unresolved: {label} for {len(computers):,} hosts on {channel} "
                        f"(sample: {', '.join(computers[:10])})"
                    )
        for (reason, channel), (count, samples) in sorted(refused.items()):
            if count <= 10:
                reasons += [
                    f"shipper gaps unresolved: continuity state refused on {channel} for {computer}: {reason}"
                    for computer in sorted(samples)
                ]
            else:
                sample = ", ".join(sorted(samples))
                reasons.append(
                    f"shipper gaps unresolved: continuity state refused for {count:,} host/channel groups on "
                    f"{channel} (sample: {sample}): {reason}"
                )
        short: dict[str, list[str]] = {}
        short_counts: dict[str, int] = {}
        for _target, computer, channel in sorted(touched):
            row = self._db.execute(
                "SELECT samples FROM continuity WHERE target = ? AND computer = ? AND channel = ?",
                (_target, computer, channel),
            ).fetchone()
            if row is not None and row[0] < 2:
                short_counts[channel] = short_counts.get(channel, 0) + 1
                samples = short.setdefault(channel, [])
                if len(samples) < 10:
                    samples.append(computer)
        for channel, channel_count in sorted(short_counts.items()):
            computers = short[channel]
            if channel_count <= 10:
                reasons += [
                    f"shipper gaps unresolved: fewer than two record_id samples on {channel} for {computer}"
                    for computer in computers
                ]
            else:
                reasons.append(
                    f"shipper gaps unresolved: fewer than two record_id samples for {channel_count:,} "
                    f"host/channel groups on {channel} (sample: {', '.join(computers)})"
                )
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
    excluded. Native event time and a digest of the structured Windows payload are always included, so exact
    copies merge while same-instant native records with different content do not.
    """
    source = hit.get("_source") or {}
    winlog = source.get("winlog") or {}
    native_event_id = winlog.get("event_id")
    try:
        native_event_id = int(native_event_id)
    except (TypeError, ValueError):
        native_event_id = str(native_event_id or "").strip()
    event_class = lookup_event_class(winlog.get("channel"), winlog.get("provider_name"), native_event_id)
    provider = (
        event_class.provider.casefold()
        if event_class is not None
        else str(winlog.get("provider_name") or "").strip().casefold()
    )
    native: dict[str, object] = {}
    for container in ("event_data", "user_data"):
        content = winlog.get(container)
        if isinstance(content, dict):
            native.update(content)
    original = _get(source, "event.original")
    if not native and isinstance(original, str) and original:
        try:
            native = {name: item.value for name, item in _xml_data(original, "signature").items()}
        except WindowsInputError:
            native = {"event.original": original}
    native_time = (
        winlog.get("time_created")
        or native.get("TimeCreated")
        or native.get("SystemTime")
        or _get(source, "event.created")
    )
    if native_time not in (None, ""):
        native.setdefault("TimeCreated", native_time)
    # Shippers vary only the spelling of some native names (for example Defender's ``Threat Name``,
    # ``Threat_Name`` and ``ThreatName``). Collapse those separators without changing payload values.
    payload: dict[str, list[object]] = {}
    for name, value in native.items():
        canonical_name = re.sub(r"[\s_]+", "", str(name)).casefold()
        payload.setdefault(canonical_name, []).append(value)
    payload = {name: sorted(values, key=lambda value: json.dumps(value, sort_keys=True, default=str))
               for name, values in payload.items()}
    payload_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    identity = {
        "provider": provider,
        "event_id": native_event_id,
        "time_created": str(native_time or ""),
        "payload_digest": payload_digest,
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
    for native_name in ("Hashes", "Hash"):
        hashes = data.get(native_name)
        if hashes is None or not isinstance(hashes.value, str):
            continue
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
    return WindowsRecord(hit, event_class, data, [])


def _raw_ref(hit: dict) -> RawRef:
    encoded = json.dumps(hit["_source"], sort_keys=True, separators=(",", ":")).encode()
    return RawRef(
        target=hit["_index"],
        native_id=hit["_id"],
        digest=hashlib.sha256(encoded).hexdigest(),
    )


def windows_path_key(path: object) -> str:
    """Comparison form for a Windows path without expanding aliases or guessing drive letters."""
    text = str(path).strip().strip('"').replace("/", "\\")
    lowered = text.casefold()
    if lowered.startswith(("\\\\?\\unc\\", "\\??\\unc\\")):
        text = "\\\\" + text[8:]
    elif text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
    return ntpath.normpath(text).casefold()


def _prefix_preserving_windows_path_key(path: object) -> str:
    """Comparison spelling that retains an extended-path prefix supplied by the record."""
    return ntpath.normpath(str(path).replace("/", "\\")).casefold()


def registry_path_key(path: object) -> str:
    """Canonical registry comparison key; architecture and control-set distinctions remain visible."""
    text = re.sub(r"\\+", r"\\", str(path).strip().replace("/", "\\")).casefold()
    for native, canonical in sorted(_REGISTRY_ROOTS.items(), key=lambda item: -len(item[0])):
        if text == native or text.startswith(native + "\\"):
            return canonical + text[len(native):]
    return text


def _guid(value: object) -> str:
    match = _GUID.fullmatch(str(value).strip())
    if match is None:
        raise ValueError("not a GUID")
    normalized = match.group(1).casefold()
    return "" if normalized == "00000000-0000-0000-0000-000000000000" else normalized


def _integer(value: object) -> int:
    if isinstance(value, bool):
        raise WindowsInputError("boolean is not an integer event field")
    text = str(value).strip()
    return int(text, 0) if text.casefold().startswith("0x") else int(text, 10)


def _boolean(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().casefold()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    mapped = _MESSAGE_CODES.get(text)
    if isinstance(mapped, bool):
        return mapped
    raise ValueError(f"unknown boolean/message code {value!r}")


def _message_value(value: object) -> object:
    text = str(value).strip().casefold()
    if not text.startswith("%%"):
        return value
    if text not in _MESSAGE_CODES:
        raise ValueError(f"unknown Windows message code {value!r}")
    return _MESSAGE_CODES[text]


def _ip(value: object) -> str:
    address = ipaddress.ip_address(str(value).strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _hostname(value: object) -> str:
    return str(value).strip().rstrip(".").casefold()


def _string_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        values = value
    else:
        values = re.split(r"[\r\n;,]+", str(value))
    return [text for item in values if (text := str(item).strip()) and text != "-"]


def _key_value_lines(value: object) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in str(value).splitlines():
        match = re.match(r"^\s*([^:=]+?)\s*(?:=|:)\s*(.*?)\s*$", line)
        if match and match.group(1).strip() and match.group(2).strip():
            parsed[match.group(1).strip()] = match.group(2).strip()
    return parsed


def _dns_answer_parts(value: object) -> tuple[list[str], list[str]]:
    addresses: list[str] = []
    names: list[str] = []
    for answer in _string_list(value):
        candidate = answer.strip()
        typed = re.fullmatch(r"type\s*:\s*(\d+)\s+(.+)", candidate, re.IGNORECASE)
        record_type = typed.group(1) if typed else None
        if typed:
            candidate = typed.group(2).strip()
            if record_type not in {"1", "5", "28"}:
                continue
        if record_type == "5":
            normalized_name = candidate.rstrip(".").casefold()
            if normalized_name and normalized_name not in names:
                names.append(normalized_name)
            continue
        try:
            normalized = _ip(candidate)
        except ValueError:
            if record_type is not None:
                continue
            normalized_name = candidate.rstrip(".").casefold()
            if normalized_name and normalized_name not in names:
                names.append(normalized_name)
        else:
            if normalized not in addresses:
                addresses.append(normalized)
    return addresses, names


def _call_trace_modules(value: object) -> list[str]:
    modules: list[str] = []
    for frame in re.split(r"[|;,\r\n]+", str(value)):
        module, separator, _offset = frame.strip().partition("+")
        if separator and module and module not in modules:
            modules.append(module)
    return modules


def _uac_changes(record: WindowsRecord) -> tuple[list[str], str] | None:
    item = record.data.get("UserAccountControl")
    if item is None or _native_value_is_absent("UserAccountControl", item.value):
        return None
    changes: list[str] = []
    for token in re.findall(r"%%\d+|[^\s,;]+", str(item.value)):
        if token.startswith("%%"):
            change = _UAC_MESSAGE_CODES.get(token)
            if change is None:
                record.caveats.append(
                    f"UserAccountControl contains unknown Windows message code {token!r}; it was omitted"
                )
                continue
        else:
            change = token
        if change not in changes:
            changes.append(change)
    return (changes, item.origin) if changes else None


def _powershell_data_fields(fields: dict[str, FieldValue], record: WindowsRecord) -> None:
    item = record.data.get("Data")
    if item is None or _native_value_is_absent("Data", item.value):
        return
    values = item.value if isinstance(item.value, (list, tuple)) else (item.value,)
    text = "\n".join(str(value) for value in values)
    if len(text.encode("utf-8")) > _POWERSHELL_DATA_MAX_BYTES:
        record.caveats.append(f"Data exceeds {_POWERSHELL_DATA_MAX_BYTES} bytes and was not parsed")
        return
    parsed = {key.casefold(): value for key, value in _key_value_lines(text).items()}
    for typed, native in (
        ("script.host_application", "HostApplication"),
        ("script.engine_version", "EngineVersion"),
    ):
        value = parsed.get(native.casefold())
        if typed not in fields and value not in (None, ""):
            fields[typed] = fv(value, item.origin + "#parsed:powershell-data")


def _access_fields(
    fields: dict[str, FieldValue], record: WindowsRecord, typed: str, native: str = "AccessList",
) -> None:
    item = record.data.get(native)
    if item is None or _native_value_is_absent(native, item.value):
        return
    names: list[str] = []
    codes: list[str] = []
    for token in re.findall(r"%%\d+|[^\s,;]+", str(item.value)):
        if token.startswith("%%"):
            name = _ACCESS_CODES.get(token)
            if name is None:
                record.caveats.append(f"{native} contains unknown Windows message code {token!r}; it was omitted")
                continue
            codes.append(token)
            names.append(name)
        else:
            names.append(token)
    if names:
        fields[typed] = fv(names, item.origin + "#parsed:access-names")
    if codes:
        fields[f"{typed.rsplit('.', 1)[0]}.access_codes"] = fv(codes, item.origin + "#parsed:access-codes")


def _task_kind(tag: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", tag).casefold()


def _event_time(value: object) -> datetime:
    text = str(value).strip().replace(" ", "T", 1)
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _native_value_is_absent(name: str, value: object) -> bool:
    if value in (None, ""):
        return True
    text = str(value).strip().casefold()
    if text == "-":
        return True
    if name.casefold().endswith("sid") and text in {"null sid", "s-1-0-0"}:
        return True
    if name.casefold().endswith(("address", "ip")) and text in {"::", "0", "0.0.0.0"}:
        return True
    return text in _ABSENT_FIELD_VALUES.get(name, frozenset())


def _put(fields: dict[str, FieldValue], record: WindowsRecord, typed: str, *native: str, transform=None) -> None:
    for name in native:
        item = record.data.get(name)
        if item is None or _native_value_is_absent(name, item.value):
            continue
        try:
            value = transform(item.value) if transform else item.value
        except (TypeError, ValueError) as exc:
            record.caveats.append(f"{name} is malformed and {typed} was omitted: {exc}")
            return
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


def _path_metadata(
    fields: dict[str, FieldValue], source: str, key: str, *, preserve_recorded_prefix: bool = False,
) -> None:
    item = fields.get(source)
    if item is None:
        return
    text = str(item.value)
    canonical = windows_path_key(text)
    fields[key] = fv(
        _prefix_preserving_windows_path_key(text) if preserve_recorded_prefix else canonical,
        item.origin if preserve_recorded_prefix else item.origin + "#canonical:windows-path",
    )
    if preserve_recorded_prefix:
        canonical_key = key.removesuffix("_key") + "_canonical_key"
        fields[canonical_key] = fv(canonical, item.origin + "#canonical:windows-path")
    fields[f"{key}.extended_prefix"] = fv(
        text.startswith(("\\\\?\\", "\\??\\")), item.origin + "#parsed:path-prefix",
    )
    fields[f"{key}.device_path"] = fv(
        text.casefold().startswith(("\\device\\", "\\systemroot\\", "%systemroot%")),
        item.origin + "#parsed:path-prefix",
    )
    fields[f"{key}.short_name"] = fv(bool(_SHORT_PATH.search(text)), item.origin + "#parsed:8dot3")


def _session_id(record: WindowsRecord, *names: str) -> tuple[str, str] | None:
    for name in names:
        item = record.data.get(name)
        if item is None or _native_value_is_absent(name, item.value):
            continue
        try:
            value = _integer(item.value)
        except (TypeError, ValueError) as exc:
            record.caveats.append(f"{name} is malformed and the session key was omitted: {exc}")
            return None
        text = hex(value)
        if value == 0 or text in _WELL_KNOWN_LOGON_IDS:
            return None
        return text, item.origin
    return None


def _auth_session_id(record: WindowsRecord, *names: str) -> tuple[str, str] | None:
    """Validate auth session ids while preserving their typed source spelling."""
    for name in names:
        item = record.data.get(name)
        if item is None or _native_value_is_absent(name, item.value):
            continue
        try:
            value = _integer(item.value)
        except (TypeError, ValueError) as exc:
            record.caveats.append(f"{name} is malformed and the session key was omitted: {exc}")
            return None
        if value == 0 or hex(value) in _WELL_KNOWN_LOGON_IDS:
            return None
        return str(item.value).strip().casefold(), item.origin
    return None


def _process_fields(fields: dict[str, FieldValue], record: WindowsRecord, host: str) -> None:
    event_id = record.event_class.event_id
    _put(fields, record, "process.command_line", "CommandLine")
    _put(fields, record, "process.executable", "Image", "NewProcessName", "ProcessName")
    _put(fields, record, "process.parent.executable", "ParentImage", "ParentProcessName")
    if event_id == 4688:
        _put(fields, record, "process.pid", "NewProcessId", transform=_integer)
        _put(fields, record, "process.ppid", "ProcessId", "CreatorProcessId", transform=_integer)
    else:
        _put(fields, record, "process.pid", "ProcessId", transform=_integer)
        if event_id == 1:
            _put(fields, record, "process.ppid", "ParentProcessId", transform=_integer)
    _put(fields, record, "process.guid", "ProcessGuid", transform=_guid)
    _put(fields, record, "process.parent.guid", "ParentProcessGuid", transform=_guid)
    _put(fields, record, "process.original_file_name", "OriginalFileName")
    _put(fields, record, "process.description", "Description")
    _put(fields, record, "process.product", "Product")
    _put(fields, record, "process.company", "Company")
    _put(fields, record, "process.file_version", "FileVersion")
    _put(fields, record, "process.integrity_level", "IntegrityLevel", transform=lambda value: str(value).casefold())
    _put(fields, record, "process.terminal_session_id", "TerminalSessionId", transform=_integer)
    _put(fields, record, "process.current_directory", "CurrentDirectory")
    _put(fields, record, "process.parent.command_line", "ParentCommandLine")
    _put(fields, record, "process.parent.user", "ParentUser")
    _put(fields, record, "process.user", "User")
    _put(fields, record, "process.token_elevation_type", "TokenElevationType", transform=_message_value)
    _put(fields, record, "process.mandatory_label", "MandatoryLabel")
    _put(fields, record, "process.target_user_sid", "TargetUserSid")
    _put(fields, record, "process.target_user_name", "TargetUserName")
    _put(fields, record, "process.target_user_domain", "TargetDomainName")
    _put(fields, record, "process.logon_guid", "LogonGuid", transform=_guid)
    if event_id == 4688:
        for typed, native in (
            ("process.subject_session_id", "SubjectLogonId"),
            ("process.target_session_id", "TargetLogonId"),
        ):
            role_session = _session_id(record, native)
            if role_session:
                fields[typed] = fv(*role_session)
    session_names = ("TargetLogonId", "SubjectLogonId") if event_id == 4688 else ("LogonId",)
    session = _session_id(record, *session_names)
    if session:
        value, origin = session
        fields["process.session_id"] = fv(value, origin)
        fields["process.session_key"] = fv(f"{host}:{value}", origin)
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
    _path_metadata(fields, "process.executable", "process.executable_key", preserve_recorded_prefix=True)
    _path_metadata(fields, "process.parent.executable", "process.parent.executable_key", preserve_recorded_prefix=True)
    for algorithm in ("MD5", "SHA1", "SHA256", "IMPHASH"):
        _put(fields, record, f"file.hash.{algorithm.casefold()}", f"Hashes.{algorithm}")
    if event_id in {4689, 5}:
        fields["process.fence"] = fv("termination", fields.get("event.code", fv(event_id, "catalog")).origin)


def _role_process_fields(fields: dict[str, FieldValue], record: WindowsRecord, role: str) -> None:
    prefix = role.title()
    _put(fields, record, f"{role}.guid", f"{prefix}ProcessGuid", transform=_guid)
    _put(fields, record, f"{role}.pid", f"{prefix}ProcessId", transform=_integer)
    _put(fields, record, f"{role}.executable", f"{prefix}Image")
    _put(fields, record, f"{role}.user", f"{prefix}User")
    _path_metadata(fields, f"{role}.executable", f"{role}.executable_key")
    for suffix in ("guid", "pid", "executable", "executable_key"):
        item = fields.get(f"{role}.{suffix}")
        if item is not None:
            fields[f"process.{role}.{suffix}"] = item


_AUTH_ACTIONS = {
    4624: "logon",
    4625: "logon",
    4648: "explicit_credentials",
    4672: "special_privileges",
    4634: "logoff",
    4647: "logoff",
    4768: "kerberos_tgt_requested",
    4769: "kerberos_service_ticket_requested",
    4770: "kerberos_service_ticket_renewed",
    4771: "kerberos_preauthentication_failed",
    4776: "credential_validation",
    4778: "session_reconnected",
    4779: "session_disconnected",
    4964: "special_groups_assigned",
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
    4725: "disable",
    4729: "remove_from_global_group",
    4733: "remove_from_local_group",
    4757: "remove_from_universal_group",
    4767: "unlock",
    4781: "rename",
    4765: "sid_history_added",
    4766: "sid_history_add_failed",
    4794: "directory_services_restore_mode_password_set",
    4741: "computer_create",
    4742: "computer_modify",
    4743: "computer_delete",
    4704: "user_right_assigned",
    4705: "user_right_removed",
}

_TASK_ACTIONS = {
    4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated",
    106: "registered", 140: "updated", 141: "deleted", 129: "process_created",
    200: "action_started", 201: "action_completed",
}

_FILE_ACTIONS = {
    2: "creation_time_changed", 11: "created", 15: "alternate_data_stream_created",
    23: "deleted_archived", 26: "deleted",
}

_REGISTRY_ACTIONS = {12: "object", 13: "value_set", 14: "object_renamed", 4657: "value_modified"}

_DEFENDER_ACTIONS = {
    1006: "malware_detected", 1007: "remediation_succeeded", 1008: "remediation_failed",
    1009: "item_restored", 1011: "quarantine_deleted", 1012: "remediation_failed",
    1116: "malware_detected", 1117: "remediation_succeeded", 1118: "remediation_failed",
    1119: "remediation_critical_failure", 1121: "attack_surface_reduction_blocked",
    1122: "attack_surface_reduction_audited", 1123: "controlled_folder_access_blocked",
    1124: "controlled_folder_access_audited", 1125: "network_protection_audited",
    1126: "network_protection_blocked", 5000: "antimalware_disabled", 5001: "realtime_protection_disabled",
    5004: "configuration_changed", 5007: "configuration_changed", 5010: "scanning_disabled",
    5012: "behavior_monitoring_disabled",
}

# These identifiers belong to Windows itself, not portable user sessions.
_WELL_KNOWN_LOGON_IDS = {"0x3e4", "0x3e5", "0x3e7"}


def _status_failed(record: WindowsRecord) -> bool:
    for name in ("Status", "SubStatus", "FailureCode", "ResultCode", "ErrorCode"):
        value = record.value(name)
        if _native_value_is_absent(name, value):
            continue
        try:
            if _integer(value) != 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _audit_outcome(record: WindowsRecord) -> Outcome:
    """Use only explicit ECS or Windows audit markers; absence defaults to success."""
    observed: set[Outcome] = set()
    ecs_outcome = _get(record.hit.get("_source") or {}, "event.outcome")
    if isinstance(ecs_outcome, str):
        normalized = ecs_outcome.strip().casefold()
        if normalized in {outcome.value for outcome in Outcome}:
            observed.add(Outcome(normalized))
    winlog = (record.hit.get("_source") or {}).get("winlog") or {}
    keywords = winlog.get("keywords")
    values = list(keywords) if isinstance(keywords, (list, tuple, set)) else [keywords]
    if record.value("Keywords") not in (None, ""):
        values.append(record.value("Keywords"))
    for value in values:
        normalized = str(value or "").strip().casefold()
        if normalized in {"audit failure", "0x8010000000000000"}:
            observed.add(Outcome.failure)
        elif normalized in {"audit success", "0x8020000000000000"}:
            observed.add(Outcome.success)
    if len(observed) > 1:
        record.caveats.append("conflicting Windows audit outcome markers; outcome is unknown")
        return Outcome.unknown
    return next(iter(observed), Outcome.success)


def _address_fields(
    fields: dict[str, FieldValue], record: WindowsRecord, role: str, *native_names: str,
) -> None:
    _put(fields, record, f"{role}.ip", *native_names, transform=_ip)
    item = fields.get(f"{role}.ip")
    if item is None:
        return
    address = ipaddress.ip_address(item.value)
    fields[f"{role}.address_family"] = fv(f"ipv{address.version}", item.origin + "#parsed:address-family")
    fields[f"{role}.is_loopback"] = fv(address.is_loopback, item.origin + "#parsed:is-loopback")


def _auth_fields(fields: dict[str, FieldValue], record: WindowsRecord, host: str) -> Outcome:
    event_id = record.event_class.event_id
    fields["auth.action"] = fv(_AUTH_ACTIONS[event_id], fields["event.code"].origin)
    _put(fields, record, "auth.logon_type", "LogonType", transform=_integer)
    _address_fields(fields, record, "source", "IpAddress", "ClientAddress", "SourceNetworkAddress")
    _put(fields, record, "source.port", "IpPort", "ClientPort", transform=_integer)
    _put(fields, record, "source.hostname", "WorkstationName", "Workstation", "ClientName", transform=_hostname)
    session = _auth_session_id(record, "TargetLogonId", "SubjectLogonId", "LogonID", "SessionID")
    if session:
        session_id, origin = session
        fields["auth.session_id"] = fv(session_id, origin)
        fields["auth.session_key"] = fv(f"{host}:{session_id}", origin)
    for typed, names, transform in (
        ("auth.logon_guid", ("LogonGuid",), _guid),
        ("auth.logon_process", ("LogonProcessName",), None),
        ("auth.package", ("AuthenticationPackageName", "PackageName"), None),
        ("auth.lm_package", ("LmPackageName",), None),
        ("auth.key_length", ("KeyLength",), _integer),
        ("auth.status", ("Status",), _integer),
        ("auth.sub_status", ("SubStatus",), _integer),
        ("auth.failure_code", ("FailureCode", "ResultCode"), _integer),
        ("auth.failure_reason", ("FailureReason",), _message_value),
        ("auth.elevated_token", ("ElevatedToken",), _boolean),
        ("auth.impersonation_level", ("ImpersonationLevel",), _message_value),
        ("auth.restricted_admin_mode", ("RestrictedAdminMode",), _boolean),
        ("auth.virtual_account", ("VirtualAccount",), _boolean),
        ("auth.outbound_user", ("TargetOutboundUserName",), None),
        ("auth.outbound_domain", ("TargetOutboundDomainName",), lambda value: str(value).casefold()),
        ("auth.target_server", ("TargetServerName",), _hostname),
        ("auth.target_info", ("TargetInfo",), None),
        ("auth.service_name", ("ServiceName",), None),
        ("auth.service_sid", ("ServiceSid",), None),
        ("auth.ticket_options", ("TicketOptions",), _integer),
        ("auth.encryption_type", ("TicketEncryptionType",), _integer),
        ("auth.preauth_type", ("PreAuthType",), _integer),
        ("auth.transmitted_services", ("TransmittedServices",), _string_list),
        ("auth.group_membership", ("GroupMembership",), _string_list),
        ("auth.certificate.issuer", ("CertIssuerName",), None),
        ("auth.certificate.serial_number", ("CertSerialNumber",), None),
        ("auth.certificate.thumbprint", ("CertThumbprint",), None),
    ):
        _put(fields, record, typed, *names, transform=transform)
    if event_id in {4624, 4625, 4648}:
        _process_fields(fields, record, host)
    failed = event_id in {4625, 4771, 4766} or _status_failed(record)
    return Outcome.failure if failed else Outcome.success


def _account_change_fields(fields: dict[str, FieldValue], record: WindowsRecord) -> Outcome:
    event_id = record.event_class.event_id
    fields["account.action"] = fv(_ACCOUNT_ACTIONS[event_id], fields["event.code"].origin)
    for typed, names, transform in (
        ("account.member_id", ("MemberSid",), None),
        ("account.member_name", ("MemberName",), lambda value: str(value).casefold()),
        ("account.group_id", ("TargetSid",), None),
        ("account.group_name", ("TargetUserName",), lambda value: str(value).casefold()),
        ("account.old_name", ("OldTargetUserName",), lambda value: str(value).casefold()),
        ("account.new_name", ("NewTargetUserName",), lambda value: str(value).casefold()),
        ("account.old_uac", ("OldUacValue",), _integer),
        ("account.new_uac", ("NewUacValue",), _integer),
        ("account.spns", ("ServicePrincipalNames", "ServicePrincipalName"), _string_list),
        ("account.sid_history", ("SidHistory",), _string_list),
        ("account.privileges", ("PrivilegeList",), _string_list),
        ("account.sam_name", ("SamAccountName",), lambda value: str(value).casefold()),
        ("account.dns_host_name", ("DnsHostName",), _hostname),
        ("account.allowed_to_delegate_to", ("AllowedToDelegateTo",), _string_list),
    ):
        _put(fields, record, typed, *names, transform=transform)
    uac_changes = _uac_changes(record)
    if uac_changes:
        changes, origin = uac_changes
        fields["account.uac_changes"] = fv(changes, origin + "#parsed:uac-flags")
    return Outcome.failure if event_id == 4766 or _status_failed(record) else Outcome.success


def _local_name(element) -> str:
    return str(element.tag).rsplit("}", 1)[-1]


def _task_child_text(element, name: str) -> str | None:
    for child in element:
        if _local_name(child) == name and child.text not in (None, ""):
            return child.text.strip()
    return None


def _task_child(element, name: str):
    if element is None:
        return None
    return next((child for child in element if _local_name(child) == name), None)


def _parse_task_xml(fields: dict[str, FieldValue], record: WindowsRecord) -> None:
    item = record.data.get("TaskContent")
    if item is None or _native_value_is_absent("TaskContent", item.value):
        return
    xml = str(item.value)
    try:
        if len(xml.encode("utf-8")) > _TASK_XML_MAX_BYTES:
            raise ValueError(f"TaskContent exceeds {_TASK_XML_MAX_BYTES} bytes")
        upper = xml.upper()
        if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
            raise ValueError("TaskContent may not contain DOCTYPE or ENTITY declarations")
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, UnicodeError, ValueError) as exc:
        fields["task.xml_parse"] = fv("failed", item.origin + "#parsed:task-xml")
        fields["task.xml_parse_reason"] = fv(str(exc), item.origin + "#parsed:task-xml")
        record.caveats.append(f"TaskContent parse failed: {exc}")
        return
    fields["task.xml_parse"] = fv("success", item.origin + "#parsed:task-xml")
    actions = []
    triggers = []
    for element in root.iter():
        tag = _local_name(element)
        if tag == "Exec":
            action = {"kind": "exec"}
            command = _task_child_text(element, "Command")
            arguments = _task_child_text(element, "Arguments")
            working = _task_child_text(element, "WorkingDirectory")
            if command:
                action["command"] = command
            if arguments:
                action["arguments"] = arguments
            if working:
                action["working_directory"] = working
            actions.append(action)
        elif tag == "ComHandler":
            action = {"kind": "com_handler"}
            class_id = _task_child_text(element, "ClassId")
            if class_id:
                try:
                    action["class_id"] = _guid(class_id)
                except ValueError:
                    action["class_id"] = class_id.casefold()
            actions.append(action)
        elif tag == "Actions":
            for child in element:
                child_tag = _local_name(child)
                if child_tag not in {"Exec", "ComHandler"}:
                    actions.append({"kind": _task_kind(child_tag)})
        elif element is not root and tag.endswith("Trigger"):
            trigger = {"kind": tag[:-7].casefold() or "generic"}
            enabled = _task_child_text(element, "Enabled")
            if enabled is not None:
                try:
                    trigger["enabled"] = _boolean(enabled)
                except ValueError:
                    record.caveats.append(f"TaskContent trigger Enabled is malformed: {enabled!r}")
            for child, key in (("StartBoundary", "start"), ("EndBoundary", "end"),
                               ("Delay", "delay"), ("Subscription", "subscription")):
                value = _task_child_text(element, child)
                if value:
                    trigger[key] = value
            triggers.append(trigger)
    if actions:
        fields["task.actions"] = fv(actions, item.origin + "#parsed:task-actions")
    if triggers:
        fields["task.triggers"] = fv(triggers, item.origin + "#parsed:task-triggers")
    registration = _task_child(root, "RegistrationInfo")
    principals = _task_child(root, "Principals")
    principal = _task_child(principals, "Principal")
    settings = _task_child(root, "Settings")
    for typed, container, name, transform in (
        ("task.author", registration, "Author", None),
        ("task.uri", registration, "URI", None),
        ("task.principal.user_id", principal, "UserId", None),
        ("task.principal.group_id", principal, "GroupId", None),
        ("task.principal.logon_type", principal, "LogonType", lambda value: value.casefold()),
        ("task.principal.run_level", principal, "RunLevel", lambda value: value.casefold()),
        ("task.hidden", settings, "Hidden", _boolean),
    ):
        value = _task_child_text(container, name) if container is not None else None
        if value is None:
            continue
        try:
            value = transform(value) if transform else value
        except ValueError as exc:
            record.caveats.append(f"TaskContent {name} is malformed: {exc}")
            continue
        fields[typed] = fv(value, item.origin + f"#parsed:task-{name.casefold()}")


def _file_change_fields(fields: dict[str, FieldValue], record: WindowsRecord) -> Outcome:
    event_id = record.event_class.event_id
    fields["file.action"] = fv(_FILE_ACTIONS[event_id], fields["event.code"].origin)
    _process_fields(fields, record, str(fields["host.name"].value))
    _put(fields, record, "file.path", "TargetFilename", "TargetObject")
    _put(fields, record, "file.previous_creation_time", "PreviousCreationUtcTime")
    _put(fields, record, "file.creation_time", "CreationUtcTime")
    _put(fields, record, "file.hash.sha256", "Hashes.SHA256")
    _put(fields, record, "file.stream.content", "Contents")
    path = fields.get("file.path")
    if path:
        text = str(path.value)
        fields["file.path_key"] = fv(windows_path_key(text), path.origin + "#canonical:windows-path")
        base, separator, stream = text.partition(":") if not re.match(r"^[A-Za-z]:", text) else (
            text[:2] + text[2:].split(":", 1)[0], ":" if ":" in text[2:] else "",
            text[2:].split(":", 1)[1] if ":" in text[2:] else "",
        )
        if event_id == 15 and separator and stream:
            fields["file.stream.name"] = fv(stream, path.origin + "#parsed:alternate-data-stream")
            fields["file.stream.base_path"] = fv(base, path.origin + "#parsed:alternate-data-stream")
    return Outcome.success


def _registry_fields(fields: dict[str, FieldValue], record: WindowsRecord) -> Outcome:
    event_id = record.event_class.event_id
    fields["registry.action"] = fv(_REGISTRY_ACTIONS[event_id], fields["event.code"].origin)
    _process_fields(fields, record, str(fields["host.name"].value))
    _put(fields, record, "registry.path", "TargetObject", "ObjectName")
    _put(fields, record, "registry.event_type", "EventType")
    _put(fields, record, "registry.operation_type", "OperationType", transform=_message_value)
    _put(fields, record, "registry.new_path", "NewName")
    _put(fields, record, "registry.value_name", "ObjectValueName", "ValueName")
    _put(fields, record, "registry.value_type", "NewValueType")
    _put(fields, record, "registry.value", "NewValue", "Details")
    _put(fields, record, "registry.old_value", "OldValue")
    path = fields.get("registry.path")
    if path:
        text = str(path.value)
        fields["registry.path_key"] = fv(registry_path_key(text), path.origin + "#canonical:registry-path")
        lowered = text.casefold()
        fields["registry.wow6432node"] = fv("\\wow6432node\\" in f"\\{lowered}\\",
                                               path.origin + "#parsed:registry-architecture")
        fields["registry.control_set_alias"] = fv(bool(re.search(
            r"\\(?:currentcontrolset|controlset\d{3})(?:\\|$)", lowered,
        )), path.origin + "#parsed:control-set")
    details = record.data.get("Details")
    if details is not None:
        text = str(details.value)
        truncated = len(text) >= _DETAILS_MAX_CHARS or text.endswith(("...", "…")) or "(truncated)" in text.casefold()
        fields["registry.details_truncated"] = fv(truncated, details.origin + "#parsed:truncation")
    return Outcome.success


def _semantic_fields(fields: dict[str, FieldValue], record: WindowsRecord, host: str) -> Outcome:
    event_id, family = record.event_class.event_id, record.event_class.family
    _account_fields(fields, record)
    if family in {"process_exec", "process_termination"}:
        _process_fields(fields, record, host)
        return Outcome.success
    if family == "net_socket":
        _process_fields(fields, record, host)
        _address_fields(fields, record, "source", "SourceIp")
        _address_fields(fields, record, "destination", "DestinationIp")
        _put(fields, record, "source.port", "SourcePort", transform=_integer)
        _put(fields, record, "destination.port", "DestinationPort", transform=_integer)
        _put(fields, record, "source.hostname", "SourceHostname", transform=_hostname)
        _put(fields, record, "destination.hostname", "DestinationHostname", transform=_hostname)
        _put(fields, record, "destination.service.name", "DestinationPortName")
        _put(fields, record, "source.is_ipv6", "SourceIsIpv6", transform=_boolean)
        _put(fields, record, "destination.is_ipv6", "DestinationIsIpv6", transform=_boolean)
        _put(fields, record, "network.transport", "Protocol", transform=lambda value: str(value).casefold())
        _put(fields, record, "network.direction", "Initiated",
             transform=lambda value: "egress" if _boolean(value) else "ingress")
        src, dst = fields.get("source.ip"), fields.get("destination.ip")
        sport, dport = fields.get("source.port"), fields.get("destination.port")
        transport = fields.get("network.transport")
        if src and dst and sport and dport and transport:
            value = community_id(src.value, sport.value, dst.value, dport.value, transport.value)
            if value:
                fields["network.community_id"] = fv(
                    value, f"{src.origin}+{sport.origin}+{dst.origin}+{dport.origin}+{transport.origin}"
                    "#computed:community_id_v1",
                )
        return Outcome.success
    if family == "auth":
        return _auth_fields(fields, record, host)
    if family == "account_change":
        return _account_change_fields(fields, record)
    if family == "service_change":
        action = "start_type_changed" if event_id == 7040 else "installed"
        fields["service.action"] = fv(action, fields["event.code"].origin)
        _put(fields, record, "service.name", "ServiceName", "param1")
        _put(fields, record, "service.image_path", "ImagePath", "ServiceFileName")
        _put(fields, record, "service.start_type", "StartType", "ServiceStartType", "param3")
        _put(fields, record, "service.old_start_type", "OldStartType", "param2")
        _put(fields, record, "service.account", "AccountName", "ServiceAccount")
        _put(fields, record, "service.type", "ServiceType")
        return Outcome.success
    if family == "scheduled_task":
        fields["task.action"] = fv(_TASK_ACTIONS[event_id], fields["event.code"].origin)
        _put(fields, record, "task.name", "TaskName", "TaskName1")
        _put(fields, record, "task.xml", "TaskContent")
        _put(fields, record, "task.engine_pid", "EnginePID", "ProcessID", transform=_integer)
        _put(fields, record, "task.action_name", "ActionName")
        _put(fields, record, "task.user_context", "UserContext")
        _put(fields, record, "task.result_code", "ResultCode", transform=_integer)
        _parse_task_xml(fields, record)
        return Outcome.failure if _status_failed(record) else Outcome.success
    if family == "file_change":
        return _file_change_fields(fields, record)
    if family == "audit_config":
        actions = {
            4719: "audit_policy_changed", 1102: "log_cleared", 104: "log_cleared",
            1100: "event_log_service_shutdown", 1104: "security_log_full", 1108: "event_processing_error",
            4: "sysmon_state_changed", 16: "sysmon_configuration_changed", 255: "sysmon_error",
        }
        fields["audit.config.action"] = fv(actions.get(event_id, "changed"), fields["event.code"].origin)
        _put(fields, record, "audit.config.subcategory_guid", "SubcategoryGuid", transform=_guid)
        _put(fields, record, "audit.config.changes", "AuditPolicyChanges")
        _put(fields, record, "audit.config.state", "State")
        _put(fields, record, "audit.config.configuration", "Configuration")
        _put(fields, record, "audit.config.error", "Description", "Error")
        return Outcome.success
    if family == "system_state":
        state = "boot_start" if event_id in {12, 6005} else "boot_stop"
        fields["system.event"] = fv(state, fields["event.code"].origin)
        fields["process.fence"] = fv("boot", fields["event.code"].origin)
        return Outcome.success
    if family == "process_access":
        fields["process.access.action"] = fv("opened", fields["event.code"].origin)
        _role_process_fields(fields, record, "source")
        _role_process_fields(fields, record, "target")
        _put(fields, record, "process.access.mask", "GrantedAccess", transform=_integer)
        _put(fields, record, "process.access.call_trace", "CallTrace")
        trace = fields.get("process.access.call_trace")
        if trace:
            fields["process.access.call_trace_modules"] = fv(
                _call_trace_modules(trace.value), trace.origin + "#parsed:call-trace",
            )
        return Outcome.success
    if family == "image_load":
        _process_fields(fields, record, host)
        kind = "driver" if event_id == 6 else "image"
        fields["image.kind"] = fv(kind, fields["event.code"].origin)
        _put(fields, record, "image.path", "ImageLoaded", "Image")
        _put(fields, record, "image.signature", "Signature")
        _put(fields, record, "image.signature_status", "SignatureStatus")
        _put(fields, record, "image.signed", "Signed", transform=_boolean)
        _put(fields, record, "image.original_file_name", "OriginalFileName")
        for algorithm in ("MD5", "SHA1", "SHA256", "IMPHASH"):
            _put(fields, record, f"image.hash.{algorithm.casefold()}", f"Hashes.{algorithm}")
        image = fields.get("image.path")
        if image:
            fields["image.path_key"] = fv(windows_path_key(image.value), image.origin + "#canonical:windows-path")
        return Outcome.success
    if family == "remote_thread":
        _role_process_fields(fields, record, "source")
        _role_process_fields(fields, record, "target")
        _put(fields, record, "thread.id", "NewThreadId", transform=_integer)
        _put(fields, record, "thread.start_address", "StartAddress")
        _put(fields, record, "thread.start_module", "StartModule")
        _put(fields, record, "thread.start_function", "StartFunction")
        return Outcome.success
    if family == "process_tampering":
        _process_fields(fields, record, host)
        _put(fields, record, "process.tampering.type", "Type", "EventType")
        return Outcome.success
    if family == "registry_change":
        return _registry_fields(fields, record)
    if family == "object_access":
        fields["object.action"] = fv({4656: "handle_requested", 4663: "accessed", 4670: "permissions_changed"}.get(
            event_id, "accessed"), fields["event.code"].origin)
        _put(fields, record, "object.server", "ObjectServer")
        _put(fields, record, "object.type", "ObjectType")
        _put(fields, record, "object.name", "ObjectName")
        _put(fields, record, "object.handle_id", "HandleId")
        _put(fields, record, "object.access_mask", "AccessMask", transform=_integer)
        _access_fields(fields, record, "object.accesses")
        _put(fields, record, "object.old_security_descriptor", "OldSd")
        _put(fields, record, "object.new_security_descriptor", "NewSd")
        _process_fields(fields, record, host)
        return _audit_outcome(record)
    if family == "pipe_event":
        fields["pipe.action"] = fv("created" if event_id == 17 else "connected", fields["event.code"].origin)
        _put(fields, record, "pipe.name", "PipeName")
        _process_fields(fields, record, host)
        return Outcome.success
    if family == "wmi_subscription":
        fields["wmi.action"] = fv({19: "filter_registered", 20: "consumer_registered",
                                    21: "binding_registered", 5861: "subscription_activity"}.get(event_id),
                                   fields["event.code"].origin)
        for typed, native in (("wmi.operation", "Operation"), ("wmi.namespace", "EventNamespace"),
                              ("wmi.namespace", "NamespaceName"),
                              ("wmi.name", "Name"), ("wmi.query", "Query"),
                              ("wmi.type", "Type"), ("wmi.destination", "Destination"),
                              ("wmi.consumer", "Consumer"), ("wmi.filter", "Filter"),
                              ("wmi.binding", "Binding"), ("wmi.user", "User")):
            _put(fields, record, typed, native)
        return Outcome.success
    if family == "dns_lookup":
        _process_fields(fields, record, host)
        _put(fields, record, "dns.question.name", "QueryName", transform=lambda value: str(value).rstrip(".").casefold())
        _put(fields, record, "dns.answers", "QueryResults", transform=_string_list)
        answers = record.data.get("QueryResults")
        if answers is not None and not _native_value_is_absent("QueryResults", answers.value):
            addresses, names = _dns_answer_parts(answers.value)
            if addresses:
                fields["dns.answers.addresses"] = fv(addresses, answers.origin + "#parsed:dns-addresses")
            if names:
                fields["dns.answers.cnames"] = fv(names, answers.origin + "#parsed:dns-cnames")
        _put(fields, record, "dns.status", "QueryStatus", transform=_integer)
        return Outcome.failure if _status_failed(record) else Outcome.success
    if family == "script_block":
        fields["script.action"] = fv({4104: "script_block", 4103: "module_log", 400: "engine_start",
                                      403: "engine_stop", 800: "pipeline_execution"}.get(event_id, "execution"),
                                     fields["event.code"].origin)
        _put(fields, record, "script.block_id", "ScriptBlockId", transform=_guid)
        _put(fields, record, "script.path", "Path", "ScriptName")
        _put(fields, record, "script.text", "ScriptBlockText", "Payload")
        _put(fields, record, "script.context", "ContextInfo", transform=_key_value_lines)
        _put(fields, record, "script.host_application", "HostApplication")
        _put(fields, record, "script.engine_version", "EngineVersion")
        if event_id in {400, 403, 800}:
            _powershell_data_fields(fields, record)
        for typed, parsed_as in (
            ("script.context", "powershell-context"),
            ("script.host_application", "powershell-host-application"),
            ("script.engine_version", "powershell-engine-version"),
        ):
            item = fields.get(typed)
            if item is not None:
                fields[typed] = fv(item.value, item.origin + f"#parsed:{parsed_as}")
        _put(fields, record, "script.message_number", "MessageNumber", transform=_integer)
        _put(fields, record, "script.message_total", "MessageTotal", transform=_integer)
        _put(fields, record, "script.runspace_id", "RunspaceId", transform=_guid)
        _put(fields, record, "script.pipeline_id", "PipelineId", transform=_guid)
        complete = True
        if event_id == 4104:
            block_id = fields.get("script.block_id")
            number = fields.get("script.message_number")
            total = fields.get("script.message_total")
            valid_parts = (
                number is not None
                and total is not None
                and isinstance(number.value, int)
                and not isinstance(number.value, bool)
                and isinstance(total.value, int)
                and not isinstance(total.value, bool)
                and 1 <= number.value <= total.value <= SCRIPT_BLOCK_MAX_PARTS
            )
            complete = bool(block_id is not None and valid_parts and number.value == 1 and total.value == 1)
            if block_id is None:
                record.caveats.append(
                    "PowerShell 4104 ScriptBlockId is missing, zero, or malformed; this part cannot be correlated"
                )
            if (total is not None and isinstance(total.value, int) and not isinstance(total.value, bool)
                    and total.value > SCRIPT_BLOCK_MAX_PARTS):
                record.caveats.append(
                    "PowerShell 4104 part metadata exceeds supported maximum "
                    f"{SCRIPT_BLOCK_MAX_PARTS}; script completeness is unknown"
                )
            elif not valid_parts:
                record.caveats.append(
                    "PowerShell 4104 part metadata is missing or malformed; script completeness is unknown"
                )
        fields["script.complete"] = fv(
            complete,
            fields["event.code"].origin + "#computed:single-part",
        )
        return Outcome.success
    if family in {"directory_access", "directory_change"}:
        prefix = "directory.access" if family == "directory_access" else "directory.change"
        fields[f"{prefix}.action"] = fv({4662: "accessed", 5136: "modified", 5137: "created",
                                         5138: "undeleted", 5139: "moved", 5141: "deleted"}.get(event_id),
                                        fields["event.code"].origin)
        _put(fields, record, "directory.object.server", "ObjectServer")
        _put(fields, record, "directory.object.type", "ObjectType")
        _put(fields, record, "directory.object.dn", "ObjectDN", "ObjectName")
        _put(fields, record, "directory.object.guid", "ObjectGUID", "ObjectGuid", transform=_guid)
        _put(fields, record, "directory.object.class", "ObjectClass")
        _put(fields, record, f"{prefix}.access_mask", "AccessMask", transform=_integer)
        _access_fields(fields, record, f"{prefix}.accesses")
        _put(fields, record, f"{prefix}.operation_type", "OperationType", transform=_message_value)
        _put(fields, record, "directory.attribute.ldap_name", "AttributeLDAPDisplayName")
        _put(fields, record, "directory.attribute.value", "AttributeValue")
        properties = record.data.get("Properties")
        if properties:
            guids = [match.group(1).casefold() for match in _GUID_IN_TEXT.finditer(str(properties.value))]
            if guids:
                fields["directory.rights.guids"] = fv(guids, properties.origin + "#parsed:right-guids")
                names = [_DIRECTORY_RIGHT_GUIDS[guid] for guid in guids if guid in _DIRECTORY_RIGHT_GUIDS]
                if names:
                    fields["directory.rights.names"] = fv(names, properties.origin + "#mapped:ad-schema")
        return _audit_outcome(record)
    if family == "share_access":
        fields["share.action"] = fv("accessed" if event_id == 5145 else "connected",
                                    fields["event.code"].origin)
        _put(fields, record, "share.name", "ShareName")
        _put(fields, record, "share.local_path", "ShareLocalPath")
        _put(fields, record, "share.relative_target", "RelativeTargetName")
        _put(fields, record, "share.access_mask", "AccessMask", transform=_integer)
        _access_fields(fields, record, "share.accesses")
        session = _session_id(record, "SubjectLogonId", "TargetLogonId")
        if session:
            fields["share.session_id"] = fv(*session)
        _address_fields(fields, record, "source", "IpAddress", "SourceAddress")
        _put(fields, record, "source.port", "IpPort", "SourcePort", transform=_integer)
        _put(fields, record, "source.hostname", "WorkstationName", transform=_hostname)
        return _audit_outcome(record)
    if family == "defender_event":
        fields["defender.action"] = fv(_DEFENDER_ACTIONS.get(event_id, "event"), fields["event.code"].origin)
        for typed, names, transform in (
            ("defender.threat.name", ("Threat Name", "ThreatName", "Threat_Name", "Name"), None),
            ("defender.threat.id", ("Threat ID", "ThreatID", "Threat_ID"), None),
            ("defender.severity", ("Severity Name", "SeverityName", "Severity_Name"),
             lambda value: str(value).casefold()),
            ("defender.category", ("Category Name", "CategoryName", "Category_Name"), None),
            ("defender.path", ("Path",), None),
            ("defender.process", ("Process Name", "ProcessName", "Process_Name"), None),
            ("defender.user", ("Detection User", "DetectionUser", "Detection_User"), None),
            ("defender.recorded_action", ("Action Name", "ActionName", "Action_Name", "Action"), None),
            ("defender.old_value", ("Old Value", "OldValue", "Old_Value"), None),
            ("defender.new_value", ("New Value", "NewValue", "New_Value"), None),
            ("defender.error_code", ("Error Code", "ErrorCode", "Error_Code"), _integer),
            ("defender.error_description", ("Error Description", "ErrorDescription", "Error_Description"), None),
        ):
            _put(fields, record, typed, *names, transform=transform)
        return Outcome.failure if event_id in {1008, 1012, 1118, 1119} else Outcome.success
    if family == "remote_access":
        actions = {1149: "rdp_authentication", 21: "rdp_logon", 22: "rdp_shell_start",
                   24: "rdp_disconnect", 25: "rdp_reconnect", 6: "winrm_listener_started",
                   91: "winrm_session", 3: "bits_job_created", 59: "bits_transfer_started",
                   60: "bits_transfer_completed"}
        fields["remote.action"] = fv(actions.get(event_id, "remote_activity"), fields["event.code"].origin)
        address_names = (
            ("Param3", "IpAddress", "Address", "ClientAddress", "SourceNetworkAddress")
            if event_id == 1149 else
            ("IpAddress", "Address", "ClientAddress", "SourceNetworkAddress")
        )
        _address_fields(fields, record, "source", *address_names)
        _put(fields, record, "source.port", "Port", "ClientPort", transform=_integer)
        _put(fields, record, "source.hostname", "ClientName", "WorkstationName", transform=_hostname)
        _put(fields, record, "remote.session_id", "SessionID", "SessionId", transform=_integer)
        user_names = ("Param1", "User", "UserName") if event_id == 1149 else ("User", "UserName")
        domain_names = ("Param2", "DomainName") if event_id == 1149 else ("DomainName",)
        _put(fields, record, "remote.user", *user_names)
        _put(fields, record, "remote.domain", *domain_names)
        _put(fields, record, "remote.resource", "ResourceUri", "Url", "RemoteName")
        _put(fields, record, "bits.job_id", "JobId", transform=_guid)
        _put(fields, record, "bits.job_name", "JobName")
        _put(fields, record, "bits.remote_url", "Url", "RemoteName")
        _put(fields, record, "bits.local_file", "LocalName", "FileName")
        return Outcome.failure if _status_failed(record) else Outcome.success
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
        caveats=record.caveats,
    )
