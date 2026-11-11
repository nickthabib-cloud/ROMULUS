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

from romulus.evidence import rpc_catalog
from romulus.evidence.community import community_id
from romulus.evidence.typed import FieldValue, Outcome, RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows_catalog import (
    EVENT_CLASSES,
    WINDOWS_DATASETS,
    WindowsEventClass,
    lookup_event_class,
)

if TYPE_CHECKING:
    from romulus.detect.bounded import Account, StateBudget

WINDOWS_NORMALIZER = "windows-ecs@20"
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
    "%%1906": "registry_value_deleted",
    "%%1936": "default",
    "%%1937": "full",
    "%%1938": "limited",
    "%%1832": "identification",
    "%%1833": "impersonation",
    "%%1840": "delegation",
    "%%2304": "error_during_logon",
    "%%2305": "account_expired",
    "%%2306": "netlogon_not_started",
    "%%2307": "account_locked_out",
    "%%2308": "logon_type_not_granted",
    "%%2309": "password_expired",
    "%%2310": "account_disabled",
    "%%2311": "logon_time_restriction",
    "%%2312": "workstation_restriction",
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
    "%%7688": "control_access",
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

# Message ids and their object-specific meanings are defined by Windows msobjs.dll.
# Rights bits alone are ambiguous across file, key and process object types.
_OBJECT_ACCESS_CODES = {
    "process": dict(zip((f"%%{code}" for code in range(4480, 4494)), (
        "terminate", "create_thread", "set_session_id", "vm_operation", "vm_read", "vm_write",
        "dup_handle", "create_process", "set_quota", "set_information", "query_information",
        "set_termination_port", "undefined_bit_12", "undefined_bit_13",
    ), strict=True)),
    "key": dict(zip((f"%%{code}" for code in range(4432, 4440)), (
        "query_value", "set_value", "create_sub_key", "enumerate_sub_keys", "notify", "create_link",
        "undefined_bit_6", "undefined_bit_7",
    ), strict=True)),
}
# SAM message labels are defined by the native msobjs.dll resource table; the request
# schema and its object-dependent access semantics are documented at event 4661.
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4661
_SAM_ACCESS_CODES = {
    **dict(zip((f"%%{code}" for code in range(5392, 5401)), (
        "ReadPasswordParameters", "WritePasswordParameters", "ReadOtherParameters", "WriteOtherParameters",
        "CreateUser", "CreateGlobalGroup", "CreateLocalGroup", "GetLocalGroupMembership", "ListAccounts",
    ), strict=True)),
    **dict(zip((f"%%{code}" for code in range(5410, 5416)), (
        "AddMember", "RemoveMember", "ListMembers", "Undefined Access (no effect) Bit 5",
        "Undefined Access (no effect) Bit 6", "Undefined Access (no effect) Bit 7",
    ), strict=True)),
    **dict(zip((f"%%{code}" for code in range(5440, 5449)), (
        "ReadGeneralInformation", "ReadPreferences", "WritePreferences", "ReadLogon", "ReadAccount",
        "WriteAccount", "ChangePassword (with knowledge of old password)",
        "SetPassword (without knowledge of old password)", "ListGroups",
    ), strict=True)),
}
_OBJECT_ACCESS_CODES.update({name: _SAM_ACCESS_CODES for name in (
    "sam_user", "sam_group", "sam_alias", "sam_domain", "sam_server")})

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
        self._db.execute("PRAGMA journal_mode=MEMORY")
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
        headroom = self.budget.physical_allowance(self.account) if self.account is not None else self.budget.headroom()
        if headroom is None:
            return
        pages = self._db.execute("PRAGMA page_count").fetchone()[0]
        self._db.execute(f"PRAGMA max_page_count = {pages + headroom // self._page}")

    def _charge_growth(self) -> None:
        size = self._db.execute("PRAGMA page_count").fetchone()[0] * self._page
        growth = size - self._size
        if growth > 0 and self.budget is not None and self.account is not None:
            self.budget.charge(self.account, growth)
            self.budget.physical_account(self.account, growth)
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
            if self.budget is not None and self.account is not None:
                self.budget.release_physical_account(self.account)

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
            source = windows_view(record.get("_source") or {})
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
                        if "full" in str(exc).lower():
                            self.budget.refuse_capacity(self.account, reason)
                        else:
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
    """Require a Windows shipper marker or a complete native Windows record envelope."""
    datasets = (_get(source, "data_stream.dataset"), _get(source, "event.dataset"))
    winlogbeat = str(_get(source, "agent.type") or "").casefold() == "winlogbeat"
    return any(isinstance(dataset, str) and dataset.casefold() in WINDOWS_DATASETS for dataset in datasets) or (
        (winlogbeat or isinstance(source.get(NXLOG_ADAPTED), dict)
         or isinstance(source.get(EVTX_JSON_ADAPTED), dict)) and isinstance(source.get("winlog"), dict)
    ) or is_nxlog_windows(source) or is_evtx_json(source)


# ---------------------------------------------------------------------------------------------
# NXLog im_msvistalog records (to_json(), shipped directly or through Logstash or Beats)
# ---------------------------------------------------------------------------------------------
# One flat JSON object per event: the event's System values under NXLog's names, and every EventData/UserData value
# at the top level under the provider's own name (under EventData.<Name> or UserData.<Name> when NXLog's AddPrefix is
# set). There is no winlog object and often no dataset; channel names keep the source's spelling ("security").
# nxlog_to_winlog adapts such a record to the Winlogbeat layout this module reads; every typed value then cites the
# record's own field.
#
# NXLog's own fields (the im_msvistalog reference's field list, with the fields its documented output also shows):
# never event data. A provider's event-data name equal to one of these cannot be told from it and is read as NXLog's.
NXLOG_ENVELOPE = frozenset({
    "AccountName", "AccountType", "ActivityID", "Category", "Channel", "Domain", "ERROR_EVT_UNRESOLVED", "EventID",
    "EventReceivedTime", "EventTime", "EventType", "EventXML", "ExecutionProcessID", "ExecutionThreadID", "Hostname",
    "Keywords", "Level", "LevelValue", "Message", "Opcode", "OpcodeValue", "ProviderGuid", "RecordNumber",
    "RelatedActivityID", "Severity", "SeverityValue", "SourceModuleName", "SourceModuleType", "SourceName", "Task",
    "TaskValue", "ThreadID", "UserID", "Version", "raw_event",
    # a computer-name spelling some pipelines write in place of Hostname
    "Computer",
})
# What a shipping pipeline adds around the record (Logstash, Beats, NXLog's output modules): never event data.
NXLOG_PIPELINE_FIELDS = frozenset({
    "@timestamp", "@version", "@metadata", "agent", "beat", "data_stream", "ecs", "event", "fields", "host", "input",
    "log", "message", "observer", "offset", "path", "port", "related", "tags", "type",
    # a creation time some pipelines add beside EventTime; its zone is not stated, so it is never read as a time
    "TimeCreated",
})
# The key an adapted record carries: the NXLog values the adapted layout has no place for.
NXLOG_ADAPTED = "_nxlog"
NXLOG_TIME_CAVEAT = "Time from the shipping pipeline; the event's own time was recorded without a zone."
NXLOG_SHAPE = "windows.nxlog"
NXLOG_OFFSET = "windows.nxlog.clock_offset:"
# A Windows channel's dataset name, for tagging an NXLog record that cannot be read with the families it could hold;
# any other channel could hold any Windows family.
_NXLOG_CHANNEL_DATASETS = {
    "security": "windows.security", "system": "windows.system",
    "microsoft-windows-sysmon/operational": "windows.sysmon_operational",
    "microsoft-windows-powershell/operational": "windows.powershell_operational",
    "windows powershell": "windows.powershell",
    "microsoft-windows-windows defender/operational": "windows.windows_defender",
}
_SCALAR = (str, int, float, bool)
NXLOG_CATALOG_CHANNEL_CAVEAT = ("NXLog's Channel held the provider's own Channel event data (the log it names); the "
                                "event's channel is the catalog's for its provider and event id")
# The skip of an NXLog record whose provider and event id name a catalogued class but whose Channel names none: it is
# counted against those classes' families (normalize.normalize_hits), never as an unread class.
NXLOG_CHANNEL_SKIP = "NXLog record's Channel names no catalogued class of its provider and event id"
# Classes whose own event data carry a "Channel" value (the Eventlog provider's log-cleared and service events).
_NXLOG_CHANNEL_DATA_CLASSES = frozenset(("microsoft-windows-eventlog", code) for code in (104, 1100, 1102, 1104, 1108))


def _by_provider_id() -> dict[tuple[str, int], tuple[WindowsEventClass, ...]]:
    out: dict[tuple[str, int], tuple[WindowsEventClass, ...]] = {}
    for event in EVENT_CLASSES:
        key = (event.provider.casefold(), event.event_id)
        out[key] = (*out.get(key, ()), event)
    return out


_CLASSES_BY_PROVIDER_ID = _by_provider_id()


# NXLog's EventType is one of these severity names; Sysmon's registry events carry an event-data EventType of their own
# ("SetValue", "CreateKey", ...), never one of them.
NXLOG_EVENT_TYPES = frozenset({"CRITICAL", "ERROR", "AUDIT_FAILURE", "AUDIT_SUCCESS", "INFO", "WARNING", "VERBOSE"})


def _nxlog_event_data_value(name: str, value: object) -> bool:
    """Whether a value under one of NXLog's own names can only be a provider's event data, by NXLog's documented
    value domain: an EventType outside NXLog's names, a Version that is text and not NXLog's integer (Sysmon's
    "15.15"). Any other collision is read as NXLog's: the record does not say which value it kept."""
    if name == "EventType":
        return isinstance(value, str) and value not in NXLOG_EVENT_TYPES
    if name == "Version":
        return isinstance(value, str) and not value.strip().isdigit()
    return False


_NXLOG_AUDIT_TYPES = {"AUDIT_SUCCESS": "Audit Success", "AUDIT_FAILURE": "Audit Failure"}


def _nxlog_keywords(keywords: object, event_type: object) -> list[str]:
    """Winlogbeat's winlog.keywords from NXLog's: the 64-bit keyword mask (NXLog writes it as a signed decimal) in
    the hexadecimal form Windows renders, and the audit result NXLog's EventType names. Both are exact; a record
    whose two markers disagree is left to the normalizer, which then types its outcome as unknown."""
    out = []
    mask = None
    if isinstance(keywords, int) and not isinstance(keywords, bool):
        mask = keywords
    elif isinstance(keywords, str):
        text = keywords.strip()
        with contextlib.suppress(ValueError):
            mask = int(text, 16) if text.casefold().startswith("0x") else int(text)
    if mask is not None and -(1 << 63) <= mask < (1 << 64):
        out.append(f"0x{mask & ((1 << 64) - 1):016x}")
    if isinstance(event_type, str) and event_type in _NXLOG_AUDIT_TYPES:
        out.append(_NXLOG_AUDIT_TYPES[event_type])
    return out


def is_nxlog_windows(source: dict) -> bool:
    """NXLog's flat Windows record: EventID, Channel, a computer name and a provider at the top level, no winlog."""
    return (not isinstance(source.get("winlog"), dict) and source.get("EventID") is not None
            and source.get("Channel") is not None and source.get("SourceName") is not None
            and (source.get("Hostname") is not None or source.get("Computer") is not None))


def _zoned_time(value: object) -> datetime | None:
    """A time that names its zone, else None (a time without one is never read as UTC)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def nxlog_to_winlog(source: dict) -> tuple[dict, dict[str, str]]:
    """The Winlogbeat layout of an NXLog flat record, and the record's own field for each adapted path.

    The channel keeps its spelling (the catalog matches channels without case, so "security" and "Security" are one
    channel). Time: an EventTime that names its zone is the event's own time; one that does not is never read as UTC,
    so the pipeline's @timestamp is used; with neither, the record cannot be placed in time and is an error."""
    event_data: dict[str, object] = {}
    paths: dict[str, str] = {}

    def put(name: str, value: object, native: str) -> None:
        if name in event_data and event_data[name] != value:
            raise WindowsInputError(f"NXLog record holds two values for event-data field {name!r}")
        event_data[name] = value
        paths[f"winlog.event_data.{name}"] = native

    for name, value in source.items():
        if name in ("EventData", "UserData") and isinstance(value, dict):
            for inner, item in value.items():
                if isinstance(item, _SCALAR):
                    put(str(inner), item, f"{name}.{inner}")
            continue
        if name in NXLOG_PIPELINE_FIELDS or name.startswith("@") or name == NXLOG_ADAPTED or (
                name in NXLOG_ENVELOPE and not _nxlog_event_data_value(name, value)):
            continue
        if not isinstance(value, _SCALAR):
            continue                    # an object or list is a pipeline's, never a Windows event-data value
        prefix, dot, inner = name.partition(".")
        put(inner if dot and prefix in ("EventData", "UserData") else name, value, name)
    computer_path = "Hostname" if source.get("Hostname") is not None else "Computer"
    winlog: dict[str, object] = {
        "channel": source.get("Channel"), "event_id": source.get("EventID"), "provider_name": source.get("SourceName"),
        "computer_name": source.get(computer_path), "event_data": event_data,
    }
    paths.update({"winlog.channel": "Channel", "winlog.event_id": "EventID", "winlog.provider_name": "SourceName",
                  "winlog.computer_name": computer_path})
    if source.get("RecordNumber") is not None:
        winlog["record_id"] = source["RecordNumber"]
        paths["winlog.record_id"] = "RecordNumber"
    # System values Winlogbeat keeps under winlog.* that this module reads: the writing process, the user SID, the
    # activity id, and the audit keywords
    for native, path in (("ExecutionProcessID", "process.pid"), ("UserID", "user.identifier"),
                         ("ActivityID", "activity_id")):
        if isinstance(source.get(native), _SCALAR) and source[native] != "":
            parts = path.split(".")
            target = winlog
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = source[native]
            paths[f"winlog.{path}"] = native
    keywords = _nxlog_keywords(source.get("Keywords"), source.get("EventType"))
    if keywords:
        winlog["keywords"] = keywords
        paths["winlog.keywords"] = "Keywords+EventType"
    event_time = source.get("EventTime")
    pipeline_time = _pipeline_time(source.get("@timestamp"))
    adapted: dict[str, object] = {"winlog": winlog, NXLOG_ADAPTED: {
        "channel": source.get("Channel"), "event_time": None if event_time is None else str(event_time),
        "pipeline_time": False, "catalog_channel": False}}
    if _zoned_time(event_time) is not None:
        winlog["time_created"] = event_time
        paths["winlog.time_created"] = "EventTime"
        adapted["@timestamp"] = pipeline_time if pipeline_time is not None else event_time
        paths["@timestamp"] = "@timestamp" if pipeline_time is not None else "EventTime"
    elif pipeline_time is not None:
        adapted["@timestamp"] = pipeline_time
        paths["@timestamp"] = "@timestamp"
        adapted[NXLOG_ADAPTED]["pipeline_time"] = True
    else:
        raise WindowsInputError("time unresolved: neither EventTime nor @timestamp names its zone")
    class_key = _nxlog_class_key(source)
    if (class_key in _NXLOG_CHANNEL_DATA_CLASSES and len(_CLASSES_BY_PROVIDER_ID.get(class_key, ())) == 1
            and lookup_event_class(winlog["channel"], winlog["provider_name"], winlog["event_id"]) is None):
        # The provider's own event data names a channel (the log that was cleared), and NXLog wrote it over its own
        # Channel: the event's channel is the catalog's for this provider and event id, and the value is event data.
        if not isinstance(event_data.get("Channel"), str):
            event_data["Channel"] = winlog["channel"]
            paths["winlog.event_data.Channel"] = "Channel"
        winlog["channel"] = _CLASSES_BY_PROVIDER_ID[class_key][0].channel
        paths["winlog.channel"] = "SourceName+EventID#catalog-channel"
        adapted[NXLOG_ADAPTED]["catalog_channel"] = True
    return adapted, paths


def _pipeline_time(value: object) -> str | None:
    """The pipeline's @timestamp as a zoned ISO-8601 time: a time naming its zone, or Elasticsearch's numeric epoch
    milliseconds; anything else (a time without a zone) is never read as UTC."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value / 1000, UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    return value.strip() if _zoned_time(value) is not None else None


def _nxlog_class_key(source: dict) -> tuple[str, int] | None:
    try:
        return str(source.get("SourceName") or "").strip().casefold(), int(source.get("EventID"))
    except (TypeError, ValueError):
        return None


def nxlog_class_families(source: dict) -> frozenset[str]:
    """The families of the catalogued classes an NXLog record's provider and event id name (whatever its channel)."""
    return frozenset(event.family for event in _CLASSES_BY_PROVIDER_ID.get(_nxlog_class_key(source), ()))


def windows_view(source: dict) -> dict:
    """A Winlogbeat-layout view of a native Windows record, or {} when adaptation fails."""
    try:
        if is_evtx_json(source):
            return evtx_json_to_winlog(source)
        if is_nxlog_windows(source):
            return nxlog_to_winlog(source)[0]
    except WindowsInputError:
        return {}
    return source


EVTX_JSON_ADAPTED = "_evtx_json"
EVTX_JSON_RECOVERED = "recovered from unallocated log space"
# Standard keyword bit names are defined by Windows' Winmeta metadata. Provider-specific low bits need the
# provider's message resources; an unknown bit never supplies an audit outcome.
_EVTX_KEYWORDS = ((1 << 48, "Response Time"), (1 << 50, "WDI Diag"),
                  (1 << 51, "SQM"), (1 << 52, "Audit Failure"), (1 << 53, "Audit Success"),
                  (1 << 54, "Correlation Hint"), (1 << 55, "Classic"))


def _evtx_attributes(system: dict, name: str) -> tuple[dict, str]:
    """The XML attributes in the renderer's ordinary or separate-attributes JSON mode."""
    value = system.get(name)
    nested = value.get("#attributes") if isinstance(value, dict) else None
    flat = system.get(name + "_attributes")
    if isinstance(nested, dict):
        if isinstance(flat, dict) and nested != flat:
            raise WindowsInputError(f"EVTX JSON has conflicting attributes for {name}")
        return nested, f"Event.System.{name}.#attributes"
    if isinstance(flat, dict):
        return flat, f"Event.System.{name}_attributes"
    return {}, f"Event.System.{name}.#attributes"


def is_evtx_json(source: dict) -> bool:
    """A native Event/System envelope, never an arbitrary application Event key or a wrapped export.

    Presence identifies the shape; malformed identity values are rejected by the adapter instead of guessed.
    Channel may be null in native ETW records; only the catalog's existing provider-specific handling can read it.
    """
    event = source.get("Event")
    system = event.get("System") if isinstance(event, dict) else None
    if isinstance(source.get("winlog"), dict) or not isinstance(system, dict):
        return False
    provider = system.get("Provider")
    attributes = provider.get("#attributes") if isinstance(provider, dict) else None
    flat = system.get("Provider_attributes")
    return (all(name in system for name in ("Channel", "Computer", "EventID"))
            and (isinstance(attributes, dict) and "Name" in attributes
                 or isinstance(flat, dict) and "Name" in flat))


def _evtx_integer(value: object, name: str, bits: int) -> int:
    if isinstance(value, bool) or not (isinstance(value, int) or (
            isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()))):
        raise WindowsInputError(f"EVTX JSON {name} must be an unsigned integer")
    try:
        number = int(value)
    except (ValueError, OverflowError) as exc:
        raise WindowsInputError(f"EVTX JSON {name} is malformed") from exc
    if not 0 <= number < (1 << bits):
        raise WindowsInputError(f"EVTX JSON {name} is outside its unsigned {bits}-bit range")
    return number


def _evtx_data_scalar(value: object) -> object:
    """Restore XML scalar text and Winlogbeat's lexical line-ending normalization."""
    if isinstance(value, str):
        # XML normalizes CRLF and bare CR to LF; Winlogbeat also removes trailing newlines from data pairs.
        return value.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return value


def evtx_json_to_winlog(source: dict) -> dict:
    """Adapt an EVTX JSON Event to the Winlogbeat layout without altering or discarding its raw record.

    A private path table translates every resulting field origin back to its indexed XML/JSON path. Both nested
    ``#attributes`` and separate ``*_attributes`` exports are accepted. No event.original XML fallback is copied.
    """
    if not is_evtx_json(source):
        raise WindowsInputError("EVTX JSON is missing its Event/System identity fields")
    event, paths = source["Event"], {}
    system = event["System"]
    provider, provider_path = _evtx_attributes(system, "Provider")
    computer = system["Computer"]
    if not isinstance(computer, str) or not computer.strip():
        raise WindowsInputError("EVTX JSON Computer is missing or malformed")
    if not isinstance(provider.get("Name"), str) or not provider["Name"].strip():
        raise WindowsInputError("EVTX JSON Provider Name is missing or malformed")
    if system["Channel"] is not None and not isinstance(system["Channel"], str):
        raise WindowsInputError("EVTX JSON Channel is malformed")
    event_id = system["EventID"]
    id_path = "Event.System.EventID"
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
        id_path += ".#text"
    winlog = {"event_id": _evtx_integer(event_id, "EventID", 16), "channel": system["Channel"],
              "provider_name": provider["Name"], "computer_name": computer}
    paths.update({"winlog.event_id": id_path, "winlog.channel": "Event.System.Channel",
                  "winlog.provider_name": provider_path + ".Name", "winlog.computer_name": "Event.System.Computer"})
    attrs, attr_path = _evtx_attributes(system, "EventID")
    qualifiers = attrs.get("Qualifiers", system.get("EventIDQualifiers"))
    if qualifiers is not None:
        winlog["qualifiers"] = _evtx_integer(qualifiers, "EventID qualifiers", 16)
        paths["winlog.qualifiers"] = (attr_path + ".Qualifiers" if "Qualifiers" in attrs
                                      else "Event.System.EventIDQualifiers")
        if "EventIDQualifiers" in system and winlog["qualifiers"] != _evtx_integer(
                system["EventIDQualifiers"], "EventIDQualifiers", 16):
            raise WindowsInputError("EVTX JSON has conflicting EventID qualifiers")
    for name, target in (("Guid", "provider_guid"), ("EventSourceName", "event_source_name")):
        if name in provider:
            winlog[target] = provider[name]
            paths["winlog." + target] = provider_path + "." + name
    for name, target, bits in (("EventRecordID", "record_id", 64), ("Version", "version", 8),
                               ("Level", "level", 8), ("Task", "task", 16), ("Opcode", "opcode", 8)):
        if system.get(name) is not None:
            winlog[target] = _evtx_integer(system[name], name, bits)
            paths["winlog." + target] = "Event.System." + name
    for element, name, target, bits in (
        ("Execution", "ProcessID", "process.pid", 32), ("Execution", "ThreadID", "process.thread.id", 32),
        ("Execution", "ProcessorID", "processor_id", 32), ("Execution", "SessionID", "session_id", 32),
        ("Execution", "KernelTime", "kernel_time", 32), ("Execution", "UserTime", "user_time", 32),
        ("Execution", "ProcessorTime", "processor_time", 32),
        ("Security", "UserID", "user.identifier", None), ("Correlation", "ActivityID", "activity_id", None),
        ("Correlation", "RelatedActivityID", "related_activity_id", None),
    ):
        attrs, attr_path = _evtx_attributes(system, element)
        if attrs.get(name) is None:
            continue
        value = _evtx_integer(attrs[name], element + "." + name, bits) if bits else attrs[name]
        node, parts = winlog, target.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
        paths["winlog." + target] = attr_path + "." + name
    keyword_mask = system.get("Keywords")
    if keyword_mask is not None:
        try:
            if not isinstance(keyword_mask, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", keyword_mask):
                raise ValueError
            number = int(keyword_mask, 16)
        except ValueError as exc:
            raise WindowsInputError("EVTX JSON Keywords must be a hexadecimal 64-bit mask") from exc
        winlog["keywords"] = [name for bit, name in _EVTX_KEYWORDS if number & bit]
        paths["winlog.keywords"] = "Event.System.Keywords"

    data = event.get("EventData")
    if data is not None and not isinstance(data, dict):
        raise WindowsInputError("EVTX JSON EventData must be an object or null")
    event_data = {}

    def put(name: str, value: object, path: str) -> None:
        if name in event_data:
            raise WindowsInputError(f"EVTX JSON has conflicting event-data field {name!r}")
        event_data[name] = _evtx_data_scalar(value)
        paths["winlog.event_data." + name] = path

    for name, value in (data or {}).items():
        if name == "#attributes":
            continue
        path = "Event.EventData." + name
        if name == "Data":
            if isinstance(value, dict) and set(value) <= {"#text", "#attributes"}:
                attributes = value.get("#attributes") or {}
                text_path = path + (".#text" if "#text" in value else "#empty-element")
                if isinstance(attributes, dict) and attributes.get("Name"):
                    put(str(attributes["Name"]), value.get("#text", ""), text_path)
                    continue
                value, path = value.get("#text", ""), text_path
            unnamed = value if isinstance(value, list) else [value]
            for index, item in enumerate(unnamed, 1):
                put(f"param{index}", item, f"{path}#{index}" if isinstance(value, list) else path)
        elif isinstance(value, dict) and isinstance(value.get("#attributes"), dict) and (
                isinstance(value["#attributes"].get("Name"), str)):
            put(value["#attributes"]["Name"], value.get("#text", ""),
                path + (".#text" if "#text" in value else "#empty-element"))
        else:
            put(name, value, path)
    winlog["event_data"] = event_data
    userdata = event.get("UserData")
    if userdata is not None:
        if not isinstance(userdata, dict):
            raise WindowsInputError("EVTX JSON UserData must be an object")
        schemas = [(name, value) for name, value in userdata.items() if name != "#attributes"]
        if len(schemas) != 1 or not isinstance(schemas[0][1], dict):
            raise WindowsInputError("EVTX JSON UserData must contain one schema element")
        schema, content = schemas[0]
        converted = {"xml_name": schema}
        for name, value in content.items():
            if name == "#attributes" and isinstance(value, dict):
                value = {key: item for key, item in value.items() if key != "xmlns" and not key.startswith("xmlns:")}
                if not value:
                    continue
            converted[name] = _evtx_data_scalar(value)
            paths["winlog.user_data." + name] = f"Event.UserData.{schema}.{name}"
        winlog["user_data"] = converted
    attrs, attr_path = _evtx_attributes(system, "TimeCreated")
    created = attrs.get("SystemTime")
    if created is not None:
        winlog["time_created"] = created
        paths["winlog.time_created"] = attr_path + ".SystemTime"
    timestamp = _pipeline_time(source.get("@timestamp")) if "@timestamp" in source else _pipeline_time(created)
    if timestamp is None:
        raise WindowsInputError("EVTX JSON time unresolved: @timestamp or SystemTime must name its zone")
    paths["@timestamp"] = "@timestamp" if "@timestamp" in source else attr_path + ".SystemTime"
    adapted = {"winlog": winlog, "@timestamp": timestamp, EVTX_JSON_ADAPTED: {
        "paths": paths, "recovered": source.get("recovered") is True or event.get("recovered") is True}}
    message = _get(event, "RenderingInfo.Message")
    if isinstance(source.get("message"), str):
        adapted["message"] = source["message"]
    elif isinstance(message, str):
        adapted["message"] = message
        paths["message"] = "Event.RenderingInfo.Message"
    return adapted


def _windows_hit(hit: dict) -> dict:
    source = hit.get("_source") or {}
    view = windows_view(source)
    return hit if view is source else {**hit, "_source": view}


def nxlog_error_tag(source: dict) -> str:
    """The dataset an NXLog record's normalization error is counted under: its channel's, else every Windows family."""
    return _NXLOG_CHANNEL_DATASETS.get(str(source.get("Channel") or "").strip().casefold(), "winlog.winlog")


def nxlog_clock_offset(source: dict) -> str | None:
    """The shape-table key of how far an NXLog record's zoneless EventTime is from its pipeline's @timestamp: the
    offset as a zone ("UTC-05:00") when it is a whole number of quarter hours within a day's zones, else "other";
    None when the record has no zoneless EventTime or no readable @timestamp. Times are never changed by it."""
    event_time, pipeline_time = source.get("EventTime"), source.get("@timestamp")
    if not isinstance(event_time, str) or _zoned_time(event_time) is not None or not isinstance(pipeline_time, str):
        return None
    try:
        local = datetime.fromisoformat(event_time.strip()).replace(microsecond=0)
        utc = datetime.fromisoformat(pipeline_time.strip())
    except ValueError:
        return None
    if utc.tzinfo is None:
        return None
    seconds = int((local - utc.astimezone(UTC).replace(tzinfo=None, microsecond=0)).total_seconds())
    if seconds % 900 or abs(seconds) > 14 * 3600:
        return f"{NXLOG_OFFSET}other"
    sign = "-" if seconds < 0 else "+"
    hours, minutes = divmod(abs(seconds) // 60, 60)
    return f"{NXLOG_OFFSET}UTC{sign}{hours:02d}:{minutes:02d}"


def _native_origin(origin: str, native_id: str, paths: dict[str, str]) -> str:
    """An adapted record's origin (one path, or several joined by "+"), naming the NXLog record's own fields."""
    prefix = f"{native_id}:"
    ordered = sorted(paths, key=len, reverse=True)
    out, start = [], 0
    while (found := origin.find(prefix, start)) >= 0:
        rest = found + len(prefix)
        out.append(origin[start:rest])
        start = rest
        for adapted in ordered:
            end = rest + len(adapted)
            if origin.startswith(adapted, rest) and origin[end:end + 1] in ("", "#", "+", ":"):
                out.append(paths[adapted])
                start = end
                break
    out.append(origin[start:])
    return "".join(out)


def windows_record_key(hit: dict) -> tuple[str, str, str] | None:
    """Logical shipper identity used to deduplicate copies without trusting index or document ids."""
    source = windows_view(hit.get("_source") or {})
    winlog = source.get("winlog") or {}
    computer = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
    channel = str(winlog.get("channel") or "").strip().casefold()
    record_id = winlog.get("record_id")
    event_class = lookup_event_class(winlog.get("channel"), winlog.get("provider_name"), winlog.get("event_id"))
    if event_class is not None and event_class.family == "rpc_call":
        channel = event_class.provider.casefold()
    if not computer or not channel or record_id in (None, "") or isinstance(record_id, bool):
        return None
    return computer, channel, str(record_id)


def _signature_time(value: object) -> object:
    """Canonical native instant at the millisecond precision shared by Windows exporters."""
    parsed = _zoned_time(value)
    if parsed is None:
        return value
    try:
        when = parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        return value
    when = when.replace(microsecond=when.microsecond // 1000 * 1000)
    return when.isoformat(timespec="milliseconds" if when.microsecond else "seconds").replace("+00:00", "Z")


def windows_record_signature(hit: dict) -> str:
    """Stable content discriminator for copies that share a native record id.

    Shipper envelope fields such as index, document id, ingest time and agent metadata are deliberately
    excluded. Native event time and a digest of the structured Windows payload are always included, so exact
    copies merge while same-instant native records with different content do not.
    """
    source = windows_view(hit.get("_source") or {})
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
            native.update({name: value for name, value in content.items() if name != "xml_name"})
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
        or source.get("@timestamp")
    )
    native_time = _signature_time(native_time)
    if native_time not in (None, ""):
        native.setdefault("TimeCreated", native_time)
    # Shippers vary only the spelling of some native names (for example Defender's ``Threat Name``,
    # ``Threat_Name`` and ``ThreatName``). Collapse those separators without changing payload values.
    payload: dict[str, list[object]] = {}
    for name, value in native.items():
        canonical_name = re.sub(r"[\s_]+", "", str(name)).casefold()
        if canonical_name in {"timecreated", "systemtime"}:
            value = _signature_time(value)
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
    if event_class is not None and event_class.family == "rpc_call":
        identity["side"] = "client" if native_event_id == 5 else "server"
        identity["pid"] = _get(winlog, "process.pid")
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


EVENT_XML_MAX_BYTES = 1_048_576


def _original_too_large(original: str) -> bool:
    return len(original) > EVENT_XML_MAX_BYTES or len(original.encode("utf-8")) > EVENT_XML_MAX_BYTES


def _xml_data(original: str, native_id: str) -> dict[str, FieldValue]:
    if _original_too_large(original):
        raise WindowsInputError(f"event.original exceeds {EVENT_XML_MAX_BYTES} bytes; XML was not parsed")
    upper = original.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise WindowsInputError("event.original XML may not contain DOCTYPE or ENTITY declarations")
    try:
        root = ElementTree.fromstring(original)
    except ElementTree.ParseError as exc:
        raise WindowsInputError(f"event.original is not valid XML: {exc}") from exc
    values: dict[str, FieldValue] = {}
    unnamed = 0
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "TimeCreated" and element.attrib.get("SystemTime"):
            name = "TimeCreated"
            value = element.attrib["SystemTime"]
        elif tag == "Data" and element.attrib.get("Name"):
            name = element.attrib["Name"]
            value = element.text or ""
        elif tag == "Data":
            unnamed += 1
            name = f"param{unnamed}"
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
            if name == "xml_name":
                continue
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
    caveats = []
    if isinstance(original, str) and _original_too_large(original):
        caveats.append(f"event.original exceeds {EVENT_XML_MAX_BYTES} bytes; XML was not parsed")
    elif not data and original not in (None, ""):
        if not isinstance(original, str):
            raise WindowsInputError("event.original must be text")
        data = _xml_data(original, hit["_id"])
    time_created = winlog.get("time_created") or source.get("@timestamp")
    if time_created not in (None, "") and "TimeCreated" not in data:
        time_origin = "winlog.time_created" if winlog.get("time_created") else "@timestamp"
        data["TimeCreated"] = fv(time_created, f"{hit['_id']}:{time_origin}")
    _parsed_hashes(data)
    if event_class.family in {"silent_process_exit", "database_audit", "boot_configuration", "ese_database",
                              "winsock_catalog", "application_compatibility", "msi_install", "security_enumeration",
                              "privilege_adjustment", "dcom_access", "network_filter", "remote_access", "rpc_call"}:
        for name, path in (("EnvelopeProcessId", "process.pid"), ("EnvelopeActorSid", "user.identifier"),
                           ("ConnectionActivity", "activity_id")):
            # These keys are reserved internal aliases, never native payload facts.
            # Remove case variants too because _put supports case-insensitive native names.
            for key in tuple(data):
                if key.casefold() == name.casefold():
                    data.pop(key)
            value = _get(winlog, path)
            if value is not None:
                data[name] = fv(value, f"{hit['_id']}:winlog.{path}")
    return WindowsRecord(hit, event_class, data, caveats)


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


def _descriptor_text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("security descriptor must be a native string")
    return value


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
    names = ("param3",) if record.event_class.event_id in {400, 403} else ("param2", "param3")
    remaining = _POWERSHELL_DATA_MAX_BYTES
    for name in (*names, "Data"):
        item = record.data.get(name)
        if item is None or _native_value_is_absent(name, item.value):
            continue
        values = item.value if isinstance(item.value, (list, tuple)) else (item.value,)
        text = "\n".join(str(value) for value in values)
        size = len(text.encode("utf-8")) if len(text) <= remaining else remaining + 1
        if size > remaining:
            record.caveats.append(f"{name} exceeds {_POWERSHELL_DATA_MAX_BYTES} bytes and was not parsed")
            continue
        remaining -= size
        context = _key_value_lines(text)
        if record.event_class.event_id == 800 and name == "param2" and context:
            fields["script.context"] = fv(context, item.origin)
        parsed = {key.casefold(): value for key, value in context.items()}
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
    object_type = str(record.data.get("ObjectType").value).casefold() if "ObjectType" in record.data else ""
    object_codes = _OBJECT_ACCESS_CODES.get(object_type, {})
    for token in re.findall(r"%%\d+|[^\s,;]+", str(item.value)):
        if token.startswith("%%"):
            name = object_codes.get(token) or _ACCESS_CODES.get(token)
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
    if text == "-" and name.casefold() != "startmodule":
        return True
    if name.casefold().endswith("sid") and text in {"null sid", "s-1-0-0"}:
        return True
    if name.casefold().endswith(("address", "ip")) and text in {"::", "0", "0.0.0.0"}:
        return True
    return text in _ABSENT_FIELD_VALUES.get(name, frozenset())


def _put(fields: dict[str, FieldValue], record: WindowsRecord, typed: str, *native: str, transform=None) -> None:
    for name in native:
        item = record.data.get(name)
        if item is None:
            folded = record.__dict__.get("_folded_data")
            if folded is None:
                folded = {}
                for key, field in record.data.items():
                    folded.setdefault(key.casefold(), []).append(field)
                record.__dict__["_folded_data"] = folded
            candidates = folded.get(name.casefold(), [])
            if candidates and all(field.value == candidates[0].value for field in candidates):
                item = candidates[0]
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
    23: "deleted_archived", 26: "deleted", 29: "executable_detected",
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
    fields: dict[str, FieldValue], record: WindowsRecord, role: str, *native_names: str, transform=_ip,
) -> None:
    _put(fields, record, f"{role}.ip", *native_names, transform=transform)
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
    return Outcome.failure if event_id == 4766 or _status_failed(record) else _audit_outcome(record)


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
    _put(fields, record, "file.is_executable", "IsExecutable", transform=_boolean)
    hashes = {algorithm.casefold(): str(item.value).casefold() for algorithm in ("MD5", "SHA1", "SHA256", "IMPHASH")
              if (item := record.data.get(f"Hashes.{algorithm}")) is not None}
    if hashes:
        origin = next(item.origin for algorithm in ("MD5", "SHA1", "SHA256", "IMPHASH")
                      if (item := record.data.get(f"Hashes.{algorithm}")) is not None)
        marker = "#parsed:sysmon-hashes"
        fields["file.hashes"] = fv(hashes, origin if origin.endswith(marker) else origin + marker)
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


def _host_port(value: object) -> tuple[str, int | None]:
    """Parse native endpoint notation without mistaking bare IPv6 for a port."""
    text = str(value).strip()
    try:
        return _ip(text), None
    except ValueError:
        pass
    if text.startswith("["):
        host, separator, tail = text[1:].partition("]")
        if not separator or (tail and not tail.startswith(":")):
            raise ValueError("invalid bracketed endpoint")
        port = tail[1:] if tail else ""
    else:
        host, separator, port = text.rpartition(":")
        if not separator:
            raise ValueError("missing endpoint separator")
    number = _integer(port) if port else None
    if number is not None and not 0 <= number <= 65535:
        raise ValueError("port is outside the valid range")
    return _ip(host), number


def _wfp_port(value: object) -> int:
    # The server-side WFP filter matches native decimal port fields. Accept only
    # representations for which that typed retrieval contract is a superset.
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TypeError("port must be canonical decimal text or integer")
    text = str(value)
    if not re.fullmatch(r"0|[1-9][0-9]{0,4}", text) or int(text) > 65535:
        raise ValueError("port must be canonical decimal in 0..65535")
    return int(text)


def _wfp_address(value: object) -> str:
    # Retrieval uses native-address prefixes, so padding is outside this schema.
    # Expanded IPv6 remains supported and is canonicalized by the common parser.
    if not isinstance(value, str):
        raise TypeError("WFP address must be text")
    if value != value.strip():
        raise ValueError("WFP address contains surrounding whitespace")
    return _ip(value)


def _boot_option(value: object) -> object:
    text = str(value)
    if text in {"%%1846", "%%1848"}:
        return {"%%1846": "Default", "%%1848": "Off"}[text]
    return _message_value(value)


_CATALOG_FAMILIES = frozenset({
    "silent_process_exit", "database_audit", "boot_configuration", "ese_database", "winsock_catalog",
    "application_compatibility", "msi_install", "security_enumeration", "privilege_adjustment",
    "dcom_access", "network_filter",
})


def _sql_audit_fields(value: str) -> dict[str, str]:
    """Read audit headers once; everything after statement belongs to SQL text."""
    headers = {"action_id", "succeeded", "object_name", "server_principal_name", "database_name",
               "client_ip", "application_name", "session_id", "statement"}
    result: dict[str, str] = {}
    lines = value.splitlines()
    for index, line in enumerate(lines):
        name, separator, text = line.partition(":")
        name = name.strip().casefold()
        if not separator or name not in headers:
            continue
        if name == "statement":
            # SQL comments and literals can themselves contain header-looking lines.
            # They must never overwrite authoritative metadata or truncate the SQL.
            result[name] = "\n".join([text, *lines[index + 1:]]).strip()
            break
        if text.strip():
            result.setdefault(name, text.strip())
    return result


def _catalog_fields(fields: dict[str, FieldValue], record: WindowsRecord) -> Outcome | None:
    family, code = record.event_class.family, record.event_class.event_id
    if family not in _CATALOG_FAMILIES and family != "remote_access":
        return None
    _put(fields, record, "process.pid", "EnvelopeProcessId", transform=_integer)
    _put(fields, record, "process.actor_sid", "EnvelopeActorSid")
    if family == "remote_access":
        return None
    mappings = {
        "silent_process_exit": (("monitor.exited_image", "param1"), ("monitor.initiating_image", "param2"),
                                ("monitor.exited_creation_time", "param4")),
        "ese_database": (("ese.instance", "param1"), ("ese.database_path", "param5")),
        "winsock_catalog": (("lsp.name", "LSPName"), ("lsp.installer", "Installer"),
                            ("lsp.catalog", "Catalog"), ("lsp.guid", "GUID"), ("lsp.category", "Category")),
        "application_compatibility": (("compat.exe_path", "ExePath"), ("compat.fix_name", "FixName"),
                                      ("compat.resolver", "ResolverName"), ("compat.fix_id", "FixID"),
                                      ("compat.flags", "Flags")),
        "msi_install": (("msi.package", "param1"),),
        "security_enumeration": (("enum.target_name", "TargetUserName"), ("enum.target_sid", "TargetSid"),
                                 ("enum.target_domain", "TargetDomainName"), ("enum.caller_process", "CallerProcessName")),
        "dcom_access": tuple((f"dcom.{name}", f"param{index}") for index, name in enumerate(
            ("permission", "scope", "operation", "clsid", "appid", "domain", "user", "user_sid", "address"), 1)),
        "network_filter": (("wfp.application", "Application"), ("wfp.layer", "LayerName")),
    }
    for typed, native in mappings.get(family, ()):
        transform = _guid if typed in {"lsp.guid", "compat.fix_id", "dcom.clsid", "dcom.appid"} else None
        _put(fields, record, typed, native, transform=transform)
    for typed in ("monitor.exited_image", "monitor.initiating_image", "ese.database_path", "lsp.installer",
                  "compat.exe_path", "enum.caller_process", "wfp.application"):
        _path_metadata(fields, typed, typed + "_key")
    if family == "silent_process_exit":
        _put(fields, record, "monitor.exit_code", "param3", transform=_integer)
    elif family == "ese_database":
        fields["ese.action"] = fv({216: "engine_detached", 325: "created", 326: "attached", 327: "detached"}[code], fields["event.code"].origin)
        _put(fields, record, "ese.pid", "param2", transform=_integer)
    elif family == "application_compatibility":
        fields["compat.action"] = fv("shim_applied" if code == 500 else "resolver_fired", fields["event.code"].origin)
        _put(fields, record, "compat.pid", "ProcessId", transform=_integer)
    elif family == "msi_install":
        fields["msi.action"] = fv("transaction_begin" if code == 1040 else "transaction_end", fields["event.code"].origin)
        _put(fields, record, "msi.client_pid", "param2", transform=_integer)
        item = fields.get("msi.package")
        if item:
            text = str(item.value)
            kind = "url" if re.match(r"(?i)^(?:https?|ftp)://[^\s/]+", text) else "product_code" if _GUID.fullmatch(text) else "path"
            fields["msi.package_kind"] = fv(kind, item.origin + "#computed:package-kind")
            if kind == "path":
                _path_metadata(fields, "msi.package", "msi.package_key")
    elif family == "database_audit":
        fields["db.instance"] = fields["event.provider"]
        fields["db.action"] = fv({15457: "option_changed", 33205: "audit_record", 15281: "procedure_blocked",
                                  18456: "login_failed", 18454: "login_succeeded"}[code], fields["event.code"].origin)
        if code == 15457:
            for name, native in (("name", "param1"), ("old", "param2"), ("new", "param3")):
                _put(fields, record, f"db.option.{name}", native)
        elif code == 15281:
            _put(fields, record, "db.blocked.procedure", "param6")
        elif code == 33205:
            raw = record.data.get("param1")
            if raw:
                audit = _sql_audit_fields(str(raw.value)[:_DETAILS_MAX_CHARS])
                for name, source in (("action_id", "action_id"), ("object_name", "object_name"),
                                     ("statement", "statement"), ("server_principal", "server_principal_name"),
                                     ("database", "database_name"), ("application", "application_name")):
                    if audit.get(source):
                        fields[f"db.audit.{name}"] = fv(audit[source].strip(), raw.origin + "#parsed:" + source)
                for name, transform in (("succeeded", _boolean), ("client_ip", _ip)):
                    if name in audit:
                        try:
                            fields[f"db.audit.{name}"] = fv(transform(audit[name]), raw.origin + "#parsed:" + name)
                        except (ValueError, TypeError):
                            record.caveats.append(f"SQL audit {name} is malformed; field omitted")
                if len(str(raw.value)) > _DETAILS_MAX_CHARS:
                    record.caveats.append("SQL audit text exceeds retained detail limit; parsed fields are partial")
        else:
            _put(fields, record, "db.login.name", "param1")
            if code == 18456:
                _put(fields, record, "db.login.reason", "param2")
            _put(fields, record, "db.login.client_ip", "param3" if code == 18456 else "param2",
                 transform=lambda value: _ip(re.sub(r"(?i)^\s*\[CLIENT:\s*|\]\s*$", "", str(value))))
        if code == 33205:
            result = fields.get("db.audit.succeeded")
            return Outcome.unknown if result is None else Outcome.success if result.value else Outcome.failure
        return Outcome.failure if code in {18456, 15281} else Outcome.success
    elif family == "boot_configuration":
        for name, native in (("kernel_debug", "KernelDebug"), ("test_signing", "TestSigning"),
                             ("flight_signing", "FlightSigning"), ("disable_integrity_checks", "DisableIntegrityChecks"),
                             ("hypervisor_debug", "HypervisorDebug")):
            _put(fields, record, f"boot.{name}.raw", native)
            item = record.data.get(native)
            if item:
                if str(item.value) in {"%%1842", "%%1843"}:
                    fields[f"boot.{name}"] = fv(item.value == "%%1842", item.origin + "#parsed:boot-setting")
                else:
                    record.caveats.append(f"Unknown boot setting {native}; boolean omitted")
        for name, native in (("advanced_options", "AdvancedOptions"), ("config_access_policy", "ConfigAccessPolicy"),
                             ("vsm_launch_type", "VsmLaunchType")):
            _put(fields, record, f"boot.{name}", native, transform=_boot_option)
    elif family == "security_enumeration":
        fields["enum.action"] = fv("local_group_members" if code == 4799 else "local_user_groups", fields["event.code"].origin)
        _put(fields, record, "enum.caller_pid", "CallerProcessId", transform=_integer)
        if fields.get("enum.caller_pid") and fields["enum.caller_pid"].value == 0:
            fields.pop("enum.caller_pid")
    elif family == "privilege_adjustment":
        _put(fields, record, "privilege.enabled", "EnabledPrivilegeList", transform=lambda v: str(v).split())
        _put(fields, record, "privilege.disabled", "DisabledPrivilegeList", transform=lambda v: str(v).split())
        _put(fields, record, "process.executable", "ProcessName")
        _path_metadata(fields, "process.executable", "process.executable_key")
        _put(fields, record, "process.pid", "ProcessId", transform=_integer)
    elif family == "network_filter":
        _put(fields, record, "wfp.layer", "LayerName", transform=lambda value:
             {"%%14610": "Receive/Accept", "%%14611": "Connect"}.get(str(value), str(value)))
        _put(fields, record, "process.pid", "ProcessID", transform=_integer)
        _address_fields(fields, record, "source", "SourceAddress", transform=_wfp_address)
        _address_fields(fields, record, "destination", "DestAddress", transform=_wfp_address)
        _put(fields, record, "source.port", "SourcePort", transform=_wfp_port)
        _put(fields, record, "destination.port", "DestPort", transform=_wfp_port)
        direction = {"%%14592": "ingress", "%%14593": "egress"}.get(str(record.value("Direction")))
        if direction:
            fields["network.direction"] = fv(direction, record.origin("Direction") + "#parsed:wfp-direction")
            local, remote = ("destination.ip", "source.ip") if direction == "ingress" else ("source.ip", "destination.ip")
            for typed, key in (("network.local_address", local), ("network.remote_address", remote)):
                if key in fields:
                    fields[typed] = fields[key]
        elif record.value("Direction"):
            record.caveats.append("Unknown WFP direction; local and remote address roles omitted")
        _put(fields, record, "network.transport", "Protocol", transform=lambda v: {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}.get(_integer(v), str(v)))
    elif family == "dcom_access":
        return Outcome.failure
    return Outcome.success


def rpc_protocol(value: object) -> str:
    """The RPC provider's numeric and protocol-sequence spellings; unknowns are never guessed."""
    protocols = {"1": "tcp", "ncacn_ip_tcp": "tcp", "2": "named_pipe", "ncacn_np": "named_pipe",
                 "3": "local", "ncalrpc": "local"}
    result = protocols.get(str(value).strip().casefold())
    if result is None:
        raise ValueError("unrecognized RPC protocol")
    return result


def _rpc_address(value: object) -> str | None:
    if not isinstance(value, str):
        raise TypeError("RPC network address must be text")
    text = value.strip().lstrip("\\").strip("[]")
    if not text or text.casefold() == "null":
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        if re.fullmatch(r"[\w.-]+", text):
            return text.rstrip(".").casefold()
        raise ValueError("not an IP address or host name") from None


def _rpc_fields(fields, record):
    fields["rpc.side"] = fv("client" if record.event_class.event_id == 5 else "server",
                            fields["event.code"].origin + "#computed:side")
    _put(fields, record, "rpc.interface_uuid", "InterfaceUuid", transform=rpc_catalog.canonical_uuid)
    _put(fields, record, "rpc.opnum", "ProcNum", transform=_integer)
    if "rpc.opnum" not in fields:
        record.caveats.append("ProcNum missing or invalid; RPC operation is untyped")
    _put(fields, record, "rpc.protocol", "Protocol", transform=rpc_protocol)
    if "rpc.protocol" not in fields:
        record.caveats.append("Protocol missing or unrecognized; RPC transport is untyped")
    _put(fields, record, "rpc.endpoint", "Endpoint")
    _put(fields, record, "rpc.network_address", "NetworkAddress", transform=_rpc_address)
    _put(fields, record, "process.pid", "EnvelopeProcessId", transform=_integer)
    call = rpc_catalog.lookup_call(fields.get("rpc.interface_uuid", fv(None, "")).value,
                                  fields.get("rpc.opnum", fv(None, "")).value)
    origin = record.origin("InterfaceUuid") if "InterfaceUuid" in record.data else fields["event.code"].origin
    fields["rpc.op_class"] = fv(call.op_class, origin + "#rpc_catalog")
    if call.interface:
        fields["rpc.interface_name"] = fv(call.interface.zeek_names[0], origin + "#rpc_catalog")
    if call.operation:
        fields["rpc.operation"] = fv(call.operation.name, origin + "#rpc_catalog")
    return Outcome.unknown


def _semantic_fields(fields: dict[str, FieldValue], record: WindowsRecord, host: str) -> Outcome:
    event_id, family = record.event_class.event_id, record.event_class.family
    if family == "rpc_call":
        return _rpc_fields(fields, record)
    _account_fields(fields, record)
    extra = _catalog_fields(fields, record)
    if extra is not None:
        return extra
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
        if event_id not in {12, 13, 6005, 6006}:
            fields["system.event"] = fv("service_state_changed" if event_id == 7036 else "security_activity",
                                        fields["event.code"].origin)
            _put(fields, record, "service.name", "param1")
            _put(fields, record, "service.state", "param2")
            _put(fields, record, "security.logon_process", "LogonProcessName")
            _put(fields, record, "security.service", "Service")
            _put(fields, record, "security.privileges", "PrivilegeList", transform=lambda v: str(v).split())
            _put(fields, record, "security.group_membership", "GroupMembership")
            _put(fields, record, "transaction.id", "TransactionId")
            return Outcome.failure if event_id in {5805, 5723} else _audit_outcome(record)
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
        fields["object.action"] = fv({4656: "handle_requested", 4661: "handle_requested", 4663: "accessed", 4670: "permissions_changed"}.get(
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
                              ("wmi.namespace", "Namespace"), ("wmi.filter", "ESS"),
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
        if event_id == 800:
            _put(fields, record, "script.text", "param1")
            _put(fields, record, "script.module_payload", "param3")
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
        complete = event_id != 800
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
        fields["script.view"] = fv(
            "single" if event_id != 4104 or complete else "fragment",
            fields["event.code"].origin + "#computed:script-view",
        )
        return Outcome.success
    if family in {"directory_access", "directory_change"}:
        prefix = "directory.access" if family == "directory_access" else "directory.change"
        session = _session_id(record, "SubjectLogonId")
        if session:
            fields["directory.actor_session_id"] = fv(*session)
        fields[f"{prefix}.action"] = fv({4662: "accessed", 4706: "trust_created", 4716: "trust_modified",
                                         5136: "modified", 5137: "created",
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
        for suffix, names, transform in (
            ("domain_name", ("DomainName",), None), ("domain_sid", ("DomainSid",), None),
            ("type", ("TdoType", "TrustType"), _integer),
            ("direction", ("TdoDirection", "TrustDirection"), _integer),
            ("attributes", ("TdoAttributes", "TrustAttributes"), _integer),
            ("sid_filtering_enabled", ("SidFilteringEnabled",), None),
        ):
            _put(fields, record, f"directory.trust.{suffix}", *names, transform=transform)
        properties = record.data.get("Properties")
        if properties:
            guids = [match.group(1).casefold() for match in _GUID_IN_TEXT.finditer(str(properties.value))]
            if guids:
                fields["directory.rights.guids"] = fv(guids, properties.origin + "#parsed:right-guids")
                names = [_DIRECTORY_RIGHT_GUIDS[guid] for guid in guids if guid in _DIRECTORY_RIGHT_GUIDS]
                if names:
                    fields["directory.rights.names"] = fv(names, properties.origin + "#mapped:ad-schema")
        return _audit_outcome(record)
    if family == "share_change":
        fields["share.change"] = fv({5142: "added", 5143: "modified", 5144: "deleted"}[event_id],
                                   fields["event.code"].origin)
        _put(fields, record, "share.name", "ShareName")
        _put(fields, record, "share.local_path", "ShareLocalPath")
        _put(fields, record, "share.security_descriptor.old", "OldSD", transform=_descriptor_text)
        _put(fields, record, "share.security_descriptor.new", "NewSD", transform=_descriptor_text)
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
                   60: "bits_transfer_completed", 4: "bits_job_complete", 5: "bits_job_cancelled",
                   61: "bits_transfer_error", 209: "bits_notification", 169: "winrm_authentication",
                   193: "winrm_virtual_account", 131: "rdp_connection_accepted", 132: "rdp_channel_created",
                   148: "rdp_channel_closed", 168: "rdp_client_resolution", 104: "rdp_client_timezone",
                   68: "rdp_connection_setup", 129: "rdp_listener"}
        fields["remote.action"] = fv(actions.get(event_id, "remote_activity"), fields["event.code"].origin)
        activity = record.hit["_source"]["winlog"].get("activity_id")
        if isinstance(activity, str) and activity:
            fields["remote.connection_activity"] = fv(activity, f"{record.hit['_id']}:winlog.activity_id")
        elif activity not in (None, ""):
            record.caveats.append("winlog.activity_id is malformed; connection correlation was omitted")
        _put(fields, record, "remote.channel_name", "ChannelName")
        _put(fields, record, "remote.tunnel_id", "TunnelID")
        _put(fields, record, "remote.conn_type", "ConnType")
        _put(fields, record, "remote.monitor_width", "MonitorWidth", transform=_integer)
        _put(fields, record, "remote.monitor_height", "MonitorHeight", transform=_integer)
        _put(fields, record, "remote.auth_mechanism", "authenticationMechanism")
        if record.value("ClientIP") is not None:
            try:
                ip, port = _host_port(record.value("ClientIP"))
                origin = record.origin("ClientIP")
                fields["source.ip"] = fv(ip, origin + "#parsed:host-port")
                fields["source.is_loopback"] = fv(ipaddress.ip_address(ip).is_loopback, origin + "#computed:loopback")
                if port is not None:
                    fields["source.port"] = fv(port, origin + "#parsed:host-port")
            except (ValueError, TypeError) as exc:
                record.caveats.append(f"ClientIP is malformed and source endpoint was omitted: {exc}")
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
        _put(fields, record, "remote.resource", "ResourceUri", "Url", "RemoteName", "connection")
        _put(fields, record, "bits.job_id", "JobId", "Id", transform=_guid)
        _put(fields, record, "bits.job_name", "jobTitle", "JobName", "name", "string")
        _put(fields, record, "bits.owner", "jobOwner", "string2")
        _put(fields, record, "bits.process_path", "processPath")
        _path_metadata(fields, "bits.process_path", "bits.process_path_key")
        _put(fields, record, "bits.process_id", "processId", transform=_integer)
        _put(fields, record, "bits.remote_url", "Url", "RemoteName")
        _put(fields, record, "bits.local_file", "LocalName", "FileName")
        remote = fields.get("bits.remote_url")
        if remote:
            text = str(remote.value).casefold()
            scheme = text.split(":", 1)[0] if "://" in text else "unc" if text.startswith("\\\\") else "file"
            fields["bits.url_scheme"] = fv(scheme, remote.origin + "#computed:url-scheme")
        if event_id == 169 and fields.get("remote.user"):
            user = fields["remote.user"]
            domain, separator, name = str(user.value).partition("\\")
            fields["remote.user"] = fv(name if separator else domain, user.origin)
            if separator:
                fields["remote.domain"] = fv(domain, user.origin)
        return Outcome.failure if _status_failed(record) else Outcome.success
    return Outcome.unknown


def normalize_windows(hit: dict) -> TypedEvent:
    """Normalize one cataloged Windows event from structured shipper fields only."""
    if is_nxlog_windows(hit.get("_source") or {}):
        return _normalize_nxlog(hit)
    if is_evtx_json(hit.get("_source") or {}):
        adapted = evtx_json_to_winlog(hit["_source"])
        event = _normalize_windows({**hit, "_source": adapted}, hit)
        paths = adapted[EVTX_JSON_ADAPTED]["paths"]
        event.fields = {name: fv(value.value, _native_origin(value.origin, hit["_id"], paths))
                        for name, value in event.fields.items()}
        if adapted[EVTX_JSON_ADAPTED]["recovered"]:
            event.caveats.append(EVTX_JSON_RECOVERED)
        return event
    return _normalize_windows(hit, hit)


def _normalize_nxlog(hit: dict) -> TypedEvent:
    """An NXLog flat record, normalized as its Winlogbeat-layout twin: every typed value cites the record's own
    field, the native channel spelling and EventTime text are kept, and a time taken from the pipeline says so."""
    source, native_id = hit["_source"], hit["_id"]
    adapted, paths = nxlog_to_winlog(source)
    winlog = adapted["winlog"]
    named = _CLASSES_BY_PROVIDER_ID.get(_nxlog_class_key(source), ())
    if named and lookup_event_class(winlog["channel"], winlog["provider_name"], winlog["event_id"]) is None:
        # a catalogued provider and event id under a channel that names none of their classes: counted against
        # those classes' families, never as an unread class
        raise WindowsNotNormalized(f"{NXLOG_CHANNEL_SKIP} ({named[0].provider}|{named[0].event_id})")
    event = _normalize_windows({**hit, "_source": adapted}, hit)
    event.fields = {name: fv(value.value, _native_origin(value.origin, native_id, paths))
                    for name, value in event.fields.items()}
    event.fields["nxlog.channel"] = fv(source.get("Channel"), f"{native_id}:Channel")
    if source.get("EventTime") is not None:
        event.fields["nxlog.event_time"] = fv(str(source["EventTime"]), f"{native_id}:EventTime")
    created = event.fields.get("event.created")
    if adapted[NXLOG_ADAPTED]["pipeline_time"] and (created is None or created.origin == f"{native_id}:@timestamp"):
        event.caveats.append(NXLOG_TIME_CAVEAT)
    if adapted[NXLOG_ADAPTED]["catalog_channel"]:
        event.caveats.append(NXLOG_CATALOG_CHANNEL_CAVEAT)
    return event


def _normalize_windows(hit: dict, raw_hit: dict) -> TypedEvent:
    """Normalize `hit` (Winlogbeat or Agent layout); `raw_hit` is the record as indexed, which the event cites."""
    record = read_windows_event(hit)
    source, winlog = hit["_source"], hit["_source"]["winlog"]
    ref = _raw_ref(raw_hit)
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
        try:
            timestamp = _event_time(event_time.value)
            fields["event.created"] = fv(timestamp.isoformat(), event_time.origin)
        except (ValueError, TypeError, OverflowError):
            record.caveats.append(f"malformed native event time at {event_time.origin}; @timestamp used")
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
