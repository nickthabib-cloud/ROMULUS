"""Indicator export: values seen in typed fields of reportable findings, as STIX 2.1 and CSV.

Values come only from typed evidence: a finding's typed entities and predicate fields, and the typed fields of the
events it cites as its subject. Each value is read by the field that gives it meaning (an address as a source or
destination, a name as a DNS question or a TLS server name, a hash as a process image's), and that field and role
are exported with it. Nothing is read from raw text, claims, notes, mentions or model prose; a finding whose claim is
a mention (text a record contains) contributes no value. Presence here is not a verdict that a value is malicious:
the export lists what the reportable findings rest on, with each address marked internal or external by the hunt's
recorded site networks so a partner can filter.

Every value passes credential masking before it is kept: a value holding a credential (a URL's user information or
a credential parameter, a credential-like literal, a configured secret) is withheld and counted by reason, never
exported in part. The aggregation runs in a scratch SQLite file (`romulus.report.spill`), so a hunt with a million
findings is exported exactly with bounded memory; the files are written streaming, and their content digest and
counts are checked against the report manifest before they replace anything.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from itertools import groupby

from romulus.content.indicator_values import (
    _SECRET_ASSIGNMENT,
    _SECRET_LITERAL,
    _URI_USERINFO,
    normalize_value,
)
from romulus.detect.netdef import SiteNetworks
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.evidence.zeek_credentials import REDACTED
from romulus.hunt.mention_fields import mask_credentials
from romulus.report.spill import scratch_db

LABEL = ("Values seen in typed fields of reportable findings (never raw text, mentions or model prose). An entry is "
         "not a verdict that the value is malicious: internal addresses and the hunt's own hosts are marked so they "
         "can be filtered")
CSV_SUFFIX = "-iocs.csv"
STIX_SUFFIX = "-iocs-stix.json"
PREVIEW = 50
STIX_FINDING_IDS = 100
STIX_ROLES = 20
MAX_TEXT = 4096
FINDING_BATCH = 200
EVENT_BATCH = 500
ROW_BATCH = 5_000
SCOPES = ("external", "unknown", "not_applicable", "internal")

# typed field -> (indicator kind, role); a list value is read element by element
FIELD_KINDS = {
    "source.ip": ("ip", "source address"), "client.ip": ("ip", "client address"),
    "destination.ip": ("ip", "destination address"), "server.ip": ("ip", "server address"),
    "vpn.assigned_ip": ("ip", "VPN-assigned address"), "vpn.assigned_ipv6": ("ip", "VPN-assigned address"),
    "dns.question.name": ("domain", "DNS question name"), "dns.question.names": ("domain", "DNS question name"),
    "http.hostname": ("domain", "HTTP host"), "http.host": ("domain", "HTTP host"),
    "url.domain": ("domain", "URL host"), "destination.domain": ("domain", "destination domain"),
    "tls.client.server_name": ("domain", "TLS server name (SNI)"),
    "x509.san_dns": ("domain", "certificate subject alternative name"),
    "url.full": ("url", "URL"), "url.original": ("url", "URL"), "http.url": ("url", "URL"),
    "bits.remote_url": ("url", "BITS transfer URL"),
    "file.path": ("file_path", "file path"), "file.name": ("file_name", "file name"),
    "image.path": ("file_path", "loaded image path"),
    "process.executable": ("process_executable", "executable"),
    "process.parent.executable": ("process_executable", "parent executable"),
    "process.name": ("file_name", "process name"),
    "user.name": ("user_account", "account"), "process.user": ("user_account", "process account"),
    "auth.target_user": ("user_account", "target account"), "auth.target_account": ("user_account", "target account"),
    "tls.ja3": ("ja3", "TLS client fingerprint"), "tls.ja3s": ("ja3s", "TLS server fingerprint"),
    "tls.ja4": ("ja4", "TLS client fingerprint"), "tls.ja4s": ("ja4s", "TLS server fingerprint"),
    "ssh.hassh": ("hassh", "SSH client fingerprint"), "ssh.hassh_server": ("hassh_server", "SSH server fingerprint"),
    "ssh.hasshServer": ("hassh_server", "SSH server fingerprint"),
    "x509.fingerprint": ("x509_sha256", "certificate fingerprint"),
    "tls.server.hash_sha1": ("x509_sha1", "server certificate"), "tls.client.hash_sha1": ("x509_sha1",
                                                                                          "client certificate"),
    "tls.server.hash.sha256": ("x509_sha256", "server certificate"),
    "file.sha256": ("sha256", "HTTP body hash"),
}
HASH_PREFIXES = {"process.hash": "process image hash", "image.hash": "loaded image hash", "file.hash": None}
HASH_ROLE_BY_FAMILY = {"process_exec": "process image hash", "image_load": "loaded image hash",
                       "file_change": "file hash", "file_transfer": "transferred file hash"}
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128, "x509_sha1": 40, "x509_sha256": 64,
                "ja3": 32, "ja3s": 32, "hassh": 32, "hassh_server": 32}
ENTITY_KINDS = {"ip": "ip", "host": "hostname", "account": "user_account", "domain": "domain", "url": "url",
                "sni": "domain", "executable": "process_executable", "file": "file_path"}
ENTITY_ROLES = {("ip", "src"): "source address", ("ip", "dst"): "destination address",
                ("ip", "assigned"): "VPN-assigned address", ("host", "observer"): "network sensor",
                ("host", "host"): "reporting host", ("account", "actor"): "acting account",
                ("account", "subject"): "target account", ("sni", "subject"): "TLS server name (SNI)"}
_JA4 = re.compile(r"[a-z0-9_]{1,128}")
_HEX = re.compile(r"[0-9a-f]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
# a CSV cell a spreadsheet would run as a formula once leading space is skipped
_FORMULA = re.compile(r"^[\s]*[=+\-@\t\r|%]")

# STIX: the 2.1 namespace for cyber-observable ids, and one for the objects this export identifies by content
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
ROMULUS_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:romulus:report:stix")
IDENTITY_TIME = "2024-01-01T00:00:00.000Z"
HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
FINGERPRINT_KINDS = ("ja3", "ja3s", "ja4", "ja4s", "hassh", "hassh_server")


class ExportMismatch(ValueError):
    """The export's content differs from what its report manifest recorded."""


def csv_cell(value) -> str:
    """A CSV cell a spreadsheet shows as text: a value that would start a formula is prefixed with a quote."""
    text = "" if value is None else str(value)
    return "'" + text if _FORMULA.match(text) else text


def _utc(value) -> str | None:
    if value in (None, "", "None"):
        return None
    try:
        moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except ValueError:
        return None
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _secrets(settings) -> list[str]:
    if settings is None:
        return []
    from romulus.config import _secret_forms, secret_settings

    return sorted({form for _name, secret in secret_settings(settings) if len(secret) >= 4
                   for form in _secret_forms(secret)}, key=len, reverse=True)


class _Checker:
    """Validation and credential masking of one value; returns (kind, canonical value) or (None, reason)."""

    def __init__(self, networks: SiteNetworks | None, secrets: list[str]):
        self.networks, self.secrets = networks, secrets

    def __call__(self, kind: str, value) -> tuple[str | None, str]:
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return None, "not a text value"
        text = str(value).strip()
        if not text or text in ("-", "(empty)") or REDACTED in text:
            return None, "empty or already redacted"
        if len(text) > MAX_TEXT or _CONTROL.search(text) or any(0xD800 <= ord(c) <= 0xDFFF for c in text):
            return None, "too long or holds control characters"
        if any(secret in text for secret in self.secrets):
            return None, "holds a configured secret"
        if (mask_credentials(text) != text or _SECRET_ASSIGNMENT.search(text) or _SECRET_LITERAL.search(text)
                or _URI_USERINFO.search(text)):
            return None, "holds a credential"
        if kind == "ip":
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                return None, "not an address"
            return ("ipv4" if address.version == 4 else "ipv6"), str(address)
        if kind == "domain":
            if _is_address(text):
                return self("ip", text)
            try:
                return "domain", normalize_value("domain", text)
            except ValueError:
                return None, "not a domain name"
        if kind == "url":
            if "://" not in text:
                return None, "not an absolute URL"
            try:
                return "url", normalize_value("url", text)
            except ValueError:
                return None, "invalid or credential-bearing URL"
        if kind in HASH_LENGTHS:
            lowered = text.lower()
            if len(lowered) != HASH_LENGTHS[kind] or not _HEX.fullmatch(lowered):
                return None, "not a hash of its kind"
            return kind, lowered
        if kind in ("ja4", "ja4s"):
            lowered = text.lower()
            return (kind, lowered) if _JA4.fullmatch(lowered) else (None, "not a fingerprint")
        return kind, text

    def scope(self, kind: str, value: str) -> str:
        if kind == "hostname":
            return "internal"
        address = None
        if kind in ("ipv4", "ipv6"):
            address = ipaddress.ip_address(value)
        elif kind == "url":
            host = value.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            host = host[1:host.index("]")] if host.startswith("[") and "]" in host else host.rsplit(":", 1)[0]
            address = ipaddress.ip_address(host) if _is_address(host) else None
        elif kind != "domain":
            return "not_applicable"
        if address is None or self.networks is None:
            return "unknown"
        # the uncached lookup: each value is asked once here, and the definition's answer cache is left unfilled
        return "internal" if self.networks._decide(address) else "external"


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _values(value) -> list:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, (str, int)) and not isinstance(item, bool)]
    return [value] if value is not None else []


def event_values(event: dict) -> Iterator[tuple[str, object, str, str]]:
    """(kind, value, role, field) for every allowlisted typed field of one stored event."""
    fields = event.get("fields") or {}
    family = event.get("family")

    def get(name):
        item = fields.get(name)
        return item.get("value") if isinstance(item, dict) else None

    for name, (kind, role) in FIELD_KINDS.items():
        for value in _values(get(name)):
            yield kind, value, role, name
    for prefix, role in HASH_PREFIXES.items():
        for algorithm in HASH_NAMES:
            name = f"{prefix}.{algorithm}"
            for value in _values(get(name)):
                yield algorithm, value, role or HASH_ROLE_BY_FAMILY.get(family, "file hash"), name
    hashes = get("file.hashes")
    if isinstance(hashes, dict):
        for algorithm in HASH_NAMES:
            if isinstance(hashes.get(algorithm), str):
                yield (algorithm, hashes[algorithm], HASH_ROLE_BY_FAMILY.get(family, "file hash"),
                       "file.hashes")
    if event.get("host"):
        yield ("hostname", event["host"], "network sensor" if family in NETWORK_OBSERVER_FAMILIES
               else "reporting host", "host.name")


def finding_values(finding: dict) -> Iterator[tuple[str, object, str, str]]:
    """(kind, value, role, field) for a finding's typed entities and allowlisted predicate fields."""
    for entity in finding.get("entities") or ():
        if not isinstance(entity, (list, tuple)) or len(entity) < 2:
            continue
        kind = ENTITY_KINDS.get(str(entity[0]))
        if kind is None:
            continue
        role = str(entity[2]) if len(entity) > 2 else ""
        yield kind, entity[1], ENTITY_ROLES.get((str(entity[0]), role), role or str(entity[0])), f"entity.{entity[0]}"
    for predicate in finding.get("predicate_fields") or ():
        name = str(predicate.get("field", "")) if isinstance(predicate, dict) else ""
        if name in FIELD_KINDS:
            kind, role = FIELD_KINDS[name]
            for value in _values(predicate.get("value")):
                yield kind, value, role, name


def _subject_event_ids(finding: dict, context: set[str]) -> list[str]:
    """The records a finding is about: the events it cites except those cited only as context for its claim (a
    lineage ancestor, a record bounding a stated span), as `romulus.hunt.publish.subject_event_ids` reads them."""
    cited = list(dict.fromkeys(str(cite["event_id"]) for cite in finding.get("citations") or ()
                               if isinstance(cite, dict) and cite.get("event_id")))
    return [event_id for event_id in cited if event_id not in context] or cited


def _context_ids(repo, findings: list[dict]) -> dict[str, set[str]]:
    """Each finding's context-only event ids, read from its stored candidate."""
    if not hasattr(repo, "candidate_graph_inputs"):
        return {}
    return {row["id"]: set(row.get("context_event_ids") or ())
            for row in repo.candidate_graph_inputs([finding["id"] for finding in findings])}


def _site_networks(record: dict | None) -> tuple[SiteNetworks | None, dict]:
    """The hunt's recorded site networks (the default for a hunt recorded before they existed); an unreadable
    record leaves every address `unknown`, never external."""
    networks = None
    if record is None or record.get("source") in ("configured", "default"):
        try:
            networks = SiteNetworks.from_record(record)
        except (KeyError, TypeError, ValueError):
            networks = None
    if networks is None:
        return None, {"source": "unreadable", "note": "addresses are marked unknown, never external"}
    return networks, {"source": networks.source, "digest": networks.digest}


class IndicatorTable:
    """The rows of one export, held in a scratch database."""

    def __init__(self, db, networks_view: dict, secrets_checked: bool):
        self.db, self.networks_view, self.secrets_checked = db, networks_view, secrets_checked
        self.withheld: Counter = Counter()
        self.counts: Counter = Counter()
        self.hunt_id: str | None = None

    def rows(self) -> Iterator[tuple]:
        """Every row with its finding and its indicator's aggregates, in export order."""
        yield from self.db.execute(
            "SELECT r.kind, r.value, r.role, r.field, i.scope, f.id, f.lane, f.severity, f.confidence, f.provenance, "
            "f.rule_id, f.observed_at, i.first_seen, i.last_seen, i.findings FROM row r "
            "JOIN finding f ON f.seq = r.seq JOIN ind i ON i.kind = r.kind AND i.value = r.value "
            "ORDER BY r.kind, r.value, r.seq, r.role, r.field")

    def digest(self) -> str:
        """A content digest over every row (finding ids included), the same for every write of one manifest."""
        hasher = hashlib.sha256()
        for row in self.rows():
            hasher.update(json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass"))
            hasher.update(b"\n")
        return hasher.hexdigest()

    def summary(self) -> dict:
        """The manifest's indicator view: exact counts, a bounded preview, and the digest the files must match."""
        by_kind = {}
        for kind, indicators, rows, *scopes in self.db.execute(
                "SELECT i.kind, count(*), sum(i.rows), " + ", ".join(
                    f"sum(i.scope = '{scope}')" for scope in SCOPES) + " FROM ind i GROUP BY i.kind ORDER BY i.kind"):
            by_kind[kind] = {"indicators": indicators, "rows": rows,
                             **{scope: count for scope, count in zip(SCOPES, scopes, strict=True) if count}}
        order = " ".join(f"WHEN '{scope}' THEN {position}" for position, scope in enumerate(SCOPES))
        preview = []
        for kind, value, scope, first, last, findings in self.db.execute(
                f"SELECT kind, value, scope, first_seen, last_seen, findings FROM ind ORDER BY CASE scope {order} END, "
                "findings DESC, kind, value LIMIT ?", (PREVIEW,)):
            roles = [f"{role} ({field})" for role, field in self.db.execute(
                "SELECT DISTINCT role, field FROM row WHERE kind = ? AND value = ? ORDER BY role, field LIMIT 5",
                (kind, value))]
            preview.append({"kind": kind, "value": value, "scope": scope, "findings": findings,
                            "first_seen": first, "last_seen": last, "roles": roles})
        indicators = sum(item["indicators"] for item in by_kind.values())
        return {
            "label": LABEL, "status": "complete", "files": {"csv_suffix": CSV_SUFFIX, "stix_suffix": STIX_SUFFIX},
            "counts": {"indicators": indicators, "rows": sum(item["rows"] for item in by_kind.values()),
                       "findings": self.counts["findings"], "findings_with_indicators": self.db.execute(
                           "SELECT count(DISTINCT seq) FROM row").fetchone()[0],
                       "mention_findings_skipped": self.counts["mention_findings"],
                       "fleet_members_read": self.counts["fleet_members"],
                       "fleet_members_not_read": self.counts["fleet_members_not_read"],
                       "events_not_retained": self.counts["events_not_retained"], "by_kind": by_kind},
            "withheld": {kind: dict(sorted(reasons.items())) for kind, reasons in sorted(_nest(self.withheld).items())},
            "internal_networks": self.networks_view, "secrets_checked": self.secrets_checked,
            "digest": self.digest(), "preview": preview,
        }


def _nest(counter: Counter) -> dict[str, Counter]:
    nested: dict[str, Counter] = {}
    for (kind, reason), count in counter.items():
        nested.setdefault(kind, Counter())[reason] = count
    return nested


@contextmanager
def collect(repo, findings: Iterable[dict], internal_networks: dict | None, *, hunt_id: str | None = None,
            settings=None, scratch=None):
    """Gather the indicator rows of `findings` (reportable findings, report order) into an `IndicatorTable`. With
    `hunt_id`, a fleet finding's members are read from its host appendix as well."""
    networks, networks_view = _site_networks(internal_networks)
    check = _Checker(networks, _secrets(settings))
    with scratch_db(scratch) as db:
        db.execute("CREATE TABLE finding (seq INTEGER PRIMARY KEY, id TEXT, lane TEXT, severity TEXT, "
                   "confidence TEXT, provenance TEXT, rule_id TEXT, observed_at TEXT)")
        db.execute("CREATE TABLE row (kind TEXT, value TEXT, role TEXT, field TEXT, seq INTEGER, "
                   "PRIMARY KEY (kind, value, role, field, seq)) WITHOUT ROWID")
        table = IndicatorTable(db, networks_view, settings is not None)
        table.hunt_id = hunt_id
        batch: list[tuple[int, dict]] = []
        for seq, finding in enumerate(findings):
            table.counts["findings"] += 1
            if finding.get("claim_type") == "mention":
                table.counts["mention_findings"] += 1
                continue
            batch.append((seq, finding))
            if len(batch) >= FINDING_BATCH:
                _add_batch(repo, db, batch, check, table)
                batch = []
        if batch:
            _add_batch(repo, db, batch, check, table)
        db.execute("CREATE TABLE ind AS SELECT r.kind AS kind, r.value AS value, '' AS scope, "
                   "min(f.observed_at) AS first_seen, max(f.observed_at) AS last_seen, "
                   "count(DISTINCT r.seq) AS findings, count(*) AS rows FROM row r JOIN finding f ON f.seq = r.seq "
                   "GROUP BY r.kind, r.value")
        db.execute("CREATE UNIQUE INDEX ind_key ON ind (kind, value)")
        db.create_function("scope_of", 2, check.scope, deterministic=True)
        db.execute("UPDATE ind SET scope = scope_of(kind, value)")
        yield table


def _fleet_values(repo, table: IndicatorTable, finding: dict) -> Iterator[tuple[str, object, str, str]]:
    """The members a fleet finding stands for, from its immutable host appendix: hosts, or addresses."""
    ref = finding.get("fleet_hosts")
    if not ref:
        return
    if table.hunt_id is None or not hasattr(repo, "report_hosts"):
        table.counts["fleet_members_not_read"] += int(ref.get("count") or 0)
        return
    kind, role = (("ip", "fleet member address") if finding.get("fleet_member_kind") in (
        "external_address", "internal_address") else ("hostname", "fleet member host"))
    for row in repo.report_hosts(table.hunt_id, ref["sha256"]):
        table.counts["fleet_members"] += 1
        yield kind, row["host"], role, "fleet_hosts"


def _add_batch(repo, db, batch: list[tuple[int, dict]], check: _Checker, table: IndicatorTable) -> None:
    context = _context_ids(repo, [finding for _seq, finding in batch])
    subjects = {finding["id"]: _subject_event_ids(finding, context.get(finding["id"], set()))
                for _seq, finding in batch}
    wanted = list(dict.fromkeys(event_id for ids in subjects.values() for event_id in ids))
    events: dict[str, dict] = {}
    for start in range(0, len(wanted), EVENT_BATCH):
        for row in repo.events_by_ids(wanted[start:start + EVENT_BATCH]):
            payload = row.get("event") if isinstance(row.get("event"), dict) else {}
            events[row["id"]] = {"fields": payload.get("fields") or {}, "family": row.get("family"),
                                 "host": row.get("host")}
    rows = []
    for seq, finding in batch:
        db.execute("INSERT INTO finding VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
            seq, finding["id"], finding.get("lane"), finding.get("severity"), finding.get("confidence"),
            finding.get("provenance") or "deterministic", finding.get("rule_id"), _utc(finding.get("observed_at"))))
        sources = [finding_values(finding), _fleet_values(repo, table, finding)]
        for event_id in subjects[finding["id"]]:
            if event_id in events:
                sources.append(event_values(events[event_id]))
            else:
                table.counts["events_not_retained"] += 1
        for source in sources:
            for kind, value, role, field in source:
                exported, detail = check(kind, value)
                if exported is None:
                    table.withheld[(kind, detail)] += 1
                    continue
                rows.append((exported, detail, role, field, seq))
                if len(rows) >= ROW_BATCH:          # a fleet appendix can hold many members: insert as they come
                    db.executemany("INSERT OR IGNORE INTO row VALUES (?, ?, ?, ?, ?)", rows)
                    rows = []
    db.executemany("INSERT OR IGNORE INTO row VALUES (?, ?, ?, ?, ?)", rows)


# ---- writers ---------------------------------------------------------------------------------------------------

CSV_HEADER = ["kind", "value", "role", "field", "network_scope", "finding_id", "finding_lane", "finding_severity",
              "finding_confidence", "finding_provenance", "rule_id", "finding_observed_at", "indicator_first_seen",
              "indicator_last_seen", "indicator_findings"]


def write_csv(table: IndicatorTable, stream) -> int:
    """One row per indicator and finding (and role and field), every cell guarded against formula injection."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_HEADER)
    count = 0
    for row in table.rows():
        writer.writerow([csv_cell(value) for value in row])
        count += 1
        if buffer.tell() >= 1 << 16:
            stream.write(buffer.getvalue())
            buffer.seek(0)
            buffer.truncate(0)
    stream.write(buffer.getvalue())
    return count


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sco_id(kind: str, contributing: dict) -> str:
    """A STIX 2.1 deterministic cyber-observable id: UUIDv5 over its id-contributing properties."""
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, _canonical(contributing))}"


def romulus_id(kind: str, content) -> str:
    return f"{kind}--{uuid.uuid5(ROMULUS_NAMESPACE, _canonical(content))}"


def _split_path(path: str) -> tuple[str | None, str]:
    cut = max(path.rfind("/"), path.rfind("\\"))
    if cut <= 0 or cut == len(path) - 1:
        return None, path
    return path[:cut], path[cut + 1:]


def observables(kind: str, value: str) -> list[dict]:
    """The STIX cyber-observable objects for one indicator; the main object last."""
    def sco(stix_type: str, properties: dict, contributing: dict | None = None) -> dict:
        return {"type": stix_type, "spec_version": "2.1",
                "id": sco_id(stix_type, properties if contributing is None else contributing), **properties}

    if kind in ("ipv4", "ipv6", "domain", "url"):
        stix_type = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url"}[kind]
        return [sco(stix_type, {"value": value})]
    if kind in HASH_NAMES:
        return [sco("file", {"hashes": {HASH_NAMES[kind]: value}})]
    if kind in ("x509_sha1", "x509_sha256"):
        return [sco("x509-certificate", {"hashes": {"SHA-1" if kind == "x509_sha1" else "SHA-256": value}})]
    if kind == "user_account":
        return [sco("user-account", {"account_login": value})]
    if kind == "file_name":
        return [sco("file", {"name": value})]
    if kind in ("file_path", "process_executable"):
        directory, name = _split_path(value)
        if directory is None:
            return [sco("file", {"name": value})]
        folder = sco("directory", {"path": directory})
        return [folder, sco("file", {"name": name, "parent_directory_ref": folder["id"]})]
    if kind == "hostname":
        return [sco("x-romulus-hostname", {"value": value})]
    if kind in FINGERPRINT_KINDS:
        return [sco("x-romulus-fingerprint", {"fingerprint_type": kind, "value": value})]
    raise ValueError(f"no STIX mapping for indicator kind {kind}")


def stix_time(manifest: dict) -> str:
    """The export's object time: when the hunt ended, else the end of its window (never the clock)."""
    hunt = manifest.get("hunt") or {}
    return _utc(hunt.get("ended_at")) or _utc((hunt.get("window") or {}).get("end")) or IDENTITY_TIME


def write_stix(table: IndicatorTable, stream, manifest: dict) -> dict:
    """A STIX 2.1 bundle: the ROMULUS identity, per indicator its observables and an observed-data object, and a
    report object that references them all. Every id is derived from content, so a rewrite is byte-identical."""
    hunt = manifest["hunt"]
    revision = (manifest.get("revision") or {}).get("id") or ""
    when = stix_time(manifest)
    window = hunt.get("window") or {}
    identity = {"type": "identity", "spec_version": "2.1", "id": romulus_id("identity", "ROMULUS"),
                "created": IDENTITY_TIME, "modified": IDENTITY_TIME, "name": "ROMULUS", "identity_class": "system"}
    db = table.db
    db.execute("CREATE TEMP TABLE written (id TEXT PRIMARY KEY, seq INTEGER) WITHOUT ROWID")
    order = 0
    stream.write('{"id": "' + romulus_id("bundle", {"hunt": hunt["id"], "revision": revision,
                                                    "object": "bundle"})
                 + '", "objects": [\n')
    stream.write(json.dumps(identity, sort_keys=True))
    counts = Counter()
    # one ordered pass over every row, grouped by value: per value only bounded state is held
    joined = db.execute(
        "SELECT i.kind, i.value, i.scope, i.first_seen, i.last_seen, i.findings, r.role, r.field, f.seq, f.id, "
        "f.lane, f.provenance FROM ind i JOIN row r ON r.kind = i.kind AND r.value = i.value "
        "JOIN finding f ON f.seq = r.seq ORDER BY i.kind, i.value, f.seq")
    for (kind, value, scope, first, last, findings), group in groupby(joined, key=lambda row: row[:6]):
        objects = observables(kind, value)
        for item in objects:
            if db.execute("INSERT OR IGNORE INTO written VALUES (?, ?)", (item["id"], order)).rowcount:
                order += 1
                stream.write(",\n" + json.dumps(item, sort_keys=True, ensure_ascii=False))
                counts["observables"] += 1
        ids, lanes, provenance, pairs, previous = [], Counter(), Counter(), set(), None
        for *_value, role, field, seq, finding_id, lane, origin in group:
            pairs.add((role, field))
            if seq == previous:
                continue
            previous = seq
            if len(ids) < STIX_FINDING_IDS:
                ids.append(finding_id)
            lanes[lane] += 1
            provenance[origin] += 1
        roles = [f"{role} ({field})" for role, field in sorted(pairs)[:STIX_ROLES]]
        timed = first is not None
        observed = {
            "type": "observed-data", "spec_version": "2.1",
            "id": romulus_id("observed-data", {"hunt": hunt["id"], "revision": revision, "object": objects[-1]["id"]}),
            "created": when, "modified": when, "created_by_ref": identity["id"],
            "first_observed": first if timed else (_utc(window.get("start")) or when),
            "last_observed": last if timed else (_utc(window.get("end")) or when),
            "number_observed": max(1, min(findings, 999_999_999)),
            "object_refs": [item["id"] for item in objects],
            "x_romulus_kind": kind, "x_romulus_network_scope": scope, "x_romulus_roles": roles,
            "x_romulus_finding_count": findings, "x_romulus_finding_ids": ids,
            "x_romulus_finding_ids_more": findings - len(ids), "x_romulus_lanes": dict(sorted(lanes.items())),
            "x_romulus_provenance": dict(sorted(provenance.items())),
            "x_romulus_time_basis": ("times of the findings citing the value" if timed else
                                     "the hunt window: no finding citing the value recorded a time"),
        }
        db.execute("INSERT OR IGNORE INTO written VALUES (?, ?)", (observed["id"], order))
        order += 1
        stream.write(",\n" + json.dumps(observed, sort_keys=True, ensure_ascii=False))
        counts["observed_data"] += 1
    report_id = romulus_id("report", {"hunt": hunt["id"], "revision": revision, "object": "report"})
    head = {"type": "report", "spec_version": "2.1", "id": report_id, "created": when, "modified": when,
            "created_by_ref": identity["id"], "published": when, "report_types": ["observed-data"],
            "name": f"ROMULUS hunt {hunt['id']} report revision {revision}: values seen in reportable findings",
            "description": LABEL + ".", "x_romulus_hunt_id": hunt["id"], "x_romulus_revision": revision}
    text = json.dumps(head, sort_keys=True, ensure_ascii=False)
    # the report's reference list is streamed: written objects in bundle order, the identity first
    stream.write(",\n" + text[:-1] + ', "object_refs": [' + json.dumps(identity["id"]))
    for (object_id,) in db.execute("SELECT id FROM written ORDER BY seq"):
        stream.write(", " + json.dumps(object_id))
    stream.write("]}\n], \"type\": \"bundle\"}\n")
    return dict(counts)
