"""Positive-only service-name observations with disk-backed source membership.

Only DNS question, TLS SNI and HTTP Host fields supply names. A reversed-label
trie walks each name once: O(name length + labels + matches), independent of the
catalog size. Lists of names are observations in one record, not transactions.
SQLite retains one row and at most two compact witnesses per entry/source pair;
finalization streams groups and fleet membership. Source addresses count network
clients, not verified machine identities: NAT and shared resolvers can hide hosts.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import UTC
from pathlib import Path
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted, register_store
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.evidence.typed import TypedEvent
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

NAME_FIELDS = ("dns.question.name", "dns.question.names", "tls.client.server_name", "http.hostname")
CATALOG_PATH = Path(__file__).resolve().parents[3] / "content/network/services.json"
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_SUFFIXES = 50_000
MAX_CITATION_BYTES = 64 * 1024
MAX_NAMES_PER_RECORD = 1024
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_CATEGORIES = {"remote_access", "tunnelling", "ide_tunnel", "callback", "file_sharing"}


def canonical_name(value: object, *, host: bool = False) -> str | None:
    """Canonicalize the DNS envelope; trie edges validate matched suffix labels."""
    if not isinstance(value, str) or not value or len(value) > 260:
        return None
    if host and ":" in value:
        # Bracketed IPv6 is an IP authority, never a catalog service name.
        if value.startswith("["):
            return None
        value, separator, port = value.rpartition(":")
        if not separator or not port.isascii() or not port.isdecimal() or not 0 <= int(port) <= 65535:
            return None
    if len(value) > 254 or re.search(r"[\s/:\\\[\]*?#@]", value):
        return None
    # IDNA maps the Unicode full stops as well as the label text. Strip only a
    # single root dot: doubled empty labels are malformed, not a hidden suffix.
    try:
        name = value.casefold().encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    name = name.removesuffix(".")
    if len(name) > 253 or not name or any(not label or len(label) > 63 for label in name.split(".")):
        return None
    return name


class NameTrie:
    """One dictionary edge per DNS label; no event-name cache or catalog scan."""

    def __init__(self, suffixes: Iterable[tuple[str, str]]):
        self._root: dict = {}
        count = 0
        for suffix, entry in suffixes:
            count += 1
            if count > MAX_SUFFIXES:
                raise ValueError("service catalog exceeds its suffix bound")
            canonical = canonical_name(suffix)
            if canonical is None or "." not in canonical or any(
                    not _LABEL.fullmatch(label) for label in canonical.split(".")):
                raise ValueError("service catalog suffix must be a full DNS name")
            node = self._root
            for label in reversed(canonical.split(".")):
                node = node.setdefault(label, {})
            if "" in node and node[""] != entry:
                raise ValueError("service catalog suffix belongs to more than one entry")
            node[""] = entry
        self.suffix_count = count

    def lookup(self, name: object) -> tuple[str, ...]:
        canonical = canonical_name(name)
        return () if canonical is None else self.lookup_canonical(canonical)

    def lookup_canonical(self, name: str) -> tuple[str, ...]:
        node = self._root
        found = []
        seen = set()  # at most one match per DNS label, not one per catalog entry
        for label in reversed(name.split(".")):
            if not _LABEL.fullmatch(label):
                break
            node = node.get(label)
            if node is None:
                break
            entry = node.get("")
            if entry is not None and entry not in seen:
                found.append(entry)
                seen.add(entry)
        return tuple(found)


class Catalog:
    def __init__(self, body: dict):
        if body.get("schema") != "romulus.network-services@1" or not body.get("version"):
            raise ValueError("unknown service catalog schema or missing version")
        entries = body.get("entries")
        if not isinstance(entries, list) or not entries or len(entries) > MAX_SUFFIXES:
            raise ValueError("service catalog entries missing or over bound")
        self.version = str(body["version"])
        self.entries = {}
        for item in entries:
            key = item.get("id", "")
            if not isinstance(key, str) or not _SLUG.fullmatch(key) or key in self.entries:
                raise ValueError("service catalog has an invalid or duplicate entry id")
            if item.get("category") not in _CATEGORIES or not item.get("name"):
                raise ValueError("service catalog entry lacks name or known category")
            if not item.get("attack") or not item.get("suffixes") or not item.get("license"):
                raise ValueError("service catalog entry lacks techniques, suffixes or license")
            sources = item.get("sources", ())
            if not sources or any(not source.get("url", "").startswith("https://")
                                  or not source.get("license") for source in sources):
                raise ValueError("service catalog entry lacks public source and source license record")
            self.entries[key] = item
        self.trie = NameTrie((suffix, key) for key, item in self.entries.items() for suffix in item["suffixes"])


def load_catalog(path: Path = CATALOG_PATH) -> Catalog:
    with path.open("rb") as source:
        payload = source.read(MAX_CATALOG_BYTES + 1)
    if len(payload) > MAX_CATALOG_BYTES:
        raise ValueError("service catalog exceeds its byte bound")
    return Catalog(json.loads(payload))


def _source(event: TypedEvent):
    from ipaddress import ip_address
    value = event.get("source.ip")
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    if address.version == 6:
        address = address.ipv4_mapped or address
    return address


class ServiceCatalog(Playbook):
    id = "network.service_catalog"
    title = "Remote access, tunnel, callback or file-sharing service name observed"
    version = "3"
    families = ("dns_query", "tls_session", "http_tx", "net_session")
    required_fields = ("source.ip",)
    kind = "aggregate"
    claim_type = "network_observation"
    anchor_class = "network_observation"
    severity = "high"
    lane = "lead"
    assures_negative = False
    positive_only_reason = ("Known service names only; custom domains, self-hosted services and absent name fields "
                            "cannot establish that remote access, tunnelling or transfer did not occur.")
    direction_dependent = True
    uses_site_facts = True
    attack = ("T1219.002", "T1219.001", "T1572", "T1090.002", "T1071", "T1567", "T1567.002", "T1567.003")
    benign = ("Approved support, development, testing and file sharing use these services.",)
    next_checks = ("Confirm the source address and whether this service use was authorized.",
                   "Inspect related connection and host records before inferring execution or data transfer.")
    card: ClassVar[dict] = {"behavior": title, "telemetry": "Typed DNS question, TLS SNI or HTTP Host",
                           "fidelity": "A service name is present; no session success, execution or transfer is inferred."}

    def __init__(self, catalog: Catalog | None = None):
        super().__init__()
        self.catalog = catalog if catalog is not None else load_catalog()
        self._ready = False
        self._external = 0
        self._approval_trie = None
        self._approved_ids = frozenset()
        self._approved_suffixes = {}

    def _prepare_approvals(self):
        if self._approval_trie is not None:
            return
        approvals = getattr(getattr(self, "site_facts", None), "approved_remote_access", ())
        self._approved_ids = frozenset(value for value in approvals if value in self.catalog.entries)
        suffixes = []
        for value in approvals:
            if "." not in value:
                continue
            # A suffix approval may narrow a catalog suffix, never approve a
            # wider parent domain or the other suffixes belonging to an entry.
            entries = self.catalog.trie.lookup(value)
            for entry in entries:
                self._approved_suffixes.setdefault(entry, []).append(value)
            if entries:
                suffixes.append((value, value))
        self._approval_trie = NameTrie(suffixes)
        self._approved_suffixes = {entry: frozenset(values) for entry, values in self._approved_suffixes.items()}

    def _db(self):
        spill = self.spill()
        if not self._ready:
            # A compound primary key keeps membership and counts exact without
            # a Python host set or a separate counter that could partly commit.
            spill.table("service_groups", "entry TEXT NOT NULL, approved INTEGER NOT NULL, source TEXT NOT NULL, "
                        "first_rank TEXT NOT NULL, "
                        "last_rank TEXT NOT NULL, first_event BLOB, last_event BLOB, "
                        "PRIMARY KEY(entry, approved, source)")
            register_store(self, spill)
            self._ready = True
        return spill

    def _citation(self, event, field):
        names = event.get(field)
        if (len(event.raw) > 8 or len(event.caveats) > 8 or len(event.id) > 1024
                or len(event.normalizer) > 1024 or event.host is not None and len(event.host) > 1024
                or any(len(ref.target) > 1024 or len(ref.native_id) > 4096 or len(ref.digest) > 256 for ref in event.raw)
                or any(len(note) > 4096 for note in event.caveats)
                or any(len(event.fields[key].origin) > 1024 for key in ("source.ip", field))
                or isinstance(names, list) and (len(names) > 16 or any(
                    not isinstance(name, str) or len(name) > 254 for name in names))):
            payload = None
        else:
            view = event.model_copy(update={"fields": {key: event.fields[key] for key in ("source.ip", field)}})
            payload = compact_event(view)
            if len(payload) > MAX_CITATION_BYTES:
                payload = None
        if payload is None:
            self.note_limit("service_citations", "Service presence retained; a witness exceeded the compact citation bound")
        return payload

    def consume(self, events):
        self._prepare_approvals()
        for event in events:
            if event.family not in self.families or not self.event_in_os_scope(event):
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            source = _source(event)
            if source is None:
                self.missing_required += 1
                continue
            assume_direction(self)
            if not current().is_internal(source):
                self._external += 1
                continue
            names_present = False
            malformed = False
            remaining = MAX_NAMES_PER_RECORD
            omitted = 0
            matches = {}  # bounded by the shipped catalog, not event count
            for field in NAME_FIELDS:
                raw = event.get(field)
                if raw is None:
                    continue
                values = raw if isinstance(raw, list) else (raw,)
                if not values:
                    malformed = True
                available = min(len(values), remaining)
                omitted += len(values) - available
                remaining -= available
                for index in range(available):
                    name = canonical_name(values[index], host=field == "http.hostname")
                    if name is None:
                        malformed = True
                        continue
                    names_present = True
                    suffix_approvals = self._approval_trie.lookup_canonical(name) if self._approved_suffixes else ()
                    for entry in self.catalog.trie.lookup_canonical(name):
                        allowed_suffixes = self._approved_suffixes.get(entry, ())
                        approved = entry in self._approved_ids or any(suffix in allowed_suffixes for suffix in suffix_approvals)
                        matches.setdefault((entry, approved), field)
            if omitted:
                self.refuse("service_names", f"Only the first {MAX_NAMES_PER_RECORD} typed names per record were "
                            "evaluated; additional names and their service membership are unresolved")
            if malformed or not names_present:
                self.missing_required += 1
            if not names_present:
                continue
            if not matches:
                if not omitted:
                    self.evaluated += 1
                continue
            accepted = not omitted
            for (entry, approved), field in matches.items():
                try:
                    spill = self._db()
                    key = (entry, int(approved), str(source))
                    before = spill.db.execute("SELECT first_rank, last_rank FROM service_groups "
                                              "WHERE entry=? AND approved=? AND source=?", key).fetchone()
                    rank = event.ts.astimezone(UTC).isoformat(timespec="microseconds") + "|" + event.id
                    if before is not None and before[0] <= rank <= before[1]:
                        continue
                    blob = self._citation(event, field)
                    spill.write("INSERT INTO service_groups VALUES (?, ?, ?, ?, ?, ?, ?) "
                                "ON CONFLICT(entry,approved,source) DO UPDATE SET "
                                "first_rank=min(first_rank,excluded.first_rank), "
                                "last_rank=max(last_rank,excluded.last_rank), "
                                "first_event=CASE WHEN excluded.first_rank < first_rank THEN excluded.first_event "
                                "ELSE first_event END, "
                                "last_event=CASE WHEN excluded.last_rank > last_rank THEN excluded.last_event "
                                "ELSE last_event END", [(*key, rank, rank, blob, blob)])
                    if before is None and not approved:
                        yield self._match(entry, str(source), (blob, blob), 1, final=False)
                except StateExhausted as error:
                    if accepted:
                        self.refuse("service_state", str(error))
                        accepted = False
                    else:
                        self.note_limit("service_state", str(error))
                    # Matching already established a positive. Even when the
                    # aggregate cannot grow, publish its bounded live witness
                    # under the same source identity; fleet coverage is partial.
                    blob = self._citation(event, field)
                    yield self._match(entry, None if approved else str(source), (blob, blob), 1,
                                      final=False, approved=approved, known_source=str(source))
            if accepted:
                self.evaluated += 1

    def _match(self, entry, source, blobs, count, *, final, approved=False, known_source=None):
        item = self.catalog.entries[entry]
        events = []
        for blob in blobs:
            if blob is not None:
                event = expand_event(blob)
                if not events or event.id != events[0].id:
                    events.append(event)
        predicate = [pf(event, field) for event in events for field in ("source.ip", *NAME_FIELDS)
                     if event.has(field)]
        notes = [COMPACT_CITATION_NOTE, "A name observation does not establish execution, session success or data transfer.",
                 "Distinct internal source addresses are counted; NAT and shared resolvers can hide multiple hosts.",
                 f"Service catalog version {self.catalog.version}; category {item['category']}."]
        if item.get("notes"):
            notes.append(item["notes"])
        if self.direction_assumed:
            notes.append(DIRECTION_ASSUMED_REASON)
        if approved:
            if entry in self._approved_ids:
                notes.append(f"This service is site-approved by catalog ID '{entry}'; the observation remains a lead.")
            else:
                suffixes = sorted(self._approved_suffixes[entry])
                notes.append("These observations are site-approved only within the configured DNS suffixes: "
                             + ", ".join(suffixes[:8])
                             + (f" ({len(suffixes)} suffix approvals total; first 8 shown)." if len(suffixes) > 8 else ".")
                             + " Other suffixes of this service are not covered by that approval.")
        if self.capped:
            notes.append("Source host count is a lower bound: some matching records could not be retained.")
        if "service_names" in self.limits:
            notes.append("Some typed names exceeded the per-record name bound and were not evaluated; "
                         "service membership is partial.")
        if source is None:
            claim = f"A lookup or connection to the {item['name']} service was observed from {count} internal source address(es)."
            group_key = f"{entry}|approved|fleet" if approved and entry not in self._approved_ids else f"{entry}|fleet"
            if approved:
                claim += " This roll-up covers site-approved observations."
            if count > 2:
                notes.append("Event citation coverage is partial: at most two representative witnesses are retained; "
                             "the distinct source count and streamed membership remain exact unless otherwise noted.")
        else:
            claim = f"A lookup or connection to the {item['name']} service was observed from {source}."
            group_key = f"{entry}|source|{source}"
        fleet = self._hosts(entry, approved) if source is None and self._ready else ()
        # A fleet citation can be hostless network telemetry. Retain only its
        # two representative source entities here; full membership streams above.
        entities = [("ip", source, "src")] if source else list(dict.fromkeys(
            ("ip", str(address), "src") for event in events if (address := _source(event)) is not None))
        if not entities and known_source is not None:
            entities = [("ip", known_source, "src")]
        return Match(self.id, claim, self.claim_type, events, predicate, events[-1].ts if events else None,
                     "high" if item["category"] in {"remote_access", "tunnelling", "ide_tunnel"} else "medium",
                     "lead", "high", entities=entities, notes=notes,
                     group_key=group_key, bounded_revision=True,
                     revision_reason="Final service source span and fleet count" if final and source else "",
                     citation_unavailable=not events, fleet_hosts=fleet, fleet_host_count=count if source is None else 0,
                     fleet_hosts_complete=source is None and final and not self.capped,
                     aggregate_summary={"source_host_count": count, "rare_service": int(count <= 2 and not self.capped),
                                        "source_count_complete": int(final and not self.capped)},
                     attack=tuple(item["attack"]))

    def _hosts(self, entry, approved):
        for (source,) in self._spill.db.execute("SELECT source FROM service_groups WHERE entry=? AND approved=? "
                                               "ORDER BY source", (entry, int(approved))):
            yield source, ""

    def finalize(self):
        if self._external:
            self.note_coverage("external_sources", f"{self._external} record(s) had sources outside the internal networks.")
        if not self._ready:
            return
        # The aggregate has at most one count per catalog entry. SQLite sorts on
        # disk; source membership and witnesses are streamed, never collected.
        counts = self._spill.db.execute("SELECT entry, approved, count(*) AS hosts FROM service_groups "
                                        "GROUP BY entry, approved ORDER BY (count(*) > 2), count(*), entry, approved")
        for entry, approved, count in counts:
            first_blob = last_blob = None
            first_rank = last_rank = None
            for source, first_time, last_time, first, last in self._spill.db.execute(
                    "SELECT source, first_rank, last_rank, first_event, last_event FROM service_groups "
                    "WHERE entry=? AND approved=? ORDER BY source", (entry, approved)):
                if first_rank is None or first_time < first_rank:
                    first_rank, first_blob = first_time, first
                if last_rank is None or last_time > last_rank:
                    last_rank, last_blob = last_time, last
                if not approved:
                    yield self._match(entry, source, (first, last), count, final=True)
            yield self._match(entry, None, (first_blob, last_blob), count, final=True, approved=bool(approved))

    def finalize_fallback(self, reason):
        self.note_limit("service_finalize", reason)
        return self.finalize()

    def release_state(self):
        self.close_spill()
