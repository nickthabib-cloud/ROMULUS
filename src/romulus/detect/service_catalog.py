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

NAME_FIELDS = ("dns.question.name", "tls.client.server_name", "http.hostname")
CATALOG_PATH = Path(__file__).resolve().parents[3] / "content/network/services.json"
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_SUFFIXES = 50_000
MAX_CITATION_BYTES = 64 * 1024
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_CATEGORIES = {"remote_access", "tunnelling", "ide_tunnel", "callback", "file_sharing"}


def canonical_name(value: object) -> str | None:
    """A DNS name, not a URL, authority with a port, wildcard, or free text."""
    if not isinstance(value, str) or not value or len(value) > 254:
        return None
    # IDNA maps the Unicode full stops as well as the label text. Strip only a
    # single root dot: doubled empty labels are malformed, not a hidden suffix.
    try:
        name = value.casefold().encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    name = name.removesuffix(".")
    if len(name) > 253 or not name or any(not _LABEL.fullmatch(label) for label in name.split(".")):
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
            if canonical is None or "." not in canonical:
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
    version = "1"
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
    attack = ("T1219.002", "T1219.001", "T1572", "T1090.002", "T1071", "T1567", "T1567.002")
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

    def _db(self):
        spill = self.spill()
        if not self._ready:
            # A compound primary key keeps membership and counts exact without
            # a Python host set or a separate counter that could partly commit.
            spill.table("service_groups", "entry TEXT NOT NULL, source TEXT NOT NULL, first_rank TEXT NOT NULL, "
                        "last_rank TEXT NOT NULL, first_event BLOB, last_event BLOB, "
                        "PRIMARY KEY(entry, source)")
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
            matches = {}  # bounded by the shipped catalog, not event count
            for field in NAME_FIELDS:
                raw = event.get(field)
                if raw is None:
                    continue
                values = raw if isinstance(raw, list) else (raw,)
                if not values:
                    malformed = True
                for value in values:
                    name = canonical_name(value)
                    if name is None:
                        malformed = True
                        continue
                    names_present = True
                    for entry in self.catalog.trie.lookup_canonical(name):
                        matches.setdefault(entry, field)
            if malformed or not names_present:
                self.missing_required += 1
            if not names_present:
                continue
            if not matches:
                self.evaluated += 1
                continue
            accepted = True
            for entry, field in matches.items():
                try:
                    spill = self._db()
                    key = (entry, str(source))
                    before = spill.db.execute("SELECT first_rank, last_rank FROM service_groups "
                                              "WHERE entry=? AND source=?", key).fetchone()
                    rank = event.ts.astimezone(UTC).isoformat(timespec="microseconds") + "|" + event.id
                    if before is not None and before[0] <= rank <= before[1]:
                        continue
                    blob = self._citation(event, field)
                    spill.write("INSERT INTO service_groups VALUES (?, ?, ?, ?, ?, ?) "
                                "ON CONFLICT(entry,source) DO UPDATE SET "
                                "first_rank=min(first_rank,excluded.first_rank), "
                                "last_rank=max(last_rank,excluded.last_rank), "
                                "first_event=CASE WHEN excluded.first_rank < first_rank THEN excluded.first_event "
                                "ELSE first_event END, "
                                "last_event=CASE WHEN excluded.last_rank > last_rank THEN excluded.last_event "
                                "ELSE last_event END", [(*key, rank, rank, blob, blob)])
                    if before is None:
                        yield self._match(entry, str(source), (blob, blob), 1, final=False)
                except StateExhausted as error:
                    if accepted:
                        self.refuse("service_state", str(error))
                        accepted = False
                    # Matching already established a positive. Even when the
                    # aggregate cannot grow, publish its bounded live witness
                    # under the same source identity; fleet coverage is partial.
                    blob = self._citation(event, field)
                    yield self._match(entry, str(source), (blob, blob), 1, final=False)
            if accepted:
                self.evaluated += 1

    def _match(self, entry, source, blobs, count, *, final):
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
        if entry in getattr(getattr(self, "site_facts", None), "approved_remote_access", ()):
            notes.append("This service is site-approved; the observation remains a lead.")
        if self.capped:
            notes.append("Source host count is a lower bound: some matching records could not be retained.")
        if source is None:
            claim = f"A lookup or connection to the {item['name']} service was observed from {count} internal source address(es)."
            group_key = f"{entry}|fleet"
        else:
            claim = f"A lookup or connection to the {item['name']} service was observed from {source}."
            group_key = f"{entry}|source|{source}"
        fleet = self._hosts(entry) if source is None else ()
        # A fleet citation can be hostless network telemetry. Retain only its
        # two representative source entities here; full membership streams above.
        entities = [("ip", source, "src")] if source else list(dict.fromkeys(
            ("ip", str(address), "src") for event in events if (address := _source(event)) is not None))
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

    def _hosts(self, entry):
        for (source,) in self._spill.db.execute("SELECT source FROM service_groups WHERE entry=? ORDER BY source", (entry,)):
            yield source, ""

    def finalize(self):
        if self._external:
            self.note_coverage("external_sources", f"{self._external} record(s) had sources outside the internal networks.")
        if not self._ready:
            return
        # The aggregate has at most one count per catalog entry. SQLite sorts on
        # disk; source membership and witnesses are streamed, never collected.
        counts = self._spill.db.execute("SELECT entry, count(*) AS hosts FROM service_groups GROUP BY entry "
                                        "ORDER BY (count(*) > 2), count(*), entry")
        for entry, count in counts:
            first_blob = last_blob = None
            first_rank = last_rank = None
            for source, first_time, last_time, first, last in self._spill.db.execute(
                    "SELECT source, first_rank, last_rank, first_event, last_event FROM service_groups "
                    "WHERE entry=? ORDER BY source", (entry,)):
                if first_rank is None or first_time < first_rank:
                    first_rank, first_blob = first_time, first
                if last_rank is None or last_time > last_rank:
                    last_rank, last_blob = last_time, last
                yield self._match(entry, source, (first, last), count, final=True)
            yield self._match(entry, None, (first_blob, last_blob), count, final=True)

    def finalize_fallback(self, reason):
        self.note_limit("service_finalize", reason)
        return self.finalize()

    def release_state(self):
        self.close_spill()
