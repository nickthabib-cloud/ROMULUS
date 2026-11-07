"""Indicator lists matched by field role.

Names, addresses, domains and fingerprints are useful indicators only when they are matched in the field that
gives them meaning. Each match is worded by its role:

- program_name, executed program  : basename of the kernel-recorded process.executable -> "a program named X ran"
- program_name, interpreter script: the script operand an interpreter was started with  -> "interpreter started with X"
- program_name, argument          : any other argv token whose basename equals X         -> "an argument names X" (context)
- ip / cidr                       : typed source/destination address fields              -> "a record shows contact"
- domain                          : DNS question names, HTTP host and URL domain, at a label boundary
- domain, DNS answer              : an answer's owner name, or its target when the answer type holds a name
                                    (CNAME, DNAME, NS, PTR, MX)                         -> "a DNS answer names X"
- domain, TLS SNI                 : the server name the TLS client asked for            -> "the TLS SNI names X"
- ja3 / ja4 / hassh               : the typed client fingerprint fields of a session

Matching is exact (case-insensitive for names and domains), never a substring of free text, and every rule
here is positive-only: a renamed tool or a new address is a false negative, so absence proves nothing.
Lists live in content/indicators/*.yaml; their digest is part of this playbook's version, so a hunt manifest
records exactly which lists it used.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from romulus.content.indicator_values import KINDS as SUPPORTED_KINDS
from romulus.content.indicator_values import normalize_value
from romulus.detect.base import SEVERITIES, Match, Playbook, basename, pf
from romulus.detect.bounded import HOT_COUNT, HeldExamples, KeyedStore
from romulus.detect.citing import (
    BoundStage,
    Ends,
    bound_note,
    citation_group,
    cite_extra,
    cited_phrase,
)
from romulus.detect.host import (
    ALONE_NOTE,
    AWK_INTERPRETERS,
    SCRIPT_FILE_INTERPRETERS,
    _awk_script_file_of,
    add_unheld,
    alone,
    interpreter_name,
)
from romulus.evidence.shellparse import SHELLS, UnknownShellScript, shell_script_file_of
from romulus.evidence.typed import TypedEvent, event_os_family

KINDS = set(SUPPORTED_KINDS)
HASH_KINDS = ('md5', 'sha1', 'sha256')
CONTENT_KINDS = {*HASH_KINDS, 'url', 'x509_sha1', 'x509_sha256'}
_HASH_FAMILIES = frozenset({'process_exec', 'image_load', 'file_change', 'file_transfer'})
CONTENT_FAMILIES = {
    'md5': _HASH_FAMILIES, 'sha1': _HASH_FAMILIES, 'sha256': _HASH_FAMILIES | {'http_body'},
    'url': frozenset({'http_tx', 'http_access', 'net_session', 'remote_access', 'http_body'}),
    'x509_sha1': frozenset({'tls_session', 'net_session'}),
    'x509_sha256': frozenset({'tls_session', 'net_session', 'x509_certificate'}),
}
EXAMPLE_LIMIT = 20
ADDRESS_FIELDS = (("source.ip", "source"), ("destination.ip", "destination"))
DOMAIN_FIELDS = ("dns.question.name", "dns.question.names", "http.hostname", "url.domain")
SNI_FIELD = "tls.client.server_name"
ANSWER_FIELD = "dns.answers"
# DNS answer types whose data is itself a domain name (a CNAME target, a name server, a mail exchanger)
NAME_DATA_TYPES = {"CNAME", "DNAME", "NS", "PTR", "MX"}
FINGERPRINT_FIELDS = {"ja3": "tls.ja3", "ja4": "tls.ja4", "hassh": "ssh.hassh"}


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


class IndicatorFileError(ValueError):
    """An indicator list is malformed. Hunts refuse to run on a list they cannot read exactly."""


@dataclass(frozen=True)
class Indicator:
    id: str
    kind: str
    values: tuple[str, ...]
    label: str
    severity: str
    lane: str
    attack: tuple[str, ...] = ()
    source: str = ""
    list_name: str = ""
    author: str = ""
    list_version: int = 0
    age_days: int = 0


@dataclass
class IndicatorSet:
    indicators: list[Indicator] = field(default_factory=list)
    digest: str = "none"
    files: list[str] = field(default_factory=list)


def indicator_dir() -> Path:
    override = os.environ.get("ROMULUS_INDICATOR_DIR")
    return Path(override) if override else Path(__file__).resolve().parents[3] / "content" / "indicators"


def load_indicators(directory: Path | None = None) -> IndicatorSet:
    root = directory or indicator_dir()
    files = sorted(root.glob("*.yaml")) if root.is_dir() else []
    h = hashlib.sha256()
    out: list[Indicator] = []
    seen: set[str] = set()
    for path in files:
        raw = path.read_bytes()
        h.update(path.name.encode() + b"\0" + raw)
        try:
            doc = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            raise IndicatorFileError(f"{path.name}: not valid YAML: {exc}") from exc
        if doc.get("schema_version") != 1:
            raise IndicatorFileError(f"{path.name}: schema_version must be 1")
        for i, item in enumerate(doc.get("indicators") or []):
            where = f"{path.name} indicators[{i}]"
            if not isinstance(item, dict):
                raise IndicatorFileError(f"{where}: must be a mapping")
            iid, kind, values = item.get("id"), item.get("kind"), item.get("values")
            if not iid or iid in seen:
                raise IndicatorFileError(f"{where}: id missing or duplicated ({iid!r})")
            if kind not in KINDS:
                raise IndicatorFileError(f"{where}: kind must be one of {sorted(KINDS)}")
            if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
                raise IndicatorFileError(f"{where}: values must be a non-empty list of strings")
            if item.get("lane", "lead") not in {'high', 'lead', 'context'} or item.get("severity", "medium") not in SEVERITIES:
                raise IndicatorFileError(f"{where}: lane or severity is not a known value")
            for v in values:
                _check_value(kind, v, where)
            seen.add(iid)
            out.append(Indicator(iid, kind, tuple(values), str(item.get("label") or iid),
                                 item.get("severity", "medium"), item.get("lane", "lead"),
                                 tuple(item.get("attack") or ()), path.name))
    return IndicatorSet(out, h.hexdigest()[:12] if files else "none", [p.name for p in files])


def _check_value(kind: str, value: str, where: str) -> None:
    if kind in CONTENT_KINDS:
        try:
            normalize_value(kind, value)
        except ValueError as exc:
            raise IndicatorFileError(f'{where}: {exc}') from exc
    try:
        if kind == "ip":
            ipaddress.ip_address(value)
        elif kind == "cidr":
            ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise IndicatorFileError(f"{where}: {value!r} is not a valid {kind}") from exc
    if kind == "program_name" and "/" in value:
        raise IndicatorFileError(f"{where}: program names are basenames, not paths ({value!r})")


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def script_operand(argv: list[str]) -> str | None:
    """The script an interpreter was started with, using the host rules' exact operand logic."""
    name = interpreter_name(argv[0])
    if name in SHELLS:
        script = shell_script_file_of(argv, shell_name=name)
        return None if isinstance(script, UnknownShellScript) else (script or None)
    if name in SCRIPT_FILE_INTERPRETERS:
        return argv[1] if len(argv) > 1 and not argv[1].startswith(("-", "+")) else None
    if name in AWK_INTERPRETERS:
        return _awk_script_file_of(argv) or None
    return None


_SET = load_indicators()


class IndicatorMatch(Playbook):
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "ioc.indicator_match"
    anchor_class = "indicator"
    version = f"8+{_SET.digest}"
    title = "Indicator list match in the field that gives it meaning"
    kind = "aggregate"
    claim_type = "observed_action"
    families = ("process_exec", "net_socket", "net_flow", "net_alert", "net_session", "dns_query", "http_tx",
                "tls_session", "ssh_session", "file_transfer", "auth", "http_access")
    required_fields = ()
    assures_negative = False           # names, addresses and fingerprints change; a miss proves nothing
    severity, lane = "medium", "lead"
    attack = ()
    benign = ("a legitimate program that shares a listed name", "administrators using dual-use tools",
              "shared infrastructure behind a listed address or domain")
    next_checks = ("process_tree and session of the matching process", "network records for the same host and time",
                   "the indicator's source and age")

    def __init__(self, indicators: IndicatorSet | None = None):
        super().__init__()
        self.set = indicators or _SET
        self.names: dict[str, Indicator] = {}
        self.ips: dict[str, Indicator] = {}
        self.nets: list[tuple[ipaddress._BaseNetwork, Indicator]] = []
        self.domains: dict[str, Indicator] = {}
        self.prints: dict[tuple[str, str], Indicator] = {}
        for ind in self.set.indicators:
            for v in ind.values:
                if ind.kind == "program_name":
                    self.names[v.lower()] = ind
                elif ind.kind == "ip":
                    self.ips[str(ipaddress.ip_address(v))] = ind
                elif ind.kind == "cidr":
                    self.nets.append((ipaddress.ip_network(v, strict=False), ind))
                elif ind.kind == "domain":
                    self.domains[v.lower().rstrip(".")] = ind
                else:
                    self.prints[(ind.kind, normalize_value(ind.kind, v) if ind.kind in CONTENT_KINDS else v.lower())] = ind
        self.by_id = {ind.id: ind for ind in self.set.indicators}
        self._overlay = None
        self._kind_seen = set()
        self._batch_kind_seen = set()
        self._kind_unsearchable = Counter()
        self._batch_kind_unsearchable = Counter()
        self._configure_content()
        # (indicator id, role, host, value) -> [count, matched field, cited records]
        self.groups = KeyedStore(self, "ioc_groups", self.HOT, disk_budget=self.GROUPS_DISK)
        # (indicator id, role, host, "*") -> [count, matched field, cited records, sample values]: matches of a new
        # value once the per-value groups' disk budget is spent
        self.overflow = KeyedStore(self, "ioc_overflow", self.HOT)
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self._alone: list[Match] = []
        self.bounds = BoundStage()          # the records bounding each group's span, held while they bound it
        self.load = lambda ids: []

    def _configure_content(self):
        self._content_kinds = ({ind.kind for ind in self.set.indicators}
                               | (self._overlay.kinds if self._overlay else set())) & CONTENT_KINDS
        extra = ('file_change', 'image_load') if set(HASH_KINDS) & self._content_kinds else ()
        if 'x509_sha256' in self._content_kinds:
            extra += ('x509_certificate',)
        if 'url' in self._content_kinds:
            extra += ('remote_access',)
        if {'url', 'sha256'} & self._content_kinds:
            extra += ('http_body',)
        self.families = tuple(dict.fromkeys((*type(self).families, *extra)))

    def bind_indicators(self, repo, pins):
        """Use the hunt's immutable eligibility snapshot; values remain in SQLite."""
        if pins and pins.get('applied'):
            from romulus.content.indicator_lists import PinnedIndicators
            self._overlay = PinnedIndicators(repo, pins)
            self.version = f'{type(self).version}+{self._overlay.digest[:12]}'
        self._configure_content()

    @staticmethod
    def _from_row(row):
        source = row['list']
        return Indicator(row['id'], row['kind'], (row['value'],), row['label'], row['severity'], row['lane'],
                         tuple(row['attack']), source['source'], source['name'], source['author'],
                         source['version'], source['age_days'])

    def _indicator(self, identity):
        if identity in self.by_id:
            return self.by_id[identity]
        row = self._overlay.get(identity) if self._overlay else None
        if row is None:
            raise IndicatorFileError('A matched pinned indicator version is unavailable')
        return self._from_row(row)

    def _matching(self, kind, value, *, local=True):
        if local:
            source = self.names if kind == 'program_name' else self.ips if kind == 'ip' else None
            ind = source.get(value.lower()) if source is not None else self.prints.get(
                (kind, value if kind in CONTENT_KINDS else value.lower()))
            if ind is not None:
                yield ind
        if self._overlay and kind in self._overlay.kinds:
            try:
                value = normalize_value(kind, value)
            except ValueError:
                return
            for row in self._overlay.find(kind, value):
                yield self._from_row(row)

    def _unsearchable(self, counts):
        return [f'Indicator kind {kind} cannot be searched in {count} delivered record(s): no complete typed '
                'value was available; no negative result is asserted.'
                for kind, count in sorted(counts.items()) if count]

    def coverage_notes(self):
        return [*super().coverage_notes(), *self._unsearchable(self._kind_unsearchable)]

    def partition_coverage_notes(self):
        return self._unsearchable(self._batch_kind_unsearchable)

    def _content_values(self, event):
        """Typed value, actual predicate fields, and the role established by the record."""
        seen = set()
        def offer(kind, value, names, role):
            if kind not in self._content_kinds or not isinstance(value, str):
                return None
            try:
                value = normalize_value(kind, value)
            except ValueError:
                return None
            key = (kind, value, role)
            if key in seen:
                return None
            seen.add(key)
            return kind, value, names, role
        for kind in HASH_KINDS:
            role = {'process_exec': 'hash:process', 'image_load': 'hash:image',
                    'file_change': 'hash:file', 'file_transfer': 'hash:transfer'}.get(event.family, 'hash:record')
            prefixes = ('image.hash', 'file.hash', 'process.hash') if event.family == 'image_load' else (
                'process.hash', 'file.hash', 'image.hash')
            for prefix in prefixes:
                name = prefix+'.'+kind
                if item := offer(kind, event.get(name), (name,), role):
                    yield item
            hashes = event.get('file.hashes')
            if isinstance(hashes, dict) and (item := offer(kind, hashes.get(kind), ('file.hashes',), role)):
                yield item
        if event.family == 'http_body' and (item := offer('sha256', event.get('file.sha256'), ('file.sha256',), 'hash:body')):
            yield item
        for side in ('server', 'client'):
            role = 'certificate:'+side
            name = f'tls.{side}.hash_sha1'
            if item := offer('x509_sha1', event.get(name), (name,), role):
                yield item
            name = f'tls.{side}.certificates'
            certificates = event.get(name)
            for certificate in certificates if isinstance(certificates, list) else ():
                if isinstance(certificate, dict):
                    for alg in ('sha1', 'sha256'):
                        if item := offer('x509_'+alg, certificate.get(alg), (name,), role):
                            yield item
            name = f'tls.{side}.cert_chain_fps'
            fingerprints = event.get(name)
            for value in fingerprints if isinstance(fingerprints, list) else ():
                if item := offer('x509_sha256', value, (name,), role):
                    yield item
        if item := offer('x509_sha256', event.get('x509.fingerprint'), ('x509.fingerprint',), 'certificate:observed'):
            yield item
        if 'url' in self._content_kinds:
            if item := offer('url', event.get('bits.remote_url'), ('bits.remote_url',), 'url:record'):
                yield item
            if item := offer('url', event.get('url.full'), ('url.full',), 'url:record'):
                yield item
            elif event.family in ('http_tx', 'http_access', 'http_body', 'net_session'):
                def scalar(value):
                    return value[0] if isinstance(value, list) and len(value) == 1 else value
                target_field = 'url.path' if event.family == 'net_session' else 'url.original'
                target = scalar(event.get(target_field))
                host = scalar(event.get('http.hostname'))
                if item := offer('url', target, (target_field,), 'url:request'):
                    yield item
                elif isinstance(target, str) and target.startswith('/') and isinstance(host, str):
                    scheme_field = 'url.scheme' if event.has('url.scheme') else 'http.scheme'
                    scheme = event.get(scheme_field)
                    if not scheme and event.family in ('http_tx', 'net_session'):
                        scheme = 'http'
                    if isinstance(scheme, str):
                        names = (*((scheme_field,) if event.has(scheme_field) else ()), 'http.hostname', target_field)
                        authority = host
                        try:
                            explicit_port = urlsplit(scheme+'://'+host).port
                        except ValueError:
                            return
                        port = event.get('destination.port')
                        if explicit_port is None and port is not None:
                            if not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535:
                                return
                            if port != {'http': 80, 'https': 443}.get(scheme.lower()):
                                authority += ':'+str(port)
                                names += ('destination.port',)
                        if item := offer('url', scheme+'://'+authority+target, names, 'url:reconstructed'):
                            yield item

    def _content(self, event):
        available = set()
        for kind, value, fields, role in self._content_values(event):
            available.add(kind)
            for ind in self._matching(kind, value):
                self._keep((ind.id, role, event.host, value), event, {'field': fields})
        missing = {kind for kind in self._content_kinds - available if event.family in CONTENT_FAMILIES[kind]}
        self._kind_unsearchable.update(missing)
        self._batch_kind_unsearchable.update(missing)

    # Groups (indicator, role, host, value): the first 20 records cited (staged, held as ids) and a count. A listed
    # domain's subdomains are each a value, so there may be very many: HOT groups in memory, the rest on the rule's
    # disk spill. Once the groups' disk budget is spent, a match of a new value is still found: it joins its
    # (indicator, role, host) overflow group, whose claim counts the records with other values.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    GROUPS_DISK = 4 * 2**30
    SAMPLE_VALUES = 10

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain(), []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.groups.trim()
        self.overflow.trim()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return self.bounds.last

    # ---- matching ---------------------------------------------------------------------------------
    def _keep(self, key: tuple, e: TypedEvent, meta: dict) -> None:
        field_name = meta["field"]
        if reason := getattr(self, "_unaggregated_reason", ""):
            # The upstream identity store cannot establish cumulative-flow uniqueness.
            # Reuse the existing single-record finding; never touch retained group counts.
            self.note_limit("source_identity", reason)
            m = self._finding(key, 1, field_name, [e], operating_systems={event_os_family(e)})
            m.group_key = "|".join(map(str, key[:3])) + "|*"
            item = alone(m, self, e)
            if item is not None:
                item.notes = [note for note in item.notes if note != ALONE_NOTE]
                item.notes.append(reason + "; first matching record cited; later records of this group are not counted")
            add_unheld(self._alone, item)
            return
        group_key = key
        state = self.groups.setdefault(key, lambda: [0, field_name, HeldExamples(EXAMPLE_LIMIT), set(), Ends()])
        if state is None:
            group_key = key[:3] + ("*",)
            state = self.overflow.setdefault(group_key,
                                             lambda: [0, field_name, HeldExamples(EXAMPLE_LIMIT), [], set(), Ends()])
            if state is None:
                # an indicator hit is a finding by itself: published now as its own single-record finding
                self.note_limit("groups_alone", "the indicator match groups' disk budget is spent; later matches "
                                                "with no group are published one record at a time")
                m = self._finding(key, 1, field_name, [e], operating_systems={event_os_family(e)})
                m.group_key = "|".join(map(str, key[:3])) + "|*"   # one per indicator, role and host
                add_unheld(self._alone, alone(m, self, e))
                return
            self.note_limit("groups_overflow", "the indicator match groups' disk budget is spent; later matches of "
                                               "a new value are grouped per indicator, role and host")
            if len(state[3]) < self.SAMPLE_VALUES and key[3] not in state[3]:
                state[3].append(key[3])
        state[0] += 1
        state[-2].add(event_os_family(e))
        self.bounds.offer_at(group_key, state[-1], e)
        if state[2].offer(e):
            self._pending.append(e)
            self._fresh.append(state[2])

    @staticmethod
    def _program_basename(event: TypedEvent, path: str) -> str:
        if event.get("host.os.family") == "windows" or event.normalizer.startswith("windows-"):
            path = path.replace("\\", "/")
        return basename(path)

    def _programs(self, e: TypedEvent) -> None:
        exe = e.get("process.executable")
        exe_name = self._program_basename(e, str(exe)) if exe else ""
        for ind in self._matching('program_name', exe_name):
            self._keep((ind.id, "executed", e.host, exe_name), e, {"ind": ind, "field": "process.executable"})
        argv = e.get("process.argv")
        if not isinstance(argv, list) or not argv:
            return
        script = script_operand(argv)
        script_base = self._program_basename(e, script) if script else ""
        script_name = script_base.lower() if script_base else None
        for ind in self._matching('program_name', script_name or ''):
            self._keep((ind.id, "script", e.host, script_base), e, {"ind": ind, "field": "process.argv"})
        for token in argv[1:]:
            token_base = self._program_basename(e, token)
            name = token_base.lower()
            if name != script_name:
                found = False
                for ind in self._matching('program_name', name):
                    self._keep((ind.id, "argument", e.host, token_base), e, {"ind": ind, "field": "process.argv"})
                    found = True
                if found:
                    break

    def _addresses(self, e: TypedEvent) -> None:
        for fname, side in ADDRESS_FIELDS:
            value = e.get(fname)
            if value is None:
                continue
            try:
                ip = ipaddress.ip_address(str(value))
            except ValueError:
                continue
            ind = self.ips.get(str(ip)) or next((i for net, i in self.nets if ip in net), None)
            if ind is not None:
                self._keep((ind.id, f"address:{side}", e.host, str(ip)), e, {"ind": ind, "field": fname})
            for ind in self._matching('ip', str(ip), local=False):
                self._keep((ind.id, f'address:{side}', e.host, str(ip)), e, {'field': fname})
            if self._overlay and 'cidr' in self._overlay.kinds:
                # At most 33 IPv4 / 129 IPv6 indexed probes, independent of list size.
                for prefix in range(ip.max_prefixlen, -1, -1):
                    network = str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
                    for ind in self._matching('cidr', network, local=False):
                        self._keep((ind.id, f'address:{side}', e.host, str(ip)), e, {'field': fname})

    def _listed_domain(self, value: str) -> tuple[str, Indicator] | None:
        name = value.lower().rstrip(".")
        labels = name.split(".")
        for i in range(len(labels)):
            ind = self.domains.get(".".join(labels[i:]))
            if ind is not None:
                return name, ind
        return None

    def _domains(self, e: TypedEvent) -> None:
        candidates: list[tuple[str, str, str]] = []          # (role, field, value)
        for fname in DOMAIN_FIELDS:
            candidates += [("domain", fname, v) for v in _as_list(e.get(fname))]
        candidates += [("sni", SNI_FIELD, v) for v in _as_list(e.get(SNI_FIELD))]
        # an answer whose owner name is the question it answers adds nothing: that name is already matched as the
        # question. Owner names elsewhere in a response (a CNAME chain), and v1 answer records, which carry no
        # question, are still answer matches.
        questions = {v.lower().rstrip(".") for f in ("dns.question.name", "dns.question.names")
                     for v in _as_list(e.get(f))}
        answers = e.get(ANSWER_FIELD)
        for answer in answers if isinstance(answers, list) else []:
            if not isinstance(answer, dict):
                continue
            if isinstance(answer.get("name"), str) and answer["name"].lower().rstrip(".") not in questions:
                candidates.append(("dns_answer", ANSWER_FIELD, answer["name"]))
            if answer.get("type") in NAME_DATA_TYPES and isinstance(answer.get("data"), str):
                candidates.append(("dns_answer", ANSWER_FIELD, answer["data"]))
            elif answer.get("type") is None and isinstance(answer.get("data"), str) and not _is_address(answer["data"]):
                # a sensor that writes no answer type (Zeek's dns.log): data that is not an address may be a name (a
                # CNAME target among them), so it is matched as one; an address is matched by the address lists
                candidates.append(("dns_answer", ANSWER_FIELD, answer["data"]))
        seen = set()            # one record counts once per (indicator, role, name), whichever fields carry it
        for role, fname, value in candidates:
            hit = self._listed_domain(value)
            name = value.lower().rstrip('.')
            def matches(hit=hit, name=name):
                if hit is not None:
                    yield hit[1]
                labels = name.split('.')
                for index in range(len(labels)):
                    yield from self._matching('domain', '.'.join(labels[index:]), local=False)
            for ind in matches():
                key = (ind.id, role, e.host, name)
                if key not in seen:
                    seen.add(key)
                    self._keep(key, e, {"ind": ind, "field": fname})

    def _fingerprints(self, e: TypedEvent) -> None:
        for kind, fname in FINGERPRINT_FIELDS.items():
            for value in _as_list(e.get(fname)):
                for ind in self._matching(kind, value):
                    self._keep((ind.id, kind, e.host, value), e, {"ind": ind, "field": fname})

    def consume(self, events):
        if not self.set.indicators and self._overlay is None:
            return []
        self._batch_kind_seen = set()
        self._batch_kind_unsearchable = Counter()
        self._batch = events
        for e in events:
            if e.family not in self.families:
                continue
            self.evaluated += 1
            if e.family == "process_exec":
                self._programs(e)
            if self.ips or self.nets or self._overlay and {'ip', 'cidr'} & self._overlay.kinds:
                self._addresses(e)
            if self.domains or self._overlay and 'domain' in self._overlay.kinds:
                self._domains(e)
            if self.prints or self._overlay and set(FINGERPRINT_FIELDS) & self._overlay.kinds:
                self._fingerprints(e)
            if self._content_kinds:
                self._content(e)
        self._batch = None
        out, self._alone = self._alone, []
        return out

    def consume_unaggregated(self, events, reason):
        """Publish actual record indicators without modifying cumulative group counts."""
        self._unaggregated_reason = reason
        try:
            return self.consume_scoped_partition(events)
        finally:
            self._unaggregated_reason = ""

    def retained_events(self) -> list[TypedEvent]:
        return []                               # staged on disk instead

    # ---- publishing -------------------------------------------------------------------------------
    def finalize(self):
        if self._overlay is not None:
            return self._stream_finalized()
        out = []
        stores = ((self.groups, self.groups.keys()), (self.overflow, self.overflow.keys()))
        groups = [(key, store) for store, keys in stores for key in keys]
        for key, store in sorted(groups, key=lambda item: str(item[0])):
            state = store.peek(key)
            with citation_group(self, out, key, state):
                out.append(self._finding(key, state[0], state[1], state[2].events(self.load),
                                         state[3] if len(state) > 5 else None,
                                         operating_systems=state[-2], ends=state[-1]))
        return out

    def _stream_finalized(self):
        for store in (self.groups, self.overflow):
            for key, state in store.items():
                out = []
                with citation_group(self, out, key, state):
                    out.append(self._finding(key, state[0], state[1], state[2].events(self.load),
                        state[3] if len(state) > 5 else None, operating_systems=state[-2], ends=state[-1]))
                yield from out

    def finalize_fallback(self, reason: str) -> list[Match]:
        """A group store whose disk table cannot be read: the groups held in memory, each complete for its key."""
        out = []
        for store in (self.groups, self.overflow):
            for key, state in sorted(store.hot.items(), key=lambda item: str(item[0])):
                with citation_group(self, out, key, state):
                    m = self._finding(key, state[0], state[1], state[2].events(self.load),
                                      state[3] if len(state) > 5 else None, operating_systems=state[-2], ends=state[-1])
                    m.notes.append(f"published from memory only: the groups on disk could not be read ({reason})")
                    out.append(m)
        return out

    def uncited_finding(self, key, state, match):
        indicator = self._indicator(key[0])
        match.attack = indicator.attack if indicator.list_version else ()
        match.severity = indicator.severity
        match.proposed_lane = "lead" if key[1] == "argument" else indicator.lane
        match.claim_type = "mention" if key[1] == "argument" else "aggregate_observation"
        match.entities = [("host", str(key[2]), "observer")] if key[2] else []
        match.claim = (f"{state[0]} recorded matches of indicator {indicator.id} ({indicator.label}, list "
                       f"{indicator.source}) for {key[1]} '{key[3]}' on {key[2]}; no citation could be retained. "
                       "The positive is published from the recorded group state.")
        if indicator.list_name:
            match.notes.append(f'List {indicator.list_name}; source {indicator.source}; author {indicator.author}; '
                               f'version {indicator.list_version}; age {indicator.age_days} days.')
        return match

    def _finding(self, key: tuple, n: int, field_name: str, evs: list[TypedEvent],
                 values: list[str] | None = None, *, operating_systems: set[str], ends: Ends | None = None) -> Match:
        _iid, role, host, value = key
        missing: set[str] = set()
        context: set[str] = set()
        if ends is not None:
            # the group's first records and the records bounding its span (when the stage holds them)
            known = {e.id: e for e in evs}

            def load(ids):
                found = {e.id: e for e in self.load([i for i in ids if i not in known])}
                return [known.get(i) or found[i] for i in ids if i in known or i in found]

            evs, missing, context = cite_extra(load, load, ends, list(known))
        evs = sorted(evs, key=lambda x: (x.ts, x.id))
        ind = self._indicator(key[0])
        if values is not None:
            value = values[0]               # an overflow group: worded by its first value, then the others
        e0 = evs[0]
        if ends is not None and ends.first is not None:
            first, last = (datetime.fromtimestamp(ends.first[0], UTC), datetime.fromtimestamp(ends.last[0], UTC))
        else:
            first, last = evs[0].ts, evs[-1].ts
        span = f"{first.isoformat()} – {last.isoformat()}"
        listed = f"indicator {ind.id} ({ind.label}, list {ind.source})"
        if ind.list_name:
            listed = (f'indicator {ind.id} ({ind.label}, list {ind.list_name}, source {ind.source}, '
                      f'author {ind.author}, version {ind.list_version}, age {ind.age_days} days)')
        process_record = ("Windows process-creation" if operating_systems == {"windows"} else
                          "auditd exec" if operating_systems == {"linux"} else "process-execution")
        executable_source = ("kernel-recorded executable" if operating_systems == {"linux"}
                             else "recorded executable")
        if role == "executed":
            claim = (f"{n} {process_record} record(s) on {host} show a program whose {executable_source} is named "
                     f"'{value}' ({e0.get('process.executable')}), matching {listed} ({span}). The name matches; "
                     f"whether the program is that tool is not established, and a renamed copy would not match.")
            lane, claim_type = ind.lane, "observed_action"
        elif role == "script":
            claim = (f"{n} {process_record} record(s) on {host} show an interpreter started with script operand "
                     f"'{value}', matching {listed} ({span}). The argv names the script; its content is not "
                     f"verified.")
            lane, claim_type = ind.lane, "script_content"
        elif role == "argument":
            # A command naming an offensive tool (downloading, unpacking or chmod-ing it) is associated with an
            # attack even though it does not show the tool ran: surfaced as a lead, worded as a mention.
            claim = (f"{n} command(s) on {host} have an argument naming '{value}', matching {listed} ({span}). "
                     f"An argument naming a tool is a mention, not evidence that the tool ran.")
            lane, claim_type = "lead", "mention"
        elif role.startswith("address:"):
            claim = (f"{n} {e0.family} record(s) observed by {host} have {role.split(':')[1]} address {value}, "
                     f"matching {listed} ({span}).")
            lane, claim_type = ind.lane, "network_observation"
        elif role == "domain":
            claim = (f"{n} {e0.family} record(s) observed by {host} name '{value}', which matches {listed} at a "
                     f"label boundary ({span}).")
            lane, claim_type = ind.lane, "network_observation"
        elif role == "dns_answer":
            claim = (f"In {n} {e0.family} record(s) observed by {host}, a DNS answer names '{value}' (as the "
                     f"answer's owner name or as a name it points to), which matches {listed} at a label "
                     f"boundary ({span}). The name was in a response; whether a client then connected to it is "
                     f"not established.")
            lane, claim_type = ind.lane, "network_observation"
        elif role == "sni":
            claim = (f"In {n} {e0.family} record(s) observed by {host}, the TLS SNI names '{value}', which "
                     f"matches {listed} at a label boundary ({span}). The SNI is the name the client asked "
                     f"for; the certificate the server returned is a separate check.")
            lane, claim_type = ind.lane, "network_observation"
        elif role.startswith('hash:'):
            algorithm = {'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256'}[ind.kind]
            description = {'hash:process': f'a process image with {algorithm} {value} ran',
                'hash:image': f'a loaded image with {algorithm} {value} was observed',
                'hash:file': f'a file-change observation carries {algorithm} {value}',
                'hash:transfer': f'a file with {algorithm} {value} was observed in a transfer',
                'hash:body': f'a response body with {algorithm} {value} was observed in packets',
                'hash:record': f'a recorded file hash is {algorithm} {value}'}[role]
            claim = f'In {n} {e0.family} record(s) on {host}, {description}, matching {listed} ({span}).'
            lane, claim_type = ind.lane, 'aggregate_observation'
        elif role.startswith('certificate:'):
            algorithm = 'SHA-1' if ind.kind == 'x509_sha1' else 'SHA-256'
            claim = (f'In {n} {e0.family} record(s) observed by {host}, a {role.split(":")[1]} certificate '
                     f'with {algorithm} fingerprint {value} was observed, matching {listed} ({span}).')
            lane, claim_type = ind.lane, 'network_observation'
        elif role.startswith('url:'):
            label = {'url:record': 'recorded URL', 'url:request': 'HTTP request target URL',
                     'url:reconstructed': 'reconstructed HTTP URL from the recorded host and request target'}[role]
            claim = f'In {n} {e0.family} record(s), the {label} is {value}, matching {listed} ({span}).'
            lane, claim_type = ind.lane, 'network_observation'
        else:
            claim = (f"{n} session record(s) observed by {host} carry {role.upper()} client fingerprint {value}, "
                     f"matching {listed} ({span}).")
            lane, claim_type = ind.lane, "network_observation"
        names = (field_name,) if isinstance(field_name, str) else field_name
        if ind.kind in CONTENT_KINDS:
            names = next((fields for kind, candidate, fields, context_role in self._content_values(e0)
                          if kind == ind.kind and candidate == value and context_role == role), names)
        m = Match(self.id, claim, claim_type, evs, [pf(e0, name) for name in names], e0.ts, ind.severity, lane, "medium",
                  e0.entities(), group_key="|".join(map(str, key)), context_ids=context,
                  attack=ind.attack if ind.list_version else ())
        if ind.attack:
            m.notes.append(f"indicator ATT&CK context: {list(ind.attack)}")
        m.claim += cited_phrase(len(evs), n, not missing) + (bound_note(missing, ends) if ends is not None else "")
        if values is not None:
            others = values[1:]
            m.claim += (f" These {n} record(s) are every match of {ind.id} by {host} in this role once the "
                        f"per-value groups' disk budget was spent: '{value}' and "
                        + (f"{len(others)} more value(s) ({', '.join(others)})" if others else "no other value")
                        + (" or more; records of each value are not counted apart." if others else "."))
        return m


INDICATOR_PLAYBOOKS = [IndicatorMatch]
