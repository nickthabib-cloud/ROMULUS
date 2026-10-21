"""Indicator lists matched by field role.

Names, addresses, domains and fingerprints are useful indicators only when they are matched in the field that
gives them meaning. Each match is worded by its role:

- program_name, executed program  : basename of the kernel-recorded process.executable -> "a program named X ran"
- program_name, interpreter script: the script operand an interpreter was started with  -> "interpreter started with X"
- program_name, argument          : any other argv token whose basename equals X         -> "an argument names X" (context)
- ip / cidr                       : typed source/destination address fields              -> "a record shows contact"
- domain                          : DNS question, HTTP host and URL domain, at a label boundary
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
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from romulus.detect.base import LANES, SEVERITIES, Match, Playbook, basename, pf
from romulus.detect.host import (
    AWK_INTERPRETERS,
    SCRIPT_FILE_INTERPRETERS,
    _awk_script_file_of,
    interpreter_name,
)
from romulus.evidence.shellparse import SHELLS, UnknownShellScript, shell_script_file_of
from romulus.evidence.typed import TypedEvent

KINDS = {"program_name", "ip", "cidr", "domain", "ja3", "ja4", "hassh"}
EXAMPLE_LIMIT = 20
ADDRESS_FIELDS = (("source.ip", "source"), ("destination.ip", "destination"))
DOMAIN_FIELDS = ("dns.question.name", "http.hostname", "url.domain")
FINGERPRINT_FIELDS = {"ja3": "tls.ja3", "ja4": "tls.ja4", "hassh": "ssh.hassh"}


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
            if item.get("lane", "lead") not in LANES or item.get("severity", "medium") not in SEVERITIES:
                raise IndicatorFileError(f"{where}: lane or severity is not a known value")
            for v in values:
                _check_value(kind, v, where)
            seen.add(iid)
            out.append(Indicator(iid, kind, tuple(values), str(item.get("label") or iid),
                                 item.get("severity", "medium"), item.get("lane", "lead"),
                                 tuple(item.get("attack") or ()), path.name))
    return IndicatorSet(out, h.hexdigest()[:12] if files else "none", [p.name for p in files])


def _check_value(kind: str, value: str, where: str) -> None:
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
    id = "ioc.indicator_match"
    anchor_class = "indicator"
    version = f"2+{_SET.digest}"
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
                    self.prints[(ind.kind, v.lower())] = ind
        self.groups: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.counts: Counter = Counter()
        self.meta: dict[tuple, dict] = {}

    # ---- matching ---------------------------------------------------------------------------------
    def _keep(self, key: tuple, e: TypedEvent, meta: dict) -> None:
        self.counts[key] += 1
        self.meta.setdefault(key, meta)
        if len(self.groups[key]) < EXAMPLE_LIMIT:
            self.groups[key].append(e)

    def _programs(self, e: TypedEvent) -> None:
        exe = e.get("process.executable")
        if exe and basename(str(exe)).lower() in self.names:
            ind = self.names[basename(str(exe)).lower()]
            self._keep((ind.id, "executed", e.host, basename(str(exe))), e, {"ind": ind, "field": "process.executable"})
        argv = e.get("process.argv")
        if not isinstance(argv, list) or not argv:
            return
        script = script_operand(argv)
        script_name = basename(script).lower() if script else None
        if script_name in self.names:
            ind = self.names[script_name]
            self._keep((ind.id, "script", e.host, basename(script)), e, {"ind": ind, "field": "process.argv"})
        for token in argv[1:]:
            name = basename(token).lower()
            if name in self.names and name != script_name:
                ind = self.names[name]
                self._keep((ind.id, "argument", e.host, basename(token)), e, {"ind": ind, "field": "process.argv"})
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

    def _domains(self, e: TypedEvent) -> None:
        for fname in DOMAIN_FIELDS:
            for value in _as_list(e.get(fname)):
                name = value.lower().rstrip(".")
                labels = name.split(".")
                for i in range(len(labels)):
                    ind = self.domains.get(".".join(labels[i:]))
                    if ind is not None:
                        self._keep((ind.id, "domain", e.host, name), e, {"ind": ind, "field": fname})
                        break

    def _fingerprints(self, e: TypedEvent) -> None:
        for kind, fname in FINGERPRINT_FIELDS.items():
            for value in _as_list(e.get(fname)):
                ind = self.prints.get((kind, value.lower()))
                if ind is not None:
                    self._keep((ind.id, kind, e.host, value), e, {"ind": ind, "field": fname})

    def consume(self, events):
        if not self.set.indicators:
            return []
        for e in events:
            if e.family not in self.families:
                continue
            self.evaluated += 1
            if e.family == "process_exec":
                self._programs(e)
            if self.ips or self.nets:
                self._addresses(e)
            if self.domains:
                self._domains(e)
            if self.prints:
                self._fingerprints(e)
        return []

    def retained_events(self) -> list[TypedEvent]:
        return [e for evs in self.groups.values() for e in evs]

    # ---- publishing -------------------------------------------------------------------------------
    def finalize(self):
        out = []
        for key in sorted(self.groups, key=str):
            _iid, role, host, value = key
            evs = sorted(self.groups[key], key=lambda x: (x.ts, x.id))
            meta, n = self.meta[key], self.counts[key]
            ind: Indicator = meta["ind"]
            e0 = evs[0]
            span = f"{evs[0].ts.isoformat()} – {evs[-1].ts.isoformat()}"
            listed = f"indicator {ind.id} ({ind.label}, list {ind.source})"
            if role == "executed":
                claim = (f"{n} auditd exec record(s) on {host} show a program whose kernel-recorded executable is named "
                         f"'{value}' ({e0.get('process.executable')}), matching {listed} ({span}). The name matches; "
                         f"whether the program is that tool is not established, and a renamed copy would not match.")
                lane, claim_type = ind.lane, "observed_action"
            elif role == "script":
                claim = (f"{n} auditd exec record(s) on {host} show an interpreter started with script operand "
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
            else:
                claim = (f"{n} session record(s) observed by {host} carry {role.upper()} client fingerprint {value}, "
                         f"matching {listed} ({span}).")
                lane, claim_type = ind.lane, "network_observation"
            m = Match(self.id, claim, claim_type, evs, [pf(e0, meta["field"])], e0.ts, ind.severity, lane, "medium",
                      e0.entities(), group_key="|".join(map(str, key)))
            if ind.attack:
                m.notes.append(f"indicator ATT&CK context: {list(ind.attack)}")
            if n > len(evs):
                m.notes.append(f"{n} matching records; {len(evs)} are cited")
            out.append(m)
        return out


INDICATOR_PLAYBOOKS = [IndicatorMatch]
