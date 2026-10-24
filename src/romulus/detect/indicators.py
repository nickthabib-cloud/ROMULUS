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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

from romulus.detect.base import LANES, SEVERITIES, Match, Playbook, basename, pf
from romulus.detect.bounded import HOT_COUNT, HeldExamples, KeyedStore
from romulus.detect.citing import BoundStage, Ends, bound_note, cite_with_bounds, cited_phrase
from romulus.detect.host import (
    AWK_INTERPRETERS,
    SCRIPT_FILE_INTERPRETERS,
    _awk_script_file_of,
    add_unheld,
    alone,
    interpreter_name,
)
from romulus.evidence.shellparse import SHELLS, UnknownShellScript, shell_script_file_of
from romulus.evidence.typed import TypedEvent, event_os_family

KINDS = {"program_name", "ip", "cidr", "domain", "ja3", "ja4", "hassh"}
EXAMPLE_LIMIT = 20
ADDRESS_FIELDS = (("source.ip", "source"), ("destination.ip", "destination"))
DOMAIN_FIELDS = ("dns.question.name", "dns.question.names", "http.hostname", "url.domain")
SNI_FIELD = "tls.client.server_name"
ANSWER_FIELD = "dns.answers"
# DNS answer types whose data is itself a domain name (a CNAME target, a name server, a mail exchanger)
NAME_DATA_TYPES = {"CNAME", "DNAME", "NS", "PTR", "MX"}
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
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "ioc.indicator_match"
    anchor_class = "indicator"
    version = f"5+{_SET.digest}"
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
        self.by_id = {ind.id: ind for ind in self.set.indicators}
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
        if exe_name.lower() in self.names:
            ind = self.names[exe_name.lower()]
            self._keep((ind.id, "executed", e.host, exe_name), e, {"ind": ind, "field": "process.executable"})
        argv = e.get("process.argv")
        if not isinstance(argv, list) or not argv:
            return
        script = script_operand(argv)
        script_base = self._program_basename(e, script) if script else ""
        script_name = script_base.lower() if script_base else None
        if script_name in self.names:
            ind = self.names[script_name]
            self._keep((ind.id, "script", e.host, script_base), e, {"ind": ind, "field": "process.argv"})
        for token in argv[1:]:
            token_base = self._program_basename(e, token)
            name = token_base.lower()
            if name in self.names and name != script_name:
                ind = self.names[name]
                self._keep((ind.id, "argument", e.host, token_base), e, {"ind": ind, "field": "process.argv"})
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
        seen = set()            # one record counts once per (indicator, role, name), whichever fields carry it
        for role, fname, value in candidates:
            hit = self._listed_domain(value)
            if hit is None:
                continue
            name, ind = hit
            key = (ind.id, role, e.host, name)
            if key not in seen:
                seen.add(key)
                self._keep(key, e, {"ind": ind, "field": fname})

    def _fingerprints(self, e: TypedEvent) -> None:
        for kind, fname in FINGERPRINT_FIELDS.items():
            for value in _as_list(e.get(fname)):
                ind = self.prints.get((kind, value.lower()))
                if ind is not None:
                    self._keep((ind.id, kind, e.host, value), e, {"ind": ind, "field": fname})

    def consume(self, events):
        if not self.set.indicators:
            return []
        self._batch = events
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
        self._batch = None
        out, self._alone = self._alone, []
        return out

    def retained_events(self) -> list[TypedEvent]:
        return []                               # staged on disk instead

    # ---- publishing -------------------------------------------------------------------------------
    def finalize(self):
        out = []
        stores = ((self.groups, self.groups.keys()), (self.overflow, self.overflow.keys()))
        groups = [(key, store) for store, keys in stores for key in keys]
        for key, store in sorted(groups, key=lambda item: str(item[0])):
            state = store.peek(key)
            out.append(self._finding(key, state[0], state[1], state[2].events(self.load),
                                     state[3] if len(state) > 5 else None,
                                     operating_systems=state[-2], ends=state[-1]))
        return out

    def finalize_fallback(self, reason: str) -> list[Match]:
        """A group store whose disk table cannot be read: the groups held in memory, each complete for its key."""
        out = []
        for store in (self.groups, self.overflow):
            for key, state in sorted(store.hot.items(), key=lambda item: str(item[0])):
                m = self._finding(key, state[0], state[1], state[2].events(self.load),
                                  state[3] if len(state) > 5 else None, operating_systems=state[-2], ends=state[-1])
                m.notes.append(f"published from memory only: the groups on disk could not be read ({reason})")
                out.append(m)
        return out

    def _finding(self, key: tuple, n: int, field_name: str, evs: list[TypedEvent],
                 values: list[str] | None = None, *, operating_systems: set[str], ends: Ends | None = None) -> Match:
        _iid, role, host, value = key
        missing: set[str] = set()
        if ends is not None:
            # the group's first records and the records bounding its span (when the stage holds them)
            known = {e.id: e for e in evs}

            def load(ids):
                found = {e.id: e for e in self.load([i for i in ids if i not in known])}
                return [known.get(i) or found[i] for i in ids if i in known or i in found]

            evs, missing = cite_with_bounds(load, load, ends, list(known), EXAMPLE_LIMIT)
        evs = sorted(evs, key=lambda x: (x.ts, x.id))
        ind: Indicator = self.by_id[key[0]]
        if values is not None:
            value = values[0]               # an overflow group: worded by its first value, then the others
        e0 = evs[0]
        if ends is not None and ends.first is not None:
            first, last = (datetime.fromtimestamp(ends.first[0], UTC), datetime.fromtimestamp(ends.last[0], UTC))
        else:
            first, last = evs[0].ts, evs[-1].ts
        span = f"{first.isoformat()} – {last.isoformat()}"
        listed = f"indicator {ind.id} ({ind.label}, list {ind.source})"
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
        else:
            claim = (f"{n} session record(s) observed by {host} carry {role.upper()} client fingerprint {value}, "
                     f"matching {listed} ({span}).")
            lane, claim_type = ind.lane, "network_observation"
        m = Match(self.id, claim, claim_type, evs, [pf(e0, field_name)], e0.ts, ind.severity, lane, "medium",
                  e0.entities(), group_key="|".join(map(str, key)))
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
