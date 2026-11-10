"""Explicit non-SSH authentication decisions, grouped by host and concrete service.

NIST SP 800-63B-4 section 3.2.2 describes rate limiting, a maximum of 100 failed
attempts, and IP/timing signals: https://pages.nist.gov/800-63-4/sp800-63b.html.
Ten failures or ten distinct accounts in ten minutes is a conservative review
heuristic below that ceiling, not a NIST-prescribed attack threshold. The same
threshold is used for mail, VPN, FTP, web, database, SMB and other services because
the evidence is an explicit failed decision in every case. SSH retains its own
connection-aware evaluator, thresholds and publication identities.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import KeyedStore, SpillList
from romulus.evidence.typed import Outcome, TypedEvent

DATASETS = ("linux.text", "systemd.journal", "system.syslog", "system.auth")
AUTH_FIELDS = ("auth.service", "auth.phase", "source.ip", "user.name")


def text_field(event, name):
    value = event.get(name)
    return value if isinstance(value, str) and value.strip() else None


def source_ip(event):
    value = text_field(event, "source.ip")
    try:
        address = ip_address(value)
        return str(getattr(address, "ipv4_mapped", None) or address)
    except (ValueError, TypeError):
        return None


def group_id(key):
    return hashlib.sha256(json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Record:
    event: TypedEvent
    raw: dict


def observation(rule, records, key, claim, lane="lead", fields=()):
    unique = {record.event.id: record for record in records}
    events = sorted((record.event for record in unique.values()), key=lambda item: (item.ts, item.id))
    raw = {}
    for record in unique.values():
        raw.update(record.raw)
    last = events[-1]
    return Match(rule.id, claim, rule.claim_type, events,
                 [pf(event, name) for event in events for name in fields if name in event.fields],
                 last.ts, "high" if lane == "high" else "medium", lane, "high",
                 entities=[("host", last.host, "observed_on")] if last.host else [],
                 notes=list(rule.benign), group_key=group_id(key), raw_copies=raw)


class RecordRule(Playbook):
    """Bounded hot sets and disk-backed event ordering, including exact replay identity."""
    kind = "aggregate"
    os_families = ("linux",)
    claim_type = "aggregate_observation"
    assures_negative = False
    positive_only_reason = "Service log grammars and required fields may be incomplete; only typed positives are reported."
    datasets = DATASETS
    HOT = 128
    anchor_class = "credential_access"

    def __init__(self):
        super().__init__()
        self._rows = SpillList(self, "service_rows", self.HOT)
        self._ids = KeyedStore(self, "service_ids", self.HOT)
        self._stores = [self._ids]
        self._done = False

    def store(self, name, **kwargs):
        store = KeyedStore(self, name, self.HOT, **kwargs)
        self._stores.append(store)
        return store

    def put(self, store, key, value):
        if store.put(key, value):
            return True
        self.refuse("service_state", f"State for {store.name} was refused by the disk budget")
        return False

    def trim(self):
        self._rows.hot_size = self.HOT
        self._rows.trim()
        for store in self._stores:
            store.hot_size = self.HOT
            store.trim()

    def accept(self, event):
        return True

    def in_scope(self, event):
        return event.family in self.families and self.event_in_os_scope(event)

    def consume(self, events):
        for index, event in enumerate(events):
            if not self.in_scope(event):
                continue
            if self._ids.get(event.id) is not None:
                continue
            if not self.put(self._ids, event.id, True):
                continue
            if self.accept(event):
                # A success at the same timestamp precedes failures: only strictly earlier
                # failures may support a "followed by success" observation.
                order = (event.ts.timestamp(), f"{0 if event.outcome == Outcome.success else 1}:{event.id}")
                if self._rows.append(Record(event, self.raw_of(event)), order):
                    self.evaluated += 1
                else:
                    self.refuse("service_records", "A service record was refused by the disk budget")
            if index % 128 == 0:
                self.trim()
        self.trim()
        return []

    def release_state(self):
        self._rows.clear()
        for store in self._stores:
            store.clear()


def authentication(event, owner, *, exclude_ssh=True):
    service, phase = text_field(event, "auth.service"), text_field(event, "auth.phase")
    if (exclude_ssh and service == "sshd") or (phase and phase != "authentication"):
        return None
    user, address = text_field(event, "user.name"), source_ip(event)
    if not (service and phase and user and address and event.host) or event.outcome == Outcome.unknown:
        owner.missing_required += 1
        return None
    return event.host, service, user, address


@dataclass
class _AuthState:
    failures: list[Record] = field(default_factory=list)
    users: dict[str, Record] = field(default_factory=dict)
    success_seen: bool = False
    match: Match | None = None


class ServicePasswordGuessing(RecordRule):
    """Ten explicit failures per account/source/service in 600 s; see the NIST rationale above."""
    id = "auth.password_guessing"
    title = "Repeated failed authentication for one service account"
    families = ("auth",)
    required_fields = AUTH_FIELDS
    attack = ("T1110.001",)
    benign = ("Stale credentials, client retries and user mistakes can produce a failure burst.",)
    next_checks = ("Review the account and source activity and any later successful authentication.",)
    threshold = 10
    seconds = 600
    card: ClassVar[dict] = {"behavior": title, "telemetry": "Typed service authentication decisions",
            "fidelity": "Explicit failed decisions only; ten failures in ten minutes is a review heuristic."}

    def __init__(self):
        super().__init__()
        self._groups = self.store("auth_groups", candidate=lambda state: state.match is not None)

    def accept(self, event):
        return authentication(event, self) is not None

    def in_scope(self, event):
        return (super().in_scope(event) and event.get("auth.service") != "sshd"
                and text_field(event, "auth.phase") in (None, "authentication"))

    def finalize(self):
        if self._done:
            return
        self._done = True
        for index, record in enumerate(self._rows.ordered()):
            event = record.event
            key = (event.host, event.get("auth.service"), event.get("user.name"), source_ip(event))
            if isinstance(self, ServicePasswordSpraying):
                key = (key[0], key[1], key[3])
            state = self._groups.get(key)
            if state is None:
                state = _AuthState()
                if not self.put(self._groups, key, state):
                    continue
            self.advance(state, record, key)
            if index % 128 == 0:
                self.trim()
        self.trim()
        for _key, state in self._groups.items(candidates=True):  # noqa: PERF102 - disk-backed KeyedStore has no values()
            yield state.match

    def advance(self, state, record, key):
        event = record.event
        if event.outcome != Outcome.failure:
            return
        cutoff = event.ts.timestamp() - self.seconds
        state.failures = [row for row in state.failures if row.event.ts.timestamp() >= cutoff]
        state.failures.append(record)
        state.failures = state.failures[-self.threshold:]
        if len(state.failures) == self.threshold and state.match is None:
            state.match = observation(self, state.failures, key,
                                      f"Service {key[1]} on {key[0]} recorded at least {self.threshold} failed "
                                      f"authentication decisions for account '{key[2]}' from {key[3]} within "
                                      f"{self.seconds} seconds.", fields=AUTH_FIELDS)


class ServicePasswordSpraying(ServicePasswordGuessing):
    """Ten distinct failed accounts per service/source in 600 s; breadth avoids retry inflation."""
    id = "auth.password_spraying"
    title = "Failed service authentication for many accounts from one source"
    attack = ("T1110.003",)
    card: ClassVar[dict] = {"behavior": title, "telemetry": "Typed service authentication decisions",
            "fidelity": "Ten distinct explicitly failed accounts per concrete service in ten minutes."}

    def advance(self, state, record, key):
        if record.event.outcome != Outcome.failure:
            return
        cutoff = record.event.ts.timestamp() - self.seconds
        state.users = {user: row for user, row in state.users.items() if row.event.ts.timestamp() >= cutoff}
        state.users[record.event.get("user.name")] = record
        if len(state.users) > self.threshold:
            oldest = min(state.users, key=lambda user: (state.users[user].event.ts, user))
            del state.users[oldest]
        if len(state.users) == self.threshold and state.match is None:
            state.match = observation(self, list(state.users.values()), key,
                                      f"Service {key[1]} on {key[0]} recorded failures for at least "
                                      f"{self.threshold} distinct accounts from {key[2]} within {self.seconds} seconds.",
                                      fields=AUTH_FIELDS)


class ServiceSuccessAfterFailures(ServicePasswordGuessing):
    """First observed login after a source or account failure burst; no historical novelty claim."""
    id = "auth.success_new_source_after_failures"
    version = "2"
    SPRAY_NAMES = 3
    title = "First recorded service login from a source after repeated failures"
    lane = "high"
    severity = "high"
    attack = ("T1110", "T1078")
    card: ClassVar[dict] = {"behavior": title, "telemetry": "Typed service authentication decisions",
            "fidelity": "First success in the supplied window only; earlier account history is unknown."}

    def __init__(self):
        super().__init__()
        self._sources = self.store("auth_source_failures")
        self._accounts = self.store("auth_account_failures")

    def advance(self, state, record, key):
        cutoff = record.event.ts.timestamp() - self.seconds
        source_key, account_key = (key[0], key[1], key[3]), key[:3]
        if record.event.outcome == Outcome.failure:
            for store, identity, maximum in ((self._sources, source_key, self.threshold),
                                              (self._accounts, account_key, 2 * self.threshold - 1)):
                recent = [row for row in (store.get(identity) or []) if row.event.ts.timestamp() >= cutoff]
                recent.append(record)
                self.put(store, identity, recent[-maximum:])
            return
        if state.success_seen:
            return
        state.success_seen = True
        own = [row for row in (self._sources.get(source_key) or [])
               if cutoff <= row.event.ts.timestamp() < record.event.ts.timestamp()]
        others = [row for row in (self._accounts.get(account_key) or [])
                  if cutoff <= row.event.ts.timestamp() < record.event.ts.timestamp()
                  and source_ip(row.event) != key[3]]
        # If fewer than N failures came from this source, the latest 2N-1 account
        # failures retain N from other sources whenever they exist in the window.
        same_source = len(own) >= self.threshold
        failures, lane = (own, "high") if same_source else (others, "lead")
        if len(failures) >= self.threshold:
            caution = ""
            accounts = {row.event.get("user.name") for row in own}
            spraying = len(accounts) >= self.SPRAY_NAMES or any(
                row.event.get("auth.user_valid") is False for row in own)
            if same_source and key[2] not in accounts and not spraying:
                lane = "lead"
                caution = (f"None of the failures named '{key[2]}', and they show neither several names nor "
                           "invalid users, so they need not belong to this login. ")
            relation = ("failures from that source" if same_source
                        else "failures against that account from other sources")
            state.match = observation(self, failures[-self.threshold:] + [record], key,
                                      f"Service {key[1]} on {key[0]} recorded the first successful authentication "
                                      f"in the supplied window for '{key[2]}' from {key[3]}, after at least "
                                      f"{self.threshold} {relation} within {self.seconds} seconds. "
                                      f"{caution}Earlier source history and credential compromise are not established.",
                                      lane, AUTH_FIELDS + ("auth.user_valid",))
            if caution:
                state.match.confidence = "medium"


SERVICE_AUTH_PLAYBOOKS = [ServicePasswordGuessing, ServicePasswordSpraying, ServiceSuccessAfterFailures]
