"""Evidence-based ranking: entity evidence, finding rank and the Reported set.

A finding's rank comes from the structure of the evidence in its own hunt, not from a per-rule opinion of how
alarming the rule is. Intrusions touch few entities, progress through ATT&CK tactics and co-occur in time; benign
agent, antivirus and servicing activity recurs across many hosts over the whole window. Every factor below is
computed only from the hunt's own candidates, so it carries to any network.

Tiers. A confirmed finding (lane `urgent`) is always reported on its own. Every admitted `high` or `lead` finding is
in the ranked pool; its stored lane stays as the rule's own estimate and enters only through its rule prior. Context
and suppressed records are outside the pool and stay visible as supporting records.

Entities. A host-telemetry finding counts toward its host and its account, when typed. A network-telemetry finding
counts toward its endpoints (typed source and destination addresses, internal ones first, at most two): an internal
endpoint is a host, named by the host whose own telemetry owns that address unambiguously in the hunt, else by the
address; an external endpoint is an `ip` entity. The sensor that observed the traffic is never an entity. A finding
with no typed host, account or endpoint is unattributed: it is ranked on its own prior and listed. Accounts that name
the same well-known principal on every host (SYSTEM, the local and network service accounts, the Unix superuser) are
not entities of their own: such an account says nothing beyond its host, and one name shared by the whole fleet would
join unrelated hosts' evidence.

Agent findings. A finding the AI agent proposed (provenance `agent`) is ranked and can be reported like any pool
finding, but it never counts toward any entity's confirmed findings, tactics, rules, co-occurrence or strongest rule
prior. The model must never raise the rank of the entities it chose to investigate.

This module holds the model only; `romulus.hunt.rank` runs it over a hunt's stored candidates in bounded batches.
"""
from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

RANK_VERSION = "rank@1"

# Tiers and the pool.
CONFIRMED_LANE = "urgent"
POOL_LANES = ("high", "lead")
RANKED_LANES = (CONFIRMED_LANE, *POOL_LANES)
AGENT_PROVENANCE = "agent"

# Entity kinds, as candidates type them.
HOST = "host"
ACCOUNT = "account"
IP = "ip"
# The entity kind shown for a finding with no typed host, account or endpoint. It is not an entity: such findings
# are never pooled together, they are ranked on their own prior.
UNATTRIBUTED = "unattributed"
# The entity role of a network sensor that only observed a flow; the sensor is not the finding's host.
OBSERVER_ROLE = "observer"
# Endpoints a network finding counts toward. A flow has two ends; a finding about more addresses (a scan, a sweep)
# counts toward its internal ones first, and toward at most two, as a host finding counts toward its host and user.
MAX_ENDPOINTS = 2
# The typed event families whose records come from a network sensor. A sensor's own host.ip names the sensor, so
# their records never map an address to a host.
NETWORK_FAMILIES = (
    "net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session", "net_session",
    "http_body", "app_tx", "x509_certificate", "smb_tx", "rpc_tx", "kerberos_tx", "ntlm_tx", "remote_session",
    "ldap_tx", "address_assignment", "asset_observed", "sensor_health", "ics_tx",
)

# Entity score weights. They are ordinal design choices, fixed before any evaluation and never fitted to data: a
# confirmed finding outweighs any breadth an unconfirmed entity can show (40 is four tactics), tactic breadth
# outweighs rule diversity (a second stage is stronger evidence than a second rule of the same stage), and diversity
# outweighs co-occurrence (pairs grow quadratically with rules, so each is worth less).
WEIGHT_CONFIRMED = 40
WEIGHT_TACTIC = 10
WEIGHT_RULE = 5
WEIGHT_COOCCURRENCE = 3

# Two distinct rules co-occur on an entity when findings of both fall within this window of each other. An hour
# holds one hands-on-keyboard session or one scripted stage on any network, and stays well under the daily rhythm
# of scheduled jobs and patch cycles that make benign rules coincide.
COOCCURRENCE_WINDOW = timedelta(minutes=60)
# Co-occurring pairs counted per entity. Beyond ten pairs (five rules all mutually co-occurring) more pairs say
# nothing new, and the cap keeps one very busy entity from outscoring a confirmed one on co-occurrence alone.
COOCCURRENCE_CAP = 10

# Recurring fleet-wide behaviour. A rule is recurring fleet-wide in a hunt when it fires on at least
# max(FLEET_MIN_HOSTS, FLEET_HOST_SHARE of the hunt's hosts with any candidate) AND its findings span at least
# FLEET_SPAN_SHARE of the hunt window. Both are shares of this hunt, not counts, so they scale from a ten-host
# enclave to a hundred-thousand-host fleet. The time condition keeps a burst (a mass deployment, a worm, ransomware
# staging) from being penalized: an attack that reaches half the fleet does so in a short span. Below three hosts
# prevalence says nothing, so the penalty is off.
# The hosts counted are those with any deterministic candidate in the pass (any lane); findings the AI agent proposed
# never count, so the model can neither raise nor lower a rule's prevalence.
FLEET_MIN_HOSTS = 3
FLEET_HOST_SHARE = 0.5
FLEET_SPAN_SHARE = 0.5
# Rank removed from each finding of a recurring fleet-wide rule. It is less than the gap between a high and a low
# severity prior (30), so it reorders the pool without ever removing a finding from it.
FLEET_PENALTY = 30

# The evidence bar an entity's pool findings must meet to be reported: a confirmed finding, or two tactics, or three
# rules of which at least one pair co-occurs. Recurring fleet-wide rules count toward none of these.
BAR_CONFIRMED = 1
BAR_TACTICS = 2
BAR_RULES = 3
BAR_COOCCURRENCE = 1

# Tactic breadth T is the size of a maximum matching between an entity's counted rules and the tactics each maps
# to: every rule contributes at most one tactic, so one rule whose technique spans several tactics (T1078 Valid
# Accounts spans four) counts once, and only distinct rules in distinct stages add breadth. A maximum matching never
# needs more rules per tactic than there are tactics, and the vendored ATT&CK Enterprise and ICS releases together
# define 18 distinct tactics (Enterprise and ICS share several names), so keeping this many rules per tactic (the lowest rule ids) leaves T exact while bounding the matching's input. Were a tactic
# list ever longer, the entity's reasons say T may be understated.
MATCHING_RULES_PER_TACTIC = 32
# Separates the alternatives of a tactic group (see detect.metadata.LEGACY_TACTIC_ALTERNATIVES).
TACTIC_GROUP_SEPARATOR = "|"

# Accounts that are the same principal on every host, and so are not entities of their own: an action by one of them
# says nothing beyond the host it ran on (the host entity carries that evidence), and one name shared by the whole
# fleet would join unrelated hosts' evidence into one entity. They are the Windows local system and service accounts
# and anonymous logon (by SID and by name), the builtin-group, per-service, window-manager and font-driver SID
# families with their pseudo-domains, the null SID, and the Unix superuser. Values are compared casefolded, as the
# normalizers type them (`sid:<sid>`, `name:<domain>\\<name>`, or a bare name).
SHARED_PRINCIPALS = frozenset({
    "root", "system", "local service", "network service", "anonymous logon",
    "name:root", "name:system", "name:local service", "name:network service", "name:anonymous logon",
    "sid:s-1-5-18", "sid:s-1-5-19", "sid:s-1-5-20", "sid:s-1-5-7", "sid:s-1-0-0",
})
# Well-known SID families (builtin groups, per-service, window manager, font driver host) and the Windows
# pseudo-domains whose accounts exist identically on every host.
SHARED_PRINCIPAL_PREFIXES = (
    "sid:s-1-5-32-", "sid:s-1-5-80-", "sid:s-1-5-90-", "sid:s-1-5-96-",
    "name:nt authority\\", "name:nt service\\", "name:window manager\\", "name:font driver host\\",
)


def is_shared_principal(value: str) -> bool:
    folded = value.casefold()
    return folded in SHARED_PRINCIPALS or folded.startswith(SHARED_PRINCIPAL_PREFIXES)


def _never_internal(_address: str) -> bool:
    return False


def address_is_internal(site_networks) -> Callable[[str], bool]:
    """An address test over the hunt's recorded internal-network definition; an unparsable address is not internal."""
    def test(address: str) -> bool:
        try:
            return bool(site_networks.is_internal(ipaddress.ip_address(address)))
        except ValueError:
            return False
    return test


def network_endpoints(entities, *, is_internal: Callable[[str], bool] = _never_internal) -> list[tuple[str, bool]]:
    """A network finding's endpoint addresses (typed source and destination addresses) with whether each is internal:
    internal endpoints first, then external, at most MAX_ENDPOINTS."""
    addresses: list[str] = []
    for item in entities or []:
        if (isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == IP and item[1] not in (None, "")
                and str(item[1]) not in addresses):
            addresses.append(str(item[1]))
    flagged = [(address, is_internal(address)) for address in addresses]
    return ([item for item in flagged if item[1]] + [item for item in flagged if not item[1]])[:MAX_ENDPOINTS]


def is_network_finding(entities) -> bool:
    """A finding typed on no endpoint host of its own: network-sensor telemetry, whose typed host (when any) is the
    sensor that observed the traffic."""
    return not any(isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == HOST and item[1] not in (None, "")
                   and (item[2] if len(item) > 2 else None) != OBSERVER_ROLE for item in entities or [])


def ranking_entities(entities, *, is_internal: Callable[[str], bool] = _never_internal,
                     host_for_address: Mapping[str, str] | None = None) -> list[tuple[str, str]]:
    """The (kind, value) entities a finding counts toward, from its typed entity list.

    Host telemetry: its hosts and accounts. Network telemetry: its endpoints (internal ones first, at most
    MAX_ENDPOINTS) and accounts; the sensor that observed the traffic is never an entity. An internal endpoint is a
    `host`: the host whose own telemetry owns that address unambiguously in this hunt (`host_for_address`), else
    the address itself, kept apart rather than guessed. An external endpoint is an `ip` entity. A finding with none
    of these is unattributed (an empty list): it is ranked on its own prior and listed, never dropped.

    An account named with a domain or by SID is one principal across hosts (which is what shows lateral movement);
    a bare account name is local to its host (`www-data` on two web servers is two accounts), so it is qualified by
    each host the finding counts toward, and a bare name with no such host is not an entity."""
    out: list[tuple[str, str]] = []
    network = is_network_finding(entities)
    if network:
        for address, internal in network_endpoints(entities, is_internal=is_internal):
            key = (HOST, (host_for_address or {}).get(address) or address) if internal else (IP, address)
            if key not in out:
                out.append(key)
    accounts: list[str] = []
    for item in entities or []:
        if not isinstance(item, (list, tuple)) or len(item) < 2 or item[1] in (None, ""):
            continue
        kind, value = item[0], str(item[1])
        role = item[2] if len(item) > 2 else None
        if kind == HOST and role != OBSERVER_ROLE and not network:
            if (HOST, value) not in out:
                out.append((HOST, value))
        elif kind == ACCOUNT and not is_shared_principal(value) and value not in accounts:
            accounts.append(value)
    hosts = [value for kind, value in out if kind == HOST]
    for value in accounts:
        names = [value] if is_qualified_account(value) else [qualify_account(host, value) for host in hosts]
        for name in names:
            if (ACCOUNT, name) not in out:
                out.append((ACCOUNT, name))
    return out


def is_qualified_account(value: str) -> bool:
    """An account typed with its domain (`domain\\name`, `name@realm`) or by SID."""
    bare = value.removeprefix("name:")
    return value.casefold().startswith("sid:") or "\\" in bare or "@" in bare


def qualify_account(host: str, value: str) -> str:
    """A bare (host-local) account name qualified by its host."""
    return f"{host}\\{value.removeprefix('name:')}"


def finding_addresses(entities, *, is_internal: Callable[[str], bool] = _never_internal) -> list[str]:
    """The internal endpoint addresses a network finding's entities would resolve through the address map."""
    if not is_network_finding(entities):
        return []
    return [address for address, internal in network_endpoints(entities, is_internal=is_internal) if internal]


def fleet_recurring(rule_hosts: int, hunt_hosts: int, span_seconds: float, window_seconds: float) -> bool:
    """Whether a rule is recurring fleet-wide in a hunt (see FLEET_* above)."""
    if hunt_hosts < FLEET_MIN_HOSTS or window_seconds <= 0:
        return False
    needed = max(FLEET_MIN_HOSTS, math.ceil(FLEET_HOST_SHARE * hunt_hosts))
    return rule_hosts >= needed and span_seconds >= FLEET_SPAN_SHARE * window_seconds


def fleet_reason(rule_id: str, rule_hosts: int, hunt_hosts: int, span_seconds: float,
                 window_seconds: float) -> str:
    share = span_seconds / window_seconds if window_seconds else 0.0
    return (f"recurring fleet-wide rule {rule_id}: {rule_hosts} of {hunt_hosts} hosts over {share:.0%} of the "
            f"window (-{FLEET_PENALTY})")


def tactic_breadth(rule_tactics: Mapping[str, set[str] | tuple[str, ...]]) -> tuple[str, ...]:
    """The tactics of a maximum matching between rules and the tactics each maps to (T is its length): each rule
    contributes at most one tactic and each tactic is counted once. Augmenting paths over rules in id order, so the
    result is deterministic.

    A tactic group (`a|b`, a legacy tactic tag whose stage the current release splits in two) is one choice whose
    stage is unknown, so it never adds breadth beside either of its tactics: it is counted, as itself, only when no
    rule's definite tactic already covers one of them and no definite tactic was left for that rule."""
    definite = {rule: {tactic for tactic in tactics if TACTIC_GROUP_SEPARATOR not in tactic}
                for rule, tactics in rule_tactics.items()}
    matched: dict[str, str] = {}                     # tactic -> rule

    def augment(rule: str, seen: set[str]) -> bool:
        for tactic in sorted(definite[rule]):
            if tactic in seen:
                continue
            seen.add(tactic)
            if tactic not in matched or augment(matched[tactic], seen):
                matched[tactic] = rule
                return True
        return False

    for rule in sorted(definite):
        augment(rule, set())
    used = set(matched.values())
    groups = {tactic for rule, tactics in rule_tactics.items() if rule not in used
              for tactic in tactics if TACTIC_GROUP_SEPARATOR in tactic}
    for group in sorted(groups):
        if not set(group.split(TACTIC_GROUP_SEPARATOR)) & set(matched):
            matched[group] = "group"
    return tuple(sorted(matched))


@dataclass(frozen=True)
class EntityEvidence:
    """One entity's evidence from the hunt's deterministic findings, recurring fleet-wide rules excluded."""
    confirmed: int                    # U
    tactics: tuple[str, ...]          # the matched tactics; T is its length
    rules: int                        # R
    cooccurrence: int                 # C, already capped
    max_prior: float | None           # the strongest rule prior among the entity's deterministic findings
    fleet_rules: tuple[str, ...] = ()  # recurring fleet-wide rules seen on the entity, not counted
    notes: tuple[str, ...] = ()        # limits that may understate a factor


def evidence_bar(evidence: EntityEvidence) -> str | None:
    """Which criterion of the evidence bar the entity meets, or None."""
    if evidence.confirmed >= BAR_CONFIRMED:
        return f"a confirmed finding (U>={BAR_CONFIRMED})"
    if len(evidence.tactics) >= BAR_TACTICS:
        return f"{len(evidence.tactics)} ATT&CK tactics (T>={BAR_TACTICS})"
    if evidence.rules >= BAR_RULES and evidence.cooccurrence >= BAR_COOCCURRENCE:
        return (f"{evidence.rules} rules with {evidence.cooccurrence} co-occurring pair(s) "
                f"(R>={BAR_RULES} with C>={BAR_COOCCURRENCE})")
    return None


def entity_score(evidence: EntityEvidence) -> tuple[float, bool, list[str]]:
    """The entity's score, whether it meets the evidence bar, and the reasons for both."""
    tactic_count = len(evidence.tactics)
    prior = evidence.max_prior or 0.0
    score = float(WEIGHT_CONFIRMED * evidence.confirmed + WEIGHT_TACTIC * tactic_count
                  + WEIGHT_RULE * evidence.rules + WEIGHT_COOCCURRENCE * evidence.cooccurrence + prior)
    reasons = [
        f"confirmed findings U={evidence.confirmed} (+{WEIGHT_CONFIRMED * evidence.confirmed})",
        (f"ATT&CK tactics T={tactic_count}, at most one per rule"
         + (f" ({', '.join(evidence.tactics)})" if evidence.tactics else "") + f" (+{WEIGHT_TACTIC * tactic_count})"),
        f"distinct rules R={evidence.rules} (+{WEIGHT_RULE * evidence.rules})",
        (f"co-occurring rule pairs within {int(COOCCURRENCE_WINDOW.total_seconds() // 60)} min "
         f"C={evidence.cooccurrence} (+{WEIGHT_COOCCURRENCE * evidence.cooccurrence})"),
        f"strongest rule prior (+{prior:g})",
    ]
    if evidence.fleet_rules:
        reasons.append("recurring fleet-wide rules not counted: " + ", ".join(evidence.fleet_rules))
    reasons.extend(evidence.notes)
    met = evidence_bar(evidence)
    reasons.append(f"evidence bar met: {met}" if met else
                   f"evidence bar not met (needs U>={BAR_CONFIRMED}, or T>={BAR_TACTICS}, "
                   f"or R>={BAR_RULES} with C>={BAR_COOCCURRENCE})")
    return score, met is not None, reasons


@dataclass(frozen=True)
class EntityRank:
    kind: str
    value: str
    score: float
    reported: bool


def finding_rank(*, lane: str, prior: float, provenance: str, entities: list[EntityRank],
                 fleet: str | None) -> tuple[float, EntityRank | None, bool, list[str]]:
    """A finding's rank, the entity it is listed under, whether it is reported, and why.

    Rank = the best entity's score + the finding's own rule prior - FLEET_PENALTY when its rule is recurring
    fleet-wide (`fleet` is that rule's reason). A confirmed finding is always reported; a pool finding is reported
    when any of its entities meets the evidence bar. A reported finding is listed under its best entity that meets the
    bar (so every reported finding appears under a reported entity); any other finding under its best entity."""
    best = max(entities, key=lambda item: (item.score, item.kind == HOST, item.kind, item.value), default=None)
    score = (best.score if best else 0.0) + prior - (FLEET_PENALTY if fleet else 0)
    reasons = [f"best entity {best.kind}:{best.value} score {best.score:g} (+{best.score:g})" if best else
               "unattributed: no typed host, account or endpoint (+0)",
               f"rule prior (+{prior:g})"]
    if fleet:
        reasons.append(fleet)
    if provenance == AGENT_PROVENANCE:
        reasons.append("AI agent finding: ranked, never counted toward any entity's evidence")
    reporting = [item for item in entities if item.reported]
    listed = max(reporting, key=lambda item: (item.score, item.kind == HOST, item.kind, item.value),
                 default=best)
    if lane == CONFIRMED_LANE:
        reported = True
        reasons.append("reported: confirmed finding")
    elif reporting:
        reported = True
        reasons.append(f"reported: entity {listed.kind}:{listed.value} meets the evidence bar")
    else:
        reported = False
        reasons.append("not reported: no entity of this finding meets the evidence bar")
    return score, listed, reported, reasons


class CooccurrenceScan:
    """Co-occurring rule pairs on one entity, from its findings fed in time order.

    Only each rule's latest finding time inside the window is kept, so the state is bounded by the rules active in one
    window (at most the rule catalog), never by how many findings the entity has. A pair of rules co-occurs when any
    finding of one is within COOCCURRENCE_WINDOW of any finding of the other: when the later of the two is fed, the
    other rule's latest time is at least the earlier finding's, so the pair is seen."""

    def __init__(self) -> None:
        self.latest: dict[str, datetime] = {}
        self.pairs: set[tuple[str, str]] = set()

    @property
    def full(self) -> bool:
        return len(self.pairs) >= COOCCURRENCE_CAP

    @property
    def count(self) -> int:
        return min(len(self.pairs), COOCCURRENCE_CAP)

    def add(self, rule_id: str, ts: datetime) -> None:
        horizon = ts - COOCCURRENCE_WINDOW
        for other in [rule for rule, seen in self.latest.items() if seen < horizon]:
            del self.latest[other]
        for other in sorted(self.latest):
            if other != rule_id and not self.full:
                self.pairs.add((min(rule_id, other), max(rule_id, other)))
        self.latest[rule_id] = ts
