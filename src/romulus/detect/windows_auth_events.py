"""Positive Windows authentication shapes and concentrated, cited record windows."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime

from romulus.detect.base import Match, pf
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.detect.windows_burst_rows import BurstRows
from romulus.detect.windows_events import WindowsEventRule, integer, signal
from romulus.detect.windows_rows import row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows_catalog import (
    RDP_LSM_CHANNEL,
    RDP_LSM_PROVIDER,
    RDP_RCM_CHANNEL,
    RDP_RCM_PROVIDER,
    SECURITY,
)

_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-"
_FIELDS = ("event.code", "source.ip", "source.hostname", "host.full_name", "auth.target_account", "account.name", "account.domain", "user.entity_id",
           "auth.status", "auth.sub_status", "auth.failure_code", "auth.target_server", "auth.service_name")


def account_key(event):
    value = str(event.get("auth.target_account") or "").casefold()
    return value if value not in {"", "name:-", "sid:s-1-0-0"} else None


def source_ip(event):
    try:
        value = ipaddress.ip_address(str(event.get("source.ip")))
        if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
            value = value.ipv4_mapped
        return str(value) if not value.is_unspecified else None
    except ValueError:
        return None


def source_key(event):
    address = source_ip(event)
    if address:
        return "IP " + address
    workstation = event.get("source.hostname")
    if isinstance(workstation, str) and workstation.strip() not in {"", "-"}:
        return "reported workstation " + workstation.strip().rstrip(".").casefold()
    reporter = event.get("host.full_name") or event.host
    return "source unresolved, reported by " + str(reporter).rstrip(".").casefold() if reporter else None


class _Burst(WindowsEventRule):
    version = "4"
    citation_fields = _FIELDS
    needs_live_loader = False
    direct_eligible = False
    kind, claim_type, anchor_class = "aggregate", "aggregate_observation", "credential_access"
    families = ("auth",)
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4625, 4771, 4776))
    seconds, threshold, distinct = 600, 20, True
    benign = ("stale automation credentials, synchronized reconnects and authorized authentication testing",)
    next_checks = ("review cited status codes, source identities and site-wide authentication activity",)
    research = (_DOC + "4625", _DOC + "4771", _DOC + "4776")
    rationale = "Twenty failed records in ten minutes tests concentrated retries rather than isolated mistakes."

    def __init__(self):
        super().__init__()
        self.rows = BurstRows(self)
        self._batch = {}

    def eligible(self, event):
        return event.get("event.code") in {4625, 4771, 4776} and event.outcome == Outcome.failure

    def key_value(self, event):
        raise NotImplementedError

    def _load_witnesses(self, ids):
        found = {event.id: event for event in self.rows.compact(ids)}
        return [found[key] for key in ids]

    def _maybe(self, key, event_id, stamp, value, host, *, phase):
        identity = row_key(self.id, key, host)
        state_key = ("replay:" if phase == "finalize" else "window:") + identity
        previous = self.rows.marker(state_key)
        state = json.loads(previous) if previous else None
        if state is not None and stamp <= state["latest_end"]:
            return []
        if state is None and self.distinct and not self.rows.marked("qualified-key:"+key) and self.rows.prior_value(
                key, stamp, value, host, event_id, int(stamp//self.seconds)*self.seconds):
            return []
        evidence = self.rows.witnesses(key, stamp, self.seconds, self.threshold,
                                       distinct=self.distinct, latest=True)
        if len(evidence) != self.threshold:
            return []
        self.rows.first("qualified-key:"+key)
        if state is not None and min(item[1] for item in evidence) <= state["latest_end"]:
            return []
        loaded = self._load_witnesses(list(dict.fromkeys([event_id, *(item[0] for item in evidence)])))
        event = loaded[0]
        by_id = {item.id: item for item in loaded}
        witnesses = [by_id[item[0]] for item in evidence]
        start, end = min(item.ts.timestamp() for item in witnesses), max(item.ts.timestamp() for item in witnesses)
        if state is not None and start <= state["latest_end"]:
            return []
        state = {"first_start": start if state is None else state["first_start"],
                 "first_end": end if state is None else state["first_end"],
                 "latest_start": start, "latest_end": end, "windows": 1 if state is None else state["windows"]+1}
        self.rows.remember(state_key, json.dumps(state, sort_keys=True))
        emitted = self.rows.marker("emitted:"+identity)
        emitted = json.loads(emitted) if emitted else None
        if emitted is not None and end < emitted["latest_end"]:
            return []
        total = self.rows.count(key)
        selected = {item.id: item for item in loaded}
        signature = hashlib.sha256(row_key(state, sorted(selected), total).encode()).hexdigest()
        if emitted is not None and signature == emitted["signature"]:
            return []
        self.rows.remember("emitted:"+identity, json.dumps({"latest_end": end, "signature": signature}))
        reporter = key.startswith('["reporter",')
        key_text = ("reporting host " + str(event.get("host.full_name") or host) +
                    "; recorded sources may be unresolved or unrelated" if reporter else self.key_description(event))
        def iso(value):
            return datetime.fromtimestamp(value, UTC).isoformat()
        claim = (f"{self.description}: at least {self.threshold} {self.units} within {self.seconds} seconds "
                 f"for {self.describe(key_text)}. First qualifying window {iso(state['first_start'])} to "
                 f"{iso(state['first_end'])}; latest qualifying window {iso(start)} to {iso(end)}. "
                 f"The {self.threshold} cited witnesses describe the latest window. "
                 f"The current supporting record is on {event.host}. This is a concentration signal, not proof of intent.")
        return [Match(self.id, claim, self.claim_type, list(selected.values()),
                      [pf(item, name) for item in selected.values() for name in _FIELDS if item.has(name)], event.ts,
                      "medium", "lead", "medium", event.entities(),
                      [self.rationale, "Counts are records; several channels may describe one authentication attempt.",
                       (f"The correlation key has {total} recorded witnesses across {state['windows']} non-overlapping "
                        f"qualifying windows; at most {self.threshold+1} latest-window witnesses are cited. "
                        "First/latest bounds and window count are retained; other window members remain in disk-backed history."),
                       "Reported workstation labels do not establish verified host identities or IP ownership."],
                      group_key="windows-burst:" + hashlib.sha256(identity.encode()).hexdigest(),
                      context_ids=set(selected) - {event.id},
                      revision_reason="A later qualifying window or chronological replay revised the cited witnesses." if emitted else "")]

    def consume(self, events):
        out = []
        scoped = self.scope_partition(events)
        if not any(self.eligible(event) for event in scoped):
            if not self._events_pre_scoped:
                self.os_applicable += len(scoped)
            return out
        with self.rows.batch():
            for event in sorted(scoped, key=lambda item: (item.ts, item.id)):
                if not self._events_pre_scoped:
                    self.os_applicable += 1
                if not self.eligible(event):
                    continue
                self.evaluated += 1
                pair = self.key_value(event)
                if pair is None:
                    self.missing_required += 1
                    self.note_coverage("burst_keys", "Source, principal or target fields required for correlation were missing.")
                    continue
                key, value = pair
                if self.rows.put(key, event, value):
                    out.extend(self._maybe(key, event.id, event.ts.timestamp(), value, event.host, phase="consume"))
                    if isinstance(self, WindowsPasswordSpray):
                        reporter = str(event.get("host.full_name") or event.host).casefold()
                        report_key = row_key("reporter", reporter)
                        self.rows.put(report_key, event, value)
                        out.extend(self._maybe(report_key, event.id, event.ts.timestamp(), value, event.host, phase="consume"))
                        self.rows.put(row_key("daily-source", source_key(event)), event, value)
                        self.rows.put(row_key("daily-reporter", reporter), event, value)
        self._batch = {}
        return out

    def finalize(self):
        if not self.rows.ready:
            return
        with self.rows.batch():
            # Stream replay catches windows made visible by late or out-of-order target arrivals.
            for key, event_id, stamp, value, host in self.rows.iterate():
                if key.startswith('["daily-'):
                    continue
                yield from self._maybe(key, event_id, stamp, value, host, phase="finalize")
            if isinstance(self, WindowsPasswordSpray):
                yield from self._daily()

    def _daily(self):
        # Calendar days are explicit UTC partitions, not an assumed rolling lifetime or an absence test.
        threshold = 100
        for key, day, count, offset in self.rows.daily_groups(threshold):
            identity = "windows-daily-auth:" + hashlib.sha256(row_key(key).encode()).hexdigest()
            previous = self.rows.marker(identity)
            evidence = self.rows.daily_witnesses(key, day, threshold, offset)
            signature = json.dumps([count, max(item[1] for item in evidence)], separators=(",", ":"))
            if previous is not None:
                prior_count, prior_end = json.loads(previous)
                if prior_end >= max(item[1] for item in evidence) and prior_count >= count:
                    continue
            witnesses = sorted(self._load_witnesses([item[0] for item in evidence]), key=lambda item: (item.ts, item.id))
            if len(witnesses) != threshold:
                continue
            self.rows.remember(identity, signature)
            label, subject = json.loads(key)
            scope = "reporting host" if label == "daily-reporter" else "recorded source"
            interval = ("the hunt span" if day is None else
                        f"a UTC day partition (offset {offset//3600} hours) containing {witnesses[0].ts.isoformat()}")
            claim = (f"Failed authentication records named {count} distinct target-account identities during {interval} "
                     f"for {scope} {self.describe(subject)}; "
                     f"{threshold} distinct-account witnesses are cited. This account breadth can expose "
                     "slow or rotating-source guessing; it is not proof of intent or a verified common source.")
            yield Match(self.id, claim, self.claim_type, witnesses,
                        [pf(item, name) for item in witnesses for name in _FIELDS if item.has(name)], witnesses[-1].ts,
                        "medium", "lead", "medium", witnesses[0].entities(),
                        [("One hundred distinct accounts in a UTC day, offset day or hunt span tests breadth beyond the short "
                         "burst window. This absolute review threshold is independent of fleet size; central DCs, "
                         "outages and legitimate automation can exceed it and require site review."),
                         ("Daily, twelve-hour-offset daily and hunt-span partitions are checked; no negative assurance is made. "
                         "Account/source keys and late-record replay are disk-backed; only a stated disk refusal "
                         "can leave records unassessed.")], group_key=identity,
                        context_ids={item.id for item in witnesses[1:]},
                        revision_reason="Later records or a broader partition changed the distinct-account count." if previous else "")

    def release_state(self):
        self._batch = {}
        self._pending = []
        self.rows.close()
        super().release_state()


class WindowsPasswordSpray(_Burst):
    id, title = "win.password_spray", "Failed authentication against many accounts by source or reporting host"
    attack = ("T1110.003",)
    description, units = "Many target accounts were named by failed authentication records", "distinct target-account identities"
    rationale = ("Twenty distinct accounts in ten minutes tests concentrated account breadth per recorded source or "
                 "reporting host, independent of fleet size. Reporting-host concentration does not attribute a "
                 "common source; central authentication servers and outages can produce benign concentrations.")

    def key_value(self, event):
        source, account = source_key(event), account_key(event)
        return (row_key(source), account) if source and account else None

    def key_description(self, event):
        return source_key(event)


class WindowsBruteForce(_Burst):
    id, title = "win.brute_force", "Repeated failures against one account by source or reporting host"
    attack = ("T1110.001",)
    description, units, distinct = ("Failed authentication records repeatedly named one account",
                                    "failed authentication records", False)

    def key_value(self, event):
        source, account = source_key(event), account_key(event)
        return (row_key(source, account), event.id) if source and account else None

    def key_description(self, event):
        return f"{account_key(event)} from {source_key(event)}"


class WindowsDistributedGuessing(_Burst):
    id, title = "win.distributed_auth_failures", "Many sources failed authentication against one account"
    attack = ("T1110.001",)
    threshold = 10
    description, units = ("Many source or unresolved-source reporter identifiers had failed authentication records "
                          "naming one account"), "distinct source or reporter identifiers"
    rationale = "Ten source identifiers in ten minutes tests distributed concentration; workstation labels are unverified."

    def key_value(self, event):
        source, account = source_key(event), account_key(event)
        return (row_key(account), source) if source and account else None

    def key_description(self, event):
        return account_key(event)


class WindowsExplicitCredentialFanout(_Burst):
    id, title = "win.explicit_credential_fanout", "Explicit credentials named several target servers"
    attack = ("T1078",)
    windows_event_classes = (("Security", SECURITY, 4648),)
    threshold = 5
    description, units = "Explicit-credential audit records named many servers", "distinct target-server names"
    rationale = "Five destinations in ten minutes tests credential fanout per source host, actor and credential principal."
    research = (_DOC + "4648",)

    def eligible(self, event):
        return event.get("event.code") == 4648 and event.outcome != Outcome.failure

    def key_value(self, event):
        actor, account, server = event.get("user.entity_id"), account_key(event), event.get("auth.target_server")
        if not event.host or not actor or not account or not server or str(server).casefold() in {"-", "localhost"}:
            return None
        return row_key(event.host, str(actor).casefold(), account), str(server).rstrip(".").casefold()

    def key_description(self, event):
        return f"{event.get('user.entity_id')} using {account_key(event)} on {event.host}"


class WindowsKerberoastDiversity(_Burst):
    id, title = "win.kerberos_service_fanout", "One principal requested tickets for many service names"
    attack = ("T1558.003",)
    windows_event_classes = (("Security", SECURITY, 4769),)
    threshold, seconds = 10, 300
    description, units = "Service-ticket records named many services for one principal/client", "distinct recorded service names"
    rationale = "Ten service names in five minutes tests concentrated breadth per principal/client, independent of fleet size."
    research = (_DOC + "4769",)

    def eligible(self, event):
        return event.get("event.code") == 4769 and event.outcome == Outcome.success

    def key_value(self, event):
        account, source, service = account_key(event), source_ip(event), event.get("auth.service_name")
        return (row_key(account, source), str(service).casefold()) if account and source and service else None

    def key_description(self, event):
        return f"{account_key(event)} from {source_ip(event)}"


class WindowsHashLogonShape(WindowsEventRule):
    version = "2"
    id, title = "win.hash_logon_shape", "Logon fields have a pass-the-hash-associated shape"
    families = ("auth",)
    windows_event_classes = (("Security", SECURITY, 4624),)
    attack, anchor_class = ("T1550.002",), "credential_access"
    benign = ("runas /netonly, legitimate NewCredentials use and NTLM session-security configuration",)
    next_checks = ("inspect process_session and credential activity; the shape does not establish stolen hashes",)
    research = (_DOC + "4624", "https://attack.mitre.org/techniques/T1550/002/")

    def judge(self, event):
        if event.get("event.code") != 4624 or event.outcome == Outcome.failure:
            return []
        kind = integer(event.get("auth.logon_type"))
        if kind == 9 and str(event.get("auth.logon_process") or "").strip().casefold() == "seclogo":
            text = "A NewCredentials (type9) logon recorded the seclogo logon process"
        elif (kind == 3 and str(event.get("auth.package") or "").strip().casefold() == "ntlm"
              and integer(event.get("auth.key_length")) == 0):
            text = "An NTLM network (type3) logon recorded a zero-length session-security key"
        else:
            return []
        return [signal(event, "hash_logon_shape", text + "; this shape alone does not prove pass-the-hash", self.attack,
                       (*_FIELDS, "auth.logon_type", "auth.logon_process", "auth.package", "auth.key_length",
                        "auth.logon_guid", "auth.session_key"),
                       content=row_key(kind, event.get("auth.logon_process"), event.get("auth.package"),
                                       event.get("auth.key_length"), account_key(event), source_ip(event),
                                       event.get("source.hostname")))]


class WindowsExternalRdp(WindowsEventRule):
    version = "2"
    id, title = "win.rdp_external_source", "RDP source outside the site's internal-network definition"
    direction_dependent = True
    families = ("auth", "remote_access")
    windows_event_classes = (("Security", SECURITY, 4624), (RDP_RCM_CHANNEL, RDP_RCM_PROVIDER, 1149),
                             *((RDP_LSM_CHANNEL, RDP_LSM_PROVIDER, code) for code in (21, 25)))
    attack, anchor_class = ("T1021.001",), "remote_login"
    benign = ("authorized remote access through a gateway, VPN or partner network",)
    next_checks = ("validate the network definition, account and resulting RDP session",)
    research = (_DOC + "4624", "https://attack.mitre.org/techniques/T1021/001/")

    def judge(self, event):
        if event.family == "auth":
            if event.get("event.code") != 4624 or integer(event.get("auth.logon_type")) != 10:
                return []
            activity = "a RemoteInteractive logon audit"
        else:
            activity = {1149: "an RDP authentication record", 21: "an RDP logon record", 25: "an RDP reconnection record"}.get(event.get("event.code"))
            if not activity or event.get("remote.action") not in {"rdp_authentication", "rdp_logon", "rdp_reconnect"}:
                return []
            if (event.get("event.code") in {21, 25}
                    and str(event.get("windows.event_data.Address") or "").strip().casefold() == "local"):
                return []
        source = source_ip(event)
        if not source:
            self.note_limit("rdp_source", "An RDP record's source address is missing or unusable.")
            return [signal(event, "rdp_source_unknown", activity + " has an unresolved source address", self.attack,
                           ("source.ip", "auth.logon_type", "remote.action"),
                           content=row_key(activity, account_key(event), event.get("remote.user")))]
        assume_direction(self)
        if current().is_internal(ipaddress.ip_address(source)):
            return []
        notes = () if current().configured else (DIRECTION_ASSUMED_REASON,)
        return [signal(event, "rdp_external", f"Windows recorded {activity} from {source}, outside the site's internal-network "
                       "definition; authorization and resulting session activity are unresolved", self.attack,
                       (*_FIELDS, "auth.logon_type", "remote.action", "remote.user", "remote.session_id"), notes=notes,
                       content=row_key(activity, source, account_key(event), event.get("remote.user")))]


WINDOWS_AUTH_EVENT_PLAYBOOKS = (WindowsPasswordSpray, WindowsBruteForce, WindowsDistributedGuessing,
                               WindowsExplicitCredentialFanout, WindowsKerberoastDiversity,
                               WindowsHashLogonShape, WindowsExternalRdp)
