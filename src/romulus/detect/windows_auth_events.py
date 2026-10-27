"""Positive Windows authentication shapes and concentrated, cited record windows."""
from __future__ import annotations

import hashlib
import ipaddress

from romulus.detect.base import Match, pf
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, assume_direction, current
from romulus.detect.windows_events import WindowsEventRule, integer, signal
from romulus.detect.windows_rows import WindowsRows, row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows_catalog import (
    RDP_LSM_CHANNEL,
    RDP_LSM_PROVIDER,
    RDP_RCM_CHANNEL,
    RDP_RCM_PROVIDER,
    SECURITY,
)

_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-"
_FIELDS = ("event.code", "source.ip", "auth.target_account", "account.name", "account.domain", "user.entity_id",
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
    return None


class _Burst(WindowsEventRule):
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
        self.rows = WindowsRows(self)

    def eligible(self, event):
        return event.get("event.code") in {4625, 4771, 4776} and event.outcome == Outcome.failure

    def key_value(self, event):
        raise NotImplementedError

    def _maybe(self, key, event, value, *, phase):
        bucket = int(event.ts.timestamp() // self.seconds)
        identity = row_key(self.id, key, event.host, bucket)
        mark = ("finalized:" if phase == "finalize" else "published:") + identity
        if self.rows.marked(mark):
            return []
        qualified = row_key("qualified", phase, key, bucket)
        if (self.distinct and not self.rows.first(row_key("checked", phase, key, event.host, bucket, value))
                and not self.rows.marked(qualified)):
            return []
        evidence = self.rows.witnesses(key, event.ts.timestamp(), self.seconds, self.threshold, distinct=self.distinct)
        if len(evidence) != self.threshold or not self.rows.first(mark):
            return []
        self.rows.first(qualified)
        witnesses = [item for item, copies in evidence]
        selected = {item.id: item for item in [event, *witnesses]}
        raw = {name: body for item, copies in evidence for name, body in copies.items()}
        raw.update(self.raw_of(event))
        claim = (f"{self.description}: at least {self.threshold} {self.units} within {self.seconds} seconds "
                 f"for {self.describe(self.key_description(event))}. The {self.threshold} cited witnesses span "
                 f"{min(item.ts for item in witnesses).isoformat()} to {max(item.ts for item in witnesses).isoformat()}. "
                 f"The current supporting record is on {event.host}. This is a concentration signal, not proof of intent.")
        signature = hashlib.sha256(row_key(claim, sorted(selected)).encode()).hexdigest()
        previous = self.rows.marker("signature:" + identity)
        self.rows.remember("signature:" + identity, signature)
        self.rows.first("published:" + identity)
        if phase == "finalize" and previous == signature:
            return []
        return [Match(self.id, claim, self.claim_type, list(selected.values()),
                      [pf(item, name) for item in selected.values() for name in _FIELDS if item.has(name)], event.ts,
                      "medium", "lead", "medium", event.entities(),
                      [self.rationale, "Counts are records; several channels may describe one authentication attempt.",
                       "Reported workstation labels do not establish verified host identities or IP ownership."],
                      group_key="windows-burst:" + hashlib.sha256(identity.encode()).hexdigest(), raw_copies=raw,
                      context_ids=set(selected) - {event.id},
                      revision_reason=("Chronological replay selected the earliest qualifying cited witnesses "
                                       "after late records arrived." if phase == "finalize" and previous else ""))]

    def consume(self, events):
        out = []
        for event in sorted(self.scope_partition(events), key=lambda item: (item.ts, item.id)):
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
                out.extend(self._maybe(key, event, value, phase="consume"))
        return out

    def finalize(self):
        # Stream replay catches windows made visible by late or out-of-order target arrivals.
        for key, event, raw, value in self.rows.iterate():
            for match in self._maybe(key, event, value, phase="finalize"):
                match.raw_copies.update(raw)
                yield match

    def release_state(self):
        self.rows.close()
        super().release_state()


class WindowsPasswordSpray(_Burst):
    id, title = "win.password_spray", "One source failed authentication against many accounts"
    attack = ("T1110.003",)
    description, units = "Many target accounts were named by failed authentication records", "distinct target-account identities"
    rationale = "Twenty distinct accounts in ten minutes tests concentrated account breadth per source, independent of fleet size."

    def key_value(self, event):
        source, account = source_key(event), account_key(event)
        return (row_key(source), account) if source and account else None

    def key_description(self, event):
        return source_key(event)


class WindowsBruteForce(_Burst):
    id, title = "win.brute_force", "Repeated failures against one account from one source"
    attack = ("T1110.001",)
    description, units, distinct = "One source repeatedly failed authentication for one account", "failed authentication records", False

    def key_value(self, event):
        source, account = source_key(event), account_key(event)
        return (row_key(source, account), event.id) if source and account else None

    def key_description(self, event):
        return f"{account_key(event)} from {source_key(event)}"


class WindowsDistributedGuessing(_Burst):
    id, title = "win.distributed_auth_failures", "Many sources failed authentication against one account"
    attack = ("T1110.001",)
    threshold = 10
    description, units = "Many source identifiers had failed authentication records naming one account", "distinct recorded source identifiers"
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
                        "auth.logon_guid", "auth.session_key"))]


class WindowsExternalRdp(WindowsEventRule):
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
        source = source_ip(event)
        if not source:
            self.note_limit("rdp_source", "An RDP record's source address is missing or unusable.")
            return [signal(event, "rdp_source_unknown", activity + " has an unresolved source address", self.attack,
                           ("source.ip", "auth.logon_type", "remote.action"))]
        assume_direction(self)
        if current().is_internal(ipaddress.ip_address(source)):
            return []
        notes = () if current().configured else (DIRECTION_ASSUMED_REASON,)
        return [signal(event, "rdp_external", f"Windows recorded {activity} from {source}, outside the site's internal-network "
                       "definition; authorization and resulting session activity are unresolved", self.attack,
                       (*_FIELDS, "auth.logon_type", "remote.action", "remote.user", "remote.session_id"), notes=notes)]


WINDOWS_AUTH_EVENT_PLAYBOOKS = (WindowsPasswordSpray, WindowsBruteForce, WindowsDistributedGuessing,
                               WindowsExplicitCredentialFanout, WindowsKerberoastDiversity,
                               WindowsHashLogonShape, WindowsExternalRdp)
