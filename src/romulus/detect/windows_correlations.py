"""Cited account sequences and explicitly unresolved Kerberos context."""
from __future__ import annotations

import hashlib
import re

from romulus.detect.base import Match, pf
from romulus.detect.windows_account_events import creation_target_sid, privileged_group_sid
from romulus.detect.windows_auth_events import source_ip
from romulus.detect.windows_events import WindowsEventRule
from romulus.detect.windows_rows import WindowsRows, row_key
from romulus.evidence.typed import Outcome
from romulus.evidence.windows_catalog import SECURITY

_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-"
_FIELDS = ("event.code", "account.group_id", "account.member_id", "account.name", "account.domain",
           "user.entity_id", "auth.target_account", "source.ip", "auth.service_name", "auth.encryption_type")


def _member_sid(event):
    value = str(event.get("account.member_id") or "").strip().casefold()
    match = re.fullmatch(r"s-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})-(\d{1,10})", value, re.ASCII)
    if not match or any(int(item) > 0xffffffff for item in match.groups()):
        return None
    return "s-1-5-21-" + "-".join(str(int(item)) for item in match.groups())


def kerberos_principal(event):
    name = str(event.get("account.name") or "").strip().casefold()
    realm = str(event.get("account.domain") or "").strip().rstrip(".").casefold()
    if "@" in name:
        name, upn_realm = name.rsplit("@", 1)
        if realm and realm != upn_realm.rstrip("."):
            return None
        realm = upn_realm.rstrip(".")
    if name and realm:
        return row_key(realm, name)
    identity = str(event.get("auth.target_account") or "").strip().casefold()
    return identity if identity.startswith("sid:s-1-") else None


class _RowsRule(WindowsEventRule):
    direct_eligible = False
    kind, claim_type = "aggregate", "correlated_observation"

    def __init__(self):
        super().__init__()
        self.rows = WindowsRows(self)

    def release_state(self):
        self.rows.close()
        super().release_state()

    def _match(self, subject, context, raw, claim, identity, *, lane="lead", notes=(), revision=""):
        records = [subject, *context]
        return Match(self.id, claim, self.claim_type, records,
                     [pf(item, name) for item in records for name in _FIELDS if item.has(name)], subject.ts,
                     "high" if lane == "high" else "medium", lane, "medium", subject.entities(),
                     [*notes, "ATT&CK context (not proof): " + ", ".join(self.attack)], group_key=identity,
                     raw_copies=raw, context_ids={item.id for item in context}, revision_reason=revision)


class CreatedThenPrivileged(_RowsRule):
    id, title = "win.created_then_privileged", "Account creation followed by sensitive group membership"
    lane = severity = "high"
    families = ("account_change",)
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4720, 4741, 4728, 4732, 4756))
    attack, anchor_class = ("T1136", "T1098.007"), "persistence"
    benign = ("approved provisioning followed by planned administrator or remote-access group membership",)
    next_checks = ("validate account and member SIDs, actor approval and subsequent logons",)
    research = (_DOC + "4720", _DOC + "4728", _DOC + "4732")
    seconds = 86400

    def _judge_member(self, member, member_raw):
        sid = _member_sid(member)
        if not sid or not privileged_group_sid(member.get("account.group_id")):
            return None
        pair = self.rows.prior(row_key("created", sid), member.ts.timestamp(), self.seconds)
        if not pair:
            return None
        created, raw = pair
        identity = "windows-created-privileged:" + hashlib.sha256(member.id.encode()).hexdigest()
        previous = self.rows.marker(identity)
        if previous == created.id:
            return None
        self.rows.remember(identity, created.id)
        delta = int((member.ts-created.ts).total_seconds())
        claim = (f"An account-creation audit on {created.host} at {created.ts.isoformat()} was followed {delta} seconds "
                 f"later by a sensitive-group addition audit on {member.host} at {member.ts.isoformat()}; "
                 f"the created target SID and added member SID are both {sid}. "
                 f"The group SID is {member.get('account.group_id')}. Authorization and intent are unresolved.")
        return self._match(member, [created], {**raw, **member_raw}, claim, identity, lane="high",
                           notes=(("The 24-hour sequence tests recent provisioning followed by privilege assignment; "
                                   "longer gaps fall outside this predicate. SID equality is the recorded identity link."),),
                           revision="A later creation record changed the nearest preceding creation context." if previous else "")

    def consume(self, events):
        out = []
        for event in sorted(self.scope_partition(events), key=lambda item: (item.ts, item.id)):
            if not self._events_pre_scoped:
                self.os_applicable += 1
            code = event.get("event.code")
            if code not in {4720, 4741, 4728, 4732, 4756} or event.outcome != Outcome.success:
                continue
            self.evaluated += 1
            sid = creation_target_sid(event) if code in {4720, 4741} else _member_sid(event)
            if not sid:
                self.missing_required += 1
                self.note_coverage("account_sid", "Creation correlation requires a validated target/member SID.")
                continue
            kind = "created" if code in {4720, 4741} else "member"
            if kind == "member" and not privileged_group_sid(event.get("account.group_id")):
                continue
            if self.rows.put(row_key(kind, sid), event, kind) and kind == "member":
                match = self._judge_member(event, self.raw_of(event))
                if match:
                    out.append(match)
        return out

    def finalize(self):
        # Late creation targets may precede arbitrarily many membership records; stream rather than building a list.
        for key, event, raw, kind in self.rows.iterate():
            if kind == "member":
                match = self._judge_member(event, raw)
                if match:
                    yield match


class KerberosTgtContext(_RowsRule):
    id, title = "win.kerberos_tgt_context", "Service-ticket record with unresolved collected TGT context"
    families = ("auth",)
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4768, 4769))
    attack, anchor_class = ("T1558.001", "T1558.002"), "credential_access"
    benign = ("cached or renewed TGTs, cross-DC collection gaps, domain policy and a hunt starting after authentication",)
    next_checks = ("retrieve authentication context across DCs and verify the domain's ticket lifetime",)
    research = (_DOC + "4768", _DOC + "4769")
    seconds = 36000

    def consume(self, events):
        for event in sorted(self.scope_partition(events), key=lambda item: (item.ts, item.id)):
            if not self._events_pre_scoped:
                self.os_applicable += 1
            code = event.get("event.code")
            if code not in {4768, 4769} or event.outcome != Outcome.success:
                continue
            self.evaluated += 1
            principal, client = kerberos_principal(event), source_ip(event)
            if not principal or not client:
                self.missing_required += 1
                self.note_coverage("ticket_keys", "TGT context requires a realm-qualified principal and client IP.")
                continue
            self.rows.put(row_key("tgt" if code == 4768 else "tgs", principal, client), event, str(code))
        return []

    def finalize(self):
        for key, service, raw, code in self.rows.iterate():
            if code != "4769":
                continue
            principal, client = kerberos_principal(service), source_ip(service)
            prior = self.rows.prior(row_key("tgt", principal, client), service.ts.timestamp(), self.seconds)
            identity = "windows-tgt-context:" + hashlib.sha256(row_key(
                service.id, service.host, principal, client).encode()).hexdigest()
            previous = self.rows.marker(identity)
            # A companion's presence by itself is not an attack signal. Only revise a previously published gap.
            if prior and previous is None:
                continue
            signature = "paired:" + prior[0].id if prior else "unresolved:" + service.id
            if previous == signature:
                continue
            if previous and not prior:
                continue
            self.rows.remember(identity, signature)
            notes = ("The ten-hour lookback is a default ticket-lifetime assumption, not this domain's configured policy.",
                     ("Only collected records were compared; cached/reused tickets, other DCs, collection gaps and the hunt "
                      "boundary can leave context unresolved; this does not establish a missing TGT or forged ticket."),
                     "Principal and client-IP equality is context, not a cryptographic link to one logon or ticket.")
            if prior:
                tgt, copies = prior
                claim = (f"The service-ticket record at {service.ts.isoformat()} has a recorded companion 4768 at "
                         f"{tgt.ts.isoformat()} on {tgt.host} with the same realm-qualified principal and client IP {client}; "
                         "this comparison does not establish a cryptographic ticket relationship.")
                context = [tgt]
                raw = {**copies, **raw}
            else:
                claim = (f"Service-ticket record at {service.ts.isoformat()} on {service.host} for recorded principal "
                         f"{self.describe(principal)} from {client} has unresolved TGT context in this hunt's recorded subset. "
                         "This is a context gap, not evidence of ticket forgery.")
                context = []
            yield self._match(service, context, raw, claim, identity, notes=notes,
                              revision="Later collected authentication evidence resolved the prior TGT context gap." if previous else "")


WINDOWS_CORRELATION_PLAYBOOKS = (CreatedThenPrivileged, KerberosTgtContext)
