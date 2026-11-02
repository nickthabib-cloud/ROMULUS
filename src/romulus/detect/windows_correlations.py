"""Cited account sequences supported by positively recorded actions."""
from __future__ import annotations

import hashlib
import re

from romulus.detect.base import Match, pf
from romulus.detect.windows_account_events import (
    creation_target_sid,
    privileged_group_sid,
    sensitive_group_lane,
)
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
    version = "2"
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
        return self._match(member, [created], {**raw, **member_raw}, claim, identity,
                           lane=sensitive_group_lane(member.get("account.group_id")),
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


WINDOWS_CORRELATION_PLAYBOOKS = (CreatedThenPrivileged,)
