"""Typed MTA delivery and logged attachment observations.

External recipient rate is a documented outbound-abuse signal:
https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure.
Fifty distinct external recipients in ten minutes is a review heuristic, not a
vendor enforcement limit. Mailing lists and automation explain a LEAD; a preceding
same-account, same-service failure burst raises it to HIGH. External means outside
explicitly configured mail domains, never outside a guessed sender domain.

Attachment names follow the risky file-type rationale documented at
https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about.
A logged name establishes neither file contents nor execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

from romulus.detect.base import Playbook
from romulus.detect.bounded import KeyedStore, RecentIds
from romulus.detect.service_auth import DATASETS, Record, RecordRule, group_id, observation, text_field
from romulus.evidence.typed import Outcome

MAIL_AUTH_SERVICES = frozenset({"dovecot", "postfix", "exim", "cyrus", "sendmail", "saslauthd"})


@dataclass
class _Burst:
    recipients: dict[str, Record] = field(default_factory=dict)
    attributions: dict[str, Record] = field(default_factory=dict)
    failures: list[Record] = field(default_factory=list)
    match: object = None


class MailOutboundBurst(RecordRule):
    id = "mail.outbound_burst"
    title = "Many distinct external mail recipients from one sender or host"
    families = ("mail_message", "auth")
    required_by_family: ClassVar[dict] = {"mail_message": ("mail.service", "mail.direction", "mail.message_id", "mail.to"),
                          "auth": ("auth.service", "auth.phase", "user.name")}
    attack = ("T1078",)
    threshold = 50
    seconds = 600
    uses_site_facts = True
    benign = ("Mailing lists, batch jobs and legitimate announcements can send to many recipients.",)
    next_checks = ("Configure mail_domains in the site collection file before judging external recipients.",
                   "Review the sender's authentication and whether the deliveries were authorized.")
    card: ClassVar[dict] = {"behavior": title, "telemetry": "MTA queue identity, delivery recipient and authenticated sender",
            "fidelity": "Delivered recipients outside configured mail domains; failures can strengthen the lead."}

    def __init__(self, internal_domains=()):
        super().__init__()
        self.internal_domains = frozenset(domain.casefold().rstrip(".") for domain in internal_domains)
        self._queues = self.store("mail_queues")
        self._groups = self.store("mail_groups", candidate=lambda state: state.match is not None)
        self._failures = self.store("mail_failures")

    def domains(self):
        return self.internal_domains or frozenset(getattr(getattr(self, "site_facts", None), "mail_domains", ()))

    def in_scope(self, event):
        if not super().in_scope(event):
            return False
        return (event.family == "mail_message" or
                (event.get("auth.service") in MAIL_AUTH_SERVICES
                 and event.get("auth.phase") == "authentication" and event.outcome == Outcome.failure))

    def accept(self, event):
        if event.family == "auth":
            service = text_field(event, "auth.service")
            if service not in MAIL_AUTH_SERVICES or event.get("auth.phase") != "authentication":
                return False
            if event.outcome != Outcome.failure:
                return False
            if not event.host or not text_field(event, "user.name"):
                self.missing_required += 1
                return False
            return True
        if not self.domains():
            self.missing_required += 1
            self.note_coverage("mail_domains", "External mail recipients cannot be judged without configured mail_domains.")
            return False
        if not event.host or not text_field(event, "mail.service") or not text_field(event, "mail.message_id"):
            self.missing_required += 1
            return False
        direction = event.get("mail.direction")
        # Queue metadata may carry the account on a different line from the delivered recipient.
        if direction in {None, "received"} and text_field(event, "mail.authenticated_user"):
            return True
        if direction != "delivered":
            return False
        recipients = event.get("mail.to")
        if not isinstance(recipients, list) or not recipients or not all(isinstance(item, str) for item in recipients):
            self.missing_required += 1
            return False
        if event.outcome == Outcome.failure:
            return False
        count = event.get("mail.to_count")
        if isinstance(count, int) and count > len(recipients):
            self.missing_required += 1  # recorded prefix can still prove a positive; cannot prove a negative
        return True

    def finalize(self):
        if self._done:
            return
        self._done = True
        for index, record in enumerate(self._rows):
            event = record.event
            account = text_field(event, "mail.authenticated_user")
            if event.family == "mail_message" and account:
                key = (event.host, event.get("mail.service"), event.get("mail.message_id"))
                previous = self._queues.get(key)
                # Queue ids may be reused; conflicting identities cannot support an account join.
                value = (account, record) if previous is None else previous
                if previous is not None and previous[0] != account:
                    value = ("", None)
                self.put(self._queues, key, value)
            if index % 128 == 0:
                self.trim()
        for index, record in enumerate(self._rows.ordered()):
            event = record.event
            if event.family == "auth":
                key = (event.host, event.get("auth.service"), event.get("user.name"))
                recent = self._failures.get(key) or []
                recent = [row for row in recent if (event.ts - row.event.ts).total_seconds() <= self.seconds]
                recent.append(record)
                self.put(self._failures, key, recent[-10:])
            elif event.get("mail.direction") == "delivered":
                self.delivery(record)
            if index % 128 == 0:
                self.trim()
        self.trim()
        for _key, state in self._groups.items(candidates=True):  # noqa: PERF102 - disk-backed KeyedStore has no values()
            yield state.match

    def delivery(self, record):
        event = record.event
        queue = self._queues.get((event.host, event.get("mail.service"), event.get("mail.message_id")))
        if queue and queue[1] is not None and queue[1].event.ts > event.ts:
            queue = None  # a future account record cannot establish attribution for an earlier delivery
        account = text_field(event, "mail.authenticated_user") or (queue[0] if queue else None)
        if queue is not None and not queue[0]:
            self.missing_required += 1
            account = None
        key = (event.host, event.get("mail.service"), "account" if account else "host", account or event.host)
        state = self._groups.get(key)
        if state is None:
            state = _Burst()
            if not self.put(self._groups, key, state):
                return
        cutoff = event.ts.timestamp() - self.seconds
        state.recipients = {recipient: row for recipient, row in state.recipients.items()
                            if row.event.ts.timestamp() >= cutoff}
        for recipient in event.get("mail.to"):
            if "@" not in recipient or not recipient.rsplit("@", 1)[0]:
                self.missing_required += 1
                continue
            domain = recipient.rsplit("@", 1)[1].casefold().rstrip(".")
            if (len(domain) > 253 or "." not in domain
                    or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                           for label in domain.split("."))):
                self.missing_required += 1
                continue
            if domain in self.domains():
                continue
            # Domain names are case-insensitive; local parts are not necessarily so.
            identity = recipient.rsplit("@", 1)[0] + "@" + domain
            state.recipients[identity] = record
            if queue and queue[1] is not None:
                state.attributions[identity] = queue[1]
            else:
                state.attributions.pop(identity, None)
            if len(state.recipients) > self.threshold:
                oldest = min(state.recipients, key=lambda name: (state.recipients[name].event.ts, name))
                del state.recipients[oldest]
        state.attributions = {name: row for name, row in state.attributions.items() if name in state.recipients}
        if len(state.recipients) < self.threshold:
            return
        failures = self._failures.get((event.host, event.get("mail.service"), account)) if account else None
        first_delivery = min(row.event.ts for row in state.recipients.values())
        high = bool(failures and len(failures) == 10 and failures[-1].event.ts < first_delivery
                    and (event.ts - failures[0].event.ts).total_seconds() <= self.seconds)
        if state.match is not None and (state.match.proposed_lane == "high" or not high):
            return
        records = list(state.recipients.values()) + list(state.attributions.values())
        if high:
            records += failures
        suffix = " following ten failed authentications for that account and mail service" if high else ""
        state.match = observation(self, records, key,
                                  f"Mail service {key[1]} on {key[0]} recorded deliveries from {key[2]} '{key[3]}' "
                                  f"to at least {self.threshold} distinct external recipients within {self.seconds} "
                                  f"seconds{suffix}. External domains are judged against the configured site mail domains.",
                                  "high" if high else "lead",
                                  ("mail.service", "mail.message_id", "mail.direction", "mail.to",
                                   "mail.authenticated_user", "auth.service", "user.name"))


class MailExecutableAttachment(Playbook):
    id = "mail.executable_attachment"
    title = "Executable or script name logged as a mail attachment"
    families = ("mail_message",)
    os_families = ("linux",)
    datasets = DATASETS
    required_fields = ("mail.service", "mail.message_id", "mail.attachment_names")
    lane = "high"
    severity = "high"
    attack = ("T1566.001",)
    assures_negative = False
    positive_only_reason = (
        "No parsed MTA log currently supplies attachment names; this rule only evaluates explicitly supplied typed "
        "attachment names, so absence cannot exclude executable attachments.")
    state_slice = "strong"
    benign = ("Authorized software distribution can include executable attachments; a filename does not prove execution.",)
    next_checks = ("Inspect the preserved message and attachment safely and verify sender authorization.",)
    extensions = frozenset({"exe", "com", "scr", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
                            "wsf", "hta", "sh", "bash", "py", "pl", "jar", "dll", "elf"})
    card: ClassVar[dict] = {"behavior": title, "telemetry": "Explicit logged mail attachment names",
            "fidelity": "Risky extension in a logged filename; message contents and execution are unknown."}

    def __init__(self):
        super().__init__()
        self._messages = KeyedStore(self, "attachment_messages", 128)
        self._recent = RecentIds()

    def consume(self, events):
        for event in self.applicable(events):
            names = event.get("mail.attachment_names")
            if (not event.host or not text_field(event, "mail.service") or not text_field(event, "mail.message_id")
                    or not isinstance(names, list) or not all(isinstance(name, str) for name in names)):
                self.missing_required += 1
                continue
            risky = next((name for name in names if "." in name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                          and name.rsplit(".", 1)[-1].casefold() in self.extensions), None)
            if risky is None:
                continue
            key = (event.host, event.get("mail.service"), event.get("mail.message_id"))
            identity = group_id(key)
            if identity in self._recent or self._messages.get(key) is not None:
                continue
            # A strong per-record positive needs no aggregate state. If optional de-duplication
            # cannot grow, stable group identity still merges repeated publication downstream.
            self._messages.put(key, True)
            self._recent.add(identity)
            self._messages.trim()
            yield observation(self, [Record(event, self.raw_of(event))], key,
                              f"Mail message {key[2]} on {key[0]} logged attachment '{risky}' with an executable "
                              "or script extension. File contents, delivery and execution are not established.",
                              "high", self.required_fields)

    def release_state(self):
        self._messages.clear()


MAIL_PLAYBOOKS = [MailOutboundBurst, MailExecutableAttachment]
