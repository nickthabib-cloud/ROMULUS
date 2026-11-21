"""Refusals logged by Linux privilege brokers: sudo, su, runuser and pkexec.

Each broker writes its own decision to syslog or the journal, so on a host without process auditing these lines are
the record of who tried to become another account and was refused:
- sudoers(5) EVENT LOGGING: a rejected command's line names the reason ("user NOT in sudoers", "command not allowed",
  "3 incorrect password attempts", ...) before its TTY/PWD/USER/COMMAND fields;
- util-linux login-utils/su-common.c log_syslog: "FAILED SU (to <target>) <caller> on <tty>" (and FAILED RUNUSER);
- shadow-utils lib/sulog.c: "FAILED su for <target> by <caller>";
- polkit src/programs/pkexec.c log_message: "<caller>: Error executing command as another user: Not authorized ...",
  and the SHELL and environment checks that CVE-2021-4034 (PwnKit) exploitation trips
  (https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt).
The broker's log line is the evidence; the command and working directory in it are the caller's own text and are
never read as an action that ran.
"""
from __future__ import annotations

import json
import re
from typing import ClassVar

from romulus.detect.base import Match, basename, pf
from romulus.detect.bounded import KeyedStore
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS
from romulus.detect.linux_direct import FoldedLinuxDirect, observed
from romulus.detect.log_writer import line_subject, writer_sentence, writer_state
from romulus.evidence.linux_service_text import PKEXEC_AMBIGUOUS_CAVEAT
from romulus.evidence.linux_text_types import SUDO_AMBIGUOUS_CAVEAT
from romulus.evidence.typed import Outcome

BROKERS = frozenset({"sudo", "su", "runuser", "pkexec"})
_FIELDS = ("auth.service", "user.name", "auth.target_user", "privilege.denial_reason", "process.tty",
           "privilege.rejected_variable", "sudo.command", "privilege.command", "process.cwd", "process.pid")
_RESEARCH = ("sudoers(5) EVENT LOGGING (https://www.sudo.ws/docs/man/sudoers.man/); util-linux "
             "login-utils/su-common.c log_syslog; shadow-utils lib/sulog.c; polkit src/programs/pkexec.c "
             "log_message; Elastic System integration auth pipeline test logs (test-sudo-optional-fields.log, "
             "test-auth.log); ")


def _quote(value) -> str:
    return repr(str(value)) if value not in (None, "") else "an unrecorded account"


class PrivilegeBrokerRefusal(FoldedLinuxDirect):
    version = "1"
    id = "host.privilege_broker_refusal"
    title = "A privilege broker (sudo, su, runuser or pkexec) refused an account's request to act as another account"
    families = ("privilege_use",)
    required_fields = ("auth.service",)
    anchor_class = "privilege_escalation"
    severity, lane = "medium", "lead"
    attack = ("T1548", "T1548.003", "T1110.001")
    benign = ("an administrator mistyping a password, or an account not yet granted sudo trying it",
              "automation calling sudo without a terminal where a password is required",
              "a user running a command sudoers does not allow (policy working as intended)")
    next_checks = ("the account's other sudo, su and login records on the host before and after",
                   "what the account's session ran (process exec records, shell history) around the refusal",
                   "whether the account later became the target account by another route")
    card: ClassVar[dict] = {
        "behavior": "sudo, su, runuser or pkexec logged that it refused an account's request to run as another "
                    "account: not in sudoers, not authorized on the host, command not allowed, a password required "
                    "or wrong, or su/runuser authentication failed",
        "telemetry": "privilege_use from the brokers' own syslog or journal lines in any Linux shipper shape "
                     "(auth.service, user.name, auth.target_user, privilege.denial_reason, process.tty, process.pid; "
                     "sudo.command and privilege.command are the caller's text). The lab profile has sudo journal "
                     "records; su and pkexec lines where those programs are used",
        "fidelity": "direct: the broker's own decision record. It shows the request was refused, never that the "
                    "account had no other route to the target account",
        "benign_and_cost": "mistyped passwords and unprivileged users trying sudo; one folded lead per (host, broker, "
                           "account, target, reason), so a burst of retries is one finding with its count",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the account's session on the host: its logins, its commands, and any later success as the "
                      "target account",
        "adds": "no earlier rule reads privilege broker refusals; the SSH and service guessing rules read only "
                "network logins",
        "research_basis": _RESEARCH + "ATT&CK Enterprise 20.0 T1548, T1548.003, T1110.001",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
        "lanes": "lead: a refusal is a failed operation, which admission keeps at lead; a refused web-service account "
                 "(a web shell trying to escalate) is named in the claim and grouped on its own. Never context",
    }

    def match(self, e):
        service = str(e.get("auth.service"))
        if service not in BROKERS:
            return []
        if e.has("privilege.rejected_variable"):
            return []                     # pkexec's environment checks are host.pkexec_environment_rejection's
        if e.outcome == Outcome.unknown:
            self.missing_required += 1
            return []
        if e.outcome != Outcome.failure:
            return []
        reason = e.get("privilege.denial_reason")
        actor, target = e.get("user.name"), e.get("auth.target_user")
        web = actor in WEB_SERVICE_USERS
        subject = line_subject(e, service)
        said = f"{subject} says that {service} refused" if subject else f"{service} logged that it refused"
        claim = (f"On {e.host}, {said} {_quote(actor)} acting as {_quote(target)}"
                 + (f" ({reason})" if reason else "") + ".")
        if web:
            claim += " The refused account is a web-service account, which does not normally ask for another account."
        if e.has("sudo.chunk"):
            claim += " sudo split this record across lines and the rest was not joined, so the run-as account is unknown."
        elif SUDO_AMBIGUOUS_CAVEAT in e.caveats and not e.has("auth.target_user"):
            claim += (" The record is ambiguous: a field separator inside the caller's text kept its fields from being "
                      "read apart, so the run-as account is unknown and the reason may be cut short.")
        return [observed(self, e, claim, "lead", group=json.dumps([e.host, service, actor, target, reason, web,
                                                                    writer_state(e)]), names=_FIELDS)]


class PkexecEnvironmentRejection(FoldedLinuxDirect):
    version = "1"
    id = "host.pkexec_environment_rejection"
    title = "pkexec refused a SHELL or environment value (the check CVE-2021-4034 exploitation trips)"
    families = ("privilege_use",)
    required_fields = ("auth.service",)
    anchor_class = "privilege_escalation"
    severity, lane = "high", "high"
    attack = ("T1068",)
    benign = ("a user whose login shell is not listed in /etc/shells running pkexec",
              "an environment variable with '..' or '%' in its value passed to pkexec by a desktop session")
    next_checks = (("the caller's session around the record: files it wrote (a gconv-modules file and a shared "
                    "object in its working directory), and any root shell or process started next"),
                   "the installed polkit version (CVE-2021-4034 is fixed in 0.120 and distribution backports)")
    card: ClassVar[dict] = {
        "behavior": "pkexec logged that the SHELL value was not in /etc/shells, or that an environment variable's "
                    "value was suspicious, and refused to continue: the trace CVE-2021-4034 (PwnKit) exploitation "
                    "leaves",
        "telemetry": "privilege_use from pkexec's own syslog or journal line (auth.service pkexec, "
                     "privilege.rejected_variable, user.name, auth.target_user, process.tty, process.cwd; "
                     "privilege.command is the caller's text). Present wherever pkexec's authpriv log is shipped",
        "fidelity": "direct: pkexec's own record of the rejected value, typed with an unknown outcome because pkexec "
                    "writes it before the report where exploitation runs its code. It shows the check was tripped, "
                    "not that an exploit ran its payload or succeeded",
        "benign_and_cost": "rare: a login shell missing from /etc/shells, or a desktop environment value with "
                           "'..' or '%'; cheap to rule out by the caller's shell and the command text",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the caller's working directory for a gconv-modules file and a shared object, and the "
                      "processes the caller's session started as root after the record",
        "adds": "the refusal rule leaves these records to this rule, which names the exploitation trace",
        "research_basis": _RESEARCH + "Qualys CVE-2021-4034 advisory (the two log messages exploitation leaves, "
                          "including polkit 0.105's 'not found the /etc/shells file' and 'suscipious content' "
                          "spellings); ATT&CK Enterprise 20.0 T1068",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
        "lanes": "high: the record is rare, and an exploit that succeeded gives root",
    }

    def match(self, e):
        if e.get("auth.service") != "pkexec" or not e.has("privilege.rejected_variable"):
            return []
        variable = e.get("privilege.rejected_variable")
        actor, target = e.get("user.name"), e.get("auth.target_user")
        subject = line_subject(e, "pkexec")
        said = f"{subject} says that pkexec" if subject else "pkexec"
        claim = (f"On {e.host}, {said} run by {_quote(actor)} to act as {_quote(target)} rejected the value of "
                 f"{variable} ({e.get('privilege.denial_reason')}). CVE-2021-4034 exploitation leaves exactly this "
                 "record; whether an exploit payload ran is not shown by it.")
        return [observed(self, e, claim, "high", group=json.dumps([e.host, actor, variable, writer_state(e)]),
                         names=(*_FIELDS, "log.identifier", "log.writer"))]


# Who asked. Web-service accounts and the system accounts Debian's base-passwd and Fedora's setup package create
# without a login shell never legitimately ask a broker for another account: any success is high. Application,
# monitoring, CI and database accounts often hold narrow NOPASSWD sudo rules their jobs use on a schedule (a
# monitoring check reading a root-only file): their success is a lead, raised only by what the routine job never
# shows (see PrivilegeBrokerSuspiciousSuccess.app_risks).
NEVER_BROKER_ACCOUNTS = frozenset({
    "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "backup", "list",
    "irc", "gnats", "nfsnobody", "_apt", "messagebus", "sshd", "syslog", "polkitd", "tss"})
APP_ACCOUNTS = frozenset({
    "nagios", "icinga", "zabbix", "prometheus", "grafana", "telegraf", "jenkins", "gitlab-runner", "git", "postgres",
    "mysql", "mariadb", "mongodb", "redis", "memcached", "rabbitmq", "elasticsearch", "kibana", "tomcat", "tomcat9",
    "jetty", "named", "bind", "dnsmasq", "squid", "postfix", "dovecot", "ftp", "ansible", "puppet", "chef", "salt"})
NO_TTY = frozenset({"unknown", "none", "(none)", "notty", "?"})


def account_class(actor: str) -> str:
    """'web', 'never' (a system account that never uses a broker), 'app' or 'user'."""
    if actor in WEB_SERVICE_USERS:
        return "web"
    if actor in NEVER_BROKER_ACCOUNTS or actor.startswith("systemd-"):
        return "never"
    return "app" if actor in APP_ACCOUNTS else "user"


# Refusals that say the account had no right to the request at all (not a password problem): a success afterwards
# means the account's rights or route changed within minutes.
POLICY_REFUSALS = ("user NOT in sudoers", "user NOT authorized on host", "unknown user")
_ATTEMPTS = re.compile(r"(\d+) incorrect password attempts?")


def refusal_weight(event) -> tuple[int, bool]:
    """(failed password attempts the refusal record stands for, whether it is a policy refusal)."""
    reason = str(event.get("privilege.denial_reason") or "")
    if any(reason.startswith(text) for text in POLICY_REFUSALS):
        return 0, True
    counted = _ATTEMPTS.fullmatch(reason)
    return (int(counted[1]) if counted else 1), False


def _identifier(event) -> str:
    return str(event.get("log.identifier") or event.get("auth.service") or "the broker")


class PrivilegeBrokerSuspiciousSuccess(FoldedLinuxDirect):
    """A privilege broker granted an account another account (a) after refusing it, within WINDOW_SECONDS, for the
    same host, account and target; or (b) when the account is a web-service, system or application account (see
    account_class and app_risks for the lanes).

    Refusals and successes are both held per (host, account, target) in keyed stores (hot sets over the rule's disk
    spill, never forgotten), at most KEPT per key and only inside the window. A success reads the refusals before it;
    a refusal that arrives after a success it precedes (another partition or target read later) re-judges that success,
    so the result does not depend on the order partitions and targets are read. A success is re-reported only when its
    judgment changes."""
    version = "1"
    id = "host.privilege_broker_suspicious_success"
    title = ("A privilege broker let an account act as another account after refusing it, or let a service account "
             "act as another account")
    families = ("privilege_use",)
    required_fields = ("auth.service",)
    anchor_class = "privilege_escalation"
    severity, lane = "high", "high"
    attack = ("T1548", "T1548.003", "T1110.001", "T1078.003")
    benign = ("an administrator who mistyped the password once and then got it right (kept as a lead)",
              "a monitoring, CI or database account running its scheduled NOPASSWD sudo command (kept as a lead)",
              "an account added to sudoers minutes after a refused attempt, by its administrator")
    next_checks = ("what the account ran as the target account right after the success",
                   "how the account's rights changed between the refusal and the success (sudoers, group membership)",
                   ("for a service account: the process that ran sudo, su or pkexec, and the web request or job "
                    "behind it"))
    WINDOW_SECONDS = 900.0
    KEPT = 16
    GUESSING_ATTEMPTS = 3
    card: ClassVar[dict] = {
        "behavior": "sudo, su, runuser or pkexec logged a success letting an account act as another account, either "
                    "after it refused the same account and target within 15 minutes, or for a web-service, system or "
                    "application account",
        "telemetry": "privilege_use from the brokers' own lines in any Linux shipper shape: auth.service, user.name, "
                     "auth.target_user, outcome, privilege.denial_reason (failed attempts read from sudo's 'N "
                     "incorrect password attempts'), process.tty, sudo.command / privilege.command (caller text), "
                     "process.pid; log.identifier and log.writer name an unconfirmed or contradicted writer",
        "fidelity": "direct: the broker's own records of the refusal(s) and the success. They show the account was "
                    "let in, not what it did next",
        "benign_and_cost": "a single mistyped password then success is common, so it is a lead (one guess is not "
                           "guessing); monitoring, CI and database accounts run scheduled NOPASSWD sudo commands, so "
                           "their routine success is one folded lead per (host, account, target); a refusal line "
                           "journald shows another program wrote never raises the lane",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the target account's activity right after the success on the same host",
        "adds": "the refusal rule reports refusals; this rule reports the success that follows them, and broker "
                "success for accounts that should never use a broker",
        "research_basis": _RESEARCH + "sudoers(5) passwd_tries (3) and timestamp_timeout (5 minutes, 15 on some "
                          "distributions); pam_faillock deny (3); Debian base-passwd and Fedora setup system "
                          "accounts; ATT&CK Enterprise 20.0 T1548, T1548.003, T1110.001, T1078.003",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
        "window": "15 minutes: the longest default sudo credential cache (timestamp_timeout) and longer than a person "
                  "or script needs to retry; it comes from the tools' defaults, not from any one network's data",
        "accounts": "web-service accounts and system accounts that never use a broker (nobody, daemon, bin, sys, "
                    "mail, sshd, messagebus, systemd-*, ...): any success is high, because nothing legitimate runs "
                    "sudo, su or pkexec as them. Application, monitoring, CI and database accounts (nagios, zabbix, "
                    "jenkins, postgres, mysql, tomcat, prometheus, git, ...) are often granted one NOPASSWD command "
                    "their scheduled job runs without a terminal: a lead, high only when a terminal is present, the "
                    "command is a shell or interpreter or su, the command is missing or ambiguous, or refusals came "
                    "first - none of which a scheduled job shows",
        "lanes": "high: a web-service or never-broker account's success; an application account's success with a "
                 "terminal, a shell, interpreter or su command, a missing or ambiguous command, or after refusals; "
                 "any account's success after a policy refusal (not in sudoers, not authorized on the host, unknown "
                 "user) or after at least 3 failed password attempts (sudo's passwd_tries, pam_faillock's deny). "
                 "Lead: an application account's routine success; a success after fewer failed attempts; a success "
                 "whose only refusals are lines journald shows another program wrote. Never context",
    }

    def __init__(self):
        super().__init__()
        # (host, account, target) -> [(refusal event, its raw copies)], newest last
        self.refusals = KeyedStore(self, "broker_refusals", self.HOT)
        # (host, account, target) -> [(success event, its raw copies, its last reported judgment)], newest last
        self.successes = KeyedStore(self, "broker_successes", self.HOT)
        self._cited_raw: dict[str, dict] = {}       # raw copies of what a record's matches cite, for this batch

    @staticmethod
    def order(events):
        """Time order, a refusal before a success of the same instant."""
        return sorted(events, key=lambda e: (e.ts, e.outcome != Outcome.failure, e.id))

    def raw_of(self, event):
        return {**self._cited_raw.get(event.id, {}), **super().raw_of(event)}

    def consume(self, events):
        out = super().consume(self.order(events))
        self._cited_raw.clear()
        self.refusals.trim()
        self.successes.trim()
        return out

    def match_each(self, events, judged_ids):
        return super().match_each(self.order(events), judged_ids)

    def release_state(self):
        super().release_state()
        self.refusals.clear()
        self.successes.clear()

    def _held(self, store, key, when):
        return [item for item in store.get(key, []) if abs(when - item[0].ts.timestamp()) <= self.WINDOW_SECONDS]

    def _put(self, store, key, items) -> None:
        if not store.put(key, items[-self.KEPT:]):
            self.note_limit(store.name, f"the {store.name.replace('_', ' ')} store's disk budget is spent; later "
                                        "records are not held for the refusal-then-success join")

    def match(self, e):
        service = str(e.get("auth.service"))
        if service not in BROKERS or e.has("privilege.rejected_variable") or e.has("sudo.chunk"):
            return []
        actor, target = e.get("user.name"), e.get("auth.target_user")
        if actor in (None, "") or target in (None, ""):
            self.missing_required += 1
            return []
        key = (e.host, str(actor), str(target))
        when = e.ts.timestamp()
        if e.outcome == Outcome.failure:
            refusals = self._held(self.refusals, key, when) + [(e, super().raw_of(e))]
            self._put(self.refusals, key, refusals)
            # successes this refusal precedes, read earlier (another partition or target): judge them again
            out, successes = [], self._held(self.successes, key, when)
            for index, (success, raw, judged) in enumerate(successes):
                if not 0 <= success.ts.timestamp() - when <= self.WINDOW_SECONDS:
                    continue
                match = self._judge(success, raw, refusals, e)
                if match is not None and (match.group_key, match.proposed_lane) != judged:
                    successes[index] = (success, raw, (match.group_key, match.proposed_lane))
                    out.append(match)
            if out:
                self._put(self.successes, key, successes)
            return out
        if e.outcome != Outcome.success:
            self.missing_required += 1
            return []
        if actor == target:
            return []
        match = self._judge(e, super().raw_of(e), self._held(self.refusals, key, when), e)
        judged = (match.group_key, match.proposed_lane) if match is not None else None
        self._put(self.successes, key, self._held(self.successes, key, when) + [(e, super().raw_of(e), judged)])
        return [match] if match is not None else []

    def app_risks(self, success) -> list[str]:
        """What an application account's success shows that its scheduled job would not."""
        risks = []
        tty = success.get("process.tty")
        if isinstance(tty, str) and tty and tty.lower() not in NO_TTY:
            risks.append(f"it ran from terminal {tty}")
        service = str(success.get("auth.service"))
        command = success.get("sudo.command") if service == "sudo" else success.get("privilege.command")
        first = basename(str(command).split()[0]) if isinstance(command, str) and command.split() else ""
        if service in ("su", "runuser"):
            risks.append(f"it used {service} to become the account")
        elif not first:
            risks.append("the command is not recorded")
        elif first in INTERPRETERS or first in ("su", "sudo"):
            risks.append(f"the command is {first!r}, a shell, interpreter or account switch")
        if any(caveat in success.caveats for caveat in (SUDO_AMBIGUOUS_CAVEAT, PKEXEC_AMBIGUOUS_CAVEAT)):
            risks.append("the command text is ambiguous")
        return risks

    def _judge(self, success, success_raw, held_refusals, reading):
        """The finding for a success given the refusals held for its key (None when it is not one). `reading` is the
        record being consumed: the match's raw copies are filed under it."""
        when = success.ts.timestamp()
        kept = [(r, raw) for r, raw in held_refusals if 0 <= when - r.ts.timestamp() <= self.WINDOW_SECONDS]
        before = [r for r, _raw in kept]
        actor, target, service = str(success.get("user.name")), str(success.get("auth.target_user")), \
            str(success.get("auth.service"))
        kind = account_class(actor)
        counted = [r for r in before if writer_state(r) != "mismatch"]
        forged = len(before) - len(counted)
        attempts = sum(refusal_weight(r)[0] for r in counted)
        policy = any(refusal_weight(r)[1] for r in counted)
        risks = self.app_risks(success) if kind == "app" else []
        if kind in ("web", "never"):
            high, shape = True, "service"
        elif kind == "app":
            high, shape = bool(risks or counted), "app-risk" if risks or counted else "app-routine"
        elif before:
            high = policy or attempts >= self.GUESSING_ATTEMPTS
            shape = "policy" if policy else "guessing" if high else "retry"
        else:
            return None
        subject = line_subject(success, service)
        said = f"{subject} says that {service} let" if subject else f"{service} logged that it let"
        claim = f"On {success.host}, {said} {_quote(actor)} act as {_quote(target)}."
        if before:
            reasons = sorted({str(r.get("privilege.denial_reason") or "refused") for r in before})
            claim += (f" In the {self.WINDOW_SECONDS / 60:.0f} minutes before, the broker(s) refused the same account "
                      f"and target {len(before)} time(s) ({'; '.join(reasons[:4])}"
                      + (f"; and {len(reasons) - 4} more" if len(reasons) > 4 else "")
                      + f"), {attempts} counted failed password attempt(s)"
                      + (", including a refusal of the account's right to it" if policy else "") + ".")
            if forged:
                claim += (f" {forged} of those refusal line(s) journald shows another program wrote; they are not "
                          "counted toward the lane.")
            claim += writer_sentence([r for r in before if writer_state(r) == "unverified"], _identifier).replace(
                "The record(s) are", "The refusal record(s) are")
            if kind == "user" and not high:
                claim += (" Fewer than 3 counted failed attempts and no policy refusal: a mistyped password looks like "
                          "this." if counted else "")
        if kind == "web":
            claim += (f" {_quote(actor)} is a web-service account, which does not log in to type a password: a web "
                      "process, or code running as it, asked to act as another account.")
        elif kind == "never":
            claim += f" {_quote(actor)} is a system account that never legitimately uses a privilege broker."
        elif kind == "app":
            claim += (f" {_quote(actor)} is an application, monitoring, CI or database account; "
                      + ("its success stands out because " + "; ".join(risks) + "." if risks else
                         "refusals came first." if counted else
                         "a scheduled job's NOPASSWD sudo command looks like this (no terminal, no shell)."))
        lane = "high" if high else "lead"
        cited = sorted([*before[-5:], success], key=lambda x: (x.ts, x.id))
        self._cited_raw.setdefault(reading.id, {}).update(
            {k: v for raw in [success_raw, *(raw for _r, raw in kept[-5:])] for k, v in raw.items()})
        return Match(self.id, claim, self.claim_type, cited,
                     [pf(x, name) for x in cited for name in (*_FIELDS, "log.identifier", "log.writer") if x.has(name)],
                     success.ts, "high" if high else "medium", lane, "high", success.entities(),
                     group_key=json.dumps([success.host, actor, target, shape, lane, writer_state(success)]))


PRIVILEGE_BROKER_RULES = [PrivilegeBrokerRefusal, PkexecEnvironmentRejection, PrivilegeBrokerSuspiciousSuccess]
