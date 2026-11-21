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

from romulus.detect.base import Match, pf
from romulus.detect.bounded import KeyedStore
from romulus.detect.host import WEB_SERVICE_USERS
from romulus.detect.linux_direct import FoldedLinuxDirect, observed
from romulus.detect.log_writer import line_subject, writer_state
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


# Accounts that never log in to type a password: the web-service accounts and the system accounts Debian's
# base-passwd and Fedora's setup package create without a login shell, plus the service accounts common daemons
# install. A privilege broker granting one of them another account is a service process (or code running as it)
# asking to become someone else.
SERVICE_ACCOUNTS = frozenset(WEB_SERVICE_USERS | {
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "backup", "list", "irc",
    "gnats", "nobody", "nfsnobody", "ftp", "named", "bind", "dnsmasq", "squid", "postfix", "dovecot", "mysql",
    "postgres", "redis", "mongodb", "tomcat", "tomcat9", "jetty", "jenkins", "git", "memcached", "rabbitmq",
    "elasticsearch", "kibana", "grafana", "prometheus", "zabbix", "nagios", "tss", "polkitd", "messagebus",
    "systemd-network", "systemd-resolve", "systemd-timesync", "sshd", "_apt", "syslog"})
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


class PrivilegeBrokerSuspiciousSuccess(FoldedLinuxDirect):
    """A privilege broker granted an account another account (a) after refusing it, within WINDOW_SECONDS, for the
    same host, account and target; or (b) when the account is a web-service or system service account.

    Refusals are held per (host, account, target) in a keyed store (hot set over the rule's disk spill, never
    forgotten), at most REFUSALS_KEPT per key and only those inside the window; a success reads them back."""
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
              "a deployment that grants a service account sudo for one script (poor practice, still worth a look)",
              "an account added to sudoers minutes after a refused attempt, by its administrator")
    next_checks = ("what the account ran as the target account right after the success",
                   "how the account's rights changed between the refusal and the success (sudoers, group membership)",
                   ("for a service account: the process that ran sudo, su or pkexec, and the web request or job "
                    "behind it"))
    WINDOW_SECONDS = 900.0
    REFUSALS_KEPT = 16
    GUESSING_ATTEMPTS = 3
    card: ClassVar[dict] = {
        "behavior": "sudo, su, runuser or pkexec logged a success letting an account act as another account, either "
                    "after it refused the same account and target within 15 minutes, or for a web-service or "
                    "system service account",
        "telemetry": "privilege_use from the brokers' own lines in any Linux shipper shape: auth.service, user.name, "
                     "auth.target_user, outcome, privilege.denial_reason (failed attempts read from sudo's 'N "
                     "incorrect password attempts'), process.pid; log.identifier and log.writer name an unconfirmed "
                     "or contradicted writer",
        "fidelity": "direct: the broker's own records of the refusal(s) and the success. They show the account was "
                    "let in, not what it did next",
        "benign_and_cost": "a single mistyped password then success is common, so it is a lead (one guess is not "
                           "guessing); service accounts with sudo for one script are rare and cheap to check; one "
                           "folded finding per (host, account, target, shape)",
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
        "lanes": "high for a service account's success, for a success after a policy refusal (not in sudoers, not "
                 "authorized on the host, unknown user: the account's rights changed within minutes), or after at "
                 "least 3 failed password attempts (sudo's passwd_tries, pam_faillock's deny); lead for a success "
                 "after fewer failed password attempts. Never context",
    }

    def __init__(self):
        super().__init__()
        # (host, account, target) -> [(refusal event, its raw copies)], newest last
        self.refusals = KeyedStore(self, "broker_refusals", self.HOT)
        self._cited_raw: dict[str, dict] = {}       # a success's refusals' raw copies, until consume reads them

    def raw_of(self, event):
        return {**self._cited_raw.pop(event.id, {}), **super().raw_of(event)}

    def consume(self, events):
        out = super().consume(sorted(events, key=lambda e: (e.ts, e.id)))
        self.refusals.trim()
        return out

    def release_state(self):
        super().release_state()
        self.refusals.clear()

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
            held = [(r, raw) for r, raw in self.refusals.get(key, []) if when - r.ts.timestamp() <= self.WINDOW_SECONDS]
            held = (held + [(e, super().raw_of(e))])[-self.REFUSALS_KEPT:]
            if not self.refusals.put(key, held):
                self.note_limit("broker_refusals", "the refusal store's disk budget is spent; later refusals are "
                                                   "not held for a success to follow")
            return []
        if e.outcome != Outcome.success or actor == target:
            return [] if e.outcome == Outcome.success else self._unknown()
        kept = [(r, raw) for r, raw in self.refusals.get(key, []) if 0 <= when - r.ts.timestamp() <= self.WINDOW_SECONDS]
        before = [r for r, _raw in kept]
        service_account = str(actor) in SERVICE_ACCOUNTS
        if not before and not service_account:
            return []
        attempts = sum(refusal_weight(r)[0] for r in before)
        policy = any(refusal_weight(r)[1] for r in before)
        high = service_account or policy or attempts >= self.GUESSING_ATTEMPTS
        subject = line_subject(e, service)
        said = f"{subject} says that {service} let" if subject else f"{service} logged that it let"
        claim = f"On {e.host}, {said} {_quote(actor)} act as {_quote(target)}."
        if before:
            reasons = sorted({str(r.get("privilege.denial_reason") or "refused") for r in before})
            claim += (f" In the {self.WINDOW_SECONDS / 60:.0f} minutes before, the broker(s) refused the same account "
                      f"and target {len(before)} time(s) ({'; '.join(reasons[:4])}"
                      + (f"; and {len(reasons) - 4} more" if len(reasons) > 4 else "")
                      + f"), {attempts} failed password attempt(s) in all"
                      + (", including a refusal of the account's right to it" if policy else "") + ".")
            if not high:
                claim += " Fewer than 3 failed attempts: a mistyped password looks like this."
        if service_account:
            claim += (f" {_quote(actor)} is a web-service or system service account, which does not log in to type a "
                      "password: a service process, or code running as it, asked to act as another account.")
        lane = "high" if high else "lead"
        shape = "service" if service_account else "policy" if policy else "guessing" if high else "retry"
        cited = sorted([*before[-5:], e], key=lambda x: (x.ts, x.id))
        self._cited_raw[e.id] = {k: v for _r, raw in kept[-5:] for k, v in raw.items()}
        match = Match(self.id, claim, self.claim_type, cited,
                      [pf(x, name) for x in cited for name in (*_FIELDS, "log.identifier", "log.writer")
                       if x.has(name)],
                      e.ts, "high" if high else "medium", lane, "high", e.entities(),
                      group_key=json.dumps([e.host, actor, target, shape, writer_state(e)]))
        return [match]

    def _unknown(self) -> list:
        self.missing_required += 1
        return []


PRIVILEGE_BROKER_RULES = [PrivilegeBrokerRefusal, PkexecEnvironmentRejection, PrivilegeBrokerSuspiciousSuccess]
