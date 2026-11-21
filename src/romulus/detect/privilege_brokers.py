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
from typing import ClassVar

from romulus.detect.host import WEB_SERVICE_USERS
from romulus.detect.linux_direct import FoldedLinuxDirect, observed
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
        claim = (f"On {e.host}, {service} logged that it refused {_quote(actor)} acting as {_quote(target)}"
                 + (f" ({reason})" if reason else "") + ".")
        if web:
            claim += " The refused account is a web-service account, which does not normally ask for another account."
        return [observed(self, e, claim, "lead",
                         group=json.dumps([e.host, service, actor, target, reason, web]), names=_FIELDS)]


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
        claim = (f"On {e.host}, pkexec run by {_quote(actor)} to act as {_quote(target)} rejected the value of "
                 f"{variable} ({e.get('privilege.denial_reason')}). CVE-2021-4034 exploitation leaves exactly this "
                 "record; whether an exploit payload ran is not shown by it.")
        return [observed(self, e, claim, "high", group=json.dumps([e.host, actor, variable]), names=_FIELDS)]


PRIVILEGE_BROKER_RULES = [PrivilegeBrokerRefusal, PkexecEnvironmentRejection]
