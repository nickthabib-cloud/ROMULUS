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

import itertools
import json
import math
import re
from typing import ClassVar

from romulus.detect.base import Match, basename, pf
from romulus.detect.bounded import KeyedStore
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS
from romulus.detect.linux_argv import PATTERN_READERS, PLAIN_READERS, normalize_path, read_operand_paths
from romulus.detect.linux_direct import FoldedLinuxDirect, observed
from romulus.detect.linux_semantics import classify_credential
from romulus.detect.log_writer import line_subject, writer_sentence, writer_state
from romulus.detect.packets import show
from romulus.evidence.linux_service_text import PKEXEC_AMBIGUOUS_CAVEAT
from romulus.evidence.linux_text_types import SUDO_AMBIGUOUS_CAVEAT
from romulus.evidence.shellparse import SHELLS, classify_redirect, parse_script
from romulus.evidence.typed import Outcome
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

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


# Who asked (account_class). Web-service accounts, system accounts Debian's base-passwd and Fedora's setup package
# create without a login shell, and network daemons' accounts never legitimately ask a broker for another account:
# any success is high. Application, monitoring and database accounts, and automation accounts, often hold narrow
# NOPASSWD sudo rules their scheduled jobs or deployments use: their success is a lead, raised only by what such a job
# does not show (PrivilegeBrokerSuspiciousSuccess.risks).
NEVER_BROKER_ACCOUNTS = frozenset({
    "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "backup", "list",
    "irc", "gnats", "nfsnobody", "_apt", "messagebus", "sshd", "syslog", "polkitd", "tss"})
# Exploitable network daemons that do not normally hold sudo rules.
DAEMON_ACCOUNTS = frozenset({
    "named", "bind", "dnsmasq", "squid", "postfix", "dovecot", "ftp", "redis", "memcached", "mongodb",
    "elasticsearch", "rabbitmq", "kibana"})
# Monitoring, database and application-server accounts: a check or maintenance command, without a terminal.
APP_ACCOUNTS = frozenset({
    "nagios", "icinga", "zabbix", "prometheus", "telegraf", "grafana", "postgres", "mysql", "mariadb", "tomcat",
    "tomcat9", "jetty", "git"})
# Configuration management and CI accounts: they run shell scripts as root by design (Ansible's become wraps every
# task in `sh -c 'echo BECOME-SUCCESS-<id> ; <module>'`), often from a pseudo-terminal.
AUTOMATION_ACCOUNTS = frozenset({"ansible", "jenkins", "gitlab-runner", "puppet", "chef", "salt"})
NO_TTY = frozenset({"unknown", "none", "(none)", "notty", "?"})
# GTFOBins (https://gtfobins.github.io/, functions "sudo" and "shell"): programs a sudo rule can allow that let the
# caller start a shell (a pager, editor, -exec, a command option, a write over a file root runs).
SHELL_ESCAPE_PROGRAMS = frozenset({
    "find", "vi", "vim", "view", "rvim", "nvim", "ex", "ed", "nano", "pico", "emacs", "less", "more", "most", "man",
    "awk", "gawk", "mawk", "nawk", "env", "xargs", "tar", "zip", "unzip", "cpio", "rsync", "ssh", "scp", "sftp", "git",
    "systemctl", "journalctl", "nmap", "tee", "cp", "mv", "dd", "install", "chmod", "chown", "sed", "perl", "ruby",
    "lua", "php", "node", "nodejs", "gdb", "strace", "ltrace", "script", "expect", "tclsh", "wish", "socat", "nc",
    "ncat", "netcat", "time", "timeout", "nohup", "nice", "watch", "flock", "taskset", "busybox", "docker", "make",
    "crontab", "apt", "apt-get", "yum", "dnf", "pip", "pip3", "openssl", "curl", "wget", "sqlite3", "psql", "mysql",
    "ftp", "zsh", "csh", "tcsh", "ksh", "dash", "bash", "sh"})
# systemctl and journalctl escape only through their pager, which needs a terminal: a plain subcommand on named
# units without one is a routine service action.
SYSTEMCTL_PLAIN = frozenset({"start", "stop", "restart", "reload", "status", "try-restart", "reload-or-restart",
                             "is-active", "is-enabled", "is-failed", "enable", "disable", "show"})
QUIET_OPTIONS = frozenset({"--no-pager", "-q", "--quiet", "--now", "--no-block"})


def account_class(actor: str) -> str:
    """'web', 'never' (a system account that never uses a broker), 'daemon', 'app', 'automation' or 'user'."""
    if actor in WEB_SERVICE_USERS:
        return "web"
    if actor in NEVER_BROKER_ACCOUNTS or actor.startswith("systemd-"):
        return "never"
    if actor in DAEMON_ACCOUNTS:
        return "daemon"
    if actor in AUTOMATION_ACCOUNTS:
        return "automation"
    return "app" if actor in APP_ACCOUNTS else "user"


def _shellish(name: str) -> bool:
    return name in INTERPRETERS or name.startswith("python")


# Separators of the statements in a `sh -c` script as sudo logs it (words split on spaces).
_SCRIPT_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
_NETCAT = frozenset({"nc", "ncat", "netcat"})


def script_risks(script: list[str]) -> list[str]:
    """What a `sh -c` script run as root shows that a deployment script does not: a statement that is a bare shell or
    interpreter, a shell with -i, or a reverse-shell form (nc/ncat -e, socat exec:)."""
    risks: list[str] = []
    statement: list[str] = []
    for word in [*script, ";"]:
        if word not in _SCRIPT_SEPARATORS and not word.endswith(";"):
            statement.append(word)
            continue
        if word.endswith(";") and word != ";":
            statement.append(word[:-1])
        if statement:
            first, rest = basename(statement[0]), statement[1:]
            if _shellish(first) and ("-i" in rest or not any(not arg.startswith("-") for arg in rest)):
                risks.append(f"its script starts an interactive {first!r}")
            elif first in _NETCAT and any(arg in ("-e", "-c", "--exec", "--sh-exec")
                                          or (arg.startswith("-") and not arg.startswith("--") and "e" in arg[1:])
                                          for arg in rest):
                risks.append(f"its script runs {first!r} with a command to execute (a reverse-shell form)")
            elif first == "socat" and any(arg.lower().startswith(("exec:", "system:")) for arg in rest):
                risks.append("its script runs socat with exec: (a reverse-shell form)")
        statement = []
    return risks


def ansible_module_run(words: list[str], account: str) -> bool:
    """Ansible's become wrapper: the BECOME-SUCCESS marker, and a module under the account's ~/.ansible/tmp
    (remote_tmp's default, ~/.ansible/tmp/ansible-tmp-<id>/)."""
    marker = any(word.startswith("BECOME-SUCCESS-") for word in words)
    module = any(re.search(rf"^(?:~|/home/{re.escape(account)}|/var/lib/{re.escape(account)})"
                           r"/\.ansible/tmp/ansible-tmp-[^/\s]+/", word) for word in words)
    return marker and module


def _plain_service_action(program_name: str, args: list[str]) -> bool:
    if program_name == "systemctl":
        return (bool(args) and args[0] in SYSTEMCTL_PLAIN
                and all(not arg.startswith("-") or arg in QUIET_OPTIONS for arg in args[1:]))
    return program_name == "journalctl" and all(arg not in ("-e", "--pager-end") for arg in args)


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


def _held_success(event) -> bytes:
    """A held success: its whole typed event (every field with its provenance, its native reference and digest),
    compressed, without its raw copy. A re-judged success is cited from this, marked compact, and its raw body is
    fetched by native reference at publication."""
    return compact_event(event)


class PrivilegeBrokerSuspiciousSuccess(FoldedLinuxDirect):
    """A privilege broker granted an account another account (a) after refusing it, within WINDOW_SECONDS, for the
    same host, account and target; or (b) for a web-service, system, daemon, application or automation account (see
    account_class and risks for the lanes).

    Refusals and successes are both held per (host, account, target) in keyed stores (hot sets over the rule's disk
    spill), at most KEPT per key and only inside the window; a success is held compact (the fields it is judged on and
    its native reference, no raw copy). A success reads the refusals before it; a refusal that arrives after a success
    it precedes (a later partition or target) judges that success again, so the result does not depend on the order
    records are read. A success is reported again only when its judgment changes. Held rows are pruned by time across
    every key (prune), not only when a key is read again."""
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
              "a monitoring, database or automation account running its NOPASSWD command or script (kept as a lead)",
              "an account added to sudoers minutes after a refused attempt, by its administrator")
    next_checks = ("what the account ran as the target account right after the success",
                   "how the account's rights changed between the refusal and the success (sudoers, group membership)",
                   ("for a service account: the process that ran sudo, su or pkexec, and the web request or job "
                    "behind it"))
    WINDOW_SECONDS = 900.0
    # Held rows older than every relevant target's progress minus the window and this margin are pruned. Within one
    # target the sweep reads partitions in time order; the margin covers records of one partition delivered out of
    # time order and host clocks behind the pipeline time. A target not yet read holds the horizon at its start.
    PRUNE_MARGIN_SECONDS = 900.0
    BUCKET_SECONDS = 300
    KEPT = 16
    GUESSING_ATTEMPTS = 3
    card: ClassVar[dict] = {
        "behavior": "sudo, su, runuser or pkexec logged a success letting an account act as another account, either "
                    "after it refused the same account and target within 15 minutes, or for a web-service, system, "
                    "network-daemon, application or automation account",
        "telemetry": "privilege_use from the brokers' own lines in any Linux shipper shape: auth.service, user.name, "
                     "auth.target_user, outcome, privilege.denial_reason (failed attempts read from sudo's 'N "
                     "incorrect password attempts'), process.tty, sudo.command / privilege.command (caller text, split "
                     "on spaces as sudo logs it), process.pid; log.identifier and log.writer name an unconfirmed or "
                     "contradicted writer",
        "fidelity": "direct: the broker's own records of the refusal(s) and the success. They show the account was "
                    "let in, not what it did next",
        "benign_and_cost": "a single mistyped password then success is common, so it is a lead (one guess is not "
                           "guessing); monitoring, database and automation accounts run NOPASSWD commands and scripts, "
                           "so their routine success is one folded lead per (host, account, target); a refusal line "
                           "journald shows another program wrote never raises the lane",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the target account's activity right after the success on the same host",
        "adds": "the refusal rule reports refusals; this rule reports the success that follows them, and broker "
                "success for accounts that should never use a broker",
        "research_basis": _RESEARCH + "sudoers(5) passwd_tries (3) and timestamp_timeout (5 minutes, 15 on some "
                          "distributions); pam_faillock deny (3); Debian base-passwd and Fedora setup system "
                          "accounts; GTFOBins (https://gtfobins.github.io/) sudo and shell functions for the "
                          "shell-escape programs; Ansible's become wrapper (BECOME-SUCCESS marker); ATT&CK Enterprise "
                          "20.0 T1548, T1548.003, T1110.001, T1078.003",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
        "window": "15 minutes: the longest default sudo credential cache (timestamp_timeout) and longer than a person "
                  "or script needs to retry; it comes from the tools' defaults, not from any one network's data",
        "accounts": "web-service accounts, system accounts that never use a broker (nobody, daemon, bin, sys, mail, "
                    "sshd, messagebus, systemd-*, ...) and network daemons' accounts (named, bind, dnsmasq, squid, "
                    "postfix, dovecot, ftp, redis, memcached, mongodb, elasticsearch, rabbitmq, kibana: exploitable "
                    "network services that do not normally hold sudo rules): any success is high. Monitoring, "
                    "database and application-server accounts (nagios, icinga, zabbix, prometheus, telegraf, grafana, "
                    "postgres, mysql, mariadb, tomcat, jetty, git) hold one NOPASSWD command a scheduled job runs "
                    "without a terminal: a lead, high with a terminal, a shell or interpreter command, su or sudo, an "
                    "argument that is a shell or interpreter, a GTFOBins shell-escape program, a missing or ambiguous "
                    "command, or refusals first. Automation accounts (ansible, jenkins, gitlab-runner, puppet, chef, "
                    "salt) run shell scripts as root by design, often from a pseudo-terminal (Ansible's 'sh -c echo "
                    "BECOME-SUCCESS-<id> ; <module>', routine only with the marker and a module under the account's "
                    "~/.ansible/tmp): a non-interactive 'sh -c <script>' or '<shell> <script-file>' is a lead; high "
                    "when the script starts a bare or -i shell or interpreter, opens /dev/tcp or /dev/udp, or holds a "
                    "reverse-shell form (nc/ncat -e, socat exec:), for a bare interactive shell or interpreter, su or "
                    "sudo, an argument that is a "
                    "shell or interpreter, a shell-escape program, a missing or ambiguous command, or refusals first. "
                    "systemctl and journalctl escape only through a pager, so a plain subcommand on named units "
                    "without a terminal stays a lead",
        "lanes": "high: a web-service, never-broker or network-daemon account's success; an application or "
                 "automation account's success with what its routine job never shows (see accounts); any account's "
                 "success after a policy refusal (not in sudoers, not authorized on the host, unknown user) or after "
                 "at least 3 failed password attempts (sudo's passwd_tries, pam_faillock's deny). Lead: an application "
                 "or automation account's routine success; a success after fewer failed attempts; a success whose only "
                 "refusals are lines journald shows another program wrote. Never context. A lead whose success a later "
                 "refusal raised to high is revised with a note naming the high finding (both stay)",
        "state": "refusals with their raw copies, and successes as their whole typed event compressed without a raw "
                 "copy (fetched by native reference when a late refusal cites one), per (host, account, target), at "
                 "most 16 each and only inside the window, in keyed stores over the rule's disk spill; rows are "
                 "pruned across every key once every Linux-capable target has read past them by the window plus 15 "
                 "minutes (a network-only target never holds them); a record read after rows of its time were pruned "
                 "is still judged and makes the window partial",
    }

    def __init__(self):
        super().__init__()
        # (host, account, target) -> [(refusal event, its raw copies)], newest last
        self.refusals = KeyedStore(self, "broker_refusals", self.HOT)
        # (host, account, target) -> [(compact success, its time, its last reported (group key, lane))], newest last
        self.successes = KeyedStore(self, "broker_successes", self.HOT)
        # time bucket -> keys holding rows of that bucket, for pruning across every key
        self.buckets = KeyedStore(self, "broker_buckets", self.HOT)
        self._oldest_bucket: int | None = None
        self._pruned_before = float("-inf")           # rows older than this may have been pruned
        self._progress: dict[str | None, float] = {}    # per source target: the newest record time read
        self._done: set[str | None] = set()              # targets the sweep finished reading
        self._current: str | None = None
        self._cited_raw: dict[str, dict] = {}       # raw copies of what a record's matches cite, for this batch
        self._superseded: dict[str, str] = {}       # lead fold key -> the high finding that raised one of its successes

    @staticmethod
    def order(events):
        """Time order, a refusal before a success of the same instant."""
        return sorted(events, key=lambda e: (e.ts, e.outcome != Outcome.failure, e.id))

    def raw_of(self, event):
        return {**self._cited_raw.get(event.id, {}), **super().raw_of(event)}

    def consume(self, events):
        target = self.raw_target()
        if target != self._current:
            if self._current in self._progress:
                self._done.add(self._current)       # the sweep reads one target to its end before the next
            self._current = target
            self._done.discard(target)
        self._progress.setdefault(target, float("-inf"))
        if events:
            self._progress[target] = max(self._progress[target], max(e.ts.timestamp() for e in events))
        out = super().consume(self.order(events))
        out += self._revise_superseded()
        self._cited_raw.clear()
        self.prune()
        self.refusals.trim()
        self.successes.trim()
        self.buckets.trim()
        return out

    def match_each(self, events, judged_ids):
        return super().match_each(self.order(events), judged_ids)

    def release_state(self):
        super().release_state()
        for store in (self.refusals, self.successes, self.buckets):
            store.clear()

    # ------------------------------------------------------------------------------------------------- held rows
    def horizon(self) -> float:
        """Rows older than this are needed by no record still to be read: every relevant target that is not finished
        has read past it by the window plus the margin. A planned target not yet read holds it at the hunt's start.
        Only targets that can hold broker lines count (the sweep's linux_host_targets: a Linux target, or one mixing
        Linux text); a network-only target never holds the horizon."""
        planned = getattr(self, "linux_host_targets", None)
        relevant = list(planned) if planned is not None else list(self._progress)
        # every relevant target read: nothing older than the newest of them, less the window, is needed
        pending = [t for t in relevant if t not in self._done] or relevant
        reached = min((self._progress.get(t, float("-inf")) for t in pending), default=float("-inf"))
        return reached - self.WINDOW_SECONDS - self.PRUNE_MARGIN_SECONDS

    def _index(self, key, when: float) -> None:
        bucket = int(when // self.BUCKET_SECONDS)
        held = self.buckets.get(bucket, None)
        if held is None or key not in held:
            self._put(self.buckets, bucket, {*(held or ()), key}, cap=None)
        self._oldest_bucket = bucket if self._oldest_bucket is None else min(self._oldest_bucket, bucket)

    def prune(self) -> int:
        """Drop held rows older than the horizon from every key whose rows fall in an expired time bucket."""
        limit = self.horizon()
        if self._oldest_bucket is None or not math.isfinite(limit):
            return 0
        last = int(limit // self.BUCKET_SECONDS)          # buckets before this one hold only expired rows
        dropped = 0
        bucket = self._oldest_bucket
        while bucket < last:
            for key in self.buckets.pop(bucket, None) or []:
                for store in (self.refusals, self.successes):
                    rows = store.get(key)
                    if not rows:
                        continue
                    kept = [row for row in rows if self._row_time(row) >= limit]
                    dropped += len(rows) - len(kept)
                    if kept:
                        store.put(key, kept)
                    else:
                        store.pop(key, None)
            bucket += 1
        self._oldest_bucket = last
        self._pruned_before = max(self._pruned_before, limit)
        return dropped

    @staticmethod
    def _row_time(row) -> float:
        return row[1] if isinstance(row[1], float) else row[0].ts.timestamp()

    def _held(self, store, key, when):
        return [row for row in store.get(key, []) if abs(when - self._row_time(row)) <= self.WINDOW_SECONDS]

    def _put(self, store, key, items, cap: int | None = KEPT) -> None:
        if not store.put(key, items[-cap:] if cap and isinstance(items, list) else items):
            self.note_limit(store.name, f"the {store.name.replace('_', ' ')} store's disk budget is spent; later "
                                        "records are not held for the refusal-then-success join")

    # ------------------------------------------------------------------------------------------------- judging
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
        if when < self._pruned_before:
            # read after rows of its time were pruned (a target or partition out of the expected order): it is still
            # judged, but a refusal or success it would have joined may be gone
            self.note_limit("late_record", "a broker record older than the pruning horizon was read after rows of "
                                           "its time were pruned; a refusal or success it would join may be missing",
                            records=0)
        if e.outcome == Outcome.failure:
            refusals = self._held(self.refusals, key, when) + [(e, super().raw_of(e))]
            self._put(self.refusals, key, refusals)
            self._index(key, when)
            # successes this refusal precedes, read earlier (another partition or target): judge them again
            out, successes = [], self._held(self.successes, key, when)
            for index, (blob, at, judged) in enumerate(successes):
                if not 0 <= at - when <= self.WINDOW_SECONDS:
                    continue
                success = expand_event(blob)
                success = success.model_copy(update={"caveats": [*success.caveats, COMPACT_CITATION_NOTE]})
                match = self._judge(success, {}, refusals, e)
                now = (match.group_key, match.proposed_lane) if match is not None else None
                if match is not None and now != (tuple(judged) if judged else None):
                    if judged and judged[1] == "lead" and match.proposed_lane == "high":
                        self._superseded[judged[0]] = match.group_key
                    successes[index] = (blob, at, now)
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
        self._put(self.successes, key, self._held(self.successes, key, when) + [(_held_success(e), when, judged)])
        self._index(key, when)
        return [match] if match is not None else []

    def _revise_superseded(self) -> list:
        """A lead fold one of whose successes a later refusal raised to high: the candidate store keeps a fold's
        count, so the lead stays, revised with a note naming the high finding."""
        out = []
        for lead_key, high_key in self._superseded.items():
            state = self.folds.get(lead_key)
            if state is None or not state.published:
                continue
            host, actor, target = json.loads(high_key)[:3]
            note = (f"At least one success in this lead was raised to high by refusals read afterwards; see the "
                    f"{self.id} high finding for {actor!r} acting as {target!r} on {host}.")
            for witness in (state.first, state.last):
                if note not in witness.notes:
                    witness.notes.append(note)
            out.append(self.fold_publication(lead_key, state, "A success in this group was raised to high."))
        self._superseded.clear()
        return out

    def risks(self, success, kind: str, counted: bool) -> list[str]:
        """What an application or automation account's success shows that its routine job does not."""
        risks = []
        tty = success.get("process.tty")
        on_tty = isinstance(tty, str) and bool(tty) and tty.lower() not in NO_TTY
        if counted:
            risks.append("refusals came first")
        service = str(success.get("auth.service"))
        if service in ("su", "runuser"):
            return [*risks, f"it used {service} to become the account"]
        if any(caveat in success.caveats for caveat in (SUDO_AMBIGUOUS_CAVEAT, PKEXEC_AMBIGUOUS_CAVEAT)):
            risks.append("the command text is ambiguous")
        command = success.get("sudo.command") if service == "sudo" else success.get("privilege.command")
        words = str(command).split() if isinstance(command, str) else []
        if not words:
            return [*risks, "the command is not recorded"]
        name, args = basename(words[0]), words[1:]
        if kind == "app" and on_tty:
            risks.append(f"it ran from terminal {tty}")
        if socket := next((word for word in words if "/dev/tcp/" in word or "/dev/udp/" in word), None):
            risks.append(f"the command opens a network socket through the shell ({socket!r})")
        if name in ("su", "sudo"):
            risks.append(f"the command is {name!r}, an account switch")
        elif _shellish(name):
            bare = "-c" not in args and not any(not arg.startswith("-") for arg in args)
            if kind == "app":
                risks.append(f"the command is {name!r}, a shell or interpreter")
            elif bare:
                risks.append(f"the command is a bare interactive {name!r}"
                             + (f" from terminal {tty}" if on_tty else ""))
            else:
                script = args[args.index("-c") + 1:] if "-c" in args else []
                risks += script_risks(script)
                if str(success.get("user.name")) == "ansible" and not ansible_module_run(words, "ansible"):
                    risks.append("it is not Ansible's become wrapper (no BECOME-SUCCESS marker with a module under "
                                 "the account's ~/.ansible/tmp)")
        else:
            shells = [arg for arg in args if _shellish(basename(arg))]
            if shells:
                risks.append(f"an argument is a shell or interpreter ({shells[0]!r})")
            if name in SHELL_ESCAPE_PROGRAMS and not (not on_tty and _plain_service_action(name, args)):
                risks.append(f"{name!r} can start a shell (GTFOBins)"
                             + (" through its pager on a terminal" if name in ("systemctl", "journalctl") else ""))
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
        risks = self.risks(success, kind, bool(counted)) if kind in ("app", "automation") else []
        if kind in ("web", "never", "daemon"):
            high, shape = True, "service"
        elif kind in ("app", "automation"):
            high, shape = bool(risks), f"{kind}-risk" if risks else f"{kind}-routine"
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
            if kind == "user" and not high and counted:
                claim += (" Fewer than 3 counted failed attempts and no policy refusal: a mistyped password looks like "
                          "this.")
        if kind == "web":
            claim += (f" {_quote(actor)} is a web-service account, which does not log in to type a password: a web "
                      "process, or code running as it, asked to act as another account.")
        elif kind == "never":
            claim += f" {_quote(actor)} is a system account that never legitimately uses a privilege broker."
        elif kind == "daemon":
            claim += (f" {_quote(actor)} is a network daemon's account, which does not normally hold sudo rules: the "
                      "daemon, or code running as it, asked to act as another account.")
        elif kind == "app":
            claim += (f" {_quote(actor)} is a monitoring, database or application-server account; "
                      + ("its success stands out because " + "; ".join(risks) + "." if risks else
                         "a scheduled job's NOPASSWD sudo command looks like this (no terminal, no shell, no "
                         "shell-escape program)."))
        elif kind == "automation":
            routine = ("Ansible's become wrapper (BECOME-SUCCESS marker)"
                       if "BECOME-SUCCESS-" in str(success.get("sudo.command") or "") else "a deployment or job script")
            claim += (f" {_quote(actor)} is a configuration-management or CI account; "
                      + ("its success stands out because " + "; ".join(risks) + "." if risks else
                         f"{routine} run non-interactively as root looks like this."))
        lane = "high" if high else "lead"
        cited = sorted([*before[-5:], success], key=lambda x: (x.ts, x.id))
        self._cited_raw.setdefault(reading.id, {}).update(
            {k: v for raw in [success_raw, *(raw for _r, raw in kept[-5:])] for k, v in raw.items()})
        return Match(self.id, claim, self.claim_type, cited,
                     [pf(x, name) for x in cited for name in (*_FIELDS, "log.identifier", "log.writer") if x.has(name)],
                     success.ts, "high" if high else "medium", lane, "high", success.entities(),
                     group_key=json.dumps([success.host, actor, target, shape, lane, writer_state(success)]))


# ---- credential stores named in a broker's logged command -------------------------------------------------------
# Programs that open the files they are given and show their contents: the plain and pattern readers the argv parser
# places operands for (cp's destination excluded), and further readers and editors whose every non-option operand is a
# file they read. Programs that can also write an operand (tee, install, rsync, tar, curl -o, openssl -out) are never
# taken to read one: their credential operands are 'named'.
_PLACED_READERS = PLAIN_READERS | PATTERN_READERS | {"dd"}
_OPERAND_READERS = frozenset({
    "view", "vim", "nvim", "ex", "emacs", "pico", "bat", "batcat", "sqlite3", "diff", "cmp", "comm", "paste", "wc",
    "rev", "fold", "fmt", "pr", "expand", "jq", "sha224sum", "sha384sum", "b2sum", "cksum", "sum", "egrep", "fgrep",
    "rgrep", "zgrep", "john", "hashcat",
})
# Programs whose use of a credential path is routine and documented, so a logged command naming one is not reported:
# - account and policy management that reads and writes the hash files and sudoers by design (shadow-utils
#   passwd(1), chpasswd(8), chage(1), usermod(8), vipw(8), pwck(8), pwconv(8); sudo's visudo(8) and sudoedit);
# - package managers and their queries (dpkg -S /etc/shadow, rpm -qf, rpm -V name a path to look it up);
# - metadata and permission tools that never read contents (ls, stat, chmod, chown, chattr, getfacl, restorecon);
# - audit and integrity tooling whose path argument is a watch or a search key (auditctl -w /etc/shadow,
#   ausearch -f, aide, debsums, rkhunter);
# - key and agent management (ssh-keygen -l/-y fingerprints or derives the public key; ssh-add loads an agent);
# - programs that only print or ignore their arguments (echo, printf, true, sleep).
BROKER_CREDENTIAL_ROUTINE = frozenset({
    "passwd", "chpasswd", "chage", "usermod", "useradd", "userdel", "adduser", "deluser", "groupadd", "groupmod",
    "groupdel", "gpasswd", "newusers", "vipw", "vigr", "pwck", "grpck", "pwconv", "pwunconv", "grpconv", "grpunconv",
    "chsh", "chfn", "visudo", "sudoedit", "cvtsudoers",
    "apt", "apt-get", "aptitude", "apt-cache", "apt-file", "dpkg", "dpkg-query", "dpkg-statoverride", "rpm", "yum",
    "dnf", "zypper", "pacman", "apk", "snap", "flatpak", "debsums",
    "ls", "stat", "chmod", "chown", "chgrp", "chattr", "lsattr", "touch", "getfacl", "setfacl", "getfattr",
    "setfattr", "restorecon", "chcon", "file", "test", "[", "du", "namei", "realpath", "readlink", "basename",
    "dirname", "find", "locate", "rm", "shred", "ln", "mkdir",
    "auditctl", "ausearch", "aureport", "aide", "tripwire", "rkhunter", "chkrootkit", "lynis", "osqueryi",
    "ssh-keygen", "ssh-add", "ssh-copy-id",
    "echo", "printf", "true", "false", "sleep",
})
# Directories whose whole contents are credentials, named by an archiver or copier (tar czf x /root/.ssh).
_CREDENTIAL_DIRS = (("/.ssh", "T1552.004", "an SSH key directory"), ("/.gnupg", "T1552.004", "a GnuPG home"),
                    ("/.aws", "T1552.001", "an AWS credential directory"),
                    ("/.azure", "T1552.001", "an Azure CLI credential directory"),
                    ("/.config/gcloud", "T1552.001", "a Google Cloud SDK credential directory"),
                    ("/.kube", "T1552.001", "a Kubernetes client configuration directory"),
                    ("/.password-store", "T1555.005", "a pass password store"))
_HASH_AND_KEY = frozenset({"T1003.008", "T1552.004"})


def broker_credential_class(path: str) -> tuple[str, str] | None:
    """(ATT&CK technique, description) of a credential store a path names, or None: `classify_credential`'s classes,
    the sudoers policy, password-manager vaults, cloud SDK credential files, older browser login stores, and whole
    credential directories."""
    found = classify_credential(path)
    if found:
        technique, _lane, description = found
        return technique, description
    low, name = path.lower(), basename(path).lower()
    if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
        return "T1548.003", f"the sudoers policy {path}"
    if name.endswith((".kdbx", ".kdb", ".psafe3", ".agilekeychain", ".opvault")):
        return "T1555.005", f"a password-manager vault {path}"
    if name in {"signons.sqlite", "key3.db", "signons3.txt"}:
        return "T1555.003", f"a browser saved-login store {path}"
    if low.endswith(("/.azure/accesstokens.json", "/.azure/msal_token_cache.json", "/.azure/msal_token_cache.bin",
                     "/.config/gcloud/credentials.db", "/.config/gcloud/access_tokens.db",
                     "/.config/gcloud/application_default_credentials.json")):
        return "T1552.001", f"cloud SDK credentials ({path})"
    for suffix, technique, description in _CREDENTIAL_DIRS:
        if low.endswith(suffix) or low.rstrip("/").endswith(suffix):
            return technique, f"{description} ({path})"
    if path.rstrip("/") == "/etc/ssh":
        return "T1552.004", f"the SSH configuration directory with the host keys ({path})"
    return None


# Wrappers that run the command after their own options, with the options that take a value (`nice -n 10`,
# `timeout -s KILL 5`, `env -u NAME`) and how many leading operands are theirs (timeout's duration, chrt's priority).
_WRAPPER_VALUES = {
    "env": ({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "ionice": ({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}, 0),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "chrt": (set(), 1),
    "taskset": ({"-c"}, 0),
    "xargs": ({"-n", "-I", "-i", "-d", "-P", "-L", "-l", "-s", "-E", "-e", "-a"}, 0),
    "nohup": (set(), 0), "setsid": (set(), 0), "time": ({"-f", "-o"}, 0), "command": (set(), 0),
    "exec": ({"-a"}, 0), "busybox": (set(), 0), "sudo": ({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}, 0),
    "doas": ({"-u", "-C"}, 0), "pkexec": ({"--user"}, 0),
}


def _unwrap(words: list[str]) -> list[str]:
    """The command a wrapper runs: its options, their values and its own operands stepped over."""
    while words and basename(words[0]) in _WRAPPER_VALUES:
        name = basename(words[0])
        valued, operands = _WRAPPER_VALUES[name]
        rest = words[1:]
        while rest:
            word = rest[0]
            if name == "env" and "=" in word and not word.startswith("-"):
                rest = rest[1:]
            elif word.startswith("-") and word != "-":
                rest = rest[2:] if word in valued else rest[1:]
            else:
                break
        if name == "taskset" and rest and not any(w in ("-c", "--cpu-list") for w in words[1:]):
            operands = 1                    # the mask
        words = rest[operands:]
    return words


def _statements(words: list[str]) -> list[list[str]]:
    """A logged command as statements. A shell's `-c` script (sudo logs the words joined by spaces, so its quoting
    is gone) is parsed with the shell grammar (`romulus.evidence.shellparse`), so unspaced pipes, separators and
    redirects (`cat</etc/shadow|base64`) are read; a script the grammar cannot model is split on spaced separators.
    Each command's input redirects are kept as `<` operands; wrappers are stepped over."""
    words = _unwrap(words)
    if not words:
        return []
    name = basename(words[0])
    if name in SHELLS and "-c" in words[1:]:
        script = " ".join(words[words.index("-c", 1) + 1:])
        if len(script) > 1 and script[0] == script[-1] and script[0] in "'\"":
            script = script[1:-1]          # a script logged with the quotes the caller typed around it
        parsed = parse_script(script)
        if parsed.ok and not parsed.partial:
            out = []
            for command in parsed.commands():
                argv = list(command.argv)
                for op, target in command.redirects:
                    read = classify_redirect(op, target).reads_file
                    if read:
                        argv += ["<", read]
                if argv:
                    out.extend(_statements(argv))
            return out
        out, current = [], []
        for word in [*words[words.index("-c", 1) + 1:], ";"]:
            if word in _SCRIPT_SEPARATORS or (word.endswith(";") and word != ";"):
                if word.endswith(";") and word not in _SCRIPT_SEPARATORS:
                    current.append(word[:-1])
                if current:
                    out.extend(_statements([w.strip("'\"") for w in current]))
                current = []
            else:
                current.append(word)
        return out
    return [words]


def _hit_strength(hit: tuple[str, str, str]) -> int:
    """How strongly a hit shows credential access: a read of the hash files or a private key, then a mode that
    exposes them, then a read of other credential material, then a hash file or key only named, then the rest
    (sudoers last among equals)."""
    _program, path, how = hit
    technique = broker_credential_class(path)[0]
    strong = technique in _HASH_AND_KEY
    rank = {("read", True): 5, ("widened", True): 4, ("read", False): 3, ("named", True): 2}.get((how, strong), 1)
    return rank * 2 - (technique == "T1548.003")


_OCTAL_MODE = re.compile(r"[0-7]{3,4}")


def _world_readable(mode: str) -> bool:
    """Whether a chmod mode gives every account read access: an octal mode whose 'other' digit has the read bit, or a
    symbolic clause adding or setting read for others or for all (`o+r`, `a+rw`, `+r`, `go=r`)."""
    if _OCTAL_MODE.fullmatch(mode):
        return bool(int(mode[-1]) & 4)
    for clause in mode.split(","):
        found = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", clause)
        if found and found[2] in "+=" and "r" in found[3] and (not found[1] or "o" in found[1] or "a" in found[1]):
            return True
    return False


def _widened(args: list[str], cwd) -> list[tuple[str, str, str]]:
    """chmod operands that are the hash files or a private key, when the mode makes them readable by every account
    (a tightening such as `chmod 600 id_rsa` is routine)."""
    operands = [arg for arg in args if not arg.startswith("-") or _OCTAL_MODE.fullmatch(arg.lstrip("-"))]
    if len(operands) < 2 or not _world_readable(operands[0]):
        return []
    found = []
    for item in operands[1:]:
        path = normalize_path(item, cwd)
        cls = broker_credential_class(path) if path else None
        if cls and cls[0] in _HASH_AND_KEY:
            found.append(("chmod", path, "widened"))
    return found


def _named_paths(words: list[str], cwd) -> list[tuple[str, str, str]]:
    """(program, path, how) for each credential path a statement's arguments name. `how` is 'read' when the program
    reads the files it is given (or a `<` redirect feeds it), 'named' for any other program; a routine program gives
    nothing."""
    name = basename(words[0])
    # a word logged with the quotes the caller typed around it ('/etc/shadow') is that word
    args = [word[1:-1] if len(word) > 1 and word[0] == word[-1] and word[0] in "'\"" else word for word in words[1:]]
    if name == "chmod":
        return _widened(args, cwd)
    if name in BROKER_CREDENTIAL_ROUTINE:
        return []
    found: list[tuple[str, str, str]] = []
    redirected = [args[i + 1] for i, word in enumerate(args[:-1]) if word in ("<", "0<")]
    redirected += [word[1:] for word in args if word.startswith("<") and len(word) > 1 and word[1] != "<"]
    for item in redirected:
        path = normalize_path(item, cwd)
        if path and broker_credential_class(path):
            found.append((name, path, "read"))
    plain = [arg for i, arg in enumerate(args) if arg not in ("<", "0<") and not (i and args[i - 1] in ("<", "0<"))
             and not arg.startswith("<")]
    candidates: list[tuple[str, str]] = []
    if name in _PLACED_READERS:
        placed, _unplaced = read_operand_paths(name, plain, cwd)
        candidates = [(path, "read") for path in placed]
    # a placed reader's other words are patterns, options and destinations the parser has already set aside
    for arg in [] if name in _PLACED_READERS else plain:
        if arg.startswith("-") and "=" not in arg:
            continue
        # the word itself and a value after '=' (--file=/x, if=/x, field=@/x); a curl-style '@file' value is a file
        # the program reads and sends
        for value in {arg, arg.split("=", 1)[1] if "=" in arg else ""}:
            sent = value.startswith("@")
            value = value.removeprefix("@")
            if not value or value.startswith(("-", "@")):
                continue
            path = normalize_path(value, cwd)
            if path and not any(path == known for known, _how in candidates):
                candidates.append((path, "read" if sent or name in _OPERAND_READERS else "named"))
    # The broker joins the words with spaces and records no quoting, so a path with a space in its last component
    # ('Login Data') arrives as two words: a word with no '/' is joined back onto the one before it.
    words = [arg for arg in plain if not arg.startswith("-")]
    for left, right in itertools.pairwise(words):
        if "/" in right:
            continue
        path = normalize_path(f"{left} {right}", cwd)
        if path and not any(path == known for known, _how in candidates):
            reads = name in _PLACED_READERS or name in _OPERAND_READERS
            candidates.append((path, "read" if reads else "named"))
    found += [(name, path, how) for path, how in candidates if broker_credential_class(path)]
    return found


class PrivilegeBrokerCredentialArgs(FoldedLinuxDirect):
    """A command sudo or pkexec logged whose arguments name a credential store.

    The broker's own record names the command it allowed (or refused) for the caller, so on a host without process
    auditing it is the record of a privileged read of the password-hash files, private keys, cloud and password-manager
    credentials. The command is the caller's text: the record shows the broker's decision, never that the program
    ran to completion or read the file."""
    version = "1"
    id = "host.privilege_broker_credential_args"
    title = "A privilege broker logged a command whose arguments name a credential store"
    families = ("privilege_use",)
    required_fields = ("auth.service",)
    anchor_class = "credential_access"
    severity, lane = "high", "lead"
    attack = ("T1003.008", "T1552.001", "T1552.004", "T1555.003", "T1555.005", "T1548.003")
    benign = (("an administrator reading the hash files or a key from a terminal while troubleshooting (named in the "
              "claim with the terminal)"),
              "backup or compare jobs run through sudo that name the hash files or key directories",
              "account, package, permission, audit and key-management tools are not reported: "
              + ", ".join(sorted(BROKER_CREDENTIAL_ROUTINE)))
    next_checks = (("what the caller's session did next: copies, archives or transfers of the file, and outbound "
                   "connections from the host"),
                   "the caller's login: its source, its terminal and whether the account normally uses sudo",
                   "whether the credential (hash, key, token) is used elsewhere after the record")
    card: ClassVar[dict] = {
        "behavior": "sudo or pkexec logged a command for a caller whose arguments name a credential store: the "
                    "password-hash files (/etc/shadow, /etc/gshadow and their backups), sudoers, SSH and TLS private "
                    "keys, Kerberos keytabs and caches, cloud SDK and CI credentials, password-manager vaults and "
                    "browser saved-login stores",
        "telemetry": "privilege_use from sudo's and pkexec's own syslog or journal lines in any Linux shipper shape: "
                     "auth.service, user.name, auth.target_user, sudo.command or privilege.command (the caller's "
                     "text, words joined by spaces), process.cwd, process.tty, privilege.denial_reason. The lab "
                     "profile has sudo journal records. doas lines are not typed by any normalizer yet (unresolved)",
        "fidelity": "the broker's decision record and the command text it logged: a read by a known file reader is "
                    "stated as the command the broker allowed, never as a completed read",
        "benign_and_cost": "administrators troubleshooting from a terminal, backup and compare jobs; account, "
                           "package, permission, audit and key-management tools are not reported, except a chmod that "
                           "makes the hash files or a private key readable by every account (lead). One folded lead "
                           "per (host, broker, account, target, program, path, outcome, terminal)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the caller's session after the record: copies, archives, transfers and outbound connections",
        "adds": "hosts without process auditing: host.credential_store_read and host.credential_material_access "
                "read exec and file-access records, which such hosts do not have",
        "research_basis": _RESEARCH + "sudoers(5) COMMAND field; ATT&CK Enterprise 20.0 T1003.008, T1552.001, "
                          "T1552.004, T1555.003, T1555.005, T1548.003; the register's credential-store path classes "
                          "(romulus.detect.linux_semantics.classify_credential)",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
        "lanes": "high when the broker allowed a known file reader on the hash files or a private key from an "
                 "interactive terminal, or for a web-service, system or daemon account (which never reads them "
                 "legitimately); lead otherwise, including refusals, an unknown outcome, other credential classes "
                 "and programs not known to read their arguments. Severity high: the material gives other accounts",
    }

    def match(self, e):
        service = str(e.get("auth.service"))
        if service not in ("sudo", "pkexec"):
            return []                       # su and runuser log no command
        if e.has("privilege.rejected_variable"):
            return []
        command = e.get("sudo.command") if service == "sudo" else e.get("privilege.command")
        if not isinstance(command, str) or not command.strip():
            self.missing_required += 1      # the command was not recorded: it cannot be judged
            return []
        cwd = e.get("process.cwd")
        hits = [hit for statement in _statements(command.split()) for hit in _named_paths(statement, cwd)]
        if not hits:
            return []
        if e.outcome == Outcome.unknown:
            self.missing_required += 1      # positive, but the decision is unknown: never a clean evaluation
        # the strongest hit decides the lane, the severity and the path the claim leads with; the rest are named
        hits = sorted(hits, key=_hit_strength, reverse=True)
        program, path, how = hits[0]
        technique, description = broker_credential_class(path)
        actor, target = e.get("user.name"), e.get("auth.target_user")
        tty = e.get("process.tty")
        on_tty = isinstance(tty, str) and bool(tty) and tty.lower() not in NO_TTY
        kind = account_class(str(actor)) if actor else "user"
        sensitive = technique in _HASH_AND_KEY and how == "read" and e.outcome == Outcome.success
        lane = "high" if sensitive and (on_tty or kind in {"web", "never", "daemon"}) else "lead"
        subject = line_subject(e, service)
        if e.outcome == Outcome.success:
            decision = "allowed"
        elif e.outcome == Outcome.failure:
            reason = e.get("privilege.denial_reason")
            decision = "refused" + (f" ({reason})" if reason else "")
        else:
            decision = "logged, with an unknown decision,"
        said = f"{subject} says that {service} {decision}" if subject else f"{service} {decision}"
        shown = (f"the command '{show(command, 300)}'" if len(command) <= 300 else
                 f"a command of {len(command)} characters beginning `{show(command, 300)}`")
        claim = (f"On {e.host}, {said} {_quote(actor)} to run as {_quote(target)} {shown}"
                 + (f" from terminal {tty}" if on_tty else " without a terminal") + ". ")
        if how == "read":
            claim += f"'{program}' reads the files it is given, and its arguments name {description}."
        elif how == "widened":
            claim += f"Its mode makes {description} readable by every account on the host."
        else:
            claim += (f"An argument of '{program}', a program not known here to read its arguments, names "
                      f"{description}.")
        claim += " The record shows the broker's decision, not that the command ran to completion or read the file."
        others = sorted({hit[1] for hit in hits[1:] if hit[1] != path})
        if others:
            claim += f" Its arguments also name {len(others)} other credential path(s): {[show(o) for o in others[:5]]}."
        if kind in {"web", "never", "daemon"}:
            claim += f" {_quote(actor)} is a {'web-service' if kind == 'web' else 'system or daemon'} account."
        if e.has("sudo.chunk") or SUDO_AMBIGUOUS_CAVEAT in e.caveats or PKEXEC_AMBIGUOUS_CAVEAT in e.caveats:
            claim += (" The record is incomplete or ambiguous, so the command may be cut short; only the words read "
                      "are judged.")
        match = observed(self, e, claim, lane,
                         group=json.dumps([e.host, service, actor, target, program, path, how, decision.split()[0],
                                           on_tty, lane, writer_state(e)]),
                         names=(*_FIELDS, "log.identifier", "log.writer"))
        # impact if adverse: the hash files, keys and stored credentials give other accounts; the sudoers policy shows
        # who may become whom
        match.severity = "medium" if technique == "T1548.003" else self.severity
        match.attack = tuple(dict.fromkeys(technique for technique in (
            broker_credential_class(hit[1])[0] for hit in hits)))
        return [match]


PRIVILEGE_BROKER_RULES = [PrivilegeBrokerRefusal, PkexecEnvironmentRejection, PrivilegeBrokerSuspiciousSuccess,
                          PrivilegeBrokerCredentialArgs]
