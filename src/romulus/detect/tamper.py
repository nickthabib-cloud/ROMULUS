"""Audit and log tampering on Linux hosts.

Three rules, each grouped per (host, actor, form) so a script that repeats one action is one finding:
- `host.security_or_logging_service_stop`: a logging, audit or security service stopped, disabled, masked or
  killed by command (systemctl, service, invoke-rc.d, init scripts, pkill/killall with a terminating signal,
  update-rc.d/chkconfig/rc-update/sv), SELinux switched to permissive, AppArmor profiles unloaded; and the service
  manager's own records of such a unit stopping (audit SERVICE_STOP, journal unit stop jobs).
- `host.audit_rules_tamper`: `auditctl` deleting rules, switching auditing off, removing watches, rate-limiting or
  stopping the daemon; commands writing the audit configuration files; and the kernel's CONFIG_CHANGE records of
  rules removed, auditing disabled or the audit daemon unregistering.
- `host.log_or_history_clearing`: log files deleted, truncated, overwritten, edited in place or linked to
  /dev/null; journal vacuuming; shell history files removed, and history recording switched off in shell text.

What the evidence shows: an exec record shows a command was started (its outcome is stated); shell command text
shows intent; a service manager or kernel record shows the state change. Claims keep these apart. Commands are
recognised from argv and shell text, so every rule is positive-only.

Shutdown and restart: a stop recorded within SHUTDOWN_WINDOW of a typed shutdown or reboot marker on the same host
(audit SYSTEM_SHUTDOWN, SYSTEM_RUNLEVEL to 0 or 6, the service manager (pid 1) starting a shutdown target, or a
shutdown/reboot command) is a lead worded as such, never dropped. A unit stop followed by the same unit starting
within RESTART_SECONDS is a restart and is not reported; a longer gap is a lead that states it.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar, NamedTuple

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.host import Lineage, ProcessLineage, _argv_summary, _outcome_tally, lineage_phrase
from romulus.detect.linux_argv import (
    canonical,
    getopt_long,
    is_editor,
    is_under,
    normalize_path,
    operands_after_options,
    program,
    write_targets,
)
from romulus.evidence.normalize import service_name
from romulus.evidence.shellparse import SHELLS, UnknownShellScript, shell_script_of
from romulus.evidence.shellparse import _lex as _shell_tokens  # the parser's own lexer, reused read-only
from romulus.evidence.shellparse import _Unmodelled as _ShellUnmodelled
from romulus.evidence.typed import Outcome, TypedEvent

SHUTDOWN_WINDOW = 900.0          # seconds either side of a stop in which a shutdown marker explains it
RESTART_SECONDS = 10.0           # a stop followed this soon by a start of the same unit is a restart
RESTART_WINDOW = 300.0           # a start within this long after a stop is reported with the stop, as a lead
COMMAND_LINK_BEFORE = 120.0      # a typed stop this soon after a command naming the unit is shown with it
COMMAND_LINK_AFTER = 5.0
CITE = 10

# Units and daemons whose stop removes logging, auditing or security monitoring. Matched on the service name
# (lower case, without the .service/.socket suffix or a template instance) or on a process name.
SERVICE_CATEGORIES: dict[str, str] = {
    **dict.fromkeys(("auditd", "audispd", "auditbeat", "auoms", "go-audit"), "audit"),
    **dict.fromkeys(("rsyslog", "rsyslogd", "syslog", "syslogd", "syslog-ng", "systemd-journald",
                     "systemd-journald-dev-log", "systemd-journald-audit", "filebeat", "journalbeat", "fluentd",
                     "td-agent", "td-agent-bit", "fluent-bit", "vector", "nxlog", "logstash", "splunk", "splunkd",
                     "splunkforwarder", "elastic-agent", "amazon-cloudwatch-agent", "google-cloud-ops-agent",
                     "azuremonitoragent", "omsagent", "wazuh-logcollector", "ossec-logcollector"), "logging"),
    **dict.fromkeys(("osqueryd", "osquery", "wazuh-agent", "wazuh-manager", "wazuh-agentd", "wazuh-syscheckd",
                     "wazuh-modulesd", "wazuh-execd", "ossec", "ossec-hids", "ossec-agentd", "ossec-syscheckd",
                     "falco", "sysmon", "mdatp", "wdavdaemon", "falcon-sensor", "falcond", "cbagentd",
                     "cb-psc-sensor", "sentinelone", "cylancesvc", "sophos-spl", "sav-protect", "clamav-daemon",
                     "clamd", "elastic-endpoint", "suricata", "snort", "zeek", "arkimecapture", "fail2ban",
                     "apparmor", "qualys-cloud-agent", "nessusagent"), "security"),
}
SHUTDOWN_TARGETS = {"shutdown.target", "reboot.target", "poweroff.target", "halt.target", "kexec.target",
                    "soft-reboot.target", "final.target"}
SHUTDOWN_COMMANDS = {"shutdown", "reboot", "poweroff", "halt"}
SYSTEMCTL_SHUTDOWN_VERBS = {"reboot", "poweroff", "halt", "kexec", "soft-reboot"}
# Signals that do not end a process: reload, log reopen, status and continue requests.
NON_TERMINATING = {"0", "HUP", "SIGHUP", "1", "USR1", "SIGUSR1", "10", "USR2", "SIGUSR2", "12", "CONT", "SIGCONT", "18",
                   "WINCH", "SIGWINCH", "28", "CHLD", "SIGCHLD", "URG", "SIGURG"}


def service_category(name: str) -> str:
    key = service_name(name)
    if key in SERVICE_CATEGORIES:
        return SERVICE_CATEGORIES[key]
    return "security" if key.startswith("falco-") else ""


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _unique(events) -> list[TypedEvent]:
    out: dict[str, TypedEvent] = {}
    for event in events:
        if event is not None:
            out.setdefault(event.id, event)
    return list(out.values())


def _identity(e: TypedEvent) -> tuple[str, list[str], bool] | None:
    """(program name, operands, named from the kernel-recorded executable) for an exec record."""
    argv = e.get("process.argv")
    if not isinstance(argv, list) or not argv:
        return None
    prog = program(e)
    if prog is not None:
        return prog.name, prog.args, True
    return canonical(basename(str(argv[0]))), [str(a) for a in argv[1:]], False


class Segment(NamedTuple):
    assignments: list[str]       # NAME=VALUE words before the command name
    argv: list[str]
    redirects: list[tuple[str, str]]


_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def shell_segments(name: str, args: list[str]) -> tuple[list[Segment], bool]:
    """Simple commands of a shell started with -c, and whether the text was only partly modelled. Read with the
    shell parser's own lexer, so quoting is honoured; unlike the parser, assignment prefixes (`HISTFILE=/dev/null`)
    are kept as assignments, because they are what this module looks for. Nothing a construct the lexer does not
    model (expansions, substitutions, here-documents) would run is read."""
    if name not in SHELLS:
        return [], False
    script = shell_script_of([name, *args])
    if isinstance(script, UnknownShellScript):
        return [], True
    if not script:
        return [], False
    incomplete = False
    try:
        tokens = _shell_tokens(script)
    except _ShellUnmodelled as error:
        tokens, incomplete = error.tokens, True
    segments: list[Segment] = []
    current = Segment([], [], [])
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind in {"operator", "pipe"}:
            if current.argv or current.assignments or current.redirects:
                segments.append(current)
            current = Segment([], [], [])
        elif token.kind == "redirect":
            if index + 1 < len(tokens) and tokens[index + 1].kind == "word":
                current.redirects.append((token.value, tokens[index + 1].value))
                index += 1
            else:
                incomplete = True
        elif not current.argv and _ASSIGNMENT.match(token.value):
            current.assignments.append(token.value)
        else:
            current.argv.append(token.value)
        index += 1
    if current.argv or current.assignments or current.redirects:
        segments.append(current)
    return segments, incomplete


@dataclass
class _Item:
    host: str | None
    ts: float
    group: tuple
    form: str                    # what the command or record shows, worded as an attempt or as recorded
    target: str
    lane: str
    event: TypedEvent
    lineage: Lineage
    actor: str
    category: str = ""
    linked: list[TypedEvent] = field(default_factory=list)
    from_text: bool = False


class _ShutdownMarkers:
    """Typed shutdown or reboot markers per host, from the service manager, the kernel audit trail and commands."""

    def __init__(self):
        self.marks: dict[str | None, list[tuple[float, str, TypedEvent]]] = defaultdict(list)

    def observe(self, e: TypedEvent) -> None:
        what = None
        if e.family == "system_state":
            if e.get("system.event") == "shutdown":
                what = "an audit SYSTEM_SHUTDOWN record"
            elif e.get("system.event") == "runlevel" and str(e.get("system.runlevel")) in {"0", "6"}:
                what = f"an audit SYSTEM_RUNLEVEL record (new runlevel {e.get('system.runlevel')})"
        elif e.family == "service_change":
            if (e.get("service.unit") in SHUTDOWN_TARGETS and e.get("service.job") == "start"
                    and e.get("service.scope") == "system" and e.get("process.pid") == 1):
                what = f"the service manager starting {e.get('service.unit')}"
        elif e.family == "process_exec":
            ident = _identity(e)
            if ident is not None and e.outcome != Outcome.failure:
                name, args, _ = ident
                if name in SHUTDOWN_COMMANDS and not ({"-c", "-k", "--help", "--wall"} & set(args)):
                    what = f"a '{name}' command"
                elif name == "systemctl":
                    operands = operands_after_options(args, _SYSTEMCTL_VALUES)
                    if operands and (operands[0] in SYSTEMCTL_SHUTDOWN_VERBS or (
                            operands[0] == "isolate" and set(operands[1:]) & SHUTDOWN_TARGETS)):
                        what = f"a 'systemctl {operands[0]}' command"
                elif name in {"init", "telinit"} and args[:1] in (["0"], ["6"]):
                    what = f"an '{name} {args[0]}' command"
        if what:
            self.marks[e.host].append((e.ts.timestamp(), what, e))

    def near(self, host: str | None, ts: float) -> tuple[float, str, TypedEvent] | None:
        best = None
        for mark in self.marks.get(host, ()):
            if abs(mark[0] - ts) <= SHUTDOWN_WINDOW and (best is None or abs(mark[0] - ts) < abs(best[0] - ts)
                                                         or (abs(mark[0] - ts) == abs(best[0] - ts)
                                                             and mark[2].id < best[2].id)):
                best = mark
        return best


_SYSTEMCTL_VALUES = {"-H", "--host", "-M", "--machine", "-t", "--type", "-s", "--signal", "--kill-whom",
                     "--kill-value", "--job-mode", "--root", "-p", "--property", "-n", "--lines", "-o", "--output",
                     "--state", "--what", "--timestamp", "--message", "--when", "--image", "--drop-in",
                     "--preset-mode", "--boot-loader-menu", "--boot-loader-entry", "--reboot-argument"}
_STOP_VERBS = {"stop": "stop", "disable": "disable", "mask": "mask", "kill": "kill"}


def _signal_value(args: list[str]) -> str | None:
    """The signal a systemctl/pkill/killall command line names (`-s SIG`, `-sSIG`, `--signal[=]SIG`, `-SIG`, `-9`)."""
    for index, arg in enumerate(args):
        if arg in {"-s", "--signal"} and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--signal="):
            return arg.split("=", 1)[1]
    return None


def _terminating(signal: str | None) -> bool:
    if signal is None:
        return True                                    # the default is SIGTERM
    return signal.upper().removeprefix("SIG") not in {s.removeprefix("SIG") for s in NON_TERMINATING}


def service_requests(name: str, args: list[str]) -> list[tuple[str, str, str]]:
    """(verb, service or process name, how) for each logging/audit/security unit or daemon a command line asks to
    stop, disable, mask or kill. Restart, reload, status and non-terminating signals ask for none."""
    out: list[tuple[str, str, str]] = []
    if name in {"systemctl", "deb-systemd-invoke", "deb-systemd-helper"}:
        if {"--user", "--global"} & set(args):
            return []                                  # a user manager's units, not the system's
        operands = operands_after_options([a for a in args if not a.startswith("-s") or a == "-s"],
                                          _SYSTEMCTL_VALUES)
        if not operands or operands[0] not in _STOP_VERBS:
            return []
        verb = operands[0]
        if verb == "kill":
            signal = _signal_value(args) or next((a[2:] for a in args if a.startswith("-s") and len(a) > 2), None)
            if not _terminating(signal):
                return []
        if verb in {"disable", "mask"} and "--now" in args:
            verb = f"{verb} --now"
        for unit in operands[1:]:
            if service_category(unit):
                out.append((verb, service_name(unit), f"'{name} {verb} {unit}'"))
    elif name in {"service", "invoke-rc.d", "rc-service"}:
        operands = [a for a in args if not a.startswith("-")]
        if len(operands) >= 2 and operands[1] in {"stop", "force-stop"} and service_category(operands[0]):
            out.append(("stop", service_name(operands[0]), f"'{name} {operands[0]} {operands[1]}'"))
    elif name == "update-rc.d":
        operands = [a for a in args if not a.startswith("-")]
        if len(operands) >= 2 and operands[1] in {"disable", "remove"} and service_category(operands[0]):
            out.append(("disable", service_name(operands[0]), f"'update-rc.d {operands[0]} {operands[1]}'"))
    elif name == "chkconfig":
        operands = [a for a in args if not a.startswith("-")]
        if "--del" in args and operands and service_category(operands[-1]):
            out.append(("disable", service_name(operands[-1]), f"'chkconfig --del {operands[-1]}'"))
        elif len(operands) >= 2 and operands[-1] == "off" and service_category(operands[-2]):
            out.append(("disable", service_name(operands[-2]), f"'chkconfig {operands[-2]} off'"))
    elif name == "rc-update":
        operands = [a for a in args if not a.startswith("-")]
        if len(operands) >= 2 and operands[0] in {"del", "delete"} and service_category(operands[1]):
            out.append(("disable", service_name(operands[1]), f"'rc-update {operands[0]} {operands[1]}'"))
    elif name == "sv":
        operands = [a for a in args if not a.startswith("-")]
        if len(operands) >= 2 and operands[0] in {"down", "d", "stop", "force-stop", "exit", "x"}:
            out += [("stop", service_name(unit), f"'sv {operands[0]} {unit}'") for unit in operands[1:]
                    if service_category(basename(unit))]
    elif name in {"pkill", "killall"}:
        signal = _signal_value(args)
        for arg in args:
            if arg.startswith("-") and len(arg) > 1 and arg[1:].lstrip("SIG").isalnum() and arg[1:].upper() == arg[1:]:
                signal = signal or arg[1:]
        if not _terminating(signal):
            return []
        values = {"-u", "--euid", "-U", "--uid", "-g", "--pgroup", "-G", "--group", "-P", "--parent", "-t",
                  "--terminal", "-s", "--signal", "--session", "-F", "--pidfile", "--ns", "--nslist", "-o",
                  "--older-than", "-y", "--younger-than", "-Z", "--context", "-n"} if name == "killall" else \
                 {"-u", "--euid", "-U", "--uid", "-g", "--pgroup", "-G", "--group", "-P", "--parent", "-t",
                  "--terminal", "-s", "--signal", "--session", "-F", "--pidfile", "--ns", "--nslist"}
        for operand in operands_after_options(args, values):
            # pkill -f matches the whole command line, so its pattern's first word is the program it names
            words = operand.removeprefix("^").removesuffix("$").split()
            pattern = basename(words[0]) if words else ""
            if service_category(pattern):
                out.append(("kill", service_name(pattern), f"'{name} {operand}'"
                            + (f" with signal {signal}" if signal else "")))
    elif name in SHELLS and args and is_under(normalize_path(args[0]) or args[0], ("/etc/init.d", "/etc/rc.d/init.d")):
        unit = basename(args[0])
        if len(args) >= 2 and args[1] in {"stop", "force-stop"} and service_category(unit):
            out.append(("stop", service_name(unit), f"'{args[0]} {args[1]}'"))
    return out


def mac_requests(name: str, args: list[str]) -> list[tuple[str, str, str]]:
    """(form key, target, how) for commands that relax SELinux or AppArmor enforcement."""
    if name == "setenforce" and args[:1] and args[0].lower() in {"0", "permissive"}:
        return [("selinux_permissive", "SELinux", f"'setenforce {args[0]}' (enforcement switched to permissive)")]
    if name == "aa-teardown":
        return [("apparmor_unload", "AppArmor", "'aa-teardown' (every AppArmor profile unloaded)")]
    if name in {"aa-disable", "aa-complain"}:
        profiles = [a for a in args if not a.startswith("-")]
        effect = "disabled" if name == "aa-disable" else "set to complain mode"
        how = f"'{name} {' '.join(profiles[:3])}' (profile(s) {effect})"
        return [("apparmor_relax", "AppArmor", how)] if profiles else []
    if name == "apparmor_parser" and ({"-R", "--remove"} & set(args)):
        return [("apparmor_relax", "AppArmor", "'apparmor_parser -R' (profile(s) removed from the kernel)")]
    return []


def _actor(e: TypedEvent) -> str:
    return str(e.get("process.user") or (f"uid {e.get('process.uid')}" if e.has("process.uid") else
                                         "an unrecorded account"))


class _TamperRule(Playbook):
    kind = "aggregate"
    claim_type = "aggregate_observation"
    assures_negative = False
    anchor_class = "execution"

    def __init__(self):
        super().__init__()
        self.lineage = ProcessLineage()
        self.markers = _ShutdownMarkers()
        self.items: list[_Item] = []
        self._seen: set[str] = set()

    def consume(self, events):
        order = {"process_exec": 0, "system_state": 1, "service_change": 2, "audit_config": 3}
        fresh = [e for e in events if e.family in self.families and e.id not in self._seen]
        for e in sorted(fresh, key=lambda x: (x.ts, order.get(x.family, 9), x.id)):
            self._seen.add(e.id)
            self.markers.observe(e)
            if e.family == "process_exec":
                self.lineage.observe(e)
            self._event(e)
        return []

    def _event(self, e: TypedEvent) -> None: ...

    def retained_events(self):
        return ([i.event for i in self.items] + [e for i in self.items for e in i.linked]
                + [m[2] for marks in self.markers.marks.values() for m in marks])

    def _exec_items(self, e: TypedEvent, found: list[tuple[str, str, str, str]], from_text: bool) -> None:
        """found: (group form key, target, how, proposed lane before lineage and shutdown)."""
        lineage = self.lineage.classify(e)
        actor = _actor(e)
        for key, target, how, lane in found:
            self.items.append(_Item(e.host, e.ts.timestamp(), (e.host, actor, lineage.kind, key), how, target,
                                    lane, e, lineage, actor, from_text=from_text))

    def _group_findings(self, describe) -> list[Match]:
        groups: dict[tuple, list[_Item]] = defaultdict(list)
        for item in self.items:
            groups[item.group].append(item)
        return [describe(key, sorted(items, key=lambda i: (i.ts, i.event.id)))
                for key, items in sorted(groups.items(), key=lambda kv: str(kv[0]))]

    @staticmethod
    def _command_lane(items: list[_Item], proposed: str, notes: list[str]) -> str:
        lineage = next((i.lineage for i in items if i.lineage.kind == "web"), items[0].lineage)
        if lineage.kind == "web":
            return "high"
        if lineage.kind in {"package", "cloud-init", "logrotate"}:
            if proposed == "high":
                notes.append(f"lane lowered: started under {lineage.kind} lineage")
            return "lead"
        commands = [i.event for i in items if i.event.family == "process_exec"]
        if proposed == "high" and commands and all(c.outcome == Outcome.failure for c in commands) and not any(
                linked.outcome == Outcome.success for i in items for linked in i.linked):
            notes.append("lane lowered: every recorded exec failed")
            return "lead"
        return proposed


class SecurityOrLoggingServiceStop(_TamperRule):
    id = "host.security_or_logging_service_stop"
    version = "1"
    title = "Logging, audit or security service stopped, disabled or killed (command or service manager record)"
    families = ("process_exec", "service_change", "system_state")
    severity, lane = "high", "high"
    attack = ("T1685", "T1685.004")
    positive_only_reason = (
        "stop commands are recognised from argv and shell text, and the service manager records only the units it "
        "manages; a daemon can be stopped in ways neither shows (a kill by process id, a crash, a changed unit file), "
        "so a window without matches proves nothing")
    benign = ("maintenance or troubleshooting by an administrator",
              "package upgrades stopping a service before replacing it", "system shutdown or reboot")
    next_checks = ("what the same account or session ran while the service was down",
                   "whether the service was started again, and when (telemetry gap for the host)",
                   "auth_activity for the session that issued the stop")
    card: ClassVar[dict] = {
        "behavior": "a logging, audit or security service or daemon was stopped, disabled, masked or killed, or "
                    "SELinux/AppArmor enforcement was relaxed",
        "telemetry": "auditd process_exec (process.executable, process.argv, process.pid, process.ppid, "
                     "process.user): present; audit SERVICE_STOP/SERVICE_START (SERVICE_STOP present in the lab profile) and"
                     "journal systemd unit job records (UNIT, JOB_TYPE, JOB_RESULT or MESSAGE_ID; lab field set "
                     "unverified) as service_change; audit SYSTEM_SHUTDOWN/SYSTEM_RUNLEVEL as system_state",
        "fidelity": "a command was started (outcome stated); a service manager record shows the unit stopped; the "
                    "two are shown together only by unit name and time, labelled as such",
        "benign_and_cost": "admin maintenance, package upgrades (grouped, lead), shutdowns (lead with the marker "
                           "named), restarts (a start within 10 s: not reported)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the host's activity while the service was down",
        "adds": "the firewall rule covers firewall services only; nothing else covered defence-tool stops",
        "research_basis": "ATT&CK Enterprise 20.0 T1685 (revokes T1562.001) and T1685.004 (revokes T1562.012), "
                          "procedure examples stopping auditd/rsyslog/security agents; SigmaHQ Linux process-creation "
                          "rules on disabling security tools and SELinux, as references (reimplemented; upstream "
                          "commits not re-verified offline)",
        "lanes": "high for a stop/disable/mask/kill of a watched unit, AppArmor teardown, or any form under "
                 "web-service lineage; lead under package/cloud-init/logrotate lineage, near a shutdown marker, "
                 "when every exec failed, for SELinux permissive and single AppArmor profiles, and for service "
                 "manager stops that ended in a failed state or were restarted within 5 minutes",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def __init__(self):
        super().__init__()
        self.stops: list[TypedEvent] = []
        self.starts: dict[tuple, list[float]] = defaultdict(list)

    def _event(self, e):
        if e.family == "process_exec":
            ident = _identity(e)
            if ident is None:
                self.missing_required += 1
                return
            self.evaluated += 1
            name, args, from_exe = ident
            found = self._requests(name, args)
            segments, incomplete = shell_segments(name, args)
            if incomplete:
                self.missing_required += 1
            text_found = [f for seg in segments if seg.argv
                          for f in self._requests(canonical(basename(seg.argv[0])), seg.argv[1:])]
            if not from_exe and found:
                self.missing_required += 1
            self._exec_items(e, found, False)
            self._exec_items(e, text_found, True)
        elif e.family == "service_change":
            name, job = e.get("service.name"), e.get("service.job")
            if not name or not job:
                self.missing_required += 1
                return
            self.evaluated += 1
            if e.get("service.scope") != "system" or not service_category(str(name)):
                return
            if e.get("service.source") == "journal" and e.has("process.pid") and e.get("process.pid") != 1:
                return              # any process can write a journal entry shaped like the service manager's
            if job == "stop" and e.get("service.job_phase") not in {"begun"}:
                self.stops.append(e)
            elif job == "start" and e.get("service.job_phase") == "done":
                self.starts[(e.host, name)].append(e.ts.timestamp())
        else:
            self.evaluated += 1

    @staticmethod
    def _requests(name, args):
        out = []
        for verb, unit, how in service_requests(name, args):
            out.append((f"{verb.split()[0]}:{unit}", unit, f"{how} ({service_category(unit)} service)", "high"))
        for key, target, how in mac_requests(name, args):
            out.append((key, target, how, "high" if key == "apparmor_unload" else "lead"))
        return out

    def retained_events(self):
        return super().retained_events() + self.stops

    def finalize(self):
        restarts = 0
        typed: dict[tuple, list[tuple[TypedEvent, str, float | None]]] = defaultdict(list)
        commands_by_unit: dict[tuple, list[_Item]] = defaultdict(list)
        for item in self.items:
            commands_by_unit[(item.host, item.target)].append(item)
        for stop in sorted(self.stops, key=lambda e: (e.ts, e.id)):
            ts = stop.ts.timestamp()
            name = str(stop.get("service.name"))
            later = [t for t in self.starts.get((stop.host, name), ()) if t >= ts]
            gap = min(later) - ts if later else None
            if gap is not None and gap <= RESTART_SECONDS:
                restarts += 1
                continue
            linked = [i for i in commands_by_unit.get((stop.host, name), ())
                      if -COMMAND_LINK_AFTER <= ts - i.ts <= COMMAND_LINK_BEFORE]
            if linked:
                for item in linked:
                    item.linked.append(stop)
                continue
            if stop.outcome == Outcome.failure:
                kind = "failed"
            elif gap is not None and gap <= RESTART_WINDOW:
                kind = "restarted"
            elif self.markers.near(stop.host, ts):
                kind = "shutdown"
            else:
                kind = "stopped"
            typed[(stop.host, name, kind)].append((stop, kind, gap))
        out = self._group_findings(self._describe_commands)
        for key in sorted(typed, key=str):
            out.append(self._describe_records(key, typed[key]))
        if restarts:
            for match in out:
                match.notes.append(f"{restarts} unit stop(s) followed by a start within {RESTART_SECONDS:.0f} s "
                                   "were restarts and are not reported")
        return out

    def _describe_commands(self, key, items: list[_Item]) -> Match:
        host, actor, _lineage_kind, form = key
        notes: list[str] = []
        commands = _unique(i.event for i in items)
        linked = sorted(_unique(e for i in items for e in i.linked), key=lambda e: (e.ts, e.id))
        first = items[0]
        text = any(i.from_text for i in items)
        hows = list(dict.fromkeys(i.form for i in items))
        claim = (f"On {host}, account '{actor}' ran {len(commands)} command(s)"
                 + (" (some as shell command text)" if text else "") + f" to {'; '.join(hows[:4])}"
                 + (f" and {len(hows) - 4} more" if len(hows) > 4 else "")
                 + f" (e.g. {_argv_summary(commands[0].get('process.argv'), 120)}); {_outcome_tally(commands)}.")
        if linked:
            claim += (f" The service manager recorded '{first.target}' stopping {len(linked)} time(s), the first at "
                      f"{linked[0].ts.isoformat()}, within {COMMAND_LINK_BEFORE:.0f} s after such a command (linked "
                      "by unit name and time, not by process).")
        elif form.split(":")[0] in {"stop", "kill"}:
            claim += " No service manager record of the unit stopping was linked, so whether it stopped is not established."
        proposed = max((i.lane for i in items), key=lambda lane: lane == "high")
        lane = self._command_lane(items, proposed, notes)
        marker = self.markers.near(host, first.ts)
        if marker and lane == "high" and next((i.lineage for i in items if i.lineage.kind == "web"), None) is None:
            lane = "lead"
            notes.append("lane lowered: a shutdown or reboot marker is near")
        if marker:
            claim += (f" A shutdown or reboot marker on the host ({marker[1]}) is {abs(marker[0] - first.ts):.0f} s "
                      f"{'before' if marker[0] <= first.ts else 'after'} the first command.")
        phrase = lineage_phrase(next((i.lineage for i in items if i.lineage.kind == "web"), first.lineage))
        if phrase:
            claim += f" Exec lineage: {phrase}."
        events = sorted(_unique([*commands[:CITE], *linked[:CITE], *([marker[2]] if marker else [])]),
                        key=lambda e: (e.ts, e.id))
        predicate = [pf(c, "process.argv") for c in commands[:3]] + [pf(e, "service.unit") for e in linked[:2]]
        match = Match(self.id, claim, self.claim_type, events, predicate, events[0].ts, self.severity, lane,
                      "high" if linked else "medium", commands[0].entities(),
                      group_key="cmd|" + "|".join(str(p) for p in key))
        match.notes = notes + (["T1685.004"] if any(service_category(i.target) == "audit" for i in items) else
                               ["T1685"])
        return match

    def _describe_records(self, key, entries) -> Match:
        host, name, kind = key
        stops = [stop for stop, _kind, _gap in entries]
        sources = defaultdict(int)
        for stop in stops:
            sources[stop.get("service.source")] += 1
        count = max(sources.values())
        listed = "; ".join(f"{n} {'audit SERVICE_STOP' if s == 'audit' else 'journal unit stop'} record(s)"
                           for s, n in sorted(sources.items(), key=lambda kv: str(kv[0])))
        claim = (f"On {host}, the service manager recorded the {service_category(name)} service '{name}' stopping at "
                 f"least {count} time(s) ({stops[0].ts.isoformat()} – {stops[-1].ts.isoformat()}; {listed}); no "
                 f"command naming it was linked within {COMMAND_LINK_BEFORE:.0f} s before.")
        lane, notes, cited = "high", [], list(stops[:CITE])
        if kind == "failed":
            claim += (" The records report a result other than success (the unit failed, or the stop job did not "
                      "complete), so this may be a crash rather than a requested stop.")
            lane = "lead"
        elif kind == "restarted":
            gap = min(g for _s, _k, g in entries if g is not None)
            claim += f" It was started again {gap:.0f} s later (a short gap, as in a restart or upgrade)."
            lane = "lead"
        elif kind == "shutdown":
            marker = self.markers.near(host, stops[0].ts.timestamp())
            claim += (f" A shutdown or reboot marker on the host ({marker[1]}) is "
                      f"{abs(marker[0] - stops[0].ts.timestamp()):.0f} s away, so this may be part of a shutdown.")
            lane = "lead"
            cited.append(marker[2])
        else:
            claim += f" No start of the unit within {RESTART_WINDOW:.0f} s and no shutdown marker were recorded."
        events = sorted(_unique(cited), key=lambda e: (e.ts, e.id))
        match = Match(self.id, claim, self.claim_type, events, [pf(s, "service.unit") for s in stops[:3]],
                      stops[0].ts, self.severity, lane, "high", stops[0].entities(),
                      group_key=f"record|{host}|{name}|{kind}")
        match.notes = notes + (["T1685.004"] if service_category(name) == "audit" else ["T1685"])
        return match


# ---------------------------------------------------------------- auditctl and the kernel's audit configuration

_AUDITCTL = ("FaAdSmRrefbwWpkCq", "cDlhistv", {
    "--signal": ("--signal", True), "--loginuid-immutable": ("--loginuid-immutable", False),
    "--backlog_wait_time": ("--backlog_wait_time", True), "--reset-lost": ("--reset-lost", False),
    "--reset_backlog_wait_time_actual": ("--reset_backlog_wait_time_actual", False)})
AUDIT_CONFIG_PATHS = ("/etc/audit",)


def auditctl_requests(args: list[str]) -> list[tuple[str, str, str]]:
    """(form key, how, proposed lane) for an auditctl command line. `-e 2` (lock the configuration until reboot)
    is hardening that rule files end with, so on its own it asks for nothing; it is named when it accompanies a
    deletion, because it then keeps the deletion in force."""
    parsed = getopt_long(args, *_AUDITCTL)
    opts = parsed.options
    keys = {k for k, _v in opts}
    if "h" in keys or "v" in keys:
        return []
    out = []
    lock = " and lock the configuration until reboot (-e 2)" if ("e", "2") in opts else ""
    if "D" in keys:
        out.append(("delete_all_rules", f"delete every audit rule (-D){lock}", "high"))
    if ("e", "0") in opts:
        out.append(("disable_auditing", "switch kernel auditing off (-e 0)", "high"))
    for key, value in opts:
        if key == "d":
            out.append(("delete_rule", f"delete the audit rule '{value}' (-d){lock}", "lead"))
        elif key == "W":
            out.append(("delete_watch", f"remove the file watch on {value} (-W){lock}", "lead"))
        elif key == "--signal" and value and value.upper().removeprefix("SIG") in {"TERM", "STOP", "KILL", "QUIT"}:
            out.append(("stop_daemon", f"signal the audit daemon to stop (--signal {value})", "high"))
        elif key == "r" and value and value.isdigit() and int(value) > 0:
            out.append(("rate_limit", f"limit audit messages to {value} per second (-r)", "lead"))
    return out


class AuditRulesTamper(_TamperRule):
    id = "host.audit_rules_tamper"
    version = "1"
    title = "Audit rules deleted, auditing switched off or audit configuration changed (command or kernel record)"
    families = ("process_exec", "audit_config", "service_change", "system_state")
    severity, lane = "high", "high"
    attack = ("T1685.004",)
    positive_only_reason = (
        "auditctl and configuration-file writes are recognised from argv and shell text; the kernel records "
        "configuration changes only while auditing runs, so a window without matches proves nothing")
    benign = ("an administrator reloading rules (augenrules, auditctl -R) or editing rule files",
              "audit daemon restarts during upgrades", "system shutdown")
    next_checks = ("what ran on the host after the rules were removed",
                   "the current rule set (auditctl -l output in a later record, or the rule files)",
                   "the session that issued the change")
    RELOAD_SECONDS = 120.0
    card: ClassVar[dict] = {
        "behavior": "audit rules were deleted, auditing was switched off, the audit daemon was told to stop or "
                    "unregistered, or the audit configuration files were written",
        "telemetry": "auditd process_exec of auditctl and of write-capable programs (process.argv, "
                     "process.executable, process.pid): present (no auditctl runs in the lab profile); kernel "
                     "CONFIG_CHANGE records as audit_config (audit.config.op/setting/value/old, process.auid, "
                     "process.session_id, process.pid from the SYSCALL companion): typed; the lab profile holds only "
                     "boot-time add_rule/set records",
        "fidelity": "auditctl exec: the command was started; CONFIG_CHANGE: the kernel applied the change "
                    "(res=1) or refused it (res=0); a file write command: started, content unknown",
        "benign_and_cost": "rule reloads (a removal followed by additions from the same session within 120 s: "
                           "lead), daemon restarts (re-registration within 10 s: not reported), shutdowns (lead)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "commands and connections on the host after the change",
        "adds": "no earlier rule covered the audit system itself",
        "research_basis": "ATT&CK Enterprise 20.0 T1685.004 (revokes T1562.012: 'auditctl -D', '-e 0'); auditctl(8) "
                          "option grammar; kernel audit_log_config_change and audit_log_rule_change record formats",
        "lanes": "high for -D, -e 0, --signal TERM, CONFIG_CHANGE audit_enabled=0, rules removed without "
                 "re-adds, the daemon unregistering outside a shutdown, or web-service lineage; lead otherwise",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def __init__(self):
        super().__init__()
        self.configs: list[TypedEvent] = []                               # records of a reportable kind
        self.registrations: dict[str | None, list[float]] = defaultdict(list)   # audit daemon (re)registrations
        self.adds: dict[tuple, list[float]] = defaultdict(list)          # rule additions per (host, auid, session)

    def _event(self, e):
        if e.family == "process_exec":
            ident = _identity(e)
            if ident is None:
                self.missing_required += 1
                return
            self.evaluated += 1
            name, args, _from_exe = ident
            found = self._requests(name, args, e.get("process.cwd"))
            segments, incomplete = shell_segments(name, args)
            text_found = []
            for seg in segments:
                if seg.argv:
                    text_found += self._requests(canonical(basename(seg.argv[0])), seg.argv[1:], e.get("process.cwd"))
                for op, target in seg.redirects:
                    path = normalize_path(target, e.get("process.cwd"))
                    if op in {">", ">>", "1>", "1>>"} and path and is_under(path, AUDIT_CONFIG_PATHS):
                        how = f"write audit configuration file {path} with a shell redirect ('{op}')"
                        text_found.append(("config_file", how, "lead"))
            if incomplete:
                self.missing_required += 1
            self._exec_items(e, [(k, "audit", how, lane) for k, how, lane in found], False)
            self._exec_items(e, [(k, "audit", how, lane) for k, how, lane in text_found], True)
        elif e.family == "audit_config":
            if not e.has("audit.config.op"):
                self.missing_required += 1
                return
            self.evaluated += 1
            ts = e.ts.timestamp()
            if e.get("audit.config.setting") == "audit_pid" and str(e.get("audit.config.value")) != "0":
                self.registrations[e.host].append(ts)
            if e.get("audit.config.op") in {"add_rule", "add rule"} and e.outcome != Outcome.failure:
                self.adds[(e.host, e.get("process.auid"), e.get("process.session_id"))].append(ts)
            if self._config_kind(e) is not None:
                self.configs.append(e)
        else:
            self.evaluated += 1

    @staticmethod
    def _requests(name, args, cwd):
        if name == "auditctl":
            return auditctl_requests(args)
        out = []
        targets, _unresolved = write_targets(name, args, cwd)
        for target in targets:
            if is_under(target.path, AUDIT_CONFIG_PATHS) and not name.startswith("ch"):
                out.append(("config_file", f"write audit configuration file {target.path} ({target.form})", "lead"))
        if name in {"rm", "unlink", "shred"}:
            for operand in operands_after_options(args, set()):
                path = normalize_path(operand, cwd)
                if path and is_under(path, AUDIT_CONFIG_PATHS):
                    out.append(("config_file", f"delete audit configuration file {path} ('{name}')", "lead"))
        return out

    def retained_events(self):
        return super().retained_events() + self.configs

    def finalize(self):
        by_pid: dict[tuple, list[_Item]] = defaultdict(list)
        for item in self.items:
            if isinstance(item.event.get("process.pid"), int):
                by_pid[(item.host, item.event.get("process.pid"))].append(item)
        typed: dict[tuple, list[TypedEvent]] = defaultdict(list)
        registrations, adds = self.registrations, self.adds
        for config in sorted(self.configs, key=lambda e: (e.ts, e.id)):
            kind = self._config_kind(config)
            ts = config.ts.timestamp()
            linked = [i for i in by_pid.get((config.host, config.get("process.pid")), ()) if abs(i.ts - ts) <= 10]
            if linked:
                for item in linked:
                    item.linked.append(config)
                continue
            if kind == "unregistered":
                back = [t for t in registrations.get(config.host, ()) if t >= ts]
                if back and min(back) - ts <= RESTART_SECONDS:
                    continue                                  # the daemon restarted
            actor = str(config.get("process.login_user") or config.get("process.user")
                        or (f"audit login uid {config.get('process.auid')}" if config.has("process.auid")
                            else "no login session"))
            session = (config.get("process.auid"), config.get("process.session_id"))
            typed[(config.host, actor, kind, session)].append(config)
        out = self._group_findings(self._describe_commands)
        for key in sorted(typed, key=str):
            out.append(self._describe_records(key, typed[key], adds, registrations))
        return out

    @staticmethod
    def _config_kind(e: TypedEvent) -> str | None:
        op, setting, value = e.get("audit.config.op"), e.get("audit.config.setting"), str(e.get("audit.config.value"))
        if setting == "audit_enabled" and value == "0":
            return "disabled"
        if setting == "audit_pid" and value == "0" and str(e.get("audit.config.old")) not in {"0", "None"}:
            return "unregistered"
        if op in {"remove_rule", "remove rule"}:
            return "rules_removed"
        return None

    def _describe_commands(self, key, items: list[_Item]) -> Match:
        host, actor, _lineage_kind, form = key
        notes: list[str] = []
        commands = _unique(i.event for i in items)
        linked = sorted(_unique(e for i in items for e in i.linked), key=lambda e: (e.ts, e.id))
        hows = list(dict.fromkeys(i.form for i in items))
        text = any(i.from_text for i in items)
        claim = (f"On {host}, account '{actor}' ran {len(commands)} command(s)" + (" (some as shell command text)"
                                                                                  if text else "")
                 + f" to {'; '.join(hows[:4])}" + (f" and {len(hows) - 4} more" if len(hows) > 4 else "")
                 + f" (e.g. {_argv_summary(commands[0].get('process.argv'), 120)}); {_outcome_tally(commands)}.")
        if linked:
            applied = sum(1 for e in linked if e.outcome == Outcome.success)
            claim += (f" {len(linked)} kernel CONFIG_CHANGE record(s) from the same process(es) show the change "
                      f"({', '.join(sorted({self._config_text(e) for e in linked}))}); {applied} applied, "
                      f"{len(linked) - applied} refused or unrecorded.")
        elif form in {"delete_all_rules", "disable_auditing", "delete_rule", "delete_watch"}:
            claim += " No kernel CONFIG_CHANGE record from the same process was retrieved, so whether the change was applied is not established."
        proposed = "high" if any(i.lane == "high" for i in items) else "lead"
        lane = self._command_lane(items, proposed, notes)
        if linked and all(e.outcome == Outcome.failure for e in linked) and lane == "high":
            lane = "lead"
            notes.append("lane lowered: the kernel refused every recorded change")
        phrase = lineage_phrase(next((i.lineage for i in items if i.lineage.kind == "web"), items[0].lineage))
        if phrase:
            claim += f" Exec lineage: {phrase}."
        events = sorted(_unique([*commands[:CITE], *linked[:CITE]]), key=lambda e: (e.ts, e.id))
        predicate = [pf(c, "process.argv") for c in commands[:3]] + [pf(e, "audit.config.op") for e in linked[:2]]
        match = Match(self.id, claim, self.claim_type, events, predicate, events[0].ts, self.severity, lane,
                      "high" if linked else "medium", commands[0].entities(),
                      group_key="cmd|" + "|".join(str(p) for p in key))
        match.notes = notes
        return match

    @staticmethod
    def _config_text(e: TypedEvent) -> str:
        if e.has("audit.config.setting"):
            return (f"op={e.get('audit.config.op')} {e.get('audit.config.setting')}={e.get('audit.config.value')}"
                    + (f" old={e.get('audit.config.old')}" if e.has("audit.config.old") else ""))
        return f"op={e.get('audit.config.op')}" + (f" key={e.get('audit.key')}" if e.has("audit.key") else "")

    def _describe_records(self, key, configs: list[TypedEvent], adds, registrations) -> Match:
        host, actor, kind, session = key
        first, last = configs[0], configs[-1]
        applied = sum(1 for e in configs if e.outcome == Outcome.success)
        tally = f"{applied} applied (res=1), {len(configs) - applied} refused or unrecorded"
        lane, notes, cited = "high", [], list(configs[:CITE])
        exe = first.get("process.executable")
        by = f" by '{exe}'" if exe else ""
        if kind == "disabled":
            claim = (f"On {host}, {len(configs)} kernel CONFIG_CHANGE record(s) show auditing being switched off "
                     f"(audit_enabled=0){by} as {actor}, the first at {first.ts.isoformat()}; {tally}.")
        elif kind == "unregistered":
            claim = (f"On {host}, {len(configs)} kernel CONFIG_CHANGE record(s) show the audit daemon unregistering "
                     f"(audit_pid=0), the first at {first.ts.isoformat()}; {tally}.")
            back = [t for t in registrations.get(host, ()) if t >= first.ts.timestamp()]
            if back:
                claim += f" A daemon registered again {min(back) - first.ts.timestamp():.0f} s later."
                lane = "lead" if min(back) - first.ts.timestamp() <= RESTART_WINDOW else lane
        else:
            readded = [t for t in adds.get((host, *session), ()) if 0 <= t - last.ts.timestamp() <= self.RELOAD_SECONDS]
            claim = (f"On {host}, {len(configs)} kernel CONFIG_CHANGE record(s) show audit rules being removed{by} "
                     f"as {actor} ({first.ts.isoformat()} – {last.ts.isoformat()}; {tally}).")
            if readded:
                claim += (f" The same audit session added {len(readded)} rule(s) within {self.RELOAD_SECONDS:.0f} s "
                          "afterwards, as a rule reload does.")
                lane = "lead"
            else:
                claim += (f" No rule was added by the same audit session within {self.RELOAD_SECONDS:.0f} s "
                          "afterwards.")
        marker = self.markers.near(host, first.ts.timestamp())
        if marker and kind == "unregistered":
            claim += f" A shutdown or reboot marker on the host ({marker[1]}) is near, so this may be part of a shutdown."
            lane = "lead"
            cited.append(marker[2])
        if applied == 0 and lane == "high":
            lane = "lead"
            notes.append("lane lowered: no record shows the change applied")
        lineage = self.lineage.classify_pid(host, first.get("process.pid"), first.ts.timestamp())
        if lineage.kind == "web":
            lane = "high"
            claim += f" Exec lineage: {lineage_phrase(lineage)}."
        events = sorted(_unique(cited), key=lambda e: (e.ts, e.id))
        match = Match(self.id, claim, self.claim_type, events, [pf(e, "audit.config.op") for e in configs[:3]],
                      first.ts, self.severity, lane, "high", first.entities(),
                      group_key=f"record|{host}|{actor}|{kind}|{session}")
        match.notes = notes
        return match


# ---------------------------------------------------------------- logs and shell history

LOG_ROOTS = ("/var/log", "/run/log/journal", "/var/run/utmp", "/run/utmp")
# Live records whose loss removes login, authentication, audit or system history (rotated archives are not here).
CRITICAL_LOG_NAMES = {"wtmp", "btmp", "lastlog", "faillog", "tallylog", "utmp", "auth.log", "secure", "syslog",
                      "messages", "kern.log", "audit.log"}
CRITICAL_LOG_DIRS = ("/var/log/audit", "/var/log/journal", "/run/log/journal")
HISTORY_FILES = {".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".history", ".histfile",
                 ".python_history", ".mysql_history", ".psql_history"}
HISTORY_VARIABLES = {"HISTFILE", "HISTSIZE", "HISTFILESIZE", "SAVEHIST", "HISTCONTROL", "HISTIGNORE"}
_NULL_SOURCES = {"/dev/null", "/dev/zero"}
_FIND_FILTERS = {"-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-mtime", "-mmin", "-atime", "-amin",
                 "-ctime", "-cmin", "-newer", "-size", "-user", "-group", "-perm"}


def log_target(path: str) -> str:
    """'critical', 'log', 'history' or '' for a normalized absolute path (or a history file named by basename)."""
    if basename(path) in HISTORY_FILES:
        return "history"
    if not path.startswith("/"):
        return ""
    if path == "/var/log" or is_under(path, CRITICAL_LOG_DIRS) or path in {"/var/run/utmp", "/run/utmp"}:
        return "critical"
    if is_under(path, ("/var/log",)):
        return "critical" if basename(path) in CRITICAL_LOG_NAMES else "log"
    return ""


def _path(operand: str, cwd: str | None) -> str:
    """Normalized absolute path; a `~` operand from shell text keeps its basename, which is all a history file
    check needs."""
    if operand.startswith("~"):
        return operand
    return normalize_path(operand, cwd)


_TIME_UNITS = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600, "d": 86400, "day": 86400,
               "w": 604800, "week": 604800, "month": 2629800, "y": 31557600, "year": 31557600}
_SIZE_UNITS = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}


def _seconds(value: str) -> float | None:
    m = re.fullmatch(r"(\d+)\s*([a-z]*)", value.strip().lower())
    if not m:
        return None
    unit = m.group(2).rstrip("s") if m.group(2) not in {"s", ""} else "s"
    return int(m.group(1)) * _TIME_UNITS[unit] if unit in _TIME_UNITS else None


def _bytes(value: str) -> float | None:
    m = re.fullmatch(r"(\d+)([kmgt]?)b?", value.strip().lower())
    return int(m.group(1)) * _SIZE_UNITS[m.group(2)] if m else None


def journal_vacuum(args: list[str]) -> tuple[str, str, str] | None:
    """(category, how, lane) for `journalctl --vacuum-*` (with or without --rotate). Retention that keeps almost
    nothing (under a day, under a megabyte, one file, or a rotation first) is high; routine reclaiming is a lead."""
    values = {}
    for index, arg in enumerate(args):
        key, has, value = arg.partition("=")
        if key in {"--vacuum-time", "--vacuum-size", "--vacuum-files"}:
            values[key] = value if has else (args[index + 1] if index + 1 < len(args) else "")
    if not values:
        return None
    rotate = "--rotate" in args
    aggressive = rotate or any((k == "--vacuum-time" and (_seconds(v) or 0) < 86400)
                               or (k == "--vacuum-size" and (_bytes(v) or 0) <= 1024 ** 2)
                               or (k == "--vacuum-files" and v.isdigit() and int(v) <= 1)
                               for k, v in values.items())
    how = "'journalctl " + " ".join(f"{k}={v}" for k, v in sorted(values.items())) + (" --rotate" if rotate else "") \
        + "' (archived journal files removed)"
    return ("journal_vacuum", how, "high" if aggressive else "lead")


def log_requests(name: str, args: list[str], cwd: str | None) -> list[tuple[str, str, str, str]]:
    """(category, target, how, proposed lane) for each log or history file a command line deletes, truncates,
    overwrites, edits or links away. Readers and appends ask for nothing."""
    out: list[tuple[str, str, str, str]] = []

    def add(path: str, how: str, edit: bool = False):
        kind = log_target(path)
        if not kind:
            return
        if kind == "history":
            out.append(("history_file", path, f"{how} shell history file {path}", "high"))
        elif edit:
            out.append(("log_edit", path, f"{how} log {path}", "lead"))
        else:
            out.append(("log_wipe" if kind == "critical" else "log_change", path, f"{how} log {path}",
                        "high" if kind == "critical" else "lead"))

    if name == "journalctl":
        found = journal_vacuum(args)
        return [(found[0], "the systemd journal", found[1], found[2])] if found else []
    if name in {"rm", "unlink", "srm", "wipe"}:
        for operand in operands_after_options(args, set()):
            add(_path(operand, cwd), f"delete ('{name}')")
    elif name == "shred":
        values = {"-n", "--iterations", "-s", "--size", "--random-source"}
        removes = any(a in {"-u", "--remove"} or (a.startswith("-") and not a.startswith("--") and "u" in a)
                      for a in args)
        for operand in operands_after_options(args, values):
            add(_path(operand, cwd), "overwrite" + (" and delete" if removes else "") + " ('shred')")
    elif name == "truncate":
        size = None
        for index, arg in enumerate(args):
            if arg in {"-s", "--size"} and index + 1 < len(args):
                size = args[index + 1]
            elif arg.startswith("--size="):
                size = arg.split("=", 1)[1]
            elif arg.startswith("-s") and len(arg) > 2:
                size = arg[2:]
        for target in write_targets(name, args, cwd)[0]:
            add(target.path, "truncate to zero length ('truncate')" if size == "0" else
                f"truncate or resize ('truncate -s {size}')", edit=size != "0")
    elif name in {"cp", "install", "dd", "ln"}:
        sources = ({a[3:] for a in args if a.startswith("if=")} if name == "dd"
                   else set(operands_after_options(args, {"-t", "--target-directory", "-S", "--suffix", "-m",
                                                          "--mode", "-o", "--owner", "-g", "--group"})[:-1]))
        if sources & _NULL_SOURCES:
            for target in write_targets(name, args, cwd)[0]:
                if not target.assumed:
                    add(target.path, f"replace with {min(sources & _NULL_SOURCES)} ('{name}')")
    elif name == "mv":
        operands = operands_after_options(args, {"-t", "--target-directory", "-S", "--suffix"})
        to_directory = any(a == "-t" or a.startswith("--target-directory") for a in args)
        for operand in operands if to_directory else operands[:-1]:
            add(_path(operand, cwd), "move away ('mv')")
    elif name in {"sed", "perl"}:
        for target in write_targets(name, args, cwd)[0]:
            add(target.path, f"edit in place ('{name} -i')", edit=True)
    elif name in {"tee", "sponge"} and not ({"-a", "--append"} & set(args)):
        for target in write_targets(name, args, cwd)[0]:
            add(target.path, f"overwrite ('{name}')")
    elif is_editor(name):
        for target in write_targets(name, args, cwd)[0]:
            if log_target(target.path) in {"critical", "history"}:
                how = f"open {target.path} in the editor '{name}' (reading and editing cannot be told apart)"
                out.append(("log_editor", target.path, how, "lead"))
    elif name == "find":
        starts = []
        for arg in args:
            if arg.startswith("-") or arg in {"(", "!", ")"}:
                break
            starts.append(arg)
        exec_cmd = next((args[i + 1] for i, a in enumerate(args[:-1]) if a in {"-exec", "-execdir"}), "")
        deletes = "-delete" in args or basename(exec_cmd) in {"rm", "shred", "truncate", "unlink"}
        if deletes:
            filtered = bool(_FIND_FILTERS & set(args))
            action = "-delete" if "-delete" in args else f"-exec {basename(exec_cmd)}"
            suffix = " with name or age filters" if filtered else ""
            named = {args[i + 1] for i, a in enumerate(args[:-1]) if a in {"-name", "-iname"}}
            for history in sorted(named & HISTORY_FILES):
                out.append(("history_file", history, f"delete shell history files named {history} ('find {action}')",
                            "high"))
            for start in starts:
                path = _path(start, cwd)
                kind = log_target(path)
                if kind:
                    category = ("log_wipe" if kind == "critical" and not filtered else
                                "history_file" if kind == "history" else "log_change")
                    how = f"delete files under {path} ('find {action}'{suffix})"
                    out.append((category, path, how, "high" if category in {"log_wipe", "history_file"} else "lead"))
    elif name == "history":
        if "-c" in args or any(a.startswith("-") and "c" in a[1:] for a in args):
            out.append(("history_off", "shell history", "clear the shell's in-memory history ('history -c')", "lead"))
        if "-w" in args and "/dev/null" in args:
            out.append(("history_off", "shell history", "write the history to /dev/null ('history -w /dev/null')",
                        "lead"))
    elif name == "unset":
        names = [a for a in args if a in HISTORY_VARIABLES]
        if names:
            out.append(("history_off", "shell history", f"unset {', '.join(names)} ('unset')", "lead"))
    elif name == "export":
        out += _history_assignments([a for a in args if "=" in a])
    elif name == "set" and "+o" in args and "history" in args:
        out.append(("history_off", "shell history", "switch history recording off ('set +o history')", "lead"))
    return out


def _history_assignments(words: list[str]) -> list[tuple[str, str, str, str]]:
    out = []
    for word in words:
        variable, _, value = word.partition("=")
        if ((variable == "HISTFILE" and value in {"/dev/null", ""})
                or (variable in {"HISTSIZE", "HISTFILESIZE", "SAVEHIST"} and value in {"0", ""})
                or (variable == "HISTIGNORE" and value == "*")):
            out.append(("history_off", "shell history", f"set {variable}={value or '(empty)'}", "lead"))
    return out


class LogOrHistoryClearing(_TamperRule):
    id = "host.log_or_history_clearing"
    version = "1"
    title = "Log or shell history deleted, truncated, overwritten or switched off (command or shell text)"
    families = ("process_exec",)
    severity, lane = "high", "high"
    attack = ("T1685.006", "T1070.003", "T1690")
    positive_only_reason = (
        "the deleting or truncating command and its target are read from argv and shell command text; files can "
        "be removed in ways exec records do not show (shell built-ins in an interactive shell, programs deleting "
        "files from their own code), so a window without matches proves nothing")
    benign = ("disk-space clean-up of old logs by administrators or scripts", "package removal purging its logs",
              "log rotation helpers", "privacy settings that switch history off for service accounts")
    next_checks = ("what the account did just before the clearing (the activity the logs held)",
                   "other copies of the cleared logs (remote collection, backups)",
                   "the session that issued the command")
    card: ClassVar[dict] = {
        "behavior": "log files under /var/log, login records (wtmp/btmp/lastlog/utmp), the journal, or shell "
                    "history files were deleted, truncated, overwritten, edited in place, moved away or linked to "
                    "/dev/null; the journal was vacuumed; or shell text switched history recording off",
        "telemetry": "auditd process_exec (process.argv, process.executable, process.cwd, process.pid, "
                     "process.ppid, process.user): present; lab profile: 0 vacuum, shred or truncate runs on "
                     "/var/log; file-change records are not read by this rule",
        "fidelity": "a command was started on the file, or shell text names the action; the file change itself is "
                    "not established",
        "benign_and_cost": "clean-up of rotated logs (lead), package purge (lead under package lineage), routine "
                           "journal vacuuming with normal retention (lead)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "what the account did before the clearing; whether remote copies of the logs exist",
        "adds": "no earlier rule covered log or history clearing",
        "research_basis": "ATT&CK Enterprise 20.0 T1685.006 (revokes T1070.002), T1070.003, T1690 (revokes "
                          "T1562.003); SigmaHQ Linux rules on clearing logs and history and Atomic Red Team "
                          "T1070.002/T1070.003 procedures as fixture ideas (reimplemented; upstream commits not "
                          "re-verified offline)",
        "lanes": "high for wiping a live critical log (login records, auth, syslog, audit, journal, /var/log "
                 "itself), shell history files, aggressive journal vacuuming, or any form under web-service "
                 "lineage; lead for other logs, editors on logs, in-place edits, history variables and built-ins, "
                 "and anything under package, cloud-init or log-rotation lineage",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def _event(self, e):
        ident = _identity(e)
        if ident is None:
            self.missing_required += 1
            return
        self.evaluated += 1
        name, args, _from_exe = ident
        cwd = e.get("process.cwd")
        found = log_requests(name, args, cwd)
        segments, incomplete = shell_segments(name, args)
        text_found = []
        for seg in segments:
            text_found += _history_assignments(seg.assignments)
            if seg.argv:
                text_found += log_requests(canonical(basename(seg.argv[0])), seg.argv[1:], cwd)
            for op, target in seg.redirects:
                if op in {">", "1>"}:
                    path = _path(target, cwd)
                    kind = log_target(path)
                    if kind:
                        category = {"history": "history_file", "critical": "log_wipe"}.get(kind, "log_change")
                        text_found.append((category, path, f"truncate or overwrite {'shell history file' if kind == 'history' else 'log'} {path} with a shell redirect ('{op}')",
                                           "high" if kind in {"history", "critical"} else "lead"))
        if incomplete:
            self.missing_required += 1
        self._exec_items(e, [(c, t, how, lane) for c, t, how, lane in found], False)
        self._exec_items(e, [(c, t, how, lane) for c, t, how, lane in text_found], True)

    def finalize(self):
        return self._group_findings(self._describe)

    def _describe(self, key, items: list[_Item]) -> Match:
        host, actor, _lineage_kind, category = key
        notes: list[str] = []
        commands = _unique(i.event for i in items)
        hows = list(dict.fromkeys(i.form for i in items))
        text_only = all(i.from_text for i in items)
        claim = (f"On {host}, account '{actor}' "
                 + ("started shell(s) with command text" if text_only else f"ran {len(commands)} command(s)")
                 + f" to {'; '.join(hows[:5])}" + (f" and {len(hows) - 5} more" if len(hows) > 5 else "")
                 + f" (e.g. {_argv_summary(commands[0].get('process.argv'), 120)}); {_outcome_tally(commands)}.")
        claim += (" The command text shows intent; whether it ran is not established by these records."
                  if text_only else " Whether the files changed is not established by exec records.")
        proposed = "high" if any(i.lane == "high" for i in items) else "lead"
        lane = self._command_lane(items, proposed, notes)
        phrase = lineage_phrase(next((i.lineage for i in items if i.lineage.kind == "web"), items[0].lineage))
        if phrase:
            claim += f" Exec lineage: {phrase}."
        events = sorted(commands[:CITE], key=lambda e: (e.ts, e.id))
        if len(commands) > CITE:
            claim += f" The earliest {CITE} records are cited."
        match = Match(self.id, claim, "script_content" if text_only else self.claim_type, events,
                      [pf(c, "process.argv") for c in events[:3]], events[0].ts, self.severity, lane,
                      "medium" if text_only else "high", commands[0].entities(),
                      group_key="|".join(str(p) for p in key))
        technique = {"history_file": "T1070.003", "history_off": "T1690"}.get(category, "T1685.006")
        match.notes = notes + [technique]
        return match


TAMPER_PLAYBOOKS = [SecurityOrLoggingServiceStop, AuditRulesTamper, LogOrHistoryClearing]
