"""Anchor-gated context rules. They never run in the full-window sweep.

Each rule judges a record only after it is reached through an explicit typed link from an admitted anchor.
Programs and file operands are identified from the kernel-recorded `process.executable` and token-aware argv
parsing (`romulus.detect.linux_argv`), never from substrings of a serialized record. All of these rules read
argv or script text, so they are positive-only: they publish findings worded to what the text shows and never
assure a complete negative.

Findings are aggregated per session so that one foothold does not produce one finding per command, and lanes
follow a deliberate policy: a broad rule sits at `lead` until stronger context (a discovery burst, an
unbrokered root process, a staged-then-exfiltrated file, a client-plus-connect to an admin port) raises it.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import ClassVar

from romulus.detect.base import (
    ContextAnchor,
    ContextLink,
    ContextPlaybook,
    Match,
    basename,
    outcome_phrase,
    pf,
)
from romulus.detect.host import is_internal
from romulus.detect.linux_argv import (
    is_suid_perm,
    is_under,
    nc_destination,
    normalize_path,
    operands_after_options,
    program,
    read_operands,
    scp_remote_host,
    split_flags,
    ssh_destination,
    tar_spec,
)
from romulus.evidence.shellparse import parse_script, shell_script_of
from romulus.evidence.typed import Outcome, TypedEvent

# Anchor classes that denote a host-attributed foothold whose session or lineage is worth judging. A
# network-only anchor ("network_observation" / "indicator") has no host session, so these rules never claim
# its context.
ANCHOR_HOST = (
    "initial_access", "remote_login", "web_shell", "execution", "credential_access",
    "persistence", "lateral_movement",
)
HOST_LINKS = ("login_session", "process_lineage")
EXEC_REQUIRED = {"process_exec": ("process.executable", "process.argv")}

# Directories whose enumeration is post-access reconnaissance rather than routine listing.
SENSITIVE_DIRS = ("/etc", "/root", "/home", "/var/www", "/opt", "/srv", "/boot", "/var/log", "/var/lib")
# Elevation helpers: a root process brokered by one of these is a normal elevation, not an exploit signal.
ELEVATION_HELPERS = {"sudo", "su", "pkexec", "doas"}
CITE_LIMIT = 12


def _context_suffix(anchor: ContextAnchor, link: ContextLink) -> str:
    if link.strength == "inferred":
        return (f"This is a hypothesis linked to {anchor.id} by inferred {link.link_type} link {link.id}; "
                "no observed session or lineage key proves the actor is the same.")
    return f"It was reached from {anchor.id} through observed {link.link_type} link {link.id}."


def _session_key(event: TypedEvent, anchor: ContextAnchor) -> tuple:
    """Group key for one session/lineage: host, boot id (when typed) and audit session id. When no session id
    is typed (a lineage link), the anchor keeps lineages on one host apart."""
    session = event.get("process.session_id")
    boot = event.get("host.boot.id")
    return (event.host, boot, session if session is not None else f"lin:{anchor.id}")


def _group_id(key: tuple) -> str:
    host, boot, session = key
    return f"{host}|{boot}|{session}"


def _outcome_summary(events: list[TypedEvent]) -> tuple[str, bool, bool]:
    counts = {Outcome.success: 0, Outcome.failure: 0, Outcome.unknown: 0}
    for event in events:
        counts[event.outcome] = counts.get(event.outcome, 0) + 1
    text = (f"recorded exec outcomes: {counts[Outcome.success]} succeeded, {counts[Outcome.failure]} failed, "
            f"{counts[Outcome.unknown]} unknown")
    return text, counts[Outcome.success] > 0, counts[Outcome.failure] > 0


def _cite(events: list[TypedEvent]) -> list[TypedEvent]:
    return sorted(events, key=lambda event: (event.ts, event.id))[:CITE_LIMIT]


def _predicate(events: list[TypedEvent], *fields: str):
    out = []
    for event in events:
        for name in fields:
            if event.has(name):
                out.append(pf(event, name))
        if out:
            break
    return out


class _HostContextRule(ContextPlaybook):
    """Shared base for the host-session context rules (exec and socket evidence)."""

    anchor_class = "execution"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    assures_negative = False
    claim_type = "correlated_observation"

    def _finish(self, match: Match, cited: list[TypedEvent], anchor: ContextAnchor,
                link: ContextLink) -> Match:
        # M7: a failed exec cannot carry a high-lane claim on its own.
        _summary, succeeded, failed = _outcome_summary(cited)
        if match.proposed_lane == "high" and failed and not succeeded:
            match.proposed_lane, match.severity = "lead", "medium"
            match.notes.append("lane lowered: the recorded exec(s) failed")
        return match


# ================================================================================================
# Post-access discovery (T1033, T1082, T1016, T1049, T1057, T1083, T1087, T1069, T1007, T1518,
# T1135, T1201, T1680).
# ================================================================================================

_NAME_DISCOVERY = {
    "whoami": ("T1033", "current-user discovery"), "logname": ("T1033", "current-user discovery"),
    "id": ("T1033", "current-user and group discovery"), "who": ("T1033", "logged-in-user discovery"),
    "w": ("T1033", "logged-in-user discovery"), "users": ("T1033", "logged-in-user discovery"),
    "last": ("T1033", "login-history discovery"), "lastlog": ("T1033", "login-history discovery"),
    "groups": ("T1069", "permission-group enumeration"),
    "hostnamectl": ("T1082", "host-information discovery"), "uname": ("T1082", "system-information discovery"),
    "arch": ("T1082", "system-information discovery"), "lscpu": ("T1082", "system-information discovery"),
    "lshw": ("T1082", "system-information discovery"), "dmidecode": ("T1082", "system-information discovery"),
    "lsb_release": ("T1082", "OS-version discovery"), "iwconfig": ("T1016", "network-configuration discovery"),
    "netstat": ("T1049", "network-connection discovery"), "ss": ("T1049", "network-connection discovery"),
    "ps": ("T1057", "process discovery"), "pstree": ("T1057", "process discovery"),
    "pgrep": ("T1057", "process discovery"), "top": ("T1057", "process discovery"),
    "htop": ("T1057", "process discovery"), "df": ("T1680", "local-storage discovery"),
    "lsblk": ("T1680", "local-storage discovery"), "blkid": ("T1680", "local-storage discovery"),
    "tree": ("T1083", "file-and-directory discovery"), "locate": ("T1083", "file-and-directory discovery"),
    "showmount": ("T1135", "network-share discovery"),
}
_DISCOVERY_FILES = {
    "/etc/passwd": ("T1087", "local-account enumeration"),
    "/etc/group": ("T1069", "permission-group enumeration"),
    "/etc/os-release": ("T1082", "OS-version discovery"),
    "/etc/lsb-release": ("T1082", "OS-version discovery"),
    "/etc/issue": ("T1082", "system-banner discovery"),
    "/etc/issue.net": ("T1082", "system-banner discovery"),
    "/proc/version": ("T1082", "kernel-version discovery"),
    "/proc/cpuinfo": ("T1082", "system-information discovery"),
    "/proc/meminfo": ("T1082", "system-information discovery"),
    "/etc/resolv.conf": ("T1016", "network-configuration discovery"),
    "/etc/hosts": ("T1016", "network-configuration discovery"),
    "/etc/networks": ("T1016", "network-configuration discovery"),
    "/etc/login.defs": ("T1201", "password-policy discovery"),
    "/etc/pam.d/common-password": ("T1201", "password-policy discovery"),
    "/etc/exports": ("T1135", "network-share discovery"),
    "/etc/fstab": ("T1680", "local-storage discovery"),
}
_IP_SHOW_OBJECTS = {"addr", "a", "address", "link", "l", "route", "r", "neigh", "n", "rule", "maddr", "maddress"}
_IP_CHANGE_VERBS = {"add", "del", "delete", "set", "change", "replace", "flush", "append"}
_SYSTEMCTL_READ = {"list-units", "list-unit-files", "list-timers", "list-sockets", "status", "is-active",
                   "is-enabled", "is-failed", "show", "cat", "get-default"}
_ENV_VALUE = {"-u", "--unset", "-C", "--chdir"}
_PKG_READERS = {
    "dpkg": lambda flags, ops: bool(flags & {"-l", "--list", "-L", "--listfiles"}),
    "dpkg-query": lambda flags, ops: bool(flags & {"-l", "--list", "-W", "--show"}),
    "rpm": lambda flags, ops: "-q" in flags and "-a" in flags,
    "snap": lambda flags, ops: ops[:1] == ["list"],
    "flatpak": lambda flags, ops: ops[:1] == ["list"],
    "pip": lambda flags, ops: ops[:1] in (["list"], ["freeze"]),
    "pip3": lambda flags, ops: ops[:1] in (["list"], ["freeze"]),
    "apt": lambda flags, ops: ops[:1] == ["list"],
    "yum": lambda flags, ops: ops[:1] == ["list"],
    "dnf": lambda flags, ops: ops[:1] == ["list"],
}


def _find_is_suid_search(args: list[str]) -> bool:
    return any(args[i] == "-perm" and i + 1 < len(args) and is_suid_perm(args[i + 1])
               for i in range(len(args)))


def _ls_is_sensitive(args: list[str], cwd: str | None) -> bool:
    _flags, operands = split_flags(args)
    for operand in operands:
        path = normalize_path(operand, cwd)
        if path and (is_under(path, SENSITIVE_DIRS) or path.endswith("/.ssh")):
            return True
    return False


def _env_is_discovery(args: list[str]) -> bool:
    # env/printenv only enumerate when no command follows. `#!/usr/bin/env python3` runs as [env, python3, x].
    return all("=" in operand for operand in operands_after_options(args, _ENV_VALUE))


def classify_discovery(name: str, args: list[str], cwd: str | None) -> tuple[str, str] | None:
    """(ATT&CK technique, behaviour) for a discovery command, or None. Argument-sensitive programs are
    classified by subcommand/flags so a modifying form is never read as discovery."""
    if name in _NAME_DISCOVERY:
        return _NAME_DISCOVERY[name]
    flags, operands = split_flags(args)
    if name == "printenv":
        return ("T1082", "environment-variable enumeration")
    if name == "env":
        return ("T1082", "environment-variable enumeration") if _env_is_discovery(args) else None
    if name == "hostname":
        return ("T1082", "host-information discovery") if not operands else None
    if name == "ifconfig":
        return (None if set(operands) & {"up", "down", "add", "del", "delete"}
                else ("T1016", "network-configuration discovery"))
    if name == "route":
        return (None if set(operands) & {"add", "del", "delete", "flush"}
                else ("T1016", "network-configuration discovery"))
    if name == "arp":
        blocked = bool(flags & {"-d", "-s"}) or "--delete" in args or "--set" in args
        return None if blocked else ("T1016", "network-configuration discovery")
    if name == "ip":
        if operands and operands[0] in _IP_SHOW_OBJECTS and not (set(operands) & _IP_CHANGE_VERBS):
            return ("T1016", "network-configuration discovery")
        return None
    if name == "lsof":
        return ("T1049", "network-connection discovery") if any(f.startswith("-i") for f in flags) else None
    if name == "getent":
        return {"passwd": ("T1087", "local-account enumeration"),
                "group": ("T1069", "permission-group enumeration")}.get(operands[0] if operands else "")
    if name == "systemctl":
        return ("T1007", "system-service discovery") if operands and operands[0] in _SYSTEMCTL_READ else None
    if name == "service":
        return ("T1007", "system-service discovery") if "--status-all" in args else None
    if name == "crontab":
        return ("T1007", "scheduled-task (cron) discovery") if "-l" in flags else None
    if name in _PKG_READERS:
        return ("T1518", "installed-software discovery") if _PKG_READERS[name](flags, operands) else None
    if name == "chage":
        return ("T1201", "password-policy discovery") if "-l" in flags else None
    if name == "smbclient":
        return ("T1135", "network-share discovery") if "-L" in flags else None
    if name == "find":
        return None if _find_is_suid_search(args) else ("T1083", "file-and-directory discovery")
    if name in {"ls", "dir"}:
        return ("T1083", "file-and-directory discovery") if _ls_is_sensitive(args, cwd) else None
    for path in read_operands(name, args, cwd):
        if path in _DISCOVERY_FILES:
            return _DISCOVERY_FILES[path]
    return None


class PostAccessDiscovery(_HostContextRule):
    id = "context.post_access_discovery"
    version = "3"
    title = "Discovery commands in an anchored session or process lineage"
    anchor_class = "execution"
    families = ("process_exec",)
    positive_only_reason = ("discovery commands are identified from the executable and argv tokens and are only "
                            "evaluated on records reached through an anchor link; absence outside that linked "
                            "scope, or in records with no exec, proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1033", "T1082", "T1016", "T1049", "T1057", "T1083", "T1087", "T1069",
              "T1007", "T1518", "T1135", "T1201", "T1680")
    benign = ("administrator troubleshooting after an approved login",
              "inventory, monitoring and compliance scripts", "package-manager list queries")
    next_checks = ("privilege probing or credential-file reads by the same session",
                   "network flows the session opens next")

    def match_linked(self, anchor, link, events):
        groups: dict[tuple, list[tuple[str, str, TypedEvent]]] = defaultdict(list)
        for event in self.eligible(events, EXEC_REQUIRED):
            prog = program(event)
            if prog is None:
                continue
            found = classify_discovery(prog.name, prog.args, event.get("process.cwd"))
            if found is not None:
                groups[_session_key(event, anchor)].append((found[0], found[1], event))

        out = []
        for key, hits in groups.items():
            techniques = sorted({technique for technique, _behavior, _event in hits})
            behaviors = sorted({behavior for _technique, behavior, _event in hits})
            cited = _cite([event for _t, _b, event in hits])
            summary, _succeeded, _failed = _outcome_summary([event for _t, _b, event in hits])
            lane = "high" if len(techniques) >= 3 else "lead"
            burst = ("a discovery burst" if lane == "high"
                     else "discovery activity")
            claim = (f"On {key[0]}, {burst}: {len(hits)} command(s) across {len(techniques)} distinct "
                     f"discovery class(es) [{', '.join(behaviors)}] ran in this session. {summary}. "
                     f"{_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate(cited, "process.executable", "process.argv"), cited[0].ts,
                          "high" if lane == "high" else "medium", lane, "medium",
                          cited[0].entities(), group_key=f"discovery|{_group_id(key)}")
            match.notes.extend(techniques)
            out.append(self._finish(match, cited, anchor, link))
        return out


# ================================================================================================
# Privilege probing and escalation (T1548, T1548.001, T1548.003, T1068).
# ================================================================================================

_SUDO_VALUE_OPTS = {"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R"}
_SUDO_VALUE_LETTERS = set("ugUChprtDR")


def _sudo_is_list(args: list[str]) -> bool:
    """True when sudo's own options request --list, parsing only sudo options and stopping at the command."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--list" or arg.startswith("--list"):
            return True
        if arg in {"-l", "-ll"}:
            return True
        if arg in _SUDO_VALUE_OPTS:
            index += 2
            continue
        if arg.startswith("--"):
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            letters = set(arg[1:])
            if letters & _SUDO_VALUE_LETTERS:
                return False                      # a value-taking option; not a plain -l
            if "l" in letters:
                return True
            index += 1
            continue
        return False                              # first operand is the command sudo will run
    return False


def _root_identity(event: TypedEvent) -> str | None:
    """The typed field that shows effective uid 0, or None. euid is preferred when both are present."""
    if str(event.get("process.euid")) == "0":
        return "process.euid"
    if str(event.get("process.uid")) == "0":
        return "process.uid"
    return None


def _login_user_is_nonroot(event: TypedEvent) -> bool:
    auid = event.get("process.auid")
    return auid is not None and str(auid) not in {"0", "4294967295", "-1"}


def _classify_probe(prog, event: TypedEvent) -> tuple[str, str] | None:
    name, args = prog.name, prog.args
    if name == "sudo" and _sudo_is_list(args):
        return ("T1548.003", "the privilege-listing command 'sudo -l'")
    if name == "find" and _find_is_suid_search(args):
        return ("T1548.001", "a 'find' search for setuid/setgid binaries (a privilege-escalation vector scan)")
    if name == "getcap":
        return ("T1548", "a 'getcap' enumeration of file capabilities (a privilege-escalation vector scan)")
    if name == "pkexec":
        return ("T1548", "an invocation of the setuid helper 'pkexec'")
    for path in read_operands(name, args, event.get("process.cwd")):
        if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
            return ("T1548.003", f"a read of the sudoers configuration file {path}")
    return None


class PrivilegeProbing(_HostContextRule):
    id = "context.privilege_probing"
    version = "2"
    title = "Privilege probing or escalation in an anchored session or lineage"
    families = ("process_exec",)
    positive_only_reason = ("the probing commands and the setuid/sudo/capability operands are identified from "
                            "argv, and an effective-uid-0 process is visible only when its exec was recorded; "
                            "absence proves neither that privileges were not probed nor that none were gained")
    severity, lane = "medium", "lead"
    attack = ("T1548", "T1548.001", "T1548.003", "T1068")
    benign = ("an administrator checking their own sudo rights or auditing setuid binaries",
              "configuration-management and vulnerability-scanning tools",
              "a legitimate sudo or su to an admin account")
    next_checks = ("whether a listed sudo rule or setuid binary was then run",
                   "credential-file reads by the same session",
                   "commands the root-privileged process ran next")

    def match_linked(self, anchor, link, events):
        eligible = self.eligible(events, EXEC_REQUIRED)
        probes: dict[tuple, list[tuple[str, str, TypedEvent]]] = defaultdict(list)
        helper_ts: dict[tuple, float] = {}
        root_events: dict[tuple, TypedEvent] = {}
        for event in sorted(eligible, key=lambda item: (item.ts, item.id)):
            prog = program(event)
            if prog is None:
                continue
            key = _session_key(event, anchor)
            if prog.name in ELEVATION_HELPERS and key not in helper_ts:
                helper_ts[key] = event.ts.timestamp()
            found = _classify_probe(prog, event)
            if found is not None:
                probes[key].append((found[0], found[1], event))
            if (key not in root_events and _root_identity(event) is not None
                    and _login_user_is_nonroot(event)):
                root_events[key] = event

        out = []
        for key, hits in probes.items():
            techniques = sorted({technique for technique, _b, _e in hits})
            behaviors = sorted({behavior for _t, behavior, _e in hits})
            cited = _cite([event for _t, _b, event in hits])
            summary, _s, _f = _outcome_summary([event for _t, _b, event in hits])
            claim = (f"On {key[0]}, privilege probing in this session: {', '.join(behaviors)}. {summary}. "
                     f"{_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate(cited, "process.executable", "process.argv"), cited[0].ts,
                          "medium", "lead", "medium", cited[0].entities(),
                          group_key=f"privprobe|{_group_id(key)}")
            match.notes.extend(techniques)
            out.append(self._finish(match, cited, anchor, link))

        for key, event in root_events.items():
            field = _root_identity(event)
            brokered = key in helper_ts and helper_ts[key] <= event.ts.timestamp()
            lane = "lead" if brokered else "high"
            auid = event.get("process.auid")
            broker = ("an elevation helper (sudo/su/pkexec/doas) earlier in the session brokered it"
                      if brokered else "no elevation helper preceded it in the session (an exploit signal)")
            claim = (f"On {key[0]}, a process ran with {field.split('.')[-1]}=0 (root) while the session's "
                     f"kernel-recorded login user is the non-root account auid={auid}; {broker}. "
                     f"{outcome_phrase(event)}. {_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, [event],
                          _predicate([event], field, "process.auid", "process.executable"), event.ts,
                          "high" if lane == "high" else "medium", lane, "medium", event.entities(),
                          group_key=f"euid0|{_group_id(key)}")
            match.notes.append("T1548")
            if not brokered:
                match.notes.append("T1068")
            out.append(self._finish(match, [event], anchor, link))
        return out


# ================================================================================================
# Credential access (T1003.008, T1552.001, T1552.003, T1552.004, T1555.003, T1555.005).
# ================================================================================================

_SHADOW_SET = {"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/security/opasswd"}
_HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".python_history",
                  ".mysql_history", ".psql_history", ".rediscli_history"}
_PROC_MEM = re.compile(r"^/proc/\d+/mem$")
_PROC_SHADOW = re.compile(r"^/proc/\d+/root/etc/g?shadow$")


def classify_credential(path: str) -> tuple[str, str, str] | None:
    """(technique, lane, description) for a credential-store read, or None."""
    low = path.lower()
    name = basename(path)
    if path in _SHADOW_SET:
        return ("T1003.008", "high", f"the local password-hash file {path}")
    if _PROC_MEM.match(path):
        return ("T1003", "high", f"process memory via {path}")
    if _PROC_SHADOW.match(path):
        return ("T1003.008", "high", f"the host password-hash file through {path}")
    if (name.startswith("id_") and not name.endswith(".pub")) or \
            (name.startswith("ssh_host_") and name.endswith("_key")) or name == "identity":
        return ("T1552.004", "high", f"the private key file {path}")
    if path.startswith("/etc/ssl/private/") and name.endswith((".key", ".pem")):
        return ("T1552.004", "high", f"the private key file {path}")
    if name.endswith(".keytab") or path == "/etc/krb5.keytab":
        return ("T1552.004", "high", f"the Kerberos keytab {path}")
    if re.match(r"^/tmp/krb5cc_", path):
        return ("T1552.004", "high", f"the Kerberos credential cache {path}")
    if "/.gnupg/" in path and ("/private-keys-v1.d/" in path or name.startswith("secring")
                               or name.endswith(".key")):
        return ("T1552.004", "high", f"a GnuPG private-key store {path}")
    if name in _HISTORY_NAMES:
        return ("T1552.003", "lead", f"the shell/application history file {path}")
    if low.endswith("/.netrc"):
        return ("T1552.001", "lead", f"the .netrc credential file {path}")
    for suffix, desc in (("/.aws/credentials", "AWS credentials"), ("/.git-credentials", "stored git credentials"),
                         ("/.pgpass", "stored PostgreSQL credentials"),
                         ("/.docker/config.json", "a Docker registry auth config"),
                         ("/.kube/config", "a Kubernetes client config with credentials")):
        if low.endswith(suffix):
            return ("T1552.001", "lead", f"{desc} ({path})")
    if name in {"logins.json", "key4.db"} or low.endswith("/login data"):
        return ("T1555.003", "lead", f"a browser saved-login store {path}")
    if "/.password-store/" in path or "/.local/share/keyrings/" in low:
        return ("T1555.005", "lead", f"a password-manager/keyring store {path}")
    return None


class CredentialAccessInContext(_HostContextRule):
    id = "context.credential_access"
    version = "2"
    title = "Credential-store read in an anchored session or lineage"
    anchor_class = "credential_access"
    families = ("process_exec",)
    positive_only_reason = ("the reader and the credential file are identified from argv, not from a file-access "
                            "record, and a credential store can be opened in ways argv does not show; absence "
                            "proves nothing")
    severity, lane = "high", "high"
    attack = ("T1003", "T1003.008", "T1552.001", "T1552.003", "T1552.004", "T1555.003", "T1555.005")
    benign = ("an administrator or backup job reading configuration or key files",
              "a user viewing their own shell history")
    next_checks = ("staging, encoding or outbound transfer of what was read",
                   "use of a read SSH key to log in to another host",
                   "the other commands in the same session")

    def match_linked(self, anchor, link, events):
        groups: dict[tuple, list[tuple[str, str, TypedEvent]]] = defaultdict(list)
        for event in self.eligible(events, EXEC_REQUIRED):
            prog = program(event)
            if prog is None:
                continue
            for path in read_operands(prog.name, prog.args, event.get("process.cwd")):
                found = classify_credential(path)
                if found is not None:
                    technique, lane, desc = found
                    groups[(_session_key(event, anchor), technique, lane)].append((desc, event))
                    break

        out = []
        for (key, technique, lane), hits in groups.items():
            cited = _cite([event for _desc, event in hits])
            descs = sorted({desc for desc, _event in hits})
            summary, _s, _f = _outcome_summary([event for _desc, event in hits])
            claim = (f"On {key[0]}, a file-reading tool was run against {', '.join(descs)} in this session. "
                     f"{summary}. {_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate(cited, "process.executable", "process.argv"), cited[0].ts,
                          "high" if lane == "high" else "medium", lane, "medium", cited[0].entities(),
                          group_key=f"cred|{_group_id(key)}|{technique}")
            match.notes.append(technique)
            out.append(self._finish(match, cited, anchor, link))
        return out


# ================================================================================================
# Staging and transfer (T1560.001, T1074.001, T1027.013, T1048, T1570, T1021.004).
# ================================================================================================

_ARCHIVERS = {"tar", "zip", "7z", "7za", "cpio", "pax"}
_COMPRESSORS = {"gzip", "bzip2", "xz", "zstd", "pigz", "lz4", "compress"}
_ENCODERS = {"base64", "base32", "xxd", "uuencode"}
_DECODE_FLAGS = {"-d", "--decode", "--uncompress", "-r"}


def _sensitive_input(inputs: list[str], cwd: str | None) -> str | None:
    for item in inputs:
        path = normalize_path(item, cwd)
        if path and is_under(path, SENSITIVE_DIRS):
            return path
    return None


def _shell_devtcp_target(event: TypedEvent) -> str | None:
    """A /dev/tcp or /dev/udp redirection target inside a shell -c command's script text."""
    argv = event.get("process.argv")
    if not isinstance(argv, list):
        return None
    script = shell_script_of([str(item) for item in argv])
    if not isinstance(script, str):
        return None
    parsed = parse_script(script)
    for command in parsed.commands():
        for _op, target in command.redirects:
            if target.startswith(("/dev/tcp/", "/dev/udp/")):
                return target
    return None


def classify_staging(prog, event: TypedEvent) -> tuple[str, str, str] | None:
    """(technique, kind, description) where kind is 'stage' or 'transfer', or None. 'stage' is reported only
    for a sensitive input."""
    name, args = prog.name, prog.args
    cwd = event.get("process.cwd")
    flags, _operands = split_flags(args)
    if name == "tar":
        staging, inputs = tar_spec(args)
        sensitive = _sensitive_input(inputs, cwd) if staging else None
        if sensitive:
            return ("T1560.001", "stage", f"an archive over the sensitive path {sensitive}")
        return None
    if name in _ARCHIVERS or name in _COMPRESSORS:
        if flags & _DECODE_FLAGS or name in {"gunzip", "bunzip2", "unxz", "unzip", "zcat", "lzcat"}:
            return None
        _flags, operands = split_flags(args)
        sensitive = _sensitive_input(operands, cwd)
        if sensitive:
            return ("T1560.001", "stage", f"an archive/compression command over the sensitive path {sensitive}")
        return None
    if name in _ENCODERS:
        if flags & _DECODE_FLAGS:
            return None
        _flags, operands = split_flags(args)
        sensitive = _sensitive_input(operands, cwd)
        if sensitive:
            return ("T1027.013", "stage", f"an encoding command ('{name}') over the sensitive path {sensitive}")
        return None
    if name in {"scp", "sftp", "rsync"}:
        host = scp_remote_host(name, args)
        if host:
            technique = "T1021.004" if name in {"scp", "sftp"} else "T1570"
            return (technique, "transfer", f"an outbound '{name}' transfer to remote host '{host}'")
        return None
    if name == "curl":
        if flags & {"-T", "--upload-file", "-F", "--form"} or any(
                a.startswith(("-d", "--data")) and "@" in _value_of(args, a) for a in args):
            files = _upload_files(args, {"-T", "--upload-file"}, data_flags=True)
            return ("T1048", "transfer", f"an outbound 'curl' invoked with upload options naming file(s) {files}")
        return None
    if name == "wget":
        if flags & {"--post-file", "--body-file"} or any(a.startswith(("--post-file=", "--body-file=",
                                                                        "--post-data=")) for a in args) \
                or "--post-data" in flags:
            files = _upload_files(args, {"--post-file", "--body-file"}, data_flags=False)
            return ("T1048", "transfer", f"an outbound 'wget' invoked with upload options naming file(s) {files}")
        return None
    if name == "nc":
        host, listen = nc_destination(args)
        if host and not listen:
            return ("T1048", "transfer", f"an outbound 'nc' client connection to '{host}'")
        return None
    target = _shell_devtcp_target(event)
    if target is not None:
        return ("T1048", "transfer", f"shell command text that redirects to {target}")
    return None


def _value_of(args: list[str], flag: str) -> str:
    if "=" in flag:
        return flag.split("=", 1)[1]
    if flag.startswith("-d") and len(flag) > 2:
        return flag[2:]
    try:
        index = args.index(flag)
    except ValueError:
        return ""
    return args[index + 1] if index + 1 < len(args) else ""


def _upload_files(args: list[str], value_flags: set[str], *, data_flags: bool) -> str:
    files = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in value_flags and index + 1 < len(args):
            files.append(args[index + 1])
            index += 2
            continue
        for flag in value_flags:
            if arg.startswith(flag + "="):
                files.append(arg.split("=", 1)[1])
        if data_flags and "@" in arg and arg.startswith(("-d", "--data")):
            files.append(arg.split("@", 1)[1])
        index += 1
    return ", ".join(sorted({f for f in files if f})) or "(unnamed)"


class StagingAndTransfer(_HostContextRule):
    id = "context.staging_and_transfer"
    version = "2"
    title = "Data staging or outbound transfer in an anchored session or lineage"
    families = ("process_exec",)
    positive_only_reason = ("the archiver, encoder or transfer tool and its operands are identified from argv "
                            "and shell script text; the command line shows intent and direction but not that "
                            "bytes were staged or left the host, so absence proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1560.001", "T1074.001", "T1027.013", "T1048", "T1570", "T1021.004")
    benign = ("a backup job archiving configuration or data directories",
              "a deployment copying files to another host",
              "a packaging or build step that compresses source trees")
    next_checks = ("the destination host or URL, and whether a flow to it was observed",
                   "what was archived or encoded, and whether it was read from a credential store",
                   "the other commands in the same session")

    def match_linked(self, anchor, link, events):
        groups: dict[tuple, dict[str, list]] = defaultdict(lambda: {"stage": [], "transfer": [], "tech": set()})
        for event in self.eligible(events, EXEC_REQUIRED):
            prog = program(event)
            if prog is None:
                continue
            found = classify_staging(prog, event)
            if found is None:
                continue
            technique, kind, desc = found
            bucket = groups[_session_key(event, anchor)]
            bucket[kind].append((desc, event))
            bucket["tech"].add(technique)

        out = []
        for key, bucket in groups.items():
            staged, transferred = bucket["stage"], bucket["transfer"]
            cited = _cite([event for _desc, event in staged + transferred])
            descs = sorted({desc for _k in ("stage", "transfer") for desc, _e in bucket[_k]})
            summary, _s, _f = _outcome_summary([event for _desc, event in staged + transferred])
            lane = "high" if staged and transferred else "lead"
            headline = ("sensitive data was staged and the session also ran an outbound transfer"
                        if lane == "high" else "data staging or an outbound transfer")
            claim = (f"On {key[0]}, {headline}: {'; '.join(descs)}. {summary}. {_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate(cited, "process.executable", "process.argv"), cited[0].ts,
                          "high" if lane == "high" else "medium", lane, "medium", cited[0].entities(),
                          group_key=f"stage|{_group_id(key)}")
            match.notes.extend(sorted(bucket["tech"]))
            out.append(self._finish(match, cited, anchor, link))
        return out


# ================================================================================================
# Lateral movement (T1021, T1021.001/.002/.004/.006, T1570).
# ================================================================================================

_ADMIN_PORTS = {
    22: ("T1021.004", "SSH"), 445: ("T1021.002", "SMB/Windows admin shares"),
    139: ("T1021.002", "SMB/Windows admin shares"), 3389: ("T1021.001", "RDP"),
    5985: ("T1021.006", "WinRM (HTTP)"), 5986: ("T1021.006", "WinRM (HTTPS)"),
    135: ("T1021.002", "Windows RPC endpoint mapper"),
}
_REMOTE_CLIENTS = {
    "ssh": ("T1021.004", "SSH"), "scp": ("T1021.004", "SSH (scp)"), "sftp": ("T1021.004", "SSH (sftp)"),
    "rsync": ("T1570", "rsync"), "smbclient": ("T1021.002", "SMB"),
}


def _admin_internal(ip: ipaddress._BaseAddress) -> bool:
    return is_internal(ip) and not ip.is_loopback and not ip.is_link_local


def _smbclient_target(args: list[str]) -> str | None:
    _flags, operands = split_flags(args)
    for operand in operands:
        if operand.startswith(("//", "\\\\")):
            stripped = operand.lstrip("/").lstrip("\\")
            return stripped.replace("\\", "/").split("/", 1)[0] or None
    return None


class LateralMovement(_HostContextRule):
    id = "context.lateral_movement"
    version = "2"
    title = "Lateral remote-service use from an anchored session or lineage"
    anchor_class = "lateral_movement"
    families = ("process_exec", "net_socket")
    required_fields = ()
    positive_only_reason = ("the remote-service client and its target are identified from argv, and the socket "
                            "connect path depends on the audit rule set recording that syscall; a session can "
                            "move laterally in ways these records do not show, so absence proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1021", "T1021.001", "T1021.002", "T1021.004", "T1021.006", "T1570")
    benign = ("routine administration or deployment from a jump host",
              "monitoring agents and backup jobs that connect to internal services")
    next_checks = ("whether the target host is itself an anchor or shows follow-on activity",
                   "the credential used (a key or password read earlier in the session)",
                   "whether a network sensor also recorded the flow")

    def match_linked(self, anchor, link, events):
        eligible = self.eligible(
            events, {"process_exec": ("process.executable", "process.argv"),
                     "net_socket": ("destination.ip", "destination.port")},
        )
        # (session, target) -> {"exec":[...], "socket":[(event, success)], "tech":set}
        groups: dict[tuple, dict] = defaultdict(lambda: {"exec": [], "socket": [], "tech": set()})
        client_exec_ts: dict[tuple, list[float]] = defaultdict(list)
        for event in sorted(eligible, key=lambda item: (item.ts, item.id)):
            session = _session_key(event, anchor)
            if event.family == "process_exec":
                prog = program(event)
                if prog is None or prog.name not in _REMOTE_CLIENTS:
                    continue
                target = (_smbclient_target(prog.args) if prog.name == "smbclient"
                          else ssh_destination(prog.args) if prog.name == "ssh"
                          else scp_remote_host(prog.name, prog.args))
                if not target:
                    continue
                technique, service = _REMOTE_CLIENTS[prog.name]
                bucket = groups[(session, f"host:{target}")]
                bucket["exec"].append((event, service, target))
                bucket["tech"].add(technique)
                client_exec_ts[session].append(event.ts.timestamp())
            else:
                if event.get("socket.syscall") != "connect":
                    continue
                try:
                    destination = ipaddress.ip_address(str(event.get("destination.ip")))
                except ValueError:
                    continue
                port = event.get("destination.port")
                if not _admin_internal(destination) or port not in _ADMIN_PORTS:
                    continue
                technique, service = _ADMIN_PORTS[port]
                bucket = groups[(session, f"addr:{destination}:{port}")]
                bucket["socket"].append((event, service, event.outcome == Outcome.success, destination, port))
                bucket["tech"].add(technique)

        out = []
        for (session, target), bucket in groups.items():
            match = self._build(session, target, bucket, client_exec_ts[session], anchor, link)
            if match is not None:
                out.append(match)
        return out

    def _build(self, session, target, bucket, exec_ts, anchor, link):
        exec_hits, socket_hits = bucket["exec"], bucket["socket"]
        cited = _cite([event for event, *_ in exec_hits] + [event for event, *_ in socket_hits])
        if not cited:
            return None
        lane = "lead"
        lines = []
        for event, service, host in exec_hits[:CITE_LIMIT]:
            lines.append(f"the {service} client toward '{host}' (host as given on the command line; not resolved "
                         f"in telemetry); {outcome_phrase(event)}")
        for event, service, success, destination, port in socket_hits[:CITE_LIMIT]:
            outcome = ("the connect() succeeded" if event.outcome == Outcome.success
                       else "the connect() failed" if event.outcome == Outcome.failure
                       else "the connect() outcome is unknown")
            lines.append(f"a kernel connect() to the internal {service} address {destination}:{port} "
                         f"(observed internal address, not a resolved host name); {outcome}")
            if success and any(ts <= event.ts.timestamp() for ts in exec_ts):
                lane = "high"
        headline = ("a remote-service client was followed by a successful connect to an internal admin port"
                    if lane == "high" else "lateral remote-service use")
        claim = (f"On {session[0]}, {headline}: {'; '.join(lines)}. {_context_suffix(anchor, link)}")
        predicate = _predicate([event for event, *_ in exec_hits], "process.executable", "process.argv") or \
            _predicate([event for event, *_ in socket_hits], "destination.ip", "destination.port")
        match = Match(self.id, claim, self.claim_type, cited, predicate, cited[0].ts,
                      "high" if lane == "high" else "medium", lane, "medium", cited[0].entities(),
                      group_key=f"lateral|{_group_id(session)}|{target}")
        match.notes.extend(sorted(bucket["tech"]))
        # A client exec whose own outcome failed does not by itself justify high; _finish guards exec-only.
        if not socket_hits:
            return self._finish(match, cited, anchor, link)
        return match


# ================================================================================================
# Entry-point promotion (T1078, T1021.004).
# ================================================================================================

class EntryPointPromotion(ContextPlaybook):
    """A successful external sshd login that began an anchored session is promoted once per
    (host, boot, session). The login or authentication-phase record is preferred; the PAM session-open record
    is the fallback, worded as such. If any record of the session has an internal source, it is not promoted;
    if no record carries a source, it is capped at lead with the source called unknown."""

    id = "context.entry_point_promotion"
    version = "3"
    title = "Remote-login entry point linked to a later anchor-class finding"
    anchor_class = "remote_login"
    anchor_classes = ("*",)
    link_types = ("login_session",)
    families = ("auth",)
    required_fields = ("auth.service",)
    assures_negative = False
    positive_only_reason = ("the entry point is recognised from the linked session's audit login records "
                            "(USER_LOGIN/USER_START) and sshd authentication records, only within that session; "
                            "absence of an external entry point in that scope proves nothing")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1078", "T1021.004")
    benign = ("approved remote administration followed by authorized maintenance",)
    next_checks = ("the complete login session", "the source address across hosts",
                   "whether the account logs in from this source elsewhere")

    _PHASE_RANK: ClassVar[dict[str, int]] = {"login": 0, "authentication": 0, "session_open": 2}

    def match_linked(self, anchor, link, events):
        candidates = []
        has_internal_source = False
        external_source = None
        for event in self.eligible(events, {"auth": ("auth.service",)}):
            if event.get("auth.service") != "sshd" or event.outcome != Outcome.success:
                continue
            source = event.get("source.ip")
            if source is not None:
                try:
                    address = ipaddress.ip_address(str(source))
                except ValueError:
                    self.missing_required += 1       # a present-but-unparseable source is not a clean field
                    continue
                if is_internal(address):
                    has_internal_source = True
                else:
                    external_source = str(address)
            candidates.append(event)
        if not candidates or has_internal_source:
            return []

        chosen = min(candidates, key=lambda event: (
            self._PHASE_RANK.get(event.get("auth.phase"), 1),
            0 if event.get("source.ip") is not None else 1,
            event.ts, event.id,
        ))
        session = chosen.get("process.session_id") or link.key.get("process.session_id")
        boot = chosen.get("host.boot.id")
        group_key = f"entry|{chosen.host}|{boot}|{session}"
        is_session_open = self._PHASE_RANK.get(chosen.get("auth.phase"), 1) >= 2
        if external_source is not None:
            lane, confidence = "high", "high"
            if is_session_open:
                lead = f"The session-open record of a remote SSH login from {external_source} on {chosen.host}"
            else:
                lead = f"A successful remote login from {external_source} on {chosen.host}"
        else:
            lane, confidence = "lead", "medium"
            descriptor = ("The session-open record of a remote SSH login" if is_session_open
                          else "A successful remote SSH login")
            lead = f"{descriptor} on {chosen.host} (its source address was not recorded)"
        claim = (f"{lead} began the observed login session that later performed {anchor.id}. "
                 f"{_context_suffix(anchor, link)}")
        predicate = [pf(chosen, "auth.service")]
        for name in ("source.ip", "user.name"):
            if chosen.has(name):
                predicate.append(pf(chosen, name))
        match = Match(self.id, claim, self.claim_type, [chosen], predicate, chosen.ts,
                      "high" if lane == "high" else "medium", lane, confidence, chosen.entities(),
                      group_key=group_key)
        match.notes.append("T1078")
        return [match]


CONTEXT_PLAYBOOKS = [
    PostAccessDiscovery, PrivilegeProbing, CredentialAccessInContext,
    StagingAndTransfer, LateralMovement, EntryPointPromotion,
]
