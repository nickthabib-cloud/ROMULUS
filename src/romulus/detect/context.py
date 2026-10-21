"""Anchor-gated context rules. They never run in the full-window sweep.

Each rule judges a record only after it is reached through an explicit typed link from an admitted anchor.
Programs and file operands are identified from the kernel-recorded `process.executable` and token-aware argv
parsing (`romulus.detect.linux_argv`), never from substrings of a serialized record. All of these rules read
argv or script text, so they are positive-only: they publish findings worded to what the text shows and never
assure a complete negative.

Findings are aggregated per session so that one foothold does not produce one finding per command, and lanes
follow a deliberate policy: a broad rule sits at `lead` until stronger context (a discovery burst, an
unbrokered root transition, a staged-then-exfiltrated file, a client-plus-matching-connect to an admin port)
raises it. Every matching record is cited; the claim text lists up to a fixed number and gives exact totals.
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
    client_operands,
    is_suid_perm,
    is_under,
    nc_destination,
    normalize_path,
    program,
    read_operands,
    remote_endpoint,
    scp_remote_host,
    split_flags,
    ssh_destination,
    tar_spec,
)
from romulus.evidence.shellparse import UnknownShellScript, parse_script, shell_script_of
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
ELEVATION_HELPERS = {"sudo", "su", "pkexec", "doas", "run0"}
# How many items the claim text lists before "and N more"; every matching record is still cited.
CLAIM_DISPLAY = 8


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


def _dedup_sorted(events: list[TypedEvent]) -> list[TypedEvent]:
    seen: dict[str, TypedEvent] = {}
    for event in events:
        seen[event.id] = event
    return sorted(seen.values(), key=lambda event: (event.ts, event.id))


def _and_more(items: list[str]) -> str:
    """List up to CLAIM_DISPLAY items, then 'and N more' with the exact remaining count."""
    unique = list(dict.fromkeys(items))
    shown = unique[:CLAIM_DISPLAY]
    text = ", ".join(shown)
    if len(unique) > len(shown):
        text += f", and {len(unique) - len(shown)} more"
    return text


def _predicate_all(events: list[TypedEvent], *fields: str):
    """One predicate field per cited record for each present field, so every citation has field lineage."""
    out = []
    for event in _dedup_sorted(events):
        for name in fields:
            if event.has(name):
                out.append(pf(event, name))
    return out


# ------------------------------------------------------------------------------------------------
# Process-lineage helpers (shared by privilege and lateral rules).
# ------------------------------------------------------------------------------------------------

def _exec_index(events: list[TypedEvent]) -> dict:
    index: dict[tuple, list[TypedEvent]] = defaultdict(list)
    for event in events:
        if event.family != "process_exec":
            continue
        pid = event.get("process.pid")
        if isinstance(pid, int):
            index[(event.host, pid)].append(event)
    for bucket in index.values():
        bucket.sort(key=lambda event: (event.ts, event.id))
    return index


def _latest_at(index: dict, host, pid, ts) -> TypedEvent | None:
    if not isinstance(pid, int):
        return None
    best = None
    for event in index.get((host, pid), ()):
        if event.ts <= ts:
            best = event
        else:
            break
    return best


def _ancestors(index: dict, event: TypedEvent, limit: int = 24) -> tuple[list[TypedEvent], bool]:
    """Lineage ancestors through the ppid chain, and whether the chain was fully established (reached a session
    leader / pid 0 or 1). A broken chain (an unknown parent) returns complete=False."""
    out: list[TypedEvent] = []
    pid = event.get("process.ppid")
    ts = event.ts
    for _ in range(limit):
        if not isinstance(pid, int) or pid in (0, 1):
            return out, True
        ancestor = _latest_at(index, event.host, pid, ts)
        if ancestor is None:
            return out, False
        out.append(ancestor)
        pid, ts = ancestor.get("process.ppid"), ancestor.ts
    return out, False                              # the depth limit ran out: the chain is not fully established


class _HostContextRule(ContextPlaybook):
    """Shared base for the host-session context rules (exec and socket evidence)."""

    anchor_class = "execution"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    assures_negative = False
    claim_type = "correlated_observation"

    def _finish(self, match: Match, cited: list[TypedEvent]) -> Match:
        # A failed exec cannot carry a high-lane claim on its own.
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
    from romulus.detect.linux_argv import operands_after_options
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
    required_by_family = EXEC_REQUIRED
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
        for event in self.eligible_records(events):
            prog = program(event)
            if prog is None:
                continue
            found = classify_discovery(prog.name, prog.args, event.get("process.cwd"))
            if found is not None:
                groups[_session_key(event, anchor)].append((found[0], found[1], event))

        out = []
        for key, hits in groups.items():
            techniques = sorted({technique for technique, _behavior, _event in hits})
            behaviors = [behavior for _technique, behavior, _event in hits]
            cited = _dedup_sorted([event for _t, _b, event in hits])
            summary, _succeeded, _failed = _outcome_summary(cited)
            lane = "high" if len(techniques) >= 3 else "lead"
            burst = "a discovery burst" if lane == "high" else "discovery activity"
            claim = (f"On {key[0]}, {burst}: {len(cited)} command(s) across {len(techniques)} distinct "
                     f"discovery class(es) [{_and_more(sorted(set(behaviors)))}] ran in this session. "
                     f"{summary}. {_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate_all(cited, "process.executable", "process.argv"), cited[0].ts,
                          "high" if lane == "high" else "medium", lane, "medium",
                          cited[0].entities(), group_key=f"discovery|{_group_id(key)}")
            match.notes.extend(techniques)
            out.append(self._finish(match, cited))
        return out


# ================================================================================================
# Privilege probing and escalation (T1548, T1548.001, T1548.003, T1068).
# ================================================================================================

_SUDO_VALUE_OPTS = {"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R"}
_SUDO_VALUE_LETTERS = set("ugUChprtDR")


def _sudo_is_list(args: list[str]) -> bool:
    """True when sudo's own options request --list, parsing only sudo options and stopping at the command. A
    value letter inside a short group consumes the rest of the group, but an `l` seen before it still counts."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--list" or arg.startswith("--list"):
            return True
        if arg in _SUDO_VALUE_OPTS:
            index += 2
            continue
        if arg.startswith("--"):
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            for letter in arg[1:]:
                if letter == "l":
                    return True
                if letter in _SUDO_VALUE_LETTERS:
                    break                          # consumes the rest of the group as its value
            index += 1
            continue
        return False                               # first operand is the command sudo will run
    return False


_PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "identity"}


def _matched_root_field(event: TypedEvent) -> str | None:
    if str(event.get("process.uid")) == "0":
        return "process.uid"
    if str(event.get("process.euid")) == "0":
        return "process.euid"
    return None


def _is_real_root(event: TypedEvent) -> bool:
    return str(event.get("process.uid")) == "0"


def _is_euid_only(event: TypedEvent) -> bool:
    uid = event.get("process.uid")
    return str(event.get("process.euid")) == "0" and uid is not None and str(uid) not in {"0", "4294967295", "-1"}


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
    version = "3"
    title = "Privilege probing or escalation in an anchored session or lineage"
    families = ("process_exec",)
    required_by_family = EXEC_REQUIRED
    positive_only_reason = ("the probing commands and the setuid/sudo/capability operands are identified from "
                            "argv, and a root process is visible only when its exec was recorded; absence proves "
                            "neither that privileges were not probed nor that none were gained")
    severity, lane = "medium", "lead"
    attack = ("T1548", "T1548.001", "T1548.003", "T1068")
    benign = ("an administrator checking their own sudo rights or auditing setuid binaries",
              "configuration-management and vulnerability-scanning tools",
              "a legitimate sudo or su to an admin account")
    next_checks = ("whether a listed sudo rule or setuid binary was then run",
                   "credential-file reads by the same session",
                   "commands the root-privileged process ran next")

    def match_linked(self, anchor, link, events):
        eligible = self.eligible_records(events)
        # The anchor's own exec records are not among the link events on a lineage link, so add them to the
        # index: a root record's parent may be the anchor's own shell. They are lookups only, not candidates.
        index = _exec_index(eligible + list(anchor.events))
        probes: dict[tuple, list[tuple[str, str, TypedEvent]]] = defaultdict(list)
        setuid: dict[tuple, list[tuple[str, TypedEvent]]] = defaultdict(list)
        unknown_parent: dict[tuple, list[TypedEvent]] = defaultdict(list)
        helper_first: dict[tuple, object] = {}
        transitions: list[tuple[TypedEvent, TypedEvent, tuple]] = []
        seen_transition: set[tuple] = set()
        for event in sorted(eligible, key=lambda item: (item.ts, item.id)):
            prog = program(event)
            if prog is None:
                continue
            key = _session_key(event, anchor)
            if prog.name in ELEVATION_HELPERS and key not in helper_first:
                helper_first[key] = event.ts
            found = _classify_probe(prog, event)
            if found is not None:
                probes[key].append((found[0], found[1], event))
            if not _login_user_is_nonroot(event):
                continue
            if _is_real_root(event):
                parent = _latest_at(index, event.host, event.get("process.ppid"), event.ts)
                if parent is None:
                    unknown_parent[key].append(event)   # cannot confirm a transition without the parent's exec
                    continue
                if _is_real_root(parent):
                    continue                        # inherited root, not a transition
                tkey = (event.host, event.get("host.boot.id"), key[2], event.get("process.pid"),
                        event.get("process.executable"))
                if tkey in seen_transition:
                    continue
                seen_transition.add(tkey)
                transitions.append((event, parent, key))
            elif _is_euid_only(event) and prog.name not in ELEVATION_HELPERS:
                setuid[key].append((prog.name, event))

        out = []
        out.extend(self._probe_findings(probes, anchor, link))
        out.extend(self._transition_findings(transitions, index, helper_first, anchor, link))
        out.extend(self._unknown_parent_findings(unknown_parent, anchor, link))
        out.extend(self._setuid_findings(setuid, anchor, link))
        return out

    def _probe_findings(self, probes, anchor, link):
        out = []
        for key, hits in probes.items():
            techniques = sorted({technique for technique, _b, _e in hits})
            behaviors = [behavior for _t, behavior, _e in hits]
            cited = _dedup_sorted([event for _t, _b, event in hits])
            summary, _s, _f = _outcome_summary(cited)
            claim = (f"On {key[0]}, privilege probing in this session: {_and_more(behaviors)}. {summary}. "
                     f"{_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate_all(cited, "process.executable", "process.argv"), cited[0].ts,
                          "medium", "lead", "medium", cited[0].entities(),
                          group_key=f"privprobe|{_group_id(key)}")
            match.notes.extend(techniques)
            out.append(self._finish(match, cited))
        return out

    def _transition_findings(self, transitions, index, helper_first, anchor, link):
        out = []
        for event, parent, key in transitions:
            ancestors, _complete = _ancestors(index, event)
            helper_ancestor = next(
                (a for a in ancestors
                 if (prog := program(a)) is not None and prog.name in ELEVATION_HELPERS), None)
            earlier_helper = key in helper_first and helper_first[key] <= event.ts
            cited = [event]
            if helper_ancestor is not None:
                cited.append(helper_ancestor)
                lane, techniques = "lead", ["T1548"]
                note = (f"an elevation helper ({basename(str(helper_ancestor.get('process.executable')))}) is a "
                        "lineage ancestor through the ppid chain, so this is a brokered elevation")
            else:
                # A known non-root parent with no elevation helper among its ancestors is an exploit signal.
                lane, techniques = "high", ["T1548", "T1068"]
                parent_exe = basename(str(parent.get("process.executable")))
                note = (f"the parent ({parent_exe}, pid {parent.get('process.pid')}) is not root and no elevation "
                        "helper is an ancestor in the recorded lineage"
                        + ("; a helper ran earlier in the session but is not an ancestor" if earlier_helper
                           else ""))
            field = _matched_root_field(event) or "process.uid"
            auid, pid = event.get("process.auid"), event.get("process.pid")
            exe = basename(str(event.get("process.executable")))
            claim = (f"On {event.host}, a process ({exe}, pid {pid}) ran with uid=0 (a root transition whose "
                     f"parent is a known non-root process) while the session's kernel-recorded login user is the "
                     f"non-root account auid={auid}; {note}. {outcome_phrase(event)}. "
                     f"{_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, _dedup_sorted(cited),
                          _predicate_all(cited, field, "process.uid", "process.euid", "process.auid",
                                         "process.executable", "process.ppid"),
                          event.ts, "high" if lane == "high" else "medium", lane, "medium", event.entities(),
                          group_key=f"euid0|{event.host}|{event.get('host.boot.id')}|{key[2]}|{pid}|"
                                    f"{event.get('process.executable')}")
            match.notes.extend(techniques)
            out.append(self._finish(match, [event]))
        return out

    def _unknown_parent_findings(self, unknown_parent, anchor, link):
        out = []
        for key, hits in unknown_parent.items():
            cited = _dedup_sorted(hits)
            summary, _s, _f = _outcome_summary(cited)
            names = sorted({basename(str(event.get("process.executable"))) for event in cited})
            claim = (f"On {key[0]}, root processes whose parent exec is not in the linked records "
                     f"({len(cited)} record(s): {_and_more(names)}); the elevation that produced them is outside "
                     f"this link's scope, so whether it was brokered is unknown. {summary}. "
                     f"{_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate_all(cited, "process.uid", "process.euid", "process.auid",
                                         "process.executable", "process.ppid"),
                          cited[0].ts, "medium", "lead", "medium", cited[0].entities(),
                          group_key=f"euid0unknown|{_group_id(key)}")
            match.notes.append("T1548")
            out.append(self._finish(match, cited))
        return out

    def _setuid_findings(self, setuid, anchor, link):
        out = []
        for key, hits in setuid.items():
            names = [name for name, _e in hits]
            cited = _dedup_sorted([event for _n, event in hits])
            summary, _s, _f = _outcome_summary(cited)
            claim = (f"On {key[0]}, a setuid program ran with euid=0 while its real uid is non-root "
                     f"({_and_more(sorted(set(names)))}); this is a setuid-binary elevation, not a root "
                     f"transition. {summary}. {_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate_all(cited, "process.euid", "process.uid", "process.auid",
                                         "process.executable"),
                          cited[0].ts, "medium", "lead", "medium", cited[0].entities(),
                          group_key=f"setuid|{_group_id(key)}")
            match.notes.append("T1548")
            out.append(self._finish(match, cited))
        return out


# ================================================================================================
# Credential access (T1003, T1003.008, T1552.001, T1552.003, T1552.004, T1555.003, T1555.005).
# ================================================================================================

_SHADOW_SET = {"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/security/opasswd"}
_HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".python_history",
                  ".mysql_history", ".psql_history", ".rediscli_history"}
_PROC_MEM = re.compile(r"^/proc/\d+/mem$")
_PROC_SHADOW = re.compile(r"^/proc/\d+/root/etc/g?shadow$")


def _is_private_key_path(path: str, name: str) -> bool:
    if name in _PRIVATE_KEY_NAMES:
        return True
    if name.startswith("ssh_host_") and name.endswith("_key"):
        return True
    under_ssh = "/.ssh/" in path or path.startswith("/etc/ssh/")
    return under_ssh and not name.endswith(".pub") and name.endswith(("_key", ".pem", ".key"))


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
    if _is_private_key_path(path, name):
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
    required_by_family = EXEC_REQUIRED
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
        groups: dict[tuple, list[tuple[str, TypedEvent]]] = defaultdict(list)
        for event in self.eligible_records(events):
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
            cited = _dedup_sorted([event for _desc, event in hits])
            descs = [desc for desc, _event in hits]
            summary, _s, _f = _outcome_summary(cited)
            claim = (f"On {key[0]}, a file-reading tool was run against {_and_more(sorted(set(descs)))} in this "
                     f"session. {summary}. {_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate_all(cited, "process.executable", "process.argv"), cited[0].ts,
                          "high" if lane == "high" else "medium", lane, "medium", cited[0].entities(),
                          group_key=f"cred|{_group_id(key)}|{technique}")
            match.notes.append(technique)
            out.append(self._finish(match, cited))
        return out


# ================================================================================================
# Staging and transfer (T1560.001, T1074.001, T1027.013, T1048, T1570, T1021.004, T1105).
# ================================================================================================

_COMPRESSORS = {"gzip", "bzip2", "xz", "zstd", "pigz", "lz4", "compress"}
_ENCODERS = {"base64", "base32", "xxd", "uuencode"}
_DECOMPRESS_NAMES = {"gunzip", "bunzip2", "unxz", "unzstd", "zcat", "lzcat", "bzcat", "xzcat", "uncompress",
                     "lz4cat"}
_DECODE_BY_TOOL = {
    "gzip": {"-d", "--decompress", "--uncompress"}, "bzip2": {"-d", "--decompress"},
    "xz": {"-d", "--decompress"}, "zstd": {"-d", "--decompress", "--uncompress"},
    "lz4": {"-d", "--decompress"}, "compress": {"-d", "--uncompress"}, "pigz": {"-d", "--decompress"},
    "base64": {"-d", "--decode"}, "base32": {"-d", "--decode"}, "xxd": {"-r"},
}


def _sensitive_input(inputs: list[str], base: str | None) -> str | None:
    for item in inputs:
        path = normalize_path(item, base)
        if path and is_under(path, SENSITIVE_DIRS):
            return path
    return None


def _is_decode(name: str, args: list[str]) -> bool:
    flags, _operands = split_flags(args)
    return bool(flags & _DECODE_BY_TOOL.get(name, set()))


# Options that take a separate value, so the value is not an operand.
_ZIP_VALUE_OPTS = {"-P", "-O", "-b", "-t", "-tt", "-n", "-ds", "-s", "-x", "-i", "--out", "--temp-path"}


def _archive_inputs(name: str, args: list[str]) -> list[str] | None:
    """Inputs of a zip/7z invocation, or None when the mode does not stage. The archive output (first
    operand, after the 7z command letter) is never an input; `-P`/`-o` values are skipped."""
    from romulus.detect.linux_argv import operands_after_options
    operands = operands_after_options(args, _ZIP_VALUE_OPTS)
    if name in {"7z", "7za"}:
        if not operands or operands[0] not in {"a", "u"}:   # a=add, u=update stage; x/e/l/d/t do not
            return None
        operands = operands[1:]
    else:
        flags, _ops = split_flags(args)
        if flags & {"-d", "--delete"}:
            return None                                     # zip -d deletes entries, it does not stage
    return operands[1:] if operands else []                 # the first remaining operand is the archive


def _shell_devtcp(event: TypedEvent) -> tuple[str, str, str] | None:
    """Classify a shell -c command's /dev/tcp or /dev/udp redirection. Outbound write -> T1048 transfer;
    inbound read -> T1105 ingress. A shell -c whose script cannot be safely parsed is 'unknown' (counted)."""
    argv = event.get("process.argv")
    if not isinstance(argv, list):
        return None
    script = shell_script_of([str(item) for item in argv])
    if script is None:
        return None                                # not a shell -c command
    if isinstance(script, UnknownShellScript):
        return ("T1048", "unknown", "a shell -c command whose script position is not safely modelled")
    parsed = parse_script(script)
    if not parsed.ok:
        return ("T1048", "unknown", "a shell -c command whose script text could not be fully parsed")
    out_target = in_target = None
    for command in parsed.commands():
        for op, target in command.redirects:
            if not target.startswith(("/dev/tcp/", "/dev/udp/")):
                continue
            if ">" in op:
                out_target = target
            elif "<" in op:
                in_target = target
    if out_target is not None:
        return ("T1048", "transfer", f"shell command text that redirects output to {out_target}")
    if in_target is not None:
        return ("T1105", "ingress", f"shell command text that reads from {in_target}")
    return None


def _curl_upload_files(args: list[str]) -> list[str]:
    data_flags = {"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode", "--json"}
    upload_flags = {"-T", "--upload-file"}
    form_flags = {"-F", "--form"}
    files: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        key, _, inline = arg.partition("=")
        if arg in upload_flags and index + 1 < len(args):
            files.append(args[index + 1]); index += 2; continue
        if key in upload_flags and "=" in arg:
            files.append(inline); index += 1; continue
        if arg.startswith("-d") and len(arg) > 2 and arg[2] == "@":
            files.append(arg[3:]); index += 1; continue
        if arg in data_flags and index + 1 < len(args):
            files += _curl_data_file(arg, args[index + 1]); index += 2; continue
        if key in data_flags and "=" in arg:
            files += _curl_data_file(key, inline); index += 1; continue
        if arg in form_flags and index + 1 < len(args):
            files += _curl_form_file(args[index + 1]); index += 2; continue
        if key in form_flags and "=" in arg:
            files += _curl_form_file(inline); index += 1; continue
        index += 1
    return [f for f in dict.fromkeys(files) if f]


def _curl_data_file(flag: str, value: str) -> list[str]:
    if flag == "--data-urlencode":
        if value.startswith("@"):
            return [value[1:]]
        if "@" in value:
            return [value.split("@", 1)[1]]
        return []
    return [value[1:]] if value.startswith("@") else []


def _curl_form_file(value: str) -> list[str]:
    if "=" not in value:
        return []
    rhs = value.split("=", 1)[1]
    if rhs.startswith(("@", "<")):
        return [rhs[1:].split(";", 1)[0]]
    return []


def _wget_upload_files(args: list[str]) -> list[str]:
    upload_flags = {"--post-file", "--body-file"}
    files: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        key, _, inline = arg.partition("=")
        if arg in upload_flags and index + 1 < len(args):
            files.append(args[index + 1]); index += 2; continue
        if key in upload_flags and "=" in arg:
            files.append(inline); index += 1; continue
        index += 1
    return [f for f in files if f]


def _client_transfer(name: str, args: list[str]) -> tuple[str, str, str] | None:
    operands = client_operands(name, args)
    if not operands:
        return None
    destination = remote_endpoint(operands[-1])
    if destination:
        technique = "T1021.004" if name in {"scp", "sftp"} else "T1570"
        return (technique, "transfer",
                f"an outbound '{name}' transfer to remote host '{destination}' (the destination operand)")
    for operand in operands[:-1]:
        source = remote_endpoint(operand)
        if source:
            return ("T1105", "ingress", f"an inbound '{name}' copy from remote host '{source}'")
    return None


def classify_staging(prog, event: TypedEvent) -> tuple[str, str, str] | None:
    """(technique, kind, description); kind is 'stage', 'transfer', 'ingress' or 'unknown'. 'stage' needs a
    sensitive input; 'unknown' means a shell -c script that could not be parsed (counted as partial)."""
    name, args = prog.name, prog.args
    cwd = event.get("process.cwd")
    if name == "tar":
        staging, inputs, chdir = tar_spec(args)
        base = (normalize_path(chdir, cwd) or cwd) if chdir else cwd     # -C is itself relative to cwd
        sensitive = _sensitive_input(inputs, base) if staging else None
        if sensitive:
            return ("T1560.001", "stage", f"a tar archive over the sensitive path {sensitive}")
        return None
    if name in _COMPRESSORS:
        if name in _DECOMPRESS_NAMES or _is_decode(name, args):
            return None
        _flags, operands = split_flags(args)
        sensitive = _sensitive_input(operands, cwd)
        if sensitive:
            return ("T1560.001", "stage", f"a '{name}' compression over the sensitive path {sensitive}")
        return None
    if name in {"zip", "7z", "7za"}:
        inputs = _archive_inputs(name, args)
        sensitive = _sensitive_input(inputs, cwd) if inputs else None
        if sensitive:
            return ("T1560.001", "stage", f"a '{name}' archive over the sensitive path {sensitive}")
        return None
    if name in _ENCODERS:
        if _is_decode(name, args):
            return None
        _flags, operands = split_flags(args)
        sensitive = _sensitive_input(operands, cwd)
        if sensitive:
            return ("T1027.013", "stage", f"an encoding command ('{name}') over the sensitive path {sensitive}")
        return None
    if name in {"scp", "sftp", "rsync"}:
        return _client_transfer(name, args)
    if name == "curl":
        files = _curl_upload_files(args)
        if files:
            return ("T1048", "transfer",
                    f"an outbound 'curl' invoked with upload options naming file(s) {', '.join(files)}")
        return None
    if name == "wget":
        files = _wget_upload_files(args)
        if files:
            return ("T1048", "transfer",
                    f"an outbound 'wget' invoked with upload options naming file(s) {', '.join(files)}")
        return None
    if name == "nc":
        host, listen = nc_destination(args)
        if host and not listen:
            return ("T1048", "transfer", f"an outbound 'nc' client connection to '{host}'")
        return None
    return _shell_devtcp(event)


class StagingAndTransfer(_HostContextRule):
    id = "context.staging_and_transfer"
    version = "2"
    title = "Data staging or transfer in an anchored session or lineage"
    families = ("process_exec",)
    required_by_family = EXEC_REQUIRED
    positive_only_reason = ("the archiver, encoder or transfer tool and its operands are identified from argv "
                            "and shell script text; the command line shows intent and direction but not that "
                            "bytes were staged or moved, so absence proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1560.001", "T1074.001", "T1027.013", "T1048", "T1570", "T1021.004", "T1105")
    benign = ("a backup job archiving configuration or data directories",
              "a deployment copying files to another host",
              "a packaging or build step that compresses source trees")
    next_checks = ("the destination host or URL, and whether a flow to it was observed",
                   "what was archived or encoded, and whether it was read from a credential store",
                   "the other commands in the same session")

    def match_linked(self, anchor, link, events):
        groups: dict[tuple, dict] = defaultdict(
            lambda: {"stage": [], "transfer": [], "ingress": [], "tech": set()})
        for event in self.eligible_records(events):
            prog = program(event)
            if prog is None:
                continue
            found = classify_staging(prog, event)
            if found is None:
                continue
            technique, kind, desc = found
            if kind == "unknown":
                self.missing_required += 1         # an unparseable shell -c is partial, never a clean no-match
                continue
            bucket = groups[_session_key(event, anchor)]
            bucket[kind].append((desc, event))
            bucket["tech"].add(technique)

        out = []
        for key, bucket in groups.items():
            kinds = [k for k in ("stage", "transfer", "ingress") if bucket[k]]
            all_hits = [item for k in kinds for item in bucket[k]]
            cited = _dedup_sorted([event for _desc, event in all_hits])
            descs = [desc for _desc_kind in kinds for desc, _e in bucket[_desc_kind]]
            summary, _s, _f = _outcome_summary(cited)
            # High only when a sensitive input was staged and the session also ran an outbound transfer. An
            # inbound copy (ingress) does not count toward that combination.
            lane = "high" if bucket["stage"] and bucket["transfer"] else "lead"
            headline = ("sensitive data was staged and the session also ran an outbound transfer"
                        if lane == "high" else "data staging or transfer")
            claim = (f"On {key[0]}, {headline}: {_and_more(sorted(set(descs)))}. {summary}. "
                     f"{_context_suffix(anchor, link)}")
            match = Match(self.id, claim, self.claim_type, cited,
                          _predicate_all(cited, "process.executable", "process.argv"), cited[0].ts,
                          "high" if lane == "high" else "medium", lane, "medium", cited[0].entities(),
                          group_key=f"stage|{_group_id(key)}")
            match.notes.extend(sorted(bucket["tech"]))
            out.append(self._finish(match, cited))
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


def _ip_literal(value: str | None):
    if value is None:
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


class _Client:
    __slots__ = ("event", "pid", "service", "target", "target_ip")

    def __init__(self, event, service, target, pid):
        self.event, self.service, self.target, self.pid = event, service, target, pid
        self.target_ip = _ip_literal(target)


class LateralMovement(_HostContextRule):
    id = "context.lateral_movement"
    version = "3"
    title = "Lateral remote-service use from an anchored session or lineage"
    anchor_class = "lateral_movement"
    families = ("process_exec", "net_socket")
    required_fields = ()
    required_by_family: ClassVar[dict] = {"process_exec": ("process.executable", "process.argv"),
                                          "net_socket": ("destination.ip", "destination.port")}
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
        eligible = self.eligible_records(events)
        index = _exec_index(eligible)
        clients: dict[tuple, list[_Client]] = defaultdict(list)
        exec_groups: dict[tuple, dict] = defaultdict(lambda: {"exec": [], "tech": set()})
        socket_groups: dict[tuple, dict] = defaultdict(lambda: {"socket": [], "tech": set()})
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
                clients[session].append(_Client(event, service, target, event.get("process.pid")))
                bucket = exec_groups[(session, f"host:{target}")]
                bucket["exec"].append((event, service, target))
                bucket["tech"].add(technique)
            else:
                if event.get("socket.syscall") != "connect":
                    continue
                destination = _ip_literal(event.get("destination.ip"))
                port = event.get("destination.port")
                if destination is None or not _admin_internal(destination) or port not in _ADMIN_PORTS:
                    continue
                technique, service = _ADMIN_PORTS[port]
                bucket = socket_groups[(session, f"addr:{destination}:{port}")]
                bucket["socket"].append((event, service, destination, port))
                bucket["tech"].add(technique)

        out = []
        for (session, target), bucket in exec_groups.items():
            out.append(self._exec_finding(session, target, bucket, anchor, link))
        for (session, target), bucket in socket_groups.items():
            out.append(self._socket_finding(session, target, bucket, clients.get(session, []), index,
                                            anchor, link))
        return out

    def _exec_finding(self, session, target, bucket, anchor, link):
        cited = _dedup_sorted([event for event, *_ in bucket["exec"]])
        lines = [f"the {service} client toward '{host}' (host as given on the command line; not resolved in "
                 f"telemetry); {outcome_phrase(event)}" for event, service, host in bucket["exec"]]
        claim = (f"On {session[0]}, lateral remote-service use: {_and_more(lines)}. "
                 f"{_context_suffix(anchor, link)}")
        match = Match(self.id, claim, self.claim_type, cited,
                      _predicate_all(cited, "process.executable", "process.argv"), cited[0].ts,
                      "medium", "lead", "medium", cited[0].entities(),
                      group_key=f"lateral|{_group_id(session)}|{target}")
        match.notes.extend(sorted(bucket["tech"]))
        return self._finish(match, cited)

    def _socket_finding(self, session, target, bucket, clients, index, anchor, link):
        socket_events = [event for event, *_ in bucket["socket"]]
        matched_client = None
        matched_success = False
        for event, _service, destination, _port in bucket["socket"]:
            if event.outcome != Outcome.success:
                continue
            client = self._matching_client(event, destination, clients, index)
            if client is not None:
                matched_client, matched_success = client, True
                break
        lines = []
        for event, service, destination, port in bucket["socket"]:
            outcome = ("the connect() succeeded" if event.outcome == Outcome.success
                       else "the connect() failed" if event.outcome == Outcome.failure
                       else "the connect() outcome is unknown")
            lines.append(f"a kernel connect() to the internal {service} address {destination}:{port} "
                         f"(observed internal address, not a resolved host name); {outcome}")
        cited = list(socket_events)
        tech = set(bucket["tech"])
        if matched_success and matched_client is not None:
            cited.append(matched_client.event)
            tech.update(_REMOTE_CLIENTS.get(program(matched_client.event).name, ("", ""))[:1])
            lane = "high"
            relation = (f"this connect matches the {matched_client.service} client toward "
                        f"'{matched_client.target}' (same target or process lineage)")
        else:
            lane = "lead"
            relation = ("no remote-service client exec in this session matches this connect by target or "
                        "process lineage; any relation to a client is temporal only")
        cited = _dedup_sorted(cited)
        headline = ("a remote-service client was followed by a matching successful connect to an internal admin "
                    "port" if lane == "high" else "a connect to an internal admin port")
        claim = (f"On {session[0]}, {headline}: {_and_more(lines)}. {relation}. {_context_suffix(anchor, link)}")
        predicate = _predicate_all(socket_events, "destination.ip", "destination.port", "process.pid")
        if matched_client is not None:
            predicate += _predicate_all([matched_client.event], "process.executable", "process.argv")
        match = Match(self.id, claim, self.claim_type, cited, predicate, cited[0].ts,
                      "high" if lane == "high" else "medium", lane, "medium", cited[0].entities(),
                      group_key=f"lateral|{_group_id(session)}|{target}")
        match.notes.extend(sorted(tech - {""}))
        return match

    @staticmethod
    def _matching_client(socket_event, destination, clients, index):
        # The connect must come after the client exec to be "followed by"; an earlier connect is temporal only.
        prior = [client for client in clients if client.event.ts <= socket_event.ts]
        for client in prior:                       # IP-literal target match
            if client.target_ip is not None and client.target_ip == destination:
                return client
        pids = set()
        pid = socket_event.get("process.pid")
        if isinstance(pid, int):
            pids.add(pid)
        ancestors, _complete = _ancestors(index, socket_event)
        for ancestor in ancestors:
            ancestor_pid = ancestor.get("process.pid")
            if isinstance(ancestor_pid, int):
                pids.add(ancestor_pid)
        for client in prior:
            if client.pid in pids:
                return client
        return None


# ================================================================================================
# Entry-point promotion (T1078, T1021.004).
# ================================================================================================

class EntryPointPromotion(ContextPlaybook):
    """A successful external sshd login that began an anchored session is promoted once per
    (host, boot, session). The login or authentication-phase record is preferred; the PAM session-open record
    is the fallback, worded as such. If any record of the session has an internal source, it is not promoted;
    if no record carries a source, it stays a lead with the source called unknown (never a high promotion)."""

    id = "context.entry_point_promotion"
    version = "3"
    title = "Remote-login entry point linked to a later anchor-class finding"
    anchor_class = "remote_login"
    anchor_classes = ("*",)
    link_types = ("login_session",)
    families = ("auth",)
    required_fields = ("auth.service",)
    required_by_family: ClassVar[dict] = {"auth": ("auth.service",)}
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
        # Group the session's own sshd success records by (host, boot, session id). The external-vs-internal
        # test uses only a session's own records, so another session can never affect it.
        sessions: dict[tuple, list[TypedEvent]] = defaultdict(list)
        for event in self.eligible_records(events):
            if event.get("auth.service") != "sshd" or event.outcome != Outcome.success:
                continue
            source = event.get("source.ip")
            if source is not None:
                try:
                    ipaddress.ip_address(str(source))
                except ValueError:
                    self.missing_required += 1       # a present-but-unparseable source is not a clean field
                    continue
            key = (event.host, event.get("host.boot.id"),
                   event.get("process.session_id") or link.key.get("process.session_id"))
            sessions[key].append(event)

        out = []
        for (host, boot, session), records in sessions.items():
            match = self._promote(anchor, link, host, boot, session, records)
            if match is not None:
                out.append(match)
        return out

    def _promote(self, anchor, link, host, boot, session, records):
        external_source = None
        for event in records:
            source = event.get("source.ip")
            if source is None:
                continue
            if is_internal(ipaddress.ip_address(str(source))):
                return None                          # this session's own source is internal: not an entry point
            external_source = str(source)
        chosen = min(records, key=lambda event: (
            self._PHASE_RANK.get(event.get("auth.phase"), 1),
            0 if event.get("source.ip") is not None else 1,
            event.ts, event.id,
        ))
        group_key = f"entry|{host}|{boot}|{session}"
        is_session_open = self._PHASE_RANK.get(chosen.get("auth.phase"), 1) >= 2
        if external_source is not None:
            lane, confidence = "high", "high"
            if is_session_open:
                lead = f"The session-open record of a remote SSH login from {external_source} on {host}"
            else:
                lead = f"A successful remote login from {external_source} on {host}"
        else:
            lane, confidence = "lead", "medium"
            descriptor = ("The session-open record of a remote SSH login" if is_session_open
                          else "A successful remote SSH login")
            lead = f"{descriptor} on {host} (its source address was not recorded; not confirmed external)"
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
        return match


CONTEXT_PLAYBOOKS = [
    PostAccessDiscovery, PrivilegeProbing, CredentialAccessInContext,
    StagingAndTransfer, LateralMovement, EntryPointPromotion,
]
