"""Anchor-gated context rules. They never run in the full-window sweep.

Every rule here judges a record only after it is reached through an explicit typed link from an admitted
anchor (ADR-006, deterministic expansion). Programs and file operands are identified from the kernel-recorded
`process.executable` and token-aware argv parsing (`romulus.detect.linux_argv`), never from substrings of a
serialized record. All of these rules read argv/text, so they are positive-only (ADR-004): they publish the
same findings worded to what the text shows and never assure a complete negative.
"""
from __future__ import annotations

import ipaddress
from typing import ClassVar

from romulus.detect.base import ContextAnchor, ContextLink, ContextPlaybook, Match, basename, pf
from romulus.detect.host import is_internal
from romulus.detect.linux_argv import is_under, program, read_operands, split_flags
from romulus.evidence.typed import Outcome, TypedEvent, raw_identity

# Anchor classes that denote a host-attributed foothold whose session or lineage is worth judging. A
# network-only anchor (anchor_class "network_observation" / "indicator") has no host session, so these rules
# never claim its context.
ANCHOR_HOST = (
    "initial_access", "remote_login", "web_shell", "execution", "credential_access",
    "persistence", "lateral_movement",
)
HOST_LINKS = ("login_session", "process_lineage")

# Directories whose enumeration is post-access reconnaissance rather than routine listing.
SENSITIVE_DIRS = ("/etc", "/root", "/home", "/var/www", "/opt", "/srv", "/boot", "/var/log", "/var/lib")


def _context_suffix(anchor: ContextAnchor, link: ContextLink) -> str:
    if link.strength == "inferred":
        return (f"This is a hypothesis linked to {anchor.id} by inferred {link.link_type} link {link.id}; "
                "no observed session or lineage key proves the actor is the same.")
    return f"It was reached from {anchor.id} through observed {link.link_type} link {link.id}."


def _predicate(event: TypedEvent):
    fields = [pf(event, "process.executable")] if event.has("process.executable") else []
    if event.has("process.argv"):
        fields.append(pf(event, "process.argv"))
    return fields


def _exec_context_match(
    playbook: ContextPlaybook, event: TypedEvent, technique: str, claim: str, anchor, link,
    *, confidence: str = "medium",
) -> Match:
    match = Match(
        playbook.id, claim, playbook.claim_type, [event], _predicate(event), event.ts,
        playbook.severity, playbook.lane, confidence, event.entities(),
        group_key=raw_identity(event),
    )
    match.notes.append(technique)
    return match


# ---------------------------------------------------------------------------------------------
# Post-access discovery (T1033, T1082, T1016, T1049, T1057, T1083, T1087, T1069, T1007, T1518,
# T1135, T1201, T1680). Linux command procedures, classified by typed executable and argv tokens.
# ---------------------------------------------------------------------------------------------

# Programs whose every invocation is the named enumeration.
_DISCOVERY_BY_NAME = {
    "whoami": ("T1033", "current-user discovery"),
    "logname": ("T1033", "current-user discovery"),
    "id": ("T1033", "current-user and group discovery"),
    "who": ("T1033", "logged-in-user discovery"),
    "w": ("T1033", "logged-in-user discovery"),
    "users": ("T1033", "logged-in-user discovery"),
    "last": ("T1033", "login-history discovery"),
    "lastlog": ("T1033", "login-history discovery"),
    "groups": ("T1069", "permission-group enumeration"),
    "hostname": ("T1082", "host-information discovery"),
    "hostnamectl": ("T1082", "host-information discovery"),
    "uname": ("T1082", "system-information discovery"),
    "arch": ("T1082", "system-information discovery"),
    "lscpu": ("T1082", "system-information discovery"),
    "lshw": ("T1082", "system-information discovery"),
    "dmidecode": ("T1082", "system-information discovery"),
    "lsb_release": ("T1082", "OS-version discovery"),
    "env": ("T1082", "environment-variable enumeration"),
    "printenv": ("T1082", "environment-variable enumeration"),
    "ifconfig": ("T1016", "network-configuration discovery"),
    "iwconfig": ("T1016", "network-configuration discovery"),
    "route": ("T1016", "network-configuration discovery"),
    "arp": ("T1016", "network-configuration discovery"),
    "netstat": ("T1049", "network-connection discovery"),
    "ss": ("T1049", "network-connection discovery"),
    "ps": ("T1057", "process discovery"),
    "pstree": ("T1057", "process discovery"),
    "pgrep": ("T1057", "process discovery"),
    "top": ("T1057", "process discovery"),
    "htop": ("T1057", "process discovery"),
    "df": ("T1680", "local-storage discovery"),
    "lsblk": ("T1680", "local-storage discovery"),
    "blkid": ("T1680", "local-storage discovery"),
    "tree": ("T1083", "file-and-directory discovery"),
    "locate": ("T1083", "file-and-directory discovery"),
    "showmount": ("T1135", "network-share discovery"),
}

# Files whose read is an enumeration of a specific category (credential files are NOT here; a read of a
# credential store is the credential-access rule's job).
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


def _ls_is_sensitive(args: list[str], cwd: str | None) -> bool:
    from romulus.detect.linux_argv import normalize_path
    _flags, operands = split_flags(args)
    for operand in operands:
        path = normalize_path(operand, cwd)
        if path and (is_under(path, SENSITIVE_DIRS) or path.endswith("/.ssh")):
            return True
    return False


def classify_discovery(name: str, args: list[str], cwd: str | None) -> tuple[str, str] | None:
    """Return (ATT&CK technique id, behaviour phrase) for a discovery command, or None.

    `name` is the kernel-recorded program (never argv[0]); `args` are its operands. Argument-sensitive
    programs are classified by their subcommand or flags so that a modifying invocation (`ip addr add`,
    `apt install`, `systemctl start`) is not read as discovery."""
    if name in _DISCOVERY_BY_NAME:
        return _DISCOVERY_BY_NAME[name]
    flags, operands = split_flags(args)
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
        # A setuid/setgid search is privilege probing, handled by PrivilegeProbing, not discovery.
        if _find_is_suid_search(args):
            return None
        return ("T1083", "file-and-directory discovery")
    if name in {"ls", "dir"}:
        return ("T1083", "file-and-directory discovery") if _ls_is_sensitive(args, cwd) else None
    # A reader pointed at a category file (cat /etc/passwd, grep x /etc/group, head /proc/version, …).
    for path in read_operands(name, args, cwd):
        if path in _DISCOVERY_FILES:
            return _DISCOVERY_FILES[path]
    return None


class PostAccessDiscovery(ContextPlaybook):
    id = "context.post_access_discovery"
    version = "2"
    title = "Discovery command in an anchored session or process lineage"
    anchor_class = "execution"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    families = ("process_exec",)
    required_fields = ("process.executable",)
    assures_negative = False
    positive_only_reason = ("discovery behaviour is identified from the executable and argv tokens and is only "
                            "evaluated on records reached through an anchor link; absence outside that linked "
                            "scope, or in records the session performed without an exec, proves nothing")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1033", "T1082", "T1016", "T1049", "T1057", "T1083", "T1087", "T1069",
              "T1007", "T1518", "T1135", "T1201", "T1680")
    benign = ("administrator troubleshooting after an approved login",
              "inventory, monitoring and compliance scripts", "package-manager list queries")
    next_checks = ("the other commands in the same session or lineage (a burst is stronger than one command)",
                   "privilege probing or credential-file reads by the same session",
                   "network flows the session opens next")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            name, args = (program(event) or (None, []))
            if name is None:
                continue
            found = classify_discovery(name, args, event.get("process.cwd"))
            if found is None:
                continue
            technique, behavior = found
            claim = (f"A process execution record on {event.host} contains the executable-identified "
                     f"{behavior} command '{name}'. {_context_suffix(anchor, link)}")
            out.append(_exec_context_match(self, event, technique, claim, anchor, link))
        return out


# ---------------------------------------------------------------------------------------------
# Privilege probing and escalation (T1548, T1548.001, T1548.003). Positive-only.
# ---------------------------------------------------------------------------------------------

_SUID_MASKS = {"-4000", "+4000", "4000", "-2000", "+2000", "2000", "-6000", "+6000", "6000",
               "/4000", "/2000", "/6000", "-u=s", "/u=s", "u=s", "-g=s", "/g=s", "g=s", "-u+s", "-g+s"}
_SUDOERS_PATHS = ("/etc/sudoers",)


def _find_is_suid_search(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg == "-perm" and index + 1 < len(args) and args[index + 1] in _SUID_MASKS:
            return True
    return False


def _root_identity(event: TypedEvent) -> bool:
    """A typed effective-identity of uid 0 (root), from the kernel SYSCALL record."""
    return str(event.get("process.euid")) == "0" or str(event.get("process.uid")) == "0"


def _login_user_is_nonroot(event: TypedEvent) -> bool:
    """The login uid (auid) is a non-root account: a root euid in the same lineage/session is a gained
    privilege, not a root login. auid is kernel-recorded and preserved across su/sudo."""
    auid = event.get("process.auid")
    return auid is not None and str(auid) not in {"0", "4294967295", "-1"}


class PrivilegeProbing(ContextPlaybook):
    """`sudo -l`, setuid/setgid searches, sudoers reads, pkexec, and a typed effective-uid-0 process whose
    login user is non-root, all inside an anchored session or lineage. Positive-only: a missing record never
    proves privilege was not probed or gained."""

    id = "context.privilege_probing"
    version = "1"
    title = "Privilege probing or escalation in an anchored session or lineage"
    anchor_class = "execution"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    families = ("process_exec",)
    required_fields = ("process.executable",)
    assures_negative = False
    positive_only_reason = ("programs, flags and file operands are identified from argv, and an effective-uid-0 "
                            "process is only visible when its exec was recorded; absence proves neither that "
                            "privileges were not probed nor that none were gained")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1548", "T1548.001", "T1548.003", "T1068")
    benign = ("a system administrator checking their own sudo rights or auditing setuid binaries",
              "configuration-management and vulnerability-scanning tools",
              "a legitimate sudo/su to an admin account")
    next_checks = ("whether a listed sudo rule or setuid binary was then run",
                   "credential-file reads by the same session",
                   "commands the root-privileged process ran next")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            name, args = (program(event) or (None, []))
            if name is None:
                continue
            found = self._classify(name, args, event)
            if found is None:
                continue
            technique, behavior = found
            claim = (f"A process execution record on {event.host} shows {behavior}. "
                     f"{_context_suffix(anchor, link)}")
            out.append(_exec_context_match(self, event, technique, claim, anchor, link))
        return out

    def _classify(self, name: str, args: list[str], event: TypedEvent) -> tuple[str, str] | None:
        flags, _operands = split_flags(args)
        if name == "sudo" and "-l" in flags:
            return ("T1548.003", "the executable-identified privilege-listing command 'sudo -l'")
        if name == "find" and _find_is_suid_search(args):
            return ("T1548.001", "a 'find' search for setuid/setgid binaries (a privilege-escalation vector scan)")
        if name == "getcap":
            return ("T1548", "a 'getcap' enumeration of file capabilities (a privilege-escalation vector scan)")
        if name == "pkexec":
            return ("T1548", "an invocation of the setuid helper 'pkexec' (a privilege-elevation mechanism)")
        for path in read_operands(name, args, event.get("process.cwd")):
            if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
                return ("T1548.003", f"a read of the sudoers configuration file {path}")
        if _root_identity(event) and _login_user_is_nonroot(event):
            auid = event.get("process.auid")
            return ("T1548",
                    (f"a process (euid=0/root) whose kernel-recorded login user is the non-root account "
                     f"auid={auid}: effective root was held while the session logged in unprivileged"))
        return None


# ---------------------------------------------------------------------------------------------
# Credential access (T1003.008, T1552.001, T1552.003, T1552.004, T1555, T1555.003, T1555.005). Positive-only.
# ---------------------------------------------------------------------------------------------

_CRED_EXACT = {
    "/etc/shadow": ("T1003.008", "the local password-hash file /etc/shadow"),
    "/etc/gshadow": ("T1003.008", "the local group-password file /etc/gshadow"),
    "/etc/shadow-": ("T1003.008", "the local password-hash backup /etc/shadow-"),
    "/etc/gshadow-": ("T1003.008", "the local group-password backup /etc/gshadow-"),
    "/etc/security/opasswd": ("T1003.008", "the old-password file /etc/security/opasswd"),
}
_PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity", "server-key.pem"}
_HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".python_history",
                  ".mysql_history", ".psql_history", ".rediscli_history"}
_CRED_FILE_SUFFIXES = {
    ".netrc": ("T1552.001", "the .netrc credential file"),
    "/.aws/credentials": ("T1552.001", "AWS credentials"),
    "/.git-credentials": ("T1552.001", "stored git credentials"),
    "/.pgpass": ("T1552.001", "stored PostgreSQL credentials"),
    "/.docker/config.json": ("T1552.001", "a Docker registry auth config"),
    "/.kube/config": ("T1552.001", "a Kubernetes client config with credentials"),
    "/logins.json": ("T1555.003", "a Firefox saved-login store"),
    "/key4.db": ("T1555.003", "a Firefox credential key database"),
    "/login data": ("T1555.003", "a Chromium saved-login store"),
}


def _classify_credential_path(path: str) -> tuple[str, str] | None:
    if path in _CRED_EXACT:
        return _CRED_EXACT[path]
    name = basename(path)
    lower = path.lower()
    if name in _PRIVATE_KEY_NAMES or (name.startswith("ssh_host_") and name.endswith("_key")):
        return ("T1552.004", f"the private key file {path}")
    if name.endswith("_key") and "/.ssh/" in path and not name.endswith(".pub"):
        return ("T1552.004", f"the private key file {path}")
    if name in _HISTORY_NAMES:
        return ("T1552.003", f"the shell/application history file {path}")
    for suffix, found in _CRED_FILE_SUFFIXES.items():
        if lower.endswith(suffix):
            return found
    if "/.gnupg/" in path or "/.local/share/keyrings/" in lower or "/.password-store/" in path:
        return ("T1555.005", f"a credential/keyring store {path}")
    return None


class CredentialAccessInContext(ContextPlaybook):
    """A reader program pointed at a credential store (shadow, SSH private keys, shell history, cloud and
    credential files, .netrc, browser or keyring stores) inside an anchored session or lineage.
    Positive-only: a credential file can be read in ways argv does not show (an editor, a program that opens
    it directly), so absence proves nothing."""

    id = "context.credential_access"
    version = "1"
    title = "Credential-store read in an anchored session or lineage"
    anchor_class = "credential_access"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    families = ("process_exec",)
    required_fields = ("process.executable",)
    assures_negative = False
    positive_only_reason = ("the reader and the credential file are identified from argv, not from a file-access "
                            "record, and a credential store can be opened in ways argv does not show; absence "
                            "proves nothing")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1003.008", "T1552.001", "T1552.003", "T1552.004", "T1555", "T1555.003", "T1555.005")
    benign = ("a system administrator or backup job reading configuration or key files",
              "a user viewing their own shell history")
    next_checks = ("staging, encoding or outbound transfer of what was read",
                   "use of a read SSH key to log in to another host",
                   "the other commands in the same session")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            name, args = (program(event) or (None, []))
            if name is None:
                continue
            found = None
            for path in read_operands(name, args, event.get("process.cwd")):
                found = _classify_credential_path(path)
                if found is not None:
                    break
            if found is None:
                continue
            technique, what = found
            claim = (f"A process execution record on {event.host} records the reader '{name}' invoked with "
                     f"{what} as a file operand. {_context_suffix(anchor, link)}")
            out.append(_exec_context_match(self, event, technique, claim, anchor, link))
        return out


# ---------------------------------------------------------------------------------------------
# Staging and transfer (T1560.001, T1027.013, T1048, T1570, T1021.004, T1105). Positive-only.
# ---------------------------------------------------------------------------------------------

_ARCHIVERS = {"tar", "gzip", "bzip2", "xz", "zip", "7z", "7za", "cpio", "zstd", "pigz", "lz4"}
_ENCODERS = {"base64", "base32", "xxd", "uuencode"}


def _has_sensitive_operand(args: list[str], cwd: str | None) -> str | None:
    from romulus.detect.linux_argv import normalize_path
    _flags, operands = split_flags(args)
    for operand in operands:
        path = normalize_path(operand, cwd)
        if path and is_under(path, SENSITIVE_DIRS):
            return path
    return None


def _remote_scp_target(args: list[str]) -> str | None:
    """A remote operand of scp/rsync/sftp: `user@host:path` or `host:path` (not a local absolute path, not a
    URL option). Positive-only text lead."""
    _flags, operands = split_flags(args)
    for operand in operands:
        if operand.startswith(("/", "-")):
            continue
        host_part = operand.split(":", 1)
        if len(host_part) == 2 and host_part[0] and "/" not in host_part[0]:
            return host_part[0].split("@", 1)[-1]
    return None


def _curl_upload(args: list[str]) -> bool:
    flags, _operands = split_flags(args)
    if flags & {"-T", "--upload-file", "-F", "--form"}:
        return True
    return any(a.startswith(("--data-binary", "-d@", "--data=@")) for a in args)


def classify_transfer(name: str, args: list[str], cwd: str | None) -> tuple[str, str] | None:
    """Classify a staging or outbound-transfer command. Token-aware, argv only."""
    if any("/dev/tcp/" in str(a) or "/dev/udp/" in str(a) for a in args):
        return ("T1048", "a shell /dev/tcp (or /dev/udp) pseudo-device write (an outbound byte stream)")
    if name in _ARCHIVERS:
        sensitive = _has_sensitive_operand(args, cwd)
        if sensitive:
            return ("T1560.001", (f"an archive/compression command over the sensitive path {sensitive} "
                    "(data staged for collection)"))
        return None
    if name in _ENCODERS:
        sensitive = _has_sensitive_operand(args, cwd)
        if sensitive:
            return ("T1027.013", (f"an encoding command ('{name}') over the sensitive path {sensitive} "
                    "(encoded data, often staged before transfer)"))
        return None
    if name in {"scp", "rsync", "sftp"}:
        target = _remote_scp_target(args)
        if target:
            technique = "T1021.004" if name in {"scp", "sftp"} else "T1570"
            return (technique, (f"an outbound '{name}' transfer to remote host '{target}' (host as given on the "
                    "command line; not resolved in telemetry)"))
        return None
    if name in {"curl", "wget"} and _curl_upload(args):
        return ("T1048", f"an outbound upload with '{name}' (file-upload flags present on the command line)")
    if name in {"nc", "ncat", "netcat"}:
        flags, operands = split_flags(args)
        if not (flags & {"-l", "--listen"}) and len(operands) >= 2:
            return ("T1048", f"an outbound '{name}' client connection to '{operands[0]}' (a byte stream)")
        return None
    return None


class StagingAndTransfer(ContextPlaybook):
    """Archiving/encoding of sensitive paths, or an outbound transfer command, inside an anchored session or
    lineage. Positive-only: the command line shows intent and direction; it does not prove bytes left the
    host (no record of the transfer's outcome is required here)."""

    id = "context.staging_and_transfer"
    version = "1"
    title = "Data staging or outbound transfer in an anchored session or lineage"
    anchor_class = "execution"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    families = ("process_exec",)
    required_fields = ("process.executable",)
    assures_negative = False
    positive_only_reason = ("the archiver, encoder or transfer tool and its operands are identified from argv; "
                            "the command line shows intent and direction but not that bytes were staged or "
                            "left the host, so absence proves nothing")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1560.001", "T1074.001", "T1027.013", "T1048", "T1570", "T1021.004")
    benign = ("a backup job archiving /etc or /var/lib", "a deployment copying files to another host",
              "a packaging or build step that compresses source trees")
    next_checks = ("the destination host or URL, and whether a flow to it was observed",
                   "what was archived or encoded, and whether it was read from a credential store",
                   "the other commands in the same session")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            name, args = (program(event) or (None, []))
            if name is None:
                continue
            found = classify_transfer(name, args, event.get("process.cwd"))
            if found is None:
                continue
            technique, behavior = found
            claim = (f"A process execution record on {event.host} shows {behavior}. "
                     f"{_context_suffix(anchor, link)}")
            out.append(_exec_context_match(self, event, technique, claim, anchor, link))
        return out


# ---------------------------------------------------------------------------------------------
# Lateral movement (T1021, T1021.001/.002/.004/.006, T1570). Positive-only for exec; the socket connect is a
# kernel-recorded observation with its own outcome.
# ---------------------------------------------------------------------------------------------

_LATERAL_PORTS = {
    22: ("T1021.004", "SSH"),
    445: ("T1021.002", "SMB/Windows admin shares"),
    139: ("T1021.002", "SMB/Windows admin shares"),
    3389: ("T1021.001", "RDP"),
    5985: ("T1021.006", "WinRM (HTTP)"),
    5986: ("T1021.006", "WinRM (HTTPS)"),
}
_REMOTE_CLIENTS = {
    "ssh": ("T1021.004", "SSH"),
    "scp": ("T1021.004", "SSH (scp)"),
    "sftp": ("T1021.004", "SSH (sftp)"),
    "rsync": ("T1570", "rsync"),
    "smbclient": ("T1021.002", "SMB"),
}


def _ssh_target(args: list[str]) -> str | None:
    """The destination operand of an ssh/scp/rsync/sftp client, token-aware (options skipped)."""
    skip_value = {"-i", "-p", "-l", "-o", "-F", "-c", "-m", "-b", "-e", "-J", "-w", "-D", "-L", "-R"}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in skip_value:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        host = arg.split(":", 1)[0]
        return host.split("@", 1)[-1] if host else None
    return None


class LateralMovement(ContextPlaybook):
    """A remote-service client (ssh/scp/rsync/sftp/smbclient) toward another host, or a kernel socket connect
    to an internal remote-service port (22/445/3389/5985), inside an anchored session or lineage. The client
    case is positive-only (argv). The socket case is an observed connect with its own outcome; the link
    wording states whether the target host is observed (a socket gives an internal address, not a host name)."""

    id = "context.lateral_movement"
    version = "1"
    title = "Lateral remote-service use from an anchored session or lineage"
    anchor_class = "lateral_movement"
    anchor_classes = ANCHOR_HOST
    link_types = HOST_LINKS
    families = ("process_exec", "net_socket")
    required_fields = ()
    assures_negative = False
    positive_only_reason = ("the remote-service client and its target are identified from argv, and the socket "
                            "connect path depends on the audit rule set recording that syscall; a session can "
                            "move laterally in ways these records do not show, so absence proves nothing")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1021", "T1021.001", "T1021.002", "T1021.004", "T1021.006", "T1570")
    benign = ("routine administration or deployment from a jump host",
              "monitoring agents and backup jobs that connect to internal services")
    next_checks = ("whether the target host is itself an anchor or shows follow-on activity",
                   "the credential used (a key or password read earlier in the session)",
                   "whether a network sensor also recorded the flow")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            match = self._exec_match(event, anchor, link) or self._socket_match(event, anchor, link)
            if match is not None:
                out.append(match)
        return out

    def _exec_match(self, event, anchor, link):
        if event.family != "process_exec":
            return None
        name, args = (program(event) or (None, []))
        if name not in _REMOTE_CLIENTS:
            return None
        target = _ssh_target(args) if name != "smbclient" else _smbclient_target(args)
        if not target:
            return None
        technique, service = _REMOTE_CLIENTS[name]
        internal_note = _internal_target_note(target)
        claim = (f"A process execution record on {event.host} shows the {service} client '{name}' invoked toward "
                 f"'{target}' (host as given on the command line{internal_note}; not resolved in telemetry). "
                 f"{_context_suffix(anchor, link)}")
        match = _exec_context_match(self, event, technique, claim, anchor, link)
        return match

    def _socket_match(self, event, anchor, link):
        if event.family != "net_socket" or event.get("socket.syscall") != "connect":
            return None
        try:
            destination = ipaddress.ip_address(str(event.get("destination.ip")))
        except ValueError:
            return None
        port = event.get("destination.port")
        if not is_internal(destination) or port not in _LATERAL_PORTS:
            return None
        technique, service = _LATERAL_PORTS[port]
        outcome = ("the connect() call succeeded" if event.outcome == Outcome.success
                   else "the connect() call failed" if event.outcome == Outcome.failure
                   else "the connect() outcome is unknown")
        claim = (f"A kernel socket record on {event.host} shows a connect() to the internal {service} port "
                 f"{destination}:{port}; {outcome}. The target is an observed internal address, not a resolved "
                 f"host name. {_context_suffix(anchor, link)}")
        predicate = [pf(event, "destination.ip"), pf(event, "destination.port")]
        if event.has("socket.syscall"):
            predicate.append(pf(event, "socket.syscall"))
        match = Match(
            self.id, claim, self.claim_type, [event], predicate, event.ts,
            self.severity, self.lane, "high" if event.outcome == Outcome.success else "medium",
            event.entities(), group_key=raw_identity(event),
        )
        match.notes.append(technique)
        return match


def _smbclient_target(args: list[str]) -> str | None:
    _flags, operands = split_flags(args)
    for operand in operands:
        if operand.startswith(("//", "\\\\")):
            stripped = operand.lstrip("/").lstrip("\\")
            return stripped.replace("\\", "/").split("/", 1)[0] or None
    return None


def _internal_target_note(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return ""
    return "; an internal address" if is_internal(address) else "; a non-internal address"


# ---------------------------------------------------------------------------------------------
# Entry-point promotion (T1078, T1021.004).
# ---------------------------------------------------------------------------------------------

class EntryPointPromotion(ContextPlaybook):
    """A successful external sshd login that began an anchored session is promoted exactly once per
    (host, session, account, source). The login or authentication-phase record is preferred; if the linked
    session carries only its PAM session-open record, that record is used, worded as such. A login is never
    promoted twice."""

    id = "context.entry_point_promotion"
    version = "2"
    title = "Remote-login entry point linked to a later anchor-class finding"
    anchor_class = "remote_login"
    anchor_classes = ("*",)
    link_types = ("login_session",)
    families = ("auth",)
    # Only the service is required to recognise an sshd record; the login record carries the source, while a
    # PAM session-open record may not. Requiring source.ip would drop the fallback record (ADR-006).
    required_fields = ("auth.service",)
    assures_negative = False
    positive_only_reason = ("the login is recognised from sshd records whose fields are in part parsed from "
                            "journal message text (ADR-004), and only within the linked session; absence of an "
                            "external entry point in that scope proves nothing")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1078", "T1021.004")
    benign = ("approved remote administration followed by authorized maintenance",)
    next_checks = ("the complete login session", "the source address across hosts",
                   "whether the account logs in from this source elsewhere")

    _PHASE_RANK: ClassVar[dict[str, int]] = {"login": 0, "authentication": 0, "session_open": 2}

    def match_linked(self, anchor, link, events):
        candidates = []
        for event in self.applicable(events):
            if event.get("auth.service") != "sshd" or event.outcome != Outcome.success:
                continue
            source = event.get("source.ip")
            if source is not None:
                try:
                    if is_internal(ipaddress.ip_address(str(source))):
                        continue                       # an internal SSH source is not an external entry point
                except ValueError:
                    continue
            candidates.append(event)
        if not candidates:
            return []
        # Prefer a login/authentication record (rank 0) over a session-open record (rank 2); then a record
        # that carries the source; then the earliest. One promotion for the whole linked session.
        chosen = min(candidates, key=lambda event: (
            self._PHASE_RANK.get(event.get("auth.phase"), 1),
            0 if event.get("source.ip") is not None else 1,
            event.ts, event.id,
        ))
        source = chosen.get("source.ip")
        session_id = chosen.get("process.session_id") or link.key.get("process.session_id")
        account = chosen.get("user.name")
        group_key = f"{chosen.host}|{session_id}|{account}|{source}"
        if self._PHASE_RANK.get(chosen.get("auth.phase"), 1) >= 2 or source is None:
            source_clause = (f"from {source} " if source else "")
            lead = (f"The session-open record of a remote SSH login {source_clause}on {chosen.host}")
        else:
            lead = f"A successful remote login from {source} on {chosen.host}"
        claim = (f"{lead} began the observed login session that later performed {anchor.id}. "
                 f"{_context_suffix(anchor, link)}")
        predicate = [pf(chosen, "auth.service")]
        for name in ("source.ip", "user.name"):
            if chosen.has(name):
                predicate.append(pf(chosen, name))
        confidence = "high" if source is not None else "medium"
        match = Match(
            self.id, claim, self.claim_type, [chosen], predicate, chosen.ts,
            self.severity, self.lane, confidence, chosen.entities(), group_key=group_key,
        )
        match.notes.append("T1078")
        return [match]


CONTEXT_PLAYBOOKS = [
    PostAccessDiscovery, PrivilegeProbing, CredentialAccessInContext,
    StagingAndTransfer, LateralMovement, EntryPointPromotion,
]
