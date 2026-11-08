"""Positive Linux execution, identity, credential and certificate observations.

Package names and locations come from distribution manifests; these are path indicators, not
an inspection of local package signatures or effective directory permissions.
"""
from __future__ import annotations

import ast
import json
import posixpath
import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore, RecentIds
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS, ProcessLineage, _audit_serial, boot_of
from romulus.detect.linux_argv import getopt_long, normalize_path, program, read_operand_paths, write_targets
from romulus.detect.linux_semantics import classify_credential
from romulus.detect.observed import EXEC
from romulus.evidence.typed import Outcome

DEBIAN_FILES = "https://packages.debian.org/bookworm/amd64/{}/filelist"
PACKAGE_SOURCES = tuple(DEBIAN_FILES.format(p) for p in (
    "openssh-server", "systemd", "cron", "rsyslog", "dbus-daemon", "polkitd", "util-linux", "login",
    "sudo", "bash", "dash"))
# Distribution manifests include /bin and /sbin spellings before merged-/usr.
# A directory must match exactly: /tmp/usr/bin and /usr/bin/subdir are not package locations.
BASE_PACKAGE_DIRS = frozenset({"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/systemd",
                              "/lib/systemd", "/usr/libexec"})
SYSTEM_BINARIES = {
    "sshd": "openssh-server", "systemd": "systemd", "cron": "cron", "crond": "cronie",
    "rsyslogd": "rsyslog", "dbus-daemon": "dbus-daemon", "polkitd": "polkitd",
    "agetty": "util-linux", "sudo": "sudo", "su": "util-linux", "login": "login",
    "bash": "bash", "sh": "dash",
}
PACKAGE_EXTRA_DIRS = {"polkitd": frozenset({"/usr/lib/polkit-1", "/usr/lib64/polkit-1", "/usr/lib/policykit-1"})}
# Real packaged names are never lookalikes of each other; dash, newgrp and sg are from the same manifests.
PACKAGED_NAMES = frozenset(SYSTEM_BINARIES) | {"dash", "sudoedit", "newgrp", "sg"}
PACKAGE_SOURCES += ("https://packages.fedoraproject.org/pkgs/cronie/cronie/fedora-44.html",)
# Map only documented container storage prefixes. An image path is inferred; the container's package inventory
# is unavailable, so this prevents a host-storage prefix alone from making a packaged image look displaced.
OVERLAY_PATHS = (
    re.compile(r"^/var/lib/docker/overlay2/[^/]+/merged(?P<image>/.*)$"),
    re.compile(r"^/var/lib/containers/storage/overlay/[^/]+/(?:merged|diff)(?P<image>/.*)$"),
)
KERNEL_THREAD = re.compile(r"^\[(?:kworker(?:/[^\]]+)?|kthreadd|ksoftirqd/\d+|migration/\d+|rcu[^\]]*|"
                           r"watchdog/\d+|kcompactd\d*|kswapd\d*|kdevtmpfs)\]$")
TEMP_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")
MODULE_ROOTS = ("/lib/modules", "/usr/lib/modules")
READERS = frozenset({"cat", "less", "head", "tail", "cp", "scp", "tar", "base64", "xxd", "strings", "grep"})
# Narrow exclusions name the path class and its owning service, never an arbitrary process substring.
OWNING_DAEMONS = (
    ("/var/lib/jenkins/", frozenset({"jenkins", "java"}), frozenset({"jenkins"})),
    ("/etc/vault.d/", frozenset({"vault"}), frozenset({"vault"})),
    ("/etc/ssh/ssh_host_", frozenset({"sshd", "sshd-session", "sshd-auth"}), frozenset({"root", "sshd"})),
    ("/etc/krb5.keytab", frozenset({"sssd", "winbindd", "krb5kdc"}), frozenset({"root", "sssd", "krb5kdc"})),
    ("/etc/ssl/private/", frozenset({"nginx", "apache2", "httpd", "haproxy"}),
     frozenset({"root", "nginx", "www-data", "apache", "httpd", "haproxy"})),
)
# Authentication, account management and scheduled root services routinely consult local hashes.
# Exact names in exact package directories plus a kernel-recorded uid 0 are required. A username
# alone is insufficient; interpreters and copies in other directories never enter this table.
SHADOW_DAEMONS = frozenset({
    "cron", "crond", "anacron", "atd", "sshd", "sshd-session", "sshd-auth", "unix_chkpwd",
    "polkitd", "polkit-agent-helper-1", "login", "su", "sudo", "sudoedit", "passwd", "chage",
    "chpasswd", "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "gpasswd",
    "newusers", "systemd", "systemd-logind", "systemd-userdbd", "systemd-homed", "systemd-machined",
    "systemd-sysusers", "nscd", "sssd", "sssd_pam", "sssd_nss", "sssd_be",
})
SHADOW_EXTRA_DIRS = {
    "sshd-session": frozenset({"/usr/lib/openssh", "/usr/libexec/openssh"}),
    "sshd-auth": frozenset({"/usr/lib/openssh", "/usr/libexec/openssh"}),
    "unix_chkpwd": frozenset({"/usr/lib/pam", "/usr/libexec"}),
    "polkitd": frozenset({"/usr/lib/polkit-1", "/usr/lib64/polkit-1", "/usr/lib/policykit-1"}),
    "polkit-agent-helper-1": frozenset({"/usr/lib/polkit-1", "/usr/lib64/polkit-1", "/usr/lib/policykit-1"}),
    **{name: frozenset({"/usr/libexec/sssd", "/usr/lib/sssd", "/usr/lib64/sssd"})
       for name in ("sssd_pam", "sssd_nss", "sssd_be")},
}
ROOT_BINARY_DIRS = frozenset({"/usr/bin", "/usr/sbin", "/bin", "/sbin"})
SHADOW_BACKUP_TOOLS = frozenset({"tar", "rsync", "cmp", "cp"})
# The watched read does not establish whether a backup also writes outside /etc. These remain
# folded leads, rather than exclusions, only for uid 0 tools directly in these two package dirs.
BACKUP_DIRS = frozenset({"/usr/bin", "/bin"})
# A root copy named on the command line is routine only when every destination stays in /etc or the
# distribution's backup directory (Debian's daily passwd job copies to /var/backups).
SHADOW_BACKUP_DESTINATIONS = ("/etc", "/var/backups")
# Packaged setuid/setgid helpers read the hashes with the invoking user's real uid.
SETUID_SHADOW_HELPERS = frozenset({"su", "sudo", "sudoedit", "passwd", "chage", "gpasswd", "unix_chkpwd",
                                   "polkit-agent-helper-1"})
PACKAGE_STORE_PATH = re.compile(r"^/(?:nix|gnu)/store/[^/]+-[^/]+/(?P<image>.+)$")

# ---- Hash-file reads by package maintenance and provisioning (kept as leads, never excluded) ----
# Perl's and Python's built-in account lookups (getpwnam, getspnam, pwd/spwd) open the shadow file when they run as
# root. Debian and Ubuntu package tooling is largely Perl and Python (debconf, dpkg-preconfigure, cloud-init,
# unattended-upgrades), so every provisioning run, upgrade and some service starts produce these reads. A read is
# routed to the lead lane only when every typed fact below holds; anything unresolved stays high.
# Interpreters, by kernel-recorded executable, only in the package directories they ship in.
MAINTENANCE_INTERPRETER = re.compile(r"^(?:perl|perl5(?:\.\d+)+|python|python3(?:\.\d+)*)$")
MAINTENANCE_INTERPRETER_DIRS = frozenset({"/usr/bin", "/bin"})
# Switch clusters a `#!` line passes as the one argument before the script (`#!/usr/bin/perl -w`,
# `#!/usr/bin/python3 -Es`). Only switches that take no value are accepted, so the next token is the script; any
# other leading option leaves the script unidentified (and the read high).
SHEBANG_SWITCHES = {"perl": frozenset("wTtWX"), "python": frozenset("EsSuBIOqR")}
# Script locations a package installs: the binary directories exactly, or a package's own tree under /usr/share or
# /usr/lib (at least /usr/share/<pkg>/<file>). Relative, temporary and home paths never match.
SCRIPT_BINARY_DIRS = frozenset({"/usr/bin", "/usr/sbin", "/bin", "/sbin"})
SCRIPT_PACKAGE_TREES = ("/usr/share/", "/usr/lib/")
# Package managers and provisioners whose descendants legitimately read the hash files as root. One table: compiled
# programs by name in their packaged directories, interpreter-hosted tools by the exact script path the
# interpreter runs. Each entry names its source (the distribution's file list for that package).
PROVISIONER_BINARIES = {
    # Debian/Ubuntu: dpkg, apt, aptitude (https://packages.debian.org/bookworm/amd64/{dpkg,apt,aptitude}/filelist)
    "dpkg": SCRIPT_BINARY_DIRS, "apt": SCRIPT_BINARY_DIRS, "apt-get": SCRIPT_BINARY_DIRS,
    "aptitude": SCRIPT_BINARY_DIRS,
    # RPM family: rpm, dnf5, zypper (https://packages.fedoraproject.org/pkgs/rpm/rpm/,
    # https://packages.fedoraproject.org/pkgs/dnf5/dnf5/, https://software.opensuse.org/package/zypper)
    "rpm": SCRIPT_BINARY_DIRS, "dnf5": SCRIPT_BINARY_DIRS, "zypper": SCRIPT_BINARY_DIRS,
    # PackageKit's daemon (https://packages.debian.org/bookworm/amd64/packagekit/filelist; Fedora /usr/libexec)
    "packagekitd": frozenset({"/usr/libexec", "/usr/lib/packagekit", "/usr/libexec/packagekit"}),
    # snapd (https://packages.debian.org/bookworm/amd64/snapd/filelist)
    "snapd": frozenset({"/usr/lib/snapd", "/usr/libexec/snapd"}),
}
PROVISIONER_SCRIPTS = {
    # unattended-upgrades (https://packages.debian.org/bookworm/all/unattended-upgrades/filelist)
    "/usr/bin/unattended-upgrade": "unattended-upgrade",
    # cloud-init (https://packages.debian.org/bookworm/all/cloud-init/filelist)
    "/usr/bin/cloud-init": "cloud-init",
    # debconf frontends and tools (https://packages.debian.org/bookworm/all/debconf/filelist)
    "/usr/share/debconf/frontend": "debconf frontend",
    "/usr/bin/debconf-set-selections": "debconf-set-selections",
    "/usr/bin/debconf-apt-progress": "debconf-apt-progress",
    "/usr/bin/debconf-communicate": "debconf-communicate",
    "/usr/sbin/dpkg-preconfigure": "dpkg-preconfigure",
    "/usr/sbin/dpkg-reconfigure": "dpkg-reconfigure",
    # dnf 4 and yum are Python programs (https://packages.fedoraproject.org/pkgs/dnf/dnf/,
    # https://packages.fedoraproject.org/pkgs/dnf/yum/)
    "/usr/bin/dnf": "dnf", "/usr/bin/dnf-3": "dnf", "/usr/bin/yum": "yum",
}
PROVISIONER_SOURCES = (
    "https://packages.debian.org/bookworm/amd64/dpkg/filelist",
    "https://packages.debian.org/bookworm/amd64/apt/filelist",
    "https://packages.debian.org/bookworm/all/debconf/filelist",
    "https://packages.debian.org/bookworm/all/cloud-init/filelist",
    "https://packages.debian.org/bookworm/all/unattended-upgrades/filelist",
    "https://perldoc.perl.org/functions/getpwnam",
)
# Ancestors walked above the reader. Debian's deepest routine chain is the debconf frontend under a maintainer
# script under dpkg under apt under a provisioner (four or five steps); eight leaves room for nested maintainer
# helpers (ucf, invoke-rc.d, a shell) and keeps every walk bounded. A provisioner beyond it is not found, and the
# read stays high.
PROVISIONER_DEPTH = 8


def maintenance_interpreter(executable: str) -> str:
    """The interpreter family ('perl' or 'python') of a kernel-recorded executable in a package directory, else ''."""
    name = basename(executable)
    if posixpath.dirname(executable) not in MAINTENANCE_INTERPRETER_DIRS or not MAINTENANCE_INTERPRETER.match(name):
        return ""
    return "perl" if name.startswith("perl") else "python"


def interpreter_script(family: str, argv) -> str:
    """The script an interpreter was given: argv[1], or argv[2] after one `#!`-style cluster of value-free switches.
    '' when the operand is inline code, a module, standard input or not an absolute path."""
    if not isinstance(argv, list) or len(argv) < 2:
        return ""
    operand = str(argv[1])
    if operand.startswith("-"):
        cluster = operand[1:]
        if not cluster or not set(cluster) <= SHEBANG_SWITCHES[family] or len(argv) < 3:
            return ""
        operand = str(argv[2])
    if not operand.startswith("/"):
        return ""
    return normalize_path(operand)


def packaged_script(path: str) -> bool:
    """Whether a script path lies where a package installs scripts (see SCRIPT_BINARY_DIRS)."""
    if posixpath.dirname(path) in SCRIPT_BINARY_DIRS:
        return True
    for tree in SCRIPT_PACKAGE_TREES:
        rest = path[len(tree):] if path.startswith(tree) else ""
        if "/" in rest and rest.split("/", 1)[0] and rest.split("/", 1)[1]:
            return True
    return False


def shadow_reader(path, event):
    executable = normalize_path(str(event.get("process.executable") or ""))
    name, directory = basename(executable), posixpath.dirname(executable)
    if path not in {"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-"}:
        return ""
    if str(event.get("process.uid")) != "0" and name not in SETUID_SHADOW_HELPERS:
        return ""
    dirs = ROOT_BINARY_DIRS | SHADOW_EXTRA_DIRS.get(name, frozenset())
    if name.startswith("systemd-") or name == "systemd":
        dirs |= frozenset({"/usr/lib/systemd", "/lib/systemd"})
    if name in SHADOW_DAEMONS and directory in dirs:
        return "daemon"
    return "backup" if name in SHADOW_BACKUP_TOOLS and directory in BACKUP_DIRS else ""


def routine_backup_command(p, event):
    """A root backup tool's command line stays a lead only when argv shows no copy leaving /etc and the backup
    directory: a compare, or typed write destinations that all stay there. Untyped destinations keep the read HIGH."""
    if p.name == "cmp":
        return True
    argv = event.get("process.argv")
    argv0 = str(argv[0]) if isinstance(argv, list) and argv else ""
    targets, unplaced = write_targets(p.name, p.args, event.get("process.cwd"), argv0)
    return bool(targets) and not unplaced and all(under(t.path, SHADOW_BACKUP_DESTINATIONS) for t in targets)


CREDENTIAL_SOURCES = (
    "https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html",
    "https://developer.hashicorp.com/vault/docs/commands",
    "https://www.jenkins.io/doc/book/security/securing-jenkins/",
)
DOWNLOADER_SOURCES = {
    "curl": "https://curl.se/docs/manpage.html",
    "wget": "https://www.gnu.org/software/wget/manual/html_node/Download-Options.html",
    "fetch": "https://man.freebsd.org/cgi/man.cgi?query=fetch&sektion=1",
    "tftp": "https://manpages.debian.org/bookworm/tftp-hpa/tftp.1.en.html",
    "scp": "https://man.openbsd.org/scp",
    "ftp": "https://man.openbsd.org/ftp",
    "python": "https://docs.python.org/3/library/urllib.request.html",
    "perl": "https://metacpan.org/pod/LWP::Simple",
}
# GNU Wget distinguishes log output (-o/-a) from document output (-O).
# https://raw.githubusercontent.com/mirror/wget/master/doc/wget.texi
WGET_VALUE_OPTIONS = {
    "--output-document": ("O", True), "--directory-prefix": ("P", True),
    "--output-file": ("o", True), "--append-output": ("a", True),
    "--input-file": ("i", True), "--execute": ("e", True),
    "--user-agent": ("U", True), "--header": ("header", True),
    "--post-data": ("post-data", True), "--post-file": ("post-file", True),
    "--tries": ("t", True), "--timeout": ("T", True), "--wait": ("w", True),
    "--level": ("l", True), "--quota": ("Q", True), "--user": ("user", True),
    "--password": ("password", True),
    "--quiet": ("q", False), "--verbose": ("v", False), "--no-verbose": ("nv", False),
    "--continue": ("c", False), "--recursive": ("r", False), "--no-check-certificate": ("certificate", False),
}


def under(path, roots):
    return any(path == root or path.startswith(root + "/") for root in roots)


def temporary(path):
    return under(path, TEMP_ROOTS) or bool(re.match(r"^/run/user/[^/]+/", path))


def web(event):
    return any(event.get(name) in WEB_SERVICE_USERS for name in ("process.user", "process.effective_user", "user.name"))


def wget_paths(event, args):
    """Transfer destinations and explicitly separate log destinations, including GNU attached short values."""
    parsed = getopt_long(args, "oaOieUPtTwlQ", "VhbqvdNcrpSHkKmn", WGET_VALUE_OPTIONS)
    output, directory, logs = None, None, []
    for option, value in parsed.options:
        if option == "O":
            output = value
        elif option == "P":
            directory = value
        elif option in {"o", "a"} and value:
            logs.append(normalize_path(value, event.get("process.cwd")))
    urls = [operand for operand in parsed.operands if operand.startswith(("http://", "https://", "ftp://"))]
    paths = []
    if output and output != "-":
        paths.append(normalize_path(output, event.get("process.cwd")))
    elif output is None:
        for url in urls:
            leaf = posixpath.basename(urlsplit(url).path)
            if leaf:
                paths.append(normalize_path(posixpath.join(directory or "", leaf), event.get("process.cwd")))
    paths = list(dict.fromkeys(path for path in paths if path))
    return bool(urls), paths if urls else [], list(dict.fromkeys(path for path in logs if path and path not in paths))


def download_log_paths(event):
    """Only explicitly documented log outputs can exclude a downloader's observed ancillary file writes."""
    p = program(event)
    return wget_paths(event, p.args)[2] if p and p.name == "wget" else []


def output_paths(event):
    """Downloader identity plus explicitly named destinations; no invisible shell redirection is guessed.

    Python parsing recognizes literal URLs and literal urlretrieve destinations. Other one-liners need a
    same-pid kernel file-write record; source code interpretation only adds positive observations.
    """
    p = program(event)
    if p is None:
        return False, []
    name, args = p.name, p.args
    if name == "wget":
        transferring, paths, _logs = wget_paths(event, args)
        return transferring, paths
    paths, output, directory, remote_name, urls = [], None, None, False, []
    if name.startswith("python") and "-c" in args:
        index = args.index("-c")
        if index + 1 >= len(args):
            return False, []
        try:
            tree = ast.parse(args[index + 1])
        except (SyntaxError, ValueError, RecursionError):
            return False, []
        nodes = list(ast.walk(tree))
        aliases = {}
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module in {"urllib.request", "urllib", "requests"}:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        def qualified(node):
            if isinstance(node, ast.Name):
                return aliases.get(node.id, "")
            if isinstance(node, ast.Attribute):
                parent = qualified(node.value)
                return f"{parent}.{node.attr}" if parent else ""
            return ""
        allowed = {"urllib.request.urlretrieve", "urllib.request.urlopen", "urllib.urlretrieve", "urllib.urlopen",
                   "requests.get", "requests.request"}
        downloads = [node for node in nodes if isinstance(node, ast.Call) and qualified(node.func) in allowed
                     and any(isinstance(a, ast.Constant) and isinstance(a.value, str)
                             and a.value.startswith(("http://", "https://", "ftp://")) for a in node.args)]
        if not downloads:
            return False, []
        for call in downloads:
            if qualified(call.func).endswith(".urlretrieve") and len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                value = call.args[1].value
                if isinstance(value, str) and (path := normalize_path(value, event.get("process.cwd"))):
                    paths.append(path)
        return True, paths
    if name == "perl":
        # Positive token grammar for Perl one-liners, not arbitrary text mentions.
        selected = next((args[i + 1] for i, arg in enumerate(args[:-1]) if arg in {"-e", "-E"}), "")
        uses_lwp = bool(re.search(r"\buse\s+LWP::(?:Simple|UserAgent)\b", selected)
                        or any(arg.startswith(("-MLWP::Simple", "-MLWP::UserAgent")) for arg in args))
        found = bool(uses_lwp
                     and re.search(r"\b(?:get|mirror|getstore)\s*\(?\s*['\"]https?://", selected))
        return found, []
    if name not in DOWNLOADER_SOURCES:
        return False, []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-o", "--output", "--output-document"} or name == "wget" and arg == "-O":
            if i + 1 < len(args):
                output = args[i + 1]
                i += 1
        elif arg.startswith(("--output=", "--output-document=")):
            output = arg.split("=", 1)[1]
        elif name == "curl" and arg.startswith("-o") and len(arg) > 2 or name == "wget" and arg.startswith("-O") and len(arg) > 2:
            output = arg[2:]
        elif arg in {"-P", "--directory-prefix"} and name == "wget":
            if i + 1 < len(args):
                directory = args[i + 1]
                i += 1
        elif name == "wget" and arg.startswith("--directory-prefix="):
            directory = arg.split("=", 1)[1]
        elif name == "curl" and arg.startswith("-") and not arg.startswith("--") and "O" in arg[1:] or arg == "--remote-name":
            remote_name = True
        elif arg.startswith(("http://", "https://", "ftp://", "tftp://")):
            urls.append(arg)
        i += 1
    if output and output != "-":
        paths.append(normalize_path(output, event.get("process.cwd")))
    if not output and (name == "wget" or remote_name or name == "fetch"):
        for url in urls:
            leaf = posixpath.basename(urlsplit(url).path)
            if leaf:
                paths.append(normalize_path(posixpath.join(directory or "", leaf), event.get("process.cwd")))
    transferring = bool(urls)
    if name == "scp":
        ops = [a for a in args if not a.startswith("-")]
        if len(ops) >= 2 and ":" in ops[-2] and ":" not in ops[-1]:
            target = ops[-1]
            if target.endswith("/"):
                target = posixpath.join(target, posixpath.basename(ops[-2].split(":", 1)[1]))
            paths.append(normalize_path(target, event.get("process.cwd")))
            transferring = True
    if name == "tftp" and "-g" in args:
        for flag in ("-l", "--local-file"):
            if flag in args and args.index(flag) + 1 < len(args):
                paths.append(normalize_path(args[args.index(flag) + 1], event.get("process.cwd")))
        transferring = True
    if name == "tftp" and "-c" in args:
        index = args.index("-c")
        operands = args[index + 1:]
        if len(operands) >= 2 and operands[0] == "get":
            target = operands[2] if len(operands) > 2 else posixpath.basename(operands[1])
            paths.append(normalize_path(target, event.get("process.cwd")))
            transferring = True
    return transferring, list(dict.fromkeys(path for path in paths if path)) if transferring else []


def executed_paths(event):
    path = normalize_path(str(event.get("process.executable") or ""))
    paths = [path] if path else []
    recorded = event.get("process.exec_file.path")
    if recorded:
        paths.append(str(recorded))
    p = program(event)
    if p and p.name in INTERPRETERS:
        args = p.args
        # A script operand precedes the script's own options. -c/-m/-e mean code or module, not a script file.
        for arg in args:
            if arg in {"-c", "-m", "-e", "-E"}:
                break
            if not arg.startswith("-"):
                if script := normalize_path(arg, event.get("process.cwd")):
                    paths.append(script)
                break
    return list(dict.fromkeys(paths))


def observed(rule, event, claim, lane="lead", group="", names=()):
    return Match(rule.id, claim, rule.claim_type, [event],
                 [pf(event, name) for name in names if event.has(name)], event.ts,
                 "high" if lane in {"urgent", "high"} else "info" if lane == "context" else "medium",
                 lane, "medium", event.entities(), group_key=group)


class LinuxDirect(Playbook):
    os_families = ("linux",)
    assures_negative = False
    positive_only_reason = "Only recorded typed positive observations are reported; unaudited activity is unresolved."
    argv_prefix_safe = True


@dataclass
class _DirectFold:
    count: int
    first: Match
    last: Match
    published: bool = False


class FoldedLinuxDirect(LinuxDirect):
    """Immediately publish one bounded first/latest observation per typed shape and lane.

    Keys spill without forgetting; candidate revisions replace the two citation bodies. Direct/pivot
    callers receive the complete current count from consume and do not need a finalize pass.
    """
    HOT = HOT_COUNT
    state_slice = "strong"

    def __init__(self):
        super().__init__()
        self.folds = KeyedStore(self, "linux_direct_folds", self.HOT)
        self._seen = RecentIds()
        # Records a caller hands over for context only (an expansion reach's records another evaluation owns): read
        # for lineage, never matched.
        self.observe_only: frozenset[str] = frozenset()

    @staticmethod
    def sweep_group_keys(match: Match) -> list[str]:
        """The group keys the same typed shape has in every lane: an evaluation with less context may put a record
        the sweep judged under another lane's key."""
        try:
            parts = json.loads(match.group_key)
        except (TypeError, ValueError):
            return []
        if not isinstance(parts, list) or not parts:
            return []
        return [json.dumps([*parts[:-1], lane]) for lane in ("urgent", "high", "lead")]

    def consume(self, events):
        pending = {}
        for event in self.applicable(events):
            if event.id in self._seen or event.id in self.observe_only:
                continue
            self._seen.add(event.id)
            for match in self.match(event):
                key = match.group_key
                match.raw_copies = self.raw_of(event)
                state = self.folds.get(key)
                if state is None:
                    self.witness(match)
                    state = _DirectFold(0, match, match)
                    if not self.folds.put(key, state):
                        self.note_limit("direct_folds", "The direct observation fold state was refused at the "
                                        "disk ceiling; the positive is published, but its group count is unresolved.")
                        match.notes.append("Fold state was refused at the disk ceiling; the group count is unresolved.")
                        pending[key] = match
                        continue
                state.count += 1
                if (event.ts, event.id) < (state.first.ts, state.first.events[0].id):
                    self.witness(match)
                    state.first = match
                if (event.ts, event.id) > (state.last.ts, state.last.events[0].id):
                    state.last = match
                self.folds.put(key, state)
                pending[key] = state
        out = []
        for key, state in pending.items():
            if isinstance(state, Match):
                out.append(state)
                continue
            first, last = state.first, state.last
            witnesses = list({event.id: event for match in (first, last) for event in match.events}.values())
            context = set(first.context_ids) | set(last.context_ids)
            subjects = [event for event in witnesses if event.id not in context]
            summary = {"count": state.count, "peak": state.count, "episodes": 1,
                       "first": first.ts.timestamp(), "last": last.ts.timestamp()}
            claim = (f"First observation: {first.claim} {state.count} matching record(s) from "
                     f"{first.ts.isoformat()} to {last.ts.isoformat()}; "
                     f"{len(subjects)} cited, including the first and last.")
            out.append(replace(first, claim=claim, events=witnesses,
                               predicate=[*first.predicate, *([] if first is last else last.predicate)],
                               entities=list(dict.fromkeys([*first.entities, *last.entities])),
                               context_ids=context,
                               notes=list(first.notes), raw_copies={**first.raw_copies, **last.raw_copies},
                               revision_reason="Updated the group's count and first/latest witnesses."
                               if state.published else "", bounded_revision=True, aggregate_summary=summary))
            state.published = True
            self.folds.put(key, state)
        self.folds.trim()
        return out

    def match_each(self, events, judged_ids) -> list[Match]:
        """Each judged record's own matches, unfolded, after every record was read for context (lineage): for a
        caller that must place each record in the group another evaluation published for it."""
        self.observe_only = frozenset(event.id for event in events)
        self.consume(events)                    # context only: nothing is matched
        self.observe_only = frozenset()
        out = []
        for event in self.applicable([event for event in events if event.id in judged_ids]):
            for match in self.match(event):
                match.raw_copies = self.raw_of(event)
                out.append(match)
        return out

    def witness(self, match: Match) -> None:
        """A match about to become its group's first cited observation: a rule may add the records its claim rests on
        (called once per new first witness, never per record)."""

    def release_state(self):
        self.folds.clear()
        scripts = getattr(self, "scripts", None)
        if scripts is not None:
            scripts.clear()


def one_edit(a, b):
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    small, large = (a, b) if len(a) < len(b) else (b, a)
    i = next((i for i, (x, y) in enumerate(zip(small, large)) if x != y), len(small))
    return small[i:] == large[i + 1:]


class MasqueradingBinary(FoldedLinuxDirect):
    version = "2"
    id = "host.masquerading_binary"
    title = "System binary names outside packaged locations or userland kernel-thread names"
    families = ("process_exec",)
    required_fields = ("process.executable",)
    attack = ("T1036.005", "T1036.004")
    research = PACKAGE_SOURCES

    def match(self, e):
        path = normalize_path(str(e.get("process.executable")))
        image = path
        for pattern in OVERLAY_PATHS:
            if found := pattern.match(path):
                image = found["image"]
                break
        if stored := PACKAGE_STORE_PATH.match(image):
            image = "/" + stored["image"]
        name = basename(image)
        argv = e.get("process.argv") or []
        thread = any(KERNEL_THREAD.fullmatch(str(v)) for v in (e.get("process.comm"), argv[0] if argv else ""))
        lane = ""
        if thread and path.startswith("/"):
            lane = "high"
        elif not stored and posixpath.dirname(image) not in BASE_PACKAGE_DIRS | PACKAGE_EXTRA_DIRS.get(name, frozenset()):
            if name in SYSTEM_BINARIES:
                lane = ("lead" if posixpath.dirname(image) in {"/usr/local/bin", "/usr/local/sbin"}
                        or re.fullmatch(r"/opt/[^/]+/bin", posixpath.dirname(image)) else "high")
            elif name not in PACKAGED_NAMES and any(one_edit(name, known) for known in SYSTEM_BINARIES):
                lane = "lead"
        if not lane:
            return []
        match = observed(self, e, f"On {e.host}, kernel-recorded executable {path!r} has "
                         + ("a kernel-thread argv/comm name; kernel threads do not exec files."
                            if thread else f"a system-binary name or one-edit lookalike outside its packaged directories ({name})."),
                         lane, group=json.dumps([e.host, path, lane]),
                         names=("process.executable", "process.argv", "process.comm"))
        if image != path:
            match.notes.append("The package or container storage path was mapped to its inferred package image "
                               "path; package ownership is unverified.")
        return [match]


class KernelModuleLoad(LinuxDirect):
    version = "2"
    id = "host.kernel_module_load"
    title = "A kernel module load or an insmod command outside module package trees"
    families = ("kernel_module", "process_exec")
    attack = ("T1547.006",)

    def consume(self, events):
        self._module_in_batch = any(e.family == "kernel_module" for e in events)
        return super().consume(events)

    def partition_coverage_notes(self):
        return ([] if getattr(self, "_module_in_batch", False) else [
            "No module-load auditing records were present in this partition; unaudited module loading is unresolved."])

    def match(self, e):
        p = program(e)
        executable = normalize_path(str(e.get("process.executable") or ""))
        name, directory = basename(executable), posixpath.dirname(executable)
        # A module name (modprobe ext4) is not a path. Absolute or slash-containing operands
        # give a positive file-path observation; insmod always takes a file operand.
        argv_paths = [normalize_path(a, e.get("process.cwd")) for a in p.args
                      if not a.startswith("-") and (p.name == "insmod" or "/" in a)] if p else []
        argv_paths = [path for path in argv_paths if path]
        path = normalize_path(str(e.get("module.path") or ""))
        outside = next((item for item in [path, *argv_paths] if item and not under(item, MODULE_ROOTS)), "")
        loader = p.name if p else None
        if e.family == "kernel_module" and loader == "kmod" and not p.args:
            # A kernel-requested autoload record carries no argv; its kernel-recorded comm names the kmod applet.
            loader = basename(str(e.get("process.comm") or "")) or loader
        packaged = bool(p and ((loader == "modprobe" and name in {"kmod", "modprobe"}
                               and directory in ROOT_BINARY_DIRS)
                              or (name in {"systemd-modules-load", "systemd-udevd", "udevd"}
                                  and directory in ROOT_BINARY_DIRS | {"/usr/lib/systemd", "/lib/systemd",
                                                                      "/usr/lib/udev", "/lib/udev"})))
        if e.family == "kernel_module":
            if e.get("module.op") != "load":
                return []
            path = outside or path or next(iter(argv_paths), "")
            lane = "high" if web(e) or outside else "context" if packaged else "lead"
            if e.outcome == Outcome.failure and lane == "context":
                lane = "lead"
            text = "a kernel module load record" if e.outcome == Outcome.success else "a kernel module load attempt"
        else:
            if not p or p.name not in {"insmod", "modprobe"}:
                return []
            if p.name == "modprobe" and not outside:
                return []
            path = outside or next(iter(argv_paths), "")
            lane = "high" if web(e) or outside else "lead"
            text = f"a {p.name} command (positive-only argv; load not proved)"
        return [observed(self, e, f"On {e.host}, {text}: {path or 'module file not recorded'}.",
                         lane, names=("module.op", "module.path", "module.name", "process.executable", "process.argv",
                                      "process.user"))]


class CredentialMaterialAccess(FoldedLinuxDirect):
    """Credential material named by a reading command, or a watched kernel open of it.

    A watched read of the local hash files is high, except one narrow, typed route to the lead lane (never an
    exclusion): a root interpreter in a package directory running a packaged script, outside any login session, whose
    recorded lineage shows package maintenance or provisioning (`PROVISIONER_BINARIES`, `PROVISIONER_SCRIPTS`) within
    `PROVISIONER_DEPTH` ancestors, or which the service manager (pid 1) started. The lineage is the hunt's shared exec
    lineage (held on disk when cold, never forgotten). A lineage that cannot be resolved (a missing exec record, an
    exec store that refused a process, an unordered instant) leaves the read high."""
    version = "3"
    id = "host.credential_material_access"
    title = "Credential material named by a file-reading tool or a watched kernel open"
    families = ("process_exec", "file_access", "process_observed")
    context_families = ("process_observed",)       # lineage only
    attack = ("T1552.001", "T1003.008")
    research = CREDENTIAL_SOURCES + PROVISIONER_SOURCES
    benign = ("package maintenance or provisioning reading the hash files via Perl or Python (routed to lead)",
              "packaged root service scripts started by the service manager",
              "backup and compare jobs that copy the hash files within /etc or the backup directory")
    next_checks = ("the reader's process lineage and login session",
                   "writes or network transfers by the same process after the read")

    def __init__(self):
        super().__init__()
        # The hunt's one exec lineage (`share_lineage`): exec and observed records, the hot set in memory, the rest
        # on disk.
        self.lineage = ProcessLineage(self)
        # Exec record id -> the packaged script a packaged root-capable interpreter ran. Only scripts in package
        # locations are kept (one short string per such exec); the hot set in memory, the rest on disk.
        self.scripts = KeyedStore(self, "credential_interpreter_scripts", self.HOT)
        self._scripts_refused = False

    def consume(self, events):
        self._watched_in_batch = any(e.family == "file_access" for e in events)
        # Lineage first, for the whole batch: a read's exec ancestry is read before the read is judged.
        for event in sorted((e for e in events if e.family in {"process_exec", "process_observed"}),
                            key=lambda e: (e.ts, e.id)):
            self.lineage.observe(event, self.raw_of(event), self.raw_target())
            if event.family == "process_exec":
                self._hold_script(event)
        try:
            return super().consume([e for e in events if e.family not in self.context_families])
        finally:
            self.lineage.trim()
            self.scripts.trim()

    def _hold_script(self, event) -> None:
        executable = normalize_path(str(event.get("process.executable") or ""))
        family = maintenance_interpreter(executable)
        if not family:
            return
        script = interpreter_script(family, event.get("process.argv"))
        if not script or not (packaged_script(script) or script in PROVISIONER_SCRIPTS):
            return
        if event.id in self.scripts or self.scripts.put(event.id, script):
            return
        self._scripts_refused = True
        self.note_limit("interpreter_scripts", "the store of packaged interpreter scripts took no new record; a hash "
                                               "read by a later interpreter cannot be routed to the lead lane and "
                                               "stays high")

    def _script_of(self, event_id: str) -> str:
        found = self.scripts.get(event_id)
        return found if found is not None else self.scripts.peek(event_id, "") or ""

    def _view(self, host, pid, ts, serial, boot, *, inclusive):
        """The process holding `pid` then, or None when it cannot be relied on: unknown, inferred only from a later
        record, or resting on an observation that is uncited or may be missing."""
        execs = self.lineage.execs
        view = execs.view(host, pid, ts, serial, boot, inclusive=inclusive,
                          order_domain="audit" if serial is not None else None)
        if view.image is None or not view.prior:
            return None
        if view.used and (execs.observed_incomplete or any(not item.cited for item in view.used)):
            return None
        return view

    def _provisioner(self, named) -> str:
        """The provisioner a lineage step names, or ''. Compiled tools by kernel path; interpreter-hosted tools only
        from an exec record (an observation carries no argv)."""
        executable = normalize_path(str(named.exe or ""))
        name = basename(executable)
        if posixpath.dirname(executable) in PROVISIONER_BINARIES.get(name, ()):
            return name
        if named.kind == EXEC and maintenance_interpreter(executable):
            return PROVISIONER_SCRIPTS.get(self._script_of(named.entry.event_id), "")
        return ""

    def maintenance_route(self, e) -> tuple[str, list[str], list[str]] | None:
        """('package' or 'service', the lineage named from the reader up, its exec record ids) when the hash read
        may go to the lead lane; None otherwise (the read stays high)."""
        executable = normalize_path(str(e.get("process.executable") or ""))
        pid = e.get("process.pid")
        if (not maintenance_interpreter(executable) or str(e.get("process.uid")) != "0"
                or not isinstance(pid, int) or isinstance(pid, bool) or not e.host):
            return None
        # A login session (audit login uid or session id set, or an enriched login name) means an operator ran it.
        if (e.get("process.auid") is not None or e.get("process.session_id") is not None
                or e.get("process.login_user") not in (None, "", "unset")):
            return None
        if self.lineage.execs.incomplete or self._scripts_refused:
            return None             # an exec the store refused could be the one that answers: never lower
        boot, serial = boot_of(e), _audit_serial(e)
        view = self._view(e.host, pid, e.ts.timestamp(), serial, boot, inclusive=True)
        if view is None:
            return None
        named = view.named
        record = named.entry
        if named.kind != EXEC or normalize_path(str(named.exe or "")) != executable:
            return None
        if getattr(record, "auid", None) is not None or getattr(record, "uid", None) not in (None, "0"):
            return None
        script = self._script_of(record.event_id)
        if not script or not packaged_script(script):
            return None
        chain, ids = [f"{basename(executable)} {script}"], [record.event_id]
        first = view.first
        if first.ppid == 1:
            return "service", [*chain, "pid 1"], ids
        pid, ts, serial = first.ppid, first.ts, first.serial
        boot = boot if boot is not None else first.boot
        for _depth in range(PROVISIONER_DEPTH):
            if not isinstance(pid, int) or pid <= 1:
                return None         # the lineage reached the service manager with no provisioner on it
            parent = self._view(e.host, pid, ts, serial, boot, inclusive=False)
            if parent is None:
                return None         # an ancestor is not recorded: unknown, so the read stays high
            step = parent.named
            found = self._provisioner(step)
            chain.append(found or basename(str(step.exe or "")) or f"pid {pid}")
            if step.kind == EXEC:
                ids.append(step.entry.event_id)
            if found:
                return "package", chain, ids
            top = parent.first
            pid, ts, serial = top.ppid, top.ts, top.serial
            boot = boot if boot is not None else top.boot
        return None

    def witness(self, match: Match) -> None:
        """A routed lead cites the exec records of the lineage its note names, as context."""
        route = getattr(match, "route_ids", None)
        if not route:
            return
        found, raw = self.lineage.execs.cited(list(route))
        if not found:
            match.notes.append("The lineage's exec records were not kept for citation; the route is stated from the "
                               "hunt's exec lineage.")
            return
        cited = [found[event_id] for event_id in route if event_id in found]
        match.events = [*match.events, *[event for event in cited if event.id not in {e.id for e in match.events}]]
        match.context_ids = set(match.context_ids) | {event.id for event in cited}
        match.raw_copies = {**match.raw_copies, **raw}

    positive_only_reason = ("Watched file reads are positive-only: watch inventories are unknown and hard links "
                            "can escape path classification; unrecorded access remains unresolved. "
                            "Argv operands cannot prove absence either.")

    def partition_coverage_notes(self):
        return [self.positive_only_reason] + ([] if getattr(self, "_watched_in_batch", False) else [
            "No watched file-read records were present in this partition; unrecorded credential access is unresolved."])

    def assures_negative_for(self, events):
        return False

    def match(self, e):
        if e.family == "process_observed":
            return []                   # lineage only
        if e.family == "file_access":
            paths = [str(e.get("file.path"))] if e.has("file.path") else []
            if not paths:
                self.missing_required += 1
        else:
            p = program(e)
            if not p or p.name not in READERS:
                return []
            paths, unplaced = read_operand_paths(p.name, p.args, e.get("process.cwd"))
            self.missing_required += bool(unplaced)
        out = []
        for path in paths:
            found = classify_credential(path)
            if found is None:
                continue
            p = program(e)
            actor = str(e.get("process.user") or "")
            reader = shadow_reader(path, e)
            if reader == "daemon":
                continue
            if reader == "backup" and e.family == "process_exec" and not routine_backup_command(p, e):
                reader = ""
            if (p and posixpath.dirname(str(e.get("process.executable") or "")) in BASE_PACKAGE_DIRS
                    and any(path.startswith(prefix) and actor in accounts and p.name in daemons
                            for prefix, daemons, accounts in OWNING_DAEMONS)):
                continue
            owner = e.get("file.owner.name")
            inferred_owner = (re.match(r"^/home/([^/]+)/", path) or re.match(r"^/(root)/", path))
            owner = owner or (inferred_owner[1] if inferred_owner else None)
            actor_id, owner_id = e.get("process.uid"), e.get("file.owner.id")
            other = ((actor_id is not None and owner_id is not None and str(actor_id) != str(owner_id))
                     or owner is not None and bool(actor) and actor != owner)
            shadow = found[0] == "T1003.008"
            private = "private key" in found[2] or "keytab" in found[2]
            lane = "high" if shadow or private and other else "lead"
            if e.outcome == Outcome.failure or reader == "backup":
                lane = "lead"
            # The only other route to the lead lane: a watched hash read whose sole raise is the hash file itself.
            route = (self.maintenance_route(e) if lane == "high" and shadow and not private
                     and e.family == "file_access" else None)
            if route is not None:
                lane = "lead"
            text = ("a watched kernel open names" if e.family == "file_access"
                    else "a file-reading command names (positive-only argv operand)")
            claim = f"On {e.host}, {text} {found[2]}; recorded outcome {e.outcome.value}."
            if route is not None:
                kind, chain, _ids = route
                claim += (f" The reader is a root {'service script started by the service manager'
                          if kind == 'service' else 'interpreter under package maintenance'} "
                          f"({' ← '.join(chain)}) with no login session.")
            out.append(observed(self, e, claim,
                                lane, group=json.dumps([e.host, normalize_path(str(e.get("process.executable") or "")),
                                                            path, lane]),
                                names=("file.path", "file.owner.id", "file.owner.name", "audit.key",
                                             "process.executable", "process.argv", "process.uid", "process.user")))
            if reader == "backup":
                out[-1].notes.append("A packaged root backup/compare tool read the hash file; paired writes outside /etc "
                                     "are not known, so this remains a lead rather than an exclusion.")
            if route is not None:
                kind, chain, ids = route
                what = ("Root service script started by the service manager" if kind == "service"
                        else "Root interpreter under package maintenance")
                out[-1].notes.append(f"{what} ({' ← '.join(chain)}) read the hash file with no login session; kept as "
                                     "a lead, not excluded.")
                out[-1].route_ids = ids
        return out


# Exact common-name tokens, not substring matching in a serialized record.
DEFAULT_C2_CERTIFICATES = (
    ("Cobalt Strike", "major cobalt strike",
     "https://censys.com/blog/a-beginners-guide-to-tracking-malware-infrastructure"),
)


class DefaultC2Certificate(Playbook):
    id = "net.c2_default_certificate"
    title = "TLS server certificate names a documented framework default"
    families = ("tls_session", "net_session", "x509_certificate")
    required_fields = ("tls.server.certificates",)
    attack = ("T1587.003", "T1071.001")
    lane, severity = "high", "high"
    assures_negative = False
    positive_only_reason = "A framework default name is positive evidence; custom certificates and encrypted handshakes remain unknown."

    def match(self, e):
        out = []
        for certificate in e.get("tls.server.certificates") or []:
            if not isinstance(certificate, dict):
                continue
            names = {str(v).strip().casefold() for side in ("subject", "issuer")
                     for v in certificate.get(f"{side}_cn") or []}
            for framework, common_name, source in DEFAULT_C2_CERTIFICATES:
                if common_name in names:
                    match = observed(self, e, f"A TLS server certificate recorded by {e.host} has the exact "
                                     f"subject or issuer common name of a documented {framework} default. "
                                     "This identifies the certificate shape; authorized tests can use it too.",
                                     "high", names=("tls.server.certificates",))
                    match.notes.append(source)
                    out.append(match)
                    break
        return out


DIRECT_RULES = [MasqueradingBinary, KernelModuleLoad, CredentialMaterialAccess, DefaultC2Certificate]
