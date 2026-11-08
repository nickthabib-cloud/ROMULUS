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
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS
from romulus.detect.linux_argv import getopt_long, normalize_path, program, read_operand_paths, write_targets
from romulus.detect.linux_semantics import classify_credential
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

    def consume(self, events):
        pending = {}
        for event in self.applicable(events):
            if event.id in self._seen:
                continue
            self._seen.add(event.id)
            for match in self.match(event):
                key = match.group_key
                match.raw_copies = self.raw_of(event)
                state = self.folds.get(key)
                if state is None:
                    state = _DirectFold(0, match, match)
                    if not self.folds.put(key, state):
                        self.note_limit("direct_folds", "The direct observation fold state was refused at the "
                                        "disk ceiling; the positive is published, but its group count is unresolved.")
                        match.notes.append("Fold state was refused at the disk ceiling; the group count is unresolved.")
                        pending[key] = match
                        continue
                state.count += 1
                if (event.ts, event.id) < (state.first.ts, state.first.events[0].id):
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
            summary = {"count": state.count, "peak": state.count, "episodes": 1,
                       "first": first.ts.timestamp(), "last": last.ts.timestamp()}
            claim = (f"First observation: {first.claim} {state.count} matching record(s) from "
                     f"{first.ts.isoformat()} to {last.ts.isoformat()}; "
                     f"{len(witnesses)} cited, including the first and last.")
            out.append(replace(first, claim=claim, events=witnesses,
                               predicate=[*first.predicate, *([] if first is last else last.predicate)],
                               entities=list(dict.fromkeys([*first.entities, *last.entities])),
                               notes=list(first.notes), raw_copies={**first.raw_copies, **last.raw_copies},
                               revision_reason="Updated the group's count and first/latest witnesses."
                               if state.published else "", bounded_revision=True, aggregate_summary=summary))
            state.published = True
            self.folds.put(key, state)
        self.folds.trim()
        return out

    def release_state(self):
        self.folds.clear()


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
    version = "2"
    id = "host.credential_material_access"
    title = "Credential material named by a file-reading tool or a watched kernel open"
    families = ("process_exec", "file_access")
    attack = ("T1552.001", "T1003.008")
    research = CREDENTIAL_SOURCES

    def consume(self, events):
        self._watched_in_batch = any(e.family == "file_access" for e in events)
        return super().consume(events)

    positive_only_reason = ("Watched file reads are positive-only: watch inventories are unknown and hard links "
                            "can escape path classification; unrecorded access remains unresolved. "
                            "Argv operands cannot prove absence either.")

    def partition_coverage_notes(self):
        return [self.positive_only_reason] + ([] if getattr(self, "_watched_in_batch", False) else [
            "No watched file-read records were present in this partition; unrecorded credential access is unresolved."])

    def assures_negative_for(self, events):
        return False

    def match(self, e):
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
            text = ("a watched kernel open names" if e.family == "file_access"
                    else "a file-reading command names (positive-only argv operand)")
            out.append(observed(self, e, f"On {e.host}, {text} {found[2]}; recorded outcome {e.outcome.value}.",
                                lane, group=json.dumps([e.host, normalize_path(str(e.get("process.executable") or "")),
                                                            path, lane]),
                                names=("file.path", "file.owner.id", "file.owner.name", "audit.key",
                                             "process.executable", "process.argv", "process.uid", "process.user")))
            if reader == "backup":
                out[-1].notes.append("A packaged root backup/compare tool read the hash file; paired writes outside /etc "
                                     "are not known, so this remains a lead rather than an exclusion.")
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
