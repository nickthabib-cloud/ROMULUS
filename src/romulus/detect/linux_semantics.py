"""Shared Linux discovery, credential classes and privilege predicates."""
from __future__ import annotations

import re

from romulus.detect.base import basename
from romulus.detect.linux_argv import (
    is_suid_perm,
    is_under,
    normalize_path,
    read_operand_paths,
    read_operands,
    split_flags,
)
from romulus.evidence.typed import TypedEvent

SENSITIVE_DIRS = ("/etc", "/root", "/home", "/var/www", "/opt", "/srv", "/boot", "/var/log", "/var/lib")
ELEVATION_HELPERS = {"sudo", "su", "pkexec", "doas", "run0"}
# Session/service entry points can legitimately start root processes for non-root login identities.
SANCTIONED_BROKERS = ELEVATION_HELPERS | {"sshd", "sshd-session", "cron", "crond", "systemd", "login", "polkit", "polkitd"}

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
    "lsusb": ("T1120", "peripheral-device discovery"), "lspci": ("T1120", "peripheral-device discovery"),
    "lsscsi": ("T1120", "peripheral-device discovery"), "hwinfo": ("T1120", "peripheral-device discovery"),
    "usb-devices": ("T1120", "peripheral-device discovery"), "lsdev": ("T1120", "peripheral-device discovery"),
    "lspcmcia": ("T1120", "peripheral-device discovery"), "lsinput": ("T1120", "peripheral-device discovery"),
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


# Programs classified as discovery because a token is absent (no change verb, no command, no -perm): with an
# incomplete argv the absence cannot be decided.
_DISCOVERY_BY_ABSENCE = {"env", "hostname", "ifconfig", "route", "arp", "ip", "find"}


def _operands_unplaced(prog, event: TypedEvent) -> bool:
    """True when a file a reader or `ls` was given is a relative operand with no usable working directory, so
    the record cannot be fully evaluated (it is counted as missing a required field, never as a no-match)."""
    cwd = event.get("process.cwd")
    if prog.name in {"ls", "dir"}:
        return any(not normalize_path(operand, cwd) for operand in split_flags(prog.args)[1] if operand)
    return read_operand_paths(prog.name, prog.args, cwd)[1]


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
    if re.fullmatch(r"/proc/\d+/environ", path):
        return ("T1552.001", "lead", f"process environment via {path}")
    if name == ".vault-token" or path.startswith("/etc/vault.d/"):
        return ("T1552.001", "lead", f"Vault credentials or configuration ({path})")
    if (path.startswith("/var/lib/jenkins/") and name in {"credentials.xml", "master.key", "hudson.util.Secret"}
            or low.endswith(("/.gitlab-runner/config.toml", "/.config/gh/hosts.yml", "/.npmrc", "/.pypirc"))):
        return ("T1552.001", "lead", f"CI or package-registry credential material ({path})")
    return None
