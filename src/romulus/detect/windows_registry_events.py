"""Sensitive registry writes, with exact key/value grammar and positive-only claims.

Sysmon includes the value name in TargetObject; Security 4657 supplies it separately.
No writer or payload-name allowlist can hide an otherwise relevant recorded change.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_events import WindowsEventRule, components, integer, signal
from romulus.detect.windows_path_data import BUILTIN_COM_CLASSES, path_class
from romulus.evidence.typed import TypedEvent

_LM = "hkey_local_machine"
_CU = "hkey_current_user"
_USERS = "hkey_users"
_SID = re.compile(r"s-\d+(?:-\d+)+", re.ASCII)
_GUID = re.compile(r"\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}", re.ASCII)
_CONTROL = re.compile(r"(?:currentcontrolset|controlset\d{3})", re.ASCII)
_SYSMON_DWORD = re.compile(r"dword \(0x[0-9a-f]{1,8}\)", re.ASCII)
_DWORD_TYPES = {"reg_dword", "reg_dword_little_endian", "dword", "%%1876"}
_DEFAULT_ROOT = re.compile(
    r"(?:[a-z]:\\windows|\\\\\?\\[a-z]:\\windows|\\\?\?\\[a-z]:\\windows"
    r"|\\device\\harddiskvolume\d+\\windows"
    r"|(?:\\\\\?\\|\\\?\?\\)volume\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}\\windows"
    r"|\\systemroot|%systemroot%|%windir%|%systemdrive%\\windows)", re.ASCII,
)
_NT = ("microsoft", "windows nt", "currentversion")
_FIELDS = ("registry.path_key", "registry.value_name", "registry.value", "registry.value_type",
           "registry.action", "registry.event_type", "registry.operation_type", "registry.new_path",
           "registry.details_truncated")


def default_value_name(value):
    """Canonicalize only the documented default-value markers, including old Sysmon."""
    name = str(value or "").casefold()
    return "" if name in {"(default)", "{default}"} else name


@dataclass(frozen=True)
class _Target:
    root: str
    key: tuple[str, ...]
    name: str | None
    action: str


def _target(event: TypedEvent, path=None) -> _Target | None:
    path = event.get("registry.path_key") if path is None else path
    parts = components(path)
    aliases = {"hklm": _LM, "hkcu": _CU, "hku": _USERS}
    if parts:
        parts = (aliases.get(parts[0], parts[0]), *parts[1:])
    if not parts or parts[0] not in {_LM, _CU, _USERS}:
        return None
    action = str(event.get("registry.action", "")).casefold()
    event_type = str(event.get("registry.event_type", "")).casefold()
    operation = str(event.get("registry.operation_type", "")).casefold()
    if event_type in {"deletekey", "deletevalue"} or operation == "registry_value_deleted":
        action = "deleted"
    elif event_type in {"renamekey", "renamevalue"} or action == "object_renamed":
        action = "renamed"
    elif event.get("event.code") in {13, 4657} or action in {"value_set", "value_modified"}:
        action = "written"
    else:
        action = "changed"
    # An explicit name is a separate field, including the empty default-value name.
    if event.has("registry.value_name"):
        name = str(event.get("registry.value_name") or "").casefold()
    elif (event.get("event.code") == 13
          or (event.get("event.code") == 14 and event_type != "renamekey")
          or event_type in {"deletevalue", "renamevalue", "setvalue"}):
        # Defender exclusion value names can themselves be full paths, containing backslashes.
        exclusion = next((index for index in range(1, len(parts) - 2)
                          if parts[index:index + 2] == ("microsoft", "windows defender")
                          and parts[index + 2] == "exclusions"
                          and len(parts) > index + 4
                          and parts[index + 3] in {"paths", "processes", "extensions", "ipaddresses"}), None)
        if exclusion is not None:
            parts, name = parts[:exclusion + 4], "\\".join(parts[exclusion + 4:])
        elif str(path).endswith("\\"):
            name = ""
        else:
            parts, name = parts[:-1], parts[-1]
    else:
        name = None
    if not parts:
        return None
    root, key = parts[0], parts[1:]
    if root == _USERS:
        if not key:
            return None
        if key[0].endswith("_classes") and _SID.fullmatch(key[0][:-8]):
            root, key = _CU, ("software", "classes", *key[1:])
        elif _SID.fullmatch(key[0]) or key[0] == ".default":
            root, key = _CU, key[1:]
        else:
            return None
    return _Target(root, key, default_value_name(name) if name is not None else None, action)


def _software(target: _Target) -> tuple[str, ...] | None:
    key = target.key
    if not key or key[0] != "software":
        return None
    return key[2:] if len(key) > 1 and key[1] == "wow6432node" else key[1:]


def _system(target: _Target) -> tuple[str, ...] | None:
    key = target.key
    if target.root != _LM or len(key) < 2 or key[0] != "system" or not _CONTROL.fullmatch(key[1]):
        return None
    return key[2:]


def _uncertain(event: TypedEvent) -> bool:
    value = event.get("registry.value")
    return (value is None or not isinstance(value, (str, int, list, tuple)) or isinstance(value, bool)
            or event.get("registry.details_truncated") is True)


def _recorded_dword(event: TypedEvent) -> bool:
    """Require recorded type evidence before assigning numeric setting semantics.

    NewValueType is preserved verbatim by the Windows normalizer. DWORD aliases and
    %%1876 are documented at https://learn.microsoft.com/azure/sentinel/normalization-schema-registry-event
    and https://learn.microsoft.com/windows/win32/sysinfo/registry-value-types.
    """
    if "registry.value_type" in event.fields:
        value_type = event.get("registry.value_type")
        if isinstance(value_type, int) and not isinstance(value_type, bool):
            return value_type == 4  # Windows REG_DWORD / REG_DWORD_LITTLE_ENDIAN type constant.
        return isinstance(value_type, str) and value_type.strip().casefold() in _DWORD_TYPES
    value = event.get("registry.value")
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    return (event.get("event.code") == 13 and isinstance(value, str)
            and _SYSMON_DWORD.fullmatch(value.strip().casefold()) is not None)


def _default_winlogon(value: object, name: str) -> bool:
    """One exact default image, with optional quoting and Userinit's trailing comma.

    Recognise the system-directory grammar on any volume without expanding variables,
    resolving UNC shares or treating arbitrary paths with familiar basenames as safe.
    """
    if not isinstance(value, str):
        return False
    text = value.strip().replace("/", "\\").casefold()
    if name == "userinit" and text.endswith(","):
        text = text[:-1].strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    image = "explorer.exe" if name == "shell" else "userinit.exe"
    if text == image:
        return True
    suffix = "\\" + (image if name == "shell" else "system32\\" + image)
    return text.endswith(suffix) and _DEFAULT_ROOT.fullmatch(text[:-len(suffix)]) is not None


class _RegistryRule(WindowsEventRule):
    families = ("registry_change",)
    required_fields = ("registry.path_key",)
    positive_only_reason = "Registry data is recorded content; a write does not prove execution or effective policy."

    def judge(self, event):
        targets = [_target(event)]
        if event.get("event.code") == 14 and event.get("registry.new_path"):
            targets.append(_target(event, event.get("registry.new_path")))
        out = []
        for target in dict.fromkeys(targets):
            if target is not None:
                out.extend(self._judge_target(event, target))
        return out

    def report(self, event, target, behavior, description, *, high=False, numeric=None, mask=None,
               known_numeric=(0, 1), multi=False, content=None, common=""):
        """A deletion/rename is always an observation, never a payload installation."""
        action = target.action
        value = event.get("registry.value")
        if content is None:
            content = json.dumps([target.root, target.key, target.name, action, value,
                                  event.get("registry.value_type"), event.get("registry.details_truncated")],
                                 sort_keys=True, separators=(",", ":"))
        notes = ("A registry change does not establish that the referenced code executed or the policy took effect.",)
        if action != "written":
            text = f"{description} registry target was {action}; resulting value and effective state are unknown"
            return [signal(event, behavior + ":" + action, text, self.attack, _FIELDS, notes=notes, content=content,
                           common=common)]
        if (_uncertain(event) or (isinstance(value, (list, tuple))
                                 and (not multi or any(not isinstance(item, str) for item in value)))):
            text = f"{description} registry value was written; data is missing, malformed or truncated, so its effect is unknown"
            observed_high = (high and behavior.startswith("winlogon_") and event.get("registry.details_truncated") is True
                             and isinstance(value, str) and bool(value.strip())
                             and not _default_winlogon(value.removesuffix("...").strip(), target.name or ""))
            return [signal(event, behavior + ":unknown", text, self.attack, _FIELDS, notes=notes, content=content,
                           lane="high" if observed_high else "lead", severity="high" if observed_high else "medium",
                           common=common)]
        if numeric is not None:
            if not _recorded_dword(event):
                text = f"{description} registry value was written without a supported DWORD type; its effect is unknown"
                return [signal(event, behavior + ":unknown", text, self.attack, _FIELDS, notes=notes, content=content)]
            number = integer(value)
            if number is None or number < 0 or number > 0xffffffff:
                text = f"{description} registry value was written with ambiguous DWORD data; its effect is unknown"
                return [signal(event, behavior + ":unknown", text, self.attack, _FIELDS, notes=notes, content=content)]
            if not (number & mask if mask is not None else number in numeric):
                if mask is None and number not in known_numeric:
                    text = f"{description} registry value was written with unrecognised DWORD data; its effect is unknown"
                    return [signal(event, behavior + ":unknown", text, self.attack, _FIELDS, notes=notes, content=content)]
                return []
        elif (isinstance(value, str) and not value.strip()) or value in ([], ()):
            text = f"{description} registry value was cleared; no executable payload is established by this write"
            return [signal(event, behavior + ":cleared", text, self.attack, _FIELDS, notes=notes, content=content,
                           common=common)]
        elif not isinstance(value, (str, list, tuple)):
            text = f"{description} registry value was written with malformed text data; its effect is unknown"
            return [signal(event, behavior + ":unknown", text, self.attack, _FIELDS, notes=notes, content=content,
                           common=common)]
        text = f"{description} registry value was written as '{self.describe(value)}'"
        return [signal(event, behavior, text, self.attack, _FIELDS,
                       lane="high" if high else "lead", severity="high" if high else "medium", notes=notes, content=content,
                       common=common)]


class RegistryRunKeys(_RegistryRule):
    id = "win.registry_run_keys"
    version = "3"
    title = "Run, RunOnce or RunOnceEx registry entry changed"
    attack = ("T1547.001",)
    benign = ("application installers and per-user startup preferences",)
    next_checks = ("inspect the referenced payload and its signer", "follow the writer and subsequent logon executions")
    research = ("https://attack.mitre.org/techniques/T1547/001/",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/standard-user-cannot-run-commnad-via-runonce")

    def _judge_target(self, event, target):
        key = _software(target) if target else None
        prefix = ("microsoft", "windows", "currentversion")
        if key == (*prefix, "policies", "explorer", "run"):
            return self.report(event, target, "explorer_run", "Explorer policy logon Run entry")
        if key == (*_NT, "windows") and target.name in {"load", "run"}:
            return self.report(event, target, "windows_load", "Windows logon load/run entry")
        if key == (*prefix, "explorer", "user shell folders") and target.name == "startup":
            return self.report(event, target, "startup_folder", "Per-user Startup folder location")
        if key and key[:-1] == prefix and key[-1] in {"run", "runonce"}:
            return self.report(event, target, "run_key", "Logon Run/RunOnce entry")
        # Section names need not be numbered; Depend belongs immediately beneath a section.
        if (key and key[:4] == (*prefix, "runonceex")
                and (len(key) in {4, 5} or (len(key) == 6 and key[-1] == "depend"))):
            return self.report(event, target, "runonceex", "Logon RunOnceEx configuration entry")
        return []


class RegistryWinlogon(_RegistryRule):
    id = "win.registry_winlogon"
    version = "3"
    title = "Winlogon shell, user initialization or notification registration changed"
    attack = ("T1547.004",)
    benign = ("approved custom shells and legacy logon software",)
    next_checks = ("check the exact shell and userinit list against the expected configuration",
                   "inspect notification DLLs and logon executions")
    research = ("https://attack.mitre.org/techniques/T1547/004/",)

    def _judge_target(self, event, target):
        key = _software(target) if target else None
        prefix = (*_NT, "winlogon")
        if key == prefix and target.name in {"shell", "userinit"}:
            # Whole recorded grammar only: a trusted executable followed by an extra command is not safe.
            if (target.action == "written" and not _uncertain(event)
                    and _default_winlogon(event.get("registry.value"), target.name)):
                return []
            return self.report(event, target, "winlogon_" + target.name, "Winlogon " + target.name,
                               high=True)
        if key and key[:len(prefix) + 1] == (*prefix, "notify") and len(key) in {len(prefix) + 1, len(prefix) + 2}:
            return self.report(event, target, "winlogon_notify", "Winlogon notification registration", high=True)
        return []


class RegistryImageExecution(_RegistryRule):
    id = "win.registry_image_execution"
    version = "3"
    title = "IFEO debugger or silent-exit monitoring registration changed"
    attack = ("T1546.012",)
    benign = ("debugging and application crash diagnostics",)
    next_checks = ("check the target executable and monitor/debugger payload", "inspect the GlobalFlag and ReportingMode pairing")
    research = ("https://attack.mitre.org/techniques/T1546/012/",
                "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit")

    def _judge_target(self, event, target):
        key = _software(target) if target and target.root == _LM else None
        if not key or key[:3] != _NT or len(key) not in {5, 6}:
            return []
        family = key[3]
        if (target.action == "renamed" and target.name is None
                and family in {"image file execution options", "silentprocessexit"}):
            return self.report(event, target, "image_execution_key", "Image execution monitoring configuration key")
        if family == "image file execution options" and target.name == "debugger":
            return self.report(event, target, "ifeo_debugger", "IFEO Debugger registration", high=True)
        if family == "image file execution options" and len(key) == 5 and target.name == "globalflag":
            return self.report(event, target, "ifeo_silent_exit", "IFEO silent-exit monitoring flag", numeric=(512,), mask=512)
        if family == "silentprocessexit" and len(key) == 5:
            if target.name == "monitorprocess":
                return self.report(event, target, "silent_exit_monitor", "SilentProcessExit MonitorProcess registration", high=True)
            if target.name == "reportingmode":
                return self.report(event, target, "silent_exit_mode", "SilentProcessExit launch-monitor flag", numeric=(1,), mask=1)
        return []


class RegistryAppInit(_RegistryRule):
    id = "win.registry_appinit"
    version = "3"
    title = "AppInit DLL registration or loading flag changed"
    attack = ("T1546.010",)
    benign = ("legacy application compatibility or security software",)
    next_checks = ("inspect DLL signatures and image-load events", "check Secure Boot and the effective AppInit policy")
    research = ("https://attack.mitre.org/techniques/T1546/010/",)

    def _judge_target(self, event, target):
        key = _software(target) if target and target.root == _LM else None
        if key == (*_NT, "windows"):
            if target.name == "appinit_dlls":
                return self.report(event, target, "appinit_dlls", "AppInit DLL registration", high=True)
            if target.name == "loadappinit_dlls":
                return self.report(event, target, "appinit_enable", "AppInit DLL loading enablement", numeric=(1,))
        return []


class RegistryAppCert(_RegistryRule):
    id = "win.registry_appcert"
    version = "3"
    title = "AppCert DLL registration changed"
    attack = ("T1546.009",)
    benign = ("legacy certified application hooks",)
    next_checks = ("inspect the registered DLL and subsequent image loads", "identify the writer and configuration owner")
    research = ("https://attack.mitre.org/techniques/T1546/009/",)

    def _judge_target(self, event, target):
        if target and _system(target) == ("control", "session manager", "appcertdlls"):
            return self.report(event, target, "appcert_dll", "AppCert DLL registration", high=True)
        return []


class RegistryUserCom(_RegistryRule, BehaviorFleetRule):
    id = "win.registry_user_com"
    version = "4"
    title = "Per-user COM server registration changed"
    attack = ("T1546.015",)
    benign = ("per-user COM application installation and repair",)
    next_checks = ("compare the per-user CLSID with its machine registration", "inspect the server payload and invoking process")
    research = ("https://attack.mitre.org/techniques/T1546/015/",
                "https://learn.microsoft.com/windows/win32/winprog64/shared-registry-keys",
                "https://devblogs.microsoft.com/oldnewthing/20121205-00/?p=5913",
                "https://learn.microsoft.com/windows/win32/com/treatas",
                "https://learn.microsoft.com/windows/win32/com/-progid--key",
                *(item[1] for item in BUILTIN_COM_CLASSES.values()))

    def _judge_target(self, event, target):
        key = _software(target) if target and target.root == _CU else None
        if key and key[:2] == ("classes", "wow6432node"):
            key = ("classes", *key[2:])
        if (key and len(key) == 4 and key[:2] == ("classes", "clsid")
                and _GUID.fullmatch(key[2]) and key[3] in {"inprocserver32", "localserver32", "treatas", "progid"}
                and target.name in {None, "", "(default)"}):
            value = event.get("registry.value")
            builtin = BUILTIN_COM_CLASSES.get(key[2])
            high = builtin is not None and isinstance(value, str) and bool(value.strip())
            payload = value.strip().casefold() if isinstance(value, str) and _GUID.fullmatch(value.strip().casefold()) else path_class(value)
            content = json.dumps([key, target.name, target.action, payload,
                                  event.get("registry.value_type"), event.get("registry.details_truncated")])
            common = (f"Per-user COM {key[3]} registration in the same class and payload path class was {target.action}"
                      + (f" for documented Windows built-in {builtin[0]}" if builtin else ""))
            return self.report(event, target, "user_com_server", "Per-user COM server registration", high=high,
                               content=content, common=common)
        # A ProgID's CLSID mapping is a redirection observation. Its target CLSID does
        # not establish that the source ProgID is a built-in registration being shadowed.
        if (key and len(key) == 3 and key[0] == "classes" and key[1] != "clsid" and key[2] == "clsid"
                and target.name in {None, "", "(default)"}):
            return self.report(event, target, "user_com_progid", "Per-user COM ProgID redirection",
                               common=f"Per-user COM ProgID redirection was {target.action}")
        return []


class RegistryLsaPackages(_RegistryRule):
    id = "win.registry_lsa_packages"
    version = "3"
    title = "LSA authentication, security or notification packages changed"
    attack = ("T1547.002", "T1547.005", "T1112")
    benign = ("approved authentication providers, password filters and security products",)
    next_checks = ("compare the complete package list with the expected baseline", "inspect package DLL signatures and LSASS loads")
    research = ("https://attack.mitre.org/techniques/T1547/002/", "https://attack.mitre.org/techniques/T1547/005/")

    def _judge_target(self, event, target):
        key = _system(target) if target else None
        if (key in {("control", "lsa"), ("control", "lsa", "osconfig")}
                and target.name in {"authentication packages", "security packages", "notification packages"}):
            return self.report(event, target, "lsa_packages", "LSA " + target.name + " list", high=True, multi=True)
        return []


class RegistryCredentialProtection(_RegistryRule):
    id = "win.registry_credential_protection"
    version = "3"
    title = "WDigest credential retention or LSA protection registry setting changed"
    attack = ("T1112", "T1685")
    benign = ("legacy authentication troubleshooting and authorized compatibility work",)
    next_checks = ("verify effective credential protection after reboot", "look for LSASS access and credential theft")
    research = ("https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
                "https://support.microsoft.com/help/2871997")

    def _judge_target(self, event, target):
        key = _system(target) if target else None
        if key == ("control", "securityproviders", "wdigest") and target.name == "uselogoncredential":
            return self.report(event, target, "wdigest_credentials", "WDigest plaintext credential retention request",
                               numeric=(1,), high=True)
        if key == ("control", "lsa") and target.name == "runasppl":
            return self.report(event, target, "lsa_protection_off", "LSA protected-process disablement request",
                               numeric=(0,), high=True, known_numeric=(0, 1, 2))
        return []


class RegistryDefender(_RegistryRule):
    id = "win.registry_defender"
    version = "4"
    title = "Defender policy or exclusion registry setting changed"
    attack = ("T1685", "T1112")
    benign = ("managed antivirus policy and approved performance exclusions",)
    next_checks = ("check Defender 5007 and tamper-protection outcomes", "verify effective policy and the exclusion's owner")
    research = ("https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview",
                "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure")

    def _judge_target(self, event, target):
        key = _software(target) if target and target.root == _LM else None
        if not key:
            return []
        policy = key[:1] == ("policies",)
        if policy:
            key = key[1:]
        prefix = ("microsoft", "windows defender")
        if key[:2] != prefix:
            return []
        tail = key[2:]
        # Non-policy signature inventory is update bookkeeping. Policy values under
        # the same label configure update behavior and remain reportable settings:
        # https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus
        if not policy and tail[:1] == ("signature updates",):
            return []
        if len(tail) == 2 and tail[0] == "exclusions" and tail[1] in {"paths", "processes", "extensions", "ipaddresses"}:
            if policy and target.action == "written" and event.get("registry.value") == "":
                return []
            return self.report(event, target, "defender_exclusion", "Defender exclusion registration", numeric=(0,),
                               known_numeric=(), high=True)
        disabling = {(): {"disableantispyware", "disableantivirus"},
                     ("real-time protection",): {"disablerealtimemonitoring", "disablebehaviormonitoring",
                                                 "disableonaccessprotection", "disablescanonrealtimeenable",
                                                 "disableioavprotection", "disablescriptscanning"},
                     ("spynet",): {"disableblockatfirstseen"}}
        if target.name in disabling.get(tail, set()):
            if not policy and _recorded_dword(event) and integer(event.get("registry.value")) != 1:
                return self.report(event, target, "defender_setting",
                                   "Defender configuration (effective protection impact unknown)")
            return self.report(event, target, "defender_disable", "Defender protection disablement request", numeric=(1,), high=True)
        # Every other setting is a positive observation, without inferring its effect.
        return self.report(event, target, "defender_policy" if policy else "defender_setting",
                           "Defender configuration (effective protection impact unknown)")


class RegistryRdp(_RegistryRule):
    id = "win.registry_rdp"
    version = "3"
    title = "Remote Desktop registry enablement setting changed"
    attack = ("T1021.001", "T1112")
    benign = ("authorized remote administration enablement",)
    next_checks = ("check firewall and effective RDP exposure", "look for subsequent type-10 logons and their source")
    research = ("https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-cannot-connect-remote-computer",)

    def _judge_target(self, event, target):
        if target and _system(target) == ("control", "terminal server") and target.name == "fdenytsconnections":
            return self.report(event, target, "rdp_enable", "Remote Desktop connection enablement request", numeric=(0,))
        return []


class RegistryServiceCommand(_RegistryRule):
    id = "win.registry_service_command"
    version = "3"
    title = "Service image or failure command registry setting changed"
    attack = ("T1543.003",)
    benign = ("service installation, upgrades and recovery configuration",)
    next_checks = ("inspect the service executable and failure command", "compare service installation and execution events")
    research = ("https://attack.mitre.org/techniques/T1543/003/",)

    def _judge_target(self, event, target):
        key = _system(target) if target else None
        if key and len(key) == 3 and key[0] == "services" and key[2] == "parameters" and target.name == "servicedll":
            return self.report(event, target, "service_dll", "Service implementation DLL registration")
        if key and len(key) == 2 and key[0] == "services" and target.name in {"imagepath", "failurecommand"}:
            return self.report(event, target, "service_" + target.name,
                               "Service " + self.describe(key[1]) + " " + target.name)
        return []


WINDOWS_REGISTRY_PLAYBOOKS = (
    RegistryRunKeys, RegistryWinlogon, RegistryImageExecution, RegistryAppInit, RegistryAppCert,
    RegistryUserCom, RegistryLsaPackages, RegistryCredentialProtection, RegistryDefender, RegistryRdp,
    RegistryServiceCommand,
)
