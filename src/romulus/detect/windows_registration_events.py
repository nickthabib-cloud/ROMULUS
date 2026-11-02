"""Positive Windows service/task configuration and logging-state observations."""
from __future__ import annotations

import json
import ntpath
import re
from xml.etree import ElementTree

from romulus.detect.bounded import KeyedStore
from romulus.detect.windows_cmdline import (
    cmd_payload,
    parse_cmd_payload,
    parse_powershell,
    split_argv,
    switch_value,
)
from romulus.detect.windows_events import WindowsEventRule, basename, integer, writable
from romulus.detect.windows_events import signal as _signal
from romulus.evidence.windows_catalog import (
    EVENTLOG,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    TASK_CHANNEL,
    TASK_PROVIDER,
)

_HOSTS = frozenset({"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
                    "wscript", "wscript.exe", "cscript", "cscript.exe", "mshta", "mshta.exe"})
_PS_HOSTS = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_LOLBINS = frozenset({"rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe", "certutil", "certutil.exe",
                      "msiexec", "msiexec.exe", "installutil", "installutil.exe", "regasm", "regasm.exe",
                      "regsvcs", "regsvcs.exe", "msbuild", "msbuild.exe", "forfiles", "forfiles.exe"})
_REMOTE_NAMES = frozenset({"psexesvc", "remcomsvc", "paexec"})
_SERVICE_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4697"
_TASK_DOC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4698"
_SYSMON_DOC = "https://learn.microsoft.com/sysinternals/downloads/sysmon"


def signal(event, behavior, text, attack, fields, **kwargs):
    kwargs.setdefault("content", json.dumps({name: event.get(name) for name in fields}, sort_keys=True))
    return _signal(event, behavior, text, attack, fields, **kwargs)


def _expand(path):
    # These symbolic roots have Windows-defined meanings; no local environment is read.
    text = str(path)
    text = re.sub(r"(?i)^%(?:systemroot|windir)%", r"C:\\Windows", text)
    text = re.sub(r"(?i)^\\systemroot(?=\\)", r"C:\\Windows", text)
    text = re.sub(r"(?i)^%comspec%", r"C:\\Windows\\System32\\cmd.exe", text)
    return text


def _unusual(path):
    text = ntpath.normpath(_expand(path).replace("/", "\\")).casefold()
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
    if re.match(r"%(?:programfiles(?:\(x86\))?|programw6432)%\\[^\\]+", text):
        return False
    if text.startswith("\\\\"):
        return True
    if not re.match(r"[a-z]:\\", text):
        return text.startswith("%")
    parts = text[3:].split("\\")
    return not (parts[0] in {"program files", "program files (x86)"}
                or len(parts) > 2 and parts[0] == "windows" and parts[1] not in {"temp", "tasks", "tracing"})


def _command(line: object) -> tuple[str | None, list[str], str]:
    """Keep uncertain executable boundaries as leads instead of guessing an unquoted path."""
    if not isinstance(line, str) or not line.strip():
        return None, [], "the recorded command is missing"
    text = _expand(line.strip())
    if text.startswith('"'):
        close = text.find('"', 1)
        if close < 2 or (len(text) > close + 1 and not text[close + 1].isspace()):
            return None, [], "the quoted executable boundary is ambiguous"
    else:
        first = text.split(maxsplit=1)[0]
        if len(first) != len(text) and not (
                re.search(r"\.(?:exe|com|bat|cmd)$", first, re.IGNORECASE) or basename(first) in _HOSTS):
            return None, [], "the unquoted executable boundary is ambiguous"
    argv = split_argv(_expand(text))
    return (argv[0], argv[1:], "") if argv else (None, [], "the command did not parse")


def _risks(executable: str, args: list[str], *, depth=0) -> list[str]:
    executable = _expand(executable)
    name = basename(executable)
    risks = []
    if name in _PS_HOSTS:
        call = parse_powershell(args)
        risks.append("PowerShell encoded-command argument" if call.source == "encodedcommand"
                     else "PowerShell host")
    elif name in _HOSTS:
        risks.append("shell or script host")
    elif name in _LOLBINS:
        risks.append("dual-use Windows execution or transfer utility")
    if writable(executable) or _unusual(executable) or ("\\" not in executable and name not in _HOSTS | _LOLBINS):
        risks.append("executable outside standard Windows or Program Files installation locations")
    for arg in args:
        operand = switch_value(arg) if arg.startswith(("-", "/")) else None
        operand = operand if operand is not None else arg
        if re.match(r"(?i)^(?:https?|ftp)://", operand):
            risks.append("URL in configured arguments")
        # Exact argument path prefixes, including rundll32's path,EntryPoint operand.
        if writable(operand.split(",", 1)[0]) or _unusual(operand.split(",", 1)[0]):
            risks.append("path outside standard installation locations in configured arguments")
    if name in {"cmd", "cmd.exe"} and depth < 4:
        payload = cmd_payload('cmd.exe ' + " ".join(args))
        if payload is None:
            # Some recorded launchers carry a nonstandard prefix switch (for
            # example /b). Retain the positive /c payload shape without claiming
            # that cmd accepted that switch or executed the inner command.
            for index, arg in enumerate(args):
                if arg.casefold() in {"/c", "/k", "/r"} and all(item.startswith("/") for item in args[:index]):
                    payload = cmd_payload("cmd.exe " + " ".join(args[index:]))
                    break
        if payload:
            for command in parse_cmd_payload(payload):
                words = command.argv
                if words and words[0].casefold() == "start":
                    words = words[1:]
                    while words and (not words[0] or words[0].startswith("/")):
                        words = words[1:]
                if words:
                    risks.extend(_risks(words[0], words[1:], depth=depth + 1))
    return list(dict.fromkeys(risks))


class ServiceRegistration(WindowsEventRule):
    id = "win.service_registration"
    version = "2"
    title = "Service registration contains a risky executable configuration"
    families = ("service_change",)
    windows_event_classes = (("Security", SECURITY, 4697), ("System", "Service Control Manager", 7045))
    attack = ("T1543.003",)
    benign = ("approved deployment tools and services can use script hosts or temporary staging paths",
              "authorized remote administration uses the same default service names")
    next_checks = ("inspect the registered binary and its signature", "find a subsequent service process record")
    research = (_SERVICE_DOC, "https://learn.microsoft.com/sysinternals/downloads/psexec",
                "https://github.com/kavika13/RemCom", "https://www.poweradmin.com/paexec/")

    def judge(self, event):
        if integer(event.get("event.code")) not in {4697, 7045}:
            return []
        fields = ("service.name", "service.image_path", "service.start_type", "service.account", "service.type")
        image = event.get("service.image_path")
        executable, args, reason = _command(image)
        risks = _risks(executable, args) if executable else []
        remote = str(event.get("service.name") or "").casefold() in _REMOTE_NAMES
        if not risks and not remote and not reason:
            return []
        text = (f"Service installation record registered name {self.describe(event.get('service.name'))} "
                f"with ImagePath {self.describe(image)}")
        if risks:
            text += ": " + "; ".join(risks)
        elif remote:
            text += "; the service name matches a documented remote-administration default"
        if reason:
            text += f"; {reason}"
        service_type = integer(event.get("service.type"))
        type_name = str(event.get("service.type") or "").strip().casefold()
        user_mode = bool(service_type is not None and service_type & 0x30) or type_name in {
            "user mode service", "win32 own process", "win32 share process", "own process", "share process",
        }
        second_signal = bool(executable and basename(executable) in _HOSTS | _LOLBINS)
        high = bool(risks and (user_mode or second_signal))
        return [signal(event, "service_configuration", text, self.attack, fields,
                       lane="high" if high else "lead", severity="high" if high else "medium",
                       notes=(("Registration does not establish that the configured payload executed. Service names "
                               "are controllable, and path indicators do not establish effective filesystem ACLs."),))]


def _local(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _task_structure(event) -> bool:
    """Validate the Exec locations before trusting the normalizer's broad XML walk for a strong lane."""
    xml = event.get("task.xml")
    actions = event.get("task.actions")
    if not isinstance(xml, str) or not isinstance(actions, list):
        return False
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        return False
    try:
        if len(xml.encode("utf-8")) > 1_048_576:
            return False
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, UnicodeError, ValueError):
        return False
    containers = [child for child in root if _local(child.tag) == "Actions"]
    if _local(root.tag) != "Task" or len(containers) != 1:
        return False
    direct = []
    for action in containers[0]:
        if _local(action.tag) != "Exec":
            continue
        value = {"kind": "exec"}
        for child in action:
            key = {"Command": "command", "Arguments": "arguments", "WorkingDirectory": "working_directory"}.get(
                _local(child.tag))
            if key:
                if key in value:
                    return False
                if child.text and child.text.strip():
                    value[key] = child.text.strip()
        direct.append(value)
    return direct == [action for action in actions if isinstance(action, dict) and action.get("kind") == "exec"]


class ScheduledTaskRegistration(WindowsEventRule):
    id = "win.scheduled_task_registration"
    version = "2"
    title = "Scheduled task record contains a risky action configuration"
    families = ("scheduled_task",)
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4698, 4702)) + tuple(
        (TASK_CHANNEL, TASK_PROVIDER, code) for code in (106, 140, 200))
    attack = ("T1053.005",)
    benign = ("administration, updaters and inventory tasks often run hidden, as SYSTEM, or through a script host",)
    next_checks = ("validate the complete task definition and all actions", "inspect the configured files and task results")
    research = (_TASK_DOC, "https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-schema")

    def judge(self, event):
        code = integer(event.get("event.code"))
        if code not in {4698, 4702, 106, 140, 200}:
            return []
        fields = ("task.name", "task.action", "task.actions", "task.action_name", "task.hidden", "task.principal.user_id",
                  "task.principal.run_level", "task.xml_parse", "task.xml_parse_reason", "task.result_code")
        labels = []
        uncertain = False
        risky = False
        if code == 200:
            action = event.get("task.action_name")
            # ActionName is a path, so an embedded space is never an argv boundary.
            risks = _risks(action, []) if isinstance(action, str) and action.strip() else []
            if not risks and action:
                return []
            text = (f"Task action-started record named {self.describe(action)} for task "
                    f"{self.describe(event.get('task.name'))}")
            labels.extend(risks)
            if not action:
                labels.append("no action content in this record")
                uncertain = True
        else:
            actions = event.get("task.actions")
            structural = _task_structure(event)
            if isinstance(actions, list):
                if not actions:
                    uncertain = True
                for action in actions:
                    if not isinstance(action, dict):
                        uncertain = True
                        continue
                    if action.get("kind") == "com_handler":
                        labels.append("COM handler action with class " + self.describe(action.get("class_id")))
                        continue
                    if action.get("kind") != "exec":
                        continue
                    command = action.get("command")
                    if not isinstance(command, str) or not command:
                        uncertain = True
                        continue
                    # XML Command is an executable field, not a command line: spaces inside it are literal.
                    args = split_argv("host.exe " + str(action.get("arguments") or ""))[1:]
                    risks = _risks(command, args)
                    if risks:
                        risky |= (basename(_expand(command)) in _HOSTS or writable(command) or
                                  basename(_expand(command)) in _LOLBINS and any(label in risks for label in (
                                      "URL in configured arguments", "path outside standard installation locations in configured arguments",
                                  )))
                        labels.append(f"parsed Exec Command {self.describe(command)}: " + "; ".join(risks))
            else:
                uncertain = True
                labels.append("no action content in this record")
            if labels and not structural:
                uncertain = True
            if event.get("task.hidden") is True:
                labels.append("Hidden=true in parsed configuration")
            principal = str(event.get("task.principal.user_id") or "").casefold()
            if principal in {"s-1-5-18", "system", "nt authority\\system"}:
                labels.append("SYSTEM principal in parsed configuration")
            if not labels and not uncertain:
                return []
            action = "updated" if code in {4702, 140} else "registered"
            text = f"Task {action} record for {self.describe(event.get('task.name'))}"
            if labels and not structural:
                labels.append("XML action structure was not independently established")
        if labels:
            text += ": " + "; ".join(labels)
        if uncertain:
            text += "; configuration interpretation remains uncertain"
        high = risky and not uncertain
        return [signal(event, "task_configuration", text, self.attack, fields,
                       lane="high" if high else "lead", severity="high" if high else "medium",
                       notes=(("Parsed configuration and an action-started name do not establish that the configured "
                               "payload executed successfully. Hidden and SYSTEM alone are administration leads."),))]


class WindowsAuditTamper(WindowsEventRule):
    id = "win.audit_state_change"
    version = "2"
    title = "Windows logging state, configuration, or log contents changed"
    families = ("audit_config",)
    windows_event_classes = tuple(("Security", EVENTLOG, code) for code in (1100, 1102, 1104, 1108)) + (
        ("System", "Microsoft-Windows-Eventlog", 104), ("Security", SECURITY, 4719),
    ) + tuple((SYSMON_CHANNEL, SYSMON, code) for code in (4, 16, 255))
    attack = ("T1685.001", "T1685.005", "T1685.007")
    benign = ("approved log maintenance, policy changes and Sysmon upgrades", "normal system shutdown and logging errors")
    next_checks = ("identify the change initiator and approved maintenance", "check collection continuity and actual policy")
    research = (_SYSMON_DOC, "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4719",
                "https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102")

    def __init__(self):
        super().__init__()
        self.shutdowns = KeyedStore(self, "audit_shutdown", self.HOT)

    def _owned_stores(self):
        return [*super()._owned_stores(), *([self.shutdowns] if hasattr(self, "shutdowns") else [])]

    def consume(self, events):
        events = list(events)
        for event in events:
            if event.family == "audit_config" and self.event_in_os_scope(event) and event.get("event.code") == 1100:
                key = event.get("host.full_name") or event.host
                previous = self.shutdowns.get(key)
                if (previous is None or previous[0].ts < event.ts) and not self.shutdowns.put(key, (event, self.raw_of(event))):
                    self.note_limit("shutdown_context", "Shutdown context state was full; stopping records retain unresolved context.")
        return super().consume(events)

    def judge(self, event):
        code = integer(event.get("event.code"))
        fields = ("audit.config.action", "audit.config.subcategory_guid", "audit.config.changes", "audit.config.state",
                  "audit.config.configuration", "audit.config.error", "user.entity_id")
        high = True
        attack = self.attack
        if code in {1102, 104}:
            text = "Windows recorded an event log cleared"
            attack = ("T1685.005",)
        elif code == 4719:
            changes = str(event.get("audit.config.changes") or "").strip().casefold()
            tokens = re.findall(r"(?<![\w%])%%\d+(?!\w)", changes)
            high = bool(set(tokens) & {"%%8448", "%%8450"}) or changes in {
                "success removed", "failure removed", "success removed, failure removed", "failure removed, success removed",
            }
            text = ("Windows recorded removal of an audit policy setting" if high else
                    "Windows recorded an audit policy change; the event alone does not establish disabled auditing")
            attack = ("T1685.001",)
        elif code == 1100:
            high = False
            text = "Windows recorded the event logging service shutting down"
            attack = ("T1685.001",)
        elif code == 16:
            high = False
            text = "Sysmon recorded a configuration change; its effect on collection is not established"
        elif code == 4:
            state = str(event.get("audit.config.state") or "").casefold()
            if state == "started":
                return []
            high = False
            text = ("Sysmon recorded its service stopped; shutdown context is unresolved from this record" if state == "stopped" else
                    "Sysmon recorded a service state change whose stopping effect is not established")
        elif code in {1104, 1108, 255}:
            high = False
            text = {1104: "Windows recorded the security log full", 1108: "Windows recorded an event processing error",
                    255: "Sysmon recorded an error"}[code]
        else:
            return []
        context = None
        context_raw = {}
        if code == 4 and str(event.get("audit.config.state") or "").casefold() == "stopped":
            retained = self.shutdowns.get(event.get("host.full_name") or event.host)
            if retained is not None:
                context, context_raw = retained
                text = ("Sysmon recorded its service stopped; the host's records also contain an event logging "
                        f"service shutdown at {context.ts.isoformat()}; this does not establish the cause of the stop")
        details = "; ".join(f"{name}={self.describe(event.get(name))}" for name in fields if event.has(name))
        if details:
            text += ": " + details
        hit = signal(event, f"audit_{code}", text, attack, fields,
                     lane="high" if high else "lead", severity="high" if high else "medium")
        if code == 4 and str(event.get("audit.config.state") or "").casefold() == "stopped":
            # Fleet predicates cite the stopping records. Per-host shutdown
            # context belongs to the individual finding and its own citations.
            hit.common = "Sysmon recorded its service stopped"
        if context is not None:
            hit.context.append(context)
            hit.raw_copies.update(context_raw)
        return [hit]


WINDOWS_REGISTRATION_PLAYBOOKS = (ServiceRegistration, ScheduledTaskRegistration, WindowsAuditTamper)
