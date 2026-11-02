"""Recorded Windows file and resolver signals; content is never treated as execution."""
from __future__ import annotations

import json
import ntpath
import re

from romulus.detect.windows_common import SPAWNED_CODE_RUNNERS
from romulus.detect.windows_events import (
    WindowsEventRule,
    basename,
    components,
    local_path_components,
    signal,
    writable,
)
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

EXECUTABLE_SUFFIXES = frozenset({
    ".exe", ".dll", ".com", ".scr", ".sys", ".msi", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".lnk",
})
LURE_WRITERS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                          "onenote.exe", "mspub.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
                          "brave.exe", "opera.exe"})
_SCRIPT_START = re.compile(r"\A\s*(?:#!|<script(?:\s|>)|function\s+[\w-]+\s*\{|"
                           r"(?:iex|invoke-expression|start-process|write-host|write-output)\b)", re.IGNORECASE)
_FILE_FIELDS = ("file.path", "file.path_key", "file.action", "process.executable", "process.executable_key")


def executable_path(value):
    return ntpath.splitext(str(value or ""))[1].casefold() in EXECUTABLE_SUFFIXES


def _content(event, fields=_FILE_FIELDS):
    return json.dumps({name: event.get(name) for name in fields}, sort_keys=True, separators=(",", ":"))


def startup_path(value):
    parts = components(ntpath.normpath(str(value or "")))
    marker = ("microsoft", "windows", "start menu", "programs", "startup")
    if parts and parts[0] in {"%appdata%", "%programdata%"}:
        tail = parts[1:]
    elif parts[:3] == ("%userprofile%", "appdata", "roaming"):
        tail = parts[3:]
    else:
        local = local_path_components(value)
        if local[:1] == ("programdata",):
            tail = local[1:]
        elif len(local) >= 5 and local[0] == "users" and local[2:4] == ("appdata", "roaming"):
            tail = local[4:]
        else:
            return False
    return len(tail) == len(marker) + 1 and tail[:len(marker)] == marker


class StartupFileWrite(WindowsEventRule):
    id = "win.startup_file_write"
    version = "2"
    title = "File created in a Windows startup folder"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1547.001",)
    benign = ("an installer or administrator deploying an approved startup program or shortcut",)
    next_checks = ("the recorded writer and the next logon/process execution of the file",)
    research = ("https://attack.mitre.org/techniques/T1547/001/",)

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        if event.get("event.code") != 11 or not startup_path(path):
            return []
        writer = event.get("process.executable")
        text = f"Windows recorded creation of startup artifact '{self.describe(path)}'"
        text += f" by '{self.describe(writer)}'" if writer else "; the writer image is unresolved"
        return [signal(event, "startup_file", text, self.attack, _FILE_FIELDS, content=_content(event))]


class LureApplicationFileWrite(WindowsEventRule):
    id = "win.lure_application_file_write"
    version = "2"
    title = "Office or browser process wrote a file in a user-writable directory"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1204.002", "T1105")
    benign = ("a browser download or document application exporting an approved script or installer",)
    next_checks = ("process_activity for the writer and subsequent execution of the artifact",)
    research = ("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",)

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        writer = event.get("process.executable_key") or event.get("process.executable")
        if event.get("event.code") != 11 or not path or not writable(path):
            return []
        if basename(writer) not in LURE_WRITERS:
            return []
        parts = components(path)
        if basename(path).endswith(".lnk") and ("microsoft", "office", "recent") in {
                parts[index:index + 3] for index in range(max(0, len(parts) - 2))}:
            return []
        return [signal(event, "lure_write", f"Recorded writer '{self.describe(writer)}' created "
                       f"'{self.describe(path)}' in a user-writable location; execution is not established",
                       self.attack, _FILE_FIELDS, content=_content(event))]


class ExecutableAlternateStream(WindowsEventRule):
    id = "win.executable_alternate_stream"
    version = "2"
    title = "An alternate file stream was recorded"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 15),)
    attack = ("T1564.004",)
    benign = ("application resource storage or an authorized test that intentionally uses an alternate stream",)
    next_checks = ("the raw stream body and any process that read or executed the stream",)
    research = ("https://attack.mitre.org/techniques/T1564/004/",)

    def judge(self, event):
        if event.get("event.code") != 15:
            return []
        name = str(event.get("file.stream.name") or "")
        content = str(event.get("file.stream.content") or "")
        pe = content.startswith("MZ")
        script = bool(_SCRIPT_START.match(content))
        named = executable_path(name.removesuffix(":$DATA").removesuffix(":$data"))
        if not event.get("file.path") and not event.get("file.path_key") and not event.get("file.stream.base_path"):
            return []
        what = ("an MZ prefix" if pe else "script-like starting syntax" if script else
                "an executable/script suffix" if named else "no recorded executable-content qualifier")
        return [signal(event, "executable_ads", f"Alternate stream '{self.describe(name)}' of "
                       f"'{self.describe(event.get('file.stream.base_path'))}' was recorded with {what}; "
                       "this does not establish execution or a complete executable",
                       self.attack, (*_FILE_FIELDS, "file.stream.name", "file.stream.content", "file.stream.base_path"),
                       content=_content(event, (*_FILE_FIELDS, "file.stream.name", "file.stream.content", "file.stream.base_path")))]


class ExecutableCreationTimeChange(WindowsEventRule):
    id = "win.executable_creation_time_change"
    version = "2"
    title = "Creation time changed on a Windows file"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 2),)
    attack = ("T1070.006",)
    benign = ("an installer, restore tool or build system preserving original file times",)
    next_checks = ("the writer and original/current creation timestamps in the raw event",)
    research = ("https://attack.mitre.org/techniques/T1070/006/",)

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        if event.get("event.code") != 2 or not path:
            return []
        before, after = event.get("file.previous_creation_time"), event.get("file.creation_time")
        if before is not None and before == after:
            return []
        qualifier = "the old/new timestamps are unresolved" if before is None or after is None else (
            f"from '{self.describe(before)}' to '{self.describe(after)}'")
        return [signal(event, "creation_time", f"Windows recorded a creation-time change for "
                       f"'{self.describe(path)}'; {qualifier}", self.attack,
                       (*_FILE_FIELDS, "file.previous_creation_time", "file.creation_time"),
                       content=_content(event, (*_FILE_FIELDS, "file.previous_creation_time", "file.creation_time")))]


class WritableExecutableDeletion(WindowsEventRule):
    id = "win.writable_executable_deletion"
    version = "2"
    title = "File deleted from a user-writable or startup location"
    families = ("file_change",)
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (23, 26))
    attack = ("T1070.004",)
    benign = ("browser cache cleanup, an installer or an administrator removing an unneeded artifact",)
    next_checks = ("the recorded deleting process, prior creation and execution of that exact file",)
    research = ("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",)

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        if (event.get("event.code") not in {23, 26} or not path
                or not (writable(path) or startup_path(path))):
            return []
        return [signal(event, "artifact_deleted", f"Windows recorded deletion of '{self.describe(path)}'; "
                       "the purpose of the deletion is unresolved", self.attack, _FILE_FIELDS, content=_content(event))]


class CodeRunnerDnsLookup(WindowsEventRule):
    id = "win.code_runner_dns_lookup"
    version = "2"
    title = "Script host or proxy-execution binary requested DNS resolution"
    families = ("dns_lookup",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 22),)
    attack = ("T1059", "T1218")
    benign = ("an approved script or administrative proxy binary resolving a service name",)
    next_checks = ("process_activity and the process session; query result does not establish a connection",)
    research = ("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",)

    def judge(self, event):
        image = event.get("process.executable_key") or event.get("process.executable")
        question = event.get("dns.question.name")
        if basename(image) not in SPAWNED_CODE_RUNNERS or not question:
            return []
        return [signal(event, "code_runner_dns", f"Recorded image '{self.describe(image)}' requested DNS "
                       f"resolution of '{self.describe(question)}'; the image identity is the signal, not the domain",
                       self.attack, ("process.executable", "process.executable_key", "dns.question.name", "dns.status"),
                       content=_content(event, ("process.executable", "process.executable_key", "dns.question.name", "dns.status")))]


WINDOWS_FILE_PLAYBOOKS = (StartupFileWrite, LureApplicationFileWrite, ExecutableAlternateStream,
                          ExecutableCreationTimeChange, WritableExecutableDeletion, CodeRunnerDnsLookup)
