"""Recorded Windows file and resolver signals; content is never treated as execution."""
from __future__ import annotations

import json
import ntpath
import re

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_common import SPAWNED_CODE_RUNNERS
from romulus.detect.windows_ecar import class_discriminator
from romulus.detect.windows_events import (
    WindowsEventRule,
    basename,
    components,
    local_path_components,
    signal,
    writable,
)
from romulus.detect.windows_path_data import extension_class, path_class
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

EXECUTABLE_SUFFIXES = frozenset({
    ".exe", ".dll", ".com", ".scr", ".sys", ".msi", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".lnk",
    ".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp", ".jspx", ".cgi", ".pl", ".py", ".rb",
    ".jar", ".class", ".war", ".sct", ".xsl", ".xslt", ".cpl", ".ocx", ".msp", ".mst",
    ".psd1", ".ps1xml", ".mof", ".sdb", ".reg", ".inf", ".vxd", ".drv", ".appx", ".appxbundle",
    ".msix", ".msixbundle", ".sh", ".bash", ".pyw", ".lua", ".go", ".c", ".cpp", ".h", ".cs",
    ".vb", ".tsx", ".ts", ".jsx", ".mjs", ".cjs", ".wasm", ".wsc", ".pif", ".url", ".scf",
    ".xll", ".wll", ".chm", ".msc", ".application", ".appref-ms", ".settingcontent-ms", ".ws",
    ".iqy", ".slk", ".library-ms", ".searchconnector-ms", ".diagcab", ".gadget", ".vsto", ".xbap", ".ppkg",
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".xla", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
    ".one", ".onepkg", ".iso", ".img", ".vhd", ".vhdx",
})
# Cached script/text resources do not establish a runnable downloaded artifact.
# Native binaries, active document formats, shortcuts and disk images remain code-capable.
_CACHE_TEXT_SUFFIXES = frozenset({
    ".js", ".jse", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vbs", ".vbe", ".ps1", ".psm1", ".psd1",
    ".ws", ".wsf", ".wsh", ".py", ".pyw", ".rb", ".pl", ".lua", ".go", ".c", ".cpp", ".h", ".cs", ".vb",
    ".sh", ".bash", ".bat", ".cmd", ".asp", ".aspx", ".ashx", ".asmx", ".php", ".jsp", ".jspx", ".cgi",
    ".htm", ".html", ".css", ".json", ".xml", ".txt", ".map", ".xsl", ".xslt",
})
LURE_WRITERS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                          "onenote.exe", "mspub.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
                          "brave.exe", "opera.exe"})
_BROWSER_WRITERS = frozenset({"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"})
_SCRIPT_START = re.compile(r"\A\s*(?:#!|<script(?:\s|>)|function\s+[\w-]+\s*\{|"
                           r"(?:iex|invoke-expression|start-process|write-host|write-output)\b)", re.IGNORECASE)
_FILE_FIELDS = ("file.path", "file.path_key", "file.action", "process.executable", "process.executable_key",
                "file.is_executable", "file.hashes")


def executable_path(value):
    return ntpath.splitext(str(value or ""))[1].casefold() in EXECUTABLE_SUFFIXES


def _content(event, fields=_FILE_FIELDS):
    return json.dumps({name: event.get(name) for name in fields}, sort_keys=True, separators=(",", ":"))


def _file_class(event, path=None):
    path = path or event.get("file.path_key") or event.get("file.path")
    writer = event.get("process.executable_key") or event.get("process.executable")
    content = [path_class(writer), path_class(path, directory=True), extension_class(path), event.get("file.action")]
    if _code_record(event, path):
        content += [basename(path), event.get("file.is_executable"), event.get("file.hashes")]
    return content


def _code_record(event, path=None):
    path = path or event.get("file.stream.base_path") or event.get("file.path_key") or event.get("file.path")
    parts = components(path)
    body = str(event.get("file.stream.content") or "")
    if _pe_record(event):
        return True
    writer = event.get("process.executable_key") or event.get("process.executable")
    if (basename(writer) in _BROWSER_WRITERS and _browser_cache(path)
            and extension_class(path) in _CACHE_TEXT_SUFFIXES):
        return False
    return bool(executable_path(path)
                or "startup" in parts or "wwwroot" in parts
                or executable_path(str(event.get("file.stream.name") or "").casefold().removesuffix(":$data"))
                or body.startswith("MZ") or _SCRIPT_START.match(body))


def _pe_record(event):
    """Ordinary content hashes identify bytes, not executable format."""
    hashes = event.get("file.hashes")
    imphash = hashes.get("imphash") if isinstance(hashes, dict) else None
    return (event.get("file.is_executable") is True
            or isinstance(imphash, str) and re.fullmatch(r"[0-9a-fA-F]{32}", imphash) is not None
            and bool(int(imphash, 16))
            or str(event.get("file.stream.content") or "").startswith("MZ"))


def _browser_cache(path):
    local = local_path_components(path)
    parts = components(path)
    if len(local) > 4 and local[0] == 'users' and local[2:4] == ('appdata', 'local'):
        tail = local[4:]
    elif parts[:1] == ('%localappdata%',):
        tail = parts[1:]
    else:
        return False
    if len(tail) > 3 and tail[:3] == ('microsoft', 'windows', 'inetcache'):
        return tail[3] not in {'content.outlook', 'content.mso'}
    cache = {"cache", "cache_data", "code cache", "gpucache", "cache2", "startupcache"}
    profile = tail[:3] in {('google', 'chrome', 'user data'), ('microsoft', 'edge', 'user data'),
                          ('mozilla', 'firefox', 'profiles')}
    return profile and len(tail) > 5 and tail[4] in cache


def _common(event, action, path=None):
    writer, directory, suffix, *_ = _file_class(event, path)
    return f"Windows recorded {action} by writer path class '{writer}' in directory class '{directory}' with extension '{suffix}'"


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


class _FileBehaviorRule(BehaviorFleetRule):
    def fleet_eligible(self, event, hit):
        return not _code_record(event)


class StartupFileWrite(_FileBehaviorRule):
    ecar_compatible = True
    id = "win.startup_file_write"
    version = "7"
    title = "File created in a Windows startup folder"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1547.001",)
    benign = ("an installer or administrator deploying an approved startup program or shortcut",)
    next_checks = ("the recorded writer and the next logon/process execution of the file",)
    research = ("https://attack.mitre.org/techniques/T1547/001/",)

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        if not class_discriminator(event, 11, "file_change") or not startup_path(path):
            return []
        writer = event.get("process.executable")
        text = f"Windows recorded creation of startup artifact '{self.describe(path)}'"
        text += f" by '{self.describe(writer)}'" if writer else "; the writer image is unresolved"
        return [signal(event, "startup_file", text, self.attack, _FILE_FIELDS,
                       content=json.dumps(_file_class(event)), common=_common(event, "startup-artifact creation"))]


class LureApplicationFileWrite(_FileBehaviorRule):
    ecar_compatible = True
    id = "win.lure_application_file_write"
    version = "7"
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
        if not class_discriminator(event, 11, "file_change") or not path or not writable(path):
            return []
        if basename(writer) not in LURE_WRITERS:
            return []
        parts = components(path)
        if basename(path).endswith(".lnk") and ("microsoft", "office", "recent") in {
                parts[index:index + 3] for index in range(max(0, len(parts) - 2))}:
            return []
        return [signal(event, "lure_write", f"Recorded writer '{self.describe(writer)}' created "
                       f"'{self.describe(path)}' in a user-writable location; execution is not established",
                       self.attack, _FILE_FIELDS, content=json.dumps(_file_class(event)),
                       common=_common(event, "file creation") + "; execution is not established")]


class ExecutableAlternateStream(_FileBehaviorRule):
    id = "win.executable_alternate_stream"
    version = "7"
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
        # Zone metadata varies by download URL and base filename. Those are citations,
        # not new behavior classes; executable-content qualifiers still stay distinct.
        writer = event.get("process.executable_key") or event.get("process.executable")
        shape = ([path_class(writer)] if name.casefold() == "zone.identifier" and not _code_record(event)
                 else _file_class(event, event.get("file.stream.base_path")))
        shape += [name.casefold(), what]
        path = event.get('file.stream.base_path') or event.get('file.path') or event.get('file.path_key')
        description = (f"Alternate stream '{self.describe(name)}' of '{self.describe(path)}'" if name
                       else f"Stream creation recorded on '{self.describe(path)}'; stream name not recorded")
        description += f" was recorded with {what}" if name else f"; recorded content has {what}"
        return [signal(event, "executable_ads", f"{description}; "
                       "this does not establish execution or a complete executable",
                       self.attack, (*_FILE_FIELDS, "file.stream.name", "file.stream.content", "file.stream.base_path"),
                       content=json.dumps(shape),
                       common=f"Alternate streams of the same stream and file behavior class were recorded with {what}; this does not establish execution")]


class ExecutableCreationTimeChange(_FileBehaviorRule):
    id = "win.executable_creation_time_change"
    version = "7"
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
        direction = "unresolved timestamps" if before is None or after is None else "recorded old/new timestamps"
        return [signal(event, "creation_time", f"Windows recorded a creation-time change for "
                       f"'{self.describe(path)}'; {qualifier}", self.attack,
                       (*_FILE_FIELDS, "file.previous_creation_time", "file.creation_time"),
                       content=json.dumps([*_file_class(event), direction]),
                       common=_common(event, "creation-time changes") + f"; {direction}")]


class WritableExecutableDeletion(_FileBehaviorRule):
    ecar_compatible = True
    id = "win.writable_executable_deletion"
    version = "7"
    title = "File deleted from a user-writable or startup location"
    families = ("file_change",)
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (23, 26))
    attack = ("T1070.004",)
    benign = ("browser cache cleanup, an installer or an administrator removing an unneeded artifact",)
    next_checks = ("the recorded deleting process, prior creation and execution of that exact file",)
    research = ("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",)

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        if (not (class_discriminator(event, 23, "file_change") or class_discriminator(event, 26, "file_change")) or not path
                or not (writable(path) or startup_path(path))):
            return []
        return [signal(event, "artifact_deleted", f"Windows recorded deletion of '{self.describe(path)}'; "
                       "the purpose of the deletion is unresolved", self.attack, _FILE_FIELDS,
                       content=json.dumps(_file_class(event)),
                       common=_common(event, "file deletion") + "; the purpose of the deletion is unresolved")]


class WebRootFileWrite(_FileBehaviorRule):
    ecar_compatible = True
    id = "win.web_root_file_write"
    version = "5"
    title = "File created in the default IIS web content directory"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1505.003",)
    benign = ("IIS setup, application deployment and ordinary static content updates",)
    next_checks = ("verify the actual IIS physical content path and deployment owner",
                   "inspect the created file and requests or execution that reference it")
    research = ("https://learn.microsoft.com/troubleshoot/developer/webapps/iis/www-administration-management/default-permissions-user-rights",
                "https://attack.mitre.org/techniques/T1505/003/",
                "https://learn.microsoft.com/sysinternals/downloads/sysmon")

    def judge(self, event):
        path = event.get("file.path_key") or event.get("file.path")
        parts = local_path_components(path)
        if (not class_discriminator(event, 11, "file_change") or len(parts) < 3
                or parts[:2] != ("inetpub", "wwwroot")):
            return []
        return [signal(event, "web_content_created", f"Windows recorded creation of '{self.describe(path)}' "
                       "under the default IIS web content path; serving or execution is not established",
                       self.attack, _FILE_FIELDS, content=json.dumps(_file_class(event)),
                       common=_common(event, "file creation under the default IIS web content path")
                       + "; serving or execution is not established",
                       notes=(("This path scope does not establish that IIS is active or that the file is a web shell. "
                               "Custom IIS physical paths require separate configuration evidence."),))]


class CodeRunnerDnsLookup(WindowsEventRule):
    id = "win.code_runner_dns_lookup"
    version = "5"
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
                          ExecutableCreationTimeChange, WritableExecutableDeletion, WebRootFileWrite,
                          CodeRunnerDnsLookup)
