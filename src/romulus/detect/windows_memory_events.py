"""Positive observations of process access, tampering and memory-related image loads.

An access right permits an operation; it does not prove a read or a dump occurred. Module
loads and thread creation likewise retain their recorded meaning without asserting injection.
"""
from __future__ import annotations

import re

from romulus.detect.windows_events import WindowsEventRule, basename, components, integer, signal, writable
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

_SYSMON = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
_LSASS = "https://attack.mitre.org/techniques/T1003/001/"
_RIGHTS = "https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
_DUMP_DLLS = frozenset({"dbghelp.dll", "dbgcore.dll", "comsvcs.dll"})
# These names explain potential benign use, but cannot establish trusted software identity.
_DIAGNOSTIC = frozenset({
    "werfault.exe", "werfaultsecure.exe", "taskmgr.exe", "procexp.exe", "procexp64.exe",
    "windbg.exe", "cdb.exe", "vsdebugconsole.exe", "msmpeng.exe", "mssense.exe",
    "senseir.exe", "csfalconservice.exe", "sentinelagent.exe", "avp.exe", "savservice.exe",
})
_DOTNET_HOSTS = frozenset({
    "dotnet.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe", "msbuild.exe",
    "csc.exe", "vbc.exe", "regasm.exe", "regsvcs.exe", "installutil.exe", "devenv.exe",
})
_ROLE_FIELDS = tuple(f"{role}.{suffix}" for role in ("source", "target")
                     for suffix in ("executable", "executable_key", "pid", "guid"))
_PROCESS_FIELDS = ("process.executable", "process.executable_key", "process.pid", "process.guid")
_IMAGE_FIELDS = (*_PROCESS_FIELDS, "image.kind", "image.path", "image.path_key", "image.signed",
                 "image.signature_status", "image.signature", "image.hash.sha256", "image.hash.sha1")


def _image(event):
    return event.get("image.path_key") or event.get("image.path")


def _process(event, role="process"):
    return event.get(f"{role}.executable_key") or event.get(f"{role}.executable")


def _bad_signature(event):
    status = str(event.get("image.signature_status") or "").strip().casefold()
    return event.get("image.signed") is False or status in {
        "invalid", "untrusted", "revoked", "expired", "unsigned", "not signed", "not trusted",
        "invalid chain", "invalid signature",
    }


def _signature_known_good(event):
    return (event.get("image.signed") is True
            and str(event.get("image.signature_status") or "").casefold() == "valid")


def _system_directory(path):
    parts = components(path)
    if len(parts) == 3 and parts[0] in {"%systemroot%", "%windir%", "systemroot"}:
        return parts[1] in {"system32", "syswow64"}
    if len(parts) < 4 or parts[-3:-1] not in {("windows", "system32"), ("windows", "syswow64")}:
        return False
    root = parts[:-3]
    if root and root[0] in {"?", "??"}:
        root = root[1:]
    return ((len(root) == 1 and bool(re.fullmatch(r"[a-z]:", root[0])))
            or (len(root) == 2 and root[0] == "device" and bool(re.fullmatch(r"harddiskvolume\d+", root[1]))))


def _installation_parts(path):
    """Components below a recorded local volume or Windows-root placeholder."""
    parts = components(path)
    if parts and parts[0] in {"?", "??"}:
        parts = parts[1:]
    if parts and re.fullmatch(r"[a-z]:", parts[0]):
        parts = parts[1:]
    elif len(parts) >= 2 and parts[0] == "device" and re.fullmatch(r"harddiskvolume\d+", parts[1]):
        parts = parts[2:]
    elif parts and parts[0] in {"%systemroot%", "%windir%", "systemroot"}:
        parts = ("windows", *parts[1:])
    else:
        return ()
    return parts


def _expected_clr_path(path):
    parts = _installation_parts(path)
    return (len(parts) == 5 and parts[:2] == ("windows", "microsoft.net")
            and parts[2] in {"framework", "framework64"} and bool(re.fullmatch(r"v\d+(?:\.\d+)+", parts[3]))
            and parts[4] == "clr.dll")


def _expected_dotnet_host(path):
    """Recognize a narrow installation-path scope, never software trust from a name."""
    name = basename(path)
    if name not in _DOTNET_HOSTS or writable(path):
        return False
    parts = _installation_parts(path)
    if name in {"powershell.exe", "powershell_ise.exe"}:
        return (len(parts) == 5 and parts[0] == "windows" and parts[1] in {"system32", "syswow64"}
                and parts[2:4] == ("windowspowershell", "v1.0"))
    if (name in {"msbuild.exe", "csc.exe", "vbc.exe", "regasm.exe", "regsvcs.exe", "installutil.exe"}
            and len(parts) == 5 and parts[:2] == ("windows", "microsoft.net")
            and parts[2] in {"framework", "framework64"} and re.fullmatch(r"v\d+(?:\.\d+)+", parts[3])):
        return True
    if not parts or parts[0] not in {"program files", "program files (x86)"}:
        return False
    if name == "dotnet.exe":
        return len(parts) == 3 and parts[1] == "dotnet"
    if name == "pwsh.exe":
        return (len(parts) == 4 and parts[1] == "powershell"
                and bool(re.fullmatch(r"\d+(?:\.\d+)*(?:-preview)?", parts[2])))
    if len(parts) >= 7 and parts[1] == "microsoft visual studio" and re.fullmatch(r"\d{4}", parts[2]):
        if name == "devenv.exe":
            return parts[4:] == ("common7", "ide", "devenv.exe")
        if name == "msbuild.exe":
            return parts[4:] in {("msbuild", "current", "bin", "msbuild.exe"),
                                 ("msbuild", "current", "bin", "amd64", "msbuild.exe")}
    return False


class LsassProcessAccess(WindowsEventRule):
    id = "win.lsass_process_access"
    version = "1"
    title = "A process opened LSASS with memory-related access or a notable call trace"
    families = ("process_access",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 10),)
    attack = ("T1003.001",)
    benign = ("security inspection, crash diagnostics and Task Manager can open LSASS",)
    next_checks = ("verify the source executable and signer independently", "inspect access trace and dump-file writes")
    research = (_SYSMON, _LSASS, _RIGHTS)

    def judge(self, event):
        if event.get("event.code") != 10 or basename(_process(event, "target")) != "lsass.exe":
            return []
        mask = integer(event.get("process.access.mask"))
        modules = event.get("process.access.call_trace_modules") or []
        names = {basename(module) for module in modules} if isinstance(modules, list) else set()
        trace = str(event.get("process.access.call_trace") or "").casefold()
        unknown = any(re.fullmatch(r"unknown(?:\([0-9a-fx]+\))?", name) for name in names)
        unknown |= any(re.fullmatch(r"unknown(?:\([0-9a-fx]+\))?(?:\+[0-9a-fx]+)?", frame.strip())
                       for frame in trace.split("|"))
        notable_trace = bool(names & _DUMP_DLLS or unknown)
        # VM_READ is a bit, not a fixed mask. VM_OPERATION, VM_WRITE and CREATE_THREAD
        # are independently notable rights, though none proves a completed memory operation.
        memory_rights = mask is not None and mask >= 0 and bool(mask & (0x10 | 0x08 | 0x20 | 0x02))
        if mask is not None and not memory_rights and not notable_trace:
            return []
        source = _process(event, "source")
        diagnostic = basename(source) in _DIAGNOSTIC and not writable(source)
        high = memory_rights and bool(source) and not diagnostic
        rights = "including PROCESS_VM_READ" if mask is not None and mask & 0x10 else "with memory-related qualifiers"
        text = f"A recorded source opened lsass.exe {rights}" if memory_rights else "A source opened lsass.exe"
        return [signal(event, "lsass_access", text, self.attack,
                       (*_ROLE_FIELDS, "process.access.action", "process.access.mask",
                        "process.access.call_trace", "process.access.call_trace_modules"),
                       lane="high" if high else "lead", severity="high" if high else "medium",
                       notes=("The record shows granted access, not a completed read or credential dump.",))]


class RemoteThreadCreation(WindowsEventRule):
    id = "win.remote_thread_creation"
    version = "1"
    title = "Sysmon recorded a thread created in another process"
    families = ("remote_thread",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 8),)
    attack = ("T1055",)
    benign = ("debuggers, security software and instrumentation can create remote threads",)
    next_checks = ("verify both process identities and their lineage", "inspect the thread start address and module")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1055/")

    def judge(self, event):
        if event.get("event.code") != 8:
            return []
        complete = all(any(event.get(f"{role}.{field}") not in (None, "")
                           for field in ("executable", "executable_key", "guid", "pid"))
                       for role in ("source", "target"))
        return [signal(event, "remote_thread", "Sysmon recorded creation of a thread in another process",
                       self.attack, (*_ROLE_FIELDS, "thread.id", "thread.start_address", "thread.start_module",
                                     "thread.start_function"), lane="high" if complete else "lead",
                       severity="high" if complete else "medium",
                       notes=("Start module and function are Sysmon inferences; this event alone does not prove injection.",))]


class ProcessImageTampering(WindowsEventRule):
    id = "win.process_image_tampering"
    version = "1"
    title = "Sysmon reported process image tampering"
    families = ("process_tampering",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 25),)
    attack = ("T1055.012",)
    benign = ("instrumentation or software compatibility issues require investigation",)
    next_checks = ("inspect the process image and memory", "review the process lineage and tampering type")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1055/012/")

    def judge(self, event):
        if event.get("event.code") != 25:
            return []
        detailed = bool(_process(event) and event.get("process.tampering.type"))
        return [signal(event, "process_tampering", "Sysmon reported process image tampering", self.attack,
                       (*_PROCESS_FIELDS, "process.tampering.type"), lane="high" if detailed else "lead",
                       severity="high" if detailed else "medium")]


class UnsignedDriverLoad(WindowsEventRule):
    id = "win.unsigned_driver_load"
    version = "1"
    title = "A driver loaded without a recorded valid signature"
    families = ("image_load",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 6),)
    attack = ("T1068",)
    benign = ("test-signed development drivers and legacy drivers can lack valid signatures",)
    next_checks = ("verify the driver hash, signature and provenance", "inspect the service that loaded the driver")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1068/")

    def judge(self, event):
        if event.get("event.code") != 6 or event.get("image.kind") != "driver" or _signature_known_good(event):
            return []
        bad = _bad_signature(event)
        text = ("A driver loaded with a recorded absent or invalid signature" if bad
                else "A driver loaded with signature validity unrecorded")
        return [signal(event, "driver_signature", text, self.attack, _IMAGE_FIELDS,
                       lane="high" if bad else "lead", severity="high" if bad else "medium")]


class WritableUnsignedDllLoad(WindowsEventRule):
    id = "win.writable_unsigned_dll_load"
    version = "1"
    title = "A process loaded a DLL from a user-writable location without a recorded valid signature"
    families = ("image_load",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 7),)
    attack = ("T1574.001",)
    benign = ("application plugins and per-user installations can load unsigned DLLs",)
    next_checks = ("verify the loading process signature and installation independently",
                   "inspect the DLL hash, writer and search-path resolution")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1574/001/")

    def judge(self, event):
        path = _image(event)
        if (event.get("event.code") != 7 or event.get("image.kind") != "image"
                or not basename(path).endswith(".dll") or not writable(path) or _signature_known_good(event)):
            return []
        high = _bad_signature(event) and _system_directory(_process(event))
        return [signal(event, "writable_dll", "A process loaded a DLL from a user-writable path without a recorded "
                       "valid signature", self.attack, _IMAGE_FIELDS, lane="high" if high else "lead",
                       severity="high" if high else "medium",
                       notes=(("A system-directory path does not establish a trusted process identity. "
                               "The loading process signature is unavailable in this event schema."),))]


class DumpLibraryLoad(WindowsEventRule):
    id = "win.dump_library_load"
    version = "1"
    title = "A process loaded a library that provides diagnostic or dump functionality"
    families = ("image_load",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 7),)
    attack = ("T1003.001",)
    benign = ("crash handlers, debuggers, Task Manager and security software load these libraries",)
    next_checks = ("inspect the loading executable and lineage", "seek process-access and dump-file records")
    research = (_SYSMON, _LSASS)

    def judge(self, event):
        if (event.get("event.code") != 7 or event.get("image.kind") != "image"
                or basename(_image(event)) not in _DUMP_DLLS):
            return []
        return [signal(event, "dump_library", "A process loaded a library with diagnostic or dump functionality",
                       self.attack, _IMAGE_FIELDS,
                       notes=(("A library load does not prove a dump occurred. Stronger access, tampering or "
                               "unsigned writable-load observations are evaluated separately."),))]


class UnexpectedClrLoad(WindowsEventRule):
    id = "win.unexpected_clr_load"
    version = "1"
    title = "A CLR load did not meet the expected loader, module path and signature checks"
    families = ("image_load",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 7),)
    attack = ("T1620",)
    benign = ("native applications can legitimately host the CLR through plugins or automation",)
    next_checks = ("inspect CLR-hosting expectations for this process", "seek assemblies, lineage and related memory events")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1620/")

    def judge(self, event):
        if (event.get("event.code") != 7 or event.get("image.kind") != "image"
                or basename(_image(event)) != "clr.dll"):
            return []
        if (_expected_dotnet_host(_process(event)) and _expected_clr_path(_image(event))
                and _signature_known_good(event)):
            return []
        return [signal(event, "unexpected_clr", "A CLR load did not meet the expected loader, module path and "
                       "signature checks",
                       self.attack, _IMAGE_FIELDS,
                       notes=(("A CLR load does not prove reflective code loading. The host exclusion requires an "
                               "expected loader, a canonical CLR installation path and a recorded valid module "
                               "signature; an unknown module signature remains a lead."),))]


WINDOWS_MEMORY_PLAYBOOKS = (
    LsassProcessAccess, RemoteThreadCreation, ProcessImageTampering, UnsignedDriverLoad,
    WritableUnsignedDllLoad, DumpLibraryLoad, UnexpectedClrLoad,
)
