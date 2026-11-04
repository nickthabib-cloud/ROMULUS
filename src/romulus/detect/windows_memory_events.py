"""Positive observations of process access, tampering and memory-related image loads.

An access right permits an operation; it does not prove a read or a dump occurred. Module
loads and thread creation likewise retain their recorded meaning without asserting injection.
"""
from __future__ import annotations

import json
import re

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_events import (
    WindowsEventRule,
    basename,
    components,
    integer,
    local_path_components,
    signal,
    writable,
)
from romulus.detect.windows_path_data import (
    installation_parts,
    path_class,
    protected_platform_path,
    writable_windows_path,
)
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL

_SYSMON = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
_LSASS = "https://attack.mitre.org/techniques/T1003/001/"
_RIGHTS = "https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
_DUMP_DLLS = frozenset({"dbghelp.dll", "dbgcore.dll", "comsvcs.dll"})
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
        "invalid", "untrusted", "revoked", "unsigned", "not signed", "not trusted",
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
    return installation_parts(path)


def _installed_path(path):
    """Installation-directory scope, not trust or a claim about effective ACLs."""
    parts = _installation_parts(path)
    return (protected_platform_path(path) or bool(
        parts and parts[0] in {"windows", "program files", "program files (x86)"}
        and not writable_windows_path(path)))


def _writable_indicator(path):
    parts = local_path_components(path) or _installation_parts(path)
    return writable(path) or writable_windows_path(path) or bool(parts and parts[0] in {"programdata", "perflogs"})


def _content(event, *fields):
    return json.dumps({name: event.get(name) for name in fields}, sort_keys=True, separators=(",", ":"))


def _image_content(event):
    return _content(event, "process.executable_key", "process.executable", "image.kind", "image.path_key",
                    "image.path", "image.signed", "image.signature_status", "image.signature",
                    "image.hash.sha256", "image.hash.sha1")


def _trace_modules(event):
    """Keep module identity while discarding ASLR addresses and call-site offsets."""
    modules = event.get("process.access.call_trace_modules")
    if not isinstance(modules, list) or not modules:
        modules = str(event.get("process.access.call_trace") or "").split("|")
    return tuple(re.sub(r"\+[0-9a-fx]+$", "", re.sub(r"unknown\([^)]*\)", "unknown", str(frame).strip().casefold()))
                 for frame in modules if str(frame).strip())


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
    version = "7"
    title = "A process opened LSASS with memory-related access or a notable call trace"
    families = ("process_access", "object_access")
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 10), ("Security", SECURITY, 4656), ("Security", SECURITY, 4663))
    attack = ("T1003.001",)
    benign = ("security inspection, crash diagnostics and Task Manager can open LSASS",)
    next_checks = ("verify the source executable and signer independently", "inspect access trace and dump-file writes")
    research = (_SYSMON, _LSASS, _RIGHTS, "https://github.com/antonioCoco/MalSeclogon/blob/master/MalSeclogon.c")

    def judge(self, event):
        code = event.get("event.code")
        security = code in {4656, 4663}
        if code != 10 and not security:
            return []
        if security and str(event.get("object.type") or "").casefold() != "process":
            return []
        target = (event.get("object.name_key") or event.get("object.name")) if security else _process(event, "target")
        if target and basename(target) != "lsass.exe":
            return []
        if not target:
            return [signal(event, "access_target_unresolved", "A process-access record has no target image; LSASS relevance is unresolved",
                           self.attack, (*_ROLE_FIELDS, "process.access.mask", "process.access.call_trace"),
                           content=_content(event, "source.executable_key", "source.executable", "process.access.mask"))]
        mask = integer(event.get("object.access_mask") if security else event.get("process.access.mask"))
        accesses = event.get("object.accesses") if security else None
        if mask is None and isinstance(accesses, list):
            rights_by_name = {"create_thread": 0x2, "vm_operation": 0x8, "vm_read": 0x10,
                              "vm_write": 0x20, "dup_handle": 0x40, "create_process": 0x80}
            mask = sum(rights_by_name.get(str(name).casefold(), 0) for name in set(accesses))
        modules = event.get("process.access.call_trace_modules") or []
        names = {basename(module) for module in modules} if isinstance(modules, list) else set()
        trace = str(event.get("process.access.call_trace") or "").casefold()
        unknown = any(re.fullmatch(r"unknown(?:\([0-9a-fx]+\))?", name) for name in names)
        unknown |= any(re.fullmatch(r"unknown(?:\([0-9a-fx]+\))?(?:\+[0-9a-fx]+)?", frame.strip())
                       for frame in trace.split("|"))
        trace_modules = _trace_modules(event)
        names |= {basename(module) for module in trace_modules}
        notable_trace = bool(names & (_DUMP_DLLS | {"seclogon.dll"}) or unknown or "unknown" in names)
        # VM_READ is a bit, not a fixed mask. VM_OPERATION, VM_WRITE and CREATE_THREAD
        # are independently notable rights, though none proves a completed memory operation.
        memory_rights = mask is not None and mask >= 0 and bool(mask & (0x10 | 0x08 | 0x20 | 0x02))
        related_rights = mask is not None and bool(mask & (0x40 | 0x80))
        if mask is not None and not memory_rights and not related_rights and not notable_trace:
            return []
        source = _process(event) if security else _process(event, "source")
        high = memory_rights and bool(source) and (not _installed_path(source) or notable_trace)
        rights = ("including PROCESS_VM_READ" if mask is not None and mask & 0x10 else
                  "with memory-related rights" if memory_rights else "")
        actor = f"Recorded source '{self.describe(source)}'" if source else "An unresolved source image"
        text = f"{actor} opened lsass.exe {rights}" if memory_rights else f"{actor} opened lsass.exe"
        if security:
            actor = f"by '{self.describe(source)}'" if source else "by a process not recorded"
            text = (f"Security recorded a process-object {'handle request' if code == 4656 else 'access'} "
                    f"{actor} to '{self.describe(target)}'" + (f" {rights}" if rights else ""))
            if str(event.outcome) in {"failure", "Outcome.failure"}:
                text += "; the recorded operation failed"
        if related_rights and not memory_rights:
            text += " with handle-duplication or parent-process access rights"
        priority = ""
        if high:
            reasons = []
            if not _installed_path(source):
                reasons.append("the source path does not establish system-volume installation scope")
            if notable_trace:
                notable_names = sorted(names & (_DUMP_DLLS | {"seclogon.dll"}))
                if unknown or "unknown" in names:
                    notable_names.append("an unresolved module")
                reasons.append("the call trace names " + ", ".join(notable_names))
            priority = "; high priority because memory-related rights were recorded and " + " and ".join(reasons)
            text += priority
        fields = ((*_PROCESS_FIELDS, "object.name", "object.name_key", "object.type", "object.access_mask", "object.accesses")
                  if security else (*_ROLE_FIELDS, "process.access.action", "process.access.mask",
                                    "process.access.call_trace", "process.access.call_trace_modules"))
        return [signal(event, "lsass_access", text, self.attack,
                       fields,
                       lane="high" if high else "lead", severity="high" if high else "medium",
                       content=json.dumps([path_class(source) if protected_platform_path(source) else source,
                                           target, mask, code,
                                           [path_class(item) if protected_platform_path(item) else item
                                            for item in trace_modules]], separators=(",", ":")),
                       common=(text if security else f"A recorded source in the same installation/path class opened lsass.exe {rights}" + priority),
                       notes=(("A handle request does not establish granted access or a completed read or credential dump."
                               if security and code == 4656 else
                               "A process-object access record does not establish a completed read or credential dump."
                               if security else "The record shows granted access, not a completed read or credential dump."),))]


class RemoteThreadCreation(WindowsEventRule):
    id = "win.remote_thread_creation"
    version = "7"
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
        source, target = _process(event, "source"), _process(event, "target")
        module = event.get("thread.start_module")
        address = event.get("thread.start_address")
        unresolved_module = not module or str(module).casefold() in {"unknown", "-"}
        reasons = []
        if source and target:
            if unresolved_module and address:
                reasons.append("no start module was recorded for the recorded start address")
            if not _installed_path(source):
                reasons.append("the source path does not establish system-volume installation scope")
            if basename(target) in {"lsass.exe", "winlogon.exe"}:
                reasons.append(f"the target is {basename(target)}")
        high = bool(reasons)
        detail = (f"; no start module was recorded for start address {self.describe(address)}; "
                  "Sysmon leaves it empty when the address is outside any loaded image" if unresolved_module and address
                  else "; start module was not recorded" if unresolved_module else f"; start module '{self.describe(module)}'")
        detail += (f"; start function '{self.describe(event.get('thread.start_function'))}'" if event.get('thread.start_function')
                   else "; start function not recorded")
        source_label = self.describe(source) if source else "source image not recorded"
        target_label = self.describe(target) if target else "target image not recorded"
        text = f"Sysmon recorded a remote thread from '{source_label}' into '{target_label}'" + detail
        if high:
            text += "; high priority because " + " and ".join(reasons)
        return [signal(event, "remote_thread", text,
                       self.attack, (*_ROLE_FIELDS, "thread.id", "thread.start_address", "thread.start_module",
                                     "thread.start_function"), lane="high" if high else "lead",
                       severity="high" if high else "medium",
                       content=json.dumps([source, target, module, event.get("thread.start_function")], separators=(",", ":")),
                       notes=("Start module and function are Sysmon inferences; this event alone does not prove injection.",))]


class ProcessImageTampering(BehaviorFleetRule):
    id = "win.process_image_tampering"
    version = "7"
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
        detailed = str(event.get("process.tampering.type") or "").strip().casefold() == "image is replaced"
        image, kind = _process(event), event.get("process.tampering.type")
        return [signal(event, "process_tampering", f"Sysmon reported process image tampering for '{self.describe(image)}': {self.describe(kind)}", self.attack,
                       (*_PROCESS_FIELDS, "process.tampering.type"), lane="high" if detailed else "lead",
                       severity="high" if detailed else "medium",
                       content=json.dumps([path_class(image), str(kind or '').casefold()]),
                       common=f"Sysmon reported {self.describe(kind)} for image path class '{path_class(image)}'")]


class UnsignedDriverLoad(WindowsEventRule):
    id = "win.unsigned_driver_load"
    version = "5"
    title = "A driver loaded without a recorded valid signature"
    families = ("image_load",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 6),)
    attack = ("T1547.006",)
    benign = ("test-signed development drivers and legacy drivers can lack valid signatures",)
    next_checks = ("verify the driver hash, signature and provenance", "inspect the service that loaded the driver")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1547/006/")

    def judge(self, event):
        if event.get("event.code") != 6 or event.get("image.kind") != "driver" or _signature_known_good(event):
            return []
        bad = _bad_signature(event)
        text = ("A driver loaded with a recorded absent or invalid signature" if bad
                else "A driver loaded with signature validity unrecorded")
        if str(event.get("image.signature_status") or "").casefold() == "expired" and event.get("image.signed") is True:
            text = "A driver loaded with a recorded signature status of expired"
        return [signal(event, "driver_signature", text, self.attack, _IMAGE_FIELDS,
                       lane="high" if bad else "lead", severity="high" if bad else "medium", content=_image_content(event))]


class WritableUnsignedDllLoad(WindowsEventRule):
    id = "win.writable_unsigned_dll_load"
    version = '8'
    title = "A process loaded an unsigned or invalid module, or a module outside standard installation directories"
    families = ("image_load",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 7),)
    attack = ("T1574.001",)
    benign = ("application plugins and per-user installations can load unsigned DLLs",)
    next_checks = ("verify the loading process signature and installation independently",
                   "inspect the DLL hash, writer and search-path resolution")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1574/001/")

    def __init__(self):
        super().__init__()
        self.signature_not_assessed = 0

    def consume(self, events):
        before = self.signature_not_assessed
        out = super().consume(events)
        unassessed = self.signature_not_assessed - before
        self.evaluated -= unassessed
        self.missing_required += unassessed
        return out

    def judge(self, event):
        path = _image(event)
        if (event.get("event.code") != 7 or event.get("image.kind") != "image"
                or not path or _signature_known_good(event)):
            return []
        if _installed_path(path) and not _bad_signature(event):
            self.signature_not_assessed += 1
            absent = not any(event.has(name) for name in ("image.signed", "image.signature_status", "image.signature"))
            reason = ("not assessed: no signature fields in this record" if absent
                      else "not assessed: recorded signature fields do not establish module signature validity")
            self.note_coverage("module_signature_absent" if absent else "module_signature_unresolved", reason)
            return []
        from romulus.detect.windows_system_data import KNOWN_SYSTEM_DLLS
        redirection = any(part.endswith('.exe.local') and len(part) > len('.exe.local') for part in components(path))
        located = bool(local_path_components(path) or _installation_parts(path) or _writable_indicator(path))
        known_non_system = basename(path) in KNOWN_SYSTEM_DLLS and located and (not _system_directory(path) or _writable_indicator(path))
        reason = ("an unsigned/invalid module has a writable-path indicator and the loader has a system-directory path"
                  if _bad_signature(event) and _system_directory(_process(event)) and _writable_indicator(path) else
                  "the unsigned/invalid module was loaded from an executable .local redirection directory"
                  if _bad_signature(event) and redirection else
                  "the unsigned/invalid module has a known system-DLL basename in a non-system or writable directory"
                  if _bad_signature(event) and known_non_system else "")
        high = bool(reason)
        text = ("A process loaded a module with a recorded absent or invalid signature" if _bad_signature(event)
                else "A process loaded a module outside standard installation directories without a recorded valid signature")
        text += f"; process '{self.describe(_process(event))}', module '{self.describe(path)}'"
        if high:
            text += "; high priority because " + reason
        parts = _installation_parts(path)
        family = ("ngen native images" if len(parts) > 2 and parts[:2] == ("windows", "assembly")
                  and parts[2].startswith("nativeimages_") else "Windows component store" if parts[:2] == ("windows", "winsxs") else "")
        content = (json.dumps([path_class(_process(event)), family, event.get("image.signed"), event.get("image.signature_status")])
                   if family else _image_content(event))
        common = (f"A process in loader path class '{path_class(_process(event))}' loaded unsigned or invalid modules from {family}"
                  if family else text)
        return [signal(event, "writable_dll", text, self.attack, _IMAGE_FIELDS, lane="high" if high else "lead",
                       severity="high" if high else "medium", content=content, common=common,
                       notes=(("A system-directory path does not establish a trusted process identity. "
                               "The loading process signature is unavailable in this event schema."),))]


class DumpLibraryLoad(WindowsEventRule):
    id = "win.dump_library_load"
    version = "7"
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
        if (_signature_known_good(event) and _system_directory(_image(event)) and _installed_path(_image(event))
                and _installed_path(_process(event))):
            return []
        return [signal(event, "dump_library", f"Process '{self.describe(_process(event))}' loaded library '{self.describe(_image(event))}' with diagnostic or dump functionality",
                       self.attack, _IMAGE_FIELDS, content=_image_content(event),
                       notes=(("A library load does not prove a dump occurred. Stronger access, tampering or "
                               "unsigned writable-load observations are evaluated separately."),))]


class UnexpectedClrLoad(WindowsEventRule):
    id = "win.unexpected_clr_load"
    version = "7"
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
        return [signal(event, "unexpected_clr", f"Process '{self.describe(_process(event))}' loaded CLR module '{self.describe(_image(event))}'; "
                       "the loader, module path and signature did not meet the expected checks",
                       self.attack, _IMAGE_FIELDS, content=_image_content(event),
                       notes=(("A CLR load does not prove reflective code loading. The host exclusion requires an "
                               "expected loader, a canonical CLR installation path and a recorded valid module "
                               "signature; an unknown module signature remains a lead."),))]


WINDOWS_MEMORY_PLAYBOOKS = (
    LsassProcessAccess, RemoteThreadCreation, ProcessImageTampering, UnsignedDriverLoad,
    WritableUnsignedDllLoad, DumpLibraryLoad, UnexpectedClrLoad,
)
