"""Typed Windows process-image and file-writer observations; filenames do not prove payload contents."""
from __future__ import annotations

import json
import ntpath
import re

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_ecar import class_discriminator, ecar_record, source_label
from romulus.detect.windows_events import (
    WindowsEventRule,
    basename,
    components,
    local_path_components,
    signal,
    writable,
)
from romulus.detect.windows_path_data import has_short_name, installation_parts, path_class
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

# Suffixes accepted for an OS-recorded process image, not a PATHEXT or argv list.
# The rule detects a naming discrepancy; it never claims to have inspected PE bytes.
# Microsoft PE image/driver formats and native library/plugin conventions:
# https://learn.microsoft.com/windows/win32/debug/pe-format
# https://learn.microsoft.com/windows/win32/dlls/dynamic-link-libraries
# https://learn.microsoft.com/windows/win32/shell/executable-files
# https://learn.microsoft.com/windows/win32/cossdk/com--application-file-types
# https://learn.microsoft.com/windows/win32/msi/windows-installer-file-extensions
# https://learn.microsoft.com/windows-hardware/drivers/debugger/symbols-and-symbol-files
PROCESS_IMAGE_SUFFIXES = {
    ".exe": "Windows executable image",
    ".com": "DOS or Windows executable program",
    ".scr": "Executable screen saver",
    ".pif": "Legacy executable-program launch descriptor",
    ".cpl": "Native Control Panel module",
    ".msi": "Windows Installer package; accepted launch convention",
    ".dll": "Portable executable dynamic-link library",
    ".sys": "Native system driver image",
    ".ocx": "Native ActiveX control library",
    ".drv": "Native or legacy driver library",
    ".acm": "Native Audio Compression Manager codec library",
    ".ax": "Native DirectShow filter library",
    ".efi": "Portable executable firmware application",
    ".ime": "Native input method editor library",
    ".tsp": "Native telephony service provider library",
    ".xll": "Native Excel add-in library",
    ".wll": "Native Word add-in library",
}
_IMAGE_FIELDS = ("process.executable", "process.executable_key")
_FILE_FIELDS = (*_IMAGE_FIELDS, "process.pid", "file.path", "file.path_key", "file.action")
_SYSMON_DOC = "https://learn.microsoft.com/sysinternals/downloads/sysmon#events"
_PARENT_FIELDS = ("process.parent.executable", "process.parent.executable_key")
# Native image suffix conventions, rather than the installer/launch descriptors
# also accepted by the process-image naming rule. No file headers are inspected.
_PE_SUFFIXES = PROCESS_IMAGE_SUFFIXES.keys() - {".msi", ".pif"}
_SID = re.compile(r"s-\d+(?:-\d+)+", re.ASCII)
_KEY_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.ASCII)
# ESE's default AD database/log/checkpoint names, including rollover log names:
# https://learn.microsoft.com/windows/win32/extensible-storage-engine/extensible-storage-engine-files
_ESE_FILE = re.compile(
    r"(?:ntds\.dit(?:\.jfm)?|temp\.edb|edb(?:tmp|[0-9a-f]{5,8})?\.(?:log|jtx)|"
    r"edb\.(?:chk|jcp)|edbres[0-9]{5}\.jrs|res[12]\.log)", re.ASCII)


def _path(event, stem):
    """Prefer the typed canonical key, without stringifying malformed field values."""
    recorded = event.get(stem)
    if isinstance(recorded, str) and recorded.endswith(("\\", "/")):
        return ""
    for name in (stem + "_key", stem):
        value = event.get(name)
        if isinstance(value, str) and value:
            return value
    return ""


def _normalized_path(path):
    if not isinstance(path, str) or not path or "\0" in path or path.endswith(("\\", "/")):
        return ""
    text = ntpath.normpath(path.replace("/", "\\")).casefold()
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
        if text.startswith("unc\\"):
            text = "\\\\" + text[4:]
    return text


def _resolved_file(path):
    """A recorded absolute local/UNC file path, never a guessed working directory."""
    text = _normalized_path(path)
    if not text:
        return ""
    if local_path_components(text):
        parts = local_path_components(text)
    elif text.startswith("\\\\"):
        parts = components(text)
        if len(parts) < 3:
            return ""
    else:
        return ""
    # A colon in the final component denotes an ADS rather than an image filename.
    return text if parts and ":" not in parts[-1] and "%" not in text else ""


def _suffix(path):
    name = basename(path)
    # splitext intentionally leaves ".hidden" and names without an extension undecided.
    suffix = ntpath.splitext(name)[1]
    return suffix if suffix != "." else ""


def _sysmon(event, code, family):
    if ecar_record(event):
        return class_discriminator(event, code, family)
    return (event.family == family and event.get("event.code") == code
            and str(event.get("event.provider") or "").casefold() == SYSMON.casefold()
            and str(event.get("event.channel") or "").casefold() == SYSMON_CHANNEL.casefold())


def _directory(path):
    return ntpath.dirname(_normalized_path(path)) or "<unresolved-directory>"


def _system_image(path, name):
    return installation_parts(path) in {
        ("windows", system, name) for system in ("system32", "syswow64", "sysnative")}


def _profile_tail(local, installed, aliases=()):
    """The recorded roaming application-data suffix of a standard profile path."""
    if aliases[:1] == ("%appdata%",):
        return aliases[1:]
    if aliases[:3] == ("%userprofile%", "appdata", "roaming"):
        return aliases[3:]
    if len(local) > 4 and local[0] == "users" and local[2:4] == ("appdata", "roaming"):
        return local[4:]
    for prefix in (
        ("windows", "serviceprofiles", "localservice", "appdata", "roaming"),
        ("windows", "serviceprofiles", "networkservice", "appdata", "roaming"),
        *(("windows", system, "config", "systemprofile", "appdata", "roaming")
          for system in ("system32", "syswow64", "sysnative")),
    ):
        if installed[:len(prefix)] == prefix:
            return installed[len(prefix):]
    return ()


def _lsass_store(path):
    """Recognize store path shapes, never a host's DC role or service authorization."""
    normalized = _normalized_path(path)
    aliases = components(normalized)
    volume = local_path_components(normalized)
    local = volume if re.match(r"[a-z]:\\", normalized) else ()
    installed = installation_parts(normalized)
    name = basename(normalized)
    # AD database and log locations may be moved independently. With a canonical
    # LSASS writer, an exact ESE filename on a recorded local volume is enough
    # for a store-shaped lead, without asserting the host's role or authorization.
    if volume and _ESE_FILE.fullmatch(name):
        return True
    if has_short_name(path):
        return False
    if len(installed) == 3 and installed[:2] == ("windows", "ntds") and _ESE_FILE.fullmatch(name):
        return True
    if installed[:2] == ("windows", "debug") and len(installed) == 3 and name.startswith("netlogon."):
        return True
    tail = _profile_tail(local, installed, aliases)
    if tail[:2] == ("microsoft", "protect"):
        tail = tail[2:]
    else:
        tail = next((installed[4:] for system in ("system32", "syswow64", "sysnative")
                     if installed[:4] == ("windows", system, "microsoft", "protect")), ())
    if tail and _SID.fullmatch(tail[0]):
        rest = tail[1:]
        if rest[:1] in {("user",), ("machine",)}:
            rest = rest[1:]
        if len(rest) == 1:
            key = rest[0][1:-1] if rest[0].startswith("{") and rest[0].endswith("}") else rest[0]
            if rest[0] == "preferred" or _KEY_GUID.fullmatch(key):
                return True
    # CNG paths: https://learn.microsoft.com/windows/win32/seccng/key-storage-and-retrieval
    roaming = _profile_tail(local, installed, aliases)
    common = installed
    if aliases[:1] == ("%programdata%",):
        common = ("programdata", *aliases[1:])
    elif aliases[:1] == ("%allusersprofile%",):
        tail = aliases[1:]
        common = ("programdata", *(tail[1:] if tail[:1] == ("application data",) else tail))
    elif local[:3] == ("documents and settings", "all users", "application data"):
        common = ("programdata", *local[3:])
    return ((len(common) == 5 and common[:3] == ("programdata", "microsoft", "crypto")
             and common[3] in {"keys", "systemkeys"})
            or (len(roaming) == 4 and roaming[:2] == ("microsoft", "crypto")
                and roaming[2] in {"keys", "systemkeys"}))


def _file_path_with_system_root(path):
    resolved = _resolved_file(path)
    if resolved:
        return resolved
    # Explicit SystemRoot/WinDir aliases identify the system root without
    # guessing that a remote share or arbitrary data volume is the system drive.
    installed = installation_parts(path)
    normalized = _normalized_path(path)
    parts = components(normalized)
    explicit = parts[:1] in {("%systemroot%",), ("%windir%",), ("systemroot",), ("%systemdrive%",)}
    return (normalized if explicit and len(installed) > 1 and ":" not in basename(path)
            and not any("%" in part for part in parts[1:]) else "")


def _image_directory_class(path):
    value = path_class(path, directory=True)
    # Inno's documented temporary instance folder is an identity component,
    # not a reason to suppress a process or to change its lane.
    # https://jrsoftware.org/ishelp/topic_consts.htm
    if writable(path) and "temp" in components(path):
        value = re.sub(r"(?<=\\)is-[a-z0-9]+(?:-uninstall)?\.tmp(?=\\|$)", "is-<instance>.tmp", value)
    return value


class ClientDriveProcess(WindowsEventRule):
    ecar_compatible = True
    id = "win.client_drive_process"
    title = "Process image recorded on an RDP redirected client drive"
    families = ("process_exec",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1),)
    attack = ("T1021.001",)
    benign = ("an administrator intentionally running a program from an RDP client drive",)
    next_checks = ("the RDP session, client host, user and executable contents",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1021/001/")

    def judge(self, event):
        if not _sysmon(event, 1, "process_exec"):
            return []
        path = _resolved_file(_path(event, "process.executable"))
        parts = components(path)
        if not path.startswith("\\\\") or len(parts) < 3 or parts[0] != "tsclient":
            return []
        return [signal(event, "client_drive_image",
                       f"{source_label(event)} recorded process creation with image '{self.describe(path)}' on a redirected client drive",
                       self.attack, _IMAGE_FIELDS, lane="high", severity="high", content=path)]


class NonExecutableProcessImage(BehaviorFleetRule):
    ecar_compatible = True
    id = "win.non_executable_process_image"
    version = "2"
    title = "Process image has an extension outside native executable conventions"
    families = ("process_exec",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1),)
    attack = ("T1036.008",)
    benign = ("an application intentionally launching a native image with a custom extension",)
    next_checks = ("the executable's file header, signer, original filename and parent process",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1036/008/")

    def judge(self, event):
        if not _sysmon(event, 1, "process_exec"):
            return []
        path = _resolved_file(_path(event, "process.executable"))
        suffix = _suffix(path)
        if not path or not suffix or suffix in PROCESS_IMAGE_SUFFIXES:
            return []
        parent = path_class(_path(event, "process.parent.executable"))
        directory = _image_directory_class(path)
        return [signal(event, "non_executable_image_suffix",
                       f"{source_label(event)} recorded process image '{self.describe(path)}' with extension '{self.describe(suffix)}' outside native executable conventions",
                       self.attack, (*_IMAGE_FIELDS, *_PARENT_FIELDS),
                       content=json.dumps([suffix, parent, directory]),
                       common=f"Process images had suffix '{suffix}', parent image class '{parent}' and directory class '{directory}'",
                       notes=("The recorded image extension is unusual; the file format and malicious intent are unconfirmed.",))]


class LsassFileWrite(BehaviorFleetRule):
    ecar_compatible = True
    id = "win.lsass_file_write"
    version = "3"
    title = "LSASS process recorded creating or overwriting a file"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1547.005",)
    benign = ("a diagnostic or legitimate security support provider writing a file from LSASS",)
    next_checks = ("LSASS-loaded modules, SSP configuration and the created file's contents",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1547/005/",
                "https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c")

    def judge(self, event):
        path = _path(event, "file.path")
        if (not _sysmon(event, 11, "file_change") or not path
                or basename(_path(event, "process.executable")) != "lsass.exe"):
            return []
        routine = _system_image(_path(event, "process.executable"), "lsass.exe") and _lsass_store(path)
        directory = _directory(path)
        return [signal(event, "lsass_file_write",
                       f"{source_label(event)} recorded LSASS creating or overwriting file '{self.describe(path)}'",
                       self.attack, _FILE_FIELDS, lane="lead" if routine else "high",
                       severity="medium" if routine else "high",
                       content=json.dumps([event.host, directory]) if routine else path.casefold(),
                       common=(f"LSASS file writes named a normal-store path shape in directory '{directory}'"
                               if routine else ""),
                       notes=("A file write by the recorded LSASS image does not alone establish an installed malicious SSP.",))]

    def fleet_eligible(self, event, hit):
        return hit.lane == "lead"


class SystemBinaryFileWrite(BehaviorFleetRule):
    ecar_compatible = True
    id = "win.system_binary_file_write"
    version = "2"
    title = "System pid 4 recorded writing a native binary"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1570",)
    benign = ("a legitimate SMB deployment or kernel-mediated binary creation",)
    next_checks = ("SMB sessions and share access, the binary's source and subsequent execution",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1570/")

    def judge(self, event):
        image = _path(event, "process.executable")
        path = _path(event, "file.path")
        pid = event.get("process.pid")
        # The pid is typed process.pid, never the shipper's provider/process id.
        # Some shippers omit the pseudo-image "System"; another image is contradictory.
        if (not _sysmon(event, 11, "file_change") or type(pid) is not int or pid != 4
                or image.casefold() not in {"", "system"} or not path
                or ":" in basename(path) or _suffix(path) not in {".exe", ".dll", ".sys"}):
            return []
        return [signal(event, "system_binary_file_write",
                       f"{source_label(event)} recorded System pid 4 creating or overwriting binary file '{self.describe(path)}'",
                       self.attack, _FILE_FIELDS, content=json.dumps([event.host, _directory(path), _suffix(path)]),
                       common=f"System pid 4 wrote binary-named files with suffix '{_suffix(path)}' in directory '{_directory(path)}'",
                       notes=("Kernel-mediated creation can accompany SMB transfer; the record alone does not identify a remote sender.",))]


class SpoolerFileWriteOutsideSpool(BehaviorFleetRule):
    ecar_compatible = True
    id = "win.spooler_file_write_outside_spool"
    version = "2"
    title = "Print spooler recorded writing outside a spool directory"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1068",)
    benign = ("an approved print component creating a diagnostic or configuration file outside its spool directory",)
    next_checks = ("print driver installation, the written file and spooler child processes",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1068/",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527")

    def judge(self, event):
        path = _file_path_with_system_root(_path(event, "file.path"))
        if (not _sysmon(event, 11, "file_change") or not path
                or basename(_path(event, "process.executable")) != "spoolsv.exe"
                or "spool" in components(path)[:-1]):
            return []
        installed = installation_parts(path)
        system_temp = len(installed) > 2 and installed[:2] == ("windows", "temp")
        high = _suffix(path) in _PE_SUFFIXES and not system_temp
        directory = _directory(path)
        return [signal(event, "spooler_outside_spool",
                       f"{source_label(event)} recorded spoolsv.exe creating or overwriting file '{self.describe(path)}' outside a spool directory",
                       self.attack, _FILE_FIELDS, lane="high" if high else "lead",
                       severity="high" if high else "medium",
                       content=path if high else json.dumps([event.host, _suffix(path), directory]),
                       common=(f"Spoolsv.exe file writes had suffix '{_suffix(path) or '<no-extension>'}' in directory '{directory}'"
                               if not high else ""),
                       notes=("The file write is observed; successful exploitation is unconfirmed.",))]

    def fleet_eligible(self, event, hit):
        return hit.lane == "lead"


class VolumeRootExecutableWrite(WindowsEventRule):
    ecar_compatible = True
    id = "win.volume_root_executable_write"
    version = "2"
    title = "Native executable artifact created at a local volume root"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1574.009",)
    benign = ("an installer or administrator intentionally placing a program at a volume root",)
    next_checks = ("unquoted service paths, file provenance and subsequent execution",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1574/009/")

    def judge(self, event):
        path = _resolved_file(_path(event, "file.path"))
        if (not _sysmon(event, 11, "file_change") or not path
                or len(local_path_components(path)) != 1 or _suffix(path) not in {".exe", ".com"}):
            return []
        return [signal(event, "volume_root_executable",
                       f"{source_label(event)} recorded executable-named file '{self.describe(path)}' created or overwritten at a local volume root",
                       self.attack, _FILE_FIELDS, content=path,
                       notes=("A root-level artifact can intercept an unquoted path; no vulnerable service path or execution is established by this record.",))]


RULES = (ClientDriveProcess, NonExecutableProcessImage, LsassFileWrite, SystemBinaryFileWrite,
         SpoolerFileWriteOutsideSpool, VolumeRootExecutableWrite)
