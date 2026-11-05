"""Typed Sysmon process-image and file-writer observations; filenames do not prove payload contents."""
from __future__ import annotations

import ntpath

from romulus.detect.windows_events import (
    WindowsEventRule,
    basename,
    components,
    local_path_components,
    signal,
)
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
    return (event.family == family and event.get("event.code") == code
            and str(event.get("event.provider") or "").casefold() == SYSMON.casefold()
            and str(event.get("event.channel") or "").casefold() == SYSMON_CHANNEL.casefold())


class ClientDriveProcess(WindowsEventRule):
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
                       f"Sysmon recorded process creation with image '{self.describe(path)}' on a redirected client drive",
                       self.attack, _IMAGE_FIELDS, lane="high", severity="high", content=path)]


class NonExecutableProcessImage(WindowsEventRule):
    id = "win.non_executable_process_image"
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
        return [signal(event, "non_executable_image_suffix",
                       f"Sysmon recorded process image '{self.describe(path)}' with extension '{self.describe(suffix)}' outside native executable conventions",
                       self.attack, _IMAGE_FIELDS, content=path,
                       notes=("The recorded image extension is unusual; the file format and malicious intent are unconfirmed.",))]


class LsassFileWrite(WindowsEventRule):
    id = "win.lsass_file_write"
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
        return [signal(event, "lsass_file_write",
                       f"Sysmon recorded LSASS creating or overwriting file '{self.describe(path)}'",
                       self.attack, _FILE_FIELDS, lane="high", severity="high", content=path.casefold(),
                       notes=("A file write by the recorded LSASS image does not alone establish an installed malicious SSP.",))]


class SystemBinaryFileWrite(WindowsEventRule):
    id = "win.system_binary_file_write"
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
                       f"Sysmon recorded System pid 4 creating or overwriting binary file '{self.describe(path)}'",
                       self.attack, _FILE_FIELDS, content=path.casefold(),
                       notes=("Kernel-mediated creation can accompany SMB transfer; the record alone does not identify a remote sender.",))]


class SpoolerFileWriteOutsideSpool(WindowsEventRule):
    id = "win.spooler_file_write_outside_spool"
    title = "Print spooler recorded writing outside a spool directory"
    families = ("file_change",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 11),)
    attack = ("T1068",)
    benign = ("an approved print component creating a diagnostic or configuration file outside its spool directory",)
    next_checks = ("print driver installation, the written file and spooler child processes",)
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1068/",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527")

    def judge(self, event):
        path = _resolved_file(_path(event, "file.path"))
        if (not _sysmon(event, 11, "file_change") or not path
                or basename(_path(event, "process.executable")) != "spoolsv.exe"
                or "spool" in components(path)[:-1]):
            return []
        return [signal(event, "spooler_outside_spool",
                       f"Sysmon recorded spoolsv.exe creating or overwriting file '{self.describe(path)}' outside a spool directory",
                       self.attack, _FILE_FIELDS, lane="high", severity="high", content=path,
                       notes=("The file write is observed; successful exploitation is unconfirmed.",))]


class VolumeRootExecutableWrite(WindowsEventRule):
    id = "win.volume_root_executable_write"
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
                or len(local_path_components(path)) != 1 or _suffix(path) not in PROCESS_IMAGE_SUFFIXES):
            return []
        return [signal(event, "volume_root_executable",
                       f"Sysmon recorded executable-named file '{self.describe(path)}' created or overwritten at a local volume root",
                       self.attack, _FILE_FIELDS, content=path,
                       notes=("A root-level artifact can intercept an unquoted path; no vulnerable service path or execution is established by this record.",))]


RULES = (ClientDriveProcess, NonExecutableProcessImage, LsassFileWrite, SystemBinaryFileWrite,
         SpoolerFileWriteOutsideSpool, VolumeRootExecutableWrite)
