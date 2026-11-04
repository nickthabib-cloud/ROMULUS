"""Signed-binary proxy execution and LOLBin download or decode, recognised from command-line tokens.

Each rule here reads the argument tokens of a known binary with that binary's own option grammar (never a substring
of the raw command line), and claims only what the arguments show: that the binary was run with those arguments. Only
a file or network event would show that a payload was actually fetched, written or run, so these rules are
positive-only: a quiet window proves nothing, because the same ends can be reached by binaries and
arguments the list does not name.

Covered binaries and shapes: mshta (URL or inline script), rundll32 (a DLL export, `javascript:`/`vbscript:` or
comsvcs MiniDump), regsvr32 (`/i:` with a scriptlet or URL), wscript/cscript (a script from a user-writable or remote
path), msiexec (a remote or user-writable package), installutil / regasm / regsvcs / msbuild / odbcconf / cmstp
(uninstall-or-logfile execution, inf/scriptlet payloads), certutil (`-urlcache`/`-verifyctl` download, `-decode`),
bitsadmin (`/transfer`), curl (`-o`/`-O` to disk), and powershell / pwsh (encoded command, and download-cradle cmdlet
calls parsed from script text).
"""
from __future__ import annotations

import ntpath
import re
from typing import ClassVar

from romulus.detect.base import PredicateField
from romulus.detect.powershell_tokens import read_script
from romulus.detect.windows_cmdline import (
    PARSED,
    PARSED_DECODED,
    has_switch,
    is_ordinal,
    is_remote_path,
    is_user_writable,
    operands,
    parse_powershell,
    ps_tokens,
    rundll32_target,
    split_argv,
    switch_name,
    switch_value,
    url_in,
)
from romulus.detect.windows_common import (
    Hit,
    Undecided,
    WindowsProcessRule,
    clip,
    image_name,
    parent_predicate,
    parsed_field,
    resolve_parent,
)
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from romulus.detect.windows_lolbin_data import DASH_LIKE, switch_operand
from romulus.detect.windows_path_data import has_short_name, installation_parts
from romulus.detect.windows_scripts import HIGH_TOOLS, amsi_bypass, downloads, runs_code
from romulus.evidence.typed import TypedEvent

# Download cmdlets and their characteristic members/parameters, matched as code words in parsed script text.
_DOWNLOAD_WORDS = {
    "invoke-webrequest": "Invoke-WebRequest", "iwr": "Invoke-WebRequest", "wget": "Invoke-WebRequest",
    "curl": "Invoke-WebRequest", "invoke-restmethod": "Invoke-RestMethod", "irm": "Invoke-RestMethod",
    "start-bitstransfer": "Start-BitsTransfer",
}
_DOWNLOAD_MEMBERS = {
    "downloadstring": "WebClient.DownloadString", "downloadfile": "WebClient.DownloadFile",
    "downloaddata": "WebClient.DownloadData", "openread": "WebClient.OpenRead",
}
_EXEC_WORDS = {"invoke-expression", "iex", "invoke-command", "icm"}

# Each library's proxy-export family comes from its original LOLBAS entry.
# A-suffixed exports retain their documented function family; Ex is additionally
# documented at https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa768006(v=vs.85).
_PROXY_EXPORTS = {
    "url": ({"openurl", "openurla", "fileprotocolhandler"}, "https://lolbas-project.github.io/lolbas/Libraries/Url/"),
    "ieframe": ({"openurl"}, "https://lolbas-project.github.io/lolbas/Libraries/Ieframe/"),
    "shdocvw": ({"openurl"}, "https://lolbas-project.github.io/lolbas/Libraries/Shdocvw/"),
    "advpack": ({"registerocx", "launchinfsection", "launchinfsectionex"}, "https://lolbas-project.github.io/lolbas/Libraries/Advpack/"),
    "ieadvpack": ({"registerocx", "launchinfsection", "launchinfsectionex"}, "https://lolbas-project.github.io/lolbas/Libraries/Ieadvpack/"),
    "setupapi": ({"installhinfsection"}, "https://lolbas-project.github.io/lolbas/Libraries/Setupapi/"),
    "syssetup": ({"setupinfobjectinstallaction"}, "https://lolbas-project.github.io/lolbas/Libraries/Syssetup/"),
    "pcwutl": ({"launchapplication"}, "https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/"),
    "zipfldr": ({"routethecall"}, "https://lolbas-project.github.io/lolbas/Libraries/Zipfldr/"),
    "shell32": ({"shellexec_rundll", "shellexec_rundlla", "control_rundll", "control_rundllasuser", "control_rundllw"}, "https://lolbas-project.github.io/lolbas/Libraries/Shell32/"),
    "scrobj": ({"generatetypelib"}, "https://lolbas-project.github.io/lolbas/Libraries/Scrobj/"),
    "dfshim": ({"shopenverbapplication"}, "https://lolbas-project.github.io/lolbas/Libraries/Dfshim/"),
    "shimgvw": ({"imageview_fullscreen"}, "https://lolbas-project.github.io/lolbas/Libraries/Shimgvw/"),
    "mshtml": ({"printhtml"}, "https://lolbas-project.github.io/lolbas/Libraries/Mshtml/"),
}

# Names, not trust: these suppress only a bare-name/CWD inference. An explicitly
# writable path or a proxy export is still evaluated. KnownDLL membership varies
# with Windows version; no endpoint registry inventory is inferred from this list.
# Microsoft's published KnownDLL defaults (archived original KB Q102985):
# https://ftp.zx.net.nz/pub/Patches/ftp.microsoft.com/MISC/KB/en-us/102/985.HTM
# Current search-order and per-system KnownDLL registry contract:
# https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order
_SYSTEM_LIBRARIES = frozenset({
    'advapi32.dll', 'comdlg32.dll', 'crtdll.dll', 'gdi32.dll', 'kernel32.dll', 'lz32.dll',
    'olecli32.dll', 'olesvr32.dll', 'rpcrt4.dll', 'shell32.dll', 'user32.dll', 'version.dll',
    # Windows Update component registration list (each name below):
    # https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/additional-resources-for-windows-update
    'atl.dll', 'urlmon.dll', 'mshtml.dll', 'shdocvw.dll', 'browseui.dll', 'jscript.dll', 'vbscript.dll',
    'scrrun.dll', 'msxml.dll', 'msxml3.dll', 'msxml6.dll', 'actxprxy.dll', 'softpub.dll', 'wintrust.dll',
    'dssenh.dll', 'rsaenh.dll', 'gpkcsp.dll', 'sccbase.dll', 'slbcsp.dll', 'cryptdlg.dll', 'oleaut32.dll',
    'ole32.dll', 'initpki.dll', 'wuapi.dll', 'wuaueng.dll', 'wuaueng1.dll', 'wucltui.dll', 'wups.dll',
    'wups2.dll', 'wuweb.dll', 'qmgr.dll', 'qmgrprxy.dll', 'wucltux.dll', 'muweb.dll', 'wuwebv.dll',
    # https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    'ntdll.dll',
    # https://learn.microsoft.com/windows-server/administration/windows-commands/rundll32-printui
    'printui.dll',
    # https://lolbas-project.github.io/lolbas/Libraries/Scrobj/
    'scrobj.dll',
    # https://lolbas-project.github.io/lolbas/Libraries/Dfshim/
    'dfshim.dll',
    # https://learn.microsoft.com/windows/win32/api/comsvcs/nf-comsvcs-cocreateactivity
    'comsvcs.dll',
    # https://learn.microsoft.com/windows/win32/api/davclnt/nf-davclnt-davregisterauthcallback
    'davclnt.dll',
}) | frozenset(name + '.dll' for name in _PROXY_EXPORTS)

# Microsoft names these built-in applets; this does not exclude third-party CPLs.
# https://learn.microsoft.com/windows/win32/shell/controlpanel-canonical-names
# https://learn.microsoft.com/windows/win32/shell/executing-control-panel-items
# Original Microsoft KB Q313808, archived after the original URL was retired:
# https://ftp.zx.net.nz/pub/archive/ftp.microsoft.com/MISC/KB/en-us/313/808.HTM
# https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/tools
# Microsoft's Windows XP remediation names wscui.cpl as the Security Center entry:
# https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=SecurityMasterAV
_SYSTEM_CPLS = frozenset({'appwiz.cpl', 'desk.cpl', 'hdwwiz.cpl', 'inetcpl.cpl', 'intl.cpl',
    'irprops.cpl', 'joy.cpl', 'main.cpl', 'mmsys.cpl', 'powercfg.cpl', 'sysdm.cpl', 'tabletpc.cpl',
    'telephon.cpl', 'timedate.cpl', 'wscui.cpl', 'firewall.cpl', 'access.cpl', 'ncpa.cpl',
    'nusrmgr.cpl', 'nwc.cpl', 'odbccp32.cpl', 'sapi.cpl'})

# The cited entries establish the proxy-script names, not a signature or an
# assertion that an arbitrary supplied URL was executed.
_PROXY_SCRIPTS = {
    'pubprn.vbs': 'https://lolbas-project.github.io/lolbas/Scripts/Pubprn/',
    'syncappvpublishingserver.vbs': 'https://lolbas-project.github.io/lolbas/Scripts/Syncappvpublishingserver/',
    'winrm.vbs': 'https://lolbas-project.github.io/lolbas/Scripts/Winrm/',
    'manage-bde.wsf': 'https://lolbas-project.github.io/lolbas/Scripts/Manage-bde/',
}
# SyncAppv's documented embedded script text is evaluated by its PowerShell child;
# the child process/script rules see the URL as code. This table reads plain argv.


def _command_argv(event: TypedEvent) -> list[str]:
    argv = split_argv(str(event.get("process.command_line")))
    if not argv:
        raise Undecided("command_line", "the command line did not parse into any argument")
    return argv


def place_operand(event: TypedEvent, token: str, *, dll_search: bool = False) -> tuple[str, str]:
    """Place a relative operand only with an absolute working directory in its record."""
    operand = token.strip().strip('"')
    if is_remote_path(operand) or operand.casefold().startswith(("javascript:", "vbscript:")):
        return operand, ""
    if dll_search and not ntpath.dirname(operand) and not ntpath.splitdrive(operand)[0]:
        return operand, "; resolved through the DLL search order"
    directory = event.get("process.current_directory")
    drive = ntpath.splitdrive(directory)[0] if isinstance(directory, str) else ""
    operand_drive, operand_tail = ntpath.splitdrive(operand)
    if (not ntpath.isabs(operand)
            and _absolute_directory(directory)
            and (not operand_drive or operand_drive.casefold() == drive.casefold())):
        return ntpath.normpath(ntpath.join(directory, operand_tail)), "; placed using the recorded working directory"
    return operand, ""


def _unc_path(path):
    return is_remote_path(path)


def _absolute_directory(directory):
    if not isinstance(directory, str):
        return False
    drive, tail = ntpath.splitdrive(directory)
    return (is_remote_path(directory) or bool(drive and tail.startswith(('\\', '/')))
            or directory.replace('/', '\\').casefold().startswith(('%windir%\\', '%systemroot%\\', '\\systemroot\\')))


def _system_library_path(path):
    # Inspect the literal directory, not the library basename: a short filename
    # under a literal system directory does not infer an unknown long directory.
    parts = installation_parts(ntpath.dirname(path.replace('/', '\\')))
    return parts in {('windows', 'system32'), ('windows', 'syswow64')}


def _writable_operand(event, token, label, behavior, attack, *, dll_search=False):
    placed, note = place_operand(event, token, dll_search=dll_search)
    unc = _unc_path(placed)
    predicate = [parsed_field(event, token)]
    if "placed using" in note:
        value = event.fields["process.current_directory"]
        predicate.append(PredicateField("process.current_directory", value.value, value.origin))
    if has_short_name(placed) and not unc and not _system_library_path(placed):
        return Hit(behavior, f"{label} was given target '{clip(placed)}'; path recorded in 8.3 short form; "
                   f"its long location is not recorded{note}", "lead", "medium", attack, predicate,
                   content=f"{behavior}:short-path")
    if dll_search and not ntpath.dirname(placed) and not ntpath.splitdrive(placed)[0]:
        recognized = placed.casefold()
        if not ntpath.splitext(recognized)[1]:
            recognized += '.dll'
        if recognized in _SYSTEM_LIBRARIES or recognized in _SYSTEM_CPLS:
            return None
        directory = event.get("process.current_directory")
        if not isinstance(directory, str):
            return None
        if not (_absolute_directory(directory)
                and (_unc_path(directory) or is_user_writable(directory) or has_short_name(directory))):
            return None
        value = event.fields["process.current_directory"]
        predicate.append(PredicateField("process.current_directory", value.value, value.origin))
        if has_short_name(directory) and not is_remote_path(directory):
            return Hit(behavior, f"{label} named '{clip(placed)}'; the recorded working directory "
                       f"'{clip(directory)}' has a path recorded in 8.3 short form; its long location is not recorded",
                       "lead", "medium", attack, predicate, content=f"{behavior}:short-cwd")
        return Hit(behavior, f"{label} named '{clip(placed)}', which is not a recognized Windows system library; "
                   f"the standard search order reaches the recorded working directory ({clip(directory)}) "
                   "after the application and system directories, so it may load from there",
                   "lead", "medium", attack, predicate, content=f"{behavior}:search-order")
    if not unc and not is_user_writable(placed):
        return None
    location = ("a remote URL" if unc and '://' in placed else "a UNC path") if unc else "a user-writable location"
    return Hit(behavior, f"{label} was given a target in {location} ({clip(placed)}){note}",
               "lead", "medium", attack, predicate, content=f"{behavior}:{'unc' if unc else 'writable'}")


def _rundll_arguments(argv):
    rest = [token for token in argv[1:] if token]
    if not rest:
        return "", "", []
    library, comma, entry = rest[0].partition(",")
    if comma and entry:
        return library, entry, rest[1:]
    return library, rest[1] if len(rest) > 1 else "", rest[2:]


def _proxy_export(event, argv):
    target = rundll32_target(argv)
    if target is None:
        return None
    library, entry = target
    exports, source = _PROXY_EXPORTS.get(library, ((), ""))
    operand, recorded_entry, args = _rundll_arguments(argv)
    remote = next((arg for arg in args if is_remote_path(arg) or url_in(arg)), None)
    if entry not in exports:
        if remote:
            return Hit("rundll32_remote_argument",
                       f"rundll32 export '{recorded_entry}' was given remote argument '{clip(remote)}'; "
                       "successful loading or execution is not established", "lead", "medium", ("T1218.011",),
                       [parsed_field(event, clip(' '.join(argv[1:])))],
                       content=f"rundll32:argument:{library}:{entry}")
        return None
    if library == "shell32" and entry in {"control_rundll", "control_rundllasuser", "control_rundllw"}:
        cpl = args[0].split(",", 1)[0] if args else ""
        placed, _note = place_operand(event, cpl, dll_search=True)
        if not remote and (not cpl or _system_library_path(placed)
                           or not ntpath.dirname(cpl) and cpl.casefold() in _SYSTEM_CPLS):
            return None
    placed, note = place_operand(event, operand, dll_search=True)
    payload = clip(" ".join(args)) if args else "not recorded"
    predicate = [parsed_field(event, clip(" ".join(argv[1:])))]
    if "placed using" in note:
        value = event.fields["process.current_directory"]
        predicate.append(PredicateField("process.current_directory", value.value, value.origin))
    if remote:
        return Hit("rundll32_proxy_export",
                   f"rundll32 export '{recorded_entry}' was given remote argument '{clip(remote)}'; "
                   f"this proxy export of '{clip(placed)}' names a remote target; "
                   "successful loading or execution is not established",
                   "high", "high", ("T1218.011", "T1105"), predicate,
                   content=f"rundll32:export:{library}:{entry}:remote",
                   notes=(f"Proxy-export family source: {source}",))
    if any(has_short_name(arg.split(',', 1)[0]) and not _system_library_path(arg.split(',', 1)[0]) for arg in args):
        note += "; target path recorded in 8.3 short form; its long location is not recorded"
    return Hit("rundll32_proxy_export",
               f"rundll32 named proxy export '{recorded_entry}' of '{clip(placed)}'{note}; target: {payload}; "
               "successful loading or execution is not established", "lead", "medium", ("T1218.011",),
               predicate, content=f"rundll32:export:{library}:{entry}", notes=(f"Proxy-export family source: {source}",))


class MshtaExecution(WindowsProcessRule):
    id = "win.mshta_remote_or_inline"
    version = '7'
    title = "mshta ran a remote HTA or inline script"
    assures_negative = False
    positive_only_reason = ("mshta is recognised from argv, and a payload can also be delivered by other binaries "
                            "and argument shapes; a window without a match proves nothing, and only a network or "
                            "file event would show that a remote HTA was fetched")
    severity, lane = "high", "high"
    attack = ("T1218.005", "T1059.005", "T1059.007", "T1105")
    benign = ("legacy line-of-business HTA applications launched from a known internal path",)
    next_checks = ("the network connection mshta made (Sysmon 3, proxy, DNS)",
                   "mshta's child processes", "the HTA or URL named in the arguments")
    card: ClassVar[dict] = {
        "behavior": "mshta.exe was given an http(s)/ftp URL, a UNC path, or an inline javascript:/vbscript: script",
        "telemetry": "Sysmon 1 or Security 4688 (process.executable_key, process.command_line): present when "
                     "command-line logging is on",
        "fidelity": "the command line shows mshta was asked to run that target; it does not show the target was "
                    "reachable or ran. Positive-only.",
        "benign_and_cost": "a few legacy internal HTA apps; low cost, and repeats merge per shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "mshta's network connection and children",
        "adds": "first Windows signed-binary proxy-execution rule (mshta)",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.005; LOLBAS mshta entry (reimplemented, not copied)",
        "lanes": "high: remote or inline mshta execution is a common initial-access and C2 step",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is mshta.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "mshta.exe":
            return []
        argv = _command_argv(event)
        for token in argv[1:]:
            url = url_in(token)
            lowered = token.strip().strip('"').casefold()
            if url:
                return [self._hit(event, token, f"a remote target ({url})", "mshta_remote")]
            if lowered.startswith(("javascript:", "vbscript:")):
                return [self._hit(event, token, "an inline script", "mshta_inline")]
            if is_remote_path(lowered):
                location = "a remote URL" if '://' in lowered else "a UNC path"
                return [self._hit(event, token, f"{location} ({token.strip()})", "mshta_unc")]
            if lowered.endswith(".hta") and (hit := _writable_operand(event, token, "mshta", "mshta_local", self.attack)):
                return [hit]
        if any(token.casefold() == '-embedding' for token in argv[1:]):
            return [Hit('mshta_embedding_request', 'mshta was started in embedding mode',
                        'lead', 'medium', ('T1218.005',), [parsed_field(event, '-Embedding')],
                        content='mshta:embedding',
                        notes=('An embedding-mode invocation is observed, not proof that an HTA or payload executed.',
                               'Behavior source: https://lolbas-project.github.io/lolbas/Binaries/Mshta/'))]
        return []

    def _hit(self, event: TypedEvent, token: str, what: str, shape: str) -> Hit:
        return Hit("mshta_execution", f"mshta was run with {what}", self.lane, self.severity, self.attack,
                   [parsed_field(event, token)], content=f"mshta:{shape}")


class Rundll32Execution(WindowsProcessRule):
    id = "win.rundll32_proxy"
    version = '8'
    title = "rundll32 proxied execution (script protocol, remote DLL, or LSASS MiniDump)"
    assures_negative = False
    positive_only_reason = ("rundll32 and its target are read from argv; the same proxying can be done by other means, "
                            "so a window without a match proves nothing")
    severity, lane = "high", "high"
    attack = ("T1218.011", "T1059.007", "T1059.005", "T1003.001", "T1105")
    benign = ("Windows and third-party software calling rundll32 with a local system DLL and a real export",)
    next_checks = ("the DLL or URL named", "rundll32's network and file activity", "for a MiniDump, the written file")
    card: ClassVar[dict] = {
        "behavior": "rundll32.exe with an inline script protocol, a remote library or proxy-export target, a "
                    "comsvcs MiniDump request, an outside-system Control_RunDLL target, or a library path/search "
                    "operand that warrants investigation",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show what rundll32 was asked to load; positive-only. A comsvcs MiniDump shape is a "
                    "credential-access request, not proof a dump was written.",
        "benign_and_cost": "benign rundll32 calls name a local DLL and export; the flagged shapes are specific, so "
                           "cost is low",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the named DLL/URL; for MiniDump, the output file and the target process",
        "adds": "rundll32 proxy execution and the comsvcs MiniDump credential-dump shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.011, T1003.001; LOLBAS rundll32/comsvcs (reimplemented)",
        "lanes": "high for inline, remote-library, remote-proxy-target and MiniDump shapes; lead for local "
                 "proxy exports, writable operands, unresolved short paths and unknown bare libraries with a writable CWD",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is rundll32.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "rundll32.exe":
            return []
        argv = _command_argv(event)
        library, _entry, _args = _rundll_arguments(argv)
        for token in (library,):
            url = url_in(token)
            lowered = token.strip().strip('"').casefold()
            if lowered.startswith(("javascript:", "vbscript:")):
                return [Hit("rundll32_proxy", "rundll32 was run with an inline script protocol", self.lane,
                            self.severity, ("T1218.011", "T1059.007", "T1059.005"),
                            [parsed_field(event, token)], content="rundll32:script")]
            if url or _unc_path(lowered):
                return [Hit("rundll32_proxy", f"rundll32 was asked to load a remote DLL ({token.strip()})", self.lane,
                            self.severity, ("T1218.011", "T1105"), [parsed_field(event, token)],
                            content="rundll32:remote")]
        target = rundll32_target(argv)
        if target is not None:
            dll, entry = target
            if dll == "comsvcs" and (entry == "minidump" or is_ordinal(entry)):
                return [Hit("rundll32_comsvcs_minidump",
                            f"rundll32 was run with comsvcs.dll MiniDump (entry '{entry}'), the shape used to dump a "
                            f"process's memory", self.lane, self.severity, ("T1003.001", "T1218.011"),
                            [parsed_field(event, clip(" ".join(argv[1:])))], content="rundll32:comsvcs")]
        if hit := _proxy_export(event, argv):
            return [hit]
        if library and (hit := _writable_operand(
                event, library, "rundll32", "rundll32_writable", ("T1218.011",), dll_search=True)):
            return [hit]
        if (library and ntpath.splitext(library)[1].casefold() not in {'.dll', ''}
                and ntpath.basename(library).casefold() not in _SYSTEM_CPLS):
            return [Hit('rundll32_non_dll_request', f'rundll32 received a non-DLL library operand ({clip(library)})',
                        'lead', 'medium', ('T1218.011',), [parsed_field(event, library)],
                        content=f'rundll32:non-dll:{library}',
                        notes=('The operand is observed; successful loading or execution is not established.',
                               'Behavior source: https://lolbas-project.github.io/lolbas/Binaries/Rundll32/'))]
        return []


class Regsvr32Execution(WindowsProcessRule):
    id = "win.regsvr32_scriptlet"
    version = '7'
    title = "regsvr32 registered a remote or scriptlet payload (Squiblydoo)"
    assures_negative = False
    positive_only_reason = ("regsvr32's install flag and target are read from argv; a window without a match proves "
                            "nothing, as other binaries proxy execution the same way")
    severity, lane = "high", "high"
    attack = ("T1218.010", "T1059.005", "T1105")
    benign = ("installers registering a local COM DLL with regsvr32 and a local path",)
    next_checks = ("the scriptlet or URL named", "regsvr32's network connection and children")
    card: ClassVar[dict] = {
        "behavior": "regsvr32.exe with /i: naming a URL/UNC or .sct scriptlet, typically with /s and /n/u "
                    "(Squiblydoo)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the registration request; positive-only",
        "benign_and_cost": "benign regsvr32 names a local DLL; the remote/scriptlet shape is specific, cost low",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the named scriptlet/URL and regsvr32's network activity",
        "adds": "the regsvr32 scriptlet/Squiblydoo shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.010; LOLBAS regsvr32 (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is regsvr32.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "regsvr32.exe":
            return []
        argv = _command_argv(event)
        for token in argv[1:]:
            if token.casefold().startswith(("/i:", "-i:")):
                target = switch_value(token) or ""
                url = url_in(token)
                remote = bool(url) or is_remote_path(target)
                scriptlet = target.strip().strip('"').casefold().endswith(".sct")
                if remote or scriptlet:
                    what = "a remote target" if remote else "a scriptlet (.sct)"
                    return [Hit("regsvr32_scriptlet", f"regsvr32 was run with /i: naming {what} ({clip(target)})",
                                self.lane, self.severity, self.attack, [parsed_field(event, token)],
                                content=f"regsvr32:{'remote' if remote else 'sct'}")]
        # Non-ASCII dash spellings record an attempted registration request;
        # they are not normalized into a documented, successfully accepted flag.
        for token in argv[1:]:
            if token and token[0] in DASH_LIKE - {'-'} and token[1:3].casefold() == 'i:':
                target = token[3:].strip().strip('"')
                scriptlet = target.split('?', 1)[0].split('#', 1)[0].casefold().endswith('.sct')
                if is_remote_path(target) or scriptlet:
                    return [Hit('regsvr32_attempted_scriptlet',
                                f'regsvr32 arguments show attempted scriptlet registration ({clip(target)})',
                                'lead', 'medium', self.attack, [parsed_field(event, token)],
                                content=f'regsvr32:attempt:{token}',
                                notes=('A dash-like option spelling is observed; registration or acceptance by the OS is not established.',))]
        # regsvr32 accepts exactly these flags; other slash-prefixed tokens are operands.
        # https://learn.microsoft.com/windows-server/administration/windows-commands/regsvr32
        rest = [token for token in argv[1:] if token.casefold() not in {
            '/s', '/u', '/n', '/c', '/i', '-s', '-u', '-n', '-c', '-i'}
            and not token.casefold().startswith(('/i:', '-i:'))]
        for token in rest:
            if hit := _writable_operand(event, token, "regsvr32", "regsvr32_writable", self.attack, dll_search=True):
                return [hit]
        return []


class CertutilDownloadDecode(WindowsProcessRule):
    id = "win.certutil_download_decode"
    version = "5"
    title = "certutil used to download or decode a file"
    assures_negative = False
    positive_only_reason = ("certutil's download and decode flags are read from argv; a window without a match proves "
                            "nothing, and only a file or network event would show a payload was fetched or written")
    severity, lane = "high", "lead"
    attack = ("T1105", "T1140", "T1027")
    benign = ("certificate-management scripts that genuinely fetch a CRL or decode a certificate file",)
    next_checks = ("the URL or file named", "the output file certutil wrote", "certutil's network connection")
    card: ClassVar[dict] = {
        "behavior": "certutil.exe with -urlcache/-verifyctl (download) or -decode/-decodehex (decode)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the request; positive-only. 'certutil was run with -urlcache against a URL' is "
                    "not 'certutil downloaded a payload' unless a file or network event shows it.",
        "benign_and_cost": "legitimate CRL fetches and certificate decoding exist; lane is lead, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the output file and the network connection",
        "adds": "certutil download and decode shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1105, T1140; CISA LOTL guidance; LOLBAS certutil (reimplemented)",
        "lanes": "lead: certutil is dual-use and these flags have benign uses; merged per shape",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is certutil.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "certutil.exe":
            return []
        argv = _command_argv(event)
        names = {switch_name(token) for token in argv[1:] if token[:1] in "-/–—―"}
        hits = []
        if {"urlcache", "verifyctl"} & names:
            url = next((url_in(token) for token in argv[1:] if url_in(token)), None)
            what = f" against {url}" if url else ""
            hits.append(Hit("certutil_download", f"certutil was run with a URL-cache download flag{what}", self.lane,
                            self.severity, ("T1105",), [parsed_field(event, clip(" ".join(argv[1:])))],
                            content="certutil:download"))
        if {"decode", "decodehex"} & names:
            hits.append(Hit("certutil_decode", "certutil was run with a decode flag (file deobfuscation)", self.lane,
                            self.severity, ("T1140",), [parsed_field(event, clip(" ".join(argv[1:])))],
                            content="certutil:decode"))
        return hits


class BitsadminTransfer(WindowsProcessRule):
    id = "win.bitsadmin_transfer"
    version = "5"
    title = "bitsadmin created a transfer job"
    assures_negative = False
    positive_only_reason = ("bitsadmin's transfer verb and URL are read from argv; a window without a match proves "
                            "nothing, and BITS transfers can also be created through PowerShell or the COM API")
    severity, lane = "medium", "lead"
    attack = ("T1197", "T1105")
    benign = ("software distribution and update agents that use BITS for downloads",)
    next_checks = ("the URL and local path named", "the BITS client log and the written file")
    card: ClassVar[dict] = {
        "behavior": "bitsadmin.exe /transfer (or /addfile /create with a remote source)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the job request; positive-only",
        "benign_and_cost": "update agents use BITS; lane lead, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the destination path and the written file",
        "adds": "the bitsadmin transfer shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1197, T1105; LOLBAS bitsadmin (reimplemented)",
        "lanes": "lead: BITS is used by legitimate updaters",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is bitsadmin.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "bitsadmin.exe":
            return []
        argv = _command_argv(event)
        if has_switch(argv, "transfer", "addfile"):
            url = next((url_in(token) for token in argv[1:] if url_in(token)), None)
            what = f" ({url})" if url else ""
            return [Hit("bitsadmin_transfer", f"bitsadmin was run with a transfer verb{what}", self.lane,
                        self.severity, self.attack, [parsed_field(event, clip(" ".join(argv[1:])))],
                        content="bitsadmin:transfer")]
        return []


class CurlDownload(WindowsProcessRule):
    id = "win.curl_download_to_disk"
    version = "6"
    title = "curl.exe downloaded to a file"
    assures_negative = False
    positive_only_reason = ("curl and its output flag are read from argv; a window without a match proves nothing, as "
                            "a transfer can be done by many tools")
    severity, lane = "medium", "lead"
    attack = ("T1105",)
    benign = ("scripts and installers that use curl to fetch files from approved locations",)
    next_checks = ("the URL and output path", "the written file", "curl's network connection")
    card: ClassVar[dict] = {
        "behavior": "curl.exe given a URL and -o/-O/--output (writing the response to disk)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show a download request; positive-only",
        "benign_and_cost": "curl is widely used legitimately on modern Windows; lane lead, merged per shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the written file and its later execution",
        "adds": "the curl.exe download-to-disk shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1105; LOLBAS curl (reimplemented)",
        "lanes": "lead",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is curl.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "curl.exe":
            return []
        argv = _command_argv(event)
        if not any(url_in(token) for token in argv[1:]):
            return []
        # -o/-O/--output/--remote-name, or 'o'/'O' bundled into a grouped short flag (curl -sko file)
        writes = has_switch(argv, "o", "O", "output", "remote-name") or any(
            token.startswith("-") and not token.startswith("--") and ("o" in token[1:] or "O" in token[1:])
            for token in argv[1:]
        )
        if writes:
            return [Hit("curl_download", "curl was run to download a URL to a file", self.lane, self.severity,
                        self.attack, [parsed_field(event, clip(" ".join(argv[1:])))], content="curl:download")]
        return []


class ScriptHostRemoteOrWritable(WindowsProcessRule):
    id = "win.script_host_untrusted_script"
    version = "6"
    title = "wscript or cscript ran a script from a user-writable or remote location"
    assures_negative = False
    positive_only_reason = ("the script path is read from argv and a path can be renamed or relocated; a window "
                            "without a match proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1059.005", "T1059.007", "T1218", "T1216", "T1216.001", "T1216.002")
    benign = ("administrators running maintenance scripts from a per-user profile path",
              "software that stores and runs its own scripts under ProgramData")
    next_checks = ("the script file named", "the script host's network and child activity")
    card: ClassVar[dict] = {
        "behavior": "wscript.exe or cscript.exe with a writable/remote/short-form script path, any remote "
                    "script moniker argument (remote or local writable), or a sourced proxy script with a remote URL argument",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments name a script in an untrusted location; positive-only (the file may be renamed or "
                    "may not have run)",
        "benign_and_cost": "admin and vendor scripts run from profile/ProgramData paths; lane lead, merged per shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the script's content and what the host did next",
        "adds": "the wscript/cscript untrusted-location shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.005/.007, T1218; cross-cutting user-writable-path theme",
        "lanes": "high for remote script:/scriptlet: monikers; lead for local writable monikers, other path and proxy-URL shapes",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is "
                     "wscript.exe/cscript.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"wscript.exe", "cscript.exe"}:
            return []
        argv = _command_argv(event)
        scripts = operands(argv[1:])[:1]
        script = scripts[0] if scripts else "<unrecorded>"
        name = ntpath.basename(script).casefold()
        # Every argument can carry a moniker. Plain URL arguments are a lead only
        # with a named proxy script; ordinary script arguments do not become code.
        local_moniker = None
        for position, token in enumerate(argv[1:], 1):
            if not token.casefold().startswith(('script:', 'scriptlet:')):
                continue
            target = token.partition(':')[2]
            remote = is_remote_path(target)
            if remote or is_user_writable(target):
                hit = Hit("script_host_proxy", f"script host script '{clip(script)}' was given "
                            f"{'remote' if remote else 'local user-writable'} moniker "
                            f"'{clip(token)}' at argument {position} (argv position after the executable); "
                            "successful execution is not established", "high" if remote else "lead",
                            "high" if remote else "medium", self.attack,
                            [parsed_field(event, script), parsed_field(event, token)],
                            content=f"scripthost:moniker:{name}")
                if remote:
                    return [hit]
                if local_moniker is None:
                    local_moniker = hit
        if local_moniker is not None:
            return [local_moniker]
        if name in _PROXY_SCRIPTS:
            for position, token in enumerate(argv[1:], 1):
                if url_in(token) or is_remote_path(token) and '://' in token:
                    return [Hit("script_host_proxy", f"proxy script '{clip(script)}' was given remote URL "
                                f"'{clip(token)}' at argument {position} (argv position after the executable); "
                                "successful execution is not established", "lead", "medium", self.attack,
                                [parsed_field(event, script), parsed_field(event, token)],
                                content=f"scripthost:proxy-url:{name}",
                                notes=(f"Proxy-script source: {_PROXY_SCRIPTS[name]}",))]
        for token in scripts:
            if is_remote_path(token):
                where = "a remote URL" if '://' in token else "a UNC path"
                return [Hit("script_host_untrusted", f"a script host was given a script in {where} ({clip(token)})",
                            self.lane, self.severity, self.attack, [parsed_field(event, token)],
                            content="scripthost:untrusted")]
            if hit := _writable_operand(event, token, "a script host", "script_host_untrusted", self.attack):
                return [hit]
        return []


class MsiexecRemotePackage(WindowsProcessRule):
    id = "win.msiexec_remote_package"
    version = '7'
    title = "msiexec received a remote or writable package installation request"
    assures_negative = False
    positive_only_reason = ("the package source is read from argv; a window without a match proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1218.007", "T1105")
    benign = ("enterprise software deployment installing MSIs from an internal distribution server over HTTP/UNC",)
    next_checks = ("the package URL/UNC named", "msiexec's network connection and the installed files")
    card: ClassVar[dict] = {
        "behavior": "msiexec.exe receiving a remote package installation request or naming a writable local MSI",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show a remote install request; positive-only",
        "benign_and_cost": "software deployment commonly installs MSIs from internal servers; remote packages are high and writable local packages lead, merged per "
                           "shape, and internal distribution points are expected",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the package source and the files it installed",
        "adds": "the msiexec remote-package shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.007, T1105; LOLBAS msiexec (reimplemented)",
        "lanes": "high for a remote package, lead for a writable local MSI",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is msiexec.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "msiexec.exe":
            return []
        argv = _command_argv(event)
        # Bind each target to an install/package action; unrelated URL arguments
        # cannot establish a remote package source.
        packages = tuple(switch_operand(argv, ('i', 'package', 'a'), separators=(), short_attached=True))
        for token in packages:
            if is_remote_path(token):
                url = bool(re.match(r'(?i)^(?:https?|ftp)://', token))
                return [Hit('msiexec_remote', f'msiexec was asked to install a remote package ({clip(token)})',
                            'high' if url else 'lead', 'high' if url else 'medium', self.attack, [parsed_field(event, token)],
                            content=f'msiexec:remote:{token}',
                            notes=('A package installation was requested; successful installation is not established.',))]
        for token in packages:
            if token.casefold().endswith('.msi') and (hit := _writable_operand(
                    event, token, 'msiexec', 'msiexec_writable_package', ('T1218.007',))):
                return [hit]
        install = any(token and token[0] in DASH_LIKE | {'/'} and
                      re.match(r'(?i)^(?:i|package|a)(?:[:=]|$)', token[1:]) for token in argv[1:])
        remote = next((token for token in argv[1:] if is_remote_path(token) or url_in(token)), None)
        if install and remote:
            return [Hit('msiexec_unbound_request', f'msiexec recorded an attempted or unbound remote installation request ({clip(remote)})',
                        'lead', 'medium', self.attack, [parsed_field(event, remote)],
                        content=f'msiexec:unbound:{remote}',
                        notes=('An install switch and a remote token are recorded; the package operand and successful installation are not established.',))]
        return []


class CompilerProxyExecution(WindowsProcessRule):
    id = "win.dotnet_lolbin_proxy"
    version = '7'
    title = "A build, install or XML utility received proxy-execution arguments"
    assures_negative = False
    positive_only_reason = ("the LOLBin and its payload flag are read from argv; a window without a match proves "
                            "nothing, and these tools have legitimate build and install uses")
    severity, lane = "high", "lead"
    attack = ("T1218.004", "T1218.009", "T1127.001", "T1218.008", "T1218.003", "T1220")
    benign = (("genuine software builds (MSBuild on a developer or build host) and assembly installs (InstallUtil, "
               "Regasm, Regsvcs) during deployment"),)
    next_checks = ("the project, inf or assembly named", "the tool's network and child activity")
    card: ClassVar[dict] = {
        "behavior": "InstallUtil with /logfile= /LogToConsole=false /U, Regasm/Regsvcs with /U, MSBuild building an "
                    "inline-task project from a user-writable/remote path, odbcconf /a with a REGSVR action, or cmstp "
                    "with an .inf, or msxsl given XML/XSL operands in a user-writable path",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the proxy-execution shape; positive-only",
        "benign_and_cost": "build and deployment hosts use these legitimately, so lane is lead and repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the named project/assembly/inf and the tool's children",
        "adds": "the .NET/MSBuild/odbcconf/cmstp and msxsl proxy-execution shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.004/.009/.008/.003, T1127.001, T1220; "
                          "https://attack.mitre.org/techniques/T1220/; LOLBAS (reimplemented)",
        "lanes": "lead: common on build and deployment hosts",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is one of the "
                     "named .NET LOLBins",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _command_argv(event)
        rest = argv[1:]
        if name in {"installutil.exe"} and has_switch(rest, "u", "logfile", "logtoconsole"):
            return [self._hit(event, rest, "InstallUtil", "T1218.004", "installutil")]
        if name in {"regasm.exe", "regsvcs.exe"} and has_switch(rest, "u"):
            return [self._hit(event, rest, name.split(".")[0], "T1218.009", "regasm")]
        if name == "msbuild.exe":
            for token in operands(rest):
                if is_user_writable(token) or url_in(token) or is_remote_path(token):
                    return [self._hit(event, [token], "MSBuild (project from an untrusted path)",
                                      "T1127.001", "msbuild")]
        if name == "msxsl.exe":
            for token in operands(rest):
                if token.casefold().endswith((".xsl", ".xslt", ".xml")) and (hit := _writable_operand(
                        event, token, "msxsl", "msxsl_writable", ("T1220",))):
                    return [hit]
        if name == "odbcconf.exe" and any("regsvr" in token.casefold() for token in rest):
            return [self._hit(event, rest, "odbcconf (REGSVR action)", "T1218.008", "odbcconf")]
        if name == "cmstp.exe" and any(token.strip().strip('"').casefold().endswith(".inf") for token in rest):
            return [self._hit(event, rest, "cmstp (.inf)", "T1218.003", "cmstp")]
        return []

    def _hit(self, event: TypedEvent, rest: list[str], label: str, attack_id: str, shape: str) -> Hit:
        return Hit("dotnet_lolbin_proxy", f"{label} was run with a proxy-execution argument shape", self.lane,
                   self.severity, (attack_id, *self.attack[:0]), [parsed_field(event, clip(" ".join(rest)))],
                   content=f"dotnet:{shape}")


class PowerShellEncodedOrCradle(WindowsProcessRule):
    id = "win.powershell_encoded_or_cradle"
    version = "6"
    title = "PowerShell ran an encoded command or a download cradle"
    uses_parent = True
    parent_images = LureAppSpawnsCodeRunner.parent_images | frozenset({
        "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "sqlservr.exe",
    })
    assures_negative = False
    positive_only_reason = ("the command is read from PowerShell's argv and script text, which can be obfuscated or "
                            "built at run time; a window without a match proves nothing, and only decoded/observed "
                            "behaviour would show what ran")
    severity, lane = "high", "high"
    attack = ("T1059.001", "T1027.010", "T1105", "T1140")
    benign = ("management tooling and installers that legitimately pass -EncodedCommand",
              "administrators using Invoke-WebRequest to fetch files from approved internal servers")
    next_checks = ("the decoded command", "PowerShell's network connection and child processes",
                   "the 4104 script block, if script-block logging is on")
    card: ClassVar[dict] = {
        "behavior": "powershell.exe/pwsh.exe given -EncodedCommand (prefix-matched: -e/-en/-enc...), or whose command "
                    "or decoded text calls a download cmdlet (Invoke-WebRequest/-RestMethod, Start-BitsTransfer, "
                    "WebClient.Download*) optionally piped into Invoke-Expression",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line); the -EncodedCommand value is Base64 of "
                     "UTF-16LE, decoded here and labelled parsed",
        "fidelity": "the host arguments and parsed script show what PowerShell was asked to run; positive-only. A "
                    "download cmdlet in the text is 'a download was requested', not 'a payload was fetched'.",
        "benign_and_cost": "encoded commands and Invoke-WebRequest have legitimate uses; encoded-only is lead, and "
                           "repeats merge per shape so a fleet-wide management command is triaged once",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the decoded command, PowerShell's network connection, and the 4104 script block",
        "adds": "PowerShell encoded-command decoding and download-cradle detection by parsed tokens",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.001, T1027.010, T1105, T1140; the Microsoft PowerShell host "
                          "parameter reference; SigmaHQ encoded-command patterns (reimplemented, not copied)",
        "lanes": "encoded-only and bare downloads are lead; high requires a decoded cradle, offensive or AMSI call shape, or a lure/server parent",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is "
                     "powershell.exe/pwsh.exe",
    }

    def candidate_child(self, event: TypedEvent) -> bool:
        return image_name(event.get("process.executable_key"))[0] in {None, "powershell.exe", "pwsh.exe"}

    def _fleet_match(self, shape, group, *, final):
        match = super()._fleet_match(shape, group, final=final)
        if match is None or group.behavior != "powershell_encoded" or match.proposed_lane != "high":
            return match
        # A pid-resolved parent is separate evidence. Reuse the lineage's bounded
        # citation store for one representative, rather than storing parent bodies
        # in each fleet group or claiming a parent from an uncited child field.
        for event in match.events:
            if event.id in match.context_ids:
                continue
            for hit in self.judge(event):
                if hit.behavior != group.behavior or not hit.context:
                    continue
                seen = {item.id for item in match.events}
                match.events.extend(item for item in hit.context if item.id not in seen)
                match.context_ids.update(item.id for item in hit.context)
                match.raw_copies.update(hit.raw_copies)
                match.predicate = list(hit.predicate)
                return match
        return match

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"powershell.exe", "pwsh.exe"}:
            return []
        argv = _command_argv(event)
        call = parse_powershell(argv[1:])
        hits: list[Hit] = []
        parsed = read_script(call.script) if call.script is not None else None
        strong = bool(parsed and (parsed.commands & HIGH_TOOLS or amsi_bypass(parsed)
                                 or downloads(parsed) and runs_code(parsed)))
        parent_fields, parent_context, parent_raw = [], [], {}
        parent_note = ""
        try:
            parent = resolve_parent(event, self.lineage)
        except Undecided:
            parent = None
        if parent and parent.name in self.parent_images:
            strong = True
            parent_fields, parent_context, _how, parent_raw = parent_predicate(event, parent)
            parent_note = f"; recorded parent image '{parent.name}' supports the high lane"
        encoded_lane = "high" if strong else "lead"
        if call.source == "encodedcommand":
            origin = event.fields["process.command_line"].origin
            if call.script is not None:
                value = PredicateField(field="process.command_line", value=clip(call.script),
                                       origin=f"{origin}{PARSED_DECODED}")
                note = ("the command line is truncated before decoding; only a prefix was read"
                        if call.truncated else "")
                hits.append(Hit("powershell_encoded",
                                f"PowerShell was run with an encoded command; decoded: '{clip(call.script)}'{parent_note}",
                                encoded_lane, "high" if strong else "medium", ("T1059.001", "T1027.010"), [value, *parent_fields],
                                context=parent_context, raw_copies=parent_raw,
                                content="ps:encoded", parent_name=parent.name if parent else "",
                                notes=tuple(n for n in (note,) if n)))
            else:
                reason = call.decode_error or "no value followed -EncodedCommand"
                value = PredicateField(field="process.command_line",
                                       value=clip(str(call.switches.get("encodedcommand", ""))),
                                       origin=f"{origin}{PARSED}")
                hits.append(Hit("powershell_encoded",
                                f"PowerShell was run with -EncodedCommand but its value could not be decoded "
                                f"({reason}){parent_note}", encoded_lane, "high" if strong else "medium", ("T1059.001", "T1027.010"), [value, *parent_fields],
                                context=parent_context, raw_copies=parent_raw,
                                content="ps:encoded-bad", parent_name=parent.name if parent else ""))
        cradle = self._cradle(event, call)
        if cradle is not None:
            hits.append(cradle)
        return hits

    def _cradle(self, event: TypedEvent, call) -> Hit | None:
        if call.script is None:
            return None
        tokens = ps_tokens(call.script)
        download = None
        for token in tokens:
            if token.kind == "word" and token.text in _DOWNLOAD_WORDS:
                download = _DOWNLOAD_WORDS[token.text]
                break
            if token.kind == "member" and token.text in _DOWNLOAD_MEMBERS:
                download = _DOWNLOAD_MEMBERS[token.text]
                break
        if download is None:
            return None
        executes = runs_code(read_script(call.script))
        origin = event.fields["process.command_line"].origin
        value = PredicateField(field="process.command_line", value=clip(call.script),
                               origin=f"{origin}{PARSED}")
        lane = self.lane if executes else "lead"
        tail = " and a code-evaluation call" if executes else ""
        return Hit("powershell_cradle",
                   f"PowerShell script called {download}{tail}", lane, self.severity,
                   ("T1059.001", "T1105") + (("T1140",) if executes else ()), [value],
                   content=f"ps:cradle:{download}{'+eval' if executes else ''}")


WINDOWS_PROXY_PLAYBOOKS = [
    MshtaExecution, Rundll32Execution, Regsvr32Execution, CertutilDownloadDecode, BitsadminTransfer,
    CurlDownload, ScriptHostRemoteOrWritable, MsiexecRemotePackage, CompilerProxyExecution,
    PowerShellEncodedOrCradle,
]
