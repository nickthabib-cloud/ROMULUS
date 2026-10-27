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

from typing import ClassVar

from romulus.detect.base import PredicateField
from romulus.detect.windows_cmdline import (
    PARSED,
    PARSED_DECODED,
    has_switch,
    is_ordinal,
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
    parsed_field,
)
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


def _command_argv(event: TypedEvent) -> list[str]:
    argv = split_argv(str(event.get("process.command_line")))
    if not argv:
        raise Undecided("command_line", "the command line did not parse into any argument")
    return argv


class MshtaExecution(WindowsProcessRule):
    id = "win.mshta_remote_or_inline"
    version = "2"
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
            if lowered.startswith("\\\\"):
                return [self._hit(event, token, f"a UNC path ({token.strip()})", "mshta_unc")]
        return []

    def _hit(self, event: TypedEvent, token: str, what: str, shape: str) -> Hit:
        return Hit("mshta_execution", f"mshta was run with {what}", self.lane, self.severity, self.attack,
                   [parsed_field(event, token)], content=f"mshta:{shape}")


class Rundll32Execution(WindowsProcessRule):
    id = "win.rundll32_proxy"
    version = "3"
    title = "rundll32 proxied execution (script protocol, remote DLL, or LSASS MiniDump)"
    assures_negative = False
    positive_only_reason = ("rundll32 and its target are read from argv; the same proxying can be done by other means, "
                            "so a window without a match proves nothing")
    severity, lane = "high", "high"
    attack = ("T1218.011", "T1059.007", "T1059.005", "T1003.001")
    benign = ("Windows and third-party software calling rundll32 with a local system DLL and a real export",)
    next_checks = ("the DLL or URL named", "rundll32's network and file activity", "for a MiniDump, the written file")
    card: ClassVar[dict] = {
        "behavior": "rundll32.exe with a javascript:/vbscript: protocol, a UNC/URL DLL, or comsvcs.dll MiniDump "
                    "against a process id",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show what rundll32 was asked to load; positive-only. A comsvcs MiniDump shape is a "
                    "credential-access request, not proof a dump was written.",
        "benign_and_cost": "benign rundll32 calls name a local DLL and export; the flagged shapes are specific, so "
                           "cost is low",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the named DLL/URL; for MiniDump, the output file and the target process",
        "adds": "rundll32 proxy execution and the comsvcs MiniDump credential-dump shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.011, T1003.001; LOLBAS rundll32/comsvcs (reimplemented)",
        "lanes": "high; the comsvcs MiniDump shape is worded as a credential-access request",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is rundll32.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "rundll32.exe":
            return []
        argv = _command_argv(event)
        for token in argv[1:]:
            url = url_in(token)
            lowered = token.strip().strip('"').casefold()
            if lowered.startswith(("javascript:", "vbscript:")):
                return [Hit("rundll32_proxy", "rundll32 was run with an inline script protocol", self.lane,
                            self.severity, ("T1218.011", "T1059.007", "T1059.005"),
                            [parsed_field(event, token)], content="rundll32:script")]
            if url or lowered.startswith("\\\\"):
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
        return []


class Regsvr32Execution(WindowsProcessRule):
    id = "win.regsvr32_scriptlet"
    version = "2"
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
            if token.casefold().startswith(("/i:", "-i:", "–i:")):
                target = switch_value(token) or ""
                url = url_in(token)
                remote = bool(url) or target.strip().startswith("\\\\")
                scriptlet = target.strip().strip('"').casefold().endswith(".sct")
                if remote or scriptlet:
                    what = "a remote target" if remote else "a scriptlet (.sct)"
                    return [Hit("regsvr32_scriptlet", f"regsvr32 was run with /i: naming {what} ({clip(target)})",
                                self.lane, self.severity, self.attack, [parsed_field(event, token)],
                                content=f"regsvr32:{'remote' if remote else 'sct'}")]
        return []


class CertutilDownloadDecode(WindowsProcessRule):
    id = "win.certutil_download_decode"
    version = "2"
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
    version = "2"
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
    version = "3"
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
    version = "2"
    title = "wscript or cscript ran a script from a user-writable or remote location"
    assures_negative = False
    positive_only_reason = ("the script path is read from argv and a path can be renamed or relocated; a window "
                            "without a match proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1059.005", "T1059.007", "T1218")
    benign = ("administrators running maintenance scripts from a per-user profile path",
              "software that stores and runs its own scripts under ProgramData")
    next_checks = ("the script file named", "the script host's network and child activity")
    card: ClassVar[dict] = {
        "behavior": "wscript.exe or cscript.exe whose script-file operand is under a user-writable path "
                    "(Temp, AppData, Users, ProgramData, Downloads) or a UNC path",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments name a script in an untrusted location; positive-only (the file may be renamed or "
                    "may not have run)",
        "benign_and_cost": "admin and vendor scripts run from profile/ProgramData paths; lane lead, merged per shape",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the script's content and what the host did next",
        "adds": "the wscript/cscript untrusted-location shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.005/.007, T1218; cross-cutting user-writable-path theme",
        "lanes": "lead",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is "
                     "wscript.exe/cscript.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"wscript.exe", "cscript.exe"}:
            return []
        argv = _command_argv(event)
        for token in operands(argv[1:]):
            if is_user_writable(token) or url_in(token) or token.strip().strip('"').startswith("\\\\"):
                where = "a UNC path" if token.strip().strip('"').startswith("\\\\") else "a user-writable location"
                return [Hit("script_host_untrusted", f"a script host was given a script in {where} ({clip(token)})",
                            self.lane, self.severity, self.attack, [parsed_field(event, token)],
                            content="scripthost:untrusted")]
        return []


class MsiexecRemotePackage(WindowsProcessRule):
    id = "win.msiexec_remote_package"
    version = "2"
    title = "msiexec installed a package from a remote source"
    assures_negative = False
    positive_only_reason = ("the package source is read from argv; a window without a match proves nothing")
    severity, lane = "medium", "lead"
    attack = ("T1218.007", "T1105")
    benign = ("enterprise software deployment installing MSIs from an internal distribution server over HTTP/UNC",)
    next_checks = ("the package URL/UNC named", "msiexec's network connection and the installed files")
    card: ClassVar[dict] = {
        "behavior": "msiexec.exe installing (/i or /package or /a) a package named by an http(s) URL or UNC path",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show a remote install request; positive-only",
        "benign_and_cost": "software deployment commonly installs MSIs from internal servers; lane lead, merged per "
                           "shape, and internal distribution points are expected",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the package source and the files it installed",
        "adds": "the msiexec remote-package shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.007, T1105; LOLBAS msiexec (reimplemented)",
        "lanes": "lead",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is msiexec.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "msiexec.exe":
            return []
        argv = _command_argv(event)
        if not has_switch(argv, "i", "package", "a"):
            return []
        for token in argv[1:]:
            url = url_in(token)
            if url or token.strip().strip('"').startswith("\\\\"):
                return [Hit("msiexec_remote", f"msiexec was asked to install a remote package ({clip(token)})",
                            self.lane, self.severity, self.attack, [parsed_field(event, token)],
                            content="msiexec:remote")]
        return []


class CompilerProxyExecution(WindowsProcessRule):
    id = "win.dotnet_lolbin_proxy"
    version = "2"
    title = "a .NET LOLBin (InstallUtil, Regasm, Regsvcs, MSBuild, odbcconf, cmstp) proxied execution"
    assures_negative = False
    positive_only_reason = ("the LOLBin and its payload flag are read from argv; a window without a match proves "
                            "nothing, and these tools have legitimate build and install uses")
    severity, lane = "high", "lead"
    attack = ("T1218.004", "T1218.009", "T1127.001", "T1218.008", "T1218.003")
    benign = (("genuine software builds (MSBuild on a developer or build host) and assembly installs (InstallUtil, "
               "Regasm, Regsvcs) during deployment"),)
    next_checks = ("the project, inf or assembly named", "the tool's network and child activity")
    card: ClassVar[dict] = {
        "behavior": "InstallUtil with /logfile= /LogToConsole=false /U, Regasm/Regsvcs with /U, MSBuild building an "
                    "inline-task project from a user-writable/remote path, odbcconf /a with a REGSVR action, or cmstp "
                    "with an .inf",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the proxy-execution shape; positive-only",
        "benign_and_cost": "build and deployment hosts use these legitimately, so lane is lead and repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the named project/assembly/inf and the tool's children",
        "adds": "the .NET/MSBuild/odbcconf/cmstp proxy-execution shapes",
        "research_basis": "ATT&CK Enterprise 20.0 T1218.004/.009/.008/.003, T1127.001; LOLBAS (reimplemented)",
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
                if is_user_writable(token) or url_in(token) or token.strip().strip('"').startswith("\\\\"):
                    return [self._hit(event, [token], "MSBuild (project from an untrusted path)",
                                      "T1127.001", "msbuild")]
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
    version = "2"
    title = "PowerShell ran an encoded command or a download cradle"
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
        "benign_and_cost": "encoded commands and Invoke-WebRequest have legitimate uses; lane high for encoded, and "
                           "repeats merge per shape so a fleet-wide management command is triaged once",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the decoded command, PowerShell's network connection, and the 4104 script block",
        "adds": "PowerShell encoded-command decoding and download-cradle detection by parsed tokens",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.001, T1027.010, T1105, T1140; the Microsoft PowerShell host "
                          "parameter reference; SigmaHQ encoded-command patterns (reimplemented, not copied)",
        "lanes": "high for an encoded command or a cradle piped to Invoke-Expression; a bare download cmdlet is lead",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is "
                     "powershell.exe/pwsh.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"powershell.exe", "pwsh.exe"}:
            return []
        argv = _command_argv(event)
        call = parse_powershell(argv[1:])
        hits: list[Hit] = []
        if call.source == "encodedcommand":
            origin = event.fields["process.command_line"].origin
            if call.script is not None:
                value = PredicateField(field="process.command_line", value=clip(call.script),
                                       origin=f"{origin}{PARSED_DECODED}")
                note = ("the command line is truncated before decoding; only a prefix was read"
                        if call.truncated else "")
                hits.append(Hit("powershell_encoded",
                                f"PowerShell was run with an encoded command; decoded: '{clip(call.script)}'",
                                self.lane, self.severity, ("T1059.001", "T1027.010"), [value],
                                content="ps:encoded", notes=tuple(n for n in (note,) if n)))
            else:
                reason = call.decode_error or "no value followed -EncodedCommand"
                value = PredicateField(field="process.command_line",
                                       value=clip(str(call.switches.get("encodedcommand", ""))),
                                       origin=f"{origin}{PARSED}")
                hits.append(Hit("powershell_encoded",
                                f"PowerShell was run with -EncodedCommand but its value could not be decoded "
                                f"({reason})", self.lane, self.severity, ("T1059.001", "T1027.010"), [value],
                                content="ps:encoded-bad"))
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
        executes = any(token.kind == "word" and token.text in _EXEC_WORDS for token in tokens)
        origin = event.fields["process.command_line"].origin
        value = PredicateField(field="process.command_line", value=clip(call.script),
                               origin=f"{origin}{PARSED}")
        lane = self.lane if executes else "lead"
        tail = " and piped into Invoke-Expression" if executes else ""
        return Hit("powershell_cradle",
                   f"PowerShell script called {download}{tail} (a download cradle)", lane, self.severity,
                   ("T1059.001", "T1105") + (("T1140",) if executes else ()), [value],
                   content=f"ps:cradle:{download}{'+iex' if executes else ''}")


WINDOWS_PROXY_PLAYBOOKS = [
    MshtaExecution, Rundll32Execution, Regsvr32Execution, CertutilDownloadDecode, BitsadminTransfer,
    CurlDownload, ScriptHostRemoteOrWritable, MsiexecRemotePackage, CompilerProxyExecution,
    PowerShellEncodedOrCradle,
]
