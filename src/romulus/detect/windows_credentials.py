"""Credential-store access recognised from command-line tokens (positive-only).

Each rule reads the argument tokens of a known tool with that tool's grammar and claims only that the tool was run
with those arguments. A memory dump, a registry-hive copy or a shadow-copy read leaves its proof in a file or process
event, not in the launching command line, so these rules are positive-only: a quiet window proves nothing,
and the same ends can be reached by tools and arguments the list does not name.

Shapes: comsvcs.dll MiniDump through rundll32 (covered by win.rundll32_proxy and cross-referenced here), procdump
against lsass, `reg save` of the SAM/SYSTEM/SECURITY hives, `ntdsutil ... ifm` or `create full`, `esentutl` copies of
ntds.dit or a hive (often from a shadow-copy path), and `vssadmin create shadow` / `diskshadow` scripts that stage a
shadow copy a later read can harvest.
"""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.windows_cmdline import (
    has_switch,
    operands,
    split_argv,
    switch_name,
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

_HIVES = ("sam", "system", "security")


def _argv(event: TypedEvent) -> list[str]:
    argv = split_argv(str(event.get("process.command_line")))
    if not argv:
        raise Undecided("command_line", "the command line did not parse into any argument")
    return argv


def _names_hive(token: str) -> bool:
    last = token.strip().strip('"').replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    return last in _HIVES


class ProcdumpLsass(WindowsProcessRule):
    id = "win.procdump_lsass"
    version = "1"
    title = "procdump was aimed at LSASS"
    assures_negative = False
    positive_only_reason = ("procdump and its target are read from argv; a window without a match proves nothing, and "
                            "LSASS memory can be dumped by many tools and APIs")
    severity, lane = "high", "high"
    attack = ("T1003.001",)
    benign = ("a support engineer capturing an LSASS dump for a crash investigation (rare; should be expected)",)
    next_checks = ("the output dump file procdump wrote", "the process that then read or moved the dump",
                   "Sysmon 10 LSASS access, if process-access logging is on")
    card: ClassVar[dict] = {
        "behavior": "procdump(64).exe whose operand names lsass (by name or pid-target flag)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show procdump was aimed at LSASS; positive-only (the dump may have failed or been "
                    "blocked)",
        "benign_and_cost": "legitimate crash captures are rare and should be known; lane high, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the written dump file and what read it",
        "adds": "the procdump-against-LSASS shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1003.001; Sysinternals procdump reference; LOLBAS (reimplemented)",
        "lanes": "high: aiming procdump at LSASS is a classic credential-dump step",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is procdump",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"procdump.exe", "procdump64.exe"}:
            return []
        argv = _argv(event)
        if any("lsass" in token.casefold() for token in argv[1:]):
            return [Hit("procdump_lsass", "procdump was run with LSASS as its target", self.lane, self.severity,
                        self.attack, [parsed_field(event, clip(" ".join(argv[1:])))], shape="procdump:lsass")]
        return []


class RegSaveHive(WindowsProcessRule):
    id = "win.reg_save_cred_hive"
    version = "1"
    title = "reg.exe saved a credential registry hive (SAM, SYSTEM or SECURITY)"
    assures_negative = False
    positive_only_reason = ("the hive and verb are read from reg.exe argv; a window without a match proves nothing, "
                            "and hives can also be copied through shadow copies or the registry API")
    severity, lane = "high", "high"
    attack = ("T1003.002", "T1003.004")
    benign = ("backup or migration tooling exporting hives to a known staging path (should be expected)",)
    next_checks = ("the output file reg.exe wrote", "the process that read or exfiltrated the saved hive")
    card: ClassVar[dict] = {
        "behavior": "reg.exe save (or export) of HKLM\\SAM, HKLM\\SYSTEM or HKLM\\SECURITY",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show the save request for a credential hive; positive-only",
        "benign_and_cost": "legitimate hive backups are rare and known; lane high, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the saved file and what read it",
        "adds": "the reg-save-of-credential-hive shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1003.002, T1003.004; CISA LOTL guidance (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is reg.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] not in {"reg.exe", "reg1.exe"}:
            return []
        argv = _argv(event)
        if not has_switch(argv, "save", "export") and not any(
                token.casefold() in {"save", "export"} for token in argv[1:2]):
            return []
        for token in argv[1:]:
            parts = token.casefold().replace("/", "\\").split("\\")
            if parts and parts[0] in {"hklm", "hkey_local_machine"} and len(parts) >= 2 and parts[1] in _HIVES:
                return [Hit("reg_save_hive", f"reg.exe was run to save the {parts[1].upper()} registry hive",
                            self.lane, self.severity, self.attack, [parsed_field(event, clip(" ".join(argv[1:])))],
                            shape=f"reg:save:{parts[1]}")]
        return []


class NtdsutilExtract(WindowsProcessRule):
    id = "win.ntdsutil_ifm"
    version = "1"
    title = "ntdsutil was used to create an Active Directory database copy (IFM)"
    assures_negative = False
    positive_only_reason = ("the ntdsutil sub-commands are read from argv; a window without a match proves nothing, "
                            "and NTDS.dit can also be copied through other tools and shadow copies")
    severity, lane = "high", "high"
    attack = ("T1003.003",)
    benign = (("a domain administrator creating an IFM media set for a new domain controller (should be expected on a "
               "DC, and only there)"),)
    next_checks = ("the output directory the snapshot was written to", "what read or moved the ntds.dit copy")
    card: ClassVar[dict] = {
        "behavior": "ntdsutil.exe with an 'ifm' or 'create full'/'activate instance ntds' ... snapshot sequence",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show an AD-database copy request; positive-only",
        "benign_and_cost": "legitimate only on a DC, during promotion; lane high, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the snapshot directory and what read ntds.dit",
        "adds": "the ntdsutil IFM / NTDS copy shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1003.003; Microsoft ntdsutil reference (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is ntdsutil.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "ntdsutil.exe":
            return []
        argv = _argv(event)
        lowered = [token.casefold() for token in argv[1:]]
        if "ifm" in lowered or ("create" in lowered and "full" in lowered) or any(
                token.casefold().startswith("ac i ntds") for token in argv[1:]):
            return [Hit("ntdsutil_ifm", "ntdsutil was run with an IFM / NTDS snapshot sequence", self.lane,
                        self.severity, self.attack, [parsed_field(event, clip(" ".join(argv[1:])))],
                        shape="ntdsutil:ifm")]
        return []


class EsentutlCopy(WindowsProcessRule):
    id = "win.esentutl_credential_copy"
    version = "1"
    title = "esentutl copied a credential database or hive, often from a shadow copy"
    assures_negative = False
    positive_only_reason = ("the source and verb are read from esentutl argv; a window without a match proves nothing")
    severity, lane = "high", "high"
    attack = ("T1003.003", "T1003.002", "T1006")
    benign = (("database maintenance on an application's own ESE database (names the app's file, not ntds.dit or a "
               "hive)"),)
    next_checks = ("the source and destination paths", "the written copy and what read it")
    card: ClassVar[dict] = {
        "behavior": "esentutl.exe with /y (or /vss) copying ntds.dit or a SAM/SYSTEM/SECURITY hive, often from a "
                    "\\\\?\\GLOBALROOT shadow-copy path",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show a copy of a credential database; positive-only",
        "benign_and_cost": "benign esentutl names an application's own ESE file; this shape names ntds.dit or a hive, "
                           "so cost is low",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the destination copy and what read it",
        "adds": "the esentutl credential-copy shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1003.003/.002, T1006; LOLBAS esentutl (reimplemented)",
        "lanes": "high",
        "retrieval": "the sweep retrieves every process-creation record; this reads those whose image is esentutl.exe",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "esentutl.exe":
            return []
        argv = _argv(event)
        names = {switch_name(token) for token in argv[1:] if token[:1] in "-/–—―"}
        if not ({"y", "vss"} & names):
            return []
        for token in operands(argv[1:]) + argv[1:]:
            lowered = token.casefold()
            if "ntds.dit" in lowered or _names_hive(token) or "globalroot" in lowered:
                return [Hit("esentutl_copy", "esentutl was run to copy a credential database or hive", self.lane,
                            self.severity, self.attack, [parsed_field(event, clip(" ".join(argv[1:])))],
                            shape="esentutl:copy")]
        return []


class ShadowCopyForHarvest(WindowsProcessRule):
    id = "win.shadow_copy_create_for_harvest"
    version = "1"
    title = "a shadow copy was created by a tool used to harvest NTDS or hives"
    assures_negative = False
    positive_only_reason = ("the create-shadow request is read from argv; a window without a match proves nothing, "
                            "and creating a shadow copy is itself a legitimate backup operation")
    severity, lane = "medium", "lead"
    attack = ("T1003.003", "T1006")
    benign = ("backup software and administrators creating volume shadow copies as part of normal backup",)
    next_checks = ("a later read from the shadow-copy device path (esentutl, copy, a hive save)",
                   "whether this host runs a backup product that owns shadow-copy creation")
    card: ClassVar[dict] = {
        "behavior": "vssadmin create shadow, wmic shadowcopy call create, or a diskshadow script that creates a "
                    "shadow copy (staging for a later NTDS/hive read)",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line)",
        "fidelity": "the arguments show a shadow copy was requested; this is routine for backups, so it is a lead "
                    "until a read from the shadow path follows. Positive-only.",
        "benign_and_cost": "backup is the common cause, so lane is lead and repeats merge; the discriminating pivot "
                           "is a read from the shadow path",
        "query_cost": "none beyond the sweep",
        "next_pivot": "a read from the shadow-copy device path",
        "adds": "the shadow-copy-creation staging shape (complements the deletion rule)",
        "research_basis": "ATT&CK Enterprise 20.0 T1003.003, T1006; CISA LOTL guidance (reimplemented)",
        "lanes": "lead: shadow-copy creation is a normal backup action",
        "retrieval": "the sweep retrieves every process-creation record; this reads vssadmin/wmic/diskshadow records",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        name = image_name(event.get("process.executable_key"))[0]
        argv = _argv(event)
        lowered = [token.casefold() for token in argv[1:]]
        if name == "vssadmin.exe" and "create" in lowered and "shadow" in lowered:
            return [self._hit(event, argv, "vssadmin create shadow", "vssadmin")]
        if name == "wmic.exe" and "shadowcopy" in lowered and "create" in lowered:
            return [self._hit(event, argv, "wmic shadowcopy call create", "wmic")]
        if name == "diskshadow.exe" and has_switch(argv, "s"):
            return [self._hit(event, argv, "diskshadow with a script file", "diskshadow")]
        return []

    def _hit(self, event: TypedEvent, argv: list[str], label: str, shape: str) -> Hit:
        return Hit("shadow_copy_create", f"{label} was run (a shadow copy was requested; a later read would harvest "
                                         f"NTDS or a hive)", self.lane, self.severity, self.attack,
                   [parsed_field(event, clip(" ".join(argv[1:])))], shape=f"shadow:{shape}")


WINDOWS_CREDENTIAL_PLAYBOOKS = [
    ProcdumpLsass, RegSaveHive, NtdsutilExtract, EsentutlCopy, ShadowCopyForHarvest,
]
