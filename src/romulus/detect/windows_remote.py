"""Remote-execution traces on the target host.

When a remote tool runs a command on a host, the child process carries a recognisable parent: WMI's provider
(wmiprvse.exe), WinRM/PowerShell Remoting (wsmprovhost.exe), legacy WinRS (winrshost.exe), a DCOM-activated server
(mmc.exe or an Office application started with -Embedding), or a PsExec-style service (PSEXESVC.exe or a service
binary under services.exe). The parent/child image shape is OS-recorded. ROMULUS never asserts absence, so these
rules are positive-only: a window without the shape is not evidence that none occurred.
"""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.windows_cmdline import is_remote_path, parse_cmd_payload, split_argv
from romulus.detect.windows_common import (
    SPAWNED_CODE_RUNNERS,
    Hit,
    ParentImage,
    Undecided,
    WindowsProcessRule,
    clip,
    image_name,
    parent_predicate,
    parsed_field,
    resolve_parent,
)
from romulus.evidence.typed import TypedEvent

# Parent images that mean "this child was started by a remote-execution mechanism", and what each one is.
_REMOTE_PARENTS = {
    "wmiprvse.exe": ("WMI (the WMI provider host)", "T1047"),
    "wsmprovhost.exe": ("WinRM / PowerShell Remoting", "T1021.006"),
    "winrshost.exe": ("WinRS (legacy WinRM remote shell)", "T1021.006"),
    "psexesvc.exe": ("a PsExec-style service", "T1569.002"),
    "paexec.exe": ("a PAExec service", "T1569.002"),
    "csexecsvc.exe": ("a CSExec service", "T1569.002"),
}


class RemoteExecutionParent(WindowsProcessRule):
    id = "win.remote_execution_child"
    version = "6"
    title = "a shell, script host or LOLBin was started by a remote-execution service"
    uses_parent = True
    parent_images = frozenset(_REMOTE_PARENTS)
    reads_command_line = False
    severity, lane = "high", "high"
    attack = ("T1047", "T1021.006", "T1569.002", "T1059")
    benign = (
        "approved remote administration (an admin running commands via WMI, WinRM or PsExec from a jump host)",
        "monitoring and inventory agents that execute probes through WMI",
        "configuration-management tooling (for example remote PowerShell) applying changes",
    )
    next_checks = (
        "what the remote-started process did (its children, network and file activity)",
        "the source host of the remote session (the 4624 type 3 logon that preceded it)",
        "whether this source and account normally administer this host",
    )
    card: ClassVar[dict] = {
        "behavior": "a process whose image is a shell, script host or signed proxy-execution binary and whose parent "
                    "image is wmiprvse.exe, wsmprovhost.exe, winrshost.exe, or a PsExec-style service "
                    "(PSEXESVC/PAExec/CSExec)",
        "telemetry": "Sysmon 1 (process.parent.executable_key typed). Security 4688 (parent resolved from its own "
                     "4688 record through the fenced-pid lineage). Both OS-recorded.",
        "fidelity": "direct action: the child was created by that remote-execution parent (images OS-recorded). It "
                    "does not say whether the remote session was authorised; the next pivot is the source and "
                    "account.",
        "benign_and_cost": "legitimate remote administration produces this shape, so cost depends on the "
                           "environment; repeats merge into one fleet finding so routine management is triaged once, "
                           "and the discriminating pivot is the source host and account.",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the 4624 type 3/10 logon that preceded the child, and the source host",
        "adds": "the first Windows remote-execution-trace rule (WMI/WinRM/PsExec parentage)",
        "research_basis": "ATT&CK Enterprise 20.0 T1047, T1021.006, T1569.002, T1059; Impacket and PsExec procedure "
                          "artifacts (behaviour, reimplemented)",
        "lanes": "high: remote execution is a lateral-movement step; merged fleet repeats keep the lane. Severity "
                 "high because, if adverse, this is remote code execution on the host.",
        "limits": "when a Security 4688 child names no parent image, its parent is resolved by process id and the finding is published as soon as that is decided. If the only termination of the parent pid that falls between parent and child is recorded in another stream that the sweep reads later (a Sysmon 5 record on a different target), the outcome depends on target order: read first, the finding is published and then revised in place to a lead when the termination arrives; read second, the child is undecided and no finding is published. Findings are never deleted, so the two orders end differently in this case only. A merged fleet finding takes out a record whose parent a later record withdrew, says how many it took out, and is lowered to a lead when no recurrence remains (each remaining record keeps its own finding).",
        "retrieval": "the sweep retrieves every Windows process-creation record; this reads those whose image is a "
                     "code runner (a provable subset).",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        child_name, why = image_name(event.get("process.executable_key"))
        if child_name is None:
            raise Undecided("image", f"the child image cannot be identified: {why}")
        if child_name not in SPAWNED_CODE_RUNNERS:
            return []
        parent = resolve_parent(event, self.lineage)
        mechanism = _REMOTE_PARENTS.get(parent.name)
        if mechanism is None:
            return []
        label, attack_id = mechanism
        predicate, context, how, raw = parent_predicate(event, parent)
        return [Hit(
            behavior="remote_execution_child",
            text=f"the code runner '{child_name}' was started by {label} (parent resolved from {how})",
            lane=self.lane,
            severity=self.severity,
            attack=(attack_id, "T1059"),
            predicate=predicate,
            content=f"{parent.name}>{child_name}",
            common=f"{label} starting '{child_name}'",
            context=context,
            raw_copies=raw,
            parent_name=parent.name,
        )]


class DcomActivatedChild(WindowsProcessRule):
    id = "win.dcom_activated_child"
    version = "6"
    title = "a shell or script host was started by a DCOM-activated application"
    uses_parent = True
    reads_command_line = False
    severity, lane = "high", "lead"
    attack = ("T1021.003", "T1559.001", "T1059")
    benign = (
        "legitimate DCOM/COM automation (an application embedding Office to generate documents)",
        "MMC snap-ins launched by management tooling",
    )
    next_checks = (
        "the source host that activated the DCOM object",
        "what the started shell or script host then did",
    )
    card: ClassVar[dict] = {
        "behavior": "a process whose image is a shell or script host and whose parent image is mmc.exe or an Office "
                    "application (winword/excel/powerpnt/outlook/mspub/visio) started with -Embedding",
        "telemetry": "Sysmon 1 (parent image typed). Security 4688 does not record the parent's own command line "
                     "today, so the -Embedding marker needs the parent's record; where only the parent image is "
                     "resolved (4688), the rule states that the -Embedding marker could not be confirmed and the "
                     "record is partial.",
        "fidelity": "direct action: the child was created by that parent; the -Embedding marker indicates DCOM/COM "
                    "activation. Not every DCOM activation is malicious, so lane is lead.",
        "benign_and_cost": "COM automation is common, so lane is lead and repeats merge; the discriminating pivot is "
                           "the activating source host.",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the source host of the DCOM activation and the child's activity",
        "adds": "the DCOM lateral-movement parentage shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1021.003, T1559.001, T1059; DCOM lateral-movement research "
                          "(behaviour, reimplemented)",
        "lanes": "lead: DCOM-activated shells are suspicious but legitimate COM automation exists; merged per shape.",
        "limits": "when a Security 4688 child names no parent image, its parent is resolved by process id and the finding is published as soon as that is decided. If the only termination of the parent pid that falls between parent and child is recorded in another stream that the sweep reads later (a Sysmon 5 record on a different target), the outcome depends on target order: read first, the finding is published and then revised in place to a lead when the termination arrives; read second, the child is undecided and no finding is published. Findings are never deleted, so the two orders end differently in this case only. A merged fleet finding takes out a record whose parent a later record withdrew, says how many it took out, and is lowered to a lead when no recurrence remains (each remaining record keeps its own finding).",
        "retrieval": "the sweep retrieves every Windows process-creation record; this reads those whose image is a "
                     "shell or script host (a provable subset).",
    }
    _DCOM_PARENTS = frozenset({
        "mmc.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "visio.exe",
    })
    parent_images = _DCOM_PARENTS

    def judge(self, event: TypedEvent) -> list[Hit]:
        child_name, why = image_name(event.get("process.executable_key"))
        if child_name is None:
            raise Undecided("image", f"the child image cannot be identified: {why}")
        if child_name not in SPAWNED_CODE_RUNNERS:
            return []
        parent = resolve_parent(event, self.lineage)
        if parent.name not in self._DCOM_PARENTS:
            return []
        predicate, context, _how, raw = parent_predicate(event, parent)
        embedding = ""
        if parent.resolved_by == "record":
            parent_command = event.get("process.parent.command_line")
            if parent_command is not None:
                tokens = [token.casefold() for token in split_argv(str(parent_command))]
                embedding = " started with -Embedding" if "-embedding" in tokens or "/embedding" in tokens else ""
                notes: tuple[str, ...] = ()
            else:
                notes = (("the parent's command line is not recorded, so -Embedding (DCOM activation) could not be "
                          "confirmed"),)
        else:
            notes = (("the parent was resolved by process id (Security 4688 records no parent command line), so "
                      "-Embedding (DCOM activation) could not be confirmed"),)
        return [Hit(
            behavior="dcom_activated_child",
            text=f"the code runner '{child_name}' was started by '{parent.name}'{embedding}",
            lane=self.lane,
            severity=self.severity,
            attack=self.attack,
            predicate=predicate,
            content=f"dcom:{parent.name}>{child_name}",
            common=f"'{parent.name}' starting '{child_name}' (DCOM)",
            notes=notes,
            context=context,
            raw_copies=raw,
            parent_name=parent.name,
        )]


class ServiceChildToAdminShare(WindowsProcessRule):
    id = "win.service_child_output_to_admin_share"
    version = "6"
    title = "a service-hosted command sent its output to an admin share (Impacket smbexec/atexec)"
    reads_command_line = True
    uses_parent = True
    severity, lane = "high", "high"
    attack = ("T1021.002", "T1569.002", "T1059.003")
    benign = ("administrative scripts that write output to a share, where that is the known workflow",)
    next_checks = ("the share and file written", "the source host of the service session")
    card: ClassVar[dict] = {
        "behavior": "cmd.exe /c started by services.exe (or a PsExec-style service) whose payload redirects output "
                    "to a UNC admin share (\\\\host\\ADMIN$, C$, IPC$), the Impacket/PsExec remote-command shape",
        "telemetry": "Sysmon 1 or Security 4688 (process.command_line); parent resolved from Sysmon 1 image or the "
                     "fenced-pid lineage",
        "fidelity": "the cmd payload's redirection shows output was sent to a share; positive-only (the redirection "
                    "is the recognised shape, not proof the command succeeded)",
        "benign_and_cost": "rare outside admin automation; lane high, repeats merge",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the written file on the share and the session's source host",
        "adds": "the service-command-to-admin-share (Impacket smbexec/atexec) shape",
        "research_basis": "ATT&CK Enterprise 20.0 T1021.002, T1569.002, T1059.003; Impacket smbexec/atexec artifacts "
                          "(behaviour, reimplemented)",
        "lanes": "high",
        "limits": "when a Security 4688 child names no parent image, its parent is resolved by process id and the finding is published as soon as that is decided. If the only termination of the parent pid that falls between parent and child is recorded in another stream that the sweep reads later (a Sysmon 5 record on a different target), the outcome depends on target order: read first, the finding is published and then revised in place to a lead when the termination arrives; read second, the child is undecided and no finding is published. Findings are never deleted, so the two orders end differently in this case only. A merged fleet finding takes out a record whose parent a later record withdrew, says how many it took out, and is lowered to a lead when no recurrence remains (each remaining record keeps its own finding).",
        "retrieval": "the sweep retrieves every process-creation record; this reads cmd.exe records with a "
                     "service-process parent",
    }
    _SERVICE_PARENTS = frozenset({"services.exe", "psexesvc.exe", "paexec.exe", "csexecsvc.exe"})
    parent_images = _SERVICE_PARENTS
    _ADMIN_SHARES = ("admin$", "c$", "ipc$")

    @classmethod
    def _admin_share(cls, target: object) -> str | None:
        """The `\\\\host\\ADMIN$` (or C$/IPC$) share a UNC path names, or None."""
        text = str(target or "")
        if not is_remote_path(text):
            return None
        parts = text.strip().strip('"').replace("/", "\\").lstrip("\\").split("\\")
        if len(parts) >= 2 and parts[1].casefold() in cls._ADMIN_SHARES:
            return f"\\\\{parts[0]}\\{parts[1]}"
        return None

    def judge(self, event: TypedEvent) -> list[Hit]:
        if image_name(event.get("process.executable_key"))[0] != "cmd.exe":
            return []
        from romulus.detect.windows_cmdline import cmd_payload
        command = str(event.get("process.command_line"))
        payload = cmd_payload(command)
        if payload is None:
            return []
        try:
            parent = resolve_parent(event, self.lineage)
        except Undecided:
            parent = None
        if parent is not None and parent.name not in self._SERVICE_PARENTS:
            return []
        who = (f"a cmd process started by '{parent.name}'" if parent is not None
               else "a cmd process (its parent process could not be resolved, so this finding is limited to the "
                    "recorded redirection)")
        commands = parse_cmd_payload(payload)
        stages_bat = any(str(target).strip().strip('"').casefold().endswith(".bat")
                         for cmd in commands for _op, target in cmd.redirects)
        for cmd in commands:
            # atexec/wmiexec: the command redirects its output straight to an admin share
            for _operator, target in cmd.redirects:
                share = self._admin_share(target)
                if share is not None:
                    return [self._hit(event, command, f"{who} redirected output to the admin share {share}",
                                      f"direct:{share.casefold()}", parent)]
            # smbexec: `echo <cmd> ^> \\host\C$\__output 2^>^&1 > %TEMP%\execute.bat & ... execute.bat & del ...`
            if cmd.argv and cmd.argv[0].casefold() == "echo" and stages_bat:
                for token in cmd.argv[1:]:
                    share = self._admin_share(token)
                    if share is not None:
                        return [self._hit(
                            event, command,
                            f"{who} staged a batch file that writes command output to the admin share {share} "
                            f"(the Impacket smbexec shape)", f"smbexec:{share.casefold()}", parent)]
        return []

    def _hit(self, event: TypedEvent, command: str, text: str, content: str, parent: ParentImage | None) -> Hit:
        """The finding; a resolved parent is part of its predicate and cited (its creation record when resolved by
        process id), so a later record that withdraws that parent revises the finding."""
        predicate = [parsed_field(event, clip(command))]
        context: list[TypedEvent] = []
        raw: dict = {}
        if parent is not None:
            parent_fields, context, _how, raw = parent_predicate(event, parent)
            predicate += parent_fields[1:]                 # the image field is not this rule's evidence
        return Hit("service_output_to_share", text, self.lane, self.severity, self.attack, predicate,
                   content=content, common="a service-hosted cmd sending output to an admin share",
                   context=context, raw_copies=raw, parent_name=parent.name if parent is not None else "")


WINDOWS_REMOTE_PLAYBOOKS = [RemoteExecutionParent, DcomActivatedChild, ServiceChildToAdminShare]
