"""A document, mail, browser or reader application spawned a shell, script host or LOLBin.

The behaviour: a process whose image is a productivity, mail, browser or PDF application created a child whose image
is a command shell, PowerShell, a script host or one of the signed binaries most used to proxy execution. This is the
shape phishing and drive-by chains share: the lure opens in Word, Outlook or a browser, and that process starts the
code runner. It keys on the OS-recorded parent and child image names, so it survives a renamed payload and reads no
command-line text; a window with no such pair, where process creation is inventoried and its collection is attested
for the site, is a complete negative.

When Sysmon 1 records the parent image, the pair is read from one record. When only Security 4688 is collected, the
parent image is not a typed field today: the parent is resolved from its own 4688 record through the shared pid
lineage (fenced by process termination and boot). If neither gives the parent image, the record is not judged
(partial), never a clean no-match.
"""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.windows_common import (
    SPAWNED_CODE_RUNNERS,
    Hit,
    Undecided,
    WindowsProcessRule,
    image_name,
    resolve_parent,
    typed_field,
)
from romulus.evidence.typed import TypedEvent

# Applications that open attacker-supplied content and have no routine reason to start a shell or LOLBin.
_OFFICE = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe",
    "visio.exe", "winproj.exe", "eqnedt32.exe", "wordpad.exe",
})
_BROWSERS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "vivaldi.exe",
})
_READERS_AND_MAIL = frozenset({
    "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe", "thunderbird.exe", "hxoutlook.exe",
    "hxtsr.exe", "communicator.exe",
})
_ARCHIVERS = frozenset({
    "7zfm.exe", "winrar.exe", "rar.exe", "7z.exe", "winzip32.exe",
})
_LURE_APPS = _OFFICE | _BROWSERS | _READERS_AND_MAIL | _ARCHIVERS


def _lure_kind(name: str) -> str | None:
    if name in _OFFICE:
        return "an Office application"
    if name in _BROWSERS:
        return "a web browser"
    if name in _READERS_AND_MAIL:
        return "a mail or document-reader application"
    if name in _ARCHIVERS:
        return "an archive utility"
    return None


class LureAppSpawnsCodeRunner(WindowsProcessRule):
    id = "win.lure_app_spawns_code_runner"
    version = "1"
    title = "A document, mail, browser or reader application created a shell, script host or LOLBin"
    uses_parent = True
    reads_command_line = False            # judged on images alone, so a negative is possible under attestation
    severity, lane = "high", "high"
    attack = ("T1204.002", "T1566.001", "T1059", "T1203")
    benign = (
        "a browser launching its own updater or a helper it ships",
        "an application's 'open containing folder' or 'print' action starting explorer or a print helper",
        "enterprise add-ins that legitimately call PowerShell (rare; confirm against the software baseline)",
        "a user deliberately opening a command prompt from an application's shell-execute menu",
    )
    next_checks = (
        "what the spawned shell or LOLBin then did (its own children, network and file activity)",
        "the lure document: the mail or download that delivered it",
        "whether this parent-child image pair is otherwise seen on this host or its peers",
    )
    card: ClassVar[dict] = {
        "behavior": "a process whose image is an Office, mail, browser, PDF-reader or archive application created a "
                    "child whose image is a command shell, PowerShell, a script host (wscript/cscript/mshta) or a "
                    "signed proxy-execution binary",
        "telemetry": "Sysmon 1 (process.executable_key, process.parent.executable_key, process.guid): parent image "
                     "typed. Security 4688 (process.executable_key, process.pid, process.ppid): the parent image is "
                     "not typed, so the parent is resolved from its own 4688 record through the fenced-pid lineage "
                     "(process termination 4689/Sysmon 5 and System boot records fence it). Both are OS-recorded, so "
                     "the predicate rests on kernel/OS fields.",
        "fidelity": "direct action: the child process was created by that parent (image paths are OS-recorded). It "
                    "does not prove the content was malicious or that the child did anything; the next pivot is what "
                    "the child did.",
        "benign_and_cost": "browser and Office updaters, print and 'open folder' helpers, and a few legitimate "
                           "add-ins; false-lead cost is low because the parent set is narrow and unexpected, and "
                           "repeats merge into one fleet finding.",
        "query_cost": "none beyond the sweep (reads process-creation records it already retrieves).",
        "next_pivot": "the spawned process's own children, network connections and file writes.",
        "adds": "the first Windows process-lineage rule; no earlier rule reads Windows parent/child images.",
        "research_basis": "ATT&CK Enterprise 20.0 T1204.002, T1566.001, T1203, T1059; the cross-cutting "
                          "process-lineage theme (spec section 7 item 8); Sysmon event 1 and Security 4688 field "
                          "references.",
        "negative": "negative-capable: the predicate is images only. A complete negative needs Sysmon 1 "
                    "(or 4688 with Process Creation auditing) inventoried, shipper completeness, and collection "
                    "attested; otherwise partial.",
        "lanes": "high (process creation from a lure application is rarely benign and is an execution step); merged "
                 "fleet repeats keep the lane. Severity high: if adverse this is code execution from a phishing lure.",
        "retrieval": "the sweep retrieves every Windows process-creation record of the window; this evaluator reads "
                     "a provable subset (process-creation records whose image is a code runner).",
    }

    def judge(self, event: TypedEvent) -> list[Hit]:
        child_key = event.get("process.executable_key")
        child_name, why = image_name(child_key)
        if child_name is None:
            raise Undecided("image", f"the child image cannot be identified: {why}")
        if child_name not in SPAWNED_CODE_RUNNERS:
            return []
        parent = resolve_parent(event, self.lineage)
        lure = _lure_kind(parent.name)
        if lure is None:
            return []
        how = ("its own image field" if parent.resolved_by == "record"
               else "its creation record, matched by process id")
        context = []
        predicate = [typed_field(event, "process.executable_key")]
        if parent.resolved_by == "record":
            predicate.append(typed_field(event, "process.parent.executable_key"))
        text = (f"{lure} ('{parent.name}') created the code runner '{child_name}' (parent resolved from {how})")
        return [Hit(
            behavior="lure_app_spawns_code_runner",
            text=text,
            lane=self.lane,
            severity=self.severity,
            attack=self.attack,
            predicate=predicate,
            shape=f"{parent.name}>{child_name}",
            context=context,
        )]


WINDOWS_LINEAGE_PLAYBOOKS = [LureAppSpawnsCodeRunner]
