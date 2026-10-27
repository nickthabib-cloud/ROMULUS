"""A document, mail, reader or browser application spawned a shell, script host or LOLBin.

The behaviour: a process whose image is a productivity, mail, reader or browser application created a child whose
image is a command shell, PowerShell, a script host or one of the signed binaries most used to proxy execution.
This is the shape phishing and drive-by chains share: the lure opens in Word, Outlook, a PDF reader or a browser,
and that process starts the code runner. It keys on the OS-recorded parent and child image names, so it survives a
renamed payload and reads no command-line text for the match itself.

ROMULUS never asserts absence, so the rule is positive-only: a window without such a pair is not evidence that none
occurred. Browsers are treated apart from Office/readers because a browser legitimately launches native-messaging
hosts (a `cmd.exe`/host spawn carrying a `chrome-extension://` operand) and user-run installers; those are not lure
matches or are leads, never silently dropped.

When Sysmon 1 records the parent image, the pair is read from one record. When only Security 4688 is collected, the
parent image is not a typed field: the parent is resolved from its own 4688 creation record through the shared pid
lineage (fenced by process termination and boot), that record is cited, and the parent image is carried as a
predicate field with its record's origin. If neither gives the parent image, the record is undecided (partial),
never a clean no-match and never judged benign.
"""
from __future__ import annotations

from typing import ClassVar

from romulus.detect.windows_cmdline import is_chromium_native_messaging
from romulus.detect.windows_common import (
    SPAWNED_CODE_RUNNERS,
    Hit,
    Undecided,
    WindowsProcessRule,
    image_name,
    parent_predicate,
    resolve_parent,
)
from romulus.evidence.typed import TypedEvent

# Applications that open attacker-supplied content and have no routine reason to start a shell or LOLBin.
_OFFICE = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe",
    "visio.exe", "winproj.exe", "eqnedt32.exe", "wordpad.exe",
})
_READERS_AND_MAIL = frozenset({
    "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe", "thunderbird.exe", "hxoutlook.exe",
    "hxtsr.exe", "communicator.exe",
})
_ARCHIVERS = frozenset({
    "7zfm.exe", "winrar.exe", "rar.exe", "7z.exe", "winzip32.exe",
})
_BROWSERS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "vivaldi.exe", "msedgewebview2.exe",
})
# Signed installers a browser legitimately starts when a user runs a download.
_INSTALLER_CHILDREN = frozenset({"msiexec.exe"})


def _document_kind(name: str) -> str | None:
    if name in _OFFICE:
        return "an Office application"
    if name in _READERS_AND_MAIL:
        return "a mail or document-reader application"
    if name in _ARCHIVERS:
        return "an archive utility"
    return None


def _is_native_messaging(event: TypedEvent, child_name: str) -> bool:
    """True only for the exact Chromium native-messaging host launch (a cmd.exe child). Any other command with a
    browser parent — a chrome-extension operand bolted onto an unrelated command, a rundll32 launch — is not a
    native-messaging host and is never dropped here; it stays a lead."""
    if child_name != "cmd.exe":
        return False
    command = event.get("process.command_line")
    return bool(command) and is_chromium_native_messaging(str(command))


class LureAppSpawnsCodeRunner(WindowsProcessRule):
    id = "win.lure_app_spawns_code_runner"
    version = "4"
    title = "A document, mail, reader or browser application created a shell, script host or LOLBin"
    uses_parent = True
    reads_command_line = False            # the match is images only; the command line is read only to exclude NM
    parent_images = _OFFICE | _READERS_AND_MAIL | _ARCHIVERS | _BROWSERS
    severity, lane = "high", "high"
    attack = ("T1204.002", "T1566.001", "T1059", "T1203")
    benign = (
        ("a browser launching a native-messaging host (cmd.exe starting a registered host with a chrome-extension "
         "operand) — excluded"),
        "a browser starting a user-run installer (msiexec) from a download — lead, not high",
        "an application's 'open containing folder' or 'print' action starting explorer or a print helper",
        "enterprise add-ins that legitimately call PowerShell (rare; confirm against the software baseline)",
    )
    next_checks = (
        "what the spawned shell or LOLBin then did (its own children, network and file activity)",
        "the lure document or page: the mail or download that delivered it",
        "whether this parent-child image pair is otherwise seen on this host or its peers",
    )
    card: ClassVar[dict] = {
        "behavior": "a process whose image is an Office, mail, reader or archive application created a child whose "
                    "image is a command shell, PowerShell, a script host (wscript/cscript/mshta) or a signed "
                    "proxy-execution binary (high); a browser that spawns a code runner that is not a "
                    "native-messaging host is a lead (installer children are a lead; native-messaging launches are "
                    "excluded)",
        "telemetry": "Sysmon 1 (process.executable_key, process.parent.executable_key, process.guid): parent image "
                     "typed. Security 4688 (process.executable_key, process.pid, process.ppid): the parent image is "
                     "not typed, so the parent is resolved from its own 4688 creation record through the shared "
                     "fenced-pid lineage (process termination 4689/Sysmon 5 and System boot records fence it); that "
                     "record is cited and the parent image carried as a predicate field.",
        "fidelity": "direct action: the child process was created by that parent (image paths are OS-recorded). It "
                    "does not prove the content was malicious or that the child did anything; the next pivot is what "
                    "the child did. Positive-only: a window without the pair is not evidence of absence.",
        "benign_and_cost": "browser native-messaging hosts (excluded) and user-run installers (lead); Office/reader "
                           "updaters, print and 'open folder' helpers. Cost is low because the parent set is narrow "
                           "and repeats merge into one fleet finding while new hosts keep their own.",
        "query_cost": "none beyond the sweep (reads process-creation records it already retrieves).",
        "next_pivot": "the spawned process's own children, network connections and file writes.",
        "adds": "the first Windows process-lineage rule; no earlier rule reads Windows parent/child images.",
        "research_basis": "ATT&CK Enterprise 20.0 T1204.002, T1566.001, T1203, T1059; the cross-cutting "
                          "process-lineage theme; Chromium native-messaging launch shape; Sysmon event 1 and "
                          "Security 4688 field references.",
        "lanes": "high for an Office/reader/archiver parent (process creation from a lure application is rarely "
                 "benign and is an execution step); lead for a browser parent (browsers spawn helpers legitimately), "
                 "with the reason; never context. Severity high if adverse (code execution from a lure).",
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
        document = _document_kind(parent.name)
        browser = parent.name in _BROWSERS
        if document is None and not browser:
            return []

        predicate, context, how, raw = parent_predicate(event, parent)

        if browser:
            if _is_native_messaging(event, child_name):
                return []           # a native-messaging host launch is a routine browser mechanism, not a lure
            if child_name in _INSTALLER_CHILDREN:
                lane, what = "lead", f"a browser ('{parent.name}') started the installer '{child_name}'"
            else:
                lane, what = "lead", (f"a browser ('{parent.name}') created the code runner '{child_name}' "
                                      f"(not a native-messaging host)")
            return [Hit(
                behavior="browser_spawns_code_runner",
                text=f"{what} (parent resolved from {how})",
                lane=lane, severity="medium", attack=self.attack, predicate=predicate,
                common=f"a browser spawning '{child_name}'", context=context, raw_copies=raw,
                parent_name=parent.name,
                notes=(("lead: browsers legitimately spawn helpers and installers; the discriminating pivot is what "
                        "the child did"),),
            )]

        return [Hit(
            behavior="lure_app_spawns_code_runner",
            text=f"{document} ('{parent.name}') created the code runner '{child_name}' (parent resolved from {how})",
            lane=self.lane, severity=self.severity, attack=self.attack, predicate=predicate,
            common=f"{document} spawning '{child_name}'", context=context, raw_copies=raw,
            parent_name=parent.name,
        )]


WINDOWS_LINEAGE_PLAYBOOKS = [LureAppSpawnsCodeRunner]
