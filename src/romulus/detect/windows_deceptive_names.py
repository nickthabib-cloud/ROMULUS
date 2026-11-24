"""Deceptive file names on Windows: bidirectional override characters, a document extension in front of an
executable one, and screen savers run from user locations.

Each judgement reads one typed path: the recorded process image (Sysmon 1, Security 4688), the script a Windows
script host or mshta was given (its command line, split as CommandLineToArgvW does), or the file a process created
(Sysmon 11). A name shows how a file was presented to a user; it never shows what the file contains.
"""
from __future__ import annotations

import json
import ntpath

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_cmdline import split_argv
from romulus.detect.windows_common import SECURITY_PROCESS_CREATE, SYSMON_PROCESS_CREATE
from romulus.detect.windows_ecar import class_discriminator, ecar_record
from romulus.detect.windows_events import basename, components, signal, writable
from romulus.detect.windows_path_data import writable_windows_path
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

# Unicode bidirectional formatting characters that reorder the text after them (UAX #9 explicit embeddings,
# overrides and isolates). U+202E RIGHT-TO-LEFT OVERRIDE is the one ATT&CK T1036.002 names.
BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING", "\u202b": "RIGHT-TO-LEFT EMBEDDING", "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE", "\u202e": "RIGHT-TO-LEFT OVERRIDE", "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE", "\u2068": "FIRST STRONG ISOLATE", "\u2069": "POP DIRECTIONAL ISOLATE",
}
# Extensions a user reads as a document, picture, recording or archive.
DECOY_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb", "csv", "ppt", "pptx", "pptm", "pps",
    "ppsx", "rtf", "txt", "odt", "ods", "odp", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
    "mp3", "mp4", "m4a", "wav", "wma", "avi", "mov", "wmv", "mkv", "zip", "rar", "7z", "eml", "msg",
})
# Extensions Windows runs or opens with a code host: native images, command scripts, script-host and HTML
# application files, shortcuts, PowerShell, installer packages, Control Panel items, Java archives and compiled help.
# https://learn.microsoft.com/windows/win32/shell/executable-files ; https://attack.mitre.org/techniques/T1036/007/
EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "lnk", "ps1", "msi",
    "msp", "cpl", "jar", "chm",
})
# Extensions that are native images: only these can be the recorded image of a created process.
_IMAGE_EXTENSIONS = frozenset({"exe", "scr", "com", "pif", "cpl"})
# The script hosts whose first operand is the script file they run.
SCRIPT_HOSTS = frozenset({"wscript.exe", "cscript.exe", "mshta.exe"})
# Explorer and Office write '<document>.<ext>.lnk' for every document a user opens.
_RECENT_FOLDERS = (("microsoft", "windows", "recent"), ("microsoft", "office", "recent"))
_FIELDS_IMAGE = ("process.executable", "process.executable_key", "process.parent.executable", "process.pid",
                 "user.name", "process.user")
_FIELDS_SCRIPT = (*_FIELDS_IMAGE, "process.command_line")
_FIELDS_FILE = ("file.path", "file.path_key", "process.executable", "process.executable_key", "process.pid",
                "file.action")
_SYSMON_DOC = "https://learn.microsoft.com/sysinternals/downloads/sysmon#events"


def escaped(text: str) -> str:
    """The text with every bidirectional control written as its code point, so a claim cannot be reordered."""
    return "".join(f"[U+{ord(ch):04X}]" if ch in BIDI_CONTROLS else ch for ch in text)


def displayed(name: str) -> str:
    """How a name with a RIGHT-TO-LEFT OVERRIDE reads on screen (approximately): the characters after the override,
    up to POP DIRECTIONAL FORMATTING or the end, in reverse order."""
    out, i = [], 0
    while i < len(name):
        ch = name[i]
        if ch == "\u202e":
            end = name.find("\u202c", i + 1)
            end = len(name) if end < 0 else end
            out.append(name[i + 1:end][::-1])
            i = end + 1
            continue
        if ch not in BIDI_CONTROLS:
            out.append(ch)
        i += 1
    return "".join(out)


def bidi_controls(path: str) -> list[str]:
    return sorted({BIDI_CONTROLS[ch] for ch in path if ch in BIDI_CONTROLS})


# Characters a name can be padded with before its real extension: spaces and underscores, every Unicode space
# (U+00A0, U+1680, U+2000-U+200A, U+202F, U+205F, U+3000) and the invisible zero-width ones (U+180E, U+200B-U+200D,
# U+2060, U+FEFF).
_INVISIBLE = "\u180e\u200b\u200c\u200d\u2060\ufeff"
_PADDING = (" _\u00a0\u1680\u202f\u205f\u3000" + "".join(chr(code) for code in range(0x2000, 0x200B))
            + _INVISIBLE)
# The override characters that reverse what follows them (UAX #9 LRO, RLO): the ones that make a name read as
# another extension.
OVERRIDES = frozenset({"\u202d", "\u202e"})


def double_extension(name: str) -> tuple[str, str, bool] | None:
    """(visible decoy extension, real extension, padded) when a name ends in a document extension followed by an
    executable one ('invoice.pdf.exe', 'scan.jpg      .scr'); None otherwise."""
    stem, real = ntpath.splitext(name)
    real = real[1:].casefold()
    if real not in EXECUTABLE_EXTENSIONS:
        return None
    trimmed = stem.rstrip(_PADDING)
    padded = len(stem) - len(trimmed) >= 3 or any(ch not in " _" for ch in stem[len(trimmed):])
    inner_stem, decoy = ntpath.splitext(trimmed)
    decoy = decoy[1:].casefold()
    if decoy not in DECOY_EXTENSIONS or not inner_stem.strip():
        return None
    return decoy, real, padded


def _user_path(path: str) -> bool:
    return writable(path) or writable_windows_path(path)


def _recent_shortcut(path: str) -> bool:
    parts = components(path)
    return basename(path).endswith(".lnk") and any(
        parts[i:i + 3] == folder for folder in _RECENT_FOLDERS for i in range(max(0, len(parts) - 3)))


def _is_code(event, family: str, codes: tuple[int, ...]) -> bool:
    if ecar_record(event):
        return any(class_discriminator(event, code, family) for code in codes)
    return event.family == family and event.get("event.code") in codes


class DeceptiveFileName(BehaviorFleetRule):
    ecar_compatible = True
    id = "win.deceptive_file_name"
    version = "1"
    title = "Process image, script or created file with a deceptive name"
    families = ("process_exec", "file_change")
    windows_event_classes = (SYSMON_PROCESS_CREATE, SECURITY_PROCESS_CREATE, (SYSMON_CHANNEL, SYSMON, 11))
    attack = ("T1036.002", "T1036.007", "T1204.002")
    severity = "high"
    benign = ("a program that writes Unicode isolates into file names it generates from mixed-direction text",
              ("an installer creating a '<readme>.txt.lnk' shortcut; Explorer's and Office's own '<document>.lnk' "
              "files in the Recent folders are not reported"),
              "a third-party screen saver installed into a user's profile")
    next_checks = ("how the file arrived: the browser, mail or archive process that wrote it and its Zone.Identifier",
                   "the process the file started and that process's network and file activity",
                   "the file's signer, OriginalFileName and hash")
    research = (_SYSMON_DOC, "https://attack.mitre.org/techniques/T1036/002/",
                "https://attack.mitre.org/techniques/T1036/007/", "https://attack.mitre.org/techniques/T1204/002/",
                "https://www.unicode.org/reports/tr9/")
    def judge(self, event):
        if _is_code(event, "process_exec", (1, 4688)):
            return self._process(event)
        if _is_code(event, "file_change", (11,)):
            return self._created(event)
        return []

    @staticmethod
    def _recorded(event, stem: str) -> str:
        value = event.get(stem)
        if isinstance(value, str) and value:
            return value
        key = event.get(stem + "_key")
        return key if isinstance(key, str) else ""

    def _process(self, event):
        image = self._recorded(event, "process.executable")
        if not image:
            return []
        hits = []
        name = ntpath.basename(image.replace("/", "\\"))
        controls = bidi_controls(image)
        if controls:
            hits.append(self._bidi(event, image, name, controls, "process image", _FIELDS_IMAGE, executed=True))
        double = double_extension(name)
        if double and double[1] in _IMAGE_EXTENSIONS:
            hits.append(self._double(event, image, name, double, "process image", _FIELDS_IMAGE, lane="high"))
        elif not double and not controls and name.casefold().endswith(".scr") and _user_path(image):
            hits.append(signal(
                event, "user_path_screensaver",
                f"Windows recorded the creation of a process from screen saver '{self.describe(escaped(image))}' in a "
                "user-writable location; screen savers are installed in the system directory",
                ("T1204.002", "T1036"), _FIELDS_IMAGE, lane="lead", severity="high",
                content=json.dumps(["screensaver", event.host, ntpath.dirname(image).casefold()]),
                common="Processes were created from screen savers in user-writable locations",
                notes=("A .scr file is a native executable; the name does not show what it does.",)))
        if basename(image) in SCRIPT_HOSTS:
            hits += self._script(event, basename(image))
        return hits

    def _script(self, event, host: str):
        line = event.get("process.command_line")
        if not isinstance(line, str) or not line.strip():
            self.note_coverage("script_operand", "Script-host process records without a recorded command line were "
                                                 "not judged for the script's name (Security 4688 records it only "
                                                 "when command-line auditing is on).")
            return []
        argv = split_argv(line)
        operand = next((arg for arg in argv[1:] if not arg.startswith(("/", "-")) or ":\\" in arg[:3]), "")
        if not operand:
            return []
        name = ntpath.basename(operand.replace("/", "\\"))
        controls = bidi_controls(operand)
        out = []
        if controls:
            out.append(self._bidi(event, operand, name, controls, f"script run by {host}", _FIELDS_SCRIPT,
                                  executed=True))
        double = double_extension(name)
        if double and double[1] in {"js", "jse", "vbs", "vbe", "wsf", "wsh", "hta"}:
            out.append(self._double(event, operand, name, double, f"script run by {host}", _FIELDS_SCRIPT,
                                    lane="high"))
        return out

    def _created(self, event):
        path = self._recorded(event, "file.path")
        if not path:
            return []
        name = ntpath.basename(path.replace("/", "\\"))
        out = []
        controls = bidi_controls(path)
        if controls:
            out.append(self._bidi(event, path, name, controls, "created file", _FIELDS_FILE, executed=False))
        double = double_extension(name)
        if double and not _recent_shortcut(path):
            out.append(self._double(event, path, name, double, "created file", _FIELDS_FILE, lane="lead"))
        return out

    def _bidi(self, event, path, name, controls, what, fields, *, executed):
        """High for an override character in the final name of something run, or of a created file whose real
        extension is executable; any other control (embeddings, isolates, or a control in a directory name, as
        right-to-left folder names hold) is a lead folded per directory."""
        real = ntpath.splitext(name)[1][1:].casefold()
        deceptive = any(ch in OVERRIDES for ch in name) and (executed or real in EXECUTABLE_EXTENSIONS)
        shown = displayed(name)
        text = (f"Windows recorded a {what} whose path holds the Unicode control(s) {', '.join(controls)}: "
                f"'{self.describe(escaped(path))}'")
        if "RIGHT-TO-LEFT OVERRIDE" in controls:
            text += f", whose name reads on screen roughly as '{self.describe(shown)}'"
        text += "; " + ("the process was created" if executed else "whether the file was opened or run is not shown")
        directory = ntpath.dirname(path.replace("/", "\\")).casefold()
        return signal(event, "bidi_control", text, ("T1036.002",) + (("T1204.002",) if executed else ()),
                      fields, lane="high" if deceptive else "lead", severity="high" if deceptive else "medium",
                      content=(json.dumps(["bidi", path.casefold()]) if deceptive
                               else json.dumps(["bidi", event.host, escaped(directory)])),
                      common=("" if deceptive else "Names holding Unicode direction controls in one directory "
                              "(no override in an executable name)"),
                      notes=(("Control characters are written as their code points here so that this text cannot be "
                             "reordered; the predicate's recorded value holds them as recorded."),))

    def _double(self, event, path, name, double, what, fields, *, lane):
        decoy, real, padded = double
        text = (f"Windows recorded a {what} named '{self.describe(escaped(name))}': a .{decoy} name followed by "
                f"the .{real} extension that decides how Windows opens it")
        if padded:
            text += ", with padding that pushes the real extension out of a narrow column"
        executed = what != "created file"
        text += "; the process was created" if executed else "; whether the file was opened or run is not shown"
        directory = ntpath.dirname(path.replace("/", "\\")).casefold()
        return signal(event, "double_extension", text, ("T1036.007",) + (("T1204.002",) if executed else ()),
                      fields, lane=lane, severity="high",
                      content=(path.casefold() if lane == "high"
                               else json.dumps(["double", event.host, directory, decoy, real])),
                      common=(f"Files named .{decoy}.{real} were created in one directory" if lane != "high" else ""),
                      notes=("The name shows how the file was presented, not what it contains.",))

    def fleet_eligible(self, event, hit):
        return hit.lane == "lead"


DeceptiveFileName.card = {
    "behavior": "a process image, a script given to a Windows script host, or a created file whose name carries "
                "Unicode bidirectional override or isolate characters, a document or media extension in front of an "
                "executable one, or a screen saver run from a user-writable location",
    "telemetry": "process_exec (Sysmon 1, Security 4688: process.executable, process.command_line for script "
                 "hosts) and file_change (Sysmon 11: file.path, process.executable); eCAR process and file creates. "
                 "The lab profile has no Windows source; the rule is not applicable there",
    "fidelity": "direct observation of the recorded name; a created process is stated as created, a created file "
                "is never stated as opened or run",
    "benign_and_cost": "rare: generated mixed-direction names, installer shortcuts named '<readme>.txt.lnk', "
                       "user-installed screen savers. Explorer's and Office's Recent-folder shortcuts are not "
                       "reported. Leads of one shape and directory fold into one finding",
    "query_cost": "one selective sweep of the process and file-creation classes; bounded disk-backed fleet state",
    "next_pivot": "how the file arrived (its writer and Zone.Identifier) and what the process it started did",
    "adds": "names presented to deceive a user, which the extension-mismatch rule (win.non_executable_process_image) "
            "does not read: it judges only the final extension",
    "research_basis": "; ".join(DeceptiveFileName.research) + "; ATT&CK Enterprise 20.0 T1036.002, T1036.007, "
                      "T1204.002",
    "retrieval": "the declared Sysmon 1, Security 4688 and Sysmon 11 classes; unrelated classes are inventoried "
                 "separately",
    "lanes": "high for any bidirectional control and for a double extension on a created process or on a script a "
             "script host ran; lead for a double-extension file creation (not shown to be opened) and for a screen "
             "saver run from a user-writable location. Severity high: a user ran or was led to run a disguised "
             "program",
}

RULES = (DeceptiveFileName,)
