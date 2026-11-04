"""Sourced executable and module identities; membership does not establish trust."""
from __future__ import annotations

_UAC = "https://github.com/hfiref0x/UACME"
_UAC_NAMES = "https://github.com/hfiref0x/UACME/blob/master/Source/Shared/consts.h"
_ACCESS = "https://attack.mitre.org/techniques/T1546/008/"
_VERSION = "https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfoa"
_OBSERVED_MUI_NAMES = {"cmd.exe", "regsvr32.exe", "rundll32.exe", "svchost.exe", "mmc.exe", "osk.exe"}

# This is a historical elevation-related attention inventory, not a statement that
# every Windows version auto-elevates these programs. Rules require recorded facts.
AUTO_ELEVATED_BINARIES = {
    "fodhelper.exe": _UAC, "computerdefaults.exe": _UAC, "sdclt.exe": _UAC,
    "eventvwr.exe": _UAC, "compmgmtlauncher.exe": _UAC, "wsreset.exe": _UAC,
    "changepk.exe": _UAC, "pkgmgr.exe": _UAC, "consent.exe": _UAC,
    "mmc.exe": _UAC,
    "dism.exe": "https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/methods/hybrids.c",
    "dllhost.exe": "https://learn.microsoft.com/en-us/windows/win32/com/dll-surrogates",
    "control.exe": "https://learn.microsoft.com/en-us/windows/win32/shell/executing-control-panel-items",
    "werfault.exe": "https://devblogs.microsoft.com/oldnewthing/20101101-00/?p=12393",
    "taskmgr.exe": "https://devblogs.microsoft.com/oldnewthing/20120130-00/?p=8423",
}
ELEVATION_COM_CLSIDS = {
    "{3e5fc7f9-9a51-4367-9063-a120244fbec7}": _UAC_NAMES,
    "{d2e7041b-2927-42fb-8e9f-7ce93b6dc937}": _UAC_NAMES,
}
AUTO_ELEVATION_QUALIFICATIONS = {
    "mmc.exe": "Require a parsed writable .msc executable operand in the parent's own command line.",
    "dllhost.exe": "Require a parsed /Processid:{CLSID} operand exactly present in ELEVATION_COM_CLSIDS.",
}
ACCESSIBILITY_BINARIES = {
    "osk.exe": _ACCESS, "sethc.exe": _ACCESS, "utilman.exe": _ACCESS,
    "magnify.exe": _ACCESS, "narrator.exe": _ACCESS, "atbroker.exe": _ACCESS,
    "displayswitch.exe": _ACCESS,
}


def _identity(name, source, description="", *, expected_subdirs=()):
    # Windows version queries can merge language-neutral and MUI resources. Both
    # forms are identity hints; neither proves a file's signature or authenticity.
    aliases = (name, name + ".mui") if name in _OBSERVED_MUI_NAMES else (name,)
    return {"original_file_names": aliases, "descriptions": (description,) if description else (),
            "products": ("Microsoft® Windows® Operating System", "Microsoft Windows Operating System",
                         "Microsoft� Windows� Operating System"),
            "source": source, "metadata_source": _VERSION, "expected_subdirs": expected_subdirs}


SYSTEM_BINARIES = {
    "calc.exe": _identity("calc.exe", "https://learn.microsoft.com/en-us/cpp/code-quality/c6298", "Windows Calculator"),
    "cmd.exe": _identity("cmd.exe", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd", "Windows Command Processor"),
    "regsvr32.exe": _identity("regsvr32.exe", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32", "Microsoft(C) Register Server"),
    "rundll32.exe": _identity("rundll32.exe", "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/", "Windows host process (Rundll32)"),
    "svchost.exe": _identity("svchost.exe", "https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring", "Host Process for Windows Services"),
    "mmc.exe": _identity("mmc.exe", _UAC_NAMES, "Microsoft Management Console"),
    "osk.exe": _identity("osk.exe", _UAC_NAMES, "Accessibility On-Screen Keyboard"),
    "clipup.exe": _identity("clipup.exe", _UAC_NAMES, "Client License Platform migration tool"),
    **{name: _identity(name, source) for name, source in ACCESSIBILITY_BINARIES.items() if name != "osk.exe"},
    "powershell.exe": _identity("powershell.exe", "https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell",
                                expected_subdirs=(("windowspowershell", "v1.0"),)),
    "wscript.exe": _identity("wscript.exe", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript"),
    "cscript.exe": _identity("cscript.exe", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript"),
    "mshta.exe": _identity("mshta.exe", "https://lolbas-project.github.io/lolbas/Binaries/Mshta/"),
    **{name: _identity(name, source) for name, source in AUTO_ELEVATED_BINARIES.items() if name not in {"mmc.exe"}},
}

# These are Windows module names in the original research inventory, not a mirror
# of the target machine's KnownDLLs registry configuration.
KNOWN_SYSTEM_DLLS = {
    "comctl32.dll": _UAC_NAMES, "dismcore.dll": _UAC_NAMES, "duser.dll": _UAC_NAMES,
    "gdiplus.dll": _UAC_NAMES, "iscsiexe.dll": _UAC_NAMES, "osksupport.dll": _UAC_NAMES,
    "pcadm.dll": _UAC_NAMES, "performancetracehandler.dll": _UAC_NAMES, "rsaenh.dll": _UAC_NAMES,
    "shell32.dll": _UAC_NAMES, "winmm.dll": _UAC_NAMES, "wow64log.dll": _UAC_NAMES,
    "windows.storage.dll": _UAC_NAMES, "atl.dll": _UAC_NAMES,
    "cryptbase.dll": _UAC, "cryptsp.dll": _UAC,
    "version.dll": _VERSION,
}
