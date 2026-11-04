"""Recorded non-LSASS process access with injection-capable rights and trace context."""
from __future__ import annotations

import json
import re

from romulus.detect.windows_events import WindowsEventRule, basename, integer, signal
from romulus.detect.windows_memory_events import (
    _expected_dotnet_host,
    _installation_parts,
    _installed_path,
    _trace_modules,
)
from romulus.detect.windows_path_data import writable_windows_path
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

_RIGHTS = 'https://learn.microsoft.com/windows/win32/procthread/process-security-and-access-rights'
_DOTNET = 'https://learn.microsoft.com/dotnet/core/install/windows'
_DEBUG = 'https://learn.microsoft.com/windows-hardware/drivers/debugger/debugger-download-tools'
_DEFENDER = 'https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows'
# Entries identify known installation layouts, not arbitrary basename copies.
SECURITY_LAYOUTS = {
    'msmpeng.exe': (('windows defender',), _DEFENDER),
    'mssense.exe': (('windows defender advanced threat protection',),
                    'https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint'),
    'csfalconservice.exe': (('crowdstrike',), 'https://www.crowdstrike.com/platform/endpoint-security/'),
    'sentinelagent.exe': (('sentinelone',), 'https://www.sentinelone.com/platform/'),
}
DEBUGGER_NAMES = {
    'windbg.exe': _DEBUG, 'cdb.exe': _DEBUG, 'ntsd.exe': _DEBUG,
    'vsjitdebugger.exe': 'https://learn.microsoft.com/visualstudio/debugger/debugger-feature-tour',
}
RUNTIME_MODULES = {
    'clr.dll': _DOTNET, 'coreclr.dll': _DOTNET, 'clrjit.dll': _DOTNET, 'mscorjit.dll': _DOTNET,
    'jvm.dll': 'https://docs.oracle.com/en/java/javase/25/vm/java-hotspot-virtual-machine-performance-enhancements.html',
}


def _known_source_context(source, modules):
    if writable_windows_path(source):
        return False
    parts = _installation_parts(source)
    name = basename(source)
    if _expected_dotnet_host(source):
        return True
    if parts and parts[0] in {'program files', 'program files (x86)'}:
        layout = SECURITY_LAYOUTS.get(name)
        if layout and any(part.startswith(prefix) for part in parts[1:-1] for prefix in layout[0]):
            return True
        if name in DEBUGGER_NAMES and (
                'debuggers' in parts or 'microsoft visual studio' in parts or 'windows kits' in parts):
            return True
        if name in {'java.exe', 'javaw.exe'} and any(part.startswith(('java', 'jdk', 'jre')) for part in parts[1:-1]):
            return True
    # An installed runtime frame provides native runtime context. The source is
    # also installed: a writable copied executable cannot gain this exclusion.
    return _installed_path(source) and any(
        basename(module) in RUNTIME_MODULES and _installed_path(module) for module in modules)


class InjectionShapedProcessAccess(WindowsEventRule):
    id = 'win.injection_shaped_process_access'
    title = 'Process access combined memory-write and thread-creation rights'
    families = ('process_access',)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 10),)
    required_fields = ('source.executable', 'target.executable', 'process.access.mask')
    attack = ('T1055', 'T1055.012')
    benign = ('Installed managed runtimes, security products and debuggers can legitimately access process memory.',)
    next_checks = ('Inspect the source identity, target activity and any recorded remote threads or changed images.',)
    research = (_RIGHTS, 'https://learn.microsoft.com/sysinternals/downloads/sysmon')

    def judge(self, event):
        if event.get('event.code') != 10:
            return []
        source = event.get('source.executable_key') or event.get('source.executable')
        target = event.get('target.executable_key') or event.get('target.executable')
        if not source or not target:
            self.missing_required += 1
            return []
        if basename(target) == 'lsass.exe':
            return []
        mask = integer(event.get('process.access.mask'))
        if mask is None or mask & 0x2a != 0x2a:
            return []
        modules = _trace_modules(event)
        if _known_source_context(source, modules):
            return []
        unknown = [bool(re.fullmatch(r'unknown(?:\([^)]*\))?', module)) for module in modules]
        outside = not _installed_path(source)
        if not any(unknown) and not outside:
            return []
        all_unknown = bool(unknown) and all(unknown)
        sensitive = basename(target) in {'winlogon.exe', 'svchost.exe', 'services.exe'}
        high = all_unknown or sensitive
        reasons = []
        if any(unknown):
            reasons.append('every recorded trace frame is unresolved' if all_unknown else 'some recorded trace frames are unresolved')
        if outside:
            reasons.append('the source path does not establish installation-directory scope')
        if sensitive:
            reasons.append('the target image names a logon or service host')
        fields = ('source.executable', 'source.executable_key', 'source.guid', 'source.pid',
                  'target.executable', 'target.executable_key', 'target.guid', 'target.pid',
                  'process.access.mask', 'process.access.call_trace', 'process.access.call_trace_modules')
        return [signal(event, 'injection_capable_access',
                       f"Recorded source '{self.describe(source)}' opened '{self.describe(target)}' with "
                       f'CREATE_THREAD, VM_OPERATION and VM_WRITE rights (mask0x{mask:x}); ' + '; '.join(reasons),
                       self.attack, fields, lane='high' if high else 'lead',
                       content=json.dumps([source, target, mask, modules], separators=(',', ':')),
                       notes=('Granted rights do not establish a completed memory write, remote thread creation or injection.',
                              'Installation/path and runtime context are not independent signer verification.'))]


RULES = (InjectionShapedProcessAccess,)
