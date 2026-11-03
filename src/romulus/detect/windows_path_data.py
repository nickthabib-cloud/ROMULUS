"""Sourced Windows path scopes and COM identities; scopes do not establish trust."""
from __future__ import annotations

import ntpath
import re

from romulus.detect.windows_events import components, local_path_components

# Microsoft documents versioned installation roots, including the MDE unified sensor:
# https://learn.microsoft.com/defender-endpoint/collect-diagnostic-data
# https://learn.microsoft.com/defender-endpoint/switch-to-mde-troubleshooting
PROTECTED_PLATFORM_PRODUCTS = frozenset({
    'windows defender', 'windows defender advanced threat protection',
})
_VERSION = re.compile(r'\d+(?:\.\d+){1,5}(?:-\d+)?', re.ASCII)
_GUID = re.compile(r'\{?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?', re.ASCII)
_RANDOM = re.compile(r'(?:[0-9a-f]{8,}|f_[0-9a-f]{4,})', re.ASCII)
# Alias expansion requires the actual filesystem; do not infer a trusted long name.
# https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
_SHORT_NAME = re.compile(r'[^.\\/: ]{1,6}~[0-9]+(?:\.[^.\\/: ]{1,3})?', re.ASCII)


def has_short_name(path):
    """A DOS short-name component does not record the corresponding long location."""
    return any(_SHORT_NAME.fullmatch(part) for part in components(path))

# Path indicators documented by the analytic's original researchers; effective ACLs
# vary by OS and policy. These raise attention, never establish an effective permission.
# https://research.splunk.com/endpoint/c051b68c-60f7-4022-b3ad-773bec7a225b/
WRITABLE_WINDOWS_DIRS = (
    ('windows', 'temp'), ('windows', 'tasks'), ('windows', 'tracing'),
    ('windows', 'system32', 'tasks'), ('windows', 'syswow64', 'tasks'),
    ('windows', 'system32', 'spool', 'drivers', 'color'),
    ('windows', 'syswow64', 'spool', 'drivers', 'color'),
)

# Windows built-ins named by ATT&CK's original COM-hijacking case studies.
# Each identity retains its source; this is deliberately a small positive-only list.
BUILTIN_COM_CLASSES = {
    '{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}': (
        'CAccPropServicesClass', 'https://learn.microsoft.com/dotnet/api/accessibility.caccpropservicesclass'),
    '{42aedc87-2188-41fd-b9a3-0c966feabec1}': (
        'MruPidlList', 'https://unit42.paloaltonetworks.com/bbsrat-attacks-targeting-russian-organizations-linked-to-roaming-tiger/'),
    '{f3130cdb-aa52-4c3a-ab32-85ffc23af9c1}': (
        'Microsoft WBEM New Event Subsystem', 'https://unit42.paloaltonetworks.com/bbsrat-attacks-targeting-russian-organizations-linked-to-roaming-tiger/'),
    '{bcde0395-e52f-467c-8e3d-c4579291692e}': (
        'MMDeviceEnumerator', 'https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/mmdeviceapi.h'),
    '{0358b920-0ac7-461f-98f4-58e32cd89148}': (
        'Wininet CacheTask handler', 'https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-2-com-hijacking/'),
    '{c947d50f-378e-4ff6-8835-fcb50305244d}': (
        'Windows synchronization manager', 'https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/'),
    '{ecd4fc4d-521c-11d0-b792-00a0c90312e1}': (
        'Shell Rebar BandSite', 'https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2023/11/09055246/Modern-Asian-APT-groups-TTPs_report_eng.pdf'),
}


def installation_parts(path):
    """Only explicitly system-rooted scope can lower attention from path evidence.

    A device/volume path does not identify the system volume without a recorded map.
    A non-system drive spelling never establishes installed scope.
    """
    if has_short_name(path):
        return ()
    text = ntpath.normpath(str(path or '').replace('/', '\\')).casefold()
    canonical = text[4:] if text.startswith(('\\\\?\\', '\\??\\')) else text
    parts = local_path_components(path)
    if parts and canonical.startswith(('c:\\', '%systemdrive%\\')):
        return parts
    parts = components(text)
    if parts and parts[0] in {'%systemroot%', '%windir%', 'systemroot'}:
        return ('windows', *parts[1:])
    return ()


def protected_platform_path(path):
    parts = installation_parts(path)
    return (len(parts) >= 6 and parts[:2] == ('programdata', 'microsoft')
            and parts[2] in PROTECTED_PLATFORM_PRODUCTS and parts[3] == 'platform'
            and _VERSION.fullmatch(parts[4]) is not None)


def writable_windows_path(path):
    # Positive directory indicators apply to every local volume. Only the
    # installation scope used to lower attention requires the system volume.
    parts = local_path_components(path) or installation_parts(path)
    return any(len(parts) > len(prefix) and parts[:len(prefix)] == prefix for prefix in WRITABLE_WINDOWS_DIRS)


def path_class(path, *, directory=False):
    """Normalize content identity only; exact paths remain in predicates and citations.

    This never changes a lane or suppresses a record. Directory identity retains
    application/location labels but discards profile, GUID, version and cache instances.
    """
    text = ntpath.normpath(str(path or '').replace('/', '\\')).casefold()
    parts = list(components(text))
    if not parts:
        return '<unrecorded>'
    for index, part in enumerate(parts):
        if index and parts[index - 1] in {'users', 'documents and settings'}:
            parts[index] = '<profile>'
        elif _GUID.fullmatch(part):
            parts[index] = '<guid>'
        elif _VERSION.fullmatch(part):
            parts[index] = '<version>'
        elif _RANDOM.fullmatch(part):
            parts[index] = '<instance>'
    if directory:
        parts = parts[:-1]
        for index, part in enumerate(parts):
            if part in {'cache', 'cache_data', 'code cache', 'gpucache', 'inetcache', 'cache2', 'startupcache'}:
                parts = parts[:index + 1] + (['<cache-directories>'] if index + 1 < len(parts) else [])
                break
    return '\\'.join(parts)


def extension_class(path):
    return ntpath.splitext(str(path or ''))[1].casefold() or '<no-extension>'
