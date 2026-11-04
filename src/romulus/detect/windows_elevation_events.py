"""Positive registry configuration observations and bounded elevation correlation."""
from __future__ import annotations

import json
import re
import sqlite3
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_cmdline import is_remote_path, is_user_writable, split_argv
from romulus.detect.windows_common import SPAWNED_CODE_RUNNERS
from romulus.detect.windows_compact_rows import FENCE_FIELDS, CompactWindowsRows
from romulus.detect.windows_events import basename, components, signal
from romulus.detect.windows_registry_events import (
    _CU,
    _LM,
    _RegistryRule,
    _software,
    _system,
    _target,
    _uncertain,
)
from romulus.detect.windows_rows import row_key
from romulus.detect.windows_system_data import AUTO_ELEVATED_BINARIES, ELEVATION_COM_CLSIDS, SYSTEM_BINARIES
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

_UAC_SOURCE = 'https://attack.mitre.org/techniques/T1548/002/'
_REGISTRY_SOURCE = 'https://learn.microsoft.com/windows/win32/sysinfo/registry-value-types'
_CLASSES = frozenset({'ms-settings', 'mscfile', 'exefile', 'folder', 'launcher.systemsettings'})
_REG_FIELDS = ('registry.path_key', 'registry.value_name', 'registry.value', 'registry.action',
               'registry.event_type', 'registry.value_type', 'registry.details_truncated', 'user.key', 'user.sid')
_NO_EFFECT = ('Registry configuration observations do not prove execution or that an effective policy changed.',)


def _operand(value):
    if not isinstance(value, str):
        return ''
    args = split_argv(value)
    return args[0] if args else ''


def _unclosed_command_quotes(value):
    """Check closure using the program-name and argument rules of split_argv.

    The tokenizer deliberately accepts an unterminated quoted span. A registry
    observation must not turn that tolerance into a supported payload claim.
    """
    if not isinstance(value, str):
        return False
    text = value.lstrip(' \t')
    if text.startswith('"'):
        end = text.find('"', 1)
        if end < 0:
            return True
        index = end + 1
    else:
        index = next((i for i, char in enumerate(text) if char in ' \t'), len(text))
    quoted = False
    while index < len(text):
        if text[index] == '\\':
            end = index
            while end < len(text) and text[end] == '\\':
                end += 1
            escaped = (end - index) % 2
            index = end
            if index < len(text) and text[index] == '"' and escaped:
                index += 1
                continue
        if index < len(text) and text[index] == '"':
            if quoted and text[index:index + 2] == '""':
                index += 2
                continue
            quoted = not quoted
        index += 1
    return quoted


def _payload_high(event):
    if _uncertain(event):
        return False
    operand = _operand(event.get('registry.value'))
    return (_code_runner(operand) or is_user_writable(operand))


def _code_runner(operand):
    name = basename(operand)
    return name in SPAWNED_CODE_RUNNERS or name + '.exe' in SPAWNED_CODE_RUNNERS


def uac_registry_target(event):
    """One shared typed grammar for the standalone observation and temporal join."""
    target = _target(event)
    if target is None or target.root != _CU:
        return None
    key = _software(target)
    if key and len(key) == 5 and key[0] == 'classes' and (
            key[1] in _CLASSES or key[1].startswith('appx')) and key[2] == 'shell' and (
            key[3] in {'open', 'runas'}) and key[4] == 'command' and target.name in {
                '', 'delegateexecute', 'isolatedcommand', None}:
        return target, 'per-user class command registration'
    if (key and len(key) == 5 and key[:4] == ('microsoft', 'windows', 'currentversion', 'app paths')
            and key[4].endswith('.exe') and target.name in {'', 'path'}):
        return target, 'per-user App Paths registration'
    if (target.key, target.name) in { (('environment',), 'windir'),
                                    (('volatile environment',), 'systemroot')}:
        return target, 'per-user system-root environment override'
    return None


class UacRegistryHijack(_RegistryRule):
    id = 'win.uac_registry_hijack'
    version = '2'
    title = 'Per-user elevation-associated registry target changed'
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (12, 13))
    attack = ('T1548.002',)
    benign = ('application registration and administrative repair may change per-user associations',)
    next_checks = ('inspect the payload and any same-user elevated process start within ten minutes',)
    research = (_UAC_SOURCE, 'https://learn.microsoft.com/windows/win32/shell/app-registration')

    def _judge_target(self, event, target):
        found = uac_registry_target(event)
        if found is None:
            return []
        target, label = found
        if target.name == 'path':
            return self.report(event, target, 'uac_registry', label + ' search path')
        if target.action == 'written' and _unclosed_command_quotes(event.get('registry.value')):
            return [signal(event, 'uac_registry:unknown',
                f'{label} registry value was written with unclosed command quoting; its effect is unknown',
                self.attack, _REG_FIELDS, notes=_NO_EFFECT,
                content=json.dumps([target.root, target.key, target.name, target.action, event.get('registry.value')]))]
        key = _software(target)
        high = _payload_high(event)
        if label == 'per-user App Paths registration':
            high = (key[-1] in AUTO_ELEVATED_BINARIES or key[-1] in SYSTEM_BINARIES
                    or _code_runner(_operand(event.get('registry.value'))))
        elif key and key[0] == 'classes':
            if key[1] in {'ms-settings', 'mscfile', 'launcher.systemsettings'}:
                value = event.get('registry.value')
                high = isinstance(value, str) and bool(value.strip()) and value.strip().casefold() != '(empty)'
            elif key[1] in {'folder', 'exefile'}:
                high = _code_runner(_operand(event.get('registry.value')))
        return self.report(event, target, 'uac_registry', label,
                           high=target.action == 'written' and high and not _uncertain(event))


class SecurityControlRegistry(_RegistryRule):
    id = 'win.security_control_registry'
    version = '1'
    title = 'Security-control registry configuration changed'
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (12, 13))
    attack = ('T1548.002', 'T1685.001', 'T1685', 'T1112')
    benign = ('administrative policy deployment may intentionally change these settings',)
    next_checks = ('confirm the intended policy and the actual enforcement state',)
    research = (_REGISTRY_SOURCE,
        'https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration/',
        'https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows')

    def _judge_target(self, event, target):
        software, system = _software(target), _system(target)
        branch, desired, high = None, None, False
        if target.root == _LM and software == ('microsoft', 'windows', 'currentversion', 'policies', 'system') and target.name == 'enablelua':
            branch, desired, high = 'UAC EnableLUA policy', 0, True
        policy = software[1:] if software and software[0] == 'policies' else software
        logging_key_deleted = (policy == ('microsoft', 'windows', 'powershell', 'scriptblocklogging')
                               and target.name is None and target.action == 'deleted')
        if policy == ('microsoft', 'windows', 'powershell', 'scriptblocklogging') and (
                target.name == 'enablescriptblocklogging' or logging_key_deleted):
            branch, desired, high = 'PowerShell script-block logging policy', 0, True
        if system == ('control', 'session manager', 'environment') and target.name == '__pslockdownpolicy':
            if target.action != 'deleted':
                return []
            branch, high = 'PowerShell lockdown-policy environment value', True
        if policy and len(policy) == 5 and policy[:2] == ('microsoft', 'office') and policy[-1] == 'security' and target.name == 'accessvbom':
            branch, desired = 'Office programmatic VBA project access', 1
        if system == ('services', 'lanmanserver', 'parameters') and target.name == 'nullsessionpipes':
            branch = 'SMB anonymous named-pipe exception list'
        if branch is None:
            return []
        deleted = target.action == 'deleted'
        if deleted and high and (logging_key_deleted or target.name in {'enablescriptblocklogging', '__pslockdownpolicy'}):
            return [signal(event, 'security_control_deleted', f'{branch} registry target was deleted; effective state is unknown',
                self.attack, _REG_FIELDS, lane='high', severity='high', notes=_NO_EFFECT,
                content=json.dumps([target.key, target.name, 'deleted']))]
        return self.report(event, target, 'security_control', branch, high=high,
                           numeric={desired} if desired is not None else None, multi=True)


class RegistryPersistenceExtension(_RegistryRule):
    id = 'win.registry_persistence_extension'
    version = '1'
    title = 'Registry extension or persistence-capable configuration changed'
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 13),)
    attack = ('T1547.008', 'T1546.011', 'T1547.012', 'T1547.010', 'T1112')
    benign = ('backup, printer, application compatibility and management tooling register extension paths',)
    next_checks = ('inspect the exact payload, signer, writer and subsequent loads or process starts',)
    research = tuple('https://attack.mitre.org/techniques/' + value + '/' for value in (
        'T1547/008', 'T1546/011', 'T1547/012', 'T1547/010'))

    def _judge_target(self, event, target):
        software, system = _software(target), _system(target)
        value = event.get('registry.value')
        operand = _operand(value)
        code = isinstance(value, str) and basename(operand).endswith('.dll')
        label, high = None, False
        if system == ('services', 'ntds') and target.name == 'directoryserviceextpt':
            label, high = 'Directory-service extension DLL', code and is_remote_path(operand)
        prefix = ('microsoft', 'windows nt', 'currentversion', 'appcompatflags')
        if software and len(software) >= 6 and software[:4] == prefix and software[4] in {'custom', 'installedsdb'}:
            label = 'Application compatibility database registration'
            parts = components(value)
            high = (isinstance(value, str) and value.casefold().endswith('.sdb')
                    and any(parts[index:index + 3] == ('windows', 'apppatch', 'custom')
                            for index in range(max(0, len(parts) - 2))))
        print_tail = (system[3:] if system and system[:3] == ('control', 'print', 'printers') else
                      software[5:] if software and software[:5] == ('microsoft', 'windows nt', 'currentversion', 'print', 'printers') else ())
        if len(print_tail) in {2, 3} and print_tail[1] == 'copyfiles' and target.name == 'module':
            label, high = 'Printer CopyFiles module registration', code and (is_remote_path(operand) or is_user_writable(operand))
        if software and software[:4] == ('microsoft', 'windows nt', 'currentversion', 'ports'):
            port_name = '\\'.join((*software[4:], target.name or ''))
            port_operand = port_name if basename(port_name).endswith('.dll') else operand
            if basename(port_operand).endswith('.dll'):
                label, high = 'Print port DLL configuration', is_remote_path(port_operand) or is_user_writable(port_operand)
        if software and len(software) == 7 and software[:6] == ('microsoft', 'windows', 'currentversion', 'windowsupdate', 'orchestrator', 'uscheduler') and target.name == 'cmdline':
            label, high = 'Update orchestrator command registration', _payload_high(event)
        if software and len(software) in {4, 5} and software[:4] == ('microsoft', 'ieak', 'grouppolicy', 'pendinggpos') and re.fullmatch(r'path\d*', target.name or ''):
            label = 'IEAK pending policy path'
        if target.name == 'symboliclinkvalue':
            label = 'Registry symbolic-link target value'
        if label is None:
            return []
        return self.report(event, target, 'extension_configuration', label,
                           high=bool(high) and not _uncertain(event), multi=True)


class _ElevationRows(CompactWindowsRows):
    def compact_fields(self, key):
        kind = json.loads(key)[0]
        if kind in {'boot', 'term'}:
            return FENCE_FIELDS
        if kind in {'parent', 'child'}:
            return frozenset((*_REG_FIELDS, 'event.code', 'event.channel', 'event.provider',
                              'process.executable', 'process.parent.executable', 'process.guid',
                              'process.parent.guid', 'process.integrity_level', 'process.command_line',
                              'process.user', 'user.entity_id', 'user.sid', 'user.name', 'user.domain'))
        return None

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            self.account = self.owner.state_budget().account(f'{self.owner.id}:windows_rows', strong=True)
            spill.cap()
            try:
                spill.db.execute('SAVEPOINT elevation_schema')
                spill.db.execute('CREATE TABLE IF NOT EXISTS windows_rows(k TEXT,id TEXT,ts REAL,value TEXT,event TEXT,raw TEXT,PRIMARY KEY(k,id))')
                spill.db.execute('CREATE INDEX IF NOT EXISTS windows_rows_time ON windows_rows(k,ts,id)')
                spill.db.execute('CREATE INDEX IF NOT EXISTS windows_rows_value ON windows_rows(k,value,ts)')
                spill.db.execute('CREATE TABLE IF NOT EXISTS windows_marks(k TEXT PRIMARY KEY,value TEXT)')
                spill.db.execute('RELEASE elevation_schema')
                self.ready = True
            except sqlite3.OperationalError as error:
                spill.db.rollback()
                raise spill.failed(error, account=self.account) from error
            finally:
                spill.grew()
        return spill


def _identity(event):
    sid = event.get('user.sid')
    entity = str(event.get('user.entity_id') or '')
    if sid or entity.startswith('sid:'):
        value = str(sid or entity[4:]).casefold()
        return row_key('sid', value) if re.fullmatch(r's-\d+(?:-\d+)+', value) and value != 's-1-0-0' else None
    key = entity[5:] if entity.startswith('name:') else event.get('process.user')
    if not isinstance(key, str):
        return None
    key = key.strip().casefold()
    separator = '\\' if '\\' in key else '@' if '@' in key else None
    return row_key('account', key) if separator and all(key.split(separator, 1)) else None


class AutoElevatedShell(Playbook):
    id = 'win.auto_elevated_shell'
    version = '2'
    title = 'Elevated shell started by an elevation-associated parent'
    families = ('process_exec', 'registry_change', 'process_termination', 'system_state')
    context_families = ('registry_change', 'process_termination', 'system_state')
    os_families = ('windows',)
    windows_event_classes = tuple((SYSMON_CHANNEL, SYSMON, code) for code in (1, 5, 13)) + (
        ('System', 'Microsoft-Windows-Kernel-General', 12), ('System', 'EventLog', 6005))
    kind = 'aggregate'
    assures_negative = False
    positive_only_reason = 'Starts and nearby registry writes do not prove abuse; missing state cannot prove no correlation.'
    attack = ('T1548.002',)
    card: ClassVar[dict] = {'behavior': title, 'telemetry': 'Sysmon process creation and registry value writes',
        'fidelity': 'High integrity and native same-host/account context, not proof UAC was bypassed.',
        'query_cost': 'Indexed disk-backed 600-second host/user intervals.',
        'benign_and_cost': 'Authorized elevated administration.', 'next_pivot': 'Inspect parent, payload and registry data.',
        'research_basis': _UAC_SOURCE}

    def __init__(self):
        super().__init__()
        self.rows = _ElevationRows(self)

    def _candidate(self, event):
        return (event.family == 'process_exec' and basename(event.get('process.executable')) in SPAWNED_CODE_RUNNERS
                and str(event.get('process.integrity_level') or '').casefold() in {'high', 'system'}
                and basename(event.get('process.parent.executable')) in AUTO_ELEVATED_BINARIES)

    def _parent_context(self, child):
        parent = basename(child.get('process.parent.executable'))
        if parent not in {'mmc.exe', 'dllhost.exe'}:
            return True, None
        guid = child.get('process.parent.guid')
        prior = self.rows.prior(row_key('parent', child.host, guid), child.ts.timestamp(), float('inf')) if guid and self.rows.ready else None
        if prior is None:
            self.note_limit('elevation_parent', 'The constrained elevation parent command line was not retained; the child remains a lead.')
            return False, None
        event, raw = prior
        if basename(event.get('process.executable')) != parent:
            self.note_limit('elevation_parent', 'Retained parent GUID context conflicts with the recorded parent image.')
            return False, None
        parent_key = row_key('parent', child.host, guid)
        alternatives = self.rows.store().execute(
            'SELECT value FROM windows_rows WHERE k=? AND ts<=? GROUP BY value LIMIT 2',
            (parent_key, child.ts.timestamp())).fetchall()
        boot = self.rows.prior(row_key('boot', child.host), child.ts.timestamp(), float('inf'))
        term = self.rows.prior(row_key('term', child.host, guid), child.ts.timestamp(), float('inf'))
        if len(alternatives) > 1 or any(fence and fence[0].ts >= event.ts for fence in (boot, term)):
            self.note_limit('elevation_parent', 'Parent context is ambiguous or crosses a recorded boot/termination fence.')
            return False, None
        args = split_argv(str(event.get('process.command_line') or ''))
        if parent == 'mmc.exe':
            qualified = any(arg.casefold().endswith('.msc') and is_user_writable(arg) for arg in args[1:])
        else:
            qualified = any(arg.casefold().startswith('/processid:') and arg.split(':', 1)[1].casefold() in ELEVATION_COM_CLSIDS for arg in args[1:])
        return qualified, (event, raw) if qualified else None

    def _match(self, child, child_raw):
        user = _identity(child)
        qualifying_parent, parent_context = self._parent_context(child)
        registry = self.rows.prior(row_key('write', child.host, user), child.ts.timestamp(), 600) if user and self.rows.ready else None
        high = registry is not None and qualifying_parent
        events, raw = [child], dict(child_raw)
        contexts = set()
        if parent_context:
            parent, copies = parent_context
            events.append(parent)
            contexts.add(parent.id)
            raw.update(copies)
        if high:
            written, copies = registry
            events.append(written)
            contexts.add(written.id)
            raw.update(copies)
        text = (f'A {child.get("process.integrity_level")} integrity {child.get("process.executable")} started '
                f'with recorded parent {child.get("process.parent.executable")} on {child.host}. ')
        if high:
            seconds = child.ts.timestamp() - written.ts.timestamp()
            text += f'A same-host/same-user elevation-associated registry write preceded it by {seconds:g} seconds, within 10 minutes.'
        else:
            text += 'A preceding same-host/same-user registry write within 10 minutes was not established; correlation may be incomplete.'
        return Match(self.id, text, 'aggregate_observation', events,
            [pf(event, name) for event in events for name in (*_REG_FIELDS, 'process.executable',
                'process.parent.executable', 'process.integrity_level', 'process.command_line', 'process.user') if event.has(name)],
            child.ts, 'high' if high else 'medium', 'high' if high else 'lead', 'medium', child.entities(),
            ['The temporal association is a hypothesis, not proof the registry write caused elevation.'],
            group_key='elevated-child:' + child.id, context_ids=contexts, raw_copies=raw,
            bounded_revision=True, revision_reason='Indexed native context revised the elevated-child observation.')

    def consume(self, events):
        out = []
        for event in sorted(self.applicable(events), key=lambda item: (item.ts, item.id)):
            try:
                if event.family == 'registry_change':
                    target = uac_registry_target(event)
                    user = _identity(event)
                    if target and target[0].action == 'written' and user:
                        self.rows.put(row_key('write', event.host, user), event)
                    elif target and target[0].action == 'written':
                        self.note_limit('elevation_actor', 'An elevation-associated registry write lacks a resolved actor; same-user correlation is incomplete.')
                elif event.family == 'process_exec':
                    if basename(event.get('process.executable')) in {'mmc.exe', 'dllhost.exe'} and event.get('process.guid'):
                        fingerprint = row_key(event.get('process.executable'), event.get('process.command_line'),
                                              _identity(event), event.ts.replace(microsecond=0).isoformat())
                        self.rows.put(row_key('parent', event.host, event.get('process.guid')), event, fingerprint)
                    if self._candidate(event):
                        try:
                            self.rows.put(row_key('child', event.host, _identity(event)), event)
                        finally:
                            out.append(self._match(event, self.raw_of(event)))
                elif event.family == 'system_state' and event.get('event.code') in {12, 6005}:
                    self.rows.put(row_key('boot', event.host), event)
                elif event.family == 'process_termination' and event.get('process.guid'):
                    parent_key = row_key('parent', event.host, event.get('process.guid'))
                    if self.rows.ready and self.rows.store().execute('SELECT 1 FROM windows_rows WHERE k=? LIMIT 1', (parent_key,)).fetchone():
                        self.rows.put(row_key('term', event.host, event.get('process.guid')), event)
            except StateExhausted as error:
                self.note_limit('elevation_history', f'Correlation history was refused by the physical budget: {error}')
                if self._candidate(event) and not any(event.id == match.events[0].id for match in out):
                    out.append(self._match(event, self.raw_of(event)))
        return out

    def finalize(self):
        if not self.rows.ready:
            return
        for _key, child, raw, _ in self.rows.iterate(prefix='["child",'):
            yield self._match(child, raw)

    def release_state(self):
        self.rows.close()
        super().release_state()


ELEVATION_EVENT_RULES = (UacRegistryHijack, AutoElevatedShell, SecurityControlRegistry, RegistryPersistenceExtension)
