"""Typed observations of Windows application, boot and service-provider events."""
from __future__ import annotations

import json
from typing import ClassVar

from romulus.detect.windows_behavior import BehaviorFleetRule
from romulus.detect.windows_cmdline import is_user_writable
from romulus.detect.windows_events import WindowsEventRule, basename, signal
from romulus.evidence.windows_catalog import SECURITY

_EXIT = 'Microsoft-Windows-ProcessExitMonitor'
_LSP = 'Microsoft-Windows-Winsock-WS2HELP'
_SQL = 'https://learn.microsoft.com/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option'
_BOOT = 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4826'


def _content(event, fields):
    return json.dumps([event.get(name) for name in fields], separators=(',', ':'), sort_keys=True)


def _text(event, field, absent='unrecorded'):
    return WindowsEventRule.describe(event.get(field)) if event.has(field) else absent


class SilentProcessExitLsass(WindowsEventRule):
    id = 'win.silent_process_exit_lsass'
    version = '1'
    title = 'Silent process-exit monitoring recorded LSASS termination'
    families = ('silent_process_exit',)
    windows_event_classes = (('Application', _EXIT, 3001),)
    required_fields = ('monitor.exited_image',)
    attack = ('T1003.001',)
    benign = ('intentional process-exit diagnostics may monitor sensitive processes',)
    next_checks = ('inspect the monitor configuration and any recorded dump files',)
    research = ('https://learn.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit',)

    def judge(self, event):
        if basename(event.get('monitor.exited_image')) != 'lsass.exe':
            return []
        fields = ('monitor.exited_image', 'monitor.initiating_image', 'monitor.exit_code')
        return [signal(event, 'silent_exit_lsass',
            f'A silent process-exit monitor recorded termination of lsass.exe by '
            f'{_text(event, "monitor.initiating_image")} (exit code {_text(event, "monitor.exit_code")})',
            self.attack, fields, lane='high', severity='high', content=_content(event, fields),
            notes=('The event records termination monitoring; it does not establish that a dump was created.',))]


class _MssqlOption(WindowsEventRule):
    families = ('database_audit',)
    windows_event_classes = (('Application', 'MSSQLSERVER', 15457),)
    required_fields = ('db.action', 'db.option.name', 'db.option.new')
    attack = ('T1505.001',)
    benign = ('DBA maintenance may intentionally change the option',)
    next_checks = ('inspect SQL audit execute records and the initiating principal',)
    research = (_SQL,)
    desired = '1'

    def judge(self, event):
        if (event.get('db.action') != 'option_changed'
                or str(event.get('db.option.name') or '').strip().casefold() != 'xp_cmdshell'
                or str(event.get('db.option.new')) != self.desired):
            return []
        fields = ('db.instance', 'db.option.name', 'db.option.old', 'db.option.new')
        lane = 'high' if self.desired == '1' else 'lead'
        return [signal(event, 'option_' + self.desired,
            f'MSSQL recorded the xp_cmdshell option changed from {_text(event, "db.option.old")} '
            f'to {self.desired} on instance {_text(event, "db.instance")}', self.attack, fields,
            lane=lane, severity='high' if lane == 'high' else 'medium', content=_content(event, fields))]


class MssqlXpCmdshellEnabled(_MssqlOption):
    id = 'win.mssql_xp_cmdshell_enabled'
    version = '1'
    title = 'SQL Server enabled the command-shell option'


class MssqlXpCmdshellDisabled(_MssqlOption):
    id = 'win.mssql_xp_cmdshell_disabled'
    version = '1'
    title = 'SQL Server disabled the command-shell option'
    desired = '0'


class MssqlXpCmdshellExec(WindowsEventRule):
    id = 'win.mssql_xp_cmdshell_exec'
    version = '1'
    title = 'SQL Server audited a command-shell execute operation'
    families = ('database_audit',)
    windows_event_classes = tuple((channel, provider, 33205) for channel in ('Application', 'Security')
                                  for provider in ('MSSQLSERVER', 'MSSQLSERVER$AUDIT'))
    required_fields = ('db.action', 'db.audit.object_name', 'db.audit.action_id')
    attack = ('T1059.003', 'T1505.001')
    benign = ('authorized DBA and legacy maintenance tools may use this procedure',)
    next_checks = ('review the recorded statement, server principal and client address',)
    research = (_SQL, 'https://learn.microsoft.com/sql/relational-databases/security/auditing/sql-server-audit-records')

    def judge(self, event):
        if (event.get('db.action') != 'audit_record'
                or str(event.get('db.audit.object_name') or '').strip().casefold() != 'xp_cmdshell'
                or str(event.get('db.audit.action_id') or '').strip().upper() != 'EX'):
            return []
        failed = event.get('db.audit.succeeded') is False
        fields = ('db.instance', 'db.audit.action_id', 'db.audit.object_name', 'db.audit.succeeded',
                  'db.audit.database', 'db.audit.server_principal', 'db.audit.client_ip', 'db.audit.statement')
        text = ('SQL Server audit recorded an attempted execute operation of xp_cmdshell that failed'
                if failed else 'SQL Server audit recorded an xp_cmdshell execute operation')
        text += (f' on database {_text(event, "db.audit.database")} by '
                 f'{_text(event, "db.audit.server_principal")} from {_text(event, "db.audit.client_ip")}')
        if event.has('db.audit.statement'):
            text += f'; statement: {_text(event, "db.audit.statement")}'
        return [signal(event, 'execute_failed' if failed else 'execute', text, self.attack, fields,
            lane='lead' if failed else 'high', severity='medium' if failed else 'high',
            content=_content(event, fields),
            notes=('An SQL audit operation does not prove the resulting operating-system command succeeded.',))]


class MssqlXpCmdshellBlocked(WindowsEventRule):
    id = 'win.mssql_xp_cmdshell_blocked'
    version = '1'
    title = 'SQL Server blocked a command-shell procedure request'
    families = ('database_audit',)
    windows_event_classes = (('Application', 'MSSQLSERVER', 15281),)
    required_fields = ('db.action', 'db.blocked.procedure')
    attack = ('T1505.001',)
    benign = ('legacy administration software may request a disabled procedure',)
    next_checks = ('identify the requesting principal and application',)
    research = (_SQL,)

    def judge(self, event):
        if (event.get('db.action') != 'procedure_blocked'
                or str(event.get('db.blocked.procedure') or '').strip().casefold() != 'xp_cmdshell'):
            return []
        fields = ('db.instance', 'db.blocked.procedure')
        return [signal(event, 'blocked', 'SQL Server blocked a request to xp_cmdshell on instance '
            + _text(event, 'db.instance'), self.attack, fields, content=_content(event, fields),
            notes=('The server refusal does not establish command execution.',))]


class BootConfigIntegrityDisabled(WindowsEventRule):
    id = 'win.boot_config_integrity_disabled'
    version = '1'
    title = 'Boot configuration enabled debugging or relaxed integrity policy'
    families = ('boot_configuration',)
    windows_event_classes = (('Security', SECURITY, 4826),)
    attack = ('T1553.006',)
    benign = ('driver-development systems may intentionally enable these settings',)
    next_checks = ('confirm the boot settings against the intended host role',)
    research = (_BOOT,)
    settings: ClassVar[dict[str, str]] = {'boot.test_signing': 'test signing', 'boot.kernel_debug': 'kernel debugging',
                'boot.disable_integrity_checks': 'disabled integrity checks',
                'boot.hypervisor_debug': 'hypervisor debugging'}

    def judge(self, event):
        observed = [name for name in self.settings if event.has(name)]
        if not observed:
            self.note_coverage('boot_settings', 'No recognized boot-integrity setting was recorded.')
            return []
        enabled = [name for name in observed if event.get(name) is True]
        if not enabled:
            return []
        return [signal(event, 'integrity_configuration',
            'Boot Configuration Data loaded with enabled settings: '
            + ', '.join(self.settings[name] for name in enabled), self.attack, tuple(enabled),
            lane='high', severity='high', content=json.dumps(enabled))]


class NtdsDatabaseCopy(WindowsEventRule):
    id = 'win.ntds_database_copy'
    version = '1'
    title = 'ESENT recorded an NTDS database lifecycle operation'
    families = ('ese_database',)
    windows_event_classes = tuple(('Application', 'ESENT', code) for code in (216, 325, 326, 327))
    required_fields = ('ese.action', 'ese.database_path')
    attack = ('T1003.003',)
    benign = ('domain-controller promotion and backup products can mount NTDS databases',)
    next_checks = ('inspect the recorded database path and the creating or attaching process',)
    research = ('https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530(v=ws.11)',)

    def judge(self, event):
        action = event.get('ese.action')
        if basename(event.get('ese.database_path')) != 'ntds.dit' or action not in {'created', 'attached', 'detached'}:
            return []
        fields = ('ese.database_path', 'ese.action', 'ese.pid')
        high = action != 'detached'
        return [signal(event, str(action), f'ESENT recorded an ntds.dit database {action} at '
            f'{_text(event, "ese.database_path")} by process pid {_text(event, "ese.pid")}',
            self.attack, fields, lane='high' if high else 'lead', severity='high' if high else 'medium',
            content=_content(event, ('ese.database_path', 'ese.action')),
            common=f'ESENT recorded an ntds.dit database {action} at {_text(event, "ese.database_path")}',
            notes=('A lifecycle record does not establish that credentials were extracted.',))]


class LspInstalled(BehaviorFleetRule):
    id = 'win.lsp_installed'
    version = '1'
    title = 'Winsock recorded a layered service-provider installation'
    families = ('winsock_catalog',)
    windows_event_classes = ((_LSP + '/Operational', _LSP, 1),)
    required_fields = ('lsp.name',)
    attack = ('T1547',)
    benign = ('VPN, proxy and endpoint-security software can install LSPs',)
    next_checks = ('inspect the installer lineage and the service-provider module signature',)
    research = ('https://learn.microsoft.com/windows/win32/winsock/installation-and-configuration-functions-2',)

    def fleet_eligible(self, event, hit):
        return hit.lane == 'lead'

    def judge(self, event):
        fields = ('lsp.name', 'lsp.catalog', 'lsp.installer', 'lsp.guid')
        high = is_user_writable(str(event.get('lsp.installer') or ''))
        return [signal(event, 'lsp_installed', f'A Winsock LSP {_text(event, "lsp.name")} was installed '
            f'in the {_text(event, "lsp.catalog")}-bit catalog by {_text(event, "lsp.installer")}',
            self.attack, fields, lane='high' if high else 'lead', severity='high' if high else 'medium',
            content=_content(event, fields),
            notes=('The installation alone does not establish malicious persistence.',))]


class MsiInstallFromUrl(WindowsEventRule):
    id = 'win.msi_install_from_url'
    version = '1'
    title = 'Windows Installer began a transaction for a URL package'
    families = ('msi_install',)
    windows_event_classes = tuple(('Application', 'MsiInstaller', code) for code in (1040, 1042))
    required_fields = ('msi.action', 'msi.package', 'msi.package_kind')
    attack = ('T1218.007',)
    benign = ('enterprise installers and updaters can retrieve packages from URLs',)
    next_checks = ('inspect the package, its URL and the client process',)
    research = ('https://learn.microsoft.com/windows/win32/msi/event-logging',)

    def judge(self, event):
        action = event.get('msi.action')
        if action not in {'transaction_begin', 'transaction_end'} or event.get('msi.package_kind') != 'url':
            return []
        fields = ('msi.package', 'msi.package_kind', 'msi.action', 'msi.client_pid')
        verb = 'began' if action == 'transaction_begin' else 'ended'
        return [signal(event, 'url_package', f'A Windows Installer transaction {verb} for a package at '
            f'{_text(event, "msi.package")} (client pid {_text(event, "msi.client_pid")})',
            self.attack, fields, content=_content(event, ('msi.package',)),
            common='A Windows Installer transaction lifecycle record for a package at ' + _text(event, 'msi.package'),
            notes=('A transaction lifecycle record does not prove successful installation or payload execution.',))]


CATALOG_EVENT_RULES = (SilentProcessExitLsass, MssqlXpCmdshellEnabled, MssqlXpCmdshellDisabled,
    MssqlXpCmdshellExec, MssqlXpCmdshellBlocked, BootConfigIntegrityDisabled, NtdsDatabaseCopy,
    LspInstalled, MsiInstallFromUrl)
