"""Explicit Sigma logsource and field mappings onto existing typed telemetry."""
from __future__ import annotations

from dataclasses import dataclass

from romulus.evidence.windows_catalog import (
    EVENT_CLASSES,
    LEGACY_POWERSHELL_CHANNEL,
    POWERSHELL_CHANNEL,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
)


@dataclass(frozen=True)
class LogsourceRow:
    product: str
    key: str
    value: str
    families: tuple[str, ...]
    rationale: str
    codes: tuple[int, ...] = ()
    channels: tuple[str, ...] = ()
    scope: tuple[tuple[str, tuple[str, ...]], ...] = ()


# A category selects a typed observation, never the wording of an untyped record.
# Service rows select all catalogued classes in that native channel. EventID
# selectors remain predicates: narrowing from a possibly negated selector loses data.
LOGSOURCE_TABLE = (
    LogsourceRow("windows", "category", "process_creation", ("process_exec",),
                 "Sysmon 1 and Security 4688 are native process-creation observations."),
    LogsourceRow("windows", "category", "network_connection", ("net_socket", "network_filter"),
                 "Sysmon 3 and WFP 5156 type connections; socket-bind WFP 5158 is excluded.", (3, 5156)),
    LogsourceRow("windows", "category", "file_event", ("file_change",),
                 "Sysmon 11 records file creation independently of deletion or other file actions.", (11,)),
    LogsourceRow("windows", "category", "file_delete", ("file_change",),
                 "Sysmon 23 and 26 record file deletion with and without archival.", (23, 26)),
    LogsourceRow("windows", "category", "file_change", ("file_change",),
                 "Sysmon 2 records file creation-time changes.", (2,)),
    LogsourceRow("windows", "category", "create_stream_hash", ("file_change",),
                 "Sysmon 15 records creation of a named file stream and its hash.", (15,)),
    LogsourceRow("windows", "category", "file_executable_detected", ("file_change",),
                 "Sysmon 29 records executable-file detection.", (29,)),
    LogsourceRow("windows", "category", "registry_event", ("registry_change",),
                 "Sysmon and Security registry events preserve native paths, operations and values."),
    LogsourceRow("windows", "category", "registry_add", ("registry_change",),
                 "Sysmon 12 creation is distinguished from deletion by its native EventType.", (12,),
                 scope=(("registry.event_type", ("CreateKey", "CreateValue")),)),
    LogsourceRow("windows", "category", "registry_delete", ("registry_change",),
                 "Sysmon 12 deletion is distinguished from creation by its native EventType.", (12,),
                 scope=(("registry.event_type", ("DeleteKey", "DeleteValue")),)),
    LogsourceRow("windows", "category", "registry_set", ("registry_change",),
                 "Sysmon 13 and Security 4657 record a registry value written or modified.", (13, 4657)),
    LogsourceRow("windows", "category", "registry_rename", ("registry_change",),
                 "Sysmon 14 records the old and new registry object name.", (14,)),
    LogsourceRow("windows", "category", "image_load", ("image_load",),
                 "Sysmon 7 records a loaded image independently of the owning process image.", (7,)),
    LogsourceRow("windows", "category", "driver_load", ("image_load",),
                 "Sysmon 6 records a loaded driver, with the same typed loaded-image fields.", (6,)),
    LogsourceRow("windows", "category", "pipe_created", ("pipe_event",),
                 "Sysmon 17 and 18 record named-pipe creation and connection.", (17, 18)),
    LogsourceRow("windows", "category", "dns_query", ("dns_lookup",),
                 "Sysmon 22 types the queried name and owning process."),
    LogsourceRow("windows", "category", "ps_script", ("script_block",),
                 "PowerShell 4104 records script text; module and engine messages are distinct.", (4104,)),
    LogsourceRow("windows", "service", "security", (),
                 "Security service rules read only catalogued Security-channel native classes.", channels=("Security",)),
    LogsourceRow("windows", "service", "system", (),
                 "System service rules read only catalogued System-channel native classes.", channels=("System",)),
    LogsourceRow("windows", "service", "sysmon", (),
                 "Sysmon service rules read only catalogued Sysmon operational native classes.", channels=(SYSMON_CHANNEL,)),
    LogsourceRow("windows", "service", "powershell", (),
                 "Both modern and legacy PowerShell channels have explicitly typed script observations.",
                 channels=(POWERSHELL_CHANNEL, LEGACY_POWERSHELL_CHANNEL)),
    LogsourceRow("linux", "category", "process_creation", ("process_exec",),
                 "Auditd EXECVE plus SYSCALL types execution and argv; no full command-line string is inferred."),
    LogsourceRow("linux", "category", "auditd", (
        "process_exec", "process_observed", "net_socket", "file_change", "auth", "account_change",
        "service_change", "system_state", "audit_config"),
                 "Only audit-header-bearing typed events represent auditd, excluding journal events in the same family."),
    LogsourceRow("linux", "service", "auditd", (
        "process_exec", "process_observed", "net_socket", "file_change", "auth", "account_change",
        "service_change", "system_state", "audit_config"),
                 "Only audit-header-bearing typed events represent auditd, excluding journal events in the same family."),
    LogsourceRow("*", "category", "dns", ("dns_query", "dns_lookup"),
                 "Observer and endpoint DNS families type queried names; response bodies are not searched."),
    LogsourceRow("*", "category", "proxy", ("http_tx", "http_access", "net_session"),
                 "Typed HTTP transaction/access/session fields retain URL, method and status without searching payloads."),
    LogsourceRow("*", "category", "firewall", ("net_flow", "net_socket", "net_session"),
                 "Typed endpoint tuples support flow observations; an allow/deny decision is not invented."),
)

_PROCESS = {
    "Image": "process.executable", "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable", "ParentCommandLine": "process.parent.command_line",
    "OriginalFileName": "process.original_file_name", "User": "process.user",
    "IntegrityLevel": "process.integrity_level", "ProcessId": "process.pid", "ParentProcessId": "process.ppid",
    "ProcessGuid": "process.guid", "ParentProcessGuid": "process.parent.guid", "ParentUser": "process.parent.user",
    "CurrentDirectory": "process.current_directory", "Company": "process.company", "Product": "process.product",
    "Description": "process.description", "FileVersion": "process.file_version",
}
_NETWORK = {
    "SourceIp": "source.ip", "SourcePort": "source.port", "SourceHostname": "source.hostname",
    "DestinationIp": "destination.ip", "DestinationPort": "destination.port",
    "DestinationHostname": "destination.hostname", "Protocol": "network.transport",
}
_FILE = {"TargetFilename": "file.path", "Contents": "file.stream.content"}
_REGISTRY = {"TargetObject": "registry.path", "Details": "registry.value", "NewName": "registry.new_path",
             "EventType": "registry.event_type", "ObjectValueName": "registry.value_name"}
_IMAGE = {"ImageLoaded": "image.path", "Signed": "image.signed", "Signature": "image.signature",
          "SignatureStatus": "image.signature_status", "OriginalFileName": "image.original_file_name"}
_SCRIPT = {"ScriptBlockText": "script.text", "ScriptBlockId": "script.block_id", "Path": "script.path",
           "HostApplication": "script.host_application", "Payload": "script.text"}
_SERVICE = {"ServiceName": "service.name", "ImagePath": "service.image_path", "ServiceFileName": "service.image_path",
            "ServiceType": "service.type", "StartType": "service.start_type", "ServiceAccount": "service.account"}
_AUTH = {"SubjectUserName": "user.name", "SubjectDomainName": "user.domain",
         "TargetUserName": "account.name", "TargetDomainName": "account.domain",
         "LogonType": "auth.logon_type", "AuthenticationPackageName": "auth.package",
         "LogonProcessName": "auth.logon_process", "IpAddress": "source.ip", "IpPort": "source.port"}
_COMMON_WINDOWS = {"EventID": "event.code", "Channel": "event.channel", "Provider_Name": "event.provider",
                   "Computer": "host.name"}
_LINUX = {"Image": "process.executable", "exe": "process.executable", "comm": "process.comm",
          "User": "process.user", "uid": "process.uid", "euid": "process.euid", "auid": "process.auid",
          "pid": "process.pid", "ppid": "process.ppid", "CurrentDirectory": "process.cwd",
          "TargetFilename": "file.path", "ServiceName": "service.name"}
_GENERIC_NETWORK = {**_NETWORK, "src_ip": "source.ip", "dst_ip": "destination.ip", "src_port": "source.port",
                    "dst_port": "destination.port", "src": "source.ip", "dst": "destination.ip"}
_DNS = {"QueryName": "dns.question.name", "query": "dns.question.name", "QueryResults": "dns.answers"}
_PROXY = {"url": ["url.original", "url.path"], "c-uri": ["url.original", "url.path"],
          "cs-uri": ["url.original", "url.path"], "cs-uri-stem": "url.path", "cs-method": "http.request.method",
          "cs-host": "http.hostname", "sc-status": "http.response.status_code",
          "c-useragent": "user_agent.original", "UserAgent": "user_agent.original"}
_NUMERIC = {"event.code", "process.pid", "process.ppid", "source.port", "destination.port",
            "http.response.status_code", "dns.status"}

_HASH_FIELDS = {f'{namespace}.hash.{algorithm}' for namespace in ('file', 'image')
                for algorithm in ('md5', 'sha1', 'sha256', 'imphash')}
_PROCESS_BASIC = {'process.executable', 'process.pid', 'process.guid', 'process.user'}
_FILE_CATEGORIES = {'file_event', 'file_delete', 'file_change', 'create_stream_hash',
                    'file_executable_detected'}


def _windows_fields(event):
    """Fields whose absence is observable in this native class, not merely its family.

    Only class-declared fields are usable, even if extra native keys reached the
    shared normalizer helper. Version-dependent absence is specified separately.
    """
    fields = set(_COMMON_WINDOWS.values())
    code = event.event_id
    if event.provider == SYSMON:
        if code == 1:
            fields.update(_PROCESS.values())
            fields.update(name for name in _HASH_FIELDS if name.startswith('file.'))
        elif code in {2, 3, 5, 7, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25, 26, 29}:
            fields.update(_PROCESS_BASIC)
        if code == 3:
            fields.update(_NETWORK.values())
        if code in {2, 11, 15, 23, 26, 29}:
            fields.add('file.path')
        if code in {15, 23, 26, 29}:
            fields.update(name for name in _HASH_FIELDS if name.startswith('file.'))
        if code == 15:
            fields.add('file.stream.content')
        if code in {6, 7}:
            fields.update(_IMAGE.values())
            fields.update(name for name in _HASH_FIELDS if name.startswith('image.'))
        if code in {12, 13, 14}:
            fields.update({'registry.path', 'registry.event_type'})
        if code == 13:
            fields.add('registry.value')
        if code == 14:
            fields.add('registry.new_path')
        if code in {17, 18}:
            fields.add('pipe.name')
        if code == 22:
            fields.update(_DNS.values())
    elif event.provider == SECURITY:
        if code == 4688:
            fields.update({'process.executable', 'process.command_line', 'process.pid', 'process.ppid',
                           'process.parent.executable'})
        elif code == 4689:
            fields.update({'process.executable', 'process.pid'})
        if event.family in {'auth', 'account_change', 'service_change', 'registry_change',
                            'object_access', 'scheduled_task', 'directory_access', 'directory_change'} or code in {4688, 4689}:
            fields.update({'user.name', 'user.domain'})
        if event.family == 'account_change' or code in {4624, 4625, 4648, 4768, 4769, 4770, 4771, 4776}:
            fields.update({'account.name', 'account.domain'})
        if code in {4624, 4625, 4634}:
            fields.add('auth.logon_type')
        if code in {4624, 4625, 4776}:
            fields.add('auth.package')
        if code in {4624, 4625}:
            fields.add('auth.logon_process')
        if code in {4624, 4625, 4648}:
            fields.update({'process.executable', 'process.pid'})
        if code in {4624, 4625, 4648, 4768, 4769, 4770, 4771}:
            fields.update({'source.ip', 'source.port'})
        if code in {4768, 4769, 4770, 4771}:
            fields.add('auth.service_name')
        if code == 4697:
            fields.update(_SERVICE.values())
        if code == 4657:
            fields.update({'process.executable', 'process.pid', 'registry.path', 'registry.value',
                           'registry.value_name'})
        if code in {5156, 5158}:
            fields.update({'wfp.application', 'process.pid', 'source.ip', 'source.port',
                           'destination.ip', 'destination.port', 'network.transport'})
    elif event.family == 'service_change':
        fields.update(_SERVICE.values() if code == 7045 else {'service.name', 'service.start_type'})
    elif event.family == 'script_block':
        if code == 4104:
            fields.update({'script.text', 'script.block_id', 'script.path'})
        elif code == 4103:
            fields.add('script.text')
        elif code in {400, 403, 800}:
            fields.add('script.host_application')
            if code == 800:
                fields.add('script.text')
    return fields


# Non-Windows families have no native EventID. These are the mapped fields the
# existing normalizers can retain; a delivered typed value is always authoritative.
_FAMILY_FIELDS = {
    'process_exec': set(_LINUX.values()) - {'file.path', 'service.name'},
    'process_observed': set(_LINUX.values()) - {'file.path', 'service.name'},
    'file_change': {'file.path', 'process.executable', 'process.pid', 'process.uid'},
    'service_change': {'service.name', 'process.pid'},
    'net_flow': set(_NETWORK.values()) - {'source.hostname', 'destination.hostname'},
    'net_socket': set(_NETWORK.values()) - {'source.hostname', 'destination.hostname'},
    'dns_query': {'dns.question.name', 'dns.answers', 'source.ip', 'source.port',
                  'destination.ip', 'destination.port', 'network.transport'},
    'http_tx': {'url.original', 'http.request.method', 'http.hostname', 'http.response.status_code',
                'user_agent.original', 'source.ip', 'source.port', 'destination.ip', 'destination.port'},
    'http_access': {'url.original', 'http.request.method', 'http.response.status_code',
                    'user_agent.original', 'source.ip'},
    # Session rows may represent protocols other than HTTP. An absent application
    # field cannot prove a negative without a protocol-specific native class.
    'net_session': {'source.ip', 'source.port', 'destination.ip', 'destination.port', 'network.transport',
                    'url.path', 'http.hostname', 'http.request.method', 'http.response.status_code',
                    'user_agent.original'},
}


def _targets(fields):
    result = set()
    for value in fields.values():
        result.update(value['hashes'].values() if isinstance(value, dict) else
                      value if isinstance(value, list) else [value])
    return result


def _grouping_fields(category):
    if category == 'process_creation':
        return ['process.executable', 'process.parent.executable']
    if category == 'network_connection':
        return ['destination.ip', 'destination.hostname', 'destination.port']
    if category in {'dns', 'dns_query'}:
        return ['dns.question.name']
    if category in _FILE_CATEGORIES:
        return ['file.path']
    if category.startswith('registry_'):
        return ['registry.path']
    return []


def _field_names(selectors):
    names = set()
    pending = list(selectors.values()) if isinstance(selectors, dict) else []
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            names.update(key.split("|", 1)[0] for key in item if isinstance(key, str))
        elif isinstance(item, list):
            pending.extend(value for value in item if isinstance(value, (dict, list)))
    return sorted(names)


def _fields(product, category, service, families):
    if product == "linux":
        return {key: value for key, value in _LINUX.items()
                if category != 'process_creation' or key not in {'TargetFilename', 'ServiceName'}}
    if product == "windows":
        fields = dict(_COMMON_WINDOWS)
        if category != "ps_script" and service not in {"powershell", "system"}:
            fields.update(_PROCESS)
        specialized = {"network_connection": _NETWORK, "file_event": _FILE,
            "registry_event": _REGISTRY, "registry_add": _REGISTRY, "registry_delete": _REGISTRY,
            "registry_set": _REGISTRY, "registry_rename": _REGISTRY, "image_load": _IMAGE,
            "driver_load": _IMAGE, "pipe_created": {"PipeName": "pipe.name"}, "dns_query": _DNS,
            "ps_script": _SCRIPT}
        specialized.update({name: _FILE for name in _FILE_CATEGORIES})
        if category:
            fields.update(specialized.get(category, {}))
            if category == "network_connection":
                fields["Image"] = ["process.executable", "wfp.application"]
        elif service == "powershell":
            fields.update(_SCRIPT)
        else:
            for sources, extra in (({"net_socket", "network_filter"}, _NETWORK),
                    ({"file_change"}, _FILE), ({"registry_change"}, _REGISTRY), ({"image_load"}, _IMAGE),
                    ({"script_block"}, _SCRIPT), ({"service_change"}, _SERVICE), ({"auth", "account_change"}, _AUTH),
                    ({"dns_lookup"}, _DNS), ({"pipe_event"}, {"PipeName": "pipe.name"})):
                if sources.intersection(families):
                    fields.update(extra)
            if "auth" in families and "service_change" in families:
                fields["ServiceName"] = ["service.name", "auth.service_name"]
            # In broad service rules this native field is typed by _process_fields,
            # including loaded-image records; specific image categories use image.*.
            if service != "system":
                fields["OriginalFileName"] = "process.original_file_name"
        namespace = "image" if category in {"image_load", "driver_load"} else "file"
        if category != "ps_script" and service not in {"powershell", "system"}:
            fields["Hashes"] = {"hashes": {key: f"{namespace}.hash.{key.casefold()}"
                                            for key in ("MD5", "SHA1", "SHA256", "IMPHASH")}}
        return fields
    fields = dict(_GENERIC_NETWORK)
    fields.update(_DNS if category == "dns" else _PROXY if category == "proxy" else {})
    return fields


def map_rule(logsource, selectors):
    """Map a complete rule; any named reason prevents runtime activation."""
    result = {"families": [], "event_codes": [], "os_families": [], "fields": {}, "reasons": [],
              "rationale": [], "numeric_fields": [], "windows_event_classes": [], "scope": [],
              "category": "", "grouping_fields": [], "field_inventory": [], "exclusions": [],
              "conversions": {}}
    if not isinstance(logsource, dict) or any(not isinstance(value, str) for value in logsource.values()):
        result["reasons"].append("Invalid logsource: expected string fields")
        return result
    product = logsource.get("product", "").casefold()
    category = logsource.get("category", "").casefold()
    service = logsource.get("service", "").casefold()
    result['category'] = category
    result['grouping_fields'] = _grouping_fields(category)
    unknown_keys = sorted(set(logsource) - {"product", "category", "service", "definition"})
    if unknown_keys:
        result["reasons"].append("Unsupported logsource fields: " + ", ".join(unknown_keys))
    rows = []
    for key, value in (("category", category), ("service", service)):
        if not value:
            continue
        row = next((row for row in LOGSOURCE_TABLE if row.key == key and row.value == value
                    and row.product in {product, "*"}), None)
        if row is None:
            result["reasons"].append(f"Unmapped logsource {key}: {value}")
        else:
            rows.append(row)
    if not rows:
        result["reasons"].append("Unmapped logsource: no supported category or service")
        return result
    generic = all(row.product == '*' for row in rows)
    actual_product = product or ('*' if generic else rows[0].product)
    if actual_product not in {'windows', 'linux', '*'}:
        result['reasons'].append('Unsupported explicit logsource product: '+actual_product)
    result["os_families"] = [actual_product] if actual_product != "*" else ["linux", "windows", "unknown"]
    if actual_product == "windows":
        classes = list(EVENT_CLASSES)
        for row in rows:
            classes = [event for event in classes if (not row.families or event.family in row.families)
                       and (not row.codes or event.event_id in row.codes)
                       and (not row.channels or event.channel in row.channels)]
        requested = set(_field_names(selectors))
        allowed = []
        for event in classes:
            reason = ('wfp_image_device_path_unmapped' if event.family == 'network_filter'
                      and 'Image' in requested else 'query_results_native_string_unavailable'
                      if event.provider == SYSMON and event.event_id == 22
                      and 'QueryResults' in requested else None)
            if reason:
                result['exclusions'].append({'event_class': [event.channel, event.provider, event.event_id],
                    'reason': reason, 'fields': ['Image' if event.family == 'network_filter' else 'QueryResults']})
            else:
                allowed.append(event)
        classes = allowed
        result["windows_event_classes"] = [[event.channel, event.provider, event.event_id] for event in classes]
        result["families"] = sorted({event.family for event in classes})
        result["event_codes"] = sorted({str(event.event_id) for event in classes})
    else:
        families = set(rows[0].families)
        for row in rows[1:]:
            families.intersection_update(row.families)
        result["families"] = sorted(families)
    if not result["families"]:
        result["reasons"].append("Logsource category and service have no shared typed event classes")
        result['reasons'].extend(item['reason'] for item in result['exclusions'])
    for row in rows:
        result["rationale"].append(row.rationale)
        result["scope"].extend({"field": field, "values": list(values)} for field, values in row.scope)
    if actual_product == "linux" and not generic:
        result["scope"].append({"field": "audit.time", "exists": True})
    fields = _fields('*' if generic else actual_product, category, service, result["families"])
    if generic and actual_product == 'windows':
        fields.update(_COMMON_WINDOWS)
    for name in _field_names(selectors):
        if name in fields:
            result["fields"][name] = fields[name]
        else:
            if actual_product == 'linux' and name in {'type', 'syscall', 'key'}:
                result['reasons'].append(f'Unmapped Sigma field: {name} (not retained on grouped execution records)')
                continue
            suffix = " (only argv is typed; no full command-line string)" if actual_product == "linux" and name == "CommandLine" else ""
            result["reasons"].append(f"Unmapped Sigma field: {name}{suffix}")
    result["numeric_fields"] = sorted(_NUMERIC)
    targets = _targets(result['fields'])
    if actual_product == 'windows':
        result['field_inventory'] = [{'event_class': [event.channel, event.provider, event.event_id],
                                      'fields': sorted(targets & _windows_fields(event)),
                                      'absence_fields': sorted(targets & _windows_fields(event) -
                                          ({'process.parent.executable'} if event.provider == SECURITY
                                           and event.event_id == 4688 else set()))} for event in classes]
        if 'TargetObject' in result['fields'] and any(event.provider == SECURITY and event.event_id == 4657
                                                     for event in classes):
            result['conversions']['TargetObject'] = {'type': 'security_registry_target',
                'event_classes': [['Security', SECURITY, 4657]]}
            result['rationale'].append('Security 4657 TargetObject converts the native hive and appends '
                                       'the separately typed value name; missing conversion inputs stay unknown.')
    else:
        result['field_inventory'] = [{'family': family, 'fields': sorted(targets & _FAMILY_FIELDS.get(family, set()))}
                                     for family in result['families']]
    return result
