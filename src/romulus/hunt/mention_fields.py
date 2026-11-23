"""Which text of a record the mention sweep reads: a bounded, documented selection of free-text fields per family.

The sweep never scans a serialized record. Each record is read by its family, and within the family only the fields an
attacker can put free text into (command lines, script blocks, URLs, user agents, queries, file paths, host and
domain names, mail headers, message lines) are selected. Each selected field is scanned as its own text, so a match
never spans two fields and every excerpt is one field's value.

Families (the first that fits):

- **text**: a record with a message-like field (`message`, NXLog's `Message`, a Windows record's rendered
  `Event.RenderingInfo.Message`), else an `event.original` that is plain text. Its ECS and Beats free-text fields
  (`ECS_FIELDS`) are read beside it. A Windows record also has its event data's free-text fields read
  (`WINDOWS_DATA_KEYS`, under `winlog.event_data`, `EventData` or NXLog's flat names). A record with none of the
  message-like fields is read by those fields and counted as scanned in part. A Windows event exported as XML in
  `event.original` is read by its rendered message and its event data's free-text fields (at most 1 MiB, never a
  document declaring a DTD or entity).
- **auditd**: raw Linux audit record lines (one, several joined by newlines, or an array of them). Their hex-encoded
  and quoted untrusted-string fields are decoded (`AUDIT_FIELDS`, and an EXECVE record's arguments joined), never
  the raw hex. A record a shipper indexed as fields is read by the same names under `auditd.log.*` and
  `auditd.data.*`, its process title as `process.title`, beside its message and ECS fields.
- **journald**: a journal record exported as JSON in `event.original` (`JOURNAL_FIELDS`).
- **suricata_eve**: a Suricata EVE JSON record in `event.original`, by event type (`EVE_FIELDS`, from Suricata's EVE
  output documentation). An event type the table does not list is scanned by the union of the table's fields and is
  counted as scanned only in part.
- **zeek**: a Zeek JSON log record in `event.original`, by log (`ZEEK_FIELDS`, from Zeek's base-script log
  documentation). A log the table does not list is scanned by the union of the table's fields, in part.
- **ecs_json**: an ECS-shaped JSON document in `event.original` (top-level names ECS or the Beats namespaces): its
  `ECS_FIELDS` and Windows event data. A document with other top-level names is scanned only in part.

Credentials. Before selection, a Zeek or EVE object held in `message` or `event.original` goes through its producer's
scrubber whatever recognised it (`scrub_source`), and the record the mention keeps is that scrubbed one. Never
selected: the argument of a credential command (the producers' own sets: FTP PASS/ACCT/ADAT, IRC PASS/OPER/
AUTHENTICATE/JOIN keys, Redis AUTH and the like), the argument columns of a Zeek log no table describes, the value of
an HTTP/2 header whose name is a credential's (Authorization, Cookie, tokens, keys), a message body; and every
selected text loses a URI's userinfo and a SIP URI's password.

A JSON record of no family above, a JSON array and any other XML document are not scanned (counted, with the reason). A family
record that holds none of its family's fields has no free text to scan: it is counted, and it is not a coverage gap.

Bounds per record: at most `MAX_TEXTS` selected texts (the rest counted as not scanned), at most `MAX_LIST_ITEMS`
values of one list field, a JSON path walk of at most `MAX_DEPTH` levels; the scanner reads at most
`mention_match.MAX_SCAN_CHARS` characters across all of a record's texts.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from xml.etree import ElementTree

from romulus.evidence.auditd import AuditParseError, execve_argv, is_audit_line, parse_record
from romulus.evidence.suricata_protocols import _FTP_CREDENTIAL_COMMANDS, scrub_suricata_source
from romulus.evidence.zeek import _COMMAND_ARGUMENTS as _ZEEK_COMMAND_ARGUMENTS
from romulus.evidence.zeek import scrub_zeek_source
from romulus.evidence.zeek_credentials import REDACTED, scrub_sql, strip_sip_password, strip_uri_userinfo

MAX_TEXTS = 32
MAX_LIST_ITEMS = 64
MAX_DEPTH = 8

# Families, as counted under the pool's coverage (`by_field` is "<family>:<field>")
TEXT, AUDITD, JOURNALD, EVE, ZEEK, ECS_JSON = "text", "auditd", "journald", "suricata_eve", "zeek", "ecs_json"

NO_TEXT = "no text field"
NO_LINE = "a record without a message line: only its catalogued free-text fields were scanned"
JSON_RECORD = "event.original is a JSON record of no catalogued family"
JSON_ARRAY = "event.original is a JSON array"
JSON_MESSAGE = "the message is a JSON record of no catalogued family"
JSON_MESSAGE_ARRAY = "the message is a JSON array"
XML_RECORD = "event.original is an XML record"
UNREADABLE_AUDIT = "an audit record line that does not parse: scanned as plain text"
PAST_TEXTS = f"a record with more than {MAX_TEXTS} selected free-text fields: the rest were not scanned"

_MESSAGE_FIELDS = ("message", "Message", "Event.RenderingInfo.Message")

# ECS and Beats fields that hold attacker-influencable free text (ECS field reference; Filebeat/Winlogbeat/Auditbeat
# exported fields). Identifiers, addresses, numbers and enumerations are left out: no curated pattern is about them.
ECS_FIELDS = (
    "process.command_line", "process.args", "process.title", "process.executable", "process.name",
    "process.parent.command_line", "process.parent.executable", "process.parent.args",
    "url.original", "url.full", "url.path", "url.query",
    "user_agent.original", "http.request.referrer", "http.request.body.content",
    "dns.question.name", "file.path", "file.target_path", "registry.data.strings",
    "tls.client.server_name", "email.subject", "email.attachments.file.name",
    "powershell.file.script_block_text", "powershell.command.value", "powershell.command.invocation_details.value",
    "syslog.identifier", "log.syslog.appname", "systemd.unit",
    "journald.process.command_line",
    "dns.answers.data", "url.domain", "registry.path", "file.name", "process.parent.name",
)

# Windows event data names that hold free text (Sysmon, Security, PowerShell, Task Scheduler, BITS, WMI, service
# control manager schemas). Read under winlog.event_data, EventData, or flat (NXLog without AddPrefix).
WINDOWS_DATA_KEYS = (
    "CommandLine", "ParentCommandLine", "ScriptBlockText", "Payload", "ContextInfo", "HostApplication",
    "Image", "ParentImage", "TargetFilename", "ImageLoaded", "QueryName", "QueryResults", "ServiceFileName",
    "ImagePath", "TaskContent", "TaskContentNew", "Details", "TargetObject", "PipeName", "ProcessName",
    "NewProcessName", "ParentProcessName", "ObjectName", "ShareName", "RelativeTargetName", "Url", "url",
    "Command", "Consumer", "Destination", "Operation", "Query", "CallerProcessName", "Application",
    # Sysmon process access and remote threads, DNS and network names, clipboard and file contents (event 15/24),
    # task and service names, Defender detections, AppLocker paths
    "SourceImage", "TargetImage", "StartModule", "StartFunction", "DestinationHostname", "Contents",
    "TaskName", "ServiceName", "Threat Name", "Path", "FilePath", "FullFilePath",
)

# Decoded audit record fields that hold untrusted strings (auditd's hex-encodable keys that carry text, not ids).
AUDIT_FIELDS = ("proctitle", "cmd", "exe", "comm", "data", "name", "path")
AUDIT_PROCTITLE = ("proctitle",)

# A journal record's free text: the message, the writing process's command line and executable, and the identifiers
# a writer chooses (journald's `_CMDLINE`, `_EXE`, `_COMM` are recorded by journald; SYSLOG_IDENTIFIER by the writer).
JOURNAL_FIELDS = ("MESSAGE", "_CMDLINE", "_EXE", "_COMM", "SYSLOG_IDENTIFIER")
_JOURNAL_MARKERS = ("MESSAGE", "__CURSOR", "__REALTIME_TIMESTAMP", "_BOOT_ID", "_TRANSPORT", "SYSLOG_IDENTIFIER")

# Suricata EVE free-text fields by event type (Suricata EVE JSON format documentation). A list value (an array of
# objects or strings) is read item by item. `alert.signature` and `alert.metadata` are the sensor's rule text, not
# attacker text, and are left out; a record's packet payload is not a log field and is left out.
# A message body is not read (it can hold a form's password); HTTP/2 header values are read by name, never those of a
# credential header (`_http2_headers`).
_EVE_HTTP = ("http.hostname", "http.url", "http.http_user_agent", "http.http_refer", "http.redirect")
EVE_FIELDS: dict[str, tuple[str, ...]] = {
    "http": _EVE_HTTP,
    "fileinfo": (*_EVE_HTTP, "fileinfo.filename", "smtp.helo", "smtp.mail_from", "smtp.rcpt_to", "email.subject",
                 "smb.filename", "ftp_data.filename", "nfs.filename", "tftp.file"),
    "dns": ("dns.rrname", "dns.rdata", "dns.queries.rrname", "dns.answers.rrname", "dns.answers.rdata",
            "dns.grouped.A", "dns.grouped.AAAA", "dns.grouped.CNAME", "dns.grouped.TXT", "dns.grouped.MX",
            "dns.grouped.PTR", "dns.grouped.NS", "dns.grouped.SRV"),
    "tls": ("tls.sni", "tls.subject", "tls.issuerdn"),
    "quic": ("quic.sni", "quic.ua"),
    "smtp": ("smtp.helo", "smtp.mail_from", "smtp.rcpt_to", "email.from", "email.to", "email.cc", "email.subject",
             "email.attachment", "email.url"),
    "ssh": ("ssh.client.software_version", "ssh.server.software_version"),
    "ftp": ("ftp.command", "ftp.command_data", "ftp.reply"),
    "ftp_data": ("ftp_data.filename", "ftp_data.command"),
    "smb": ("smb.filename", "smb.share", "smb.named_pipe", "smb.client_dialects"),
    "krb5": ("krb5.cname", "krb5.sname"),
    "tftp": ("tftp.file",),
    "nfs": ("nfs.filename",),
    "sip": ("sip.uri", "sip.request_line", "sip.response_line"),
    "rdp": ("rdp.client.client_name", "rdp.cookie"),
    "dhcp": ("dhcp.hostname", "dhcp.client_id"),
    "http2": (),
    "mqtt": ("mqtt.publish.topic", "mqtt.connect.client_id", "mqtt.subscribe.topics.topic"),
    "pgsql": ("pgsql.request.simple_query",),
    "rfb": ("rfb.server_security_failure_reason",),
    # event types without free text: counters, flow records, industrial and key-exchange metadata
    "stats": (), "flow": (), "netflow": (), "modbus": (), "dnp3": (), "ike": (), "snmp": (), "bittorrent-dht": (),
    "frame": (), "arp": (),
}
_EVE_ALL = tuple(dict.fromkeys(name for names in EVE_FIELDS.values() for name in names))
# an alert, a drop and an anomaly carry the application-layer block of the transaction they fired on (http, dns, tls,
# fileinfo, smtp...): they are read by every catalogued field
EVE_FIELDS.update({"alert": _EVE_ALL, "drop": _EVE_ALL, "anomaly": _EVE_ALL})

# Zeek free-text fields by log (Zeek base-script log documentation). `snmp.community` and other secrets are left out.
ZEEK_FIELDS: dict[str, tuple[str, ...]] = {
    "conn": (), "known_hosts": (), "known_services": (), "modbus": (), "dnp3": (), "tunnel": (), "pe": (),
    "ocsp": (), "ntp": (), "packet_filter": (), "capture_loss": (), "stats": (), "loaded_scripts": (),
    "dns": ("query", "answers"),
    "http": ("host", "uri", "referrer", "user_agent", "username", "origin"),
    "ssl": ("server_name", "subject", "issuer", "client_subject", "client_issuer"),
    "x509": ("certificate.subject", "certificate.issuer", "san.dns", "san.uri", "san.email"),
    "files": ("filename",),
    "smtp": ("helo", "mailfrom", "rcptto", "from", "to", "cc", "reply_to", "subject", "user_agent", "path"),
    "ftp": ("user", "command", "arg"),
    "ssh": ("client", "server"),
    "sip": ("uri", "user_agent", "request_from", "request_to", "subject"),
    "smb_files": ("name", "path", "prev_name"),
    "smb_mapping": ("path",),
    "dce_rpc": ("named_pipe",),
    "kerberos": ("client", "service"),
    "ntlm": ("username", "hostname", "domainname"),
    "rdp": ("cookie", "client_name"),
    "notice": ("msg", "sub"),
    "weird": ("name", "addl"),
    "irc": ("nick", "user", "value", "addl"),
    "mysql": ("arg",),
    "software": ("unparsed_version",),
    "dhcp": ("host_name", "client_fqdn", "domain"),
    "radius": ("username", "connect_info"),
    "socks": ("user", "request.name", "bound.name"),
    "syslog": ("message",),
    "quic": ("server_name", "user_agent"),
    "dpd": ("failure_reason",),
    "reporter": ("message",),
    "known_certs": ("subject", "issuer_subject"),
}
_ZEEK_ALL = tuple(dict.fromkeys(name for names in ZEEK_FIELDS.values() for name in names))

# Top-level names of ECS and of the Beats namespaces: a JSON document whose top-level names are all among them is read
# completely by its ECS selection
ECS_TOP = frozenset({
    "@timestamp", "agent", "as", "client", "cloud", "container", "data_stream", "destination", "device", "dll", "dns",
    "ecs", "email", "error", "event", "faas", "file", "group", "host", "http", "labels", "log", "message", "network",
    "observer", "orchestrator", "organization", "package", "process", "registry", "related", "rule", "server",
    "service", "source", "span", "tags", "threat", "tls", "trace", "transaction", "url", "user", "user_agent",
    "vulnerability", "winlog", "powershell", "journald", "syslog", "systemd", "input", "auditd", "fileset",
})


@dataclass
class Selection:
    """The texts of one record to scan: (field, text) pairs. `complete` when the selection is its family's whole
    documented set; `reason` says what was not scanned (or why nothing was); `no_text` when a family record holds none
    of its free-text fields."""
    family: str
    texts: list[tuple[str, str]] = field(default_factory=list)
    complete: bool = True
    reason: str = ""

    @property
    def no_text(self) -> bool:
        return not self.texts and self.complete


def _get(source: dict, name: str):
    """A dotted field, flat or nested."""
    if name in source:
        return source[name]
    node = source
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _strings(value, depth: int = 0) -> list[str]:
    """The non-empty strings of a value: itself, or a list's items (at most MAX_LIST_ITEMS)."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list) and depth < 2:
        out: list[str] = []
        for item in value[:MAX_LIST_ITEMS]:
            out.extend(_strings(item, depth + 1))
        return out
    return []


def _walk(node, parts: list[str], depth: int = 0) -> list[str]:
    """The strings at a dotted path through nested objects and arrays of objects (an array is read item by item)."""
    if depth > MAX_DEPTH:
        return []
    if not parts:
        return _strings(node)
    if isinstance(node, list):
        out: list[str] = []
        for item in node[:MAX_LIST_ITEMS]:
            out.extend(_walk(item, parts, depth + 1))
        return out
    if not isinstance(node, dict):
        return []
    # a flat key holding dots (Zeek's "id.orig_h", a shipper's flattened name) is tried before descending
    for size in range(len(parts), 0, -1):
        key = ".".join(parts[:size])
        if key in node:
            return _walk(node[key], parts[size:], depth + 1)
    return []


def _add(texts: list[tuple[str, str]], path: str, values: list[str], seen: set[str]) -> None:
    for value in values:
        value = mask_credentials(value)
        if value in seen:
            continue                     # the same text twice in one record is scanned once
        seen.add(value)
        texts.append((path, value))


def _bounded(selection: Selection) -> Selection:
    if len(selection.texts) > MAX_TEXTS:
        selection.texts = selection.texts[:MAX_TEXTS]
        selection.complete = False
        selection.reason = selection.reason or PAST_TEXTS
    return selection


def _paths(obj: dict, names, texts, seen, prefix: str = "") -> None:
    for name in names:
        _add(texts, prefix + name, _walk(obj, name.split(".")), seen)


def _windows_data(source: dict, texts, seen, prefix: str = "") -> None:
    for container in ("winlog.event_data", "EventData", "event_data"):
        data = _get(source, container)
        if isinstance(data, dict):
            for key in WINDOWS_DATA_KEYS:
                _add(texts, f"{prefix}{container}.{key}", _strings(data.get(key)), seen)
    for key in WINDOWS_DATA_KEYS:
        # NXLog's flat records hold event data at the top level under the provider's own names
        _add(texts, prefix + key, _strings(source.get(key)), seen)


def audit_lines(value) -> list[str]:
    """The raw audit record lines a text field holds: one line, several joined by newlines (Auditd Manager), or an
    array of them (Auditbeat's raw message); empty when its first line is no audit record."""
    if isinstance(value, str):
        parts = value.split("\n") if "\n" in value else [value]
    elif isinstance(value, list):
        parts = [item for item in value[:MAX_LIST_ITEMS] if isinstance(item, str)]
    else:
        return []
    parts = [part for part in parts if part.strip()]
    return parts if parts and is_audit_line(parts[0]) else []


def audit_texts(lines: list[str], only: tuple[str, ...] | None = None) -> Selection:
    """The decoded free-text fields of raw audit record lines (`only`: just the fields it names)."""
    texts: list[tuple[str, str]] = []
    seen: set[str] = set()
    complete, reason = True, ""
    for line in lines:
        try:
            record = parse_record(line)
        except AuditParseError:
            if only is None:
                _add(texts, "audit line", [line], seen)
                complete, reason = False, UNREADABLE_AUDIT
            continue
        for key in only or AUDIT_FIELDS:
            value = record.fields.get(key)
            if isinstance(value, str) and value and value not in ("(null)", "(none)", "?"):
                # a process title holds its arguments separated by NUL bytes
                _add(texts, f"{record.type}.{key}", [value.replace("\x00", " ").strip()], seen)
        if record.type == "EXECVE" and only is None:
            try:
                argv = execve_argv(record)
            except AuditParseError:
                argv = None
            if argv is not None and argv.args:
                _add(texts, "EXECVE.argv", [" ".join(argv.args)], seen)
    return _bounded(Selection(AUDITD, [(path, text) for path, text in texts if text], complete=complete,
                              reason=reason))


def _decoded(value: str) -> list[str]:
    """A shipper's audit value as it may be meant: decoded when it is still auditd's hex encoding and decodes to text;
    both the value and its decoding when an even run of hex digits does not decode to text (an already decoded value
    such as "cafe" stays readable)."""
    if not (len(value) % 2 == 0 and value and all(char in "0123456789ABCDEFabcdef" for char in value)):
        return [value]
    raw = bytes.fromhex(value)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [value, raw.decode("utf-8", errors="replace")]
    if all(char.isprintable() or char in "\x00\t\n" for char in text):
        return [text]
    return [value, text]


def _shipper_audit(source: dict, only: tuple[str, ...]) -> list[tuple[str, str]]:
    """Audit fields a shipper indexed by name (Filebeat's auditd module `auditd.log.*`, Auditbeat's `auditd.data.*`,
    and the process title as ECS `process.title`)."""
    texts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key in only:
        names = [f"auditd.log.{key}", f"auditd.data.{key}", *(("process.title",) if key == "proctitle" else ())]
        for name in names:
            values = [form.replace("\x00", " ").strip() for value in _strings(_get(source, name))
                      for form in _decoded(value)]
            _add(texts, name, [value for value in values if value], seen)
    return texts


# Commands whose argument is, or may hold, a credential: the producers' own sets (Suricata's FTP commands; Zeek's FTP,
# IRC, Redis and MySQL commands), so the scan never reads what their scrubbers would mask.
CREDENTIAL_COMMANDS = frozenset(_FTP_CREDENTIAL_COMMANDS) | frozenset(
    name for spec in _ZEEK_COMMAND_ARGUMENTS.values() for name in (*spec.present, *spec.unknown))
# Zeek's argument columns of a command, never read when the command is a credential one or the log is not known
_ZEEK_ARGUMENTS = ("arg", "value", "addl")
# Header names whose values are credentials or session secrets (a name holding any of these words)
_CREDENTIAL_HEADER_WORDS = ("auth", "cookie", "token", "secret", "pass", "key", "session", "credential", "signature")


_BODY_CUE = re.compile(r"pass|pwd|token|secret|auth|key=|session", re.IGNORECASE)


def _is_eve(obj: dict) -> bool:
    return isinstance(obj.get("event_type"), str) and any(key in obj for key in ("src_ip", "flow_id", "in_iface",
                                                                                 "dest_ip"))


def _zeek_log(obj: dict, source: dict):
    """A Zeek object's log name (None when it is Zeek but the log is not named), or False when it is not Zeek."""
    log = obj.get("_path") if isinstance(obj.get("_path"), str) else None
    if log is None and not ("uid" in obj and ("id.orig_h" in obj or isinstance(obj.get("id"), dict))):
        return False
    if log is None:
        dataset = _get(source, "event.dataset")
        log = dataset.split(".", 1)[-1] if isinstance(dataset, str) and dataset.startswith("zeek.") else None
    return log


def _password_command(command) -> bool:
    """A command whose argument is, or may hold, a credential (its argument is never selected)."""
    return isinstance(command, str) and command.strip().upper() in CREDENTIAL_COMMANDS


def _credential_header(name) -> bool:
    return not isinstance(name, str) or any(word in name.lower() for word in _CREDENTIAL_HEADER_WORDS)


def _http2_headers(obj: dict, texts, seen, prefix: str) -> None:
    """HTTP/2 header values, by name, never a credential header's."""
    http2 = obj.get("http2")
    if not isinstance(http2, dict):
        return
    for block in ("request_headers", "response_headers"):
        headers = http2.get(block)
        for header in headers[:MAX_LIST_ITEMS] if isinstance(headers, list) else ():
            if isinstance(header, dict) and not _credential_header(header.get("name")):
                _add(texts, f"{prefix}http2.{block}.{header.get('name')}"[:120], _strings(header.get("value")), seen)


def mask_credentials(text: str) -> str:
    """A selected text without the credentials free text can carry: a URI's userinfo, a SIP URI's password."""
    if "@" not in text:
        return text
    text, _removed, _password = strip_uri_userinfo(text)
    sip, _removed = strip_sip_password(text)
    return text if sip is None else sip


def _scrubbed_json(obj: dict, source: dict) -> dict | None:
    """A Zeek or Suricata EVE object with every credential its producer's scrubber masks, and the free-text
    credentials the mention scan would otherwise read (HTTP/2 credential headers, a message body holding a password
    cue, SIP and URI passwords, SQL password literals); None when nothing changed."""
    if _is_eve(obj):
        payload = json.dumps(obj)
        scrubbed = scrub_suricata_source({"event": {"dataset": "suricata.eve", "original": payload}})
        out = json.loads(scrubbed["event"]["original"]) if scrubbed["event"]["original"] != payload else obj
        changed = out is not obj
        if not changed:
            out = json.loads(payload)
        http2 = out.get("http2")
        for block in ("request_headers", "response_headers"):
            headers = http2.get(block) if isinstance(http2, dict) else None
            for header in headers if isinstance(headers, list) else ():
                if isinstance(header, dict) and _credential_header(header.get("name")) and header.get("value") not in (
                        None, "", REDACTED):
                    header["value"] = REDACTED
                    changed = True
        for block, key in (("http", "http_request_body_printable"), ("http", "http_request_body"),
                           ("http", "http_response_body_printable"), ("http", "http_response_body")):
            body = out.get(block) if isinstance(out.get(block), dict) else {}
            value = body.get(key)
            if isinstance(value, str) and _BODY_CUE.search(value):
                body[key] = REDACTED
                changed = True
        sip = out.get("sip")
        for key in ("uri", "request_line", "response_line", "from", "to"):
            value = sip.get(key) if isinstance(sip, dict) else None
            if isinstance(value, str):
                stripped, removed = strip_sip_password(value)
                if stripped is None or removed:
                    sip[key] = REDACTED if stripped is None else stripped
                    changed = True
        pgsql = (out.get("pgsql") or {}).get("request") if isinstance(out.get("pgsql"), dict) else None
        if isinstance(pgsql, dict) and isinstance(pgsql.get("simple_query"), str):
            scrubbed_sql = scrub_sql(pgsql["simple_query"])
            if scrubbed_sql.text != pgsql["simple_query"]:
                pgsql["simple_query"] = scrubbed_sql.text if scrubbed_sql.text is not None else REDACTED
                changed = True
        return out if changed else None
    log = _zeek_log(obj, source)
    if log is False:
        return None
    candidate = dict(obj)
    injected = "_path" not in candidate and isinstance(log, str)
    if injected:
        candidate["_path"] = log
    scrubbed = scrub_zeek_source(candidate)
    if log not in ZEEK_FIELDS:
        # a log no table here describes: its argument and password columns are not kept
        hidden = {key: REDACTED for key in (*_ZEEK_ARGUMENTS, "password")
                  if scrubbed.get(key) not in (None, "", REDACTED, "-")}
        if hidden:
            scrubbed = {**scrubbed, **hidden}
    if scrubbed is candidate:
        return None
    if injected:
        scrubbed = {key: value for key, value in scrubbed.items() if key != "_path"}
    return scrubbed


def scrub_source(source: dict) -> dict:
    """The record as the mention scan reads and keeps it: a Zeek or Suricata EVE object held in `message` or
    `event.original` scrubbed by its producer's scrubber whatever recognised it (a record whose shipper markers the
    store's cleaning did not recognise included), plus the free-text credentials `_scrubbed_json` masks. The same
    object when nothing changed."""
    out = source
    for name in ("message", "event.original"):
        flat = name in source
        value = source.get(name) if flat else _get(source, name)
        if not isinstance(value, str) or value.lstrip()[:1] != "{":
            continue
        try:
            obj = json.loads(value)
        except ValueError:
            continue
        if not isinstance(obj, dict) or (scrubbed := _scrubbed_json(obj, source)) is None:
            continue
        text = json.dumps(scrubbed, ensure_ascii=False)
        if out is source:
            out = copy.deepcopy(source)
        if flat or "." not in name:
            out[name] = text
        else:
            out["event"]["original"] = text
    # an ECS URL's userinfo and password
    url = out.get("url") if isinstance(out.get("url"), dict) else None
    if url is not None:
        masked = {key: strip_uri_userinfo(url[key])[0] for key in ("full", "original")
                  if isinstance(url.get(key), str) and "@" in url[key]}
        masked = {key: value for key, value in masked.items() if value != url[key]}
        if url.get("password") not in (None, "", REDACTED):
            masked["password"] = REDACTED
        if masked:
            if out is source:
                out = copy.deepcopy(source)
            out["url"].update(masked)
    return out


def _json_texts(obj: dict, source: dict, windows: bool, field: str = "event.original") -> Selection:
    """The selection of a JSON object held in a record's text field (`event.original`, or a `message` a shipper
    filled with the producer's JSON line)."""
    texts: list[tuple[str, str]] = []
    seen: set[str] = set()
    prefix = f"{field}#"
    if any(marker in obj for marker in _JOURNAL_MARKERS):
        for key in JOURNAL_FIELDS:
            _add(texts, f"{prefix}journal:{key}", _strings(obj.get(key)), seen)
        return _bounded(Selection(JOURNALD, texts))
    event_type = obj.get("event_type")
    if _is_eve(obj):
        known = event_type in EVE_FIELDS
        names = EVE_FIELDS.get(event_type, _EVE_ALL)
        if _password_command(_get(obj, "ftp.command")) or _password_command(_get(obj, "ftp_data.command")):
            names = tuple(name for name in names if name not in ("ftp.command_data", "ftp_data.filename"))
        _paths(obj, names, texts, seen, prefix + "eve:")
        _http2_headers(obj, texts, seen, prefix + "eve:")
        if not known:
            return _bounded(Selection(EVE, texts, complete=False,
                                      reason="a Suricata EVE event type outside the catalogued table: scanned by the "
                                             "table's free-text fields only"))
        return _bounded(Selection(EVE, texts))
    log = _zeek_log(obj, source)
    if log is not False:
        known = log in ZEEK_FIELDS
        names = ZEEK_FIELDS[log] if known else _ZEEK_ALL
        if not known or _password_command(obj.get("command")):
            # a credential command's arguments, or the argument columns of a log the scrubber may not know
            names = tuple(name for name in names if name not in _ZEEK_ARGUMENTS)
        _paths(obj, names, texts, seen, prefix + "zeek:")
        if not known:
            return _bounded(Selection(ZEEK, texts, complete=False,
                                      reason="a Zeek log outside the catalogued table: scanned by the table's "
                                             "free-text fields only"))
        return _bounded(Selection(ZEEK, texts))
    if "@timestamp" in obj or any(isinstance(obj.get(name), dict) for name in ECS_TOP):
        _paths(obj, ("message",), texts, seen, prefix)
        _paths(obj, ECS_FIELDS, texts, seen, prefix)
        if windows or isinstance(obj.get("winlog"), dict):
            _windows_data(obj, texts, seen, prefix)
        other = sorted(name for name in obj if name not in ECS_TOP)
        if other:
            return _bounded(Selection(ECS_JSON, texts, complete=False,
                                      reason="an ECS JSON document with fields outside ECS: only its ECS free-text "
                                             "fields were scanned"))
        return _bounded(Selection(ECS_JSON, texts))
    return Selection("json", [], complete=False, reason=JSON_RECORD if field == "event.original" else JSON_MESSAGE)


def _json_field(text: str, source: dict, windows: bool, field: str) -> Selection | None:
    """The selection of a text field that holds one JSON document (None when it holds a line): an object is read by
    its family, never as a serialized line; an array or an object of no family is not scanned."""
    if text.lstrip()[:1] not in ("{", "["):
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    if isinstance(parsed, list):
        return Selection("json", [], complete=False,
                         reason=JSON_ARRAY if field == "event.original" else JSON_MESSAGE_ARRAY)
    if not isinstance(parsed, dict):
        return None
    selection = _json_texts(parsed, source, windows, field)
    if selection.family != "json":
        # the record's own top-level free-text fields are read beside it
        seen = {text for _path, text in selection.texts}
        _paths(source, ECS_FIELDS, selection.texts, seen)
        selection = _bounded(selection)
    return selection


def select_texts(source: dict, *, windows: bool = False, only: tuple[str, ...] | None = None) -> Selection:
    """The texts of one record the mention sweep scans (see the module docstring). `only` restricts an audit record to
    the decoded fields it names (the fields of a record whose other fields a typed event already reads)."""
    message = next(((path, value) for path in _MESSAGE_FIELDS
                    if isinstance(value := _get(source, path), str) and value), None)
    original = _get(source, "event.original")
    original = original if isinstance(original, str) and original else None
    raw_original = _get(source, "event.original")
    lines = audit_lines(message[1] if message is not None else raw_original)
    if lines:
        return audit_texts(lines, only)
    if only is not None or isinstance(source.get("auditd"), dict):
        # an audit record a shipper indexed as fields (no raw line): its audit fields under the shipper's own names,
        # and its ECS free-text fields
        texts = _shipper_audit(source, only or AUDIT_FIELDS)
        if only is None:
            seen = {text for _path, text in texts}
            if message is not None:
                _add(texts, message[0], [message[1]], seen)
            _paths(source, ECS_FIELDS, texts, seen)
        return _bounded(Selection(AUDITD, texts))
    texts: list[tuple[str, str]] = []
    seen: set[str] = set()
    if message is not None:
        if (selection := _json_field(message[1], source, windows, message[0])) is not None:
            return selection
        _add(texts, message[0], [message[1]], seen)
    elif original is not None:
        head = original.lstrip()[:1]
        if (selection := _json_field(original, source, windows, "event.original")) is not None:
            return selection
        if head == "<" and (document := _xml_document(original)) is not None:
            return _xml_texts(document, source)
        _add(texts, "event.original", [original], seen)
    lined = bool(texts)
    _paths(source, ECS_FIELDS, texts, seen)
    if windows:
        _windows_data(source, texts, seen)
    if not texts:
        return Selection(TEXT, [], complete=False, reason=NO_TEXT)
    if not lined:
        # no message line: the catalogued fields are read, and whatever else the record holds is not
        return _bounded(Selection(TEXT, texts, complete=False, reason=NO_LINE))
    return _bounded(Selection(TEXT, texts))


# an exported event XML document read for its event data at most this long, and never one declaring a DTD or entity
MAX_XML_CHARS = 1_048_576
_XML_DECLARATIONS = re.compile(r"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)
XML_UNREAD = "event.original is an XML record that was not read (too long, or declaring a DTD or entity)"


def _xml_document(text: str):
    """The parsed XML document a text field holds, False for one that is not read (bounded, no declarations), or None
    when the text is no XML document (a line that merely starts with "<")."""
    if len(text) > MAX_XML_CHARS or _XML_DECLARATIONS.search(text):
        return False
    try:
        return ElementTree.fromstring(text)
    except (ElementTree.ParseError, ValueError):
        return None


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _xml_texts(document, source: dict) -> Selection:
    """A Windows event exported as XML: its rendered message and its event data's free-text fields. Any other XML
    document is not scanned."""
    if document is False:
        return Selection("xml", [], complete=False, reason=XML_UNREAD)
    texts: list[tuple[str, str]] = []
    seen: set[str] = set()
    if _local(document.tag) == "Event":
        message = None
        for node in document.iter():
            name = _local(node.tag)
            if name == "Message" and message is None and node.text:
                message = node.text
            elif name == "Data" and node.get("Name") in WINDOWS_DATA_KEYS and node.text:
                _add(texts, f"event.original#xml:EventData.{node.get('Name')}", [node.text], seen)
        if message:
            texts.insert(0, ("event.original#xml:RenderingInfo.Message", mask_credentials(message)))
        _paths(source, ECS_FIELDS, texts, seen)
        if texts:
            if message:
                return _bounded(Selection(TEXT, texts))
            return _bounded(Selection(TEXT, texts, complete=False, reason=NO_LINE))
    return Selection("xml", [], complete=False, reason=XML_RECORD)
