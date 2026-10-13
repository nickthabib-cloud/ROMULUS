"""Validate model-authored hunt intent and compile bounded source queries.

The model may supply selectors and an optional source-native query candidate.
Native candidates pass a strict read-only grammar and live-field check before
execution. Rejected candidates fall back to deterministic selector compilation.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any


PROTOCOLS = {"smb", "rdp", "dcom", "ssh", "vnc", "winrm", "http", "https", "dns", "tls", "tcp", "udp", "icmp"}
SOURCE_FIELDS = {
    "elasticsearch": {"message", "event.original", "event.action", "process.name", "process.command_line",
        "process.executable", "process.parent.name", "process.parent.command_line", "user.name", "user.domain",
        "host.name", "host.hostname", "host.ip", "source.ip", "destination.ip", "source.port", "destination.port",
        "network.protocol", "network.transport", "network.application", "event.code", "event.id", "winlog.event_id",
        "winlog.event_data.CommandLine", "winlog.event_data.SubjectUserName", "dns.question.name"},
    "arkime": {"ip.src", "ip.dst", "port", "protocols", "http.uri", "http.user-agent", "host.http", "dns.host"},
    "tshark": {"frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.addr", "ipv6.src", "ipv6.dst", "ipv6.addr",
        "tcp.srcport", "tcp.dstport", "tcp.port", "tcp.stream", "udp.srcport", "udp.dstport", "udp.port", "udp.stream", "tcp.flags.syn", "tcp.flags.ack",
        "dns.qry.name", "dns.a", "http.host", "http.request.uri", "http.user_agent",
        "tls.handshake.extensions_server_name", "smb2.cmd", "smb2.filename"},
}

IP_FIELDS = ("source.ip", "destination.ip", "srcIp", "dstIp", "src_ip", "dst_ip", "ip.src", "ip.dst", "host.ip")
HOST_FIELDS = ("host.name", "host.hostname", "computer_name", "hostname", "dns.question.name")
PORT_FIELDS = ("source.port", "destination.port", "srcPort", "dstPort", "src_port", "dst_port", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "port")
EVENT_FIELDS = ("event.code", "event.id", "winlog.event_id", "event_id")
PROTOCOL_FIELDS = ("network.protocol", "network.transport", "network.application", "protocol", "protocols")
TEXT_FIELDS = ("message", "event.original", "event.action", "event.dataset", "event.category", "event.kind",
    "event.type", "event.outcome", "process.name", "process.command_line", "process.executable",
    "process.parent.name", "process.parent.command_line", "winlog.event_data.CommandLine", "user.name",
    "user.domain", "host.name", "host.hostname", "audit.record_type", "log.level", "rule.name", "rule.id",
    "dns.question.name", "http.uri", "http.user-agent", "http.request.uri", "http.user_agent",
    "host.http", "dns.host", "http.host",
    "tls.handshake.extensions_server_name", "smb2.filename")
TIER_BY_SOURCE = {"elasticsearch": "elasticsearch", "arkime": "arkime", "tshark": "tshark"}
NATIVE_LANGUAGE = {"elasticsearch": {"elasticsearch_dsl"}, "arkime": {"arkime"}, "tshark": {"tshark"}}
TSHARK_PROTOCOL_ATOMS = {"ip", "ipv6", "tcp", "udp", "icmp", "dns", "http", "tls", "smb2", "dcerpc", "rdp", "ssh"}
TSHARK_FILTER_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .:=<>!&|()/-\"'[]*,")


def candidate_fields(source: str, available: list[str] | set[str]) -> list[str]:
    """Return a useful compact field catalog intersected with the actual schema."""
    actual = {f for f in available if isinstance(f, str) and _safe_field(f)}
    preferred = [*TEXT_FIELDS, *IP_FIELDS, *HOST_FIELDS, *PORT_FIELDS, *EVENT_FIELDS, *PROTOCOL_FIELDS]
    # Preserve observed mapping order after prioritizing common analysis fields.
    ordered = [f for f in preferred if f in actual]
    ordered.extend(sorted(actual - set(ordered)))
    return ordered[:80]


def validate_spec(raw: Any, *, allowed_sources: list[str], hypothesis_ids: set[str], fields_by_source: dict[str, list[str]],
                  evidence_ids: set[str]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    source = raw.get("source")
    if source not in allowed_sources:
        return None
    hypothesis_id = raw.get("hypothesis_id")
    if hypothesis_id not in hypothesis_ids:
        hypothesis_id = "general"
    intent = _clean_text(raw.get("intent"), 180)
    if not intent:
        return None
    # The intent is displayed to analysts and persisted with the task. Reject
    # IPv4-looking typos instead of allowing a valid selector plus a fabricated
    # address in the human-readable explanation.
    if _contains_malformed_ipv4_token(intent):
        return None
    intent_key=re.sub(r"[^a-z0-9]+"," ",intent.lower()).strip()
    if intent_key in {"network","host","traffic","activity","events","search","query","network flow","network traffic","host process","file transfer"}:
        return None
    fields = fields_by_source.get(source, [])
    known_fields={str(field).lower() for values in fields_by_source.values() for field in values}
    selected_fields = []
    if isinstance(raw.get("fields"), list):
        selected_fields = list(dict.fromkeys(x for x in raw["fields"] if isinstance(x, str) and _safe_field(x) and x in fields and
            (source == "elasticsearch" and x in TEXT_FIELDS or source != "elasticsearch" and x in SOURCE_FIELDS[source])))[:12]
    terms = []
    # Some models slip into field:value notation despite being asked for literal
    # terms. Normalize only when the field is in the live mapping; never pass a
    # query-language fragment through as a search term.
    raw_terms = raw.get("terms", [])
    if isinstance(raw_terms, list):
        for value in raw_terms[:8]:
            if not isinstance(value, str): continue
            if value.strip().lower() in known_fields: continue
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://",value):
                if _safe_term(value) and value not in terms: terms.append(value)
                continue
            if ":" in value:
                field, literal = value.split(":", 1)
                if _safe_field(field) and field in fields and _safe_term(literal):
                    if field not in selected_fields: selected_fields.append(field)
                    if literal not in terms: terms.append(literal)
                elif _safe_term(value) and value not in terms:
                    # Keep Windows paths, URLs without a scheme, and values such
                    # as sha256:<hash>. Field notation is recognized only when
                    # its prefix is a real field in the live source catalog.
                    terms.append(value)
            elif _safe_term(value) and value not in terms:
                terms.append(value)
            if len(terms) >= 4: break
    ips = _strings(raw.get("ips"), _safe_ip, 8, 64)
    hosts = _strings(raw.get("hostnames"), _safe_host, 8, 255)
    ports = _integers(raw.get("ports"), 8, 1, 65535)
    event_codes = _integers(raw.get("event_codes"), 12, 0, 65535) if source == "elasticsearch" else []
    protocols = [x.lower() for x in _strings(raw.get("protocols"), lambda s: s.lower() in PROTOCOLS, 8, 16)]
    index_class = raw.get("index_class") if raw.get("index_class") in {"host", "network", "all"} else "all"
    anchors = _strings(raw.get("anchor_evidence_ids"), lambda x: x in evidence_ids, 1, 80)
    native_query,native_language,native_validation=_native_candidate(raw,source,fields)
    if not (terms or ips or hosts or ports or event_codes or protocols or native_query):
        return None
    if source == "elasticsearch" and not selected_fields:
        # In particular, never fall back to an unbounded query when the model
        # names a field that does not exist in this deployment's mappings.
        selector_fields = candidate_fields(source, fields)
        selected_fields = [f for f in selector_fields if f in TEXT_FIELDS][:4] if terms else []
    if source == "tshark":
        selected_fields = selected_fields[:8]
        terms = terms[:1]; ips = ips[:2]; hosts = hosts[:1]; ports = ports[:6]; protocols = protocols[:4]
    if source == "arkime":
        selected_fields = selected_fields[:8]
        terms = terms[:1]; ips = ips[:2]; hosts = hosts[:1]; ports = ports[:6]; protocols = protocols[:4]
    # A text selector without a usable text field is not actionable for ES/TShark.
    if source in {"elasticsearch", "tshark"} and terms and not selected_fields:
        return None
    selected_fields=selected_fields[:8]
    return {"source": source, "hypothesis_id": hypothesis_id, "intent": intent,
        "terms": terms, "fields": selected_fields, "ips": ips, "hostnames": hosts,
        "ports": ports, "protocols": protocols, "event_codes": event_codes,
        "index_class": index_class if source == "elasticsearch" else "all", "anchor_evidence_ids": anchors,
        "native_query":native_query,"native_query_language":native_language,"native_query_validation":native_validation}


def fingerprint(spec: dict[str, Any]) -> str:
    executable = {k: spec.get(k) for k in ("source", "terms", "fields", "ips", "hostnames", "ports", "protocols", "event_codes", "index_class", "anchor_evidence_ids", "native_query", "native_query_language")}
    return hashlib.sha256(json.dumps(executable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:20]


def _native_candidate(raw: dict[str,Any],source: str,fields: list[str]) -> tuple[str,str,str]:
    query=raw.get("native_query")
    language=str(raw.get("native_query_language") or "none").lower()
    if not isinstance(query,str) or not query.strip() or language=="none": return "","none","not_proposed"
    query=query.strip()
    if language not in NATIVE_LANGUAGE[source]: return "","none","rejected_language_mismatch"
    try:
        if language=="elasticsearch_dsl": validate_native_es(query,fields)
        elif language=="arkime": validate_native_arkime(query,fields)
        elif language=="tshark": validate_native_tshark(query,fields)
    except (ValueError,TypeError,json.JSONDecodeError): return "","none","rejected_validation"
    return query,language,"accepted"


def validate_native_arkime(expression: str,fields: list[str]) -> str:
    if not 1<=len(expression)<=512 or any(ord(ch)<32 for ch in expression): raise ValueError("Arkime expression has invalid length or control characters")
    if any(ch in expression for ch in (";","`","{","}","$")): raise ValueError("Arkime expression contains unsupported syntax")
    if expression.count("(")!=expression.count(")") or expression.count('"')%2: raise ValueError("Arkime expression has unbalanced delimiters")
    referenced=re.findall(r"(?<![A-Za-z0-9_.-])([A-Za-z][A-Za-z0-9_.-]*)\s*(?:==|!=|=~|<=|>=|<|>)",expression)
    if not referenced or any(field not in fields or field not in SOURCE_FIELDS["arkime"] for field in referenced):
        raise ValueError("Arkime expression references an unavailable field")
    return expression


def validate_native_tshark(expression: str,fields: list[str]) -> str:
    if not 1<=len(expression)<=400 or any(ch not in TSHARK_FILTER_CHARS for ch in expression): raise ValueError("TShark expression has unsupported syntax or length")
    if expression.count("(")!=expression.count(")") or expression.count('"')%2: raise ValueError("TShark expression has unbalanced delimiters")
    structure=re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', expression)
    referenced=set(re.findall(r"(?<![A-Za-z0-9_.-])([A-Za-z][A-Za-z0-9_.-]*)\s*(?:==|!=|<=|>=|<|>|contains|matches)",structure))
    dotted=set(re.findall(r"(?<![A-Za-z0-9_.-])([A-Za-z][A-Za-z0-9_-]*\.[A-Za-z0-9_.-]+)",structure))
    if any(field not in fields or field not in SOURCE_FIELDS["tshark"] for field in referenced|dotted):
        raise ValueError("TShark expression references an unavailable field")
    atoms=set(re.findall(r"(?<![A-Za-z0-9_.-])([A-Za-z][A-Za-z0-9_-]*)(?![A-Za-z0-9_.-])",structure))
    operators={"contains","matches","and","or","not","true","false"}
    if any(atom.lower() not in TSHARK_PROTOCOL_ATOMS|operators for atom in atoms if atom not in {part for field in dotted for part in field.split(".")}):
        raise ValueError("TShark expression contains an unsupported bare identifier")
    return expression


def validate_native_es(candidate: str,fields: list[str]) -> str:
    parsed=json.loads(candidate)
    clause=parsed.get("query") if isinstance(parsed,dict) and set(parsed)=={"query"} else parsed
    _validate_es_clause(clause,set(fields))
    return candidate


def compile_native_es(candidate: str,fields: list[str],timestamp_field: str,time_range: dict[str,str] | None) -> dict[str,Any]:
    validate_native_es(candidate,fields)
    parsed=json.loads(candidate)
    clause=parsed.get("query") if isinstance(parsed,dict) and set(parsed)=={"query"} else parsed
    filters=[]
    if time_range:
        if timestamp_field not in fields: raise ValueError("No mapped timestamp field is available to enforce the hunt time window")
        filters.append({"range":{timestamp_field:time_range}})
    query={"bool":{"must":[clause],**({"filter":filters} if filters else {})}}
    _limit_dsl(query)
    return query


def _validate_es_clause(clause: Any,fields: set[str],depth: int=0) -> None:
    if depth>10 or not isinstance(clause,dict) or len(clause)!=1: raise ValueError("Elasticsearch DSL clause is malformed")
    kind,value=next(iter(clause.items()))
    if kind=="bool":
        if not isinstance(value,dict) or set(value)-{"must","filter","should","must_not","minimum_should_match"}: raise ValueError("Elasticsearch bool clause is unsupported")
        for key in ("must","filter","should","must_not"):
            children=value.get(key,[]); children=children if isinstance(children,list) else [children]
            if len(children)>24: raise ValueError("Elasticsearch bool clause is too large")
            for child in children: _validate_es_clause(child,fields,depth+1)
        minimum=value.get("minimum_should_match")
        if minimum is not None and (not isinstance(minimum,int) or minimum<0 or minimum>24): raise ValueError("minimum_should_match is invalid")
        return
    if kind=="exists":
        if not isinstance(value,dict) or set(value)!={"field"} or value.get("field") not in fields: raise ValueError("Elasticsearch exists field is unavailable")
        return
    if kind not in {"term","terms","match","match_phrase","range","wildcard","prefix"} or not isinstance(value,dict) or len(value)!=1:
        raise ValueError("Elasticsearch query clause is unsupported")
    field,operand=next(iter(value.items()))
    if field not in fields: raise ValueError("Elasticsearch query references an unavailable field")
    if kind=="terms":
        if not isinstance(operand,list) or not 1<=len(operand)<=32 or any(not isinstance(x,(str,int,float,bool)) for x in operand): raise ValueError("Elasticsearch terms values are invalid")
    elif kind=="range":
        if not isinstance(operand,dict) or set(operand)-{"gt","gte","lt","lte"} or not operand: raise ValueError("Elasticsearch range is invalid")
    elif isinstance(operand,dict):
        if set(operand)-{"value","case_insensitive"} or "value" not in operand: raise ValueError("Elasticsearch query options are unsupported")
    elif not isinstance(operand,(str,int,float,bool)):
        raise ValueError("Elasticsearch query value is invalid")


def expand_anchor_selectors(raw: Any, evidence: list[dict]) -> Any:
    """Derive validated entity selectors from model-cited evidence references."""
    if not isinstance(raw, dict): return raw
    value=dict(raw); wanted=value.get("anchor_evidence_ids",[])
    if not isinstance(wanted,list): return value
    records={e.get("evidence_id"):e for e in evidence if e.get("evidence_id")}
    selected=[records[x] for x in wanted[:1] if x in records]
    ips=list(value.get("ips",[])) if isinstance(value.get("ips"),list) else []
    hosts=list(value.get("hostnames",[])) if isinstance(value.get("hostnames"),list) else []
    # Preserve explicit model selectors. Adding every entity from an anchor on
    # top of them turns useful pivots into IP AND hostname AND term queries.
    if ips or hosts:
        return value
    for event in selected:
        raw_event=event.get("raw",{}) if isinstance(event.get("raw"),dict) else {}
        anchor_ips=[]
        for key in ("source.ip","destination.ip","srcIp","dstIp","src_ip","dst_ip","ip.src","ip.dst","ipSource","ipDestination","host.ip"):
            candidate=raw_event.get(key)
            if candidate is None and "." in key:
                parent,child=key.split(".",1); candidate=raw_event.get(parent,{}).get(child) if isinstance(raw_event.get(parent),dict) else None
            for candidate in candidate if isinstance(candidate,list) else [candidate]:
                if isinstance(candidate,str):
                    try: address=str(ipaddress.ip_address(candidate))
                    except ValueError: continue
                    if address not in anchor_ips: anchor_ips.append(address)
        source=value.get("source")
        domain_fields=("dns.question.name","dns.qry.name","dns.host","http.host","host.http",
                       "tls.handshake.extensions_server_name")
        domain_candidates=[]
        for field in domain_fields:
            candidate=raw_event.get(field)
            if candidate is None and "." in field:
                parent,child=field.split(".",1)
                candidate=raw_event.get(parent,{}).get(child) if isinstance(raw_event.get(parent),dict) else None
            domain_candidates.extend(candidate if isinstance(candidate,list) else [candidate])
        # A host asset label (for example, "corpdns") is not a DNS name or
        # HTTP Host value. It is safe as a host selector in Elasticsearch, but
        # mapping it into Arkime's dns.host/host.http fields creates false
        # constraints that can make a valid network pivot impossible.
        if source=="elasticsearch":
            candidates=[event.get("asset"),raw_event.get("host.name"),raw_event.get("host.hostname")]
        else:
            candidates=domain_candidates if not anchor_ips else []
        for candidate in candidates:
            if not isinstance(candidate,str) or not candidate: continue
            try: ipaddress.ip_address(candidate); continue
            except ValueError: pass
            if _safe_host(candidate) and candidate not in hosts: hosts.append(candidate)
        if not hosts:
            ips.extend(address for address in anchor_ips if address not in ips)
    value["ips"]=ips[:8]; value["hostnames"]=hosts[:8]
    return value


def anchor_time_range(spec: dict[str, Any], evidence: list[dict], mission_range: dict[str, str] | None):
    """Return an anchored ±15 minute UTC interval intersected with mission scope."""
    ids=spec.get("anchor_evidence_ids",[])
    if not ids: return mission_range, None
    records={e.get("evidence_id"):e for e in evidence if e.get("evidence_id")}
    event=records.get(ids[0])
    if not event: raise ValueError("Search anchor does not reference available evidence")
    observed=event.get("observed_at")
    if not isinstance(observed,str): raise ValueError("Search anchor has no usable timestamp")
    try:
        dt=datetime.fromisoformat(observed.replace("Z","+00:00"))
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        dt=dt.astimezone(timezone.utc)
    except ValueError as exc: raise ValueError("Search anchor timestamp is invalid") from exc
    start=dt-timedelta(minutes=15); end=dt+timedelta(minutes=15)
    if mission_range:
        base_start=_parse_scope_time(mission_range.get("gte"),start)
        base_end=_parse_scope_time(mission_range.get("lte"),end)
        start=max(start,base_start); end=min(end,base_end)
    if start>end: raise ValueError("Search anchor falls outside the configured mission time window")
    interval={"gte":start.isoformat(timespec="seconds"),"lte":end.isoformat(timespec="seconds")}
    label=f"{interval['gte']} through {interval['lte']} (±15m around evidence {ids[0]})"
    return interval,label


def _parse_scope_time(value, default):
    if not isinstance(value,str): return default
    now=datetime.now(timezone.utc)
    if value=="now": return now
    m=re.fullmatch(r"now-(\d+)([smhd])",value)
    if m:
        amount=int(m.group(1)); unit=m.group(2); factor={"s":1,"m":60,"h":3600,"d":86400}[unit]
        return now-timedelta(seconds=amount*factor)
    try:
        dt=datetime.fromisoformat(value.replace("Z","+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except ValueError: return default


def compile_es(spec: dict[str, Any], fields: list[str], timestamp_field: str, time_range: dict[str, str] | None) -> dict[str, Any]:
    groups = []
    actual = set(fields)
    text_fields = [f for f in spec.get("fields", []) if f in actual and f in TEXT_FIELDS][:4]
    if spec.get("terms"):
        if not text_fields:
            text_fields = [f for f in TEXT_FIELDS if f in actual][:4]
        if text_fields:
            groups.append([{"match_phrase": {field: term}} for field in text_fields for term in spec["terms"][:4]])
    ip_fields = [f for f in IP_FIELDS if f in actual][:4]
    host_fields = [f for f in HOST_FIELDS if f in actual][:3]
    port_fields = [f for f in PORT_FIELDS if f in actual][:4]
    event_fields = [f for f in EVENT_FIELDS if f in actual][:3]
    protocol_fields = [f for f in PROTOCOL_FIELDS if f in actual][:3]
    if spec.get("ips") and ip_fields: groups.append([{"term": {f: ip}} for f in ip_fields for ip in spec["ips"][:4]])
    if spec.get("hostnames") and host_fields: groups.append([{"match_phrase": {f: h}} for f in host_fields for h in spec["hostnames"][:3]])
    if spec.get("ports") and port_fields: groups.append([{"terms": {f: spec["ports"][:6]}} for f in port_fields])
    if spec.get("event_codes") and event_fields: groups.append([{"terms": {f: spec["event_codes"][:8]}} for f in event_fields])
    if spec.get("protocols") and protocol_fields: groups.append([{"terms": {f: spec["protocols"][:4]}} for f in protocol_fields])
    if not groups:
        raise ValueError("No requested selector maps to fields in the Elasticsearch mapping")
    must = [{"bool": {"should": group, "minimum_should_match": 1}} for group in groups if group]
    filters = []
    if time_range:
        if timestamp_field not in actual:
            raise ValueError("No mapped timestamp field is available to enforce the hunt time window")
        filters.append({"range": {timestamp_field: time_range}})
    query = {"bool": {"must": must, **({"filter": filters} if filters else {})}}
    _limit_dsl(query)
    return query


def compile_arkime(spec: dict[str, Any]) -> str:
    groups = []
    port_map = {"smb": [139, 445], "rdp": [3389], "dcom": [135], "ssh": [22], "vnc": [5900], "winrm": [5985, 5986]}
    semantic_protocols=set(spec.get("protocols",[]))
    requested_ports=list(spec.get("ports",[]))
    arkime_protocol={"smb":"smb","rdp":"rdp","dcom":"dcerpc","ssh":"ssh","vnc":"vnc","winrm":"http"}
    protocol_clauses=[]
    for proto in spec.get("protocols", []):
        if proto in port_map:
            if requested_ports: protocol_clauses.append(f"protocols == {arkime_protocol[proto]}")
            else: protocol_clauses.extend(f"port == {port}" for port in port_map[proto])
        elif proto == "http":
            protocol_clauses.append("protocols == http")
        elif proto in {"https", "tls"}:
            protocol_clauses.append("protocols == tls")
        elif proto in {"dns", "tcp", "udp", "icmp"}:
            protocol_clauses.append(f"protocols == {proto}")
    # Protocol and port remain separate AND constraints. This intentionally
    # supports protocol traffic on nonstandard ports (for example TLS/10443 or
    # SSH/2222), which is often the behavior a hunt needs to find.
    if requested_ports:
        groups.append("(" + " || ".join(f"port == {p}" for p in requested_ports[:6]) + ")")
    if protocol_clauses:
        groups.append("(" + " || ".join(list(dict.fromkeys(protocol_clauses))[:12]) + ")")
    if spec.get("ips"):
        groups.append("(" + " || ".join(f"ip.src == {ip} || ip.dst == {ip}" for ip in spec["ips"][:2]) + ")")
    if spec.get("hostnames"):
        if semantic_protocols and semantic_protocols <= {"dns"}:
            hostname_fields=["dns.host"]
        elif semantic_protocols and semantic_protocols <= {"http","https","tls"}:
            hostname_fields=["host.http"]
        elif semantic_protocols and semantic_protocols <= set(port_map):
            hostname_fields=[]
        else:
            hostname_fields=["dns.host","host.http"]
        if not hostname_fields:
            raise ValueError("Arkime cannot apply the requested hostname selector to the selected protocol")
        groups.append("(" + " || ".join(f"{field} == *{host}*" for field in hostname_fields for host in spec["hostnames"][:2]) + ")")
    if spec.get("terms"):
        term_clauses = []
        fields = spec.get("fields", [])
        term_field_set={"http.uri","http.user-agent","host.http","dns.host"}
        if semantic_protocols and semantic_protocols <= {"dns"}:
            protocol_fields={"dns.host"}
        elif semantic_protocols and semantic_protocols <= {"http"}:
            protocol_fields={"http.uri","http.user-agent","host.http"}
        elif semantic_protocols and semantic_protocols <= {"https","tls"}:
            # Arkime's TLS parser records the server name in host.http.
            protocol_fields={"host.http"}
        elif semantic_protocols and semantic_protocols <= set(port_map):
            protocol_fields=set()
        else:
            protocol_fields=term_field_set
        requested_fields=[f for f in fields if f in term_field_set]
        # Respect explicitly chosen fields. If the model selected HTTP fields
        # while requesting DNS, omit the inapplicable term instead of silently
        # translating it into a different network field.
        allowed=[f for f in requested_fields if f in protocol_fields] if requested_fields else sorted(protocol_fields)
        if not allowed:
            raise ValueError("Requested Arkime term fields do not match the selected protocol")
        for term in spec["terms"][:2]:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", term):
                continue
            term_clauses.extend(f"{field} == *{variant}*" for variant in _case_variants(term) for field in allowed[:2])
        if not term_clauses:
            raise ValueError("No Arkime text selector could be compiled")
        groups.append("(" + " || ".join(term_clauses[:20]) + ")")
    if not groups:
        raise ValueError("No Arkime selectors could be compiled")
    expression = " && ".join(groups)
    if len(expression) > 512:
        raise ValueError("Compiled Arkime expression exceeds 512 characters")
    return expression


def candidate_network_spec(
    lead: Mapping[str, Any],
    technique: Mapping[str, Any],
    *,
    require_entity: bool,
) -> dict[str, Any]:
    """Build one validated entity family plus bounded behavior selectors."""
    ips = []
    for value in lead.get("ips", []) if isinstance(lead.get("ips"), list) else []:
        try:
            normalized = str(ipaddress.ip_address(str(value)))
        except ValueError:
            continue
        ips.append(normalized)
        break

    hostnames = []
    if not ips:
        for value in lead.get("hostnames", []) if isinstance(lead.get("hostnames"), list) else []:
            text = str(value)
            if _safe_host(text) and not _contains_malformed_ipv4_token(text):
                hostnames.append(text.lower())
                break

    if require_entity and not (ips or hostnames):
        raise ValueError("candidate network pivot requires a safe IP or hostname entity")

    ports = []
    for value in technique.get("ports", []) if isinstance(technique.get("ports"), list) else []:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
        if len(ports) >= 6:
            break

    protocols = []
    for value in technique.get("protocols", []) if isinstance(technique.get("protocols"), list) else []:
        protocol = str(value).lower()
        if protocol in PROTOCOLS and protocol not in protocols:
            protocols.append(protocol)
        if len(protocols) >= 4:
            break
    if not require_entity and not (ips or hostnames or ports or protocols):
        protocols = ["tcp", "udp", "icmp"]

    return {
        "terms": [],
        "fields": [],
        "ips": ips,
        "hostnames": hostnames,
        "ports": ports,
        "protocols": protocols,
        "event_codes": [],
    }


def compile_tshark(spec: dict[str, Any]) -> tuple[str, list[str]]:
    groups = []
    port_map = {"smb": [139, 445], "rdp": [3389], "dcom": [135], "ssh": [22], "vnc": [5900], "winrm": [5985, 5986]}
    protocol_map = {"http": ["http"], "https": ["tls"], "dns": ["dns"], "tls": ["tls"], "tcp": ["tcp"], "udp": ["udp"], "icmp": ["icmp"]}
    semantic_protocols=set(spec.get("protocols",[]))
    requested_ports=list(dict.fromkeys(spec.get("ports", [])))
    if requested_ports:
        groups.append("(" + " || ".join(f"tcp.port == {p} || udp.port == {p}" for p in requested_ports[:12]) + ")")
    protocol_clauses=[]
    tshark_protocol={"smb":"smb2","rdp":"rdp","dcom":"dcerpc","ssh":"ssh","vnc":"vnc","winrm":"http"}
    for proto in spec.get("protocols", []):
        if proto in port_map:
            if requested_ports: protocol_clauses.append(tshark_protocol[proto])
            else: protocol_clauses.extend(f"(tcp.port == {port} || udp.port == {port})" for port in port_map[proto])
        else:
            protocol_clauses.extend(protocol_map.get(proto, []))
    if protocol_clauses:
        groups.append("(" + " || ".join(list(dict.fromkeys(protocol_clauses))[:12]) + ")")
    if spec.get("ips"):
        ips = []
        for ip in spec["ips"][:6]:
            field = "ipv6.addr" if ":" in ip else "ip.addr"
            if field == "ipv6.addr":
                # ipv6.addr is valid in Wireshark but intentionally added only here,
                # after the address was parsed and normalized.
                ips.append(f"ipv6.addr == {ip}")
            else:
                ips.append(f"ip.addr == {ip}")
        groups.append("(" + " || ".join(ips) + ")")
    field_families={"dns":{"dns.qry.name"},"http":{"http.host","http.request.uri","http.user_agent"},
                    "https":{"tls.handshake.extensions_server_name"},
                    "tls":{"tls.handshake.extensions_server_name"},"smb":{"smb2.filename"}}
    selected_field_set={f for f in spec.get("fields",[]) if f in SOURCE_FIELDS["tshark"]}
    requested_term_fields=selected_field_set & {"dns.qry.name","http.host","http.request.uri","http.user_agent",
        "tls.handshake.extensions_server_name","smb2.filename"}
    if semantic_protocols:
        allowed_term_fields=set().union(*(field_families.get(p,set()) for p in semantic_protocols))
        term_fields=[f for f in requested_term_fields if f in allowed_term_fields] if requested_term_fields else sorted(allowed_term_fields)
    else:
        term_fields=list(requested_term_fields) if requested_term_fields else ["dns.qry.name","http.host","tls.handshake.extensions_server_name","smb2.filename"]
    if spec.get("hostnames"):
        if semantic_protocols:
            hostfields=[f for f in ("dns.qry.name","http.host","tls.handshake.extensions_server_name") if f in allowed_term_fields][:2]
        else:
            hostfields=[f for f in ("dns.qry.name", "http.host", "tls.handshake.extensions_server_name") if f in SOURCE_FIELDS["tshark"]][:2]
        if not hostfields:
            raise ValueError("TShark cannot apply the requested hostname selector to the selected protocol")
        groups.append("(" + " || ".join(f'{field} contains "{host}"' for field in hostfields for host in spec["hostnames"][:1]) + ")")
        term_fields.extend(f for f in hostfields if f not in term_fields)
    if spec.get("terms"):
        if not term_fields:
            raise ValueError("No TShark term field matches the selected protocol")
        selectors = []
        for field in term_fields[:2]:
            for term in spec["terms"][:2]:
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", term):
                    selectors.extend(f'{field} contains "{variant}"' for variant in _case_variants(term)[:2])
        if not selectors:
            raise ValueError("No TShark text selector could be compiled")
        groups.append("(" + " || ".join(selectors[:12]) + ")")
    if not groups:
        raise ValueError("No TShark selectors could be compiled")
    expression = " && ".join(f"({x})" for x in groups)
    # Reserve room for the adapter's enforced packet time expression.
    if len(expression) > 400:
        raise ValueError("Compiled TShark display filter exceeds the safe pre-time-filter limit")
    fields = list(dict.fromkeys(["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", *term_fields,
        *[f for f in spec.get("fields", []) if f in SOURCE_FIELDS["tshark"]]]))[:16]
    return expression, fields


def _limit_dsl(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    if depth > 12:
        raise ValueError("Compiled Elasticsearch query exceeds depth limit")
    if isinstance(value, dict):
        for child in value.values():
            count[0] += 1
            if count[0] > 256:
                raise ValueError("Compiled Elasticsearch query exceeds clause limit")
            _limit_dsl(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value:
            _limit_dsl(child, depth + 1, count)


def _strings(value: Any, check, limit: int, max_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:limit * 2]:
        if isinstance(item, str) and len(item) <= max_length and check(item) and item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def _integers(value: Any, limit: int, low: int, high: int) -> list[int]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:limit * 2]:
        if isinstance(item, int) and not isinstance(item, bool) and low <= item <= high and item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def _safe_term(value: str) -> bool:
    return bool(value.strip()) and value == value.strip() and re.fullmatch(r"[A-Za-z0-9_.:/@+\\=-][A-Za-z0-9_.:/@+\\= -]{0,79}", value) is not None


def _safe_field(value: str) -> bool:
    return bool(re.fullmatch(r"[@A-Za-z0-9_][@A-Za-z0-9_.-]{0,159}", value))


def _safe_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _contains_malformed_ipv4_token(value: str) -> bool:
    for candidate in re.findall(r"(?<![0-9])(?:[0-9]{1,3}[.,]){3}[0-9]{1,3}(?![0-9])", value):
        if not _safe_ip(candidate):
            return True
    return False


def _safe_host(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?", value))


def _case_variants(term: str) -> list[str]:
    known={"linpeas":["linpeas","LinPEAS","LINPEAS"],"linenum":["linenum","LinEnum","LINENUM"],
        "wget":["wget","Wget"],"curl":["curl","Curl"],"meterpreter":["meterpreter","Meterpreter"],
        "pwnkit":["pwnkit","PwnKit"],"certutil":["certutil","CertUtil"],"bitsadmin":["bitsadmin","BITSAdmin"]}
    values=known.get(term.lower(),[term,term[:1].upper()+term[1:]])
    return list(dict.fromkeys(values))


def _clean_text(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", value).strip()[:limit] if isinstance(value, str) else ""
