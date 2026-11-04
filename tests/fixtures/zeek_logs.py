"""Synthetic Zeek analyzer-log records (dns, http, ssl, x509, files, pe, ssh, notice, weird, signatures, intel and the
application logs) written in every shipper layout ROMULUS reads.

Every value is synthetic (documentation addresses, made-up uids, file ids and digests). Only the published field
layouts are reproduced; no upstream file is copied. Each writer below follows, step by step, the pipeline it names:

- Zeek's own records: zeek/zeek tag v8.0.0 (commit f07a59d32cbbefdd7706bbe47a053f350c36aed0), the Info records of
  scripts/base/protocols/{dns,http,ssl,ssh,ftp,smtp,irc,mysql,postgresql,redis,socks,sip,snmp,radius}/main.zeek
  (ftp: info.zeek), base/protocols/http/entities.zeek, base/protocols/ssl/files.zeek,
  base/frameworks/{files,notice,signatures,intel,tunnels}/main.zeek, base/frameworks/notice/weird.zeek,
  base/files/{x509,pe,hash,extract}/main.zeek and policy/protocols/ssl/validate-certs.zeek; Zeek 5.0's files log
  (tag v5.0.0: tx_hosts, rx_hosts, conn_uids) and Zeek 4.0's x509 and ssl logs (tag v4.0.0: x509 `id`, ssl
  `cert_chain_fuids`). Zeek's JSON writer flattens nested records into literal dotted keys ("certificate.subject").
  Package fields: salesforce/ja3 zeek/ja3.zeek and ja3s.zeek, salesforce/hassh zeek/hassh.zeek, FoxIO JA4+ (ja4,
  ja4s, ja4h; field names as Malcolm's and Security Onion's pipelines read them: not checked against FoxIO's own
  scripts). The TDS log is amzn/zeek-plugin-tds scripts/TDS/main.zeek at commit
  9ffc62cc66dc99ddc473919c92c6ee1810160c8e (path "tds", column "command"). Zeek's names for a DNS code without a
  mnemonic ("query-N", "rcode-N") are from base/protocols/dns/consts.zeek.
- Malcolm (cisagov/Malcolm, Apache-2.0) at commit 541160e513de90ed4ea5af1d1ed7a8a64758bf8d,
  logstash/pipelines/zeek/: 1001_zeek_parse.conf (JSON parsed, id.* renamed), the per-log 10xx_zeek_<log>.conf (JSON
  renames, added proto/service), 1200_zeek_mutate.conf (shared lifts; per-log moves listed in the writer),
  1300_zeek_normalize.conf (intel, files source), 1400_zeek_convert.conf (times as ISO), and
  enrichment/97_arkimize.conf (node).
- Elastic (elastic/integrations, Elastic License 2.0) at commit 8518218716a47fdd55b5e766f15e9fed1e5c3fe2:
  packages/zeek/data_stream/<stream>/elasticsearch/ingest_pipeline/default.yml for the renames, and
  _dev/test/pipeline/test-<stream>.log-expected.json for the resulting document layout.
- Security Onion 2.4 (Security-Onion-Solutions/securityonion) at commit 742649a33797ceb85a111402fb48cd3839d2fcbb:
  salt/elasticsearch/files/ingest/zeek.<log>, zeek.common, zeek.common_ssl and ingest-dynamic/common (dataset
  prefixed with the module, message2 removed), salt/elasticfleet/files/integrations-dynamic/grid-nodes_general/
  zeek-logs.json (event.module and data_stream.dataset "zeek").
"""
from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

from romulus.evidence.community import community_id

SENSOR = "sensor-zeek-01"
T0 = 1731938400.123                         # 2024-11-18T14:00:00.123Z
INDEX = {"malcolm": "arkime_sessions3-241118", "elastic": "logs-zeek.{stream}-default",
         "security_onion": "logs-zeek-so", "plain": "zeek-json-241118"}
SHAPES = ("malcolm", "elastic", "security_onion", "plain")
CLIENT, SERVER = "10.0.0.5", "203.0.113.10"


def iso_ms(ts: float) -> str:
    ms = round(ts * 1000)
    when = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=ms // 1000)
    return when.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms % 1000:03d}Z"


@dataclass(frozen=True)
class Row:
    """One logical record of a Zeek analyzer log, as Zeek's JSON writer emits it: literal dotted keys, unset fields
    omitted, sets and vectors as arrays. `ts` is added by the writers."""
    log: str
    zeek: dict = field(hash=False)
    ts: float = T0

    def with_(self, **changes) -> Row:
        """The record with Zeek fields changed (None removes one); dotted names are passed as dict keys."""
        zeek = dict(self.zeek)
        for name, value in changes.items():
            if value is None:
                zeek.pop(name, None)
            else:
                zeek[name] = value
        return replace(self, zeek=zeek)

    def without(self, *names: str) -> Row:
        return replace(self, zeek={k: v for k, v in self.zeek.items() if k not in names})

    def json(self) -> dict:
        return {"ts": self.ts, **copy.deepcopy(self.zeek)}


def _conn(uid: str, orig_p: int, resp_p: int, resp_h: str = SERVER, orig_h: str = CLIENT) -> dict:
    return {"uid": uid, "id.orig_h": orig_h, "id.orig_p": orig_p, "id.resp_h": resp_h, "id.resp_p": resp_p}


# Synthetic digests: the right lengths, made-up values.
FP_LEAF = "1f" * 32
FP_CA = "2e" * 32
FUID_HTTP = "FhttpResp00000001"
UID_HTTP = "ChttpTxn000000001"

DNS = Row("dns", {**_conn("CdnsQuery00000001", 53001, 53, "198.51.100.53"), "proto": "udp", "trans_id": 4242,
                  "rtt": 0.0123, "query": "www.example.test", "qclass": 1, "qclass_name": "C_INTERNET",
                  "qtype": 1, "qtype_name": "A", "rcode": 0, "rcode_name": "NOERROR", "AA": False, "TC": False,
                  "RD": True, "RA": True, "Z": 0, "answers": ["www-cdn.example.test", "192.0.2.80"],
                  "TTLs": [300.0, 60.0], "rejected": False})
HTTP = Row("http", {**_conn(UID_HTTP, 51010, 80), "trans_depth": 1, "method": "GET", "host": "www.example.test",
                    "uri": "/download/report.pdf?id=7", "referrer": "http://www.example.test/", "version": "1.1",
                    "user_agent": "ExampleAgent/2.0", "request_body_len": 0, "response_body_len": 48213,
                    "status_code": 200, "status_msg": "OK", "tags": [], "resp_fuids": [FUID_HTTP],
                    "resp_filenames": ["report.pdf"], "resp_mime_types": ["application/pdf"],
                    "ja4h": "ge11nn050000_4740ae6347b0_000000000000_000000000000"})
SSL = Row("ssl", {**_conn("CsslSess000000001", 51020, 443), "version": "TLSv12",
                  "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "curve": "x25519",
                  "server_name": "www.example.test", "resumed": False, "established": True,
                  "ssl_history": "CsxknGIi", "cert_chain_fps": [FP_LEAF, FP_CA],
                  "subject": "CN=www.example.test,O=Example Org,C=US",
                  "issuer": "CN=Example Issuing CA,O=Example Org,C=US", "sni_matches_cert": True,
                  "validation_status": "ok", "ja3": "0123456789abcdef0123456789abcdef",
                  "ja3s": "fedcba9876543210fedcba9876543210", "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
                  "ja4s": "t130200_1301_234ea6891581"})
X509 = Row("x509", {"fingerprint": FP_LEAF, "certificate.version": 3, "certificate.serial": "0A1B2C3D4E5F",
                    "certificate.subject": "CN=www.example.test,O=Example Org,C=US",
                    "certificate.issuer": "CN=Example Issuing CA,O=Example Org,C=US",
                    "certificate.not_valid_before": 1730419200.0, "certificate.not_valid_after": 1738368000.0,
                    "certificate.key_alg": "rsaEncryption", "certificate.sig_alg": "sha256WithRSAEncryption",
                    "certificate.key_type": "rsa", "certificate.key_length": 2048, "certificate.exponent": "65537",
                    "san.dns": ["www.example.test", "example.test"], "san.ip": ["203.0.113.10"],
                    "basic_constraints.ca": False, "basic_constraints.path_len": 0, "host_cert": True,
                    "client_cert": False})
FILES = Row("files", {"fuid": FUID_HTTP, **_conn(UID_HTTP, 51010, 80), "source": "HTTP", "depth": 0,
                      "analyzers": ["MD5", "SHA1", "SHA256", "PE"], "mime_type": "application/x-dosexec",
                      "filename": "update.exe", "duration": 0.25, "local_orig": False, "is_orig": False,
                      "seen_bytes": 48213, "total_bytes": 48213, "missing_bytes": 0, "overflow_bytes": 0,
                      "timedout": False, "md5": "0c" * 16, "sha1": "1d" * 20, "sha256": "2e" * 32,
                      "extracted": "extract-HTTP-FhttpResp00000001.exe", "extracted_cutoff": False,
                      "extracted_size": 48213})
# Zeek 5.0's layout of the same file: sets of connections and hosts instead of one connection
FILES_50 = Row("files", {**{k: v for k, v in FILES.zeek.items()
                            if k not in ("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")},
                         "tx_hosts": [SERVER], "rx_hosts": [CLIENT], "conn_uids": [UID_HTTP]})
PE = Row("pe", {"id": FUID_HTTP, "machine": "AMD64", "compile_ts": 1700000000.0,
                "os": "Windows XP x64 or Server 2003", "subsystem": "WINDOWS_GUI", "is_exe": True, "is_64bit": True,
                "uses_aslr": True, "uses_dep": True, "uses_code_integrity": False, "uses_seh": True,
                "has_import_table": True, "has_export_table": False, "has_cert_table": False,
                "has_debug_data": True, "section_names": [".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc"]})
SSH = Row("ssh", {**_conn("CsshSess000000001", 51030, 22), "version": 2, "auth_success": False,
                  "auth_attempts": 3, "direction": "OUTBOUND", "client": "SSH-2.0-OpenSSH_9.6",
                  "server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "cipher_alg": "chacha20-poly1305@openssh.com",
                  "mac_alg": "umac-64-etm@openssh.com", "compression_alg": "none", "kex_alg": "curve25519-sha256",
                  "host_key_alg": "ssh-ed25519", "host_key": "4f:1a:2b:3c:4d:5e:6f:70:81:92:a3:b4:c5:d6:e7:f8",
                  "hassh": "aa11bb22cc33dd44ee55ff6600778899", "hasshServer": "99887766ff55ee44dd33cc22bb11aa00"})
NOTICE = Row("notice", {**_conn("CnoticeConn000001", 51040, 443), "proto": "tcp",
                        "note": "SSL::Invalid_Server_Cert",
                        "msg": "SSL certificate validation failed with (self signed certificate)",
                        "sub": "CN=selfsigned.example.test", "src": CLIENT, "dst": SERVER, "p": 443,
                        "peer_descr": "worker-1", "actions": ["Notice::ACTION_LOG"], "suppress_for": 3600.0})
WEIRD = Row("weird", {**_conn("CweirdConn0000001", 51045, 443), "name": "bad_TCP_checksum", "addl": "seq 7",
                      "notice": False, "peer": "worker-1", "source": "TCP"})
SIGNATURES = Row("signatures", {"uid": "CsigConn000000001", "src_addr": CLIENT, "src_port": 51050,
                                "dst_addr": SERVER, "dst_port": 80, "note": "Signatures::Sensitive_Signature",
                                "sig_id": "synthetic-sig-1", "event_msg": "10.0.0.5: synthetic payload marker",
                                "sub_msg": "GET /probe"})
INTEL = Row("intel", {**_conn("CintelConn0000001", 51060, 443), "seen.indicator": "listed.example.test",
                      "seen.indicator_type": "Intel::DOMAIN", "seen.where": "SSL::IN_SERVER_NAME",
                      "seen.node": "worker-1", "matched": ["Intel::DOMAIN"], "sources": ["synthetic-feed"]})
FTP = Row("ftp", {**_conn("CftpCtrl000000001", 51070, 21), "user": "ftpuser1", "command": "RETR",
                  "arg": "ftp://203.0.113.10/pub/tool.bin", "mime_type": "application/octet-stream",
                  "file_size": 1024, "reply_code": 226, "reply_msg": "Transfer complete.",
                  "data_channel.passive": True, "data_channel.orig_h": CLIENT, "data_channel.resp_h": SERVER,
                  "data_channel.resp_p": 50000, "fuid": "Fftp0000000000001"})
SMTP = Row("smtp", {**_conn("CsmtpConn00000001", 51080, 25), "trans_depth": 1, "helo": "mail.example.test",
                    "mailfrom": "<alice@example.test>", "rcptto": ["<bob@example.net>"],
                    "date": "Mon, 18 Nov 2024 14:00:00 +0000", "from": "Alice <alice@example.test>",
                    "to": ["Bob <bob@example.net>"], "cc": ["Carol <carol@example.net>"],
                    "reply_to": "alice@example.test", "msg_id": "<msg-1@example.test>",
                    "subject": "Quarterly report", "x_originating_ip": "192.0.2.25",
                    "last_reply": "250 2.0.0 Ok: queued", "path": [SERVER, CLIENT], "user_agent": "ExampleMail 1.0",
                    "tls": False, "fuids": ["Fsmtp000000000001"]})
# a USER row, the one command whose addl is its own (host, server and real name)
IRC = Row("irc", {**_conn("CircConn000000001", 51090, 6667), "nick": "synthbot", "user": "synth",
                  "command": "USER", "value": "synth", "addl": "localhost irc.example.test Synthetic Bot"})
MYSQL = Row("mysql", {**_conn("CmysqlConn0000001", 51100, 3306), "cmd": "query", "arg": "SELECT 1", "success": True,
                      "rows": 1, "response": "OK"})
TDS = Row("tds", {**_conn("CtdsConn000000001", 51110, 1433), "command": "SQLBatch"})
POSTGRESQL = Row("postgresql", {**_conn("CpgConn0000000001", 51120, 5432), "user": "app", "database": "inventory",
                                "application_name": "psql", "frontend": "simple_query", "frontend_arg": "SELECT 1",
                                "backend": "command_complete", "backend_arg": "SELECT 1", "success": True,
                                "rows": 1})
REDIS = Row("redis", {**_conn("CredisConn0000001", 51130, 6379), "cmd.name": "GET", "cmd.key": "session:42",
                      "success": True, "reply.value": "cached"})
SOCKS = Row("socks", {**_conn("CsocksConn0000001", 51140, 1080), "version": 5, "status": "succeeded",
                      "request.host": "198.51.100.90", "request_p": 443, "bound.host": "0.0.0.0", "bound_p": 0})
TUNNEL = Row("tunnel", {**_conn("CtunnelConn000001", 0, 0), "tunnel_type": "Tunnel::IP",
                        "action": "Tunnel::DISCOVER"})
SIP = Row("sip", {**_conn("CsipConn000000001", 5060, 5060), "trans_depth": 0, "method": "INVITE",
                  "uri": "sip:bob@example.net", "call_id": "call-1@example.test",
                  "request_from": "<sip:alice@example.test>", "request_to": "<sip:bob@example.net>",
                  "status_code": 200, "status_msg": "OK", "user_agent": "ExamplePhone/1.0", "seq": "1 INVITE"})
SNMP = Row("snmp", {**_conn("CsnmpConn00000001", 51150, 161), "duration": 0.5, "version": "2c",
                    "community": "synthetic-community", "get_requests": 2, "get_bulk_requests": 0,
                    "get_responses": 2, "set_requests": 0, "display_string": "Synthetic device",
                    "up_since": 1731000000.0})
RADIUS = Row("radius", {**_conn("CradiusConn000001", 51160, 1812), "username": "alice", "mac": "00:00:5e:00:53:10",
                        "framed_addr": "10.0.10.20", "reply_msg": "Welcome", "result": "success", "ttl": 0.1})

# ---- the Windows-protocol logs (Zeek's smb, dce-rpc, krb, ntlm, rdp, rfb, ldap, dhcp, software and known-* scripts at
# tag v8.0.0; ldap's Zeek 6.1 layout at tag v6.1.0) ----------------------------------------------------------------

DC, WS = "10.0.0.10", CLIENT
UID_SMB = "CsmbConn000000001"
FUID_SMB = "FsmbFile000000001"
SHARE = "\\\\DC01\\ADMIN$"                  # Zeek's tree path: \\DC01\ADMIN$
SMB_FILES = Row("smb_files", {**_conn(UID_SMB, 51200, 445, DC), "fuid": FUID_SMB, "action": "SMB::FILE_OPEN",
                              "path": SHARE, "name": "Temp\\svc-update.exe", "size": 73802,
                              "times.modified": 1731938300.5, "times.accessed": 1731938300.5,
                              "times.created": 1731938300.25, "times.changed": 1731938300.5})
SMB_MAPPING = Row("smb_mapping", {**_conn(UID_SMB, 51200, 445, DC), "path": SHARE, "service": "A:",
                                  "native_file_system": "NTFS", "share_type": "DISK"})
_REFERENCED = {"referenced_file.ts": T0, "referenced_file.uid": UID_SMB, "referenced_file.id.orig_h": WS,
               "referenced_file.id.orig_p": 51200, "referenced_file.id.resp_h": DC, "referenced_file.id.resp_p": 445,
               "referenced_file.fuid": FUID_SMB, "referenced_file.action": "SMB::FILE_OPEN",
               "referenced_file.path": SHARE, "referenced_file.name": "Temp\\svc-update.exe",
               "referenced_file.size": 73802}
SMB_CMD = Row("smb_cmd", {**_conn(UID_SMB, 51200, 445, DC), "command": "CREATE", "argument": "Temp\\svc-update.exe",
                          "status": "SUCCESS", "rtt": 0.000412, "version": "SMB2", "tree": SHARE,
                          "tree_service": "A:", **_REFERENCED})
# a command that references no file (Zeek writes no referenced_file.* keys)
SMB_CMD_NO_FILE = Row("smb_cmd", {**_conn(UID_SMB, 51200, 445, DC), "command": "TREE_CONNECT", "argument": SHARE,
                                  "status": "SUCCESS", "rtt": 0.000301, "version": "SMB2", "tree": SHARE,
                                  "tree_service": "A:"}, ts=T0 - 1)
DCE_RPC = Row("dce_rpc", {**_conn("CrpcConn000000001", 51210, 445, DC), "rtt": 0.000512, "named_pipe": "\\PIPE\\ntsvcs",
                          "endpoint": "svcctl", "operation": "CreateServiceW"})
KERBEROS = Row("kerberos", {**_conn("CkrbConn000000001", 51220, 88, DC), "request_type": "TGS",
                            "client": "alice/EXAMPLE.TEST", "service": "MSSQLSvc/sql01.example.test:1433",
                            "success": True, "from": 1731938390.0, "till": 2136422885.0, "cipher": "rc4-hmac",
                            "forwardable": True, "renewable": True,
                            "client_cert_subject": "CN=alice,OU=Users,DC=example,DC=test",
                            "client_cert_fuid": "FkrbCert000000001",
                            "server_cert_subject": "CN=dc01.example.test", "server_cert_fuid": "FkrbCert000000002"})
NTLM = Row("ntlm", {**_conn("CntlmConn00000001", 51230, 445, DC), "username": "alice", "hostname": "WS01",
                    "domainname": "EXAMPLE", "server_nb_computer_name": "DC01",
                    "server_dns_computer_name": "dc01.example.test", "server_tree_name": "example.test",
                    "success": True})
RDP = Row("rdp", {**_conn("CrdpConn000000001", 51240, 3389, "10.0.0.20"), "cookie": "alice", "result": "Success",
                  "security_protocol": "RDP", "client_channels": ["rdpdr", "rdpsnd", "cliprdr"],
                  "keyboard_layout": "English - United States", "client_build": "RDP 8.1", "client_name": "WS01",
                  "client_dig_product_id": "00000-00000-00000-AA000", "desktop_width": 1920,
                  "desktop_height": 1080, "requested_color_depth": "32bit", "cert_type": "RSA", "cert_count": 1,
                  "cert_permanent": False, "encryption_level": "Client compatible", "encryption_method": "128bit",
                  "ssl": False})
RFB = Row("rfb", {**_conn("CrfbConn000000001", 51250, 5900, "10.0.0.21"), "client_major_version": "003",
                  "client_minor_version": "008", "server_major_version": "003", "server_minor_version": "008",
                  "authentication_method": "VNC", "auth": True, "share_flag": True, "desktop_name": "ws21:0",
                  "width": 1280, "height": 800})
UID_LDAP = "CldapConn00000001"
LDAP = Row("ldap", {**_conn(UID_LDAP, 51260, 389, DC), "message_id": 1, "version": 3, "opcode": "bind SASL",
                    "result": "success", "diagnostic_message": "synthetic diagnostic",
                    "object": "CN=svc-app,OU=Service,DC=example,DC=test", "argument": "GSS-SPNEGO"})
LDAP_SEARCH = Row("ldap_search", {**_conn(UID_LDAP, 51260, 389, DC), "message_id": 2, "scope": "tree",
                                  "deref_aliases": "never", "base_object": "DC=example,DC=test", "result_count": 3,
                                  "result": "success", "diagnostic_message": "synthetic diagnostic",
                                  "filter": "(&(objectclass=user)(servicePrincipalName=*))",
                                  "attributes": ["sAMAccountName", "servicePrincipalName", "memberOf"]})
# Zeek 6.1's layout of the same records: sets and vectors where later Zeek writes one value
LDAP_61 = Row("ldap", {**{k: v for k, v in LDAP.zeek.items() if k not in (
    "opcode", "result", "diagnostic_message", "object", "argument")}, "opcodes": ["bind SASL"],
    "results": ["success"], "diagnostic_messages": ["synthetic diagnostic"],
    "objects": ["CN=svc-app,OU=Service,DC=example,DC=test"], "arguments": ["GSS-SPNEGO"]})
LDAP_SEARCH_61 = Row("ldap_search", {**{k: v for k, v in LDAP_SEARCH.zeek.items() if k not in (
    "scope", "deref_aliases", "base_object", "result", "diagnostic_message")}, "scopes": ["tree"],
    "derefs": ["never"], "base_objects": ["DC=example,DC=test"], "results": ["success"],
    "diagnostic_messages": ["synthetic diagnostic"]})
DHCP = Row("dhcp", {"uids": ["CdhcpConn00000001", "CdhcpConn00000002"], "client_addr": WS, "server_addr": "10.0.0.1",
                    "mac": "00:00:5e:00:53:05", "host_name": "WS01", "client_fqdn": "ws01.example.test",
                    "domain": "example.test", "requested_addr": WS, "assigned_addr": WS, "lease_time": 86400.0,
                    "client_message": "synthetic client message", "server_message": "synthetic server message",
                    "msg_types": ["REQUEST", "ACK"], "duration": 0.0042, "client_software": "MSFT 5.0",
                    "server_software": "synthetic-dhcpd 4.4", "msg_orig": [WS, "10.0.0.1"],
                    "circuit_id": "synthetic-circuit", "agent_remote_id": "synthetic-agent",
                    "subscriber_id": "synthetic-subscriber"})
SOFTWARE = Row("software", {"host": DC, "host_p": 22, "software_type": "SSH::SERVER", "name": "OpenSSH",
                            "version.major": 8, "version.minor": 9, "version.minor2": 0, "version.minor3": 1,
                            "version.addl": "p1", "unparsed_version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                            "url": "http://www.example.test/plugin"})
KNOWN_HOSTS = Row("known_hosts", {"host": WS})
KNOWN_SERVICES = Row("known_services", {"host": DC, "port_num": 88, "port_proto": "tcp", "service": ["KRB_TCP"]})
KNOWN_CERTS = Row("known_certs", {"host": DC, "port_num": 636, "subject": "CN=dc01.example.test",
                                  "issuer_subject": "CN=Example Issuing CA,O=Example Org,C=US",
                                  "serial": "0A1B2C3D4E5F6071"})
WINDOWS_ROWS = (SMB_FILES, SMB_MAPPING, SMB_CMD, DCE_RPC, KERBEROS, NTLM, RDP, RFB, LDAP, LDAP_SEARCH, DHCP, SOFTWARE,
                KNOWN_HOSTS, KNOWN_SERVICES, KNOWN_CERTS)

ROWS = {row.log: row for row in (DNS, HTTP, SSL, X509, FILES, PE, SSH, NOTICE, WEIRD, SIGNATURES, INTEL, FTP, SMTP,
                                 IRC, MYSQL, TDS, POSTGRESQL, REDIS, SOCKS, TUNNEL, SIP, SNMP, RADIUS, *WINDOWS_ROWS)}
# shipper streams and dataset names that differ from Zeek's own log name
ELASTIC_STREAMS = {"signatures": "signature"}
SO_NAMES = {"files": "file"}
# logs a shipper publishes no pipeline for (the catalog's absent_shapes)
NOT_WRITTEN = {"tds": {"elastic"}, "postgresql": {"elastic", "security_onion"},
               "redis": {"elastic", "security_onion"}, "smb_cmd": {"security_onion"},
               "ldap": {"elastic"}, "ldap_search": {"elastic"}, "known_hosts": {"security_onion"},
               "known_services": {"security_onion"}, "known_certs": {"security_onion"}}
# the transport each shipper knows for a log whose record has no proto (Malcolm's 10xx add_field, Elastic's set):
# used for the Community ID it writes
_TCP_WINDOWS = {log: "tcp" for log in ("smb_files", "smb_mapping", "smb_cmd", "dce_rpc", "ntlm", "rdp", "rfb")}
SHIPPER_TRANSPORT = {
    "malcolm": {"http": "tcp", "ssl": "tcp", "ftp": "tcp", "smtp": "tcp", "irc": "tcp", "tds": "tcp",
                "postgresql": "tcp", "redis": "tcp", "ssh": "tcp", "snmp": "udp", **_TCP_WINDOWS},
    # Elastic's kerberos pipeline sets tcp whatever the transport
    "elastic": {"http": "tcp", "ssl": "tcp", "ssh": "tcp", "ftp": "tcp", "smtp": "tcp", "irc": "tcp",
                "mysql": "tcp", "socks": "tcp", "sip": "udp", "snmp": "udp", "radius": "udp", **_TCP_WINDOWS,
                "kerberos": "tcp"},
    "security_onion": {"http": "tcp", "smtp": "tcp"},
}


def _set(doc: dict, path: str, value) -> None:
    """Set a dotted path in nested objects."""
    *parents, last = path.split(".")
    cur = doc
    for part in parents:
        cur = cur.setdefault(part, {})
    cur[last] = value


def _get(doc: dict, path: str):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _merge(base: dict, extra: dict) -> dict:
    """`extra` merged into `base`, objects merged key by key."""
    out = dict(base)
    for key, value in extra.items():
        out[key] = _merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def _prune(obj):
    if isinstance(obj, dict):
        pruned = {k: _prune(v) for k, v in obj.items()}
        return {k: v for k, v in pruned.items() if v is not None and v != {}}
    return obj


def _community(row: Row, transport: str | None):
    z = row.zeek
    if transport is None or not all(k in z for k in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")):
        return None
    return community_id(z["id.orig_h"], z["id.orig_p"], z["id.resp_h"], z["id.resp_p"], transport)


def _hit(shape: str, source: dict, nid: str, stream: str = "") -> dict:
    return {"_index": INDEX[shape].format(stream=stream), "_id": nid, "_source": _prune(source)}


def _text(value):
    """Zeek's text-log form of a value, as Malcolm keeps it for logs it reads as text."""
    if isinstance(value, bool):
        return "T" if value else "F"
    if isinstance(value, list):
        return ",".join(_text(v) for v in value)
    return value if value is None else str(value)


def _epoch_iso(seconds: float) -> str:
    """An epoch time as Logstash and Elasticsearch date processors write it: ISO-8601, milliseconds, Z."""
    return iso_ms(seconds)


# ---- plain Zeek JSON ---------------------------------------------------------------------------------------------

def plain(row: Row, nid: str = "pl-1", *, path: str | None = "", expanded: bool = False) -> dict:
    """Zeek's JSON line indexed as it is, with `_path` (the json-streaming-logs package) unless `path` is None."""
    source = row.json()
    if expanded:
        nested: dict = {}
        for key, value in source.items():
            _set(nested, key, value)
        source = nested
    if path is not None:
        source = {"_path": path or row.log, **source}
    return {"_index": INDEX["plain"], "_id": nid, "_source": source}


# ---- Malcolm -------------------------------------------------------------------------------------------------------

# 10xx_zeek_<log>.conf JSON renames (after 1001 renamed id.* to orig_h, orig_p, resp_h, resp_p)
MALCOLM_RENAMES = {
    "http": {"username": "user"},
    "ssl": {"version": "ssl_version"},
    "x509": {**{f"certificate.{k}": f"certificate_{k}" for k in (
        "version", "serial", "subject", "issuer", "not_valid_before", "not_valid_after", "key_alg", "sig_alg",
        "key_type", "key_length", "exponent", "curve")},
             **{f"san.{k}": f"san_{k}" for k in ("dns", "uri", "email", "ip")},
             "basic_constraints.ca": "basic_constraints_ca", "basic_constraints.path_len": "basic_constraints_path_len"},
    "pe": {"id": "fuid"},
    "signatures": {"dst_addr": "resp_h", "event_msg": "event_message", "sig_id": "signature_id",
                   "src_addr": "orig_h", "sub_msg": "sub_message"},
    "intel": {"seen.indicator": "seen_indicator", "seen.indicator_type": "seen_indicator_type",
              "seen.node": "seen_node", "seen.where": "seen_where"},
    "smtp": {"fuids": "fuid"},
    "redis": {"cmd.name": "cmd_name", "cmd.key": "cmd_key", "cmd.value": "cmd_value", "reply.value": "reply"},
    "socks": {"bound.host": "bound_host", "bound.name": "bound_name", "request.host": "request_host",
              "request.name": "request_name", "status": "server_status"},
    "radius": {"username": "user"},
    "kerberos": {"client": "cname", "service": "sname"},
    "ntlm": {"hostname": "host", "domainname": "domain", "server_nb_computer_name": "server_nb_computer",
             "server_dns_computer_name": "server_dns_computer", "server_tree_name": "server_tree", "username": "user"},
    "ldap": {"arguments": "argument", "opcode": "operation", "opcodes": "operation", "result": "result_code",
             "results": "result_code", "diagnostic_message": "result_message", "diagnostic_messages": "result_message"},
    "ldap_search": {"base_objects": "base_object", "deref_aliases": "deref", "derefs": "deref",
                    "diagnostic_message": "result_message", "diagnostic_messages": "result_message",
                    "result": "result_code", "results": "result_code", "scopes": "scope"},
    "dhcp": {"uids": "uid", "client_addr": "orig_h", "server_addr": "resp_h", "mac": "orig_l2_addr",
             "requested_addr": "requested_ip", "assigned_addr": "assigned_ip"},
    "known_certs": {"host": "orig_h", "port_num": "orig_p"},
    "known_hosts": {"host": "orig_h"},
    "known_services": {"host": "resp_h", "port_num": "resp_p", "port_proto": "proto"},
    "software": {"host": "orig_h", "host_p": "orig_p",
                 **{f"version.{part}": f"version_{part}" for part in ("major", "minor", "minor2", "minor3", "addl")}},
}
# the text-log (TSV) column names that differ from Zeek's JSON names after the renames above (10xx dissect mappings)
MALCOLM_TEXT_RENAMES = {
    "smb_files": {f"times.{name}": f"times_{name}" for name in ("modified", "accessed", "created", "changed")},
    "smb_mapping": {"service": "resource_type"},
}
# 10xx_zeek_<log>.conf add_field: proto and service (a column already there becomes a list of both: Logstash add_field)
MALCOLM_ADDED = {"dns": {"service": "dns"}, "http": {"proto": "tcp", "service": "http"},
                 "ssl": {"proto": "tcp", "service": "tls"}, "x509": {"service": "X.509"},
                 "ftp": {"proto": "tcp", "service": "ftp"}, "smtp": {"proto": "tcp", "service": "smtp"},
                 "irc": {"proto": "tcp", "service": "irc"}, "mysql": {"service": "mysql"},
                 "tds": {"proto": "tcp", "service": "tds"}, "postgresql": {"proto": "tcp", "service": "postgresql"},
                 "redis": {"proto": "tcp", "service": "redis"}, "socks": {"service": "socks"},
                 "sip": {"service": "sip"}, "snmp": {"proto": "udp", "service": "snmp"},
                 "radius": {"service": "radius"}, "ssh": {"proto": "tcp", "service": "ssh"},
                 **{log: {"proto": "tcp", "service": "smb"} for log in ("smb_files", "smb_mapping", "smb_cmd")},
                 "dce_rpc": {"proto": "tcp", "service": "dce_rpc"}, "kerberos": {"service": "krb"},
                 "ntlm": {"service": "ntlm"}, "rdp": {"service": "rdp"}, "rfb": {"service": "rfb"},
                 "ldap": {"service": "ldap"}, "ldap_search": {"service": "ldap"},
                 "dhcp": {"proto": "udp", "service": "dhcp"}, "known_certs": {"proto": "tcp", "service": "tls"}}
# 1200_zeek_mutate.conf: the shared lifts out of zeek.<log>
MALCOLM_LIFTS = {"ts": "zeek.ts", "uid": "zeek.uid", "fuid": "zeek.fuid", "is_orig": "network.is_orig",
                 "orig_h": "source.ip", "orig_p": "source.port", "resp_h": "destination.ip",
                 "resp_p": "destination.port", "orig_l2_addr": "source.mac", "resp_l2_addr": "destination.mac",
                 "proto": "network.transport", "service": "network.protocol", "user": "related.user",
                 "password": "related.password", "community_id": "network.community_id"}
# 1400_zeek_convert.conf: epoch columns written as times
MALCOLM_TIMES = {"pe": ("compile_ts",), "x509": ("certificate_not_valid_before", "certificate_not_valid_after"),
                 "snmp": ("up_since",), "kerberos": ("from", "till"),
                 "smb_files": ("times_modified", "times_accessed", "times_created", "times_changed")}


def _split_dn(dn: str) -> dict:
    """Logstash kv on a one-line name (field_split ","), as Malcolm and Elastic split certificate names."""
    out: dict = {}
    for part in dn.split(","):
        key, sep, value = part.partition("=")
        if sep:
            out[key.strip()] = value
    return out


def malcolm(row: Row, nid: str = "mc-1", *, sensor: str | None = SENSOR, text: bool = False) -> dict:
    """Malcolm's Logstash output for one row. `text`: a row Malcolm read from a text (TSV) log, whose values stay
    Zeek's text (numbers, "T"/"F", comma-separated sets)."""
    log = row.log
    cols = {"orig_h" if k == "id.orig_h" else "orig_p" if k == "id.orig_p" else "resp_h" if k == "id.resp_h"
            else "resp_p" if k == "id.resp_p" else k: v for k, v in row.json().items()}
    cols = {MALCOLM_RENAMES.get(log, {}).get(k, k): v for k, v in cols.items()}
    if text:
        cols = {MALCOLM_TEXT_RENAMES.get(log, {}).get(k, k): v for k, v in cols.items()}
    referenced = {k: cols.pop(k) for k in [k for k in cols if k.startswith("referenced_file.")]}
    for name, value in MALCOLM_ADDED.get(log, {}).items():
        cols[name] = value if name not in cols else [*(cols[name] if isinstance(cols[name], list)
                                                        else [cols[name]]), value]
    if log == "dhcp" and "orig_p" not in cols and "resp_p" not in cols:
        cols.update(orig_p=68, resp_p=67)              # 1017_zeek_dhcp.conf: the DHCP ports, when absent
    if log == "known_services" and "service" in cols:
        cols["service"] = [_malcolm_service(s) for s in cols["service"]]
    if log == "rdp" and isinstance(cols.get("client_build"), str):
        cols["client_build"] = cols["client_build"].removeprefix("RDP ")
    if log == "ssl" and str(cols.get("ssl_version", "")).startswith("DTLS"):
        cols["proto"] = "udp"
    if text:
        cols = {k: v if k in ("ts",) else _text(v) for k, v in cols.items()}
    if referenced:
        cols["referenced_file"] = _malcolm_referenced_file(referenced, text)
        if not text:                                    # JSON: the keys other than id.* stay literal
            cols.update({k: v for k, v in referenced.items() if not k.startswith("referenced_file.id.")})
    top: dict = {}
    for name, target in MALCOLM_LIFTS.items():
        if name in cols:
            value = cols.pop(name)
            if name == "service":
                value = [value] if isinstance(value, str) else value
            _set(top, target, value)
    if text:
        # 1200_zeek_mutate.conf splits these lifted text columns on commas
        for path in ("related.user", "zeek.fuid", "network.protocol"):
            value = _get(top, path)
            if isinstance(value, str):
                _set(top, path, value.split(","))
    zeek_log = cols
    ms = round(row.ts * 1000)
    source = {"@timestamp": iso_ms(row.ts), "timestamp": ms, "firstPacket": ms, "lastPacket": ms, "length": 0,
              "event": {"provider": "zeek", "dataset": log, "kind": "event"}, "node": sensor, "host": {"name": sensor},
              **top}
    zeek = {**source.get("zeek", {}), "ts": iso_ms(row.ts), log: zeek_log}
    source["zeek"] = zeek
    if "zeek" in top and "uid" in top["zeek"]:
        source["rootId"] = top["zeek"]["uid"]
        source["event"]["id"] = [top["zeek"]["uid"]]
    transport = row.zeek.get("proto") or SHIPPER_TRANSPORT["malcolm"].get(log)
    written = _community(row, transport)
    if written is not None:
        _set(source, "network.community_id", written)
    _malcolm_mutate(log, source, zeek_log, row)
    _malcolm_windows(log, source, zeek_log, text)
    for name in MALCOLM_TIMES.get(log, ()):
        if name in zeek_log and zeek_log[name] is not None:
            zeek_log[name] = _epoch_iso(float(zeek_log[name]))
    return _hit("malcolm", source, nid)


def _malcolm_mutate(log: str, source: dict, z: dict, row: Row) -> None:
    """1200_zeek_mutate.conf and 1300_zeek_normalize.conf steps that move a column out of zeek.<log>."""
    if log == "dns" and "qclass_name" in z:
        z["qclass_name"] = str(z["qclass_name"]).removeprefix("C_")
    if log == "http":
        z.pop("tags", None)
        password = _get(source, "related.password")
        users = _get(source, "related.user")
        user = (users[0] if isinstance(users, list) else users) or ""
        host, uri = z.get("host", ""), z.get("uri", "")
        _set(source, "url.original", f"http://{host}{uri}")
        _set(source, "url.full", f"http://{user}{':' + password if password else ''}{'@' if user or password else ''}"
                                 f"{host}:{_get(source, 'destination.port')}{uri}")
        if password:
            _set(source, "url.password", password)
    if log == "ssl":
        for name in ("subject", "issuer", "client_subject", "client_issuer"):
            if name in z:
                z[f"{name}_full"] = z.pop(name)
                z[name] = _split_dn(z[f"{name}_full"])
        if "ja4" in z:
            _set(source, "tls.client.ja4", z.pop("ja4"))
        if "ja4s" in z:
            _set(source, "tls.server.ja4s", z.pop("ja4s"))
        if "cert_chain_fps" in z:
            _set(source, "zeek.x509.fingerprint", z["cert_chain_fps"])
    if log == "x509":
        for name in ("certificate_subject", "certificate_issuer"):
            if name in z:
                z[f"{name}_full"] = z.pop(name)
                z[name] = _split_dn(z[f"{name}_full"])
    if log == "weird":
        _set(source, "rule.name", [z.pop("name")] if "name" in z else None)
        z.pop("peer", None)
    if log == "signatures":
        if "event_message" in z:
            _set(source, "event.original", z.pop("event_message"))
        if "note" in z:
            _set(source, "rule.category", [z.pop("note")])
        _set(source, "event.module", "zeek")        # 1200_zeek_mutate.conf adds it to signatures and notice rows
    if log == "notice":
        _set(source, "event.original", ":".join(p for p in (z.get("msg"), z.get("sub")) if p))
        _set(source, "event.module", "zeek")
    if log == "files" and "source" in z:
        name = str(z.pop("source"))
        for suffix in ("_TCP", "_UDP", "_DATA"):
            name = name.removesuffix(suffix)
        _set(source, "file.source", "TLS" if name == "SSL" else name.removeprefix("SPICY_"))
    if log == "intel":
        if "seen_indicator" in z:
            _set(source, "threat.indicator.name", z.pop("seen_indicator"))
        z.pop("seen_indicator_type", None)
        z.pop("matched", None)
        if "sources" in z:
            _set(source, "threat.indicator.provider", z.pop("sources"))
    if log in ("mysql", "postgresql") and z.get("rows") in (0, "0"):
        z.pop("rows")
    if log == "tunnel":
        for name in ("tunnel_type", "action"):
            if name in z:
                z[name] = str(z[name]).removeprefix("Tunnel::")


def _dedouble(value):
    """logstash/ruby/dedoubleslash.rb: each doubled backslash made single (it undoes the escaping of Zeek's text logs,
    and on a JSON row turns a share path's leading two into one)."""
    if isinstance(value, list):
        return [_dedouble(v) for v in value]
    return value.replace("\\\\", "\\") if isinstance(value, str) else value


def _malcolm_service(name: str) -> str:
    """1034_zeek_known.conf: a known service's name lowercased, its transport, "data", "spicy_" and cipher parts
    removed."""
    name = re.sub(r"[_-](tcp|udp|data)", "", name.lower()).replace("spicy_", "")
    return re.sub(r"(_hmac)?(_(sha|md)\d+)?$", "", name)


_TSV_REFERENCED = {"id.orig_h": "orig_h", "id.orig_p": "orig_p", "id.resp_h": "resp_h", "id.resp_p": "resp_p",
                   **{f"times.{name}": f"times_{name}" for name in ("modified", "accessed", "created", "changed")}}


def _malcolm_referenced_file(referenced: dict, text: bool) -> dict:
    """An smb_cmd row's referenced file as Malcolm reads it: a text row's whole file as the nested columns its dissect
    names; a JSON row's id.* only (1054_zeek_smb.conf renames those; the other keys stay literal)."""
    out = {}
    for key, value in referenced.items():
        name = key.removeprefix("referenced_file.")
        if text:
            out[_TSV_REFERENCED.get(name, name)] = _text(value)
        elif name.startswith("id."):
            out[_TSV_REFERENCED[name]] = value
    return out


def _merged(current, added) -> list:
    """Logstash mutate merge: the union of both, as a list."""
    items = current if isinstance(current, list) else [] if current is None else [current]
    return list(dict.fromkeys([*items, *(added if isinstance(added, list) else [added])]))


def _malcolm_windows(log: str, source: dict, z: dict, text: bool) -> None:
    """1017, 1035 and 1054 and the matching 1200_zeek_mutate.conf steps for the Windows-protocol logs."""
    if log in ("smb_files", "smb_cmd") and isinstance(z.get("action"), str):
        z["action"] = z["action"].removeprefix("SMB::")
    if log == "smb_cmd":
        if isinstance(z.get("version"), str):
            z["version"] = re.sub("^SMB", "", z["version"])
        if isinstance(z.get("command"), str):
            z["command"] = z["command"].removeprefix("SMB::")
        if "tree" in z and not text:
            z["tree"] = _dedouble(z["tree"])
        referenced = z.pop("referenced_file", None)
        if referenced is not None:
            referenced = {k: v for k, v in referenced.items() if v not in (None, "-", "(empty)", "")}
            for name in ("uid", "fuid"):
                if name in referenced:
                    _set(source, f"zeek.{name}", _merged(_get(source, f"zeek.{name}"), referenced.pop(name)))
            if isinstance(referenced.get("action"), str):
                referenced["action"] = referenced["action"].removeprefix("SMB::")
            source["zeek"]["smb_files"] = referenced
            source["event"]["dataset"] = ["smb_files", "smb_cmd"]
    if log == "smb_files" and not text:
        for name in ("path", "name", "prev_name"):
            if name in z:
                z[name] = _dedouble(z[name])
    if log == "smb_mapping" and not text and "path" in z:
        z["path"] = _dedouble(z["path"])
    if log == "dhcp":
        if text:
            for path in ("zeek.uid", "zeek.dhcp.msg_types"):
                value = _get(source, path)
                if isinstance(value, str):
                    _set(source, path, value.split(","))
        if _get(source, "source.mac") is not None:
            z["mac"] = _get(source, "source.mac")
        if isinstance(z.get("msg_types"), list):
            z["msg_types"] = list(dict.fromkeys(z["msg_types"]))        # make_unique_array.rb
        client, server = _get(source, "source.ip"), _get(source, "destination.ip")
        if client and server:                           # 1250_zeek_community_id.conf, from the ports it added
            _set(source, "network.community_id", community_id(client, 68, server, 67, "udp"))
    if log == "ldap":
        operation = z.get("operation")
        names = operation if isinstance(operation, list) else [operation]
        if any(isinstance(name, str) and "bind simple" in name for name in names):
            if z.get("object"):
                _set(source, "related.user", _merged(_get(source, "related.user"), z["object"]))
            if z.get("argument"):
                _set(source, "related.password", _merged(_get(source, "related.password"), z["argument"]))


# ---- Elastic -------------------------------------------------------------------------------------------------------

# default.yml renames per stream: Zeek column -> document path (None: removed). Columns not listed stay under
# zeek.<stream>; dotted columns are expanded there (the pipelines' dot_expander steps) except where noted.
_IDS = {"id.orig_h": "source.address", "id.orig_p": "source.port", "id.resp_h": "destination.address",
        "id.resp_p": "destination.port", "uid": "zeek.session_id"}
ELASTIC_RENAMES = {
    "dns": {**_IDS, "proto": "network.transport", "Z": None, "auth": None, "addl": None},
    "http": {**_IDS, "method": "http.request.method", "referrer": "http.request.referrer",
             "status_code": "http.response.status_code", "version": "http.version",
             "request_body_len": "http.request.body.bytes", "response_body_len": "http.response.body.bytes",
             "uri": "url.original", "host": "url.domain", "username": "url.username", "password": "url.password",
             "user_agent": "user_agent.original"},
    "ssl": {**_IDS, "server_name": "zeek.ssl.server.name", "cert_chain_fuids": "zeek.ssl.server.cert_chain_fuids",
            "client_cert_chain_fuids": "zeek.ssl.client.cert_chain_fuids",
            "validation_status": "zeek.ssl.validation.status", "subject": "tls.server.subject",
            "issuer": "tls.server.issuer", "client_issuer": "tls.client.issuer", "client_subject": None,
            "ja3": "tls.client.ja3", "ja3s": "tls.server.ja3s"},
    "x509": {"id": "zeek.session_id", "certificate.not_valid_before": "zeek.x509.certificate.valid.from",
             "certificate.not_valid_after": "zeek.x509.certificate.valid.until",
             "basic_constraints.ca": "zeek.x509.basic_constraints.certificate_authority",
             "basic_constraints.path_len": "zeek.x509.basic_constraints.path_length",
             "certificate.cn": "zeek.x509.certificate.common_name", "certificate.issuer": None,
             "certificate.subject": None, "certificate.key_alg": "zeek.x509.certificate.key.algorithm",
             "certificate.key_length": "zeek.x509.certificate.key.length",
             "certificate.key_type": "zeek.x509.certificate.key.type",
             "certificate.sig_alg": "zeek.x509.certificate.signature_algorithm"},
    "files": {"conn_uids": "zeek.files.session_ids", "filename": "file.name", "total_bytes": "file.size",
              "tx_hosts": None, "rx_hosts": None},
    "pe": {"compile_ts": "zeek.pe.compile_time"},
    "ssh": {**_IDS, "auth_attempts": "zeek.ssh.auth.attempts", "auth_success": "zeek.ssh.auth.success",
            "cipher_alg": "zeek.ssh.algorithm.cipher", "mac_alg": "zeek.ssh.algorithm.mac",
            "compression_alg": "zeek.ssh.algorithm.compression", "kex_alg": "zeek.ssh.algorithm.key_exchange",
            "host_key_alg": "zeek.ssh.algorithm.host_key"},
    "notice": {**_IDS, "proto": "network.transport", "actions": "zeek.notice.actions", "action": None,
               "remote_location": None},
    "weird": {**_IDS, "addl": "zeek.weird.additional_info"},
    "signature": {"src_addr": "source.address", "src_port": "source.port", "dst_addr": "destination.address",
                  "dst_port": "destination.port", "uid": "zeek.session_id", "sig_id": "rule.id",
                  "event_msg": "rule.description"},
    "intel": dict(_IDS),
    "ftp": {**_IDS, "file_size": "file.size", "mime_type": "file.mime_type", "fuid": "zeek.ftp.file.uid",
            "reply_code": "zeek.ftp.reply.code", "reply_msg": "zeek.ftp.reply.msg",
            "data_channel.orig_h": "zeek.ftp.data_channel.originating_host",
            "data_channel.resp_h": "zeek.ftp.data_channel.response_host",
            "data_channel.resp_p": "zeek.ftp.data_channel.response_port"},
    "smtp": {**_IDS, "trans_depth": "zeek.smtp.transaction_depth", "mailfrom": "zeek.smtp.mail_from",
             "rcptto": "zeek.smtp.rcpt_to"},
    "irc": {**_IDS, "dcc_file_name": "file.name", "dcc_mime_type": "file.mime_type", "user": "user.name"},
    "mysql": dict(_IDS), "radius": dict(_IDS),
    "socks": {**_IDS, "request_p": "zeek.socks.request.port", "bound_p": "zeek.socks.bound.port"},
    "tunnel": {**_IDS, "tunnel_type": "zeek.tunnel.type"},
    "sip": {**_IDS, "trans_depth": "zeek.sip.transaction_depth", "method": "zeek.sip.sequence.method",
            "request_from": "zeek.sip.request.from", "request_to": "zeek.sip.request.to",
            "request_path": "zeek.sip.request.path", "request_body_len": "zeek.sip.request.body_length",
            "response_from": "zeek.sip.response.from", "response_to": "zeek.sip.response.to",
            "response_path": "zeek.sip.response.path", "response_body_len": "zeek.sip.response.body_length",
            "status_code": "zeek.sip.status.code", "status_msg": "zeek.sip.status.msg", "seq": None},
    "snmp": {**_IDS, "get_requests": "zeek.snmp.get.requests", "get_bulk_requests": "zeek.snmp.get.bulk_requests",
             "get_responses": "zeek.snmp.get.responses", "set_requests": "zeek.snmp.set.requests"},
    "smb_files": dict(_IDS), "smb_mapping": dict(_IDS), "dce_rpc": dict(_IDS),
    # the referenced file's action, name, path, uid and hosts are kept under zeek.smb_cmd.file; the rest is removed
    "smb_cmd": {**_IDS, "referenced_file.uid": "zeek.smb_cmd.file.uid",
                "referenced_file.id.orig_h": "zeek.smb_cmd.file.host.tx",
                "referenced_file.id.resp_h": "zeek.smb_cmd.file.host.rx",
                "referenced_file.name": "zeek.smb_cmd.file.name", "referenced_file.path": "zeek.smb_cmd.file.path",
                "referenced_file.action": "zeek.smb_cmd.file.action",
                **{f"referenced_file.{name}": None for name in (
                    "ts", "id.orig_p", "id.resp_p", "size", "times.modified", "times.accessed", "times.created",
                    "times.changed", "fuid", "prev_name")}},
    "kerberos": {**_IDS, "till": "zeek.kerberos.valid.until", "from": "zeek.kerberos.valid.from",
                 "error_code": "zeek.kerberos.error.code", "error_msg": "zeek.kerberos.error.msg"},
    "ntlm": {**_IDS, "domainname": "zeek.ntlm.domain", "server_dns_computer_name": "zeek.ntlm.server.name.dns",
             "server_nb_computer_name": "zeek.ntlm.server.name.netbios",
             "server_tree_name": "zeek.ntlm.server.name.tree"},
    "rdp": {**_IDS, **{name: f"zeek.rdp.{target}" for name, target in (
        ("client_build", "client.build"), ("client_name", "client.name"), ("client_dig_product_id", "client.product_id"),
        ("desktop_width", "desktop.width"), ("desktop_height", "desktop.height"),
        ("requested_color_depth", "desktop.color_depth"), ("cert_type", "cert.type"), ("cert_count", "cert.count"),
        ("cert_permanent", "cert.permanent"), ("encryption_level", "encryption.level"),
        ("encryption_method", "encryption.method"))}},
    "rfb": {**_IDS, "client_major_version": "zeek.rfb.version.client.major",
            "client_minor_version": "zeek.rfb.version.client.minor",
            "server_major_version": "zeek.rfb.version.server.major",
            "server_minor_version": "zeek.rfb.version.server.minor", "auth": "zeek.rfb.auth.success",
            "authentication_method": "zeek.rfb.auth.method"},
    "dhcp": {"uids": "zeek.session_id", **{name: f"zeek.dhcp.{target}" for name, target in (
        ("assigned_addr", "address.assigned"), ("client_addr", "address.client"), ("mac", "address.mac"),
        ("requested_addr", "address.requested"), ("server_addr", "address.server"), ("host_name", "hostname"),
        ("client_message", "msg.client"), ("server_message", "msg.server"), ("msg_types", "msg.types"),
        ("msg_orig", "msg.origin"), ("client_software", "software.client"), ("server_software", "software.server"),
        ("circuit_id", "id.circuit"), ("agent_remote_id", "id.remote_agent"), ("subscriber_id", "id.subscriber"))}},
    "software": {"host": "host.ip", "software_type": "zeek.software.type",
                 "unparsed_version": "zeek.software.version.full", "version.addl": "zeek.software.version.additional"},
    "known_hosts": {"host": "host.ip"},
    "known_services": {"host": "host.ip", "port_num": "server.port", "port_proto": "network.transport",
                       "service": "network.application"},
    "known_certs": {"host": "host.ip", "port_num": "server.port",
                    "subject": "tls.server.x509.subject.distinguished_name",
                    "issuer_subject": "tls.server.x509.issuer.distinguished_name",
                    "serial": "tls.server.x509.serial_number"},
}
# columns the pipelines convert to dates (ISO)
ELASTIC_TIMES = {"zeek.x509.certificate.valid.from", "zeek.x509.certificate.valid.until", "zeek.pe.compile_time",
                 "zeek.snmp.up_since", "zeek.kerberos.valid.until", "zeek.kerberos.valid.from"}
# the known_* pipelines index only the columns they rename (they remove the parsed line)
ELASTIC_RENAMED_ONLY = {"known_hosts", "known_services", "known_certs"}


def elastic(row: Row, nid: str = "el-1", *, sensor: str | None = SENSOR, original: bool = True,
            filebeat: bool = False) -> dict:
    """The Elastic Agent integration's document for one row (`filebeat`: the Filebeat module's, which writes
    `event.module` and `fileset.name` and no data stream: elastic/beats x-pack/filebeat/module/zeek/<fileset>/test/
    *-expected.json at commit bd26a932c991bdd42314ab5f7fdf7ad7539e2584). `original`: the Zeek line kept in
    event.original (the preserve_original_event tag)."""
    stream = ELASTIC_STREAMS.get(row.log, row.log)
    renames = ELASTIC_RENAMES.get(stream, {})
    doc: dict = {}
    zeek_log: dict = {}
    for key, value in row.zeek.items():
        if key in renames:
            if renames[key] is not None:
                _set(doc, renames[key], copy.deepcopy(value))
        elif stream == "files" and key.startswith("id."):
            zeek_log[key] = value                       # no dot_expander for files: the key stays literal
        elif stream in ELASTIC_RENAMED_ONLY:
            continue
        else:
            _set(zeek_log, key, copy.deepcopy(value))
    doc = _merge(doc, {"zeek": {stream: zeek_log}})
    _elastic_steps(stream, row, doc)
    for path in ELASTIC_TIMES:
        value = _get(doc, path)
        if isinstance(value, (int, float)):
            _set(doc, path, _epoch_iso(value))
    if _get(doc, "source.address") is not None:
        _set(doc, "source.ip", _get(doc, "source.address"))
    if _get(doc, "destination.address") is not None:
        _set(doc, "destination.ip", _get(doc, "destination.address"))
    if _get(doc, "zeek.session_id") is not None:
        _set(doc, "event.id", _get(doc, "zeek.session_id"))
    transport = row.zeek.get("proto") or SHIPPER_TRANSPORT["elastic"].get(row.log)
    if transport is not None and _get(doc, "network.transport") is None:
        _set(doc, "network.transport", transport)
    written = _community(row, transport)
    if written is not None:
        _set(doc, "network.community_id", written)
    event = {**doc.get("event", {}), "dataset": f"zeek.{stream}", "kind": "event",
             "original": json.dumps(row.json()) if original else None, "module": "zeek" if filebeat else None}
    shipper = {"name": f"{sensor}-shipper" if sensor else None}
    source = {"@timestamp": iso_ms(row.ts), "agent": {"name": sensor, "type": "filebeat"},
              "host": shipper,
              "data_stream": None if filebeat else {"dataset": f"zeek.{stream}", "type": "logs"}, **doc,
              "fileset": {"name": stream} if filebeat else None, "service": {"type": "zeek"} if filebeat else None,
              "event": event,
              "tags": ["preserve_original_event", f"zeek-{stream}"] if original else [f"zeek-{stream}"]}
    if "host" in doc:                                   # an asset's address (host.ip) beside the shipper's name
        source["host"] = {**shipper, **doc["host"]}
    return _hit("elastic", source, nid, stream)


# Elastic's renames of a name's attributes after its kv split (zeek.<stream>.*), and the ECS x509 fields it sets from
# them (one-element lists)
_ELASTIC_NAME_KEYS = {"C": ("country", "country"), "CN": ("common_name", "common_name"),
                      "L": ("locality", "locality"), "O": ("organization", "organization"),
                      "OU": ("organizational_unit", "organizational_unit"), "ST": ("state", "state_or_province")}


def _elastic_name_parts(dn: str) -> tuple[dict, dict]:
    """A one-line name as Elastic's x509 and ssl pipelines leave it: escaped commas removed (gsub), split on commas
    (kv), each attribute renamed under zeek.<stream>, and set as a one-element list under the ECS x509 field."""
    zeek_parts, ecs_parts = {}, {}
    for key, value in _split_dn(dn.replace("\\,", "")).items():
        if key in _ELASTIC_NAME_KEYS:
            zeek_name, ecs_name = _ELASTIC_NAME_KEYS[key]
            zeek_parts[zeek_name] = value
            ecs_parts[ecs_name] = [value]
    return zeek_parts, ecs_parts


def _elastic_steps(stream: str, row: Row, doc: dict) -> None:
    """default.yml steps beyond the plain renames."""
    z = doc["zeek"][stream]
    zeek = row.zeek
    if stream == "dns":
        if "trans_id" in z:
            z["trans_id"] = str(z["trans_id"])                  # convert: type string
            _set(doc, "dns.id", z["trans_id"])
        for name, target in (("qtype_name", "dns.question.type"), ("rcode_name", "dns.response_code")):
            if name in z:
                _set(doc, target, z[name])
        _set(doc, "dns.type", "answer" if "rcode_name" in z else "query")
        _set(doc, "dns.header_flags", [flag for flag in ("AA", "TC", "RD", "RA") if z.get(flag)] or None)
    if stream == "http":
        _set(doc, "network.transport", "tcp")
        if _get(doc, "url.username"):
            _set(doc, "user.name", _get(doc, "url.username"))
    if stream == "ssl":
        for name in ("subject", "issuer"):
            if name in zeek:
                _set(doc, f"tls.server.{name}", zeek[name].replace("\\,", ""))
                zeek_parts, ecs_parts = _elastic_name_parts(zeek[name])
                z.setdefault("server", {})[name] = zeek_parts
                _set(doc, f"tls.server.x509.{name}", ecs_parts)
        if "client_subject" in zeek:
            z.setdefault("client", {})["subject"] = _elastic_name_parts(zeek["client_subject"])[0]
        for name in ("cipher", "curve"):
            if name in z:
                _set(doc, f"tls.{name}", z[name])
        for name in ("established", "resumed"):
            if name in z:
                _set(doc, f"tls.{name}", z[name])
    if stream == "x509":
        for name in ("subject", "issuer"):
            native = zeek.get(f"certificate.{name}")
            if native is not None:
                zeek_parts, ecs_parts = _elastic_name_parts(native)
                z.setdefault("certificate", {})[name] = zeek_parts
                _set(doc, f"file.x509.{name}", ecs_parts)
        if "san.dns" in zeek:
            _set(doc, "file.x509.alternative_names", list(zeek["san.dns"]))
    if stream == "files":
        if "conn_uids" in zeek:
            _set(doc, "zeek.session_id", zeek["conn_uids"][0])
        for name, single, side in (("tx_hosts", "tx_host", "server.ip"), ("rx_hosts", "rx_host", "client.ip")):
            if zeek.get(name):
                z[single] = zeek[name][0]
                _set(doc, side, zeek[name][0])
        for name in ("md5", "sha1", "sha256"):
            if name in z:
                _set(doc, f"file.hash.{name}", z[name])
        if "mime_type" in z:
            _set(doc, "file.mime_type", z["mime_type"])
    if stream == "notice":
        for name, side in (("src", "source.address"), ("dst", "destination.address"), ("p", "destination.port")):
            if name in z:
                value = z.pop(name)
                if _get(doc, side) is None:
                    _set(doc, side, value)
                elif _get(doc, side) != value:
                    z[name] = value
        if "note" in z:
            _set(doc, "rule.name", z["note"])
        if "msg" in z:
            _set(doc, "rule.description", z["msg"])
    if stream == "ftp" and "user" in z:
        _set(doc, "user.name", z["user"])
    if stream in ("radius", "socks") and ("username" in z or "user" in z):
        _set(doc, "user.name", z.get("username") or z.get("user"))
    if stream == "tunnel" and "action" in z:
        _set(doc, "event.action", z["action"])
    if stream == "smtp" and "tls" in z:
        _set(doc, "tls.established", z["tls"])
    if stream == "sip" and "uri" in z:
        _set(doc, "url.full", z["uri"])
    if stream == "intel" and _get(z, "seen.indicator_type") == "Intel::DOMAIN":
        _set(doc, "threat.indicator.type", "domain-name")
    _elastic_windows(stream, row, doc, z)


def _elastic_windows(stream: str, row: Row, doc: dict, z: dict) -> None:
    """default.yml steps of the Windows-protocol streams beyond the plain renames."""
    zeek = row.zeek
    if stream == "smb_files":
        for name, target in (("action", "event.action"), ("name", "file.name"), ("size", "file.size")):
            if name in z:
                _set(doc, target, z[name])
        if _get(z, "times.accessed") is not None:      # the pipeline converts all four only when accessed is set
            for name in ("modified", "accessed", "created", "changed"):
                if _get(z, f"times.{name}") is not None:
                    _set(z, f"times.{name}", _epoch_iso(_get(z, f"times.{name}")))
    if stream == "smb_cmd":
        if "referenced_file.action" not in zeek:
            file = z.get("file", {})
            file.pop("uid", None)
            file.pop("host", None)
        if "command" in z:
            _set(doc, "event.action", z["command"])
        if "username" in z:
            _set(doc, "user.name", z["username"])
    if stream == "dce_rpc" and "operation" in z:
        _set(doc, "event.action", z["operation"])
    if stream == "kerberos" and "/" in str(zeek.get("client", "")):
        name, _sep, domain = zeek["client"].partition("/")        # dissect %{user.name}/%{user.domain}
        _set(doc, "user.name", name)
        _set(doc, "user.domain", domain)
    if stream == "ntlm":
        if "username" in z:
            _set(doc, "user.name", z["username"])
        if "domain" in z:
            _set(doc, "user.domain", z["domain"])
    if stream == "rdp" and "ssl" in z:
        _set(doc, "tls.established", z["ssl"])
    if stream == "dhcp":
        client, server = zeek.get("client_addr"), zeek.get("server_addr")
        _set(doc, "network.transport", "udp")
        _set(doc, "source.port", 68)
        _set(doc, "destination.port", 67)
        if client:
            _set(doc, "source.address", client)
        if server:
            _set(doc, "destination.address", server)
        if client and server:
            _set(doc, "network.community_id", community_id(client, 68, server, 67, "udp"))
    if stream in ("software", "known_hosts", "known_services", "known_certs") and "host" in zeek:
        _set(doc, "host.ip", [zeek["host"]])
        if stream in ("known_services", "known_certs"):
            _set(doc, "server.ip", [zeek["host"]])
    if stream == "known_certs":
        for name, target in (("subject", "tls.server.subject"), ("issuer_subject", "tls.server.issuer")):
            if name in zeek:
                _set(doc, target, zeek[name])


# ---- Security Onion ------------------------------------------------------------------------------------------------

# zeek.<log> pipeline renames: Zeek column -> document path. Columns not listed are not indexed (common removes
# message2). zeek.common adds the connection's renames.
_SO_COMMON = {"uid": "log.id.uid", "id.orig_h": "source.ip", "id.orig_p": "source.port",
              "id.resp_h": "destination.ip", "id.resp_p": "destination.port",
              "community_id": "network.community_id"}
SO_RENAMES = {
    "dns": {"proto": "network.transport", "trans_id": "dns.id", "rtt": "event.duration", "query": "dns.query.name",
            "qclass": "dns.query.class", "qclass_name": "dns.query.class_name", "qtype": "dns.query.type",
            "qtype_name": "dns.query.type_name", "rcode": "dns.response.code",
            "rcode_name": "dns.response.code_name", "AA": "dns.authoritative", "TC": "dns.truncated",
            "RD": "dns.recursion.desired", "RA": "dns.recursion.available", "Z": "dns.reserved",
            "answers": "dns.answers.name", "TTLs": "dns.ttls", "rejected": "dns.query.rejected"},
    "http": {"trans_depth": "http.trans_depth", "method": "http.method", "host": "http.virtual_host",
             "uri": "http.uri", "referrer": "http.referrer", "version": "http.version",
             "user_agent": "http.useragent", "request_body_len": "http.request.body.length",
             "response_body_len": "http.response.body.length", "status_code": "http.status_code",
             "status_msg": "http.status_message", "info_code": "http.info_code", "info_msg": "http.info_message",
             "username": "http.user", "password": "http.password", "proxied": "http.proxied",
             "orig_fuids": "log.id.orig_fuids", "orig_filenames": "file.orig_filenames",
             "orig_mime_types": "file.orig_mime_types", "resp_fuids": "log.id.resp_fuids",
             "resp_filenames": "file.resp_filenames", "resp_mime_types": "file.resp_mime_types",
             "ja4h": "hash.ja4h"},
    "ssl": {"version": "ssl.version", "cipher": "ssl.cipher", "curve": "ssl.curve", "server_name": "ssl.server_name",
            "resumed": "ssl.resumed", "last_alert": "ssl.last_alert", "next_protocol": "ssl.next_protocol",
            "established": "ssl.established", "cert_chain_fps": "tls.server.hash.sha256",
            "cert_chain_fuids": "ssl.certificate.chain_fuids", "client_cert_chain_fps": "tls.client.hash.sha256",
            "client_cert_chain_fuids": "ssl.client.certificate.chain_fuids", "subject": "ssl.certificate.subject",
            "issuer": "ssl.certificate.issuer", "client_subject": "ssl.client.subject",
            "client_issuer": "ssl.client.issuer", "validation_status": "ssl.validation_status", "ja3": "hash.ja3",
            "ja3s": "hash.ja3s", "ja4": "hash.ja4", "ja4s": "hash.ja4s"},
    "x509": {"id": "log.id.fuid", **{f"certificate.{k}": f"x509.certificate.{v}" for k, v in (
        ("version", "version"), ("serial", "serial"), ("subject", "subject"), ("issuer", "issuer"),
        ("not_valid_before", "not_valid_before"), ("not_valid_after", "not_valid_after"),
        ("key_alg", "key.algorithm"), ("sig_alg", "signing_algorithm"), ("key_type", "key.type"),
        ("key_length", "key.length"), ("exponent", "exponent"), ("curve", "curve"))},
             **{f"san.{k}": f"x509.san_{k}" for k in ("dns", "uri", "email", "ip")},
             "basic_constraints.ca": "x509.basic_constraints.ca", "fingerprint": "hash.sha256", "ja4x": "hash.ja4x"},
    "files": {"fuid": "log.id.fuid", "conn_uids": "log.id.uid", "source": "file.source", "depth": "file.depth",
              "analyzers": "file.analyzer", "mime_type": "file.mime_type", "filename": "file.name",
              "duration": "event.duration", "local_orig": "file.local_orig", "is_orig": "file.is_orig",
              "seen_bytes": "file.bytes.seen", "total_bytes": "file.bytes.total",
              "missing_bytes": "file.bytes.missing", "overflow_bytes": "file.bytes.overflow",
              "timedout": "file.timed_out", "parent_fuid": "log.id.parent_fuid", "md5": "hash.md5",
              "sha1": "hash.sha1", "extracted": "file.extracted.filename", "extracted_cutoff": "file.extracted.cutoff",
              "extracted_size": "file.extracted.size"},
    "pe": {"id": "log.id.fuid", "machine": "file.machine", "compile_ts": "file.compile_timestamp", "os": "file.os",
           "subsystem": "file.subsystem", "is_exe": "file.is_exe", "is_64bit": "file.is_64bit",
           "uses_aslr": "file.aslr", "uses_dep": "file.dep", "uses_code_integrity": "file.code_integrity",
           "uses_seh": "file.seh", "has_import_table": "file.table.import", "has_export_table": "file.table.export",
           "has_cert_table": "file.table.cert", "has_debug_data": "file.debug_data",
           "section_names": "file.section_names"},
    "ssh": {"version": "ssh.version", "hassh": "hash.hassh", "auth_success": "ssh.authentication.success",
            "auth_attempts": "ssh.authentication.attempts", "direction": "ssh.direction", "client": "ssh.client",
            "server": "ssh.server", "cipher_alg": "ssh.cipher_algorithm", "compression_alg": "ssh.compression_algorithm",
            "host_key_alg": "ssh.host_key_algorithm", "hasshServer": "ssh.hassh_server", "kex_alg": "ssh.kex_algorithm",
            "mac_alg": "ssh.mac_algorithm", "host_key": "ssh.host_key"},
    "notice": {"fuid": "log.id.fuid", "proto": "network.transport", "note": "notice.note", "msg": "notice.message",
               "sub": "notice.sub_message", "p": "notice.p", "n": "notice.n", "peer_descr": "notice.peer_description",
               "actions": "notice.action", "suppress_for": "notice.suppress_for"},
    "weird": {"name": "weird.name", "addl": "weird.additional_info", "notice": "weird.notice", "peer": "weird.peer",
              "p": "weird.p", "dst": "destination.ip", "src": "source.ip"},
    "signatures": {"note": "note", "sig_id": "signature_id", "event_msg": "event_message",
                   "sub_msg": "sub_message", "sig_count": "signature_count", "host_count": "host.count"},
    "intel": {"seen.indicator": "intel.indicator", "seen.indicator_type": "intel.indicator_type",
              "seen.where": "intel.seen_where", "seen.node": "intel.seen_node", "matched": "intel.matched",
              "sources": "intel.sources", "fuid": "log.id.fuid"},
    "ftp": {"user": "ftp.user", "password": "ftp.password", "command": "ftp.command", "arg": "ftp.argument",
            "mime_type": "file.mimetype", "file_size": "file.size", "reply_code": "server.reply_code",
            "reply_msg": "server.reply_message", "data_channel.passive": "ftp.data_channel_passive",
            "data_channel.orig_h": "ftp.data_channel_source.ip",
            "data_channel.resp_h": "ftp.data_channel_destination.ip",
            "data_channel.resp_p": "ftp.data_channel_destination.port", "fuid": "fuid"},
    "smtp": {"trans_depth": "smtp.transaction_depth", "helo": "smtp.helo", "mailfrom": "smtp.mail_from",
             "rcptto": "smtp.recipient_to", "date": "smtp.mail_date", "from": "smtp.from", "to": "smtp.to",
             "cc": "smtp.cc", "reply_to": "smtp.reply_to", "msg_id": "smtp.message_id",
             "in_reply_to": "smtp.in_reply_to", "subject": "smtp.subject", "x_originating_ip": "smtp.x_originating_ip",
             "first_received": "smtp.first_received", "second_received": "smtp.second_received",
             "last_reply": "smtp.last_reply", "path": "smtp.path", "user_agent": "smtp.useragent", "tls": "smtp.tls",
             "fuids": "log.id.fuids", "is_webmail": "smtp.is_webmail"},
    "irc": {"nick": "irc.nickname", "user": "irc.username", "command": "irc.command.type", "value": "irc.command.value",
            "addl": "irc.command.info", "dcc_file_name": "file.name", "dcc_file_size": "file.size",
            "dcc_mime_type": "file.mime_type", "fuid": "log.id.fuid"},
    "mysql": {"cmd": "mysql.command", "arg": "mysql.argument", "success": "mysql.success", "rows": "mysql.rows",
              "response": "mysql.response"},
    "tds": {"command": "tds.command"},
    "radius": {"username": "user.name", "mac": "host.mac", "framed_addr": "radius.framed_address",
               "remote_ip": "destination.ip", "connect_info": "radius.connect_info", "reply_msg": "radius.reply_message",
               "result": "radius.result", "logged": "radius.logged"},
    "socks": {"version": "socks.version", "user": "socks.user", "password": "socks.password", "status": "socks.status",
              "request_host": "socks.request.host", "request.name": "socks.request.name",
              "request_p": "socks.request.port", "bound.host": "socks.bound.host", "bound_name": "socks.bound.name",
              "bound_p": "socks.bound.port"},
    "tunnel": {"tunnel_type": "tunnel.type", "action": "event.action"},
    "sip": {"trans_depth": "sip.transaction.depth", "method": "sip.method", "uri": "sip.uri", "date": "sip.date",
            "request_from": "sip.request.from", "request_to": "sip.request.to", "response_from": "sip.response.from",
            "response_to": "sip.response.to", "reply_to": "sip.reply_to", "call_id": "sip.call_id", "seq": "sip.seq",
            "subject": "sip.subject", "request_path": "sip.request.path", "response_path": "sip.response.path",
            "user_agent": "client.user_agent", "status_code": "server.status_code",
            "status_msg": "server.status_message", "warning": "sip.warning",
            "request_body_len": "sip.request.body.length", "response_body_len": "sip.response.body.length",
            "content_type": "sip.content_type"},
    "snmp": {"duration": "event.duration", "version": "snmp.version", "community": "snmp.community",
             "get_requests": "snmp.get.requests", "get_bulk_requests": "snmp.get.bulk_requests",
             "get_responses": "snmp.get.responses", "set_requests": "snmp.set.requests",
             "display_string": "snmp.display_string", "up_since": "snmp.up_since"},
    "smb_files": {"fuid": "log.id.fuid", "action": "file.action", "path": "file.path", "name": "file.name",
                  "size": "file.size", "prev_name": "file.previous_name",
                  **{f"times.{name}": f"file.times_{name}" for name in ("modified", "accessed", "created", "changed")}},
    "smb_mapping": {"path": "smb.path", "service": "smb.service", "native_file_system": "smb.file_system",
                    "share_type": "smb.share_type"},
    "dce_rpc": {"rtt": "event.duration", "named_pipe": "dce_rpc.named_pipe", "endpoint": "dce_rpc.endpoint",
                "operation": "dce_rpc.operation"},
    "kerberos": {"request_type": "kerberos.request_type", "client": "kerberos.client", "service": "kerberos.service",
                 "success": "kerberos.success", "error_msg": "kerberos.error_message",
                 "from": "kerberos.ticket.valid.from", "till": "kerberos.ticket.valid.until",
                 "cipher": "kerberos.ticket.cipher", "forwardable": "kerberos.ticket.forwardable",
                 "renewable": "kerberos.ticket.renewable",
                 "client_cert_subject": "kerberos.client_certificate_subject",
                 "client_cert_fuid": "log.id.client_certificate_fuid",
                 "server_cert_subject": "kerberos.server_certificate_subject",
                 "server_cert_fuid": "log.id.server_certificate_fuid"},
    "ntlm": {"hostname": "host.name", "domainname": "host.domain", "success": "ntlm.success", "status": "ntlm.status",
             "username": "user.name", "server_dns_computer_name": "ntlm.server.dns.name",
             "server_nb_computer_name": "ntlm.server.nb.name", "server_tree_name": "ntlm.server.tree.name"},
    "rdp": {"cookie": "rdp.cookie", "result": "rdp.result", "security_protocol": "rdp.security_protocol",
            "keyboard_layout": "rdp.keyboard_layout", "client_build": "rdp.client_build", "client_name": "client.name",
            "client_dig_product_id": "client.id.product", "desktop_width": "rdp.desktop.width",
            "desktop_height": "rdp.desktop.height", "requested_color_depth": "rdp.requested_color_depth",
            "cert_type": "rdp.certificate_type", "cert_count": "rdp.certificate_count",
            "cert_permanent": "rdp.certificate_permanent", "encryption_level": "rdp.encryption_level",
            "encryption_method": "rdp.encryption_method"},
    "rfb": {"client_major_version": "rfb.client_major_version", "client_minor_version": "rfb.client_minor_version",
            "server_major_version": "rfb.server_major_version", "server_minor_version": "rfb.server_minor_version",
            "authentication_method": "rfb.authentication.method", "auth": "rfb.authentication.success",
            "share_flag": "rfb.share_flag", "desktop_name": "rfb.desktop.name", "width": "rfb.desktop.width",
            "height": "rfb.desktop.height"},
    "ldap": {"message_id": "ldap.message_id", "opcode": "ldap.opcode", "result": "ldap.result",
             "diagnostic_message": "ldap.diagnostic_message", "version": "ldap.version", "object": "ldap.object",
             "argument": "ldap.argument"},
    "ldap_search": {"message_id": "ldap.message_id", "result": "ldap.result",
                    "diagnostic_message": "ldap.diagnostic_message", "scope": "ldap_search.scope",
                    "deref_aliases": "ldap_search.deref_aliases", "base_object": "ldap.object",
                    "result_count": "ldap_search.result_count", "filter": "ldap_search.filter",
                    "attributes": "ldap_search.attributes"},
    "dhcp": {"uids": "log.id.uids", "mac": "host.mac", "assigned_addr": "dhcp.assigned_ip",
             "lease_time": "dhcp.lease_time", "client_addr": "client.address", "server_addr": "server.address",
             "requested_addr": "dhcp.requested_address", "domain": "host.domain", "host_name": "host.hostname",
             "duration": "event.duration", "msg_types": "dhcp.message_types"},
    "software": {**{f"version.{part}": f"software.version.{part}" for part in ("major", "minor", "minor2", "minor3")},
                 "version.addl": "software.version.additional_info", "host": "source.ip", "host_p": "source.port",
                 "software_type": "software.type", "name": "software.name",
                 "unparsed_version": "software.version.unparsed"},
}
# the pipeline's own network.transport sets (zeek.http, zeek.smtp); zeek.dns renames proto
SO_TRANSPORT = {"http": "tcp", "smtp": "tcp"}


def security_onion(row: Row, nid: str = "so-1", *, sensor: str | None = SENSOR, bare: bool = False) -> dict:
    """Security Onion 2.4's document for one row. `bare`: a record that did not pass the common pipeline (its
    dataset is the bare log name). Its `message` keeps the Zeek line: a normalizer never parses it."""
    log = row.log
    renames = {**_SO_COMMON, **SO_RENAMES.get(log, {})}
    doc: dict = {}
    for key, value in row.zeek.items():
        if key == "rx_hosts" and value:
            _set(doc, "destination.ip", value[0])           # rename message2.rx_hosts.0
        elif key == "tx_hosts" and value:
            _set(doc, "source.ip", value[0])
        elif key in renames:
            _set(doc, renames[key], copy.deepcopy(value))
    transport = row.zeek.get("proto") or SO_TRANSPORT.get(log)
    if transport is not None:
        _set(doc, "network.transport", transport)
    written = _community(row, transport)
    if written is not None and _get(doc, "network.community_id") is None:
        _set(doc, "network.community_id", written)
    for side, client in (("source", "client"), ("destination", "server")):
        for part in ("ip", "port"):
            if _get(doc, f"{side}.{part}") is not None:
                _set(doc, f"{client}.{part}", _get(doc, f"{side}.{part}"))
    name = SO_NAMES.get(log, log)
    event = {**doc.get("event", {}), "module": "zeek", "category": "network",
             "dataset": name if bare else f"zeek.{name}"}
    source = {"@timestamp": iso_ms(row.ts), "message": json.dumps(row.json()), **doc, "event": event,
              "data_stream": {"dataset": "zeek", "namespace": "so"}, "observer": {"name": sensor},
              "tags": [name]}
    return _hit("security_onion", source, nid)


WRITERS = {"malcolm": malcolm, "elastic": elastic, "security_onion": security_onion, "plain": plain}


def shapes_of(log: str) -> tuple[str, ...]:
    return tuple(shape for shape in SHAPES if shape not in NOT_WRITTEN.get(log, ()))


def in_every_shape(row: Row, prefix: str = "") -> dict[str, dict]:
    """The row in every shape that writes its log."""
    return {shape: WRITERS[shape](row, f"{prefix}{shape}-{row.log}") for shape in shapes_of(row.log)}


# ---- mission-scale volume ------------------------------------------------------------------------------------------

# the Windows-protocol rows a mission network writes most of: SMB commands and DCE-RPC calls, with SMB files, Kerberos,
# NTLM and LDAP searches beside them
WINDOWS_STREAM = (SMB_CMD, DCE_RPC, SMB_CMD, DCE_RPC, SMB_FILES, KERBEROS, NTLM, LDAP_SEARCH)
_RPC_CALLS = ("CreateServiceW", "StartServiceW", "OpenSCManagerW", "SamrLookupIdsInDomain", "NetrShareEnum")
_RPC_ENDPOINTS = ("svcctl", "svcctl", "svcctl", "samr", "srvsvc")


def stream_rows(n: int, shape: str = "malcolm", *, hosts: int = 250, kinds: tuple[Row, ...] | None = None
                ) -> Iterator[dict]:
    """`n` distinct analyzer rows written lazily, one at a time (memory does not grow with `n`): dns, http, ssl, files
    and notice in turn (or `kinds`), each with its own uid, file id, time, client port and names, from `hosts` client
    addresses (the address cache is bounded, so a fixed population keeps it from filling page by page)."""
    kinds = kinds or (DNS, HTTP, SSL, FILES, NOTICE)
    for i in range(n):
        base = kinds[i % len(kinds)]
        host = i % hosts
        changes = {"uid": f"C{i:017d}", "id.orig_p": 1024 + i % 60000,
                   "id.orig_h": f"10.{(host >> 16) & 255}.{(host >> 8) & 255}.{host & 255}"}
        if base.log == "dns":
            changes.update(query=f"h{i}.example.test", trans_id=i % 65536)
        elif base.log == "http":
            changes.update(uri=f"/item/{i}")
        elif base.log in ("files", "smb_files"):
            changes.update(fuid=f"F{i:016d}")
        elif base.log == "smb_cmd":
            changes.update({"rtt": 0.0001 + (i % 997) * 1e-6, "referenced_file.fuid": f"F{i:016d}"})
        elif base.log == "dce_rpc":
            changes.update(endpoint=_RPC_ENDPOINTS[i % 5], operation=_RPC_CALLS[i % 5])
        elif base.log == "ldap_search":
            changes.update(message_id=i % 2**31, base_object=f"OU=unit{i},DC=example,DC=test")
        row = replace(base.with_(**changes), ts=T0 + i * 0.001)
        yield WRITERS[shape](row, f"{shape}-{base.log}-{i}")


# ---- malformed rows ------------------------------------------------------------------------------------------------

def malformed_rows() -> list[tuple[str, dict, str]]:
    """(name, hit, what normalization must make of it): "error", "skip", "absent" (placeholders typed as absent), or
    a native path that is dropped and listed in parse.malformed while the rest of the record is kept."""
    rows: list[tuple[str, dict, str]] = []

    def mutated(name, shape, row, mutate, outcome):
        h = WRITERS[shape](row, f"bad-{name}")
        mutate(h["_source"])
        rows.append((name, h, outcome))

    mutated("dns-trans-id-word", "plain", DNS, lambda s: s.update(trans_id="many"), "trans_id")
    mutated("dns-ttls-text", "plain", DNS, lambda s: s.update(TTLs=["soon"]), "TTLs")
    mutated("dns-answers-number", "elastic", DNS, lambda s: s["zeek"]["dns"].update(answers=[1, 2]),
            "zeek.dns.answers")
    mutated("dns-flag-text", "security_onion", DNS, lambda s: s["dns"].update(authoritative="yes"),
            "dns.authoritative")
    mutated("http-status-text", "plain", HTTP, lambda s: s.update(status_code="OK"), "status_code")
    mutated("http-ua-array", "malcolm", HTTP, lambda s: s["zeek"]["http"].update(user_agent=["a", "b"]),
            "zeek.http.user_agent")
    mutated("http-depth-negative", "elastic", HTTP, lambda s: s["zeek"]["http"].update(trans_depth=-1),
            "zeek.http.trans_depth")
    mutated("ssl-resumed-text", "security_onion", SSL, lambda s: s["ssl"].update(resumed="no"), "ssl.resumed")
    mutated("ssl-fps-numbers", "plain", SSL, lambda s: s.update(cert_chain_fps=[1, 2]), "cert_chain_fps")
    mutated("ssl-ja3-not-hex", "plain", SSL, lambda s: s.update(ja3="not a digest"), "ja3")
    mutated("x509-not-before-word", "plain", X509, lambda s: s.update({"certificate.not_valid_before": "soon"}),
            "certificate.not_valid_before")
    mutated("x509-key-length-text", "elastic", X509,
            lambda s: s["zeek"]["x509"]["certificate"]["key"].update(length="long"),
            "zeek.x509.certificate.key.length")
    mutated("x509-fingerprint-list", "malcolm", X509, lambda s: s["zeek"]["x509"].update(fingerprint=["a", "b"]),
            "zeek.x509.fingerprint")
    mutated("files-seen-text", "plain", FILES, lambda s: s.update(seen_bytes="all"), "seen_bytes")
    mutated("files-tx-hosts-garbage", "plain", FILES_50, lambda s: s.update(tx_hosts=["not-an-address"]),
            "tx_hosts")
    mutated("files-md5-not-hex", "malcolm", FILES, lambda s: s["zeek"]["files"].update(md5="zz"), "zeek.files.md5")
    mutated("pe-compile-ts-bool", "plain", PE, lambda s: s.update(compile_ts=True), "compile_ts")
    mutated("pe-sections-number", "security_onion", PE, lambda s: s["file"].update(section_names=7),
            "file.section_names")
    mutated("ssh-attempts-text", "elastic", SSH, lambda s: s["zeek"]["ssh"]["auth"].update(attempts="three"),
            "zeek.ssh.auth.attempts")
    mutated("ssh-hassh-number", "plain", SSH, lambda s: s.update(hassh=5), "hassh")
    mutated("notice-port-range", "plain", NOTICE.without("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"),
            lambda s: s.update(p=70000), "p")
    mutated("weird-name-list", "malcolm", WEIRD, lambda s: s["rule"].update(name=["a", "b"]), "rule.name")
    mutated("intel-matched-number", "plain", INTEL, lambda s: s.update(matched=[1]), "matched")
    mutated("ftp-reply-text", "security_onion", FTP, lambda s: s["server"].update(reply_code="ok"),
            "server.reply_code")
    mutated("smtp-path-garbage", "plain", SMTP, lambda s: s.update(path=["relay"]), "path")
    mutated("snmp-up-since-word", "plain", SNMP, lambda s: s.update(up_since="boot"), "up_since")
    mutated("radius-mac-garbage", "plain", RADIUS, lambda s: s.update(mac="not-a-mac"), "mac")
    mutated("socks-version-text", "plain", SOCKS, lambda s: s.update(version="five"), "version")
    # a value standing where an object belongs, a path written twice with different values
    mutated("dns-object-string", "malcolm", DNS, lambda s: s["zeek"].update(dns="not an object"), "zeek.dns")
    mutated("http-nested-and-literal-disagree", "malcolm", HTTP,
            lambda s: s["zeek"].update({"http.method": "POST"}), "zeek.http.method")
    # placeholders Zeek writes for unset and empty values are absent, never malformed
    mutated("placeholders", "malcolm", HTTP,
            lambda s: s["zeek"]["http"].update(user_agent="-", resp_mime_types="(empty)", status_msg=""), "absent")
    # unreadable: no time; a log outside the catalog is a counted skip
    mutated("no-time", "plain", DNS, lambda s: s.pop("ts"), "error")
    mutated("time-garbage", "elastic", HTTP, lambda s: s.update({"@timestamp": "yesterday"}), "error")
    mutated("uncatalogued-log", "malcolm", DNS, lambda s: s["event"].update(dataset="modbus"), "skip")
    # the Windows-protocol logs: wrong types, integers beyond Zeek's count, values no reader takes
    mutated("smb-size-huge", "plain", SMB_FILES, lambda s: s.update(size=10**30), "size")
    mutated("smb-size-text", "security_onion", SMB_FILES, lambda s: s["file"].update(size="big"), "file.size")
    mutated("smb-times-word", "plain", SMB_FILES, lambda s: s.update({"times.modified": "yesterday"}),
            "times.modified")
    mutated("smb-cmd-rtt-negative", "malcolm", SMB_CMD, lambda s: s["zeek"]["smb_cmd"].update(rtt=-1),
            "zeek.smb_cmd.rtt")
    mutated("dce-rpc-operation-number", "plain", DCE_RPC, lambda s: s.update(operation=12), "operation")
    mutated("kerberos-till-word", "plain", KERBEROS, lambda s: s.update(till="forever"), "till")
    mutated("kerberos-success-text", "elastic", KERBEROS, lambda s: s["zeek"]["kerberos"].update(success="yes"),
            "zeek.kerberos.success")
    mutated("ntlm-success-text", "security_onion", NTLM, lambda s: s["ntlm"].update(success="maybe"), "ntlm.success")
    mutated("rdp-width-beyond-count", "plain", RDP, lambda s: s.update(desktop_width=2**70), "desktop_width")
    mutated("rdp-channels-numbers", "elastic", RDP, lambda s: s["zeek"]["rdp"].update(client_channels=[1, 2]),
            "zeek.rdp.client_channels")
    mutated("rfb-width-negative", "plain", RFB, lambda s: s.update(width=-1), "width")
    mutated("ldap-message-id-text", "plain", LDAP, lambda s: s.update(message_id="first"), "message_id")
    mutated("ldap-opcodes-numbers", "plain", LDAP_61, lambda s: s.update(opcodes=[1]), "opcodes")
    mutated("ldap-attributes-object", "security_onion", LDAP_SEARCH,
            lambda s: s["ldap_search"].update(attributes={"a": 1}), "ldap_search.attributes")
    mutated("dhcp-assigned-garbage", "plain", DHCP, lambda s: s.update(assigned_addr="10.0.0.999"), "assigned_addr")
    mutated("dhcp-mac-garbage", "elastic", DHCP, lambda s: s["zeek"]["dhcp"]["address"].update(mac="zz"),
            "zeek.dhcp.address.mac")
    mutated("dhcp-lease-text", "malcolm", DHCP, lambda s: s["zeek"]["dhcp"].update(lease_time=[1]),
            "zeek.dhcp.lease_time")
    mutated("software-major-text", "plain", SOFTWARE, lambda s: s.update({"version.major": "eight"}), "version.major")
    mutated("known-services-port-range", "plain", KNOWN_SERVICES, lambda s: s.update(port_num=70000), "port_num")
    mutated("known-certs-serial-not-hex", "plain", KNOWN_CERTS, lambda s: s.update(serial="not hex"), "serial")
    mutated("known-hosts-two-addresses", "plain", KNOWN_HOSTS, lambda s: s.update(host=["10.0.0.5", "10.0.0.6"]),
            "host")
    return rows


# ---- secrets -------------------------------------------------------------------------------------------------------

SECRET = "Hunter2-synthetic-secret"


def secret_rows() -> list[tuple[str, dict]]:
    """For every log that can carry a credential, a row in every shape with SECRET wherever that shape writes it,
    plus Malcolm's derived copies (url.full, url.password, post_password_*); and rows whose free text carries one (a
    Redis reply, SQL, an IRC row holding an earlier JOIN's key), named <log>.<case>. Each must type only
    auth.cleartext_credentials_present."""
    rows: list[tuple[str, dict]] = []
    keyless = REDIS.without("cmd.key")
    logical = {
        "http": HTTP.with_(username="alice", password=SECRET),
        "ftp": FTP.with_(command="PASS", arg=SECRET, password=SECRET),
        "socks": SOCKS.with_(user="alice", password=SECRET),
        "snmp": SNMP.with_(community=SECRET),
        "irc": IRC.with_(command="JOIN", value="#ops", addl=f" with channel key: '{SECRET}'"),
        "redis": REDIS.with_(**{"cmd.name": "AUTH", "cmd.key": SECRET}),
        # an unquoted password is a syntax error, and the server's error quotes it back
        "mysql": MYSQL.with_(arg=f"CREATE USER 'app'@'%' IDENTIFIED BY {SECRET}", success=False, response=(
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version "
            f"for the right syntax to use near '{SECRET}' at line 1")),
        "postgresql": POSTGRESQL.with_(frontend_arg=f"ALTER ROLE app WITH ENCRYPTED PASSWORD '{SECRET}'",
                                       backend_arg="ALTER ROLE"),
        "redis.config": keyless.with_(**{"cmd.name": "CONFIG", "reply.value": f"[dir, /data, requirepass, {SECRET}]"}),
        "redis.acl": keyless.with_(**{"cmd.name": "ACL", "reply.value": f"[user default on >{SECRET} ~* +@all]"}),
        # a MONITOR stream's line, logged when the connection ends on a row with no command
        "redis.monitor": keyless.without("cmd.name").with_(
            **{"reply.value": f'1731938400.123456 [0 {CLIENT}:51131] "auth" "{SECRET}"'}),
        "mysql.insert": MYSQL.with_(arg=f"INSERT INTO accounts (name, password) VALUES ('svc', '{SECRET}')"),
        "postgresql.conninfo": POSTGRESQL.with_(
            frontend_arg=f"SELECT dblink_connect('host=192.0.2.5 user=app password={SECRET} dbname=inventory')"),
        "irc.nick": IRC.with_(command="NICK", value="synthbot2", addl=f" with channel key: '{SECRET}'"),
        "irc.dcc": IRC.with_(command="DCC", value="#ops", addl=f" with channel key: '{SECRET}'",
                             dcc_file_name="update.bin", dcc_file_size=1024),
        # an LDAP simple bind whose password Zeek captured (LDAP::default_capture_password), in 7.0's layout and 6.1's
        "ldap": LDAP.with_(opcode="bind simple", argument=SECRET, object="CN=alice,OU=Users,DC=example,DC=test"),
        "ldap.61": LDAP_61.with_(opcodes=["bind simple"], arguments=[SECRET],
                                 objects=["CN=alice,OU=Users,DC=example,DC=test"]),
        # a search that compares a password attribute with a value
        "ldap_search": LDAP_SEARCH.with_(filter=f"(&(objectclass=user)(userPassword={SECRET}))"),
        "software": SOFTWARE.with_(url=f"http://alice:{SECRET}@www.example.test/plugin"),
    }
    for log, row in logical.items():
        for shape, h in in_every_shape(row, "secret-").items():
            if shape == "malcolm" and log == "http":
                h["_source"].setdefault("zeek", {}).setdefault("http", {}).update(
                    post_password_plain=SECRET, post_password_md5=SECRET, post_password_sha1=SECRET,
                    post_password_sha256=SECRET)
            rows.append((f"{log}-{shape}", h))
    # every log in every shape, with a password column where that shape keeps one: Malcolm lifts any log's to
    # related.password (and url.password), Elastic leaves an unrenamed column under zeek.<stream> and keeps the Zeek
    # line in event.original, Security Onion keeps the Zeek line in message, plain JSON keeps it as Zeek wrote it
    for log, row in ROWS.items():
        with_password = row.with_(password=SECRET)
        for shape in shapes_of(log):
            nid = f"secret-{shape}-{log}-column"
            if shape == "malcolm":
                h = malcolm(row, nid)
                h["_source"]["related"] = {**h["_source"].get("related", {}), "password": [SECRET]}
                h["_source"]["url"] = {**h["_source"].get("url", {}), "password": SECRET}
            elif shape == "elastic":
                h = elastic(with_password, nid)
            elif shape == "security_onion":
                h = security_onion(with_password, nid)
            else:
                h = plain(with_password, nid)
            rows.append((f"{log}-{shape}-column", h))
    return rows
