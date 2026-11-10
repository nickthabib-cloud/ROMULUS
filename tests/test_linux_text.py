"""Synthetic text fixtures from RFC 3164/5424 and Apache/Nginx log documentation.

https://www.rfc-editor.org/rfc/rfc3164#section-4.1
https://www.rfc-editor.org/rfc/rfc5424#section-6
https://httpd.apache.org/docs/2.4/logs.html
https://nginx.org/en/docs/http/ngx_http_log_module.html
"""
import tracemalloc
from collections import Counter
from datetime import UTC, datetime

import pytest

from romulus.evidence.linux_text import classify
from romulus.evidence.normalize import normalize_hits
from romulus.sources.compile import compile_es
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import contract_from_types

ACCESS = '2001:db8::5 - alice [09/Nov/2026:12:00:00 +0000] "GET /health HTTP/1.1" 200 32 "-" "agent"'
SSH = 'Nov  9 12:00:00 origin sshd[42]: Accepted password for alice from 2001:db8::5 port 4400 ssh2'


def hit(line, dataset="custom.log", **extra):
    source = {"@timestamp": "2026-11-09T12:00:00Z", "host": {"name": "shipper"}, "message": line,
              "event": {"dataset": dataset}, **extra}
    return {"_index": "host-logs", "_id": "line-1", "_source": source}


@pytest.mark.parametrize("line,format,program", [
    (SSH, "syslog", "sshd"),
    ("<34>" + SSH, "syslog", "sshd"),
    (('<34>1 2026-11-09T12:00:00Z origin sshd 42 ID [x k="a\\]b"][y k="z"] '
      'Accepted password for alice from 192.0.2.4 port 4400 ssh2'), "syslog", "sshd"),
    ('2026-11-09T12:00:00+00:00 origin sshd[42]: Failed password for alice from 192.0.2.4 port 4400 ssh2',
     "syslog", "sshd"),
    (ACCESS, "http_access", "apache"),
    ("www.example.test:443 " + ACCESS, "http_access", "apache"),
    (ACCESS.split(' "-" "agent"')[0], "http_access", "apache"),
    ('[Mon Nov 09 12:00:00.000000 2026] [core:error] [pid 42] [client 192.0.2.4:4400] problem',
     "web_error", "apache"),
    ('2026/11/09 12:00:00 [error] 42#42: *1 upstream failed, client: 192.0.2.4', "web_error", "nginx"),
])
def test_content_identifies_documented_format(line, format, program):
    parsed = classify(line)
    assert (parsed.format, parsed.program) == (format, program)


@pytest.mark.parametrize("line", ["unknown message", "x" * 65_537,
    '<34>1 2026-11-09T12:00:00Z origin sshd 42 ID [x k="unfinished] body',
    'Nov  9 12:00:00 origin missing-program-colon', '"' * 65_536],
    ids=["unknown", "oversize", "bad-structured-data", "missing-colon", "quotes"])
def test_bad_or_overlong_lines_remain_honest_skips(line):
    fed = {}
    events, skips, errors = normalize_hits([hit(line)], skip_families=fed)
    assert not events and not errors and sum(skips.values()) == 1
    assert next(iter(skips)).startswith("text line too long" if len(line) > 65_536
                                        else "text line in no recognized format")
    assert list(fed.values()) == [None]


def test_raw_access_and_syslog_keep_pipeline_time_and_shipper_host():
    access, skips, errors = normalize_hits([hit(ACCESS)])
    assert not errors and not skips
    assert access[0].get("http.request.method") == "GET"
    assert access[0].get("source.ip") == "2001:db8::5"
    assert access[0].fields["source.ip"].origin.startswith("line-1:message")
    event = normalize_hits([hit(SSH)])[0][0]
    assert event.host == "shipper" and event.get("log.syslog.hostname") == "origin"
    assert event.ts == datetime(2026, 11, 9, 12, tzinfo=UTC)
    assert event.get("log.inline_timestamp") == "Nov  9 12:00:00"


def test_unknown_dataset_original_fallback_and_clock_difference():
    doc = hit("", input={"type": "filestream"})
    doc["_source"]["event"]["original"] = ACCESS.replace("12:00:00 +0000", "10:00:00 +0000")
    event = normalize_hits([doc])[0][0]
    assert event.ts.hour == 12
    assert any("clock" in text.lower() for text in event.caveats)
    assert event.fields["log.inline_timestamp"].origin.startswith("line-1:event.original")


def test_known_apache_shape_and_fields_stay_identical():
    doc = hit(ACCESS, "apache.access", source={"ip": "192.0.2.99"})
    event = normalize_hits([doc])[0][0]
    assert set(event.fields) == {"source.ip"}
    assert event.get("source.ip") == "192.0.2.99"
    assert event.caveats == []


def test_text_selection_excludes_known_names_on_both_dataset_fields():
    contract = contract_from_types("host-logs", {"@timestamp": "date", "event.dataset": "keyword",
        "data_stream.dataset": "keyword", "input.type": "keyword", "log.file.path": "keyword",
        "message": "text", "event.original": "text", "host.name": "keyword"})
    intent = SearchIntent(kind="raw", target="host-logs", window=Window(
        start=datetime(2026, 11, 9, tzinfo=UTC), end=datetime(2026, 11, 10, tzinfo=UTC)),
        filters=[Predicate(field="event.dataset", op="eq", value="linux.text")])
    query = compile_es(intent, contract).body
    text = str(query)
    assert "must_not" in text and "system.auth" in text and "auditd.log" in text
    assert "data_stream.dataset" in text and "event.dataset" in text
    assert "filestream" in text and "log.file.path" in text and "message" in text
    assert "'linux.text'" not in text


def test_datasetless_file_input_is_selected_by_its_mapped_fields():
    contract = contract_from_types("host-logs", {"@timestamp": "date", "input.type": "keyword", "message": "text"})
    intent = SearchIntent(kind="raw", target="host-logs", window=Window(
        start=datetime(2026, 11, 9, tzinfo=UTC), end=datetime(2026, 11, 10, tzinfo=UTC)),
        filters=[Predicate(field="event.dataset", op="eq", value="linux.text")])
    query = compile_es(intent, contract).body
    assert "filestream" in str(query) and "event.dataset" not in str(query)
    event = normalize_hits([hit(SSH, "", input={"type": "filestream"})])[0][0]
    assert event.family == "auth"


def test_inventory_names_arbitrary_text_datasets_without_guessing_network_sources():
    from romulus.evidence.linux_catalog import text_dataset_inventory
    from romulus.hunt.sweep import Sweep
    inventory = {"exim.log": 25, "myapp": 7, "system.auth": 20, "zeek.conn": 11, "suricata.eve": 6}
    assert text_dataset_inventory(inventory) == {"exim.log": 25, "myapp": 7}
    runner = object.__new__(Sweep)
    runner.stats = {}
    runner._profiles = {"host-logs": {"datasets": inventory}}
    runner._note_linux_shapes("host-logs", ["linux.text"], [], None)
    assert runner.stats["linux_shipper_inventory"]["host-logs"]["linux.text"] == {"exim.log": 25, "myapp": 7}


def test_classifier_two_hundred_thousand_lines_has_bounded_state():
    lines = (SSH, ACCESS, "not a known format", "<34>" + SSH)
    counts = Counter()
    tracemalloc.start()
    try:
        for i in range(200_000):
            parsed = classify(lines[i % 4])
            counts[parsed.format] += 1
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert counts == {"syslog": 100_000, "http_access": 50_000, "unknown": 50_000}
    assert peak < 4_000_000
