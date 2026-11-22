"""The network-to-host join's pass after the packet and baseline stages, over the rows the sweep kept.

Addresses are private or documentation ranges, hosts and accounts are invented."""
import json
import shutil
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.playbook import AdminPairBaseline
from romulus.detect.base import Match
from romulus.detect.bounded import StateBudget
from romulus.detect.net_host_join import NetworkAdminLogonJoin
from romulus.detect.packets import PACKET_PLAYBOOKS
from romulus.evidence.normalize import normalize_hits
from romulus.hunt import net_join_pass as jp
from romulus.hunt.publish import publish_match
from tests.test_net_host_join import audit_login, execve, finding, flow, sshd

BASE = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
T0 = BASE.timestamp() + 600
CLIENT_A, CLIENT_B, SERVER = "192.168.100.222", "192.168.100.223", "172.17.100.121"
RULE = "corr.network_admin_logon"


def _stamp(offset):
    return datetime.fromtimestamp(T0 + offset, UTC).isoformat().replace("+00:00", "Z")


def _eve(_id, eve, offset):
    return {"_id": _id, "_index": "romulus-network-logs", "_source": {
        "@timestamp": _stamp(offset), "host": {"name": "inetfw"},
        "event": {"dataset": f"suricata.eve.{eve['event_type']}", "original": json.dumps(eve)}}}


def _alert(client, port, offset):
    return _eve(f"al-{client}", {"timestamp": datetime.fromtimestamp(T0 + offset, UTC).isoformat(),
                                 "event_type": "alert", "src_ip": client, "src_port": port, "dest_ip": SERVER,
                                 "dest_port": 22, "proto": "TCP", "app_proto": "ssh",
                                 "alert": {"signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219,
                                           "category": "Attempted Information Leak", "severity": 1}}, offset)


def _flow(client, port, offset):
    start = datetime.fromtimestamp(T0 + offset, UTC).isoformat()
    end = datetime.fromtimestamp(T0 + offset + 60, UTC).isoformat()
    return _eve(f"fl-{client}", {"timestamp": end, "event_type": "flow", "src_ip": client, "src_port": port,
                                 "dest_ip": SERVER, "dest_port": 22, "proto": "TCP", "app_proto": "ssh",
                                 "flow": {"start": start, "end": end, "bytes_toserver": 4000,
                                          "bytes_toclient": 9000, "pkts_toserver": 20, "pkts_toclient": 20}},
                offset + 60)


def _host(client, port, session, offset, suffix):
    message = f"Accepted password for root from {client} port {port} ssh2"
    login = (f"type=USER_LOGIN msg=audit({T0 + offset + 0.5:.3f}:{700 + session}): pid=900 uid=0 auid=0 "
             f"ses={session} msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=? addr={client} "
             f"terminal=/dev/pts/0 res=success'")
    execve_line = f'type=EXECVE msg=audit({T0 + offset + 2:.3f}:{800 + session}): argc=1 a0="id"'
    syscall = (f"type=SYSCALL msg=audit({T0 + offset + 2:.3f}:{800 + session}): arch=c000003e syscall=59 "
               f"success=yes exit=0 ppid=950 pid={951 + session} auid=0 uid=0 euid=0 ses={session} comm=\"id\" "
               f"exe=\"/usr/bin/id\" key=(null)")

    def audit(_id, raw, at):
        return {"_id": _id, "_index": "romulus-host-logs", "_source": {
            "@timestamp": _stamp(at), "message": raw, "host": {"name": "videoserver"},
            "event": {"dataset": "linux.audit", "original": raw}}}
    journal = {"_id": f"j-{suffix}", "_index": "romulus-host-logs", "_source": {
        "@timestamp": _stamp(offset), "message": message, "host": {"name": "videoserver"},
        "event": {"dataset": "systemd.journal", "original": json.dumps({
            "SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "videoserver", "MESSAGE": message})}}}
    return [journal, audit(f"l-{suffix}", login, offset + 0.5), audit(f"e-{suffix}", execve_line, offset + 2),
            audit(f"s-{suffix}", syscall, offset + 2)]


@pytest.fixture
def swept(monkeypatch, tmp_path):
    """A swept hunt: client A's session has a sweep finding (an IDS alert) and is joined by the sweep; client B's has
    only a flow record, no sweep finding."""
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.test_network_correlation import _Client, _outcome

    by_target = {"romulus-host-logs": [*_host(CLIENT_A, 51022, 11, 2, "a"), *_host(CLIENT_B, 40100, 12, 32, "b")],
                 "romulus-network-logs": [_alert(CLIENT_A, 51022, 1), _flow(CLIENT_B, 40100, 31)]}
    monkeypatch.setattr(sw, "execute", lambda client_, intent, contract: _outcome(intent, by_target[intent.target]))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    order = ("romulus-host-logs", "romulus-network-logs")
    repo.create_hunt("h1", {"targets": list(order)}, "d", "t")
    window = Window(start=BASE, end=BASE + timedelta(hours=1))
    stage = tmp_path / "stage"
    sweep = sw.Sweep(repo, _Client(by_target), "h1", window, {target: None for target in order}, stage_dir=stage)
    for target in order:
        sweep.run_partition(target, None, [], window, est=4)
    sweep.finalize()
    sweep.close_stage()
    events = {event.id: event for event in normalize_hits([*by_target["romulus-network-logs"]])[0]}
    return repo, _Client(by_target), stage, events


def _later_finding(repo, playbook, rule_id, event, lane="lead"):
    match = Match(rule_id, f"{rule_id} observed the session", "network_observation", [event], [], event.ts, "medium",
                  lane, "medium", event.entities(), group_key=f"{rule_id}|{event.id}")
    raw = {ref.key: {"recorded": ref.native_id} for ref in event.raw}
    publish_match(repo, "h1", playbook, match, None, raw)


def _joins(repo):
    return [c for c in repo.candidates("h1") if c["rule_id"] == RULE]


def _flow_event(events, client):
    return next(event for event in events.values() if event.get("source.ip") == client and event.family == "net_flow")


def _alert_event(events, client):
    return next(event for event in events.values() if event.get("source.ip") == client and event.family == "net_alert")


def test_the_sweep_keeps_its_rows_and_joins_only_what_its_findings_cite(swept):
    repo, _client, stage, _events = swept
    assert jp.rows_path(stage, "h1").is_file()
    joins = _joins(repo)
    assert len(joins) == 1 and CLIENT_A in joins[0]["claim"] and CLIENT_B not in joins[0]["claim"]


def test_a_first_seen_admin_pair_is_joined_after_the_baseline_stage(swept):
    repo, client, stage, events = swept
    _later_finding(repo, AdminPairBaseline(), "bl.admin_pair", _flow_event(events, CLIENT_B))
    summary = jp.run_join_pass(repo, client, "h1", stage)
    assert summary["finished"] and summary["rows"] == "kept"
    joins = _joins(repo)
    assert len(joins) == 2
    item = next(c for c in joins if CLIENT_B in c["claim"])
    assert "bl.admin_pair (lead)" in item["claim"] and "host videoserver" in item["claim"]
    assert "client address and client port" in item["claim"] and "1 process or share record(s)" in item["claim"]
    assert item["lane"] == "lead"
    from romulus.report import manifest as rm
    assert all(c["status"] == "retained" for c in rm._citations(repo, item))
    assert not jp.rows_path(stage, "h1").exists()                    # the rows go when the pass finishes
    assert jp.finished(repo, "h1")
    cell = next(c for c in repo.rule_cells("h1", rule_id=RULE) if c["target"] == "*" and c["partition"] == "window")
    assert cell["state"] == "matched" and cell["matched"] == 2
    assert any("2 by endpoint" in reason for reason in cell["detail"]["reasons"])


def test_a_packet_stage_finding_on_an_already_joined_session_revises_the_item(swept):
    repo, client, stage, events = swept
    before = _joins(repo)[0]
    packet_rule = PACKET_PLAYBOOKS[1]()
    _later_finding(repo, packet_rule, packet_rule.id, _alert_event(events, CLIENT_A), lane="high")
    jp.run_join_pass(repo, client, "h1", stage)
    joins = _joins(repo)
    assert len(joins) == 1 and joins[0]["id"] == before["id"]
    assert f"{packet_rule.id} (" in joins[0]["claim"] and "net.suricata_alert_stack" in joins[0]["claim"]
    assert joins[0]["lane"] == "lead"                    # a network finding never raises the join's lane


def test_a_resume_over_the_kept_rows_adds_nothing_twice(swept, monkeypatch):
    repo, client, stage, events = swept
    _later_finding(repo, AdminPairBaseline(), "bl.admin_pair", _flow_event(events, CLIENT_B))
    path = jp.rows_path(stage, "h1")
    copy = path.with_name("copy.db")
    shutil.copy(path, copy)
    monkeypatch.setattr(jp, "discard_rows", lambda *_args: None)       # a crash before the rows were removed
    jp.run_join_pass(repo, client, "h1", stage)
    first = sorted((c["id"], c["claim"], c["lane"]) for c in _joins(repo))
    cell = next(c for c in repo.rule_cells("h1", rule_id=RULE) if c["target"] == "*" and c["partition"] == "window")
    summary = jp.run_join_pass(repo, client, "h1", stage)
    assert summary["items_published_or_revised"] == 0              # every item's content was already published
    shutil.copy(copy, path)                               # a crash after publishing, before its record was kept
    jp.run_join_pass(repo, client, "h1", stage)
    assert sorted((c["id"], c["claim"], c["lane"]) for c in _joins(repo)) == first
    assert len({c["id"] for c in _joins(repo)}) == len(_joins(repo)) == 2
    again = next(c for c in repo.rule_cells("h1", rule_id=RULE) if c["target"] == "*" and c["partition"] == "window")
    assert again["detail"]["reasons"] == cell["detail"]["reasons"] and again["matched"] == cell["matched"]


def test_missing_rows_leave_the_later_findings_sessions_unresolved_by_name(swept):
    repo, client, stage, events = swept
    _later_finding(repo, AdminPairBaseline(), "bl.admin_pair", _flow_event(events, CLIENT_B))
    jp.discard_rows(stage, "h1")
    summary = jp.run_join_pass(repo, client, "h1", stage)
    assert summary["rows"] == "missing" and summary["unresolved_sessions"] == 1
    assert len(_joins(repo)) == 1                         # the sweep's item stands; nothing is unmatched
    cell = next(c for c in repo.rule_cells("h1", rule_id=RULE) if c["target"] == "*" and c["partition"] == "window")
    assert cell["state"] == "match_on_partial"
    assert any("join rows not available on resume" in reason for reason in cell["detail"]["reasons"])


def test_the_pass_is_skipped_once_finished_and_its_stop_is_named(swept):
    from romulus.hunt import run
    repo, client, stage, _events = swept
    assert not jp.finished(repo, "h1")
    marked = run.mark_unrun_stages(repo, "h1", "not run: stopped by analyst", not_run=[run.JOIN_STAGE])
    assert marked == [run.JOIN_STAGE]
    cell = next(c for c in repo.rule_cells("h1", rule_id=RULE) if c["target"] == "*" and c["partition"] == "window")
    assert cell["state"] == "match_on_partial"
    assert any("did not finish (not run: stopped by analyst)" in reason for reason in cell["detail"]["reasons"])
    jp.run_join_pass(repo, client, "h1", stage)
    cell = next(c for c in repo.rule_cells("h1", rule_id=RULE) if c["target"] == "*" and c["partition"] == "window")
    assert not any("did not finish" in reason for reason in cell["detail"]["reasons"])
    assert cell["state"] == "matched"                      # the stop's partial goes with its reason
    assert jp.finished(repo, "h1")


def test_rows_go_with_the_hunt_and_pruning_keeps_only_unfinished_hunts(swept, tmp_path):
    repo, client, stage, _events = swept
    stray = jp.rows_path(stage, "gone")
    stray.write_bytes(b"")
    assert jp.prune_rows(stage, repo) == 1 and not stray.exists() and jp.rows_path(stage, "h1").exists()
    jp.run_join_pass(repo, client, "h1", stage)
    jp.rows_path(stage, "h1").write_bytes(b"")           # a copy left behind by a finished hunt
    assert jp.prune_rows(stage, repo) == 1
    with pytest.raises(ValueError):
        jp.rows_path(stage, "../h1")


def test_the_later_pass_over_many_kept_sessions_spills_and_joins_each(tmp_path):
    rule = NetworkAdminLogonJoin()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path)
    rule.remote.hot_size = rule.activity.hot_size = 128
    rule.persist_path = jp.rows_path(tmp_path / "stage", "h9")
    sessions = []
    for chunk in range(10):
        batch = []
        for n in range(1500):
            i = chunk * 1500 + n
            client = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            offset = i * 0.05
            batch += [sshd(f"a{i}", offset, client=client, port=40000 + i % 20000, host=f"h{i % 200}", boot="b"),
                      audit_login(f"u{i}", offset + 0.1, client=client, session=i, host=f"h{i % 200}", boot="b"),
                      execve(f"x{i}", offset + 0.2, "/bin/true", session=i, host=f"h{i % 200}", boot="b")]
            if i % 5 == 1:                              # (an audit session id of 0 is unset)
                sessions.append(flow(f"f{i}", client=client, cport=40000 + i % 20000, start=offset - 0.5))
        rule.consume(batch)
        assert len(rule.remote.hot) <= 128 and len(rule.activity.hot) <= 128
    rule.consume(sessions)
    store = {event.id: event for event in sessions}
    rule.bind_published(lambda lane, offset, limit: [], lambda ids: [store[i] for i in ids if i in store])
    assert list(rule.finalize()) == []                   # no sweep finding cites any session
    rule.release_state()
    assert rule.persist_path.is_file()
    later = NetworkAdminLogonJoin()
    baseline = finding("B1", sessions, rule="bl.admin_pair")
    later.bind_published(lambda lane, offset, limit: [baseline][offset:offset + limit] if lane == "lead" else [],
                         lambda ids: [store[i] for i in ids if i in store])
    kept = jp._KeptRows(rule.persist_path)
    try:
        matches = list(later.join_pass(kept, later=True))
        assert len(matches) == len(sessions) == 3000
        assert all("1 process or share record(s)" in match.claim for match in matches[:50])
        assert all(match.revision_reason for match in matches)
        assert list(later.join_pass(kept, later=True)) == []      # judged once, published once
    finally:
        kept.close()
