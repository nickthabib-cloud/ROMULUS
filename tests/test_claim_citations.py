"""Every published claim cites what it states.

A claim may state a total, a time span or a named value only when its citations carry it (tests/claim_citations.py
says how that is checked). This guard runs the checker over every finding of the synthetic multi-source hunt
(tests/throughput_fixture.py) and over fixtures shaped like the cases an aggregate rule gets wrong: more records than
it cites, spans whose last record arrives long after the first ones, more distinct values than a claim can list,
lineage ancestors named by a note, and one connection recorded by two sensors. The rules are driven through the
sweep's real event stage, holds and releases included, so a bound released too early fails here.
"""
import json
from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import dns, network
from romulus.detect.auth import AccountOrGroupChange
from romulus.detect.correlation import InterpreterExternalConnection, ProcessNetworkLink
from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.host import WebServiceSpawnsInterpreter
from romulus.detect.kernel_files import PersistencePathChange, RootExecNonRootModifiableFile
from romulus.detect.sessions import ArkimeSshReverseShellTag
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.stage import EventStage
from tests import throughput_fixture as tf
from tests.claim_citations import finding_problems, problems

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
_n = 0


def ev(family, ts, host="web01", outcome="success", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"g{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"g{_n:06d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"g{_n}")], normalizer="fixture")


def staged(rule, batches, stage_dir):
    """Drive a staged rule as the sweep does: each batch's citations are put on a real event stage, its interval
    bounds held and released, then the rule finalizes with the stage's loader."""
    stage = EventStage(stage_dir)
    try:
        for batch in batches:
            rule.consume(list(batch))
            drained = rule.drain_staged()
            held, released = rule.drain_bounds()
            holds, copies = Counter(held), Counter(e.id for e in drained)
            stage.put([e for e in {e.id: e for e in drained}.values() if copies[e.id] > holds[e.id]], {})
            stage.hold([(rule.id, e) for e in {e.id: e for e in drained}.values() for _ in range(holds[e.id])], {})
            stage.release(rule.id, released)
        rule.bind_loader(stage.load)
        return rule.finalize()
    finally:
        stage.close()


def clean(matches):
    """Every match passes the checker (the failures are listed when one does not)."""
    found = {m.claim[:120]: finding_problems(m.claim, m.notes, m.events) for m in matches}
    assert matches and not any(found.values()), {k: v for k, v in found.items() if v}


def batches(events, size):
    return [events[i:i + size] for i in range(0, len(events), size)]


# ---- the checker itself ----------------------------------------------------------------------------------------

def test_the_checker_flags_what_the_review_found_and_passes_honest_wording():
    first = ev("net_alert", T0, source__ip="198.51.100.4", destination__ip="192.0.2.10", alert__signature_id=7)
    last = ev("net_alert", T0 + timedelta(minutes=3), source__ip="198.51.100.4", destination__ip="192.0.2.10")
    span = f"({first.ts.isoformat()} – {last.ts.isoformat()})"
    # a span ending on an uncited record, and a total beyond the citations with no statement of how many are cited
    assert problems(f"479 alerts {span}.", [first]) == [
        f"span endpoint {last.ts.isoformat()} is no cited record's time",
        "states 479 alerts with 1 records cited and does not say how many are cited"]
    assert problems(f"479 alerts {span}. 2 of the 479 alerts are cited, including the first and the last.",
                    [first, last]) == []
    # a bounding record honestly not kept for citation
    assert problems(f"479 alerts {span}. 1 of the 479 alerts are cited. The record that ends this interval was not "
                    f"kept for citation; the interval is computed from every record.", [first]) == []
    # named values: a pid, an address, a signature id, a listed example and a quoted value must be in a cited record
    assert problems("pids 812 and 3 more", [first]) == ["names pid 812, in no cited record"]
    assert problems("sid 7 from 198.51.100.4; e.g. [7]", [first]) == []
    assert problems("sid 8 from 198.51.100.9", [first]) == ["names signature id 8, in no cited record",
                                                             "names address 198.51.100.9, in no cited record"]
    vim = ev("process_exec", T0, process__executable="/usr/bin/vim.basic", process__argv=["vim", "/etc/x"])
    assert problems("the editor 'vi' was started on it", [vim]) == ["quotes 'vi', in no cited record"]
    assert problems("the editor 'vim' was started on it", [vim]) == []
    # wording the rules use as constants is not a value
    assert problems("Suricata reported protocol detection 'failed' on it", [vim]) == []


# ---- the synthetic multi-source hunt ---------------------------------------------------------------------------

def test_every_finding_of_the_synthetic_hunt_cites_what_it_states(tmp_path, monkeypatch):
    tf.patched_sizes(monkeypatch)
    snapshot = tf.run_stack(tmp_path)
    events = {row["id"]: TypedEvent.model_validate(row["event"]) for row in snapshot["events"]}
    found = {}
    for c in snapshot["candidates"]:
        cited = [events[i] for i in c["event_ids"]]
        trouble = finding_problems(c["claim"], c["gate_results"].get("_notes", []), cited)
        if trouble:
            found[f"{c['rule_id']}: {c['claim'][:100]}"] = trouble
    assert len(snapshot["candidates"]) > 30 and found == {}
    # the scan states more records than it cites and says so
    scan = next(c for c in snapshot["candidates"] if c["rule_id"] == "net.port_scan")
    assert "of the 1500 flow records are cited, including the first and the last." in scan["claim"]


# ---- totals, spans and named values beyond the first records -------------------------------------------------------

def test_an_alert_stack_cites_its_span_and_every_signature_it_names(tmp_path):
    alerts = [ev("net_alert", T0 + timedelta(seconds=i * 0.4), source__ip="198.51.100.4", destination__ip="192.0.2.10",
                 alert__signature=f"ET WEB_SERVER probe {i % 64:02d}", alert__signature_id=2_016_000 + i % 64,
                 alert__severity=1, alert__category="Web Application Attack") for i in range(479)]
    [m] = staged(network.SuricataAlertStack(), batches(alerts, 50), tmp_path)
    clean([m])
    assert "479 'Web Application Attack' alert(s) at severity 1 across 64 distinct signature(s)" in m.claim
    assert " of the 479 alerts are cited, including the first and the last." in m.claim
    assert m.events[-1].ts == alerts[-1].ts and m.notes[-1].endswith("and 54 more")


def test_a_web_scan_burst_names_only_cited_user_agents(tmp_path):
    agents = ["Mozilla/5.0 (Nikto)", "sqlmap/1.7", "curl/8.0", "gobuster/3.6", "Wfuzz/3.1", "python-requests/2.31"]
    requests = [ev("http_access", T0 + timedelta(seconds=i), host="web1", source__ip="198.51.100.7",
                   url__original=f"/p{i}", http__response__status_code=404 if i % 10 else 200,
                   user_agent__original=agents[(i // 40) % len(agents)]) for i in range(260)]
    [m] = staged(network.WebScanBurst(), batches(requests, 30), tmp_path)
    clean([m])
    assert "of the 260 requests are cited, including the first and the last." in m.claim


def test_a_reverse_lookup_sweep_cites_its_span_and_the_addresses_it_names(tmp_path):
    questions = [dns_ptr(f"10.30.{4 + i // 200}.{i % 200 + 1}", T0 + timedelta(seconds=i)) for i in range(300)]
    [m] = staged(dns.DnsReverseLookupSweep(), batches(questions, 40), tmp_path)
    clean([m])
    assert "300 DNS question record(s)" in m.claim and "of the 300 question records are cited" in m.claim


def dns_ptr(address, ts):
    name = ".".join(reversed(address.split("."))) + ".in-addr.arpa"
    return ev("dns_query", ts, host="sensor", source__ip="10.20.0.15", destination__ip="10.20.0.53",
              dns__type="query", dns__question__name=name, dns__question__type="PTR")


def test_a_port_scan_and_its_reverse_pair_say_what_their_own_records_show(tmp_path):
    scanner, target = "192.0.2.66", "10.0.0.9"
    flows = [flow(scanner, 40000 + p, target, p, T0 + timedelta(seconds=p * 0.1)) for p in range(1, 400)]
    # the target's answers to the scan (from its service ports to the scanner's ephemeral ports), and a connection the
    # target itself opened to the scanner on tcp/4444, which a Suricata flow state shows
    flows += [flow(target, p, scanner, 40000 + p, T0 + timedelta(seconds=p * 0.1 + 0.01)) for p in range(1, 31)]
    flows += [flow(target, 51000, scanner, 4444, T0 + timedelta(minutes=5), state="established")]
    out = staged(network.PortScan(), batches(flows, 60), tmp_path)
    clean(out)
    by_src = {m.group_key.split("|")[0]: m for m in out}
    reverse = by_src[target]
    assert reverse.proposed_lane == "lead" and "Retained for context" not in reverse.claim
    assert f"The opposite direction, {scanner} to {target}, is reported as a port scan lead" in reverse.claim
    assert f"shows {target} opened the connection on tcp/4444" in reverse.claim


def flow(src, sport, dst, dport, ts, state=None):
    return ev("net_flow", ts, host="fw1", source__ip=src, source__port=sport, destination__ip=dst,
              destination__port=dport, network__transport="tcp", flow__state=state,
              flow__bytes_toserver=200 if state else None)


def test_a_root_run_series_cites_the_run_that_ends_its_span(tmp_path):
    runs = [root_run(T0 + timedelta(minutes=15 * i)) for i in range(28)]
    [m] = staged(RootExecNonRootModifiableFile(), batches(runs, 5), tmp_path)
    clean([m])
    assert "28 times" in m.claim and "of the 28 runs are cited, including the first and the last." in m.claim
    assert m.events[-1].ts == runs[-1].ts


def root_run(ts, path="/usr/share/stats/stats"):
    return ev("process_exec", ts, host="app01", process__argv=["/bin/sh", path], process__executable="/usr/bin/dash",
              process__uid="0", process__euid="0", process__user="root", process__pid=5001, process__ppid=5000,
              process__exec_file__path=path, process__exec_file__owner__id="33",
              process__exec_file__owner__name="www-data", process__exec_file__group__id="33",
              process__exec_file__mode="0100755", process__exec_file__inode=4242, process__exec_file__role="script")


def test_a_non_root_write_quotes_the_editor_the_record_shows_and_counts_root_runs_honestly(tmp_path):
    job = "/srv/tasks/rotate.sh"
    write = ev("process_exec", T0, host="app01", process__argv=["vim", job], process__executable="/usr/bin/vim.basic",
               process__uid="33", process__user="www-data", process__pid=4000, process__ppid=3999,
               process__cwd="/var/www/html")
    runs = []
    for i in range(56):
        ts = T0 - timedelta(hours=1) + timedelta(minutes=5 * i)
        runs += [ev("auth", ts, host="app01", auth__service="cron", auth__phase="session_open",
                    process__session_id=12 + i, process__pid=6000 + 2 * i, user__name="root", process__auid="0"),
                 ev("process_exec", ts + timedelta(seconds=1), host="app01", process__argv=["/bin/sh", "-c", job],
                    process__executable="/usr/bin/dash", process__uid="0", process__user="root", process__auid="0",
                    process__session_id=12 + i, process__pid=6001 + 2 * i, process__ppid=6000 + 2 * i,
                    process__cwd="/root")]
    out = staged(NonRootWriteRootExecutedFile(), batches([write, *runs], 20), tmp_path)
    clean(out)
    [m] = out
    assert "the editor 'vim' was started on it" in m.claim and "'vi'" not in m.claim
    assert "of these 56 records are cited" in m.claim


def test_an_account_change_cites_the_exec_ancestor_its_lineage_names(tmp_path):
    parent = ev("process_exec", T0, host="app01", process__argv=["/usr/bin/cloud-init", "modules"],
                process__executable="/usr/bin/cloud-init", process__uid="0", process__user="root", process__pid=619,
                process__ppid=1)
    child = ev("process_exec", T0 + timedelta(seconds=1), host="app01", process__argv=["useradd", "-m", "svc"],
               process__executable="/usr/sbin/useradd", process__uid="0", process__user="root", process__pid=700,
               process__ppid=619)
    out = staged(AccountOrGroupChange(), [[parent], [child]], tmp_path)
    clean(out)
    [m] = out
    assert "its exec ancestor 1 level(s) up is 'cloud-init'" in m.claim and parent.id in {e.id for e in m.events}


def test_a_rare_web_shell_shape_cites_every_run_its_count_covers(tmp_path):
    runs = [ev("process_exec", T0 + timedelta(minutes=i), host="web1", process__argv=["/bin/sh", "-c", f"id; ls {i}"],
               process__executable="/usr/bin/dash", process__user="www-data", process__uid="33", process__pid=4000 + i,
               process__ppid=3999) for i in range(3)]
    out = staged(WebServiceSpawnsInterpreter(), [runs], tmp_path)
    clean(out)
    assert len(out) == 3 and all("occurred 3 time(s) in the window. All 3 runs are cited." in m.claim for m in out)
    assert all(len(m.events) == 3 for m in out)


def test_an_interpreter_group_lists_only_pids_whose_calls_are_cited(tmp_path):
    calls = []
    for p in range(10):
        for i in range(9):
            calls.append(connect(T0 + timedelta(minutes=p * 30 + i), 57000 + p * 1000, f"203.0.113.{10 + i % 3}"))
    calls.append(connect(T0 + timedelta(hours=7), 99000, "203.0.113.10"))
    [m] = staged(InterpreterExternalConnection(), batches(calls, 15), tmp_path)
    clean([m])
    assert "91 connect() call(s)" in m.claim and "of the 91 connect() records are cited" in m.claim
    assert m.events[-1].ts == calls[-1].ts


def connect(ts, pid, address, exe="/usr/bin/perl", user="www-data"):
    return ev("net_socket", ts, host="videoserver", socket__syscall="connect", destination__ip=address,
              destination__port=443, process__executable=exe, process__user=user, process__uid="33",
              process__pid=pid, process__ppid=1)


def test_persistence_changes_cite_the_record_that_ends_their_span(tmp_path):
    changes = [ev("file_change", T0 + timedelta(seconds=30 * i), host="app01", file__path=f"/etc/cron.d/job{i % 3}",
                  file__change="content", file__owner__id="0", process__uid="0", process__user="root",
                  process__executable="/usr/bin/vim.basic", process__pid=4000, process__ppid=3999,
                  process__auid="1000", process__tty="pts0") for i in range(14)]
    [m] = staged(PersistencePathChange(), batches(changes, 4), tmp_path)
    clean([m])
    assert "of the 14 records are cited, including the first and the last." in m.claim


def test_an_ssh_tag_counts_untagged_connections_without_claiming_to_cite_them(tmp_path):
    from tests.test_flow_rules import events as normalized
    from tests.test_session_fingerprints import ssh_session
    hits = [ssh_session(f"t{i}", ["ssh-reverse-shell"], first=T0 + timedelta(minutes=i)) for i in range(3)]
    hits += [ssh_session(f"u{i}", [], first=T0 + timedelta(minutes=10 + i)) for i in range(14)]
    [m] = staged(ArkimeSshReverseShellTag(), [normalized(*hits)], tmp_path)
    clean([m])
    assert "14 other SSH connection(s)" in m.claim and "(counted; their records are not cited)" in m.claim


# ---- one connection seen by two sensors -----------------------------------------------------------------------------

def test_a_connection_recorded_by_arkime_and_by_suricata_without_a_community_id_counts_once(tmp_path):
    from tests.test_flow_rules import ark
    from tests.test_flow_rules import events as normalized
    from tests.test_network_correlation import _sock, history
    from tests.test_network_correlation import flow as eve_flow
    hs, hn = history()
    call = _sock(exe="/usr/bin/bash", comm="bash", uid="0", user="root")
    start = datetime.fromtimestamp(1731940000.050, UTC)
    # the sensor wrote no community id on its flow record (it is computed from the 5-tuple), and Arkime's session
    # of the same connection carries none in this fixture either
    network = normalized(eve_flow("s1", cid=None),
                         ark("a1", src="198.51.100.10", sport=51000, dst="192.0.2.174", dport=4444, start=start,
                             seconds=30, c2s=400, s2c=900))
    out = staged(ProcessNetworkLink(), [hs + [call], hn + network], tmp_path)
    m = next(m for m in out if "port 4444" in m.claim)
    clean([m])
    assert "2 flow or session record(s) across 1 connection(s) to 192.0.2.174 port 4444" in m.claim


def test_the_join_stages_what_it_can_cite_not_every_network_record(tmp_path):
    """Network traffic that no connect() call reaches is held only boundedly (one record per endpoint pair), and a
    call's group keeps its first calls and bounds: the stage grows with groups and pairs, not with records."""
    from tests.test_network_correlation import _sock, history
    hs, hn = history()
    calls = hs + [_sock(1000 + i, exe="/usr/bin/bash", comm="bash", uid="0", user="root",
                        t0=1731940000.1 + i) for i in range(40)]
    scan = [flow("192.0.2.66", 40000 + p, "10.0.0.9", p, T0 + timedelta(seconds=p * 0.01)) for p in range(1, 3001)]
    rule = ProcessNetworkLink()
    seen = set()
    for batch in [calls, *batches(scan, 500), hn]:
        rule.consume(batch)
        seen |= {e.id for e in rule.drain_staged()}
    # the 40 calls of one group keep their first EXAMPLE_LIMIT, and each of the 3000 scan records is the first of its
    # own (port, address) pair, held until UNMATCHED_HELD; the history's records are matched pairs
    assert len(seen & {e.id for e in calls}) <= 20 + 2 + 16 + len(hs)
    assert len(seen & {e.id for e in scan}) == 3000          # one per pair, every pair new: under the hold bound


def test_the_unmatched_network_records_held_for_citation_are_bounded(tmp_path, monkeypatch):
    from romulus.detect import correlation
    monkeypatch.setattr(correlation, "UNMATCHED_HELD", 100)
    rule = ProcessNetworkLink()
    scan = [flow("192.0.2.66", 40000 + p, "10.0.0.9", p, T0 + timedelta(seconds=p * 0.01)) for p in range(1, 1001)]
    holds = Counter()
    for batch in batches(scan, 100):
        rule.consume(batch)
        rule.drain_staged()
        held, released = rule.drain_bounds()
        holds.update(held)
        holds.subtract(released)
    assert sum(n for n in holds.values() if n > 0) == 100
    assert any("the oldest were released" in reason for reason in rule.limit_reasons())


def test_nxdomain_names_and_servers_come_from_cited_records(tmp_path):
    answers = [ev("dns_query", T0 + timedelta(seconds=3 * i), host="sensor", source__ip=f"10.20.0.{53 + i % 7}",
                  destination__ip="10.20.0.15", dns__type="answer", dns__response_code="NXDOMAIN",
                  dns__question__name=f"q{i:04d}{'x' * (i % 40)}.example.test") for i in range(240)]
    [m] = staged(dns.DnsNxdomainBurst(), batches(answers, 30), tmp_path)
    clean([m])
    assert "240 NXDOMAIN answer(s)" in m.claim and "of the 240 NXDOMAIN answer records are cited" in m.claim


def test_a_tunnel_shape_cites_its_example_names_and_span(tmp_path):
    from tests.test_dns_rules import tunnel
    out = staged(dns.DnsTunnelShape(), batches(tunnel(400), 50), tmp_path)
    clean(out)
    assert "of the 400 questions are cited, including the first and the last." in out[0].claim


def test_subdomain_and_tool_agent_groups_disclose_their_citations(tmp_path):
    queries = [ev("dns_query", T0 + timedelta(seconds=i), host="sensor", source__ip="10.20.0.15",
                  destination__ip="10.20.0.53", dns__type="query", dns__question__name=f"n{i}.corp.example")
               for i in range(150)]
    clean(staged(network.DnsSubdomainEnumeration(), batches(queries, 25), tmp_path / "a"))
    requests = [ev("http_tx", T0 + timedelta(seconds=i), host="sensor", source__ip="198.51.100.7",
                   destination__ip="10.0.0.10", http__hostname="web1", user_agent__original="curl/8.0",
                   url__original=f"/u{i}") for i in range(40)]
    [m] = staged(network.ToolUserAgentHttp(), batches(requests, 10), tmp_path / "b")
    clean([m])
    assert "URLs include ['/u0', '/u1', '/u2'] and 37 more." in m.claim


def test_spraying_names_only_the_accounts_its_cited_records_show(tmp_path):
    from romulus.detect.auth import SshPasswordGuessing, SshPasswordSpraying
    from tests.test_ssh_auth_attacks import ssh
    names = [f"user{i:02d}" for i in range(30)]
    attempts = [ssh(T0 + timedelta(seconds=20 * i), user=names[i % 30], port=40000 + i) for i in range(90)]
    clean(staged(SshPasswordSpraying(), batches(attempts, 15), tmp_path / "a"))
    guesses = [ssh(T0 + timedelta(seconds=20 * i), user="root", port=41000 + i) for i in range(60)]
    [m] = staged(SshPasswordGuessing(), batches(guesses, 15), tmp_path / "b")
    clean([m])
    assert "of the 60 attempt records are cited, including the first and the last." in m.claim


def test_discovery_counts_the_classes_it_lists():
    from romulus.detect.context import PostAccessDiscovery
    from tests.test_context_playbooks import anchor, event, link
    commands = [event(f"c{i}", process__argv=argv, process__executable=f"/usr/bin/{argv[0]}", process__session_id=42,
                      process__pid=900 + i, process__ppid=899)
                for i, argv in enumerate([["id"], ["whoami"], ["uname", "-a"], ["hostname"], ["ip", "addr"],
                                          ["ps", "aux"], ["getent", "passwd"], ["groups"]])]
    [m] = PostAccessDiscovery().consume_linked(anchor(), link(), commands)
    listed = m.claim.split("[", 1)[1].split("]", 1)[0].split(", ")
    assert f"across {len(listed)} distinct discovery class(es)" in m.claim
    assert "in audit session 42" in m.claim and "this session" not in m.claim


def _links_with_decoy(tmp_path, monkeypatch, cited_as: str | None):
    """The synthetic hunt's expansion links when every anchor-lane finding on web1 also cites an unrelated exec record
    (another process, in its own audit session), as a record of its own or only for its claim's statements."""
    from romulus.hunt import publish
    from romulus.hunt import sweep as sweep_module
    original = publish.publish_match
    decoy = TypedEvent(id="decoy-exec", family="process_exec", ts=tf.T0 + timedelta(minutes=6), host="web1",
                       outcome="success",
                       fields={"process.pid": fv(31337, "decoy:pid"), "process.ppid": fv(31336, "decoy:ppid"),
                               "process.session_id": fv(55, "decoy:ses"), "process.argv": fv(["id"], "decoy:argv"),
                               "process.executable": fv("/usr/bin/id", "decoy:exe")},
                       raw=[RawRef(target=tf.HOST_TARGET, native_id="decoy")], normalizer="fixture")

    def publish_with_decoy(repo, hunt_id, playbook, match, *args, **kwargs):
        if cited_as and match.proposed_lane in ("urgent", "high") and match.events[0].host == "web1":
            match.events = [*match.events, decoy]
            if cited_as == "context":
                match.context_ids = {*match.context_ids, decoy.id}
        return original(repo, hunt_id, playbook, match, *args, **kwargs)

    from romulus.hunt import expansion as expansion_module
    # the sweep and expansion (which re-publishes direct findings its pivots read) both cite it
    monkeypatch.setattr(sweep_module, "publish_match", publish_with_decoy)
    monkeypatch.setattr(expansion_module, "publish_match", publish_with_decoy)
    tf.patched_sizes(monkeypatch)
    snapshot = tf.run_stack(tmp_path)
    monkeypatch.undo()
    # a link and its tasks are named by the anchor's candidate id, which the decoy's citation changes: compare what
    # each link is
    rule_of = {c["id"]: (c["rule_id"], c["group_key"]) for c in snapshot["candidates"]}
    return sorted(json.dumps({**{k: v for k, v in link.items() if k not in ("id", "anchor_id", "task_ids")},
                              "anchor": rule_of[link["anchor_id"]]}, sort_keys=True, default=str)
                  for link in snapshot["links"])


def test_a_record_cited_only_for_the_claim_adds_no_expansion_link(tmp_path, monkeypatch):
    plain = _links_with_decoy(tmp_path / "a", monkeypatch, None)
    assert _links_with_decoy(tmp_path / "b", monkeypatch, "context") == plain
    # the control: the same record cited as the finding's own is expanded from
    assert _links_with_decoy(tmp_path / "c", monkeypatch, "own") != plain


def test_a_candidate_stored_without_the_field_is_about_every_record_it_cites():
    from romulus.hunt.publish import subject_event_ids
    assert subject_event_ids({"event_ids": ["a", "b"]}) == ["a", "b"]
    assert subject_event_ids({"event_ids": ["a", "b"], "context_event_ids": None}) == ["a", "b"]
    assert subject_event_ids({"event_ids": ["a", "b"], "context_event_ids": ["b"]}) == ["a"]


def test_holds_release_a_record_not_yet_staged_by_not_staging_it_and_count_each_hold():
    from romulus.detect.citing import Holds
    a, b = ev("net_flow", T0), ev("net_flow", T0)
    holds = Holds()
    holds.hold(a)
    holds.hold(a)                       # two groups hold it
    holds.hold(b)
    holds.release(b.id)                 # let go before the batch ended: never staged
    assert [e.id for e in holds.drain()] == [a.id, a.id] and holds.last == ([a.id, a.id], [])
    holds.release(a.id)                 # an earlier batch's hold: released on the stage
    assert holds.drain() == [] and holds.last == ([], [a.id])


@pytest.mark.parametrize("bad", ["", "-"])
def test_the_checker_ignores_text_without_values(bad):
    assert problems(f"Nothing to check here{bad}.", []) == []
