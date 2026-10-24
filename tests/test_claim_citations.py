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


def test_the_checker_holds_each_count_and_endpoint_to_its_own_disclosure():
    first = ev("net_alert", T0, source__ip="198.51.100.4", destination__ip="192.0.2.10", alert__signature_id=7)
    last = ev("net_alert", T0 + timedelta(minutes=3), source__ip="198.51.100.4", destination__ip="192.0.2.10")
    # a disclosure of one total does not cover another count
    assert problems("479 alerts across 64 distinct signatures. 2 of the 479 alerts are cited.", [first, last]) == [
        "states 64 signatures with 2 records cited and does not say how many are cited"]
    # a disclosure whose total differs from the stated count covers nothing
    assert problems("50 attempts. 2 of the 47 attempts are cited.", [first, last]) == [
        "states 50 attempts with 2 records cited and does not say how many are cited"]
    assert problems("50 attempts. 2 of the 50 attempts are cited.", [first, last]) == []
    # a statement about the record that ends a span excuses its end, never its start
    gap = f"({(T0 - timedelta(minutes=1)).isoformat()} – {(T0 + timedelta(minutes=9)).isoformat()})"
    assert problems(f"Alerts {gap}. The record that ends this interval was not kept for citation.", [first]) == [
        f"span endpoint {(T0 - timedelta(minutes=1)).isoformat()} is no cited record's time"]


def test_the_checker_holds_a_lower_bound_to_its_disclosure():
    first = ev("net_alert", T0, source__ip="198.51.100.4", destination__ip="192.0.2.10")
    last = ev("net_alert", T0 + timedelta(minutes=3), source__ip="198.51.100.4", destination__ip="192.0.2.10")
    # 'at least' does not excuse a count from saying how many are cited
    assert problems("across at least 2000 signatures.", [first, last]) == [
        "states 2000 signatures with 2 records cited and does not say how many are cited"]
    assert problems("across at least 2000 signatures. 2 of at least 2000 signatures are in cited alerts.",
                    [first, last]) == []
    # a lower bound disclosed as exact, and an exact count disclosed as a lower bound
    assert problems("across at least 2000 signatures. 2 of the 2000 signatures are in cited alerts.",
                    [first, last]) == ["discloses 2 of 2000 as exact, but 2000 is stated as a lower bound"]
    assert problems("across 2000 signatures. 2 of at least 2000 signatures are in cited alerts.",
                    [first, last]) == ["discloses 2 of at least 2000, but 2000 is stated exactly"]
    assert problems("at least 2 alerts. All 2 alerts are cited.", [first, last]) == [
        "says all 2 are cited, but 2 is stated as a lower bound"]


def test_the_checker_treats_a_one_word_quote_as_a_value_and_checks_who_made_the_calls():
    from tests.test_network_correlation import _sock
    # a program name the rules also quote somewhere is still a value the claim names
    assert problems("the downloader 'curl' ran", [ev("process_exec", T0, process__executable="/usr/bin/wget")]) == [
        "quotes 'curl', in no cited record"]
    own, other = _sock(pid=200), _sock(pid=300)
    ip, port = own.get("destination.ip"), own.get("destination.port")
    claim = f"'/usr/bin/perl' (pid 300, user 'www-data') made 1 connect() call(s) to {ip} port {port} that join"
    assert problems(claim, [own]) == [
        f"names pid 300 as calling {ip} port {port}, but no cited connect() record of it does",
        "names pid 300, in no cited record"]
    # a pid on a cited record that made none of the calls named (here the parent of the one that did) is caught too
    ppid = own.get("process.ppid")
    expected = f"names pid {ppid} as calling {ip} port {port}, but no cited connect() record of it does"
    assert problems(claim.replace("pid 300", f"pid {ppid}"), [own]) == [expected]
    assert problems(claim, [other]) == []
    wide = f"show '/usr/bin/perl' (pids 200, 300), a reason, making 2 connect() call(s) to 1 address(es) on port {port}"
    assert problems(wide, [own, other]) == []
    assert problems(wide, [own, other.model_copy(update={"fields": {
        **other.fields, "destination.port": fv(1, "x:destination.port")}})]) == [
        f"names pid 300 as calling port {port}, but no cited connect() record of it does"]


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
    assert "21 of the 64 signatures are in cited alerts." in m.claim
    assert m.events[-1].ts == alerts[-1].ts and m.notes[-1].endswith("and 11 more; 43 other signature(s) are in "
                                                                     "alerts not cited")


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
    """A call's group keeps its first calls, its bounds and its earliest processes' calls; network records are kept per
    (service endpoint, client address) pair: the first twenty once a call reached the endpoint, the first one before.
    The stage grows with groups and pairs, not with records, and its disk budget bounds it."""
    from tests.test_network_correlation import _sock, history
    hs, hn = history()
    calls = hs + [_sock(1000 + i, exe="/usr/bin/bash", comm="bash", uid="0", user="root",
                        t0=1731940000.1 + i) for i in range(40)]
    scan = [flow("192.0.2.66", 40000 + p, "10.0.0.9", p, T0 + timedelta(seconds=p * 0.01)) for p in range(1, 3001)]
    repeated = [flow("192.0.2.66", 50000 + i, "10.0.0.9", 443, T0 + timedelta(minutes=1, seconds=i)) for i in range(50)]
    rule = ProcessNetworkLink()
    seen = set()
    for batch in [calls, *batches(scan, 500), repeated, hn]:
        rule.consume(batch)
        seen |= {e.id for e in rule.drain_staged()}
    assert len(seen & {e.id for e in calls}) <= 20 + 2 + 16 + len(hs)
    assert len(seen & {e.id for e in scan}) == 3000          # each the first record of its own pair
    assert len(seen & {e.id for e in repeated}) == 0         # tcp/443 from 192.0.2.66 already has its first record
    assert rule.limit_reasons() == []


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


@pytest.mark.parametrize("which", ["guessing", "spraying"])
def test_ssh_attempts_claim_the_first_and_last_are_cited_only_when_they_are(tmp_path, which):
    from romulus.detect.auth import SshPasswordGuessing, SshPasswordSpraying
    from tests.test_ssh_auth_attacks import ssh
    attempts = [ssh(T0 + timedelta(seconds=20 * i), user="root" if which == "guessing" else f"user{i % 30:02d}",
                    port=42000 + i) for i in range(60)]
    base = SshPasswordGuessing if which == "guessing" else SshPasswordSpraying

    class LastNotHeld(base):
        def _load(self, ids):
            return [e for e in super()._load(ids) if e.id != attempts[-1].id]

    [m] = staged(LastNotHeld(), batches(attempts, 15), tmp_path / which)
    clean([m])
    assert attempts[-1].id not in {e.id for e in m.events}
    assert "including the first and the last" not in m.claim
    assert "The record that ends the stated span was not kept for citation" in m.claim


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


def _refusing_exec_records(monkeypatch):
    from romulus.detect.bounded import KeyedStore
    put = KeyedStore.put
    monkeypatch.setattr(KeyedStore, "put", lambda self, key, value: False if self.name == "exec_records"
                        else put(self, key, value))


def test_an_exec_record_not_kept_for_citation_changes_no_verdict_only_the_citation(monkeypatch):
    from tests.test_network_correlation import T0 as SOCK_T0
    from tests.test_network_correlation import _sock, execd, iec, observed
    spawn = observed(150, 1, "/usr/lib/systemd/systemd", SOCK_T0 - 60.004, 40, comm="(perl)")
    tree = [spawn, execd(150, 1, "/usr/bin/perl"), execd(100, 150, "/usr/bin/perl", t0=SOCK_T0 - 30)]
    kept = iec(*tree, _sock())[0]
    _refusing_exec_records(monkeypatch)
    [refused] = iec(*tree, _sock())
    # the service-manager verdict and the lowered lane stand; the exec records are named, not cited, and it says so
    assert refused.proposed_lane == kept.proposed_lane == "lead"
    assert "reaches the service manager with no web server" in refused.claim
    assert {e.id for e in refused.events} == {e.id for e in kept.events} - {"xvideoserver100", "xvideoserver150"}
    assert any("were not kept for citation" in note for note in refused.notes)
    # nothing went unevaluated: the window cell gets a note, not a limit that would make it partial
    limits, notes = refused_reasons(tree)
    assert not limits
    assert any("exec records kept for citation" in note and "still evaluated" in note for note in notes)


def refused_reasons(tree):
    from romulus.detect.correlation import InterpreterExternalConnection
    from tests.test_network_correlation import _sock
    rule = InterpreterExternalConnection()
    rule.consume([*tree, _sock()])
    return rule.limit_reasons(), rule.coverage_notes()


def _refusal_point(budget, account, step=10, limit=10_000):
    """The bytes a store holds when the budget first refuses it a new key."""
    while not budget.new_key_reason(account) and account.used < limit:
        budget.charge(account, step)
    return account.used


def test_the_exec_citation_store_takes_nothing_from_the_detection_stores_headroom():
    """Records kept only to be cited never cost a detection store its state: the citation store holds no floor, its
    bytes do not count in the headroom the detection stores share (a full one leaves their refusal point where it is
    without it), it stops growing at half their headroom, the volume's reserve still binds it, and its refusal is no
    detection store's limit."""
    from romulus.detect.bounded import StateBudget, live_stores
    from romulus.detect.host import ExecLineage
    alone = StateBudget(disk_total=1000, reserve=0)
    plain = alone.account("rule:state")
    alone.plan(1)
    budget = StateBudget(disk_total=1000, reserve=0)
    detect = budget.account("rule:state")
    cite = budget.account("rule:exec_records", yields=True)
    budget.plan(1)
    assert cite.weight == 0 and budget.floor_of(cite) == 0 and budget.floor == 500 and budget.pool == 500
    budget.charge(cite, 5000)           # a citation store far past the whole shared headroom
    assert budget.pool_used == 0 and budget.new_key_reason(cite) == ""
    assert _refusal_point(budget, detect) == _refusal_point(alone, plain) == 1000
    assert "rule:exec_records" not in budget.full and budget.full == alone.full

    # it stops growing once the detection stores hold half their headroom
    budget = StateBudget(disk_total=1000, reserve=0)
    detect, cite = budget.account("rule:state"), budget.account("rule:exec_records", yields=True)
    budget.plan(1)
    budget.charge(detect, 740)
    assert budget.new_key_reason(cite) == ""
    budget.charge(detect, 10)           # 250 of the 500 shared bytes
    assert "gives way at half" in budget.new_key_reason(cite) and budget.new_key_reason(detect) == ""
    assert not budget.spent

    # the volume's reserve binds it as it binds every store
    budget.low_space = "the stage volume's free space is below the reserve"
    assert budget.new_key_reason(cite) == budget.low_space

    class Owner:
        id = "rule"
        holds_state = False

    owner = Owner()
    lineage = ExecLineage(owner, citing=True)
    # the pack plans floors for the lineage store alone
    assert lineage.exec_records.yields and live_stores([owner]) == 1


def test_an_account_change_says_its_ancestor_is_not_cited_and_keeps_its_lane(monkeypatch, tmp_path):
    def run():
        web = ev("process_exec", T0, host="app01", process__argv=["/bin/sh", "-c", "useradd svc"],
                 process__executable="/usr/bin/dash", process__uid="33", process__user="www-data", process__pid=4000,
                 process__ppid=3999)
        child = ev("process_exec", T0 + timedelta(seconds=1), host="app01", process__argv=["useradd", "svc"],
                   process__executable="/usr/sbin/useradd", process__uid="0", process__user="root",
                   process__pid=4001, process__ppid=4000)
        return staged(AccountOrGroupChange(), [[web], [child]], tmp_path), web
    ([kept], web) = run()
    _refusing_exec_records(monkeypatch)
    ([refused], web2) = run()
    assert refused.proposed_lane == kept.proposed_lane == "high"
    assert web.id in {e.id for e in kept.events} and web2.id not in {e.id for e in refused.events}
    assert "(its exec record was not kept for citation)" in refused.claim


@pytest.mark.parametrize("exe, argv, named", [
    ("/bin/sh", ["sh", "-e", "/opt/app/run.sh"], "run.sh"),          # a shell's -e is an option: the script is named
    ("/bin/bash", ["bash", "-E", "-r", "/opt/app/run.sh"], "run.sh"),
    ("/bin/sh", ["sh", "-ec", "echo /opt/app/run.sh"], "sh"),         # -c among grouped flags: the operand is code
    ("/bin/sh", ["sh", "-c", "/opt/app/run.sh"], "sh"),
    ("/usr/bin/perl", ["perl", "-e", "print 1"], "perl"),              # an interpreter's -e takes code
    ("/usr/bin/python3", ["python3", "/opt/app/job.py"], "job.py"),
])
def test_a_lineage_names_a_shell_script_unless_its_operand_is_code(exe, argv, named):
    from romulus.detect.host import ProcessLineage
    record = ev("process_exec", T0, process__pid=10, process__ppid=1, process__executable=exe, process__argv=argv)
    assert ProcessLineage.entry(record).name == named


def test_a_helper_group_cites_a_pair_for_every_peer_before_repeating_one(monkeypatch):
    """Past the cap of cited (pid, peer) pairs, the pairs cited cover every distinct peer first: a later peer is
    named and cited, not lost behind repeats of the first."""
    from romulus.detect import lineage
    from tests.test_lineage import EXT, _daemon_helpers, run
    monkeypatch.setattr(lineage, "HELPER_PAIRS_CITED", 2)
    parts = [_daemon_helpers(pid=300 + 20 * i, start=T0 + timedelta(hours=i), peers=(EXT,)) for i in range(3)]
    parts.append(_daemon_helpers(pid=360, start=T0 + timedelta(hours=3), peers=("198.51.100.50",)))
    _pb, [m] = run([e for part in parts for e in part])
    clean([m])
    assert f"{EXT}:443" in m.claim and "198.51.100.50:443" in m.claim
    assert {e.get("destination.ip") for e in m.events if e.family == "net_socket"} == {EXT, "198.51.100.50"}


def test_rare_web_shell_shapes_are_one_candidate_each_and_keep_their_id_whatever_context_they_cite(tmp_path):
    from dataclasses import replace

    from romulus.decide.policy import candidate_id
    runs = [ev("process_exec", T0 + timedelta(minutes=i), host="web1", process__argv=["/bin/sh", "-c", f"id; ls {i}"],
               process__executable="/usr/bin/dash", process__user="www-data", process__uid="33", process__pid=4000 + i,
               process__ppid=3999) for i in range(3)]
    out = staged(WebServiceSpawnsInterpreter(), [runs], tmp_path)
    ids = {candidate_id(m, "h1") for m in out}
    assert len(out) == 3 and len(ids) == 3
    # the same finding citing other records for context is the same candidate
    m = out[0]
    extra = ev("process_exec", T0 + timedelta(hours=1), host="web1", process__pid=9, process__ppid=1)
    again = replace(m, events=[*m.events, extra], context_ids={*m.context_ids, extra.id})
    assert candidate_id(again, "h1") == candidate_id(m, "h1")


def test_a_process_with_no_linked_call_is_neither_named_nor_counted():
    """Only the processes whose calls join the network records are named and judged: an earlier process of the same
    program and account to the same endpoint, which no sensor record joins, is not one of them."""
    from tests.test_network_correlation import T0 as SOCK_T0
    from tests.test_network_correlation import _network, _sock, alert, flow, history, link
    hs, hn = history()
    early = _sock(serial=600, pid=300, t0=SOCK_T0 - 3600)
    late = _sock(serial=500, pid=200)
    [m] = [m for m in link(hs + [early, late], hn + _network(flow(), alert())) if "port 4444" in m.claim]
    assert "(pid 200," in m.claim and "300" not in m.claim and "made 1 connect() call(s)" in m.claim
    assert {e.get("process.pid") for e in m.events if e.family == "net_socket"} == {200}
    assert not finding_problems(m.claim, m.notes, m.events)


def test_a_group_the_connecting_store_cannot_take_is_still_published(monkeypatch):
    from romulus.detect import bounded
    from tests.test_network_correlation import SSHD, _network, _sock, alert, flow, history, link

    def run():
        hs, hn = history()
        return [m for m in link(hs + [_sock(**SSHD)], hn + _network(flow(), alert())) if "port 4444" in m.claim]

    [kept] = run()
    put = bounded.KeyedStore.put
    monkeypatch.setattr(bounded.KeyedStore, "put", lambda self, key, state: False
                        if self.name == "pnl_sock_groups" and key not in self.hot else put(self, key, state))
    [refused] = run()
    assert refused.proposed_lane == kept.proposed_lane
    assert {e.id for e in refused.events} >= {e.id for e in kept.events if e.family == "net_socket"}
    assert not finding_problems(refused.claim, refused.notes, refused.events)


# ---- counts at a cap are stated as lower bounds ---------------------------------------------------------------------

def test_an_alert_stack_past_its_signature_cap_states_a_lower_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(network.SuricataAlertStack, "SIGNATURES_HELD", 5)
    alerts = [ev("net_alert", T0 + timedelta(seconds=i), source__ip="198.51.100.4", destination__ip="192.0.2.10",
                 alert__signature=f"ET WEB_SERVER probe {i % 12:02d}", alert__signature_id=2_016_000 + i % 12,
                 alert__severity=1, alert__category="Web Application Attack") for i in range(40)]
    rule = network.SuricataAlertStack()
    [m] = staged(rule, batches(alerts, 10), tmp_path)
    clean([m])
    assert "across at least 5 distinct signature(s)" in m.claim and " of at least 5 signatures are in cited" in m.claim
    assert "and 2 more or more." in m.claim
    assert any("its signature count is stated as a lower bound" in r for r in rule.limit_reasons())
    # below the cap the count is exact
    exact = network.SuricataAlertStack()
    [m] = staged(exact, batches(alerts[:5], 10), tmp_path / "exact")
    assert "across 5 distinct signature(s)" in m.claim and not exact.limit_reasons()


def test_subdomain_enumeration_past_its_name_cap_states_a_lower_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(network.DnsSubdomainEnumeration, "NAMES_HELD", 120)
    queries = [ev("dns_query", T0 + timedelta(seconds=i), source__ip="10.20.0.15", dns__type="query",
                  dns__question__name=f"h{i}.example.test") for i in range(130)]
    rule = network.DnsSubdomainEnumeration()
    [m] = staged(rule, batches(queries, 50), tmp_path)
    clean([m])
    assert "130 DNS queries for at least 120 distinct names under 'example.test'" in m.claim
    assert any("its name count is stated as a lower bound" in r for r in rule.limit_reasons())


def test_a_sweep_destination_past_its_connection_cap_states_a_lower_bound(monkeypatch):
    from romulus.detect.flows import HorizontalSweep
    from tests.test_flow_rules import eve, events, sweep_flows
    from tests.test_flow_rules import run as run_flows
    monkeypatch.setattr(HorizontalSweep, "CONNECTIONS_PER_DESTINATION", 2)
    again = [eve(f"r{i}", src="10.0.0.5", sport=41000 + i, dst="10.0.1.1", dport=445,
                 start=T0 + timedelta(seconds=40 + i)) for i in range(3)]
    [m] = run_flows(HorizontalSweep(), events(*sweep_flows(30), *again))
    clean([m])
    assert "10.0.1.1 (at least 2 connections, " in m.claim and "At least " in m.claim


def test_a_mismatch_group_past_its_connection_cap_states_its_sources_as_lower_bounds(monkeypatch):
    from romulus.detect.flows import ProtocolPortMismatch
    from tests.test_flow_rules import ATTACKER, eve, events
    from tests.test_flow_rules import run as run_flows
    monkeypatch.setattr(ProtocolPortMismatch, "CONNECTIONS_PER_MISMATCH", 2)
    hits = [eve(f"x{i}", src="10.0.0.5", sport=50000 + i, dst=ATTACKER, dport=443, app_proto="ssh", c2s=4000,
                s2c=9000, pkts_s=12, start=T0 + timedelta(seconds=i)) for i in range(3)]
    [m] = run_flows(ProtocolPortMismatch(), events(*hits))
    clean([m])
    assert (f"Suricata identified ssh on at least 2 connections to {ATTACKER} on tcp/443 from at least 1 source "
            f"(10.0.0.5: at least 2)") in m.claim


@pytest.mark.slow
def test_a_port_scan_over_every_port_counts_them_exactly(tmp_path):
    """A port is 0-65535, so the scan's distinct ports are bounded by construction and never a lower bound."""
    flows = [ev("net_flow", T0 + timedelta(milliseconds=i), source__ip="198.51.100.4", source__port=40000,
                destination__ip="10.0.0.20", destination__port=port, network__transport="udp")
             for i, port in enumerate(range(65536))]
    [m] = staged(network.PortScan(), batches(flows, 8192), tmp_path)
    assert "covering 65536 distinct destination ports" in m.claim and "at least" not in m.claim
    clean([m])


def test_a_list_with_no_cited_name_says_how_many_there_are_not_none():
    from romulus.detect.auth import _names
    assert _names(set(), more_than=3) == "none of the 3 is in a cited record"
    assert _names(set()) == "none"
    assert _names({"b", "a"}, more_than=5) == "'a', 'b' and 3 more"


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
