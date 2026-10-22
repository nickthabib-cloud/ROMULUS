"""Network anchors and their victim host: an address is never used as a host name, an endpoint is
resolved to one host from typed host records or the host-side links say why not, and the flow's host side is
found by the endpoint itself when no host identity exists."""
from datetime import UTC, datetime, timedelta

from romulus.detect import netdef
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotEventBatch, PivotExecutor
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=3))
AUDIT_FAMILIES = {"process_exec", "net_socket", "auth"}


def ev(event_id, family, *, host, target, ts=T0, **fields):
    return TypedEvent(
        id=event_id, family=family, ts=ts, host=host, outcome=Outcome.success,
        fields={name.replace("__", "."): fv(value, f"{event_id}:{name}") for name, value in fields.items()},
        raw=[RawRef(target=target, native_id=event_id, digest="d")], normalizer="test@1",
    )


def contracts(*, host_ip=False):
    host_fields = {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
                   "destination.ip": "ip", "destination.port": "integer", "process.pid": "integer",
                   "process.session_id": "integer", "user.name": "keyword", "source.ip": "ip"}
    if host_ip:
        host_fields["host.ip"] = "ip"
    return {
        "host-x": contract_from_types("host-x", host_fields),
        "network-x": contract_from_types("network-x", {
            "@timestamp": "date", "event.dataset": "keyword", "source.ip": "ip", "destination.ip": "ip",
            "source.port": "integer", "destination.port": "integer", "network.community_id": "keyword",
            "network.transport": "keyword"}),
    }


def _matches(predicate, event):
    if predicate.field == "event.dataset":
        return event.family in AUDIT_FAMILIES if predicate.value == "linux.audit" else True
    value = event.host if predicate.field == "host.name" else event.get(predicate.field)
    if predicate.op == "eq":
        return value == predicate.value
    if predicate.op == "in":
        return value in predicate.value
    return True


def _honours(intent, event):
    return (event.raw[0].target == intent.target and intent.window.start <= event.ts < intent.window.end
            and all(_matches(p, event) for p in intent.filters)
            and (not intent.any_of or any(all(_matches(p, event) for p in group) for group in intent.any_of)))


class PredicateExecutor:
    """A fake source that honours every predicate it is sent, so a wrong-typed key finds nothing."""

    resolve_host_ip = PivotExecutor.resolve_host_ip

    def __init__(self, repo, events, contract_map):
        self.repo, self.events, self.contracts = repo, events, contract_map
        self.dataset_inventory, self.source_queries, self.sent = {}, 0, []
        self.hunt_id, self.owner_token = "h1", None

    def _intents(self, request):
        return PivotExecutor._intents(self, request)

    def plan(self, request):
        return PivotExecutor.plan(self, request)

    def _unsearchable_ip_coverage(self, request, intents=None):
        return PivotExecutor._unsearchable_ip_coverage(self, request, intents)

    def _execute(self, intent, contract, *, pit=None, spend_task_id=None):
        if spend_task_id is not None:                      # as the real executor: checkpoint before I/O
            self.repo.record_task_source_query(spend_task_id)
        self.source_queries += 1
        self.sent.append(intent)
        names = {}
        for event in self.events:
            if _honours(intent, event):
                names[event.host] = names.get(event.host, 0) + 1
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=T0, ended_at=T0,
                             completeness=Completeness.complete, total=sum(names.values()), total_relation="eq",
                             buckets=[{"key": {"host.name": h}, "count": n} for h, n in sorted(names.items())])

    def fetch_intents(self, owner, fetch_key, intents, retain, *, anchor_ts=None, query_cap=None,
                      planning_coverage=None):
        self.source_queries += len(intents)
        self.sent.extend(intents)
        hits = [e for e in self.events if any(_honours(i, e) for i in intents) and retain(e)]
        self.repo.save_evidence("h1", hits, {}, None)
        return PivotEventBatch(status="complete", task_ids=["t-1"], events=hits, raw_sources={}, coverage=[],
                               reasons=[], duration_ms=1)


def network_anchor_repo(src="10.0.0.2", dst="203.0.113.8", sport=50000, dport=443):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
                            "targets": [], "budgets": {}}, "digest", "test")
    alert = ev("alert", "net_alert", host="sensor1", target="network-x", source__ip=src, source__port=sport,
               destination__ip=dst, destination__port=dport, network__transport="tcp")
    repo.save_evidence("h1", [alert], {}, None)
    repo.save_candidate({
        "id": "F-net", "hunt_id": "h1", "rule_id": "net.suricata_alert", "rule_version": "1",
        "claim": "alert", "claim_type": "network_observation", "event_ids": [alert.id], "predicate_fields": [],
        "entities": [["host", "sensor1", "observer"]], "ts": alert.ts, "severity": "high", "confidence": "high",
        "lane": "high", "priority": 50.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
        "next_checks": [], "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    return repo


def run(repo, events, *, host_ip=False):
    executor = PredicateExecutor(repo, events, contracts(host_ip=host_ip))
    ExpansionEngine(repo, "h1", WINDOW, LinkFetcher(executor, WINDOW.start, WINDOW.end), max_depth=1).run()
    return executor, repo.expansion_links("h1")


def _host_name_values(executor):
    return {p.value for intent in executor.sent for p in intent.filters if p.field == "host.name"}


def test_reviewer_scenario_links_the_host_socket_by_endpoint_and_never_queries_an_ip_as_a_host():
    repo = network_anchor_repo()
    socket = ev("web1-socket", "net_socket", host="web1", target="host-x", ts=T0 + timedelta(seconds=2),
                destination__ip="203.0.113.8", destination__port=443, process__pid=4242)
    executor, links = run(repo, [socket])
    assert "10.0.0.2" not in _host_name_values(executor)                       # the B-1 defect
    side = [link for link in links if link["link_type"] == "flow_host_side"]
    assert side and all(link["strength"] == "inferred" for link in side)
    assert any("web1-socket" in link["event_ids"] and link["status"] == "complete" for link in side)
    after = [link for link in links if link["link_type"] == "host_after_anchor"]
    assert after and all(link["status"] == "unsupported" for link in after)    # never a false complete
    assert all(any("victim host unknown for 10.0.0.2" in reason for reason in link["reasons"]) for link in after)


def test_an_endpoint_that_resolves_to_one_host_runs_host_side_links_on_that_host():
    repo = network_anchor_repo()
    marker = ev("web1-ip", "process_exec", host="web1", target="host-x", ts=T0 - timedelta(minutes=30),
                host__ip="10.0.0.2", process__pid=1)
    later = ev("web1-later", "process_exec", host="web1", target="host-x", ts=T0 + timedelta(minutes=1),
               process__pid=77)
    executor, links = run(repo, [marker, later], host_ip=True)
    after = [link for link in links if link["link_type"] == "host_after_anchor"]
    assert after and all(link["key"]["host.name"] == "web1" and link["key"]["victim_ip"] == "10.0.0.2"
                         for link in after)
    assert any("web1-later" in link["event_ids"] for link in after)
    assert _host_name_values(executor) <= {"web1"}


def test_an_ambiguous_endpoint_is_unsupported_with_the_candidates():
    repo = network_anchor_repo()
    events = [ev(f"{h}-ip", "process_exec", host=h, target="host-x", host__ip="10.0.0.2", process__pid=1)
              for h in ("web1", "web2")]
    _executor, links = run(repo, events, host_ip=True)
    after = [link for link in links if link["link_type"] == "host_after_anchor"]
    assert after and all(link["status"] == "unsupported" for link in after)
    assert all(any("victim host ambiguous for 10.0.0.2" in r and "web2" in r for r in link["reasons"])
               for link in after)


def test_lateral_movement_reaches_both_internal_hosts_in_address_order():
    repo = network_anchor_repo(src="10.0.0.10", dst="10.0.0.9", dport=22)
    events = [ev("db1-ip", "process_exec", host="db1", target="host-x", host__ip="10.0.0.9", process__pid=1),
              ev("web1-ip", "process_exec", host="web1", target="host-x", host__ip="10.0.0.10", process__pid=1)]
    _executor, links = run(repo, events, host_ip=True)
    hosts = {(link["key"]["victim_ip"], link["key"]["host.name"]) for link in links
             if link["link_type"] == "host_after_anchor"}
    assert hosts == {("10.0.0.9", "db1"), ("10.0.0.10", "web1")}
    assert ExpansionEngine._victim_ips([TypedEvent(
        id="x", family="net_flow", ts=T0, host="s", fields={"source.ip": fv("10.0.0.10", "a"),
                                                              "destination.ip": fv("10.0.0.9", "b")},
        raw=[RawRef(target="n", native_id="x")], normalizer="t")]) == ["10.0.0.9", "10.0.0.10"]


def test_host_resolution_is_durable_and_spends_its_queries_once():
    repo = network_anchor_repo()
    executor = PredicateExecutor(repo, [ev("web1-ip", "process_exec", host="web1", target="host-x",
                                           host__ip="10.0.0.2", process__pid=1)], contracts(host_ip=True))
    assert executor.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)
    spent = executor.source_queries
    again = PredicateExecutor(repo, [], contracts(host_ip=True))                # a resumed process
    assert again.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)
    assert again.source_queries == 0 and spent == 1
    assert repo.expansion_source_queries("h1") == 1                            # counted in the durable budget


def test_an_incomplete_host_lookup_is_unresolved_not_unknown():
    repo = network_anchor_repo()
    executor = PredicateExecutor(repo, [], contracts(host_ip=True))
    executor._execute = lambda intent, contract, **kw: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.partial,
        reasons=["timed_out"])
    host, reason = executor.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end)
    assert host is None and "unresolved" in reason and "timed_out" in reason


def test_without_a_host_ip_field_no_query_is_spent():
    repo = network_anchor_repo()
    executor = PredicateExecutor(repo, [], contracts(host_ip=False))
    host, reason = executor.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end)
    assert host is None and "no host source has a searchable host.ip" in reason and executor.source_queries == 0


# ---- flow strength by distance, honest forward windows, no context-anchor cascade,
#      partial anchors after an exception
def _fetcher(repo, events=()):
    return LinkFetcher(PredicateExecutor(repo, list(events), contracts()), WINDOW.start, WINDOW.end)


def _flow_anchor():
    alert = ev("alert", "net_alert", host="sensor1", target="network-x", source__ip="10.0.0.2",
               source__port=50000, destination__ip="203.0.113.8", destination__port=443,
               network__transport="tcp", network__community_id="1:abc")
    return LinkAnchor(finding_id="F-net", ts=T0, event_ids=[alert.id], events=[alert])


def test_a_flow_join_is_observed_near_the_anchor_and_inferred_far_from_it():
    repo = network_anchor_repo()
    fetcher = _fetcher(repo)
    near = fetcher.fetch(_flow_anchor(), "network_flow",
                         LinkWindow(label="anchor ±5 min", start=T0 - timedelta(minutes=5), end=T0 + timedelta(minutes=5)))
    far = fetcher.fetch(_flow_anchor(), "network_flow",
                        LinkWindow(label="anchor ±2 h", start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2)))
    assert near.strength == "observed" and far.strength == "inferred"


def test_forward_links_persist_the_window_they_searched():
    repo = network_anchor_repo()
    anchor = LinkAnchor(finding_id="F-host", ts=T0, host="web1",
                        events=[ev("a", "process_exec", host="web1", target="host-x", process__pid=1,
                                   user__name="alice")])
    window = LinkWindow(label="anchor ±30 min", start=T0 - timedelta(minutes=30), end=T0 + timedelta(minutes=30))
    result = _fetcher(repo).fetch(anchor, "host_after_anchor", window)
    assert result.window.start == T0 and result.window.end == window.end


def test_context_findings_are_not_expansion_anchors():
    repo = network_anchor_repo()
    row = repo.candidate("F-net")
    keys = ("hunt_id", "rule_version", "claim", "claim_type", "event_ids", "predicate_fields", "entities", "ts",
            "severity", "confidence", "priority", "priority_reasons", "gate_results", "benign_alternatives",
            "next_checks", "source_case_id", "source_anchor_id", "source_link_id")
    repo.save_candidate({**{k: row[k] for k in keys}, "id": "F-context",
                         "rule_id": "context.post_access_discovery", "lane": "high"})
    ExpansionEngine(repo, "h1", WINDOW, _fetcher(repo), max_source_queries=0).run()
    assert {a["candidate_id"] for a in repo.expansion_anchors("h1")} == {"F-net"}


def test_an_expansion_exception_leaves_partly_expanded_anchors_partial(tmp_path, monkeypatch):
    from romulus.hunt import run as hunt_run
    repo = network_anchor_repo()
    calls = []

    class Boom(ExpansionEngine):
        def _evaluate(self, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return super()._evaluate(*args, **kwargs)

    def run_expansion(s, repo_, client, hunt, contracts_, window, owner_token):
        return Boom(repo_, hunt["id"], WINDOW, _fetcher(repo_)).run()

    monkeypatch.setattr(hunt_run, "_run_expansion", run_expansion)
    summary = hunt_run._run_expansion_safely(None, repo, None, repo.get_hunt("h1"), {}, WINDOW, None)
    assert summary["status"] == "failed"
    anchor = repo.expansion_anchors("h1")[0]
    assert anchor["status"] == "expanded_partial" and anchor["reasons"] == ["expansion error"]


def test_a_host_target_without_ip_fields_leaves_the_ip_link_unresolved_not_silent():
    repo = network_anchor_repo()
    no_ip = {"host-x": contract_from_types("host-x", {"@timestamp": "date", "event.dataset": "keyword",
                                                      "host.name": "keyword"})}
    fetcher = LinkFetcher(PredicateExecutor(repo, [], no_ip), WINDOW.start, WINDOW.end)
    anchor = LinkAnchor(finding_id="F-ip", ts=T0, host="web1",
                        events=[ev("a", "http_access", host="web1", target="host-x", source__ip="203.0.113.8")])
    window = LinkWindow(label="anchor ±5 min", start=T0 - timedelta(minutes=5), end=T0 + timedelta(minutes=5))
    result = fetcher.fetch(anchor, "source_ip", window)
    assert result.status != "complete"
    assert any("IP predicate unavailable" in reason for cell in result.coverage for reason in cell.reasons)


# ---- host resolution belongs to its hunt; transient lookups are retried; endpoints listed

def _second_hunt(repo, hunt_id="h2"):
    repo.create_hunt(hunt_id, {"window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
                               "targets": [], "budgets": {}}, "digest", "test")
    return hunt_id


def test_two_hunts_resolve_the_same_address_independently_and_both_pay_for_it():
    repo = network_anchor_repo()
    marker = [ev("web1-ip", "process_exec", host="web1", target="host-x", host__ip="10.0.0.2", process__pid=1)]
    first = PredicateExecutor(repo, marker, contracts(host_ip=True))
    assert first.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)
    second = PredicateExecutor(repo, marker, contracts(host_ip=True))
    second.hunt_id = _second_hunt(repo)
    assert second.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)
    assert first.source_queries == second.source_queries == 1               # identical hunts spend identically
    assert repo.expansion_source_queries("h1") == repo.expansion_source_queries("h2") == 1


def test_a_crashed_hunts_lookup_never_poisons_another_hunt():
    repo = network_anchor_repo()
    crashed = PredicateExecutor(repo, [], contracts(host_ip=True))
    crashed.owner_token = repo.claim_hunt("h1", 600)["lease_owner"]          # its lease is still live
    crashed._execute = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("killed mid-lookup"))
    try:
        crashed.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end)
    except RuntimeError:
        pass
    other = PredicateExecutor(repo, [ev("web1-ip", "process_exec", host="web1", target="host-x",
                                        host__ip="10.0.0.2", process__pid=1)], contracts(host_ip=True))
    other.hunt_id = _second_hunt(repo)
    other.owner_token = repo.claim_hunt("h2", 600)["lease_owner"]
    assert other.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)


def test_an_incomplete_lookup_is_retried_not_stored_as_final():
    repo = network_anchor_repo()
    flaky = PredicateExecutor(repo, [ev("web1-ip", "process_exec", host="web1", target="host-x",
                                        host__ip="10.0.0.2", process__pid=1)], contracts(host_ip=True))
    real = flaky._execute
    flaky._execute = lambda intent, contract, **kw: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=T0, ended_at=T0, completeness=Completeness.partial,
        reasons=["timed_out"])
    assert flaky.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end)[0] is None
    flaky._execute = real
    assert flaky.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)


def test_endpoints_beyond_the_cap_are_listed_not_dropped_silently():
    from romulus.hunt.expansion import MAX_ANCHOR_KEYS
    repo = network_anchor_repo()
    events = [ev(f"f{i}", "net_flow", host="sensor1", target="network-x", source__ip=f"10.0.0.{i + 1}",
                 destination__ip="203.0.113.8") for i in range(MAX_ANCHOR_KEYS + 2)]
    engine = ExpansionEngine(repo, "h1", WINDOW, _fetcher(repo))
    base = LinkAnchor(finding_id="F-net", ts=T0, events=events)
    variants, dropped, _notes = engine._victim_variants("F-net", [base], events)
    assert len(variants) == MAX_ANCHOR_KEYS and len(dropped) == 2


def test_no_host_lookup_is_spent_once_the_budget_is_used():
    repo = network_anchor_repo()
    executor = PredicateExecutor(repo, [], contracts(host_ip=True))
    ExpansionEngine(repo, "h1", WINDOW, LinkFetcher(executor, WINDOW.start, WINDOW.end), max_source_queries=0).run()
    assert executor.source_queries == 0


def _many_network_roots(count):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
                            "targets": [], "budgets": {}}, "digest", "test")
    for i in range(count):
        alert = ev(f"alert{i}", "net_alert", host="sensor1", target="network-x", ts=T0 + timedelta(minutes=i),
                   source__ip=f"10.0.0.{10 + i}", source__port=50000 + i, destination__ip="203.0.113.8",
                   destination__port=443, network__transport="tcp")
        repo.save_evidence("h1", [alert], {}, None)
        repo.save_candidate({
            "id": f"F-{i:02d}", "hunt_id": "h1", "rule_id": "net.suricata_alert", "rule_version": "1",
            "claim": "alert", "claim_type": "network_observation", "event_ids": [alert.id], "predicate_fields": [],
            "entities": [["host", "sensor1", "observer"]], "ts": alert.ts, "severity": "high", "confidence": "high",
            "lane": "high", "priority": 50.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
            "next_checks": [], "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
        })
    return repo


def test_host_lookups_stop_at_the_root_share_of_the_budget_by_the_live_query_count():
    repo = _many_network_roots(16)
    repo.upsert_task("t-pre", "h1", "expansion_link", "F-00", {}, "fp")
    for _ in range(30):                                      # 30 of 40 queries already spent
        repo.record_task_source_query("t-pre")
    executor = PredicateExecutor(repo, [], contracts(host_ip=True))
    ExpansionEngine(repo, "h1", WINDOW, LinkFetcher(executor, WINDOW.start, WINDOW.end), max_depth=2,
                    max_source_queries=40).run()
    lookups = sum(1 for intent in executor.sent if intent.purpose == "expansion:resolve_host_ip")
    root_cap = 32 + 8 // 2                                   # root budget plus the released half of the reserve
    assert executor.source_queries <= root_cap and lookups <= root_cap - 30


def test_a_resumed_run_reuses_a_durable_lookup_even_past_the_cap():
    repo = network_anchor_repo()
    first = PredicateExecutor(repo, [ev("web1-ip", "process_exec", host="web1", target="host-x",
                                        host__ip="10.0.0.2", process__pid=1)], contracts(host_ip=True))
    assert first.resolve_host_ip("F-net", "10.0.0.2", WINDOW.start, WINDOW.end) == ("web1", None)
    resumed = PredicateExecutor(repo, [], contracts(host_ip=True))
    fetcher = LinkFetcher(resumed, WINDOW.start, WINDOW.end)
    assert fetcher.resolve_host("F-net", "10.0.0.2", query_cap=0) == ("web1", None)
    assert resumed.source_queries == 0


def test_a_lookup_refused_for_budget_is_not_remembered_as_an_answer():
    repo = network_anchor_repo()
    executor = PredicateExecutor(repo, [ev("web1-ip", "process_exec", host="web1", target="host-x",
                                           host__ip="10.0.0.2", process__pid=1)], contracts(host_ip=True))
    fetcher = LinkFetcher(executor, WINDOW.start, WINDOW.end)
    host, reason = fetcher.resolve_host("F-net", "10.0.0.2", query_cap=0)
    assert host is None and reason.endswith("source query budget exhausted") and executor.source_queries == 0
    assert fetcher.resolve_host("F-net", "10.0.0.2", query_cap=5) == ("web1", None)


def test_a_small_budget_releases_none_of_its_reserve():
    # max 8: root budget 6, reserve 2. Releasing half would leave a discovered anchor one query, below the
    # two-query floor of a fetch, so roots stop at 6.
    repo = _many_network_roots(16)
    executor = PredicateExecutor(repo, [], contracts(host_ip=True))
    ExpansionEngine(repo, "h1", WINDOW, LinkFetcher(executor, WINDOW.start, WINDOW.end), max_depth=2,
                    max_source_queries=8).run()
    assert executor.source_queries <= 6


# ---- a site in public space at the default internal-network definition ------------------------------------
# The default reads every public address as outside the site, so a network anchor between a public-space site
# host and the internet has no "internal" endpoint. Host resolution decides instead: an endpoint that resolves to
# one host is a victim, one that no host record carries is not, and one that cannot be resolved says that the
# direction was assumed.

SITE_HOST, OUTSIDER = "198.51.100.20", "203.0.113.9"


def _site_host_marker():
    return ev("web1-ip", "process_exec", host="web1", target="host-x", ts=T0 - timedelta(minutes=30),
              host__ip=SITE_HOST, process__pid=1)


def _looked_up(executor):
    return {p.value for i in executor.sent if i.purpose == "expansion:resolve_host_ip" for p in i.filters
            if p.field == "host.ip"}


def test_default_definition_resolves_public_endpoints_and_pivots_on_the_site_host():
    repo = network_anchor_repo(src=OUTSIDER, dst=SITE_HOST, dport=22)
    later = ev("web1-later", "process_exec", host="web1", target="host-x", ts=T0 + timedelta(minutes=1),
               process__pid=77)
    executor, links = run(repo, [_site_host_marker(), later], host_ip=True)
    after = [link for link in links if link["link_type"] == "host_after_anchor"]
    assert after and all(link["key"]["host.name"] == "web1" and link["key"]["victim_ip"] == SITE_HOST
                         for link in after)
    assert any("web1-later" in link["event_ids"] for link in after)              # the host pivot was made
    assert _looked_up(executor) == {SITE_HOST, OUTSIDER}                      # the outsider resolved to no host
    assert not any(DIRECTION_ASSUMED_REASON in r for a in repo.expansion_anchors("h1") for r in a["reasons"])


def test_default_definition_names_the_assumption_when_resolution_is_unavailable():
    repo = network_anchor_repo(src=OUTSIDER, dst=SITE_HOST, dport=22)
    _executor, links = run(repo, [_site_host_marker()], host_ip=False)
    after = [link for link in links if link["link_type"] == "host_after_anchor"]
    assert after and all(link["status"] == "unsupported" for link in after)
    assert all(any(DIRECTION_ASSUMED_REASON in r and SITE_HOST in r for r in link["reasons"]) for link in after)
    anchor = repo.expansion_anchors("h1")[0]
    assert any(DIRECTION_ASSUMED_REASON in r for r in anchor["reasons"])


def test_default_definition_names_the_assumption_when_the_budget_refuses_a_lookup():
    repo = network_anchor_repo(src=OUTSIDER, dst=SITE_HOST, dport=22)
    executor = PredicateExecutor(repo, [_site_host_marker()], contracts(host_ip=True))
    engine = ExpansionEngine(repo, "h1", WINDOW, LinkFetcher(executor, WINDOW.start, WINDOW.end))
    events = engine._events(repo.candidate("F-net")["event_ids"])
    base = LinkAnchor(finding_id="F-net", ts=T0, events=events)
    variants, dropped, notes = engine._victim_variants("F-net", [base], events, query_cap=0)
    assert executor.source_queries == 0 and dropped == []
    assert [v.host for v in variants] == [None]
    assert DIRECTION_ASSUMED_REASON in variants[0].host_reason and "budget" in variants[0].host_reason
    assert notes and DIRECTION_ASSUMED_REASON in notes[0] and SITE_HOST in notes[0] and OUTSIDER in notes[0]


def test_a_configured_site_never_looks_up_an_address_outside_it():
    netdef.install(netdef.SiteNetworks.from_lists(["198.51.100.0/24"], []))
    repo = network_anchor_repo(src=OUTSIDER, dst=SITE_HOST, dport=22)
    executor, links = run(repo, [_site_host_marker()], host_ip=True)
    assert _looked_up(executor) == {SITE_HOST}
    assert not any(DIRECTION_ASSUMED_REASON in r for link in links for r in link["reasons"])
