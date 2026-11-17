"""The agent's typed search: validation, honest coverage, literal values at the source, admission and bounds.

Every source here is a fake that answers the compiled query the real compiler produced, so what a model value becomes
on the way to Elasticsearch is the code under test. No test reaches a real model or cluster.
"""
from __future__ import annotations

import ipaddress
import json
import re
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.admission import AgentAdmission, collect_issued_aliases, typed_alias_arguments
from romulus.agent.aliases import AliasBook
from romulus.agent.toolbox import TELEMETRY_RESPONSE_BYTES, Toolbox
from romulus.agent.tools import SearchEventsArgs, SearchEventsRequest, tool_catalog
from romulus.config import Settings
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import pivot as pivot_module
from romulus.hunt.agent_tools import HuntToolExecutor
from romulus.hunt.links import LinkFetcher
from romulus.hunt.pivot import MAX_PIVOT_PARTITIONS, PivotExecutor
from romulus.sources.compile import _escape_wildcard, utf16_length
from romulus.sources.es import SourceBudgetExhausted
from romulus.sources.profile import FieldContract, FieldSpec, contract_from_types
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
END = T + timedelta(hours=1)
SESSION = "as-search"


# ---- fixtures ----------------------------------------------------------------------------------------------------

def _dns(target: str, number: int, ts: datetime, name: str = "example.test", port: int = 53) -> dict:
    """One Suricata DNS record as an Elastic shipper stores it, its EVE line beside the fields the shipper parsed:
    it normalizes to one dns_query event, and the fake source matches its stored fields."""
    body = {"timestamp": ts.isoformat(), "event_type": "dns", "src_ip": "10.0.0.8", "dest_ip": "10.0.0.53",
            "dest_port": port, "proto": "UDP", "dns": {"type": "query", "rrname": name, "rrtype": "A"}}
    return {"_id": f"{target}-{number}", "_index": target, "_source": {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"), "host": {"name": "sensor"},
        "event": {"dataset": "suricata.eve.dns", "original": json.dumps(body)},
        "dns": {"question": {"name": name}}, "source": {"ip": "10.0.0.8"},
        "destination": {"ip": "10.0.0.53", "port": port}}}


def _stored_values(source, path: str) -> list:
    """The stored values at a dotted path, through nested objects, dotted keys or a mix, and lists; a keyword subfield
    (`CommandLine.keyword`) indexes its parent's value."""
    found: list = []

    def walk(node, parts: list[str]) -> None:
        if not parts:
            found.extend(node if isinstance(node, list) else [node])
            return
        if isinstance(node, list):
            for item in node:
                walk(item, parts)
            return
        if not isinstance(node, dict):
            return
        for index in range(1, len(parts) + 1):
            key = ".".join(parts[:index])
            if key in node:
                walk(node[key], parts[index:])

    walk(source, path.split("."))
    if not found and "." in path:
        walk(source, path.rsplit(".", 1)[0].split("."))
    return found


def _stamp(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _wildcard_regex(pattern: str) -> re.Pattern:
    """Elasticsearch's wildcard syntax: * and ? are wildcards, a backslash makes the next character literal."""
    out, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            out.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        index += 1
    return re.compile("".join(out), re.DOTALL)


class FakeES:
    """A source that evaluates the compiled query itself, as Elasticsearch would on keyword fields: term, terms,
    prefix and wildcard compare the stored text exactly (case-sensitive unless a wildcard asks otherwise, or the field
    has a lowercase normalizer in `caseless`), an address term compares addresses (a network contains them), a range
    compares times or numbers, and a value longer than its field's ignore_above (`limits`, UTF-16 code units) is not
    indexed. `generated` targets claim a total and make records on demand, for mission-scale volumes."""

    version = "8.19.0"

    class settings:
        es_flavor = "elasticsearch"

    def __init__(self, records: dict[str, list[dict]] | None = None, generated: dict[str, int] | None = None,
                 limits: dict[str, int] | None = None, caseless: set[str] | None = None):
        self.records = records or {}
        self.generated = generated or {}
        self.limits = limits or {}
        self.caseless = caseless or set()
        self.bodies: list[tuple[str, dict]] = []
        self.returned = 0

    @contextmanager
    def point_in_time(self, _target):
        yield object()

    def _indexed(self, source: dict, path: str) -> list:
        values = _stored_values(source, path)
        limit = self.limits.get(path)
        return [value for value in values
                if not (isinstance(value, str) and limit is not None and utf16_length(value) > limit)]

    def _equal(self, stored, wanted, path: str) -> bool:
        if isinstance(stored, (dict, list)) or stored is None:
            return False
        try:
            address = ipaddress.ip_address(str(stored))
            address = getattr(address, "ipv4_mapped", None) or address
            if "/" in str(wanted):
                return address in ipaddress.ip_network(str(wanted), strict=False)
            other = ipaddress.ip_address(str(wanted))
            return address == (getattr(other, "ipv4_mapped", None) or other)
        except ValueError:
            pass
        if isinstance(wanted, (int, float)) and not isinstance(wanted, bool):
            try:
                return float(stored) == float(wanted)
            except (TypeError, ValueError):
                return False
        text = ("true" if stored else "false") if isinstance(stored, bool) else str(stored)
        wanted = ("true" if wanted else "false") if isinstance(wanted, bool) else str(wanted)
        return text.casefold() == wanted.casefold() if path in self.caseless else text == wanted

    def matches(self, clause: dict, source: dict) -> bool:
        (kind, body), = clause.items()
        if kind == "bool":
            required = [*body.get("filter", []), *body.get("must", [])]
            if not all(self.matches(item, source) for item in required):
                return False
            if any(self.matches(item, source) for item in body.get("must_not", [])):
                return False
            should = body.get("should", [])
            need = body.get("minimum_should_match", 0 if required else 1) if should else 0
            return sum(self.matches(item, source) for item in should) >= need
        if kind == "exists":
            return bool(_stored_values(source, body["field"]))
        (path, spec), = body.items()
        values = self._indexed(source, path)
        if kind == "term":
            wanted = spec["value"] if isinstance(spec, dict) else spec
            return any(self._equal(value, wanted, path) for value in values)
        if kind == "terms":
            return any(self._equal(value, wanted, path) for value in values for wanted in spec)
        if kind == "prefix":
            return any(isinstance(value, str) and value.startswith(spec["value"]) for value in values)
        if kind == "wildcard":
            caseless = spec.get("case_insensitive") or path in self.caseless
            flags = re.DOTALL | (re.IGNORECASE if caseless else 0)
            pattern = _wildcard_regex(spec["value"]).pattern
            return any(isinstance(value, str) and re.fullmatch(pattern, value, flags) is not None
                       for value in values)
        if kind == "range":
            for value in values:
                moment = _stamp(value) if isinstance(value, str) else None
                ok = True
                for bound_name, bound in spec.items():
                    if bound_name not in {"gte", "lt"}:
                        continue
                    if moment is not None and _stamp(bound) is not None:
                        left, right = moment, _stamp(bound)
                    else:
                        try:
                            left, right = float(value), float(bound)
                        except (TypeError, ValueError):
                            ok = False
                            break
                    ok = ok and (left >= right if bound_name == "gte" else left < right)
                if ok:
                    return True
            return False
        raise AssertionError(f"the fake source does not evaluate {kind}")

    def iterate(self, q, max_records, page_size=None, pit=None, on_query=None, deadline=None, clock=None):
        if on_query is not None and not on_query():
            raise SourceBudgetExhausted("source query budget exhausted")
        self.bodies.append((q.target, q.body))
        descending = q.body["sort"][0]["@timestamp"]["order"] == "desc"
        if q.target in self.generated:
            bounds = q.body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
            start, end = _stamp(bounds["gte"]), _stamp(bounds["lt"])
            total = self.generated[q.target]
            span = (end - start) / max(1, max_records)
            moments = [start + span * index for index in range(min(total, max_records))]
            if descending:
                moments = [end - span * (index + 1) for index in range(min(total, max_records))]
            hits = [_dns(q.target, int(moment.timestamp() * 1e6), moment) for moment in moments]
        else:
            matching = [record for record in self.records.get(q.target, [])
                        if self.matches(q.body["query"], record["_source"])]
            # ties at one instant are ordered by document, as the source's _shard_doc tiebreak does
            matching.sort(key=lambda record: (record["_source"]["@timestamp"], record["_id"]), reverse=descending)
            total = len(matching)
            hits = matching[:max_records]
        hits = [dict(hit) for hit in hits]
        self.returned += len(hits)
        yield hits, {"problems": [], "total": total, "total_relation": "eq", "surrogate_free": True}


def _keyword_contract(target: str, role: str = "network", **extra: str) -> FieldContract:
    return contract_from_types(target, {
        "@timestamp": "date", "event.dataset": "keyword", "dns.question.name": "keyword",
        "source.ip": "ip", "destination.ip": "ip", "destination.port": "long", "event.duration": "double", **extra,
    }, role=role, os_family="linux" if role == "host" else None)


def _hunt(path=None) -> Repo:
    repo = Repo(make_engine(path or ":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {"window": {"start": T.isoformat(), "end": END.isoformat()},
                            "targets": ["net-a", "net-b"], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    anchor = TypedEvent(id="anchor-ev", family="process_exec", ts=T + timedelta(minutes=30), host="web01",
                        outcome=Outcome.success, fields={"process.argv": fv(["id"], "fixture")},
                        raw=[RawRef(target="host-a", native_id="anchor-ev", digest="d")], normalizer="test@1")
    repo.save_evidence("h1", [anchor], {"host-a/anchor-ev": {"message": "anchor"}}, None)
    repo.save_candidate({
        "id": "anchor", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "A process execution was recorded", "claim_type": "observed_action", "event_ids": [anchor.id],
        "context_event_ids": [], "predicate_fields": [], "entities": [["host", "web01", "host"]],
        "ts": anchor.ts, "severity": "high", "confidence": "high", "lane": "high", "priority": 10.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "anchor", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    repo.save_agent_session({"id": SESSION, "hunt_id": "h1", "hypothesis_id": None, "purpose": "investigate",
                             "state": "running", "tool_calls": 0, "summary": "", "started_at": utcnow(),
                             "ended_at": None})
    return repo


def _toolbox(repo: Repo, contracts: dict, client: FakeES, *, budget: int | None = None,
             packet_sources: tuple[str, ...] = (), inventory: dict | None = None) -> Toolbox:
    pivot = PivotExecutor(repo, client, "h1", contracts, source_query_budget=budget,
                          source_query_scope="agent" if budget is not None else None, dataset_inventory=inventory)
    fetcher = LinkFetcher(pivot, T, END)
    executor = HuntToolExecutor(repo, "h1", pivot, fetcher, T, END, packet_sources=packet_sources)
    return Toolbox(repo, "h1", executor=executor, session_id=SESSION)


def _search(toolbox: Toolbox, conditions, *, scope="network", **extra) -> dict:
    anchor = AliasBook(toolbox.repo, "h1").alias_for("F", "anchor")
    return toolbox.execute("search_events", {"anchor": anchor, "scope": scope, "conditions": conditions, **extra})


DNS = [{"field": "dns.question.name", "op": "eq", "values": ["example.test"]}]
ADDRESS = [{"field": "destination.ip", "op": "eq", "values": ["10.0.0.53"]}]
ABSENT = [{"field": "destination.ip", "op": "eq", "values": ["192.0.2.99"]}]
NOT_CONFIRMED = "no records matched in the sources searched; this is not a confirmed absence"


# ---- schema and validation ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("op", ["contains", "not_in", "missing", "exists"])
def test_each_excluded_op_is_refused_before_any_query(op):
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
                       [{"field": "dns.question.name", "op": op, "values": ["x"]}])
    assert response["status"] == "refused"
    assert response["data"]["error"]["code"] == "invalid_arguments"
    assert "conditions[].op: literal_error" in response["data"]["error"]["reasons"]
    assert client.bodies == []


@pytest.mark.parametrize("conditions, why", [
    ([{"field": "event.duration", "op": "gte", "values": ["5"]}], "at least one eq, in, prefix or cidr"),
    ([{"field": "event.duration", "op": "gte", "values": ["5"]},
      {"field": "event.duration", "op": "lt", "values": ["9"]}], "at least one eq, in, prefix or cidr"),
    ([{"field": "dns.question.name", "op": "in", "values": [f"v{n}" for n in range(21)]}], "at most 20"),
    ([{"field": "dns.question.name", "op": "eq", "values": ["x" * 257]}], "at most 256"),
    ([{"field": "dns.question.name", "op": "eq", "values": ["a", "b"]}], "exactly one value"),
    ([{"field": "dns.question.name", "op": "prefix", "values": ["ab"]}], "at least 3"),
    ([{"field": "destination.ip", "op": "cidr", "values": ["0.0.0.0/0"]}], "/8 or narrower"),
    ([{"field": "destination.ip", "op": "cidr", "values": ["10.0.0.300/8"]}], "one IP network"),
    ([{"field": "dns.question.name", "op": "eq", "values": [443]}], "string"),
    (DNS * 5, "at most 4"),
])
def test_the_selectivity_rule_and_value_limits_are_refused(conditions, why):
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), conditions)
    assert response["status"] == "refused", why
    assert why.split()[-1] in json.dumps(response["data"]["error"]["details"], default=str), why
    assert client.bodies == []


@pytest.mark.parametrize("field, op, value", [
    ("destination.ip", "eq", "10.0.0.999"),
    ("destination.ip", "in", "not an address"),
    ("destination.port", "eq", "443/tcp"),
    ("destination.port", "eq", "4.5"),
    ("event.duration", "gte", "nan"),
    ("@timestamp", "gte", "2024-11-18T14:00:00Z"),
])
def test_a_value_its_field_type_cannot_hold_is_refused_by_name(field, op, value):
    repo, client = _hunt(), FakeES()
    conditions = [*DNS, {"field": field, "op": op, "values": [value]}]
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), conditions)
    assert response["status"] == "refused"
    error = response["data"]["error"]
    assert error["code"] in {"search_unsupported", "invalid_arguments"}
    assert client.bodies == []


def test_a_date_field_takes_only_a_time_with_its_offset():
    contract = _keyword_contract("net-a", **{"event.start": "date"})
    plan = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract}).plan_search(_request([
        *DNS, {"field": "event.start", "op": "gte", "values": ["2024-11-18T14:05:00"]}]))
    assert plan.refusal is not None and "UTC offset" in json.dumps(plan.refusal)
    plan = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract}).plan_search(_request([
        *DNS, {"field": "event.start", "op": "gte", "values": ["2024-11-18T15:05:00+01:00"]}]))
    assert plan.refusal is None
    assert plan.intents[0].filters[1].value == "2024-11-18T14:05:00+00:00"


@pytest.mark.parametrize("window", [
    {"start": (T - timedelta(minutes=1)).isoformat()},
    {"end": (END + timedelta(seconds=1)).isoformat()},
    {"start": (T + timedelta(minutes=5)).isoformat(), "end": (T + timedelta(minutes=5)).isoformat()},
    {"start": "2024-11-18T14:05:00"},
])
def test_the_window_must_lie_inside_the_hunt_window(window):
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS, **window)
    assert response["status"] == "refused"
    assert client.bodies == []


def test_a_field_no_target_supports_is_refused_with_bounded_similar_fields():
    repo, client = _hunt(), FakeES()
    contract = contract_from_types("net-a", {"@timestamp": "date", "event.dataset": "keyword",
                                             **{f"zeek.files.f{n}": "keyword" for n in range(500)},
                                             "file.hash.sha256": "keyword", "file.hash.md5": "keyword",
                                             "process.hash.sha256": "keyword"}, role="network")
    response = _search(_toolbox(repo, {"net-a": contract}, client),
                       [{"field": "hash.sha256", "op": "eq", "values": ["ab" * 32]}])
    assert response["status"] == "refused"
    error = response["data"]["error"]
    assert error["code"] == "search_unsupported"
    assert error["reasons"] == ["conditions[].field: unsupported_field"]
    similar = [item["field"] for item in error["conditions"][0]["similar_fields"]]
    assert similar[:2] == ["file.hash.sha256", "process.hash.sha256"]
    assert len(similar) <= pivot_module.SEARCH_SIMILAR_FIELDS
    assert error["conditions"][0]["searchable_field_count"] == 504
    assert client.bodies == []


def test_an_op_the_field_type_does_not_take_is_refused_naming_the_ops_it_does():
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
                       [{"field": "destination.port", "op": "prefix", "values": ["443"]}])
    error = response["data"]["error"]
    assert response["status"] == "refused" and error["code"] == "search_unsupported"
    assert "takes eq, gte, in, lt" in error["targets"][0]["problem"]


def test_a_scope_with_no_source_is_refused():
    repo, client = _hunt(), FakeES()
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS, scope="host")
    assert response["status"] == "refused"
    assert response["data"]["error"]["code"] == "scope_has_no_source"


# ---- honest coverage ---------------------------------------------------------------------------------------------

def test_an_unsupported_field_on_one_of_two_targets_is_a_partial_naming_the_unevaluated_target():
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=3))]})
    other = contract_from_types("net-b", {"@timestamp": "date", "dns.query.name": "keyword"}, role="network")
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a"), "net-b": other}, client), DNS)
    assert response["status"] == "partial"
    assert [target for target, _body in client.bodies] == ["net-a"]
    reasons = response["data"]["result"]["reasons"]
    assert any(reason.startswith("not evaluated: net-b: field dns.question.name / op eq not supported")
               and "dns.query.name" in reason for reason in reasons)
    cell = next(cell for cell in response["data"]["result"]["coverage"] if cell["target"] == "net-b")
    assert cell["status"] == "partial" and cell["returned"] == 0 and cell["total"] is None
    assert cell["unresolved_ranges"]
    search = response["data"]["result"]["search"]
    assert search["negative"] == "matches_found" and len(response["data"]["result"]["evidence"]) == 1


def test_zero_hits_beside_an_unevaluated_target_is_unresolved():
    repo, client = _hunt(), FakeES()
    other = contract_from_types("net-b", {"@timestamp": "date"}, role="network")
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a"), "net-b": other}, client), DNS)
    assert response["status"] == "partial"
    search = response["data"]["result"]["search"]
    assert search["negative"] == "unresolved"
    assert any("not evaluated: net-b" in why for why in search["gaps_and_caveats"])


@pytest.mark.parametrize("conditions", [
    ABSENT, [{"field": "destination.port", "op": "eq", "values": ["8443"]}],
    [{"field": "source.ip", "op": "cidr", "values": ["192.0.2.0/24"]}],
    [{"field": "dns.question.name", "op": "in", "values": ["absent.test", "missing.test"]}],
    [{"field": "dns.question.name", "op": "prefix", "values": ["absent"]}],
    [{"field": "dns.question.name", "op": "eq", "values": ["example.test"]},
     {"field": "event.duration", "op": "gte", "values": ["99999"]}],
])
@pytest.mark.parametrize("role", ["network", "host"])
def test_zero_hits_is_never_a_confirmed_absence_even_under_complete_coverage(conditions, role):
    targets = ("t-a", "t-b")
    records = [_dns(target, n, T + timedelta(minutes=3 + n)) for n, target in enumerate(targets)]
    repo, client = _hunt(), FakeES({target: [record] for target, record in zip(targets, records, strict=True)})
    contracts = {target: _keyword_contract(target, role=role) for target in targets}
    response = _search(_toolbox(repo, contracts, client, inventory={target: [] for target in targets}),
                       conditions, scope=role)
    search = response["data"]["result"]["search"]
    assert response["status"] == "complete"
    assert all(cell["status"] == "complete" for cell in response["data"]["result"]["coverage"])
    assert search["negative"] == "unresolved" and search["statement"] == NOT_CONFIRMED
    assert "exhaustive" not in search and "no_match" not in json.dumps(response)



def test_packet_captures_are_named_as_not_searched_and_keep_a_zero_unresolved():
    repo, client = _hunt(), FakeES({"net-a": []})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client,
                       packet_sources=("packet captures behind arkime-sessions (Arkime viewer and TShark)",))
    response = _search(toolbox, ABSENT)
    search = response["data"]["result"]["search"]
    assert search["negative"] == "unresolved"
    # the source not searched makes the tool result and its coverage partial, with a gap that names it
    assert response["status"] == "partial" and response["coverage"]["status"] == "partial"
    assert any(gap["target"] == "packet captures behind arkime-sessions (Arkime viewer and TShark)"
               for gap in response["coverage"]["gaps"])
    assert search["not_searched"] == [(
        "packet captures behind arkime-sessions (Arkime viewer and TShark): not searched (scope unsupported for "
        "agent search)")]


def test_records_no_normalizer_reads_are_named_not_dropped():
    repo = _hunt()
    odd = {"_id": "odd", "_index": "net-a", "_source": {"@timestamp": (T + timedelta(minutes=2)).isoformat(),
                                                         "event": {"dataset": "custom.thing"},
                                                         "dns": {"question": {"name": "example.test"}}}}
    client = FakeES({"net-a": [odd]})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "partial"
    assert any(reason.startswith("records_not_normalized:1:dataset:custom.thing")
               for reason in response["data"]["result"]["reasons"])
    assert response["data"]["result"]["search"]["negative"] == "unresolved"


def test_a_spent_query_budget_is_a_failed_unresolved_search_without_tasks():
    repo, client = _hunt(), FakeES({"net-a": []})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, budget=0), DNS)
    # nothing was searched: failed, with the cap's reason, and never zero hits
    assert response["status"] == "failed"
    assert response["data"]["result"]["search"]["negative"] == "unresolved"
    assert "agent_source_query_budget:0" in response["data"]["result"]["reasons"]
    assert client.bodies == []
    assert repo.tasks("h1") == []


def test_cap_plus_one_spread_over_the_window_is_resolved_by_partitioning(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 10)
    records = [_dns("net-a", n, T + timedelta(minutes=5 * n)) for n in range(11)]
    repo, client = _hunt(), FakeES({"net-a": records})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "complete"
    assert response["counts"]["total"] == 11
    assert response["data"]["result"]["search"]["negative"] == "matches_found"


def test_records_past_the_cap_at_one_instant_are_an_honest_partial(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 10)
    moment = T + timedelta(minutes=7)
    records = [_dns("net-a", n, moment) for n in range(31)]
    repo, client = _hunt(), FakeES({"net-a": records})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "partial"
    reasons = response["data"]["result"]["reasons"]
    assert "cap:10<total:31" in reasons and "pivot_head_tail_sample" in reasons
    assert any(reason.startswith(("pivot_min_split:", "pivot_partition_limit:")) for reason in reasons)
    assert response["counts"]["total"] == 20                    # head and tail, every one shown, none invented
    partial = [cell for cell in response["data"]["result"]["coverage"] if cell["status"] == "partial"]
    assert partial and all(cell["unresolved_ranges"] for cell in partial)
    assert response["data"]["result"]["search"]["negative"] == "matches_found"


def test_the_partition_limit_is_named_and_zero_unresolved_is_never_claimed(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 5)
    repo, client = _hunt(), FakeES(generated={"net-a": 1_000_000})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "partial"
    assert f"pivot_partition_limit:{pivot_module.SEARCH_PARTITIONS}" in response["data"]["result"]["reasons"]
    search = response["data"]["result"]["search"]
    assert search["negative"] == "matches_found" and search["statement"] is None
    assert any("pivot_partition_limit" in why for why in search["gaps_and_caveats"])
    cells = response["data"]["result"]["coverage"]
    assert any(cell["unresolved_ranges"] for cell in cells)


# ---- literal values at the source --------------------------------------------------------------------------------

ADVERSARIAL = [
    'a"b', "a\\b", "a*b", "a?b", "a && b", "a || b", "(a)", "a)", "a\nb", "a\x00b", "x" * 256,
    "pаypal",                      # Cyrillic a
    "ｆｕｌｌ",         # fullwidth letters: never NFKC-folded to "full"
    "* OR 1:1", "field:value", "\\*", "{\"query_string\": 1}",
]


def _leaves(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _leaves(value, (*path, key))
    elif isinstance(node, list):
        for value in node:
            yield from _leaves(value, (*path, "[]"))
    else:
        yield path, node


def _clause_kinds(node) -> set[str]:
    return {part for path, _value in _leaves(node) for part in path}


def _assert_literal(body: dict, value: str):
    """The value is a JSON value in the body, and no clause that parses query syntax is anywhere in it."""
    assert {"query_string", "simple_query_string", "regexp", "script", "match"}.isdisjoint(_clause_kinds(body))
    assert json.loads(json.dumps(body)) == body
    assert any(leaf == value for _path, leaf in _leaves(body)), value


def test_adversarial_values_reach_the_source_only_as_literal_term_terms_and_prefix_values():
    contract = _keyword_contract("net-a")
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract})
    for value in ADVERSARIAL:
        for op in ("eq", "prefix"):
            if op == "prefix" and len(value) < 3:
                continue
            plan = executor.plan_search(_request([{"field": "dns.question.name", "op": op, "values": [value]}]))
            assert plan.refusal is None, value
            body = pivot_module.compile_es(plan.intents[0], contract).body
            clause = body["query"]["bool"]["filter"][1]
            assert clause == ({"term": {"dns.question.name": value}} if op == "eq"
                              else {"prefix": {"dns.question.name": {"value": value}}})
            _assert_literal(body, value)
    plan = executor.plan_search(_request([{"field": "dns.question.name", "op": "in", "values": ADVERSARIAL}]))
    clause = pivot_module.compile_es(plan.intents[0], contract).body["query"]["bool"]["filter"][1]
    assert clause == {"terms": {"dns.question.name": sorted(set(ADVERSARIAL))}}


def test_adversarial_values_on_case_insensitive_windows_paths_are_escaped_wildcards_only():
    spec = {"type": "keyword", "ops": ["eq", "in", "prefix", "exists", "missing"], "aggregatable": True}
    contract = FieldContract(target="win-a", os_family="windows", role="host", fields={
        "@timestamp": FieldSpec(native="@timestamp", type="date", ops=["gte", "lt"], aggregatable=True),
        "host.name": FieldSpec(native="winlog.computer_name", natives=("winlog.computer_name",), **spec),
        "event.channel": FieldSpec(native="winlog.channel", natives=("winlog.channel",), **spec),
        "process.command_line": FieldSpec(native="process.command_line", natives=("process.command_line",),
                                          type="text", ops=["eq", "in", "exists", "missing"], aggregatable=False,
                                          exact=("process.command_line.keyword",), exact_limit=64),
    })
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"win-a": contract})
    for value in ADVERSARIAL:
        conditions = [{"field": "host.name", "op": "eq", "values": [value]},
                      {"field": "event.channel", "op": "eq", "values": [value]}]
        plan = executor.plan_search(_request(conditions, scope="host"))
        assert plan.refusal is None, value
        body = pivot_module.compile_es(plan.intents[0], contract).body
        assert {"query_string", "regexp", "script", "match", "match_phrase",
                "simple_query_string"}.isdisjoint(_clause_kinds(body))
        wildcards = [leaf for path, leaf in _leaves(body) if "wildcard" in path and path[-1] == "value"]
        short = _escape_wildcard(value.strip().rstrip(".").split(".", 1)[0])
        assert wildcards and set(wildcards) <= {_escape_wildcard(value), short, f"{short}.*"}
        for pattern in wildcards:
            # every * and ? the value held is escaped: only the compiler's own trailing ".*" is a wildcard
            unescaped = pattern.replace("\\\\", "").replace("\\*", "").replace("\\?", "")
            assert "?" not in unescaped and unescaped.count("*") <= (1 if pattern.endswith(".*") else 0)
        # text equality reads the keyword subfield as a term; a value past what it keeps is never sent as a phrase
        plan = executor.plan_search(_request(
            [{"field": "process.command_line", "op": "eq", "values": [value]}], scope="host"))
        if len(value) > 64:
            assert plan.intents == [] and "cannot be matched exactly" in json.dumps(plan.refusal), value
        else:
            body = pivot_module.compile_es(plan.intents[0], contract).body
            assert body["query"]["bool"]["filter"][1] == {"term": {"process.command_line.keyword": value}}


def test_an_account_value_without_its_kind_prefix_is_not_evaluated_and_never_reaches_the_source():
    contract = FieldContract(target="win-a", os_family="windows", role="host", fields={
        "@timestamp": FieldSpec(native="@timestamp", type="date", ops=["gte", "lt"], aggregatable=True),
        "user.entity_id": FieldSpec(native="winlog.event_data.TargetUserName",
                                    natives=("winlog.event_data.TargetUserName",), type="keyword",
                                    ops=["eq", "in"], aggregatable=True),
    })
    repo, client = _hunt(), FakeES({"win-a": []})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "user.entity_id", "op": "eq", "values": ['ad"min*']}], scope="host")
    assert response["status"] == "refused"
    assert "cannot be compiled exactly" in response["data"]["error"]["targets"][0]["problem"]
    assert client.bodies == []
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "user.entity_id", "op": "eq", "values": ['name:CORP\\ad"min*']}], scope="host")
    assert response["status"] == "complete"
    (_target, body), = client.bodies
    assert body["query"]["bool"]["filter"][1] == {"wildcard": {"winlog.event_data.TargetUserName": {
        "value": 'ad"min\\*', "case_insensitive": True}}}


def test_a_compiled_clause_outside_the_allow_list_is_never_sent(monkeypatch):
    real = pivot_module.compile_es

    def hostile(intent, contract, flavor="elasticsearch"):
        compiled = real(intent, contract, flavor)
        compiled.body["query"]["bool"]["filter"].append({"query_string": {"query": "*"}})
        return compiled

    monkeypatch.setattr(pivot_module, "compile_es", hostile)
    repo, client = _hunt(), FakeES({"net-a": []})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "refused"
    assert "query_string clause" in response["data"]["error"]["targets"][0]["problem"]
    assert client.bodies == []


def test_values_reach_the_wire_body_unchanged_through_the_real_executor():
    repo = _hunt()
    client = FakeES({"net-a": []})
    _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
            [{"field": "dns.question.name", "op": "in", "values": ADVERSARIAL}])
    (_target, body), = client.bodies
    assert body["query"]["bool"]["filter"][1] == {"terms": {"dns.question.name": sorted(set(ADVERSARIAL))}}
    assert "ｆｕｌｌ" in body["query"]["bool"]["filter"][1]["terms"]["dns.question.name"]
    assert "full" not in body["query"]["bool"]["filter"][1]["terms"]["dns.question.name"]


# ---- admission, budgets and dedupe -------------------------------------------------------------------------------

def test_a_finding_citing_search_evidence_is_admitted(tmp_path):
    repo = _hunt(tmp_path / "admit.sqlite")
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=4), "beacon.example")]})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client)
    admission = AgentAdmission(Settings(home=tmp_path), repo, "h1", SESSION)
    admission.register(toolbox)
    anchor = AliasBook(repo, "h1").alias_for("F", "anchor")
    admission.issue_aliases({"finding": anchor})
    arguments = {"anchor": anchor, "scope": "network",
                 "conditions": [{"field": "dns.question.name", "op": "eq", "values": ["beacon.example"]}]}
    assert typed_alias_arguments("search_events", arguments) == {anchor}
    response = toolbox.execute("search_events", arguments)
    assert response["status"] == "complete"
    evidence = response["data"]["result"]["evidence"]
    assert len(evidence) == 1
    assert collect_issued_aliases(response, tool_name="search_events") >= set(evidence)
    admission.issue_aliases(response, tool_name="search_events")
    proposed = toolbox.execute("propose_finding", {
        "claim": "A host resolved a beacon domain found by search", "claim_kind": "network",
        "cites": evidence, "lane": "lead"})
    assert proposed["status"] == "complete", proposed
    links = [row for row in repo.expansion_links("h1") if row["link_type"] == "agent_search_events"]
    assert len(links) == 1 and links[0]["anchor_id"] == "anchor"
    assert links[0]["key"]["search"]["conditions"][0]["values"] == ["beacon.example"]
    assert links[0]["strength"] == "agent_hypothesis"


def test_a_repeated_search_is_deduplicated_and_spends_no_source_query():
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=4))]})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, budget=10)
    in_order = [{"field": "dns.question.name", "op": "in", "values": ["b.test", "example.test"]},
                {"field": "destination.port", "op": "eq", "values": ["53"]}]
    reordered = [{"field": "destination.port", "op": "eq", "values": ["53"]},
                 {"field": "dns.question.name", "op": "in", "values": ["example.test", "b.test", "b.test"]}]
    first = _search(toolbox, in_order)
    spent = repo.agent_source_queries("h1")
    again = _search(toolbox, reordered)
    assert spent >= 1 and repo.agent_source_queries("h1") == spent
    assert len(client.bodies) == 1
    assert first["data"]["result"]["cursor"] == again["data"]["result"]["cursor"]
    assert again["data"]["result"]["search"]["repeated"] is True
    assert first["data"]["result"]["search"]["repeated"] is False
    assert again["data"]["result"]["evidence"] == first["data"]["result"]["evidence"]


def test_each_search_spends_the_hunt_source_query_budget():
    repo = _hunt()
    client = FakeES({"net-a": []})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, budget=1)
    first = _search(toolbox, ABSENT)
    second = _search(toolbox, [{"field": "destination.ip", "op": "eq", "values": ["192.0.2.98"]}])
    assert first["status"] == "complete" and first["data"]["result"]["search"]["negative"] == "unresolved"
    # nothing was left to search: failed, never a confirmed absence
    assert second["status"] == "failed"
    assert second["data"]["result"]["search"]["negative"] == "unresolved"
    assert repo.agent_source_queries("h1") == 1


# ---- tool surface ------------------------------------------------------------------------------------------------

def test_search_events_is_a_loose_tool_and_the_strict_grammar_budget_holds(tmp_path):
    from romulus.agent.provider.claude_messages import (
        GRAMMAR_BUDGET,
        strict_schema_problems,
        strict_wire_schema,
    )

    repo = _hunt()
    toolbox = Toolbox(repo, "h1")
    AgentAdmission(Settings(home=tmp_path), repo, "h1", SESSION).register(toolbox)
    tools = {tool.name: tool for tool in toolbox.provider_tools()}
    assert "search_events" in tools and not tools["search_events"].strict
    strict = [tool for tool in tools.values() if tool.strict]
    assert len(strict) <= GRAMMAR_BUDGET["tools"]
    counts: dict = {}
    for tool in strict:
        assert strict_schema_problems(strict_wire_schema(tool.parameters), counts) == []
    for key in ("optional", "union", "properties", "enum"):
        assert counts[key] <= GRAMMAR_BUDGET[key], key
    # the loose schema is still a closed object the strict form of every adapter can carry
    wire = strict_wire_schema(tools["search_events"].parameters)
    assert wire["additionalProperties"] is False
    assert set(wire["properties"]) == {"anchor", "scope", "conditions", "start", "end", "page", "cursor",
                                       "chunk_index"}
    condition = tools["search_events"].parameters["$defs"]["SearchCondition"]
    assert condition["properties"]["op"]["enum"] == ["eq", "in", "prefix", "cidr", "gte", "lt"]
    assert "target" not in json.dumps(tools["search_events"].parameters["properties"])


def test_the_prompt_and_catalog_name_the_tool():
    from importlib import resources

    prompt = resources.files("romulus.agent.prompts").joinpath("investigate.md").read_text(encoding="utf-8")
    assert "search_events" in prompt and "never evidence of absence" in prompt and "no_match" not in prompt
    assert "search_events" in tool_catalog()
    assert "contains" not in tool_catalog()["search_events"]["arguments"]


# ---- bounds at mission scale -------------------------------------------------------------------------------------

def test_a_search_over_many_dense_targets_stays_bounded_and_names_what_it_did_not_evaluate(monkeypatch):
    monkeypatch.setattr(pivot_module, "SEARCH_LEAF_RECORDS", 20)
    monkeypatch.setattr(pivot_module, "MAX_SEARCH_RECORDS", 400)
    targets = [f"net-{n:02d}" for n in range(12)]
    repo = _hunt()
    # every target claims fifty million matching records in the window
    client = FakeES(generated={target: 50_000_000 for target in targets})
    toolbox = _toolbox(repo, {target: _keyword_contract(target) for target in targets}, client)
    response = _search(toolbox, DNS)

    partitions = pivot_module.SEARCH_PARTITIONS
    per_target = partitions * pivot_module.MAX_SAMPLE_QUERIES * 20
    assert response["status"] == "partial"
    # each query held at most the leaf cap, and one target took at most its splits, leaves and samples
    queries = {}
    for target, _body in client.bodies:
        queries[target] = queries.get(target, 0) + 1
    assert max(queries.values()) <= 2 * partitions - 1 + partitions * pivot_module.MAX_SAMPLE_QUERIES
    assert client.returned <= 20 * len(client.bodies)
    reasons = response["data"]["result"]["reasons"]
    searched = {target for target, _body in client.bodies}
    unevaluated = {target for target in targets if f"search_record_limit:400: not evaluated: {target}" in reasons}
    assert searched and unevaluated and searched | unevaluated == set(targets) and not searched & unevaluated
    assert len(response["data"]["result"]["evidence"]) <= 50
    assert len(response["data"]["result"]["event_summaries"]) <= 50
    assert len(json.dumps(response["data"]["result"]["event_summaries"]).encode()) <= TELEMETRY_RESPONSE_BYTES * 2
    assert response["more"] is True
    assert response["counts"]["total"] <= 400 + per_target
    links = [row for row in repo.expansion_links("h1") if row["link_type"] == "agent_search_events"]
    assert len(links[0]["event_ids"]) <= 400 + per_target


def test_the_search_bounds_hold_for_the_real_constants():
    from romulus.agent.dossier import MATERIALIZE_LINK_BYTES_LIMIT
    from romulus.store.repo import AGENT_PAGE_ITEM_LIMIT

    assert pivot_module.SEARCH_PARTITIONS < MAX_PIVOT_PARTITIONS
    assert pivot_module.MAX_SEARCH_TARGET_RECORDS == (
        pivot_module.SEARCH_PARTITIONS * pivot_module.MAX_SAMPLE_QUERIES * pivot_module.SEARCH_LEAF_RECORDS)
    kept = pivot_module.MAX_SEARCH_RECORDS + pivot_module.MAX_SEARCH_TARGET_RECORDS
    # ten worst-case searches fit the hunt's agent page items, and one search's reach link (event ids of about
    # 26 bytes, twice: its records and its evidence) stays a small share of the incident graph's payload ceiling
    assert 10 * kept < AGENT_PAGE_ITEM_LIMIT
    assert 2 * 26 * kept < MATERIALIZE_LINK_BYTES_LIMIT // 10


def _request(conditions, *, scope="network") -> SearchEventsRequest:
    return SearchEventsRequest(tool="search_events", arguments=SearchEventsArgs.model_validate({
        "scope": scope, "conditions": conditions, "start": T, "end": END}))


def test_a_tool_without_a_reach_link_type_is_refused_before_any_source_query():
    class Unlisted:
        tool = "unlisted_tool"

    class NoPivot:
        def run(self, *_args, **_kwargs):
            raise AssertionError("an unlisted tool reached the source")

    executor = HuntToolExecutor(_hunt(), "h1", NoPivot(), None, T, END)
    result = executor.run(SESSION, "anchor", Unlisted(), anchor_ts=T)
    assert result.status == "unsupported"
    assert result.reasons == ["tool unlisted_tool has no agent reach link type"]


def test_a_target_without_a_contract_is_named_and_keeps_a_zero_unresolved():
    repo, client = _hunt(), FakeES({"net-a": []})
    pivot = PivotExecutor(repo, client, "h1", {"net-a": _keyword_contract("net-a"), "net-b": None})
    executor = HuntToolExecutor(repo, "h1", pivot, LinkFetcher(pivot, T, END), T, END,
                                uncontracted_targets=("net-c",))
    response = _search(Toolbox(repo, "h1", executor=executor, session_id=SESSION), DNS)
    assert response["status"] == "partial"
    search = response["data"]["result"]["search"]
    assert search["negative"] == "unresolved" and search["statement"] == NOT_CONFIRMED
    assert "net-c: not searched (no field contract for this target)" in search["not_searched"]
    assert any(reason == "not evaluated: net-b: no field contract for this target"
               for reason in response["data"]["result"]["reasons"])


def test_a_failed_search_is_retried_and_its_successful_retry_is_then_deduplicated():
    from romulus.sources.es import SourceError

    class FlakyES(FakeES):
        failures = 1

        def iterate(self, q, max_records, **kwargs):
            if self.failures:
                self.failures -= 1
                self.bodies.append((q.target, q.body))
                raise SourceError("connection reset")
            yield from super().iterate(q, max_records, **kwargs)

    repo, client = _hunt(), FlakyES({"net-a": []})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client)
    first, second, third = (_search(toolbox, DNS) for _ in range(3))
    assert first["status"] == "failed"
    assert second["status"] == "complete" and second["data"]["result"]["search"]["repeated"] is False
    assert third["data"]["result"]["search"]["repeated"] is True
    assert third["data"]["result"]["cursor"] == second["data"]["result"]["cursor"]
    assert len(client.bodies) == 2


# ---- negatives need verbatim fields ------------------------------------------------------------------------------

def _windows_contract_and_record():
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

    event = LogicalWindowsEvent(
        "Security", "Microsoft-Windows-Security-Auditing", 4624, "WS01.corp.example", 77, "2024-11-18T14:10:00Z",
        {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS01$", "TargetUserSid": "S-1-5-21-1-2-3-500",
         "TargetUserName": "Administrator", "TargetDomainName": "CORP", "LogonType": "3",
         "IpAddress": "198.51.100.9", "IpPort": "51515", "LogonId": "0x1"})
    hit = windows_hit(event, "winlogbeat_8")
    hit.update(_index="win-a", _id="win-77")

    def flat(node, prefix=""):
        out = {}
        for key, value in node.items():
            out.update(flat(value, f"{prefix}{key}.") if isinstance(value, dict)
                       else {prefix + key: "date" if key == "@timestamp" else "keyword"})
        return out

    contract = contract_from_types("win-a", flat(hit["_source"]), role="host", os_family="windows",
                                   datasets=["windows.security"], index_limits={})
    return contract, hit


@pytest.mark.parametrize("conditions, expect", [
    # values copied from the typed event: the canonical sid form, the short host name, the case-folded user name
    ([{"field": "auth.target_account", "op": "in", "values": ["sid:s-1-5-21-1-2-3-500"]}], "matches_found"),
    ([{"field": "auth.target_account", "op": "eq", "values": ["sid:s-1-5-21-1-2-3-500"]}], "matches_found"),
    ([{"field": "host.name", "op": "in", "values": ["ws01", "ws02"]}], "matches_found"),
    ([{"field": "host.name", "op": "eq", "values": ["ws01"]}], "matches_found"),
    ([{"field": "user.name", "op": "eq", "values": ["ws01$"]}], "unresolved"),
    ([{"field": "user.name", "op": "in", "values": ["ws01$"]}], "unresolved"),
    ([{"field": "user.name", "op": "prefix", "values": ["ws0"]}], "unresolved"),
    ([{"field": "source.ip", "op": "eq", "values": ["198.51.100.10"]}], "unresolved"),
])
def test_a_value_copied_from_a_typed_event_is_a_hit_or_unresolved(conditions, expect):
    contract, hit = _windows_contract_and_record()
    repo, client = _hunt(), FakeES({"win-a": [hit]})
    response = _search(_toolbox(repo, {"win-a": contract}, client), conditions, scope="host")
    search = response["data"]["result"]["search"]
    assert search["negative"] == expect, response["data"]["result"]
    assert search["statement"] == (NOT_CONFIRMED if expect == "unresolved" else None)


def test_an_in_on_a_special_field_is_sent_as_each_value_s_equality_form():
    contract, _hit = _windows_contract_and_record()
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"win-a": contract})
    plan = executor.plan_search(_request([{"field": "auth.target_account", "op": "in",
                                           "values": ["sid:s-1-5-21-1-2-3-500", "name:corp\\bob"]}], scope="host"))
    body = json.dumps(pivot_module.compile_es(plan.intents[0], contract).body)
    assert '"terms"' not in body and "sid:" not in body and "name:" not in body
    assert '"value": "s-1-5-21-1-2-3-500", "case_insensitive": true' in body
    assert '"value": "bob", "case_insensitive": true' in body


@pytest.mark.parametrize("field_name", ["user.entity_id", "auth.target_account", "host.name", "event.channel"])
def test_a_prefix_on_a_canonical_or_case_folded_field_is_refused_saying_why(field_name):
    contract, hit = _windows_contract_and_record()
    repo, client = _hunt(), FakeES({"win-a": [hit]})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": field_name, "op": "prefix", "values": ["abc"]}], scope="host")
    assert response["status"] == "refused"
    problem = response["data"]["error"]["targets"][0]["problem"]
    assert f"field {field_name} / op prefix refused: its typed value is" in problem
    assert client.bodies == []


def test_a_hash_typed_in_another_case_than_stored_is_unresolved():
    contract = _keyword_contract("net-a", **{"file.hash.sha256": "keyword"})
    record = _dns("net-a", 1, T + timedelta(minutes=2))
    record["_source"]["file"] = {"hash": {"sha256": "AB" * 32}}
    repo, client = _hunt(), FakeES({"net-a": [record]})
    response = _search(_toolbox(repo, {"net-a": contract}, client),
                       [{"field": "file.hash.sha256", "op": "eq", "values": ["ab" * 32]}])
    search = response["data"]["result"]["search"]
    assert response["status"] == "complete" and search["negative"] == "unresolved"
    assert search["statement"] == NOT_CONFIRMED


def test_a_source_match_on_a_plain_field_is_trusted_never_re_checked():
    # a lowercase normalizer on the stored field: the source matched another case, and that match is kept
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=2))]}, caseless={"dns.question.name"})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client),
                       [{"field": "dns.question.name", "op": "eq", "values": ["EXAMPLE.test"]}])
    search = response["data"]["result"]["search"]
    assert search["discarded"] == 0 and search["negative"] == "matches_found"
    assert len(response["data"]["result"]["evidence"]) == 1



def test_a_text_parsed_host_dataset_keeps_an_address_search_unresolved():
    contract = _keyword_contract("host-a", role="host", message="match_only_text")
    for inventory, dataset in (({"host-a": ["linux.syslog", "linux.audit"]}, "linux.syslog"), (None, None)):
        repo, client = _hunt(), FakeES({"host-a": []})
        response = _search(_toolbox(repo, {"host-a": contract}, client, inventory=inventory),
                           [{"field": "source.ip", "op": "eq", "values": ["198.51.100.9"]}], scope="host")
        assert response["status"] == "partial"
        assert response["data"]["result"]["search"]["negative"] == "unresolved"
        reasons = response["data"]["result"]["reasons"]
        assert any(reason.startswith(f"dataset_text_parsed:{dataset or 'inventory unknown'}") for reason in reasons)


# ---- index length limits -----------------------------------------------------------------------------------------

LIMITED_MAPPING = {
    "idx-1": {"mappings": {"properties": {
        "@timestamp": {"type": "date"}, "cmd": {"type": "keyword", "ignore_above": 64},
        "free": {"type": "keyword"},
        "proc": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
    }}},
    "idx-2": {"mappings": {"properties": {"cmd": {"type": "keyword", "ignore_above": 128}}}},
}


def _limited_contract() -> FieldContract:
    from romulus.sources.profile import flatten_mapping, keyword_index_limits

    limits = keyword_index_limits(LIMITED_MAPPING)
    assert limits == {"cmd": 64, "free": None, "proc.keyword": 256}         # the smallest across indices
    return contract_from_types("net-a", flatten_mapping(LIMITED_MAPPING), role="network", index_limits=limits)


def test_a_prefix_on_a_limited_keyword_misses_long_values_and_is_unresolved():
    long_line = "powershell.exe -enc " + "A" * 100
    record = _dns("net-a", 1, T + timedelta(minutes=2))
    record["_source"].update(cmd=long_line, free=long_line)
    repo, client = _hunt(), FakeES({"net-a": [record]}, limits={"cmd": 64})
    toolbox = _toolbox(repo, {"net-a": _limited_contract()}, client)
    response = _search(toolbox, [{"field": "cmd", "op": "prefix", "values": ["powershell.exe -enc"]}])
    search = response["data"]["result"]["search"]
    assert search["negative"] == "unresolved"
    assert ("cmd: values longer than 64 characters are not indexed in cmd, so a prefix cannot see them"
            in search["gaps_and_caveats"])
    # a keyword with no limit names none; the long value is found
    response = _search(toolbox, [{"field": "free", "op": "prefix", "values": ["powershell.exe -enc"]}])
    search = response["data"]["result"]["search"]
    assert search["negative"] == "matches_found"
    assert not any("not indexed" in why for why in search["gaps_and_caveats"])


def test_an_equality_value_past_the_limit_in_utf16_units_is_not_evaluated():
    contract = _limited_contract()
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract})
    astral = "\U0001f600" * 33                      # 33 characters, 66 UTF-16 code units: past 64
    for value in ("x" * 65, astral):
        plan = executor.plan_search(_request([{"field": "cmd", "op": "eq", "values": [value]}]))
        assert plan.intents == []
        assert "a value longer than 64 characters is not indexed by cmd" in json.dumps(plan.refusal)
    plan = executor.plan_search(_request([{"field": "cmd", "op": "eq", "values": ["\U0001f600" * 32]}]))
    assert plan.refusal is None


def test_an_unknown_limit_keeps_an_equality_zero_unresolved():
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": _keyword_contract("net-a")})
    plan = executor.plan_search(_request(DNS))
    assert ("dns.question.name: the index length limit of dns.question.name is unknown; a longer stored value is "
            "not indexed") in plan.caveats


def test_the_reviewer_text_and_keyword_probe_shapes():
    from romulus.sources.profile import flatten_mapping, keyword_index_limits, keyword_subfield_limits

    mapping = {"idx": {"mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "Channel": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
        "EventID": {"type": "long"},
        "Hostname": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
        "CommandLine": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
        "Image": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
    }}}}
    contract = contract_from_types("win-a", flatten_mapping(mapping), role="host", os_family="windows",
                                   keyword_limits=keyword_subfield_limits(mapping),
                                   index_limits=keyword_index_limits(mapping))
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"win-a": contract})
    plan = executor.plan_search(_request([{"field": "CommandLine.keyword", "op": "prefix",
                                           "values": ["powershell.exe -enc"]}], scope="host"))
    assert any("values longer than 256 characters are not indexed in CommandLine.keyword" in caveat
               for caveat in plan.caveats)
    plan = executor.plan_search(_request([{"field": "process.command_line", "op": "prefix",
                                           "values": ["powershell.exe -enc"]}], scope="host"))
    assert plan.intents == [] and plan.refusal["code"] == "search_unsupported"


# ---- page items, failures and what was not searched --------------------------------------------------------------

def test_a_search_is_refused_before_any_query_when_the_session_has_no_page_item_headroom(monkeypatch):
    repo, client = _hunt(), FakeES({"net-a": []})
    monkeypatch.setattr(Repo, "agent_page_headroom", lambda self, hunt_id, identity: (5, 100))
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    assert response["status"] == "refused" and response["data"]["error"]["code"] == "page_quota"
    assert response["data"]["error"]["reasons"] == ["$: page_quota"]
    assert client.bodies == []


def test_a_search_failing_every_try_is_stored_and_stops_spending():
    from romulus.sources.es import SourceError

    class DownES(FakeES):
        def iterate(self, q, max_records, **kwargs):
            self.bodies.append((q.target, q.body))
            raise SourceError("connection refused")
            yield

    repo, client = _hunt(), DownES()
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client)
    responses = [_search(toolbox, DNS) for _ in range(6)]
    assert all(response["status"] == "failed" for response in responses)
    assert len(client.bodies) == 4                       # one per derived try, then the stored failure
    assert responses[-1]["data"]["result"]["search"]["repeated"] is True


def test_an_executor_that_raises_leaves_a_stored_failed_result():
    class Raising:
        runs = 0

        def run(self, *_args, **_kwargs):
            Raising.runs += 1
            raise RuntimeError("boom")

        def follow_link(self, *_args, **_kwargs):
            raise AssertionError

    repo = _hunt()
    toolbox = Toolbox(repo, "h1", executor=Raising(), session_id=SESSION)
    responses = [_search(toolbox, DNS) for _ in range(5)]
    assert responses[0]["status"] == "failed"
    assert "search failed: RuntimeError: boom" in responses[0]["data"]["result"]["reasons"]
    assert Raising.runs == 4 and responses[-1]["data"]["result"]["search"]["repeated"] is True


def test_a_reach_link_with_an_unsearched_source_is_stored_partial():
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=2))]})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client, packet_sources=("pcap-behind-net-a",))
    response = _search(toolbox, ADDRESS)
    assert response["status"] == "partial"
    link, = [row for row in repo.expansion_links("h1") if row["link_type"] == "agent_search_events"]
    assert link["status"] == "partial"
    assert any(cell["target"] == "pcap-behind-net-a" and cell["status"] == "partial" for cell in link["coverage"])


def test_listed_entities_and_skip_reasons_are_bounded_per_search(monkeypatch):
    monkeypatch.setattr(pivot_module, "MAX_SEARCH_ENTITIES", 1)
    monkeypatch.setattr(pivot_module, "MAX_SEARCH_SKIP_REASONS", 1)
    odd = [{"_id": f"odd-{name}", "_index": "net-a", "_source": {
        "@timestamp": (T + timedelta(minutes=n)).isoformat(), "event": {"dataset": f"custom.{name}"},
        "dns": {"question": {"name": "example.test"}}}} for n, name in enumerate("abc", 1)]
    records = [_dns("net-a", 1, T + timedelta(minutes=9)), *odd]
    repo, client = _hunt(), FakeES({"net-a": records})
    response = _search(_toolbox(repo, {"net-a": _keyword_contract("net-a")}, client), DNS)
    result = response["data"]["result"]
    assert len(result["entities"]) == 1
    assert any(reason.startswith("search_entities_listed:1:of:") for reason in result["reasons"])
    skip = [reason for reason in result["reasons"] if reason.startswith("records_not_normalized:")]
    assert len([reason for reason in skip if "past the first 1" not in reason]) == 1
    assert any("other reasons past the first 1" in reason for reason in skip)


def test_reasons_past_ten_are_counted_and_similar_field_names_are_bounded():
    targets = {f"net-{n:02d}": contract_from_types(f"net-{n:02d}", {"@timestamp": "date"}, role="network")
               for n in range(12)}
    targets["net-a"] = _keyword_contract("net-a")
    repo, client = _hunt(), FakeES({"net-a": []})
    search = _search(_toolbox(repo, targets, client), DNS)["data"]["result"]["search"]
    assert len(search["gaps_and_caveats"]) == 10 and search["gaps_and_caveats_omitted"] > 0
    long_name = "file.hash." + "a" * 300
    contract = contract_from_types("net-a", {"@timestamp": "date", long_name: "keyword"}, role="network")
    refusal = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": contract}).plan_search(_request(
        [{"field": "hash.sha256", "op": "eq", "values": ["x"]}])).refusal
    assert all(len(item["field"]) <= 129 for item in refusal["conditions"][0]["similar_fields"])


def test_the_searched_fields_are_never_cut_from_an_event_summary():
    # a Windows logon has more than sixteen typed fields, and source.ip sorts past the sixteenth
    contract, hit = _windows_contract_and_record()
    repo, client = _hunt(), FakeES({"win-a": [hit]})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "host.name", "op": "eq", "values": ["ws01"]},
                        {"field": "source.ip", "op": "eq", "values": ["198.51.100.9"]}], scope="host")
    summary, = response["data"]["result"]["event_summaries"]
    assert summary["searched_fields"] == {"host.name": "ws01", "source.ip": "198.51.100.9"}


# ---- the reviewer's probes: what the source matched is kept -------------------------------------------------------

def _probe_windows():
    win = {"_id": "w1", "_index": "win-a", "_source": {
        "@timestamp": "2024-11-18T14:05:00+00:00", "agent": {"type": "winlogbeat"},
        "event": {"dataset": "windows.security", "code": "4624"}, "data_stream": {"dataset": "windows.security"},
        "winlog": {"channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing", "event_id": "4624",
                   "computer_name": "WS01.corp.local", "record_id": "77", "event_data": {
                       "SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS01$", "SubjectDomainName": "CORP",
                       "TargetUserSid": "S-1-5-21-1-2-3-500", "TargetUserName": "Administrator",
                       "TargetDomainName": "CORP", "LogonType": "3", "IpAddress": "::ffff:10.0.0.9",
                       "IpPort": "50000", "WorkstationName": "WS02", "TargetLogonId": "0x1234"}}}}
    sysmon = {"_id": "s1", "_index": "win-a", "_source": {
        "@timestamp": "2024-11-18T14:06:00+00:00", "agent": {"type": "winlogbeat"},
        "event": {"dataset": "windows.sysmon_operational", "code": "1"},
        "data_stream": {"dataset": "windows.sysmon_operational"},
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "provider_name": "Microsoft-Windows-Sysmon",
                   "event_id": "1", "computer_name": "WS01.corp.local", "record_id": "88", "event_data": {
                       "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "CommandLine": "powershell.exe -enc AAAA", "ParentImage": "C:\\Windows\\explorer.exe",
                       "ProcessId": "100", "ParentProcessId": "50",
                       "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
                       "ParentProcessGuid": "{22222222-2222-2222-2222-222222222222}", "User": "CORP\\Alice",
                       "LogonId": "0x1234"}}}}
    types = {"@timestamp": "date", "agent.type": "keyword", "event.dataset": "keyword",
             "data_stream.dataset": "keyword", "event.code": "keyword", "winlog.channel": "keyword",
             "winlog.computer_name": "keyword", "winlog.event_id": "keyword", "winlog.provider_name": "keyword",
             "winlog.record_id": "keyword", "host.name": "keyword"}
    for name in ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "TargetUserSid", "TargetUserName",
                 "TargetDomainName", "LogonType", "IpAddress", "IpPort", "WorkstationName", "TargetLogonId", "Image",
                 "CommandLine", "ParentImage", "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
                 "User", "LogonId"):
        types["winlog.event_data." + name] = "keyword"
    contract = contract_from_types("win-a", types, role="host", os_family="windows",
                                   datasets=["windows.sysmon_operational", "windows.security"], index_limits={})
    return contract, [win, sysmon]


@pytest.mark.parametrize("conditions, kept", [
    # Windows events carry no typed event.dataset: the source's exact match is kept
    ([{"field": "event.dataset", "op": "eq", "values": ["windows.sysmon_operational"]}], 1),
    ([{"field": "process.guid", "op": "eq", "values": ["{11111111-1111-1111-1111-111111111111}"]}], 1),
    ([{"field": "winlog.event_data.CommandLine", "op": "prefix", "values": ["powershell"]}], 1),
    ([{"field": "process.executable", "op": "in",
       "values": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]}], 1),
    # an IPv4-mapped spelling on an alias of a keyword field: the stored spelling matched, and it is kept
    ([{"field": "source.ip", "op": "eq", "values": ["::ffff:10.0.0.9"]}], 1),
])
def test_what_the_source_matched_exactly_is_kept(conditions, kept):
    contract, records = _probe_windows()
    repo, client = _hunt(), FakeES({"win-a": records})
    response = _search(_toolbox(repo, {"win-a": contract}, client), conditions, scope="host")
    search = response["data"]["result"]["search"]
    assert len(response["data"]["result"]["evidence"]) == kept, response["data"]["result"]
    assert search["discarded"] == 0 and search["negative"] == "matches_found"


def test_a_typed_event_without_the_special_field_is_kept():
    contract, records = _probe_windows()
    repo, client = _hunt(), FakeES({"win-a": records})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "event.channel", "op": "eq", "values": ["SECURITY"]}], scope="host")
    assert response["data"]["result"]["search"]["discarded"] == 0
    assert len(response["data"]["result"]["evidence"]) == 1


def test_superset_rows_the_special_form_check_refutes_are_discarded_and_counted():
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

    def hit(record_id, data):
        event = LogicalWindowsEvent("Security", "Microsoft-Windows-Security-Auditing", 4688, "WS01.corp.example",
                                    record_id, "2024-11-18T14:10:00Z", data)
        record = windows_hit(event, "winlogbeat_8")
        record.update(_index="win-a", _id=f"w{record_id}")
        return record

    base = {"SubjectLogonId": "0x5", "NewProcessName": "C:\\x.exe", "NewProcessId": "0x10", "ProcessId": "0x4"}
    other_domain = hit(1, {**base, "SubjectUserName": "alice", "SubjectDomainName": "OTHER"})
    same_domain = hit(2, {**base, "SubjectUserName": "Alice", "SubjectDomainName": "CORP"})
    with_sid = hit(3, {**base, "SubjectUserSid": "S-1-5-21-9", "SubjectUserName": "alice",
                       "SubjectDomainName": "corp.example"})
    contract, _hit = _windows_contract_and_record()
    repo, client = _hunt(), FakeES({"win-a": [other_domain, same_domain, with_sid]})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "user.entity_id", "op": "eq", "values": ["name:CORP\\alice"]}], scope="host")
    search = response["data"]["result"]["search"]
    # the source matched the short name in every domain: another domain's alice is refuted by her typed account; a
    # sid-typed alice is checked on her typed name and domain (corp.example is CORP)
    assert client.returned == 3 and search["discarded"] == 1
    assert len(response["data"]["result"]["evidence"]) == 2


def test_a_text_parsed_record_on_a_generic_dataset_gives_unresolved():
    record = {"_id": "g1", "_index": "host-a", "_source": {
        "@timestamp": "2024-11-18T14:05:00+00:00", "event": {"dataset": "generic"}, "input": {"type": "filestream"},
        "log": {"file": {"path": "/var/log/auth.log"}}, "host": {"name": "web01"},
        "message": "Nov 18 14:05:00 web01 sshd[123]: Accepted password for bob from 10.0.0.9 port 50022 ssh2"}}
    contract = contract_from_types("host-a", {
        "@timestamp": "date", "event.dataset": "keyword", "input.type": "keyword", "log.file.path": "keyword",
        "host.name": "keyword", "message": "match_only_text", "source.ip": "ip", "source.port": "long"},
        role="host", os_family="linux", index_limits={})
    for inventory in ({"host-a": ["generic"]}, None):
        repo, client = _hunt(), FakeES({"host-a": [record]})
        response = _search(_toolbox(repo, {"host-a": contract}, client, inventory=inventory),
                           [{"field": "source.ip", "op": "eq", "values": ["10.0.0.9"]}], scope="host")
        search = response["data"]["result"]["search"]
        assert search["negative"] == "unresolved" and search["statement"] == NOT_CONFIRMED


def test_a_flattened_leaf_takes_its_root_s_index_limit():
    contract = FieldContract(target="net-a", fields={}, keyword_limits={"labels": 32, "labels.x.keyword": 8},
                             keyword_limits_known=True)
    assert contract.index_limit("labels.owner.name") == (True, 32)
    assert contract.index_limit("labels.x.keyword") == (True, 8)
    assert contract.index_limit("other.field") == (True, None)


def test_a_result_the_session_cannot_store_is_a_stored_failure(monkeypatch):
    repo = _hunt()
    client = FakeES({"net-a": [_dns("net-a", 1, T + timedelta(minutes=2))]})
    toolbox = _toolbox(repo, {"net-a": _keyword_contract("net-a")}, client)
    real = Repo.create_agent_page_plan

    def refuse_large(self, hunt_id, cursor, identity, summary, items, **kwargs):
        items = list(items)
        if len(items) > 3:
            raise ValueError("agent page item quota exceeded")
        return real(self, hunt_id, cursor, identity, summary, items, **kwargs)

    monkeypatch.setattr(Repo, "create_agent_page_plan", refuse_large)
    first = _search(toolbox, DNS)
    assert first["status"] == "failed"
    assert any("search result not stored" in reason for reason in first["data"]["result"]["reasons"])


def test_the_item_bound_counts_rows_twice_for_the_findings_they_can_raise():
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"net-a": _keyword_contract("net-a")})
    rows = pivot_module.MAX_SEARCH_RECORDS + pivot_module.MAX_SEARCH_TARGET_RECORDS
    assert executor.search_item_bound(_request(DNS)) >= 2 * rows + pivot_module.MAX_SEARCH_ENTITIES


# ---- accounts typed by sid, domain spellings, text lines under any dataset ----------------------------------------

def _logon(record_id: int, *, sid: bool = True, domain: str = "CORP", name: str = "Administrator") -> dict:
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

    data = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS01$", "TargetUserName": name,
            "TargetDomainName": domain, "LogonType": "3", "IpAddress": "198.51.100.9", "IpPort": "51515",
            "LogonId": "0x1"}
    if sid:
        data["TargetUserSid"] = f"S-1-5-21-1-2-3-{500 + record_id}"
    event = LogicalWindowsEvent("Security", "Microsoft-Windows-Security-Auditing", 4624, "WS01.corp.example",
                                record_id, "2024-11-18T14:10:00Z", data)
    record = windows_hit(event, "winlogbeat_8")
    record.update(_index="win-a", _id=f"logon-{record_id}")
    return record


@pytest.mark.parametrize("searched, records, kept", [
    # a sid-typed logon of CORP\\Administrator: another domain's name is refuted by its typed name and domain
    ("name:other\\administrator", [_logon(1)], 0),
    ("name:corp\\administrator", [_logon(1)], 1),
    ("name:CORP.LOCAL\\Administrator", [_logon(1)], 1),       # NetBIOS and FQDN spellings never refute each other
    ("name:administrator", [_logon(1)], 1),                     # no domain searched: any domain's name
    ("name:other\\administrator", [_logon(1, domain="-")], 1),  # no typed domain: nothing refutes it
    # a name-typed logon (no sid): the same domain rules on its canonical name
    ("name:corp.local\\administrator", [_logon(2, sid=False)], 1),
    ("name:other\\administrator", [_logon(2, sid=False)], 0),
])
def test_an_account_name_search_is_checked_on_the_typed_name_and_domain(searched, records, kept):
    contract, _hit = _windows_contract_and_record()
    repo, client = _hunt(), FakeES({"win-a": records})
    response = _search(_toolbox(repo, {"win-a": contract}, client),
                       [{"field": "auth.target_account", "op": "eq", "values": [searched]}], scope="host")
    search = response["data"]["result"]["search"]
    assert client.returned == len(records)                      # the source matched the short name in every case
    assert len(response["data"]["result"]["evidence"]) == kept
    assert search["discarded"] == len(records) - kept


def test_netbios_and_fqdn_spellings_of_one_domain_are_the_same_domain():
    assert pivot_module._same_domain("CORP", "corp.local")
    assert pivot_module._same_domain("corp.local.", "CORP")
    assert pivot_module._same_domain("corp.local", "CORP.LOCAL")
    assert pivot_module._same_domain("CONTOSO", "ad.contoso.com")       # a NetBIOS name need not be the first label
    assert pivot_module._same_domain("corp", "other.local")             # so an FQDN never refutes a NetBIOS name
    assert not pivot_module._same_domain("corp.local", "corp.example")
    assert not pivot_module._same_domain("corp", "other")


@pytest.mark.parametrize("inventory, named", [
    (["generic", "apache.access", "custom.app", "zeek.conn", "windows.security"],
     {"generic", "apache.access", "custom.app"}),
    (None, {None}),
])
def test_any_dataset_of_a_target_with_a_text_payload_is_named_unless_always_structured(inventory, named):
    contract = _keyword_contract("host-a", role="host", message="match_only_text")
    executor = PivotExecutor(_hunt(), FakeES(), "h1", {"host-a": contract},
                             dataset_inventory=None if inventory is None else {"host-a": inventory})
    plan = executor.plan_search(_request([{"field": "source.ip", "op": "eq", "values": ["10.0.0.9"]}], scope="host"))
    cells = {cell.dataset for cell in plan.coverage if cell.reasons[0].startswith("dataset_text_parsed:")}
    assert cells == named
