"""Scheduler observations stay visible without consuming process-lineage query budgets."""
from datetime import timedelta

from romulus.agent.models import EntityRef
from romulus.agent.tools import (
    AuthActivityArgs,
    AuthActivityRequest,
    EntityTimelineArgs,
    EntityTimelineRequest,
)
from romulus.config import Settings
from romulus.evidence.normalize import normalize_hits
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotExecutor, _host_datasets
from romulus.sources.es import ElasticClient
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.throughput_fixture import HOST_TARGET, HOST_TYPES, T0, Builder, MiniES


def _executor(docs):
    contract = contract_from_types(HOST_TARGET, {
        **HOST_TYPES, "message": "text", "event.original": "text",
    })
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": [HOST_TARGET]}, "digest", "test")
    es = MiniES({HOST_TARGET: docs}, {HOST_TARGET: contract.time_field})
    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=es.transport())
    return PivotExecutor(repo, client, "h1", {HOST_TARGET: contract})


def test_scheduler_datasets_do_not_exhaust_a_complete_audit_lineage_budget():
    # Public Linux audit SYSCALL/EXECVE fields provide the process identity and parent.
    builder = Builder(1)
    parent_pid = builder.exec_group("web1", T0, ["/bin/sh"], ppid=1, copy=False)
    builder.exec_group("web1", T0 + timedelta(seconds=1), ["/usr/bin/id"], ppid=parent_pid, copy=False)
    events, skips, errors = normalize_hits(builder.host)
    assert not skips and not errors
    parent = next(event for event in events if event.get("process.pid") == parent_pid)
    child = next(event for event in events if event.get("process.pid") != parent_pid)
    executor = _executor(builder.host)
    anchor = LinkAnchor(finding_id="parent", ts=parent.ts, host=parent.host,
                        event_ids=[parent.id], events=[parent])
    window = LinkWindow(label="ten minutes", start=T0, end=T0 + timedelta(minutes=10))

    result = LinkFetcher(executor, window.start, window.end).fetch(
        anchor, "process_lineage", window, query_cap=2,
    )

    assert result.status == "complete", result.reasons
    assert result.event_ids == [child.id]
    assert executor.source_queries == 1


def test_searchable_text_still_reaches_host_timeline_and_authentication():
    # Cron CMD is a scheduler observation; Dovecot Login is an explicit login decision.
    builder = Builder(2)
    builder._doc("web1", T0, "scheduler.log", None,
                 message="Nov 18 14:00:00 web1 CRON[42]: (root) CMD (/usr/bin/id)")
    builder._doc("web1", T0 + timedelta(seconds=1), "mail.log", None,
                 message="Nov 18 14:00:01 web1 dovecot: imap-login: Login: user=<alice>, "
                         "method=PLAIN, rip=192.0.2.8, lip=192.0.2.2")
    executor = _executor(builder.host)
    entity = EntityRef(kind="host", value="web1", role="host")
    end = T0 + timedelta(minutes=10)
    timeline = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=entity, start=T0, end=end,
    ))
    batch = executor.fetch_intents("timeline", "timeline", executor._intents(timeline), lambda _event: True)
    assert batch.status == "complete", batch.reasons
    assert {event.family for event in batch.events} == {"process_observed", "auth"}
    cron = next(event for event in batch.events if event.family == "process_observed")
    assert not cron.has("process.pid") and not cron.has("process.ppid")

    auth = AuthActivityRequest(tool="auth_activity", arguments=AuthActivityArgs(
        entity=entity, start=T0, end=end,
    ))
    batch = executor.fetch_intents("auth", "auth", executor._intents(auth),
                                  lambda event: event.family == "auth")
    assert batch.status == "complete", batch.reasons
    assert len(batch.events) == 1 and batch.events[0].get("auth.service") == "dovecot"


def test_observation_only_and_mixed_family_queries_keep_scheduler_coverage():
    contract = _executor([]).contracts[HOST_TARGET]
    for families in ({"process_observed"}, {"process_exec", "process_observed", "auth"}):
        selected = set(_host_datasets(contract, families))
        assert {"systemd.journal", "linux.syslog", "linux.text"} <= selected


def test_unmapped_text_authentication_returns_unresolved_coverage():
    executor = _executor([])
    executor.contracts[HOST_TARGET] = contract_from_types(HOST_TARGET, HOST_TYPES)
    request = AuthActivityRequest(tool="auth_activity", arguments=AuthActivityArgs(
        entity=EntityRef(kind="host", value="web1", role="host"),
        start=T0, end=T0 + timedelta(minutes=10),
    ))
    result = executor.run("auth", request)
    assert result.status == "partial"
    text_cells = [cell for cell in result.coverage if cell.dataset == "linux.text"]
    assert text_cells and all(cell.status != "complete" and cell.unresolved_ranges for cell in text_cells)
    assert any("linux.text" in reason and "not searchable" in reason for reason in result.reasons)


def test_unmapped_text_execution_refuses_without_search_or_version_requests():
    import httpx

    from romulus.sources.execute import execute
    from romulus.sources.models import Completeness, Predicate, SearchIntent, Window

    def refuse_io(_request):
        raise AssertionError("unsupported text selection must not contact the source")

    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(refuse_io))
    contract = contract_from_types(HOST_TARGET, HOST_TYPES)
    intent = SearchIntent(kind="raw", target=HOST_TARGET, window=Window(start=T0, end=T0 + timedelta(minutes=1)),
                          filters=[Predicate(field="event.dataset", op="eq", value="linux.text")])
    first = execute(client, intent, contract)
    second = execute(client, intent, contract)
    assert first.completeness == Completeness.failed
    assert first.total is None and first.total_relation == "unknown"
    assert first.returned == 0 and first.records == [] and first.backend_version == ""
    assert first.error and first.reasons == [first.error] and "linux.text" in first.error
    assert first.fingerprint == second.fingerprint and len(first.fingerprint) == 64


def test_other_compile_errors_remain_caller_errors():
    import httpx
    import pytest

    from romulus.sources.compile import CompileError
    from romulus.sources.execute import execute
    from romulus.sources.models import Predicate, SearchIntent, Window

    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(
        lambda _request: pytest.fail("invalid selector must not contact the source"),
    ))
    contract = contract_from_types(HOST_TARGET, HOST_TYPES)
    intent = SearchIntent(kind="raw", target=HOST_TARGET, window=Window(start=T0, end=T0 + timedelta(minutes=1)),
                          filters=[Predicate(field="unknown.field", op="eq", value="value")])
    with pytest.raises(CompileError):
        execute(client, intent, contract)
