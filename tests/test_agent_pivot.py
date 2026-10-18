"""Safe pivot execution and shared deterministic candidate publication."""
from datetime import UTC, datetime, timedelta

from romulus.agent.models import EntityRef
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest, ProcessTreeArgs, ProcessTreeRequest
from romulus.detect.host import CredentialStoreRead
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import pivot as pivot_module
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.publish import publish_match
from romulus.sources.models import Completeness, SearchOutcome
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
END = START + timedelta(minutes=10)


class FakeClient:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def _repo() -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _process_event(argv=None) -> TypedEvent:
    return TypedEvent(
        id="event-1", family="process_exec", ts=START, host="video", outcome=Outcome.success,
        fields={
            "process.argv": fv(argv or ["cat", "/etc/shadow"], "raw-1:event.original#auditd:EXECVE.a*"),
            "process.pid": fv(123, "raw-1:event.original#auditd:SYSCALL.pid"),
            "process.ppid": fv(100, "raw-1:event.original#auditd:SYSCALL.ppid"),
        },
        raw=[RawRef(target="romulus-host-x", native_id="raw-1", digest="d")], normalizer="test@1",
    )


def test_shared_publication_sets_source_case_and_keeps_machine_policy():
    repo = _repo()
    playbook = CredentialStoreRead()
    match = playbook.consume([_process_event()])[0]

    row = publish_match(
        repo, "h1", playbook, match, None,
        {"romulus-host-x/raw-1": {"event": {"dataset": "linux.audit"}}},
        source_case_id="case-1",
    )

    assert row is not None
    stored = repo.candidate(row["id"])
    assert stored["source_case_id"] == "case-1"
    assert stored["claim"] == match.claim
    assert stored["lane"] == "high"


def test_pivot_pack_contains_only_direct_playbooks():
    pack = fresh_direct_pack()

    assert pack
    assert all(playbook.kind == "direct" for playbook in pack)
    assert "host.web_service_spawns_interpreter" not in {playbook.id for playbook in pack}
    assert "net.port_scan" not in {playbook.id for playbook in pack}


def test_ip_timeline_queries_both_network_sides_and_safe_journal_superset(monkeypatch):
    seen = []

    def fake_execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=0, total_relation="eq", returned=0,
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    contracts = {
        "romulus-network-x": contract_from_types("romulus-network-x", {
            "@timestamp": "date", "source.ip": "ip", "destination.ip": "ip", "event.dataset": "keyword",
        }),
        "romulus-host-x": contract_from_types("romulus-host-x", {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        }),
    }
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="ip", value="203.0.113.8", role="src"), start=START, end=END,
    ))

    result = PivotExecutor(_repo(), FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "complete"
    network = next(intent for intent in seen if "network" in intent.target)
    assert [[(p.field, p.op, p.value) for p in group] for group in network.any_of] == [
        [("source.ip", "eq", "203.0.113.8")],
        [("destination.ip", "eq", "203.0.113.8")],
    ]
    journal = next(intent for intent in seen if "host" in intent.target)
    assert [(p.field, p.op, p.value) for p in journal.filters] == [
        ("event.dataset", "eq", "systemd.journal"),
    ]


def test_partial_pivot_retains_events_and_publishes_direct_matches(monkeypatch):
    event = _process_event()

    def fake_execute(_client, intent, _contract):
        record = {"_id": "raw-1", "_index": intent.target, "_source": {"event": {"dataset": "linux.audit"}}}
        return SearchOutcome(
            target=intent.target, fingerprint="fp", started_at=START, ended_at=END,
            completeness=Completeness.partial, reasons=["shard_failures"], total=2,
            total_relation="eq", returned=1, records=[record],
        )

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    monkeypatch.setattr(pivot_module, "normalize_hits", lambda _records: ([event], {}, []))
    contracts = {"romulus-host-x": contract_from_types("romulus-host-x", {
        "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
    })}
    request = ProcessTreeRequest(tool="process_tree", arguments=ProcessTreeArgs(
        host="video", process_id=123, start=START, end=END,
    ))
    repo = _repo()

    result = PivotExecutor(repo, FakeClient(), "h1", contracts).run("case-1", request)

    assert result.status == "partial"
    assert result.event_ids == ["event-1"]
    assert len(result.candidate_ids) == 1
    assert repo.candidate(result.candidate_ids[0])["source_case_id"] == "case-1"
    assert repo.tasks("h1")[0]["state"] == "evaluated"
    assert "shard_failures" in result.reasons
