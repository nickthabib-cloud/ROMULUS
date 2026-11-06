"""Versioned analyst content remains reproducible and disk backed."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def repo(tmp_path):
    engine = make_engine(tmp_path / 'local.sqlite')
    migrate(engine)
    yield Repo(engine)
    engine.dispose()


def row(value='192.0.2.1', **kw):
    return SimpleNamespace(kind='ip', value=value, label='', attack=(), expires_at=None,
                           lane='lead', severity='medium', **kw)


def create(repo, rows=None, **kw):
    from romulus.content.indicator_lists import IndicatorLists
    return IndicatorLists(repo).create_version(rows or [row()], name='Mission', source='Partner',
                                               author='analyst', now=NOW, **kw)


def test_versions_pin_and_resume_after_retire(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    service = IndicatorLists(repo)
    first = create(repo)
    pins = service.pin(now=NOW)
    second = create(repo, [row('192.0.2.2')], list_id=first['id'])
    assert second['version'] == 2
    assert service.get(first['id'])['version'] == 2
    assert service.get(first['id'], 1)['digest'] == first['digest']
    service.retire(first['id'], actor='lead', role='lead')
    old = PinnedIndicators(repo, pins)
    assert len(list(old.find('ip', '192.0.2.1'))) == 1
    assert list(old.find('ip', '192.0.2.2')) == []
    assert old.get(next(iter(old.find('ip', '192.0.2.1')))['id'])['list']['age_days'] == 0
    assert service.pin(now=NOW)['applied'] == []


def test_latest_expiry_never_falls_back_and_value_expiry_is_as_of_pin(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    first = create(repo)
    expiring = row('192.0.2.2')
    expiring.expires_at = NOW + timedelta(days=1)
    second = create(repo, [row('192.0.2.3'), expiring], list_id=first['id'],
                    expires_at=NOW + timedelta(days=2))
    service = IndicatorLists(repo)
    old = service.pin(now=NOW)
    later = service.pin(now=NOW + timedelta(days=1))
    assert len(list(PinnedIndicators(repo, old).find('ip', expiring.value))) == 1
    assert list(PinnedIndicators(repo, later).find('ip', expiring.value)) == []
    expired = service.pin(now=NOW + timedelta(days=2))
    assert expired['applied'] == []
    assert expired['excluded'][0]['version'] == second['version']
    assert service.get(first['id'])['status'] == 'expired'
    assert len(list(PinnedIndicators(repo, old).find('ip', expiring.value))) == 1


def test_overlap_dedup_audit_and_atomic_validation(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    first = create(repo, [row(), row()])
    assert first['value_count'] == 1
    assert first['expires_at'] == (NOW + timedelta(days=90)).isoformat()
    create(repo)
    pinned = PinnedIndicators(repo, IndicatorLists(repo).pin(now=NOW))
    assert len(list(pinned.find('ip', '192.0.2.1'))) == 2
    assert pinned.kinds == {'ip'}
    assert pinned.digest
    with pytest.raises(PermissionError):
        IndicatorLists(repo).retire(first['id'], actor='analyst', role='analyst')
    invalid = row()
    invalid.lane = 'invented'
    with pytest.raises(ValueError):
        create(repo, [row(), invalid])
    with repo.engine.connect() as c:
        audits = c.execute(select(t.audit_event)).mappings().all()
    assert [r['action'] for r in audits].count('indicator_list.import') == 2
    assert len(IndicatorLists(repo).lists()) == 2


def test_report_is_finalized_after_stream_and_bad_pin_fails(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    count = [0]
    def rows():
        count[0] += 1
        yield row()
    result = create(repo, rows(), report=lambda: {'accepted': count[0]})
    assert result['import_report'] == {'accepted': 1}
    pins = IndicatorLists(repo).pin(now=NOW)
    pins['applied'][0]['digest'] = 'wrong'
    with pytest.raises(ValueError, match='digest'):
        PinnedIndicators(repo, pins)



def _assert_bound_matcher_reads_pinned_values(repo, pins):
    from romulus.content.indicator_lists import PinnedIndicators
    from romulus.detect.indicators import IndicatorMatch, IndicatorSet
    from romulus.evidence.typed import RawRef, TypedEvent, fv

    target_ip, target_hash = "10.15.66.63", f"{999999:064x}"
    pinned = PinnedIndicators(repo, pins)
    expected = [next(pinned.find("ip", target_ip)), next(pinned.find("sha256", target_hash))]
    owner = IndicatorMatch(IndicatorSet())
    try:
        owner.bind_indicators(repo, pins)
        assert owner.by_id == {}
        events = [
            TypedEvent(id="large-list-contact", family="net_flow", ts=NOW, host="sensor",
                fields={"destination.ip": fv(target_ip, "fixture:destination")},
                raw=[RawRef(target="fixture", native_id="large-list-contact")], normalizer="fixture"),
            TypedEvent(id="hash-transfer", family="file_transfer", ts=NOW, host="sensor",
                fields={"file.hash.sha256": fv(target_hash, "fixture:sha256")},
                raw=[RawRef(target="fixture", native_id="hash-transfer")], normalizer="fixture"),
        ]
        owner.consume(events)
        matches = list(owner.finalize())
        assert len(matches) == 2
        for expected_row in expected:
            match = next(m for m in matches if expected_row["id"] in m.claim)
            provenance = expected_row["list"]
            assert expected_row["value"] in match.claim
            for text in (provenance["name"], provenance["source"], provenance["author"],
                         f"version {provenance['version']}", "age 0 days"):
                assert text in match.claim
        assert any("was observed in a transfer" in m.claim for m in matches)
        assert owner.by_id == {}
    finally:
        owner.release_state()


def test_bound_matcher_scale_assertions_on_small_pinned_fixture(repo):
    from romulus.content.indicator_import import ImportedIndicator
    from romulus.content.indicator_lists import IndicatorLists
    create(repo, [ImportedIndicator("ip", "10.15.66.63")])
    create(repo, [ImportedIndicator("sha256", f"{999999:064x}")])
    _assert_bound_matcher_reads_pinned_values(repo, IndicatorLists(repo).pin(now=NOW))

@pytest.mark.slow
def test_million_values_stream_with_bounded_memory_and_indexed_lookup(repo):
    import tracemalloc

    from romulus.content.indicator_import import ImportedIndicator
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    def million():
        for i in range(1_000_000):
            yield ImportedIndicator("ip", f"10.{i >> 16}.{(i >> 8) & 255}.{i & 255}")
    tracemalloc.start()
    try:
        result = create(repo, million())
        service = IndicatorLists(repo)
        assert result["value_count"] == 1_000_000
        create(repo, [ImportedIndicator("sha256", f"{999999:064x}")])
        pins = service.pin(now=NOW)
        pinned = PinnedIndicators(repo, pins)
        assert len(list(pinned.find("ip", "10.15.66.63"))) == 1
        assert list(pinned.find("ip", "192.0.2.99")) == []
        assert sum(1 for _ in service.values(result["id"])) == 1_000_000
        _assert_bound_matcher_reads_pinned_values(repo, pins)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 64 * 1024 * 1024


def test_failed_report_and_stream_abort_remove_values_and_audit_rejections(repo):
    from romulus.content.indicator_lists import IndicatorLists
    def broken():
        yield row()
        raise RuntimeError("broken import")
    with pytest.raises(RuntimeError, match="broken import"):
        create(repo, broken())
    with pytest.raises(ValueError, match="dictionary"):
        create(repo, report=list)
    assert IndicatorLists(repo).lists() == []
    with repo.engine.connect() as c:
        assert c.execute(select(t.audit_event.c.action)).all() == [
            ('indicator_list.import_rejected',), ('indicator_list.import_rejected',)]
        assert c.execute(select(t.indicator_value)).first() is None


def test_pin_digest_and_value_get_are_stable_after_status_change(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    first = create(repo)
    service = IndicatorLists(repo)
    pins = service.pin(now=NOW)
    original = PinnedIndicators(repo, pins)
    value_id = next(iter(original.find("ip", "192.0.2.1")))["id"]
    service.retire(first["id"], actor="lead", role="lead")
    resumed = PinnedIndicators(repo, pins)
    assert resumed.digest == original.digest
    assert resumed.get(value_id) == original.get(value_id)
    assert resumed.get("absent") is None
    with repo.engine.connect() as c:
        actions = c.execute(select(t.audit_event.c.action, t.audit_event.c.actor)).all()
    assert ("indicator_list.retire", "lead") in actions


def test_duplicate_metadata_preserves_longest_eligibility_and_strongest_overrides(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    earlier = row()
    earlier.expires_at = NOW + timedelta(days=1)
    earlier.attack = ("T1059",)
    later = row()
    later.expires_at = NOW + timedelta(days=3)
    later.lane = "high"
    later.severity = "high"
    later.attack = ("T1003",)
    created = create(repo, [earlier, later], role='lead', reason='confirmed payload')
    service = IndicatorLists(repo)
    matched = list(PinnedIndicators(repo, service.pin(now=NOW + timedelta(days=2))).find("ip", earlier.value))
    assert len(matched) == 1
    assert matched[0]["lane"] == matched[0]["severity"] == "high"
    assert matched[0]["attack"] == ["T1003", "T1059"]
    assert created["value_count"] == 1
    with repo.engine.connect() as c:
        audit = c.execute(select(t.audit_event.c.detail)).scalar()
    assert audit["duplicates"] == 1


def test_duplicate_without_expiry_keeps_value_eligible_across_batches(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    earlier = row()
    earlier.expires_at = NOW
    def rows():
        yield earlier
        for i in range(1000):
            yield row(f"192.0.{i // 256 + 3}.{i % 256}")
        yield row()
    created = create(repo, rows())
    pins = IndicatorLists(repo).pin(now=NOW + timedelta(days=3))
    assert len(list(PinnedIndicators(repo, pins).find("ip", earlier.value))) == 1
    assert created["value_count"] == 1001


def test_expiry_is_audited_once_and_missing_versions_fail_honestly(repo):
    from romulus.content.indicator_lists import IndicatorLists, PinnedIndicators
    created = create(repo, expires_at=NOW + timedelta(days=1))
    service = IndicatorLists(repo)
    pins = service.pin(now=NOW)
    service.pin(now=NOW + timedelta(days=1))
    service.pin(now=NOW + timedelta(days=2))
    with repo.engine.connect() as c:
        audits = c.execute(select(t.audit_event).where(
            t.audit_event.c.action == "indicator_list.expire")).mappings().all()
    assert len(audits) == 1
    assert audits[0]["detail"]["version"] == created["version"]
    assert audits[0]["detail"]["digest"] == created["digest"]
    pins["applied"][0]["version"] = 999
    with pytest.raises(ValueError, match="missing"):
        PinnedIndicators(repo, pins)


def test_attack_metadata_validation_consumes_a_bounded_prefix(repo):
    consumed = [0]
    def too_many_labels():
        for i in range(1000):
            consumed[0] += 1
            yield f"T{i:04}"
    indicator = row()
    indicator.attack = too_many_labels()
    with pytest.raises(ValueError, match="ATT&CK"):
        create(repo, [indicator])
    assert consumed[0] <= 257


@pytest.mark.parametrize("field", ["name", "source", "author", "notes", "list_id", "attack"])
def test_direct_service_refuses_credential_metadata_without_storing_or_echoing(repo, field):
    from romulus.content.indicator_lists import IndicatorLists
    secret = "password=service-secret"
    metadata = {"name": "Mission", "source": "Partner", "author": "analyst", "now": NOW}
    indicator = row()
    if field in {"label", "attack"}:
        setattr(indicator, field, [secret] if field == "attack" else secret)
    else:
        metadata[field] = secret
    with pytest.raises(ValueError) as caught:
        IndicatorLists(repo).create_version([indicator], **metadata)
    assert secret not in str(caught.value)
    assert "service-secret" not in str(caught.value)
    assert IndicatorLists(repo).lists() == []
    with repo.engine.connect() as c:
        actions = c.execute(select(t.audit_event.c.action)).scalars().all()
        assert actions == (['indicator_list.import_rejected'] if field == 'attack' else [])
        assert c.execute(select(t.indicator_value)).first() is None
