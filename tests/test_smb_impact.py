"""Public, synthetic SMB impact contract tests; no operational or evaluation data."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.smb_impact import SmbImpact
from romulus.evidence.typed import RawRef, TypedEvent, fv

START = datetime(2026, 1, 1, tzinfo=UTC)


def smb(identity, stamp=0, *, action="FILE_RENAME", name=None, previous=None,
        client="10.0.0.1", server="10.0.0.2", share=r"\\server\docs",
        producer="zeek-ecs@2", family="smb_tx", fields=None):
    values = {"source.ip": client, "destination.ip": server, "smb.action": action,
              "smb.path": share, "smb.name": name or f"dir/file-{identity}.locked"}
    if previous is not False:
        values["smb.prev_name"] = previous or f"dir/file-{identity}.docx"
    values.update(fields or {})
    return TypedEvent(id=str(identity), family=family, ts=START + timedelta(seconds=stamp), host="sensor",
                      fields={key: fv(value, f"{identity}:native.{key}") for key, value in values.items()},
                      raw=[RawRef(target="synthetic", native_id=str(identity))], normalizer=producer)


@pytest.fixture
def rule(tmp_path):
    rule = SmbImpact()
    rule.budget = StateBudget(tmp_path, disk_total=128 * 2**20, reserve=0, memory_total=2**20)
    yield rule
    rule.release_state()


def finish(rule, rows):
    return [*rule.consume(rows), *rule.finalize()]


def test_500_lockbit_renames_in_two_minutes(rule):
    [match] = finish(rule, [smb(i, i * 120 / 500, name=f"dir/f{i}.lockbit") for i in range(500)])
    assert (match.proposed_lane, match.severity) == ("high", "critical")
    assert "500" in match.claim and ".lockbit" in match.claim
    assert "T1486" in rule.attack
    assert len(match.events) <= 4 and all(len(e.raw) <= 3 for e in match.events)
    assert all(p.origin for p in match.predicate)
    assert not rule.assures_negative and rule.positive_only_reason
    assert any("dedup" in n.lower() and "3" in n for n in match.notes)
    assert any("robocopy" in n.lower() for n in match.notes)


@pytest.mark.parametrize("count,expected", [(99, False), (100, True), (101, True)])
def test_uniform_count_boundary(rule, count, expected):
    matches = finish(rule, [smb(i) for i in range(count)])
    assert bool(matches) == expected
    if expected:
        assert matches[0].proposed_lane == "high"


@pytest.mark.parametrize("dominant,expected", [(79, False), (80, True), (81, True)])
def test_exact_eighty_percent_boundary_same_timestamp(rule, dominant, expected):
    rows = [smb(i, name=f"f{i}.{'locked' if i < dominant else 'other'}") for i in range(100)]
    matches = finish(rule, rows)
    assert bool(matches) == expected


@pytest.mark.parametrize("count,expected", [(199, False), (200, True), (201, True)])
def test_delete_volume_boundary(rule, count, expected):
    matches = finish(rule, [smb(i, action="FILE_DELETE", previous=False) for i in range(count)])
    assert bool(matches) == expected
    if expected:
        assert (matches[0].proposed_lane, matches[0].severity) == ("lead", "high")


@pytest.mark.parametrize("seconds,expected", [(299.999, True), (300, True), (300.001, False)])
def test_closed_five_minute_boundary(rule, seconds, expected):
    rows = [smb(i, 0 if i < 99 else seconds) for i in range(100)]
    assert bool(finish(rule, rows)) == expected


def test_150_renames_over_two_hours_is_not_burst(rule):
    assert not finish(rule, [smb(i, i * 7200 / 149) for i in range(150)])


def test_office_300_temp_renames_of_150_documents_never_high(rule):
    rows = [smb(i, i / 3, previous=f"dir/~WRL{i:04x}.tmp", name=f"dir/document-{i % 150}.docx")
            for i in range(300)]
    matches = finish(rule, rows)
    assert [m.proposed_lane for m in matches] == []  # 150 names, below volume threshold too.
    assert any("Word" in note for note in rule.coverage_notes())


def test_office_200_distinct_documents_are_volume_lead(rule):
    [match] = finish(rule, [smb(i, previous=f"dir/~WRL{i:04x}.tmp", name=f"dir/document-{i}.docx")
                            for i in range(200)])
    assert (match.proposed_lane, match.severity) == ("lead", "high")


@pytest.mark.parametrize("previous,new", [("ordinary.tmp", "out.locked"),
                                           ("~WRL0001.tmp", "out.locked"),
                                           ("~WRLnotes.tmp", "out.docx")])
def test_word_exception_is_narrow_and_not_all_temporary_files(rule, previous, new):
    [match] = finish(rule, [smb(i, previous=f"dir{i}/{previous}", name=f"dir{i}/{new}") for i in range(100)])
    assert match.proposed_lane == "high"


def test_missing_previous_name_volume_only_and_coverage(rule):
    [match] = finish(rule, [smb(i, previous=False) for i in range(250)])
    assert (match.proposed_lane, match.severity) == ("lead", "high")
    assert rule.missing_required == 250
    assert any("prev_name" in note and "extension" in note for note in rule.coverage_notes())


@pytest.mark.parametrize("count,expected", [(9, False), (10, True), (11, True)])
def test_note_directory_boundary(rule, count, expected):
    rows = [smb(i, action="FILE_OPEN", name=f"dir{i}/Restore-My-Files.txt", previous=False)
            for i in range(count)]
    matches = finish(rule, rows)
    assert bool(matches) == expected
    if expected:
        assert (matches[0].proposed_lane, matches[0].severity) == ("lead", "high")


def test_notes_match_whole_names_and_open_create_actions_only(rule):
    rows = [smb(i, action="FILE_OPEN", name=f"dir{i}/README_DECRYPT_note_analysis.md") for i in range(30)]
    rows += [smb(i + 30, action="FILE_CLOSE", name=f"dir{i}/Restore-My-Files.txt") for i in range(30)]
    rows += [smb(i + 60, action="FILE_OPEN", name="same/Restore-My-Files.txt") for i in range(30)]
    assert not finish(rule, rows)


def test_catalog_is_versioned_attributed_and_every_name_matches(tmp_path):
    path = Path(__file__).parents[1] / "content/network/ransom_notes.json"
    content = json.loads(path.read_text(encoding="utf-8"))
    assert content["version"] and content["attribution"] and content["entries"]
    for entry in content["entries"]:
        assert entry["source"].startswith("https://") and entry["license"] and entry["license_url"]
        rule = SmbImpact()
        rule.budget = StateBudget(tmp_path, reserve=0, disk_total=128 * 2**20)
        try:
            name = entry.get('example', entry['name'])
            [match] = finish(rule, [smb(i, action="FILE_OPEN", name=f"dir{i}/{name}")
                                    for i in range(10)])
            assert match.proposed_lane == "lead"
        finally:
            rule.release_state()


@pytest.mark.parametrize("producer", ["zeek-ecs@2", "suricata-eve@1"])
def test_producers_share_contract_without_observer_labels(rule, producer):
    [match] = finish(rule, [smb(i, producer=producer, action="SMB::FILE_RENAME") for i in range(100)])
    assert match.proposed_lane == "high"


@pytest.mark.parametrize("producer,family", [("arkime@1", "net_session"), ("arkime@1", "smb_tx"),
                                             ("unknown@1", "smb_tx"), ("zeek-ecs@bad", "smb_tx")])
def test_aggregate_and_unrecognized_producers_are_excluded(rule, producer, family):
    assert not finish(rule, [smb(i, producer=producer, family=family) for i in range(200)])


def test_duplicate_actions_native_references_and_late_batches_do_not_inflate(rule):
    rows = [smb(i, i, name=f"dir/file-{i % 99}.locked", previous=f"dir/file-{i % 99}.docx") for i in range(200)]
    list(rule.consume(rows[100:]))
    list(rule.consume(rows[:100]))
    list(rule.consume(rows))
    assert not list(rule.finalize())


def test_late_denominator_prevents_premature_high(rule):
    rows = [smb(i, name=f"f{i}.{'locked' if i < 100 else 'other'}") for i in range(150)]
    assert not list(rule.consume(rows[:100]))
    assert not list(rule.consume(rows[100:]))
    assert not list(rule.finalize())


def test_reordering_yields_same_single_group_and_peak(rule):
    rows = [smb(i, i % 300) for i in range(300)]
    list(rule.consume(rows[::2]))
    list(rule.consume(list(reversed(rows[1::2]))))
    [match] = list(rule.finalize())
    assert "300" in match.claim and match.proposed_lane == "high"
    assert not list(rule.finalize())


def test_groups_never_combine_clients_servers_or_shares(rule):
    rows = [smb(i, client=f"10.0.0.{10 + i // 90}") for i in range(180)]
    rows += [smb(i + 180, server=f"10.0.1.{10 + i // 90}") for i in range(180)]
    rows += [smb(i + 360, share=rf"\\server\share{i // 90}") for i in range(180)]
    assert not finish(rule, rows)


def test_unc_separator_case_dot_and_directory_canonicalization(rule):
    rows = [smb(i, action="FILE_OPEN", name=rf"DIR{i}\.\Restore-My-Files.txt") for i in range(9)]
    rows += [smb(20 + i, action="FILE_OPEN", name=f"//SERVER/DOCS/dir{i}/RESTORE-MY-FILES.TXT",
                 share="//SERVER/DOCS/") for i in range(9)]
    assert not finish(rule, rows)


def test_partial_disk_refusal_preserves_volume_but_does_not_assert_ratio(rule):
    list(rule.consume([smb(i) for i in range(200)]))
    rule.budget.force_full("synthetic capacity refusal", lambda account: account.name.startswith(rule.id))
    list(rule.consume([smb(999, name="unknown.other")]))
    rule.budget.forced.clear()
    rule.budget._recalm()
    [match] = list(rule.finalize())
    assert match.proposed_lane == "high" and rule.capped > 0
    assert "at least 200 retained" in match.claim and "ratio is unresolved" in match.claim
    assert any("incomplete" in note for note in rule.limit_reasons())


def test_missing_native_origin_or_invalid_scalar_is_not_evaluated(rule):
    rows = [smb(i, fields={"smb.name": ["a.locked", "b.locked"]}) for i in range(200)]
    rows += [smb(i + 200).model_copy(update={"raw": []}) for i in range(200)]
    rows += [smb(i + 400, fields={"smb.path": None}) for i in range(200)]
    assert not finish(rule, rows)
    assert rule.missing_required == 600


def test_conflicting_canonical_update_cannot_assure_extension_ratio(rule):
    list(rule.consume([smb(i) for i in range(200)]))
    list(rule.consume([smb(0, name="different.other")]))
    [match] = list(rule.finalize())
    assert rule.capped and match.proposed_lane == "high"
    assert "ratio is unresolved" in match.claim


def test_completed_positive_survives_a_later_replay_refusal(rule, monkeypatch):
    from romulus.detect.bounded import StateExhausted
    list(rule.consume([smb(i) for i in range(200)] + [smb("later", 1000)]))
    original = rule.rows.add

    def fail_later(identity, stamp, entries):
        if identity == "later":
            raise StateExhausted("synthetic replay capacity refusal")
        return original(identity, stamp, entries)

    monkeypatch.setattr(rule.rows, "add", fail_later)
    [match] = list(rule.finalize())
    assert match.proposed_lane == "high"
    assert any("replay is incomplete" in note for note in rule.limit_reasons())


def test_unc_parent_traversal_cannot_change_observed_share(rule):
    rows = [smb(i, action="FILE_OPEN", name=rf"\\server\docs\..\other\dir{i}\Restore-My-Files.txt",
                share=r"\\server\other") for i in range(10)]
    assert not finish(rule, rows)
    assert rule.missing_required == 10


def test_native_field_origin_is_required(rule):
    rows = [smb(i) for i in range(100)]
    for row in rows:
        row.fields["smb.name"] = fv(row.get("smb.name"), "unrelated:invented")
    assert not finish(rule, rows)
    assert rule.missing_required == 100


def test_expired_active_members_leave_no_derived_counts(rule):
    assert not finish(rule, [smb(i, i * 301) for i in range(300)])
    assert rule.rows.derived_bytes == 0
    assert rule.rows.store().db.execute("SELECT COUNT(*) FROM impact_members").fetchone()[0] == 0


def test_ratio_window_can_start_after_older_minority_without_new_arrival(rule):
    rows = [smb(i, 0, name=f"old/f{i}.other") for i in range(26)]
    rows += [smb(100 + i, 200, name=f"new/f{i}.locked") for i in range(100)]
    [match] = finish(rule, rows)
    assert match.proposed_lane == "high" and "100" in match.claim
    assert match.ts == START + timedelta(seconds=200)
    assert all(event.ts == START + timedelta(seconds=200) for event in match.events)


def test_ratio_window_can_start_after_older_minority_before_next_arrival(rule):
    rows = [smb(i, 0, name=f"old/f{i}.other") for i in range(26)]
    rows += [smb(100 + i, 200, name=f"new/f{i}.locked") for i in range(100)]
    rows.append(smb("much-later", 1000, name="later/ordinary.docx"))
    [match] = finish(rule, rows)
    assert match.proposed_lane == "high" and "100" in match.claim
    assert all(event.ts == START + timedelta(seconds=200) for event in match.events)
