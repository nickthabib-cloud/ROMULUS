"""A write to root's schedule is a finding by itself: when the per-file store has no room for its file, the write is
judged as it is read and published on its own. A write to any other file needs a root run to mean anything, and a
later run could only join it through held state, so that record is refused, and coverage says so."""
from romulus.detect.bounded import StateBudget
from romulus.detect.hijack import NonRootWriteRootExecutedFile
from tests.test_hijack_root_job import JOB, T0, VI, web


def _full_files(tmp_path):
    pb = NonRootWriteRootExecutedFile()
    pb.spill_dir = tmp_path
    pb.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    pb.budget.force_full("files forced full (test)", lambda account: account.name.endswith(":hijack_files"))
    return pb


def test_a_schedule_write_with_no_room_for_its_file_is_published_on_its_own(tmp_path):
    pb = _full_files(tmp_path)
    write = web(["tee", "-a", "/etc/cron.d/sync"], "/usr/bin/tee")
    [m] = pb.consume([write])
    assert m.group_key.endswith("|unheld") and m.proposed_lane == "high"
    assert "which root's scheduler or service manager reads" in m.claim
    assert [e.id for e in m.events] == [write.id] and pb.capped == 0
    assert pb.consume([web(["tee", "-a", "/etc/cron.d/sync"], "/usr/bin/tee")]) == []     # once per file
    pb.close_spill()


def test_a_write_to_another_file_with_no_room_is_refused_and_said(tmp_path):
    pb = _full_files(tmp_path)
    assert pb.consume([web(*VI, ts=T0)]) == []
    assert pb.capped == 1 and any("forced full" in reason or "disk" in reason for reason in pb.limit_reasons())
    assert JOB not in str(pb.files.keys())
    pb.close_spill()
