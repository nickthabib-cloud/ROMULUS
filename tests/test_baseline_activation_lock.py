"""The check that a build excludes every cited key and the activation of that build are one locked step.

A hunt in another process commits its cited-key ledger with its own connection. If the activating transaction read the
ledger before it held SQLite's write lock, that commit could land between the check and the activation, and the build
would become cover while counting an attack key as normal history. Each publisher therefore takes the write lock
before it reads the ledger: while the check runs, no other connection can write.
"""
from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest

from romulus.store.repo import Repo
from tests.test_baseline_lookback import SPEC, START, FakeHistory, _repo, _writer


def _building(repo: Repo) -> dict:
    row = _writer(repo, FakeHistory()).segment_row(
        hunt_id="build", target="host", spec=SPEC, start=START - timedelta(hours=1), end=START, events_total=0,
    )
    assert repo.begin_baseline_segment(row)
    return row


def _probe_writes_during_check(monkeypatch, path) -> list[str]:
    """Wrap the ledger check: right after it reads, another connection tries to write. Returns what it saw."""
    real = Repo._missing_exclusion
    seen: list[str] = []

    def checked(c, segment_id):
        result = real(c, segment_id)
        other = sqlite3.connect(str(path), timeout=0)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("ROLLBACK")
            seen.append("written")
        except sqlite3.OperationalError as error:
            seen.append(str(error))
        finally:
            other.close()
        return result

    monkeypatch.setattr(Repo, "_missing_exclusion", staticmethod(checked))
    return seen


def test_finalize_reads_the_ledger_under_the_write_lock(tmp_path, monkeypatch):
    path = tmp_path / "store.db"
    repo = _repo(str(path))
    row = _building(repo)
    seen = _probe_writes_during_check(monkeypatch, path)
    repo.finalize_baseline_segment(row["id"])
    assert seen == ["database is locked"]


def test_a_derived_publication_reads_the_ledger_under_the_write_lock(tmp_path, monkeypatch):
    path = tmp_path / "store.db"
    repo = _repo(str(path))
    row = _building(repo)
    seen = _probe_writes_during_check(monkeypatch, path)
    # nothing to replace: the publication is refused after its check, which is what this test needs
    assert repo.publish_derived_baseline_segment(row["id"], replaces="none", replaces_digest="none") == "superseded"
    assert seen == ["database is locked"]


def test_a_refused_check_releases_the_lock_and_changes_nothing(tmp_path, monkeypatch):
    """A refused check rolls back: the lock it took is released and the build stays building."""
    path = tmp_path / "store.db"
    repo = _repo(str(path))
    row = _building(repo)
    monkeypatch.setattr(Repo, "_missing_exclusion", staticmethod(lambda c, segment_id: "key-k"))
    from romulus.store.repo import ExclusionsChanged
    with pytest.raises(ExclusionsChanged):
        repo.finalize_baseline_segment(row["id"])
    other = sqlite3.connect(str(path), timeout=0)
    try:
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")
    finally:
        other.close()
    assert [item["status"] for item in repo.baseline_segments()] == ["building"]
