"""Visibility publication reclaims crash leftovers without removing live or published chunks."""
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import select

from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo


@pytest.fixture
def repository(tmp_path):
    engine = make_engine(tmp_path / "visibility.db")
    migrate(engine)
    repo = Repo(engine)
    for hunt in ("h", "other"):
        repo.create_hunt(hunt, {"targets": []}, "digest", "test")
    try:
        yield repo
    finally:
        engine.dispose()


def rows(sensor, count=1):
    return [{"family": "http_tx", "sensor": sensor, "interval": index} for index in range(count)]


def insert_chunks(repo, hunt, pending, content):
    with repo.engine.begin() as connection:
        connection.execute(t.report_zeek_visibility.insert(), [
            {"hunt_id": hunt, "snapshot": pending, "ordinal": index, "body": row}
            for index, row in enumerate(content)
        ])


def private_names(repo, hunt):
    with repo.engine.connect() as connection:
        return set(connection.execute(select(t.report_zeek_visibility.c.snapshot).where(
            t.report_zeek_visibility.c.hunt_id == hunt,
            t.report_zeek_visibility.c.snapshot.like("pending-%")).distinct()).scalars())


def pointers(repo, hunt):
    with repo.engine.connect() as connection:
        return {body["row_snapshot"] for body in connection.execute(
            select(t.report_zeek_visibility.c.body).where(
                t.report_zeek_visibility.c.hunt_id == hunt,
                t.report_zeek_visibility.c.ordinal == -1)).scalars()}


def test_success_reclaims_orphans_but_preserves_every_published_pointer_and_other_hunts(repository):
    first_rows, second_rows = rows("first", 300), rows("second", 5)
    first = repository.save_zeek_visibility("h", iter(first_rows))
    second = repository.save_zeek_visibility("h", iter(second_rows))
    published_before = pointers(repository, "h")
    insert_chunks(repository, "h", "pending-crash-a", rows("orphan", 700))
    insert_chunks(repository, "h", "pending-crash-b", rows("orphan", 5))
    insert_chunks(repository, "other", "pending-other-hunt", rows("other", 5))

    third_rows = rows("third", 300)
    third = repository.save_zeek_visibility("h", iter(third_rows))
    assert private_names(repository, "h") == pointers(repository, "h")
    assert published_before <= pointers(repository, "h")
    assert private_names(repository, "other") == {"pending-other-hunt"}
    for reference, content in ((first, first_rows), (second, second_rows), (third, third_rows)):
        assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == content


def test_identical_success_also_reclaims_crash_leftovers(repository):
    content = rows("published", 300)
    reference = repository.save_zeek_visibility("h", iter(content))
    original_pointers = pointers(repository, "h")
    insert_chunks(repository, "h", "pending-crash", rows("orphan", 300))
    assert repository.save_zeek_visibility("h", iter(content)) == reference
    assert private_names(repository, "h") == original_pointers


def test_failed_attempt_only_releases_its_own_chunks_and_leaves_publications_readable(repository):
    content = rows("published", 300)
    reference = repository.save_zeek_visibility("h", iter(content))
    insert_chunks(repository, "h", "pending-prior-crash", rows("orphan", 300))
    before = private_names(repository, "h")

    def interrupted():
        yield from rows("failed", 300)
        raise ValueError("synthetic interruption")

    with pytest.raises(ValueError, match="synthetic interruption"):
        repository.save_zeek_visibility("h", interrupted())
    assert private_names(repository, "h") == before
    assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == content
    repository.save_zeek_visibility("h", iter(rows("next")))
    assert private_names(repository, "h") == pointers(repository, "h")


def test_actual_process_exit_releases_publication_lock_and_leaves_reclaimable_chunks(repository):
    source = Path(__file__).resolve().parents[1] / "src"
    program = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from romulus.store.db import make_engine
from romulus.store.repo import Repo
repo = Repo(make_engine(sys.argv[2]))
def interrupted():
    for index in range(300):
        if index == 256:
            os._exit(17)
        yield {"family": "http_tx", "sensor": "crashed", "interval": index}
repo.save_zeek_visibility("h", interrupted())
"""
    child = subprocess.run([sys.executable, "-X", "utf8", "-I", "-c", program,
                            str(source), repository.engine.url.database],
                           capture_output=True, check=False, timeout=30)
    assert child.returncode == 17, child.stderr.decode(errors="replace")
    assert private_names(repository, "h")
    content = rows("replacement", 300)
    reference = repository.save_zeek_visibility("h", iter(content))
    assert private_names(repository, "h") == pointers(repository, "h")
    assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == content


def test_concurrent_publishers_serialize_streams_and_preserve_both_snapshots(repository, monkeypatch):
    from contextlib import contextmanager

    from romulus.store import repo as module

    real_lease = module.zeek_visibility_lease
    first_chunk = threading.Event()
    second_attempted = threading.Event()
    release_first = threading.Event()
    first_finished = threading.Event()
    first_content, second_content = rows("first", 600), rows("second", 300)

    @contextmanager
    def observed_lease(engine):
        if threading.current_thread().name.startswith("second"):
            second_attempted.set()
        with real_lease(engine):
            yield

    monkeypatch.setattr(module, "zeek_visibility_lease", observed_lease)

    def first_stream():
        for index, row in enumerate(first_content):
            if index == 256:
                first_chunk.set()
                assert release_first.wait(10), "test did not release the blocked publisher"
            yield row
        first_finished.set()

    def second_stream():
        assert first_finished.is_set(), "second publisher entered its stream while the first was active"
        yield from second_content

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="first") as first_pool:
        first_future = first_pool.submit(repository.save_zeek_visibility, "h", first_stream())
        assert first_chunk.wait(10)
        try:
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="second") as second_pool:
                second_future = second_pool.submit(repository.save_zeek_visibility, "h", second_stream())
                try:
                    assert second_attempted.wait(10)
                finally:
                    release_first.set()
                first_ref, second_ref = first_future.result(timeout=10), second_future.result(timeout=10)
        finally:
            release_first.set()
    assert list(repository.zeek_visibility_rows("h", first_ref["sha256"])) == first_content
    assert list(repository.zeek_visibility_rows("h", second_ref["sha256"])) == second_content
    assert private_names(repository, "h") == pointers(repository, "h")


def test_legacy_digest_rows_survive_orphan_collection(repository):
    content = rows("legacy")
    insert_chunks(repository, "h", "legacy-digest", content)
    insert_chunks(repository, "h", "pending-crash", rows("orphan"))
    repository.save_zeek_visibility("h", iter(rows("new")))
    assert list(repository.zeek_visibility_rows("h", "legacy-digest")) == content


def test_hunt_deletion_removes_published_chunks_and_crash_leftovers(repository):
    repository.save_zeek_visibility("h", iter(rows("published", 300)))
    insert_chunks(repository, "h", "pending-crash", rows("orphan", 300))
    insert_chunks(repository, "other", "pending-other", rows("other"))
    result = repository.delete_hunt("h", actor="test")
    assert result["report_zeek_visibility"] >= 600
    assert not private_names(repository, "h")
    assert not pointers(repository, "h")
    assert private_names(repository, "other") == {"pending-other"}


def test_empty_and_in_memory_publications_remain_readable():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h", {"targets": []}, "digest", "test")
    try:
        empty = repo.save_zeek_visibility("h", iter(()))
        assert empty["count"] == 0
        assert list(repo.zeek_visibility_rows("h", empty["sha256"])) == []
        content = rows("memory", 300)
        reference = repo.save_zeek_visibility("h", iter(content))
        assert list(repo.zeek_visibility_rows("h", reference["sha256"])) == content
    finally:
        engine.dispose()


def test_recursive_publication_fails_without_deadlock_and_releases_the_lease(repository):
    def nested():
        yield from rows("interrupted", 256)
        repository.save_zeek_visibility("h", iter(rows("nested")))
    with pytest.raises(RuntimeError, match="recursively publish"):
        repository.save_zeek_visibility("h", nested())
    reference = repository.save_zeek_visibility("h", iter(rows("after")))
    assert list(repository.zeek_visibility_rows("h", reference["sha256"])) == rows("after")
    assert private_names(repository, "h") == pointers(repository, "h")
