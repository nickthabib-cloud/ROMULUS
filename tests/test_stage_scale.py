"""Stage reads grow linearly with the records of one partition.

A single complete partition of Arkime sessions is swept at two sizes, four times apart. Every session reaches the
disk stage (it is put, held, classified for reclamation and loaded back at finalize), so the stage work per partition
is proportional to its sessions. The test counts what the stage asks of SQLite, never wall-clock:
- the statements the stage connection runs grow about four times, so no per-record statement scans the stage;
- the pages SQLite must read from the stage file (page-cache misses) stay a few per record and grow far less than
  quadratically, so a lookup by event id stays a few pages deep however large the stage grows. A table whose b-tree
  is many levels deep (for example wide rows in a WITHOUT ROWID table, whose interior cells carry whole rows and
  whose rows each spill to an overflow page) fails the per-record bound.
"""
import ctypes
import os
import random
import sqlite3
import sys
import sysconfig
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from romulus.hunt import stage as stage_mod
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, tzinfo=UTC)
INDEX = "arkime_sessions3-241118"
SMALL, LARGE = 10_000, 40_000
SQLITE_DBSTATUS_CACHE_MISS = 8


def _sessions(n: int, seed: int = 7) -> list[dict]:
    """Ordinary traffic: internal clients to a pool of web servers and internal file and name servers."""
    rng = random.Random(seed)
    servers = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 60)]
    out = []
    for i in range(n):
        first = T0 + timedelta(seconds=rng.uniform(0, 86_000))
        client = f"172.17.{rng.randrange(4)}.{rng.randrange(1, 200)}"
        kind = rng.random()
        if kind < 0.6:
            server, port, proto = rng.choice(servers), 443, 6
        elif kind < 0.8:
            server, port, proto = f"172.17.0.{rng.randrange(1, 5)}", 445, 6
        else:
            server, port, proto = "172.17.0.53", 53, 17
        seconds = rng.choice((0.2, 1.0, 4.0, 30.0))
        doc = {"firstPacket": int(first.timestamp() * 1000),
               "lastPacket": int((first + timedelta(seconds=seconds)).timestamp() * 1000),
               "ipProtocol": proto, "node": "sensor1", "network": {"community_id": f"1:s{i}="},
               "source": {"ip": client, "port": rng.randrange(1024, 65535), "bytes": rng.randrange(200, 90_000),
                          "packets": rng.randrange(2, 90)},
               "destination": {"ip": server, "port": port, "bytes": rng.randrange(200, 900_000),
                               "packets": rng.randrange(2, 900)},
               "protocol": ["tcp", "tls"] if port == 443 else ["tcp", "smb"] if port == 445 else ["udp", "dns"]}
        if port == 443:
            doc["tls"] = {"ja3": [f"{rng.randrange(3):032x}"]}
        out.append({"_id": f"s{i}", "_index": INDEX, "_source": doc})
    return out


class _Client:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def _sqlite_library():
    """The SQLite library this interpreter's sqlite3 module runs on, or None when it cannot be identified."""
    import _sqlite3
    candidates = [os.path.join(os.path.dirname(_sqlite3.__file__), "sqlite3.dll")] if os.name == "nt" else []
    candidates.append(_sqlite3.__file__)
    for path in candidates:
        try:
            lib = ctypes.CDLL(path)
            lib.sqlite3_libversion.restype = ctypes.c_char_p
            if lib.sqlite3_libversion().decode() != sqlite3.sqlite_version:
                continue
        except (OSError, AttributeError):
            continue
        lib.sqlite3_db_status.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int),
                                          ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        lib.sqlite3_db_filename.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.sqlite3_db_filename.restype = ctypes.c_char_p
        return lib
    return None


# The connection's `sqlite3 *` follows the object header in CPython's connection object. Only a default build has the
# two-pointer header; a free-threaded or trace-refs build does not, and there the probe stays off.
_PROBE = (_sqlite_library() if sys.implementation.name == "cpython" and not sysconfig.get_config_var("Py_GIL_DISABLED")
          and not hasattr(sys, "getobjects") else None)


def _handle(connection, path):
    handle = ctypes.c_void_p.from_address(id(connection) + 2 * ctypes.sizeof(ctypes.c_void_p)).value
    if not handle:
        return None
    name = _PROBE.sqlite3_db_filename(handle, b"main")
    return handle if name and Path(name.decode()).resolve() == Path(path).resolve() else None


def _page_misses(connection, path):
    handle = _handle(connection, path) if _PROBE is not None else None
    if handle is None:
        return None
    current, high = ctypes.c_int(), ctypes.c_int()
    _PROBE.sqlite3_db_status(handle, SQLITE_DBSTATUS_CACHE_MISS, ctypes.byref(current), ctypes.byref(high), 0)
    return current.value


def _sweep(n, tmp_path, monkeypatch):
    """Sweep one complete partition of `n` sessions; returns the stage connection's statements and page reads."""
    counts = {"statements": 0, "pages": None, "staged": 0}

    class Counted(sqlite3.Connection):
        path = ""

        def close(self):
            if self.path:
                counts["pages"] = _page_misses(self, self.path)
            super().close()

    def connect(path, *args, **kwargs):
        if not str(path).endswith("stage.db"):
            return sqlite3.connect(path, *args, **kwargs)
        connection = sqlite3.connect(path, *args, factory=Counted, **kwargs)
        connection.path = str(path)
        connection.set_trace_callback(lambda _sql: counts.__setitem__("statements", counts["statements"] + 1))
        return connection

    module = {name: getattr(sqlite3, name) for name in dir(sqlite3) if not name.startswith("__")}
    monkeypatch.setattr(stage_mod, "sqlite3", SimpleNamespace(**{**module, "connect": connect}))
    records = _sessions(n)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=datetime.now(UTC), ended_at=datetime.now(UTC),
        completeness=Completeness.complete, total=len(records), total_relation="eq", returned=len(records),
        records=records))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": [INDEX]}, "d", "t")
    window = Window(start=T0, end=T0 + timedelta(days=1))
    sweep = sw.Sweep(repo, _Client(), "h1", window, {INDEX: None}, stage_dir=tmp_path / f"stage-{n}")
    try:
        sweep.run_partition(INDEX, None, [], window, est=n)
        counts["staged"] = sweep._stage.count()
        sweep.finalize()
    finally:
        sweep.close_stage()
    assert not sweep.partial_reasons, sweep.partial_reasons
    return counts


@pytest.fixture(scope="module")
def measured(tmp_path_factory):
    with pytest.MonkeyPatch.context() as monkeypatch:
        tmp = tmp_path_factory.mktemp("stage-scale")
        return {n: _sweep(n, tmp, monkeypatch) for n in (SMALL, LARGE)}


@pytest.mark.slow
def test_the_partition_reaches_the_stage(measured):
    # nearly every session is still staged when the partition ends (a few holds are released before then)
    assert all(counts["staged"] >= 0.99 * n for n, counts in measured.items()), measured


@pytest.mark.slow
def test_stage_statements_grow_linearly_with_partition_records(measured):
    ratio = measured[LARGE]["statements"] / measured[SMALL]["statements"]
    assert 3.0 <= ratio <= 5.0, (ratio, measured)


@pytest.mark.slow
def test_stage_page_reads_grow_linearly_with_partition_records(measured):
    if measured[SMALL]["pages"] is None:
        pytest.skip("this interpreter's SQLite page-cache counters cannot be read")
    ratio = measured[LARGE]["pages"] / measured[SMALL]["pages"]
    per_record = measured[LARGE]["pages"] / LARGE
    # The reads per record may rise a little as the stage outgrows SQLite's page cache and its b-trees gain a level
    # (logarithmically), so the bound on the ratio is well under the sixteen of a per-record scan. The bound per record
    # is what holds a lookup to a few pages: a WITHOUT ROWID event table of whole typed-event rows reads about 78 here.
    assert ratio <= 8.0, (ratio, measured)
    assert per_record <= 30, (per_record, measured)
