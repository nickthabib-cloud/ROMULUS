"""Zeek conn and SMB/DCE-RPC volume through the sweep: memory stays flat, the cross-partition state is on disk.

Thirty partitions of Malcolm conn rows and Windows-protocol rows (SMB commands and files, DCE-RPC, Kerberos, NTLM,
LDAP searches) are swept. Each partition also carries copies of rows an earlier partition read (the same rows shipped
again under another document id) and interim conn rows of connections whose later records arrive in later partitions.
The proof:
- selective interim-key lookups select the final cumulative record before evaluation; later final copies and
  interim rows cannot contribute a second connection, through state the stage keeps on disk, never in Python memory;
- once the first partitions have warmed the caches, the memory Python holds returns to the same level after each
  partition: nothing grows with the number of records swept.
"""
import gc
import itertools
import sqlite3
import tracemalloc
from dataclasses import replace
from datetime import timedelta

from romulus.detect.base import Playbook
from romulus.hunt import sweep as sw
from romulus.hunt import zeek_connections
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests import test_sweep as ts
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl

PAGES = 30
CONN_PER_PAGE = 1500
SMB_PER_PAGE = 500
COPIES_PER_PAGE = 50            # rows of the previous partition shipped again
INTERIM_PER_PAGE = 20           # interim rows of connections the next partition finishes
WARM = 4
HOSTS = 250
# Bytes a partition may leave behind once warm: allocator and cache noise, far below one partition's events (MiBs).
RESIDUE = 1 * 2**20


class _Count(Playbook):
    id, version = "test.count", 1
    families = ("net_flow", "smb_tx", "rpc_tx", "kerberos_tx", "ntlm_tx", "ldap_tx")

    def match(self, event):
        return []


def _interim(i: int) -> dict:
    """An interim (conn_long) row of the i-th volume connection: same connection, less of it."""
    conn = zf._volume_conn(i, zf.T0, HOSTS)
    return zf.malcolm(replace(conn, duration=(conn.duration or 1.0) / 2), f"interim-{i}", interim=True)


def _partitions():
    # a fixed address population: the normalizer's bounded address cache is warm after the first partitions
    conns, smb = zf.stream_conn_hits(PAGES * CONN_PER_PAGE, hosts=HOSTS), zl.stream_rows(PAGES * SMB_PER_PAGE,
                                                                          kinds=zl.WINDOWS_STREAM)
    previous: list[dict] = []
    for page in range(PAGES):
        rows = list(itertools.islice(conns, CONN_PER_PAGE)) + list(itertools.islice(smb, SMB_PER_PAGE))
        copies = [{**hit, "_index": "arkime_sessions3-copy", "_id": f"copy-{hit['_id']}"}
                  for hit in previous[:COPIES_PER_PAGE]]
        first_next = (page + 1) * CONN_PER_PAGE
        # interim rows of the next partition's first connections (their final rows arrive next), and a second
        # interim row of connections the previous partition finished (superseded: a later record was evaluated)
        interim = [_interim(first_next + k) for k in range(INTERIM_PER_PAGE)] if page + 1 < PAGES else []
        late = ([{**_interim(page * CONN_PER_PAGE + k), "_id": f"late-{page}-{k}"} for k in range(INTERIM_PER_PAGE)]
                if page > 0 else [])
        previous = rows
        yield rows + copies + interim + late


def test_zeek_volume_streams_through_the_sweep_with_flat_memory_and_disk_state(monkeypatch, tmp_path):
    contract = contract_from_types("net", {"@timestamp": "date", "event.dataset": "keyword",
                                            "event.provider": "keyword", "node": "keyword", "zeek.uid": "keyword"},
                                   role="network", os_family="unknown")
    window = Window(start=ts.START, end=ts.START + timedelta(hours=1))
    run = sw.Sweep(ts._repo(), ts.FakeClient(), "h1", window, {"net": contract}, stage_dir=tmp_path / "stage")
    run.pack = [_Count()]
    run._profiles = {"net": {"role": "network", "datasets": {}}}
    step = (window.end - window.start) / PAGES
    levels = []
    current: list[list[dict]] = [[]]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, current[0]))
    def latest(client, intent, contract, **kwargs):
        uids={uid for group in intent.any_of for pred in group if pred.field=='zeek.uid' for uid in pred.value}
        assert len(uids)<=INTERIM_PER_PAGE
        rows=[zf.malcolm(zf._volume_conn(int(uid[1:]),zf.T0,HOSTS),f'lookup-{uid}') for uid in sorted(uids)]
        return ts._complete(intent,rows)
    monkeypatch.setattr(zeek_connections,'execute',latest)
    tracemalloc.start()
    try:
        for page, records in enumerate(_partitions()):
            current[0] = records
            part = Window(start=window.start + step * page, end=window.start + step * (page + 1))
            run.run_partition("net", contract, [], part, est=len(records), any_of=[])
            current[0] = []
            del records
            gc.collect()
            if page == WARM - 1:
                baseline = tracemalloc.get_traced_memory()[0]
            elif page >= WARM:
                levels.append(tracemalloc.get_traced_memory()[0] - baseline)
    finally:
        tracemalloc.stop()
    shown = [round(level / 2**10) for level in levels]
    assert max(levels) <= RESIDUE, shown
    later = levels[len(levels) // 2:]
    assert max(later) - min(later) <= RESIDUE // 2, shown

    stats = run.stats
    assert stats["errors"] == 0
    # Interim keys are selectively resolved before consume; later finals/copies and
    # late interims cannot add a second cumulative flow to detector state.
    assert run.pack[0].evaluated == PAGES * (CONN_PER_PAGE + SMB_PER_PAGE)
    stage = run._stage
    canonical = stage.db.execute("SELECT COUNT(*) FROM zeek_canonical").fetchone()[0]
    assert canonical == PAGES * CONN_PER_PAGE
    with sqlite3.connect(stage.windows_path) as db:
        seen = db.execute("SELECT COUNT(*) FROM windows_seen").fetchone()[0]
    assert seen == PAGES * (CONN_PER_PAGE + SMB_PER_PAGE)
    cells = [c for c in run.repo.rule_cells("h1") if c["rule_id"] == "test.count"]
    assert len(cells)==PAGES
    assert not any("both were evaluated" in reason for cell in cells for reason in cell["detail"].get("reasons",[]))
    run.close_stage()
