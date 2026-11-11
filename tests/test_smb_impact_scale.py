"""Actual streamed detector-scale proof, independent of normalization throughput.

The 50M case is slow, not skipped or opt-in: the final full suite runs it once.
Use the calibration case alone while iterating. Inputs are unique synthetic
TypedEvents, with bounded batches and native provenance; no corpus is read.
"""
from __future__ import annotations

import ctypes
import json
import sys
import time
from collections import Counter
from datetime import timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.smb_impact import SmbImpact
from romulus.evidence.typed import RawRef, fv
from tests.test_smb_impact import START, smb


def _rss():
    if sys.platform == 'win32':
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                        *[(name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                          'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                          'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]]
        handle = ctypes.windll.kernel32.GetCurrentProcess
        handle.restype = wintypes.HANDLE
        query = ctypes.windll.psapi.GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not query(handle(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError()
        return counters.WorkingSetSize
    import resource
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == 'darwin' else value * 1024


def run_scale(tmp_path, *, clients, rows_per_client):
    rule = SmbImpact()
    rule.budget = StateBudget(tmp_path, disk_total=1024 * 2**20, reserve=0, memory_total=2**20)
    distribution = Counter()
    actual = peak_disk = 0
    baseline_rss = peak_rss = _rss()
    started = time.perf_counter()
    try:
        for client_index in range(clients):
            client = f'10.1.{client_index // 256}.{client_index % 256}'
            template = smb('template', client=client, action='FILE_OPEN', previous=False)
            batch = []
            for ordinal in range(rows_per_client):
                identity = f'{client_index}:{ordinal}'
                action, stamp = 'FILE_OPEN', ordinal
                name, previous = f'ordinary/file-{ordinal}.docx', None
                if client_index == 0 and ordinal < 500:
                    action, stamp = 'FILE_RENAME', ordinal * 120 / 500
                    name, previous = f'victims/f{ordinal}.lockbit', f'victims/f{ordinal}.docx'
                elif client_index == 1 and ordinal < 200:
                    action, stamp = 'FILE_DELETE', ordinal * 120 / 200
                elif client_index == 2 and ordinal < 10:
                    action, stamp = 'FILE_CREATE', ordinal
                    name = f'directory-{ordinal}/Restore-My-Files.txt'
                elif ordinal % 200 == 0:
                    action = 'FILE_RENAME' if ordinal % 400 == 0 else 'FILE_DELETE'
                    previous = f'ordinary/old-{ordinal}.docx' if action == 'FILE_RENAME' else None
                values = {'source.ip': client, 'destination.ip': '10.0.0.2',
                          'smb.path': r'\\server\docs', 'smb.name': name, 'smb.action': action}
                if previous is not None:
                    values['smb.prev_name'] = previous
                # Copying a validated envelope avoids charging normalizer parsing
                # to detector throughput. Every row and native id is still unique.
                row = template.model_copy(update={
                    'id': identity, 'ts': START + timedelta(seconds=stamp),
                    'fields': {key: fv(value, f'{identity}:native.{key}') for key, value in values.items()},
                    'raw': [RawRef(target='synthetic-scale', native_id=identity)]})
                batch.append(row)
                distribution[action] += 1
                actual += 1
                if len(batch) == 500:
                    assert not rule.consume(batch)
                    batch.clear()
            if batch:
                assert not rule.consume(batch)
            if client_index % 100 == 0:
                peak_rss = max(peak_rss, _rss())
                peak_disk = max(peak_disk, rule.budget.physical_used)
            if client_index and client_index % 1000 == 0:
                print(f'SMB_SCALE_PROGRESS rows={actual} clients={client_index + 1}', flush=True)
        consumed = time.perf_counter()
        history = rule.rows.store().db.execute('SELECT COUNT(*) FROM history').fetchone()[0]
        assert history == actual - distribution['FILE_OPEN']
        findings = list(rule.finalize())
        elapsed = time.perf_counter() - started
        peak_rss = max(peak_rss, _rss())
        peak_disk = max(peak_disk, rule.budget.physical_used)
        assert actual == clients * rows_per_client
        assert len(findings) == 3
        assert sorted((m.proposed_lane, m.severity) for m in findings) == [
            ('high', 'critical'), ('lead', 'high'), ('lead', 'high')]
        assert any('500' in m.claim and '.lockbit' in m.claim for m in findings)
        assert rule.capped == rule.missing_required == 0 and not rule.limit_reasons()
        assert peak_disk <= rule.budget.disk_total
        assert peak_rss - baseline_rss < 128 * 2**20
        assert not rule.rows.store().db.execute('SELECT 1 FROM impact_active LIMIT 1').fetchone()
        report = {'rows': actual, 'clients': clients, 'distribution': dict(distribution),
                  'retained_history': history, 'seconds': round(elapsed, 3),
                  'ingest_seconds': round(consumed - started, 3),
                  'replay_seconds': round(elapsed - (consumed - started), 3),
                  'rows_per_second': round(actual / elapsed), 'baseline_rss': baseline_rss,
                  'sampled_peak_rss': peak_rss, 'sampled_rss_growth': peak_rss - baseline_rss,
                  'physical_disk_peak': peak_disk, 'disk_budget': rule.budget.disk_total,
                  'findings': len(findings), 'capped': rule.capped}
        print('SMB_SCALE ' + json.dumps(report, sort_keys=True), flush=True)
        return report
    finally:
        rule.release_state()


def test_smb_impact_scale_calibration(tmp_path, record_property):
    report = run_scale(tmp_path, clients=100, rows_per_client=1000)
    (tmp_path / 'smb-scale.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    record_property('smb_scale', json.dumps(report, sort_keys=True))
    assert report['rows'] == 100_000


@pytest.mark.slow
def test_smb_impact_actual_50m_rows_10k_clients(tmp_path, record_property):
    report = run_scale(tmp_path, clients=10_000, rows_per_client=5000)
    (tmp_path / 'smb-scale.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    record_property('smb_scale', json.dumps(report, sort_keys=True))
    assert report['rows'] == 50_000_000
    assert report['retained_history'] >= 250_000
