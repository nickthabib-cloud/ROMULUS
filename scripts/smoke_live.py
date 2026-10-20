"""Live smoke check: profile the first two configured index patterns, then normalize one window and report rates.

Usage: ROMULUS_HOME=<install> venv/bin/python app/scripts/smoke_live.py START END
"""
import os
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from romulus.config import load_settings
from romulus.evidence.normalize import normalize_hits
from romulus.sources.es import ElasticClient
from romulus.sources.execute import execute
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import build_profile

if len(sys.argv) != 3:
    sys.exit(__doc__)
s = load_settings(Path(os.environ.get("ROMULUS_HOME", str(Path.home() / "romulus"))) / ".env")
c = ElasticClient(s)
start, end = datetime.fromisoformat(sys.argv[1]), datetime.fromisoformat(sys.argv[2])
w = Window(start=start, end=end)
host_idx, net_idx = s.es_index_patterns
for idx in (host_idx, net_idx):
    prof, contract = build_profile(c, idx)
    print(f"profile {idx}: {prof.doc_count} docs, {len(contract.fields)} fields, notes={prof.notes}")
    agg = execute(c, SearchIntent(kind="aggregate", target=idx, window=w, group_by=["event.dataset"]), contract)
    print(f"  datasets in window ({agg.completeness}, {agg.reasons}):",
          {b['key']['event.dataset']: b['count'] for b in agg.buckets})
    filters = []
    if idx == host_idx:
        filters = [Predicate(field="event.dataset", op="in",
                             value=["linux.audit", "systemd.journal", "apache.access", "apache.error"])]
    t0 = time.time()
    out = execute(c, SearchIntent(kind="raw", target=idx, window=w, filters=filters, max_records=600_000), contract)
    t1 = time.time()
    hits = [{"_id": r["_id"], "_index": r["_index"], "_source": r["_source"]} for r in out.records]
    events, skips, errors = normalize_hits(hits)
    t2 = time.time()
    print(f"  raw: {out.returned}/{out.total} ({out.completeness} {out.reasons}) in {t1-t0:.1f}s; "
          f"normalized {len(events)} events in {t2-t1:.1f}s; errors={len(errors)}")
    print("  families:", dict(Counter(e.family for e in events)))
    print("  top skips:", dict(Counter(skips).most_common(8)))
    for rid, err in errors[:5]:
        print("  ERR", rid, err[:160])
    caveat = Counter(cv for e in events for cv in e.caveats)
    print("  caveats:", dict(caveat))
