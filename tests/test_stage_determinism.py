"""Fresh interpreters exercise real stage admission with effective hash seeds."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest


def scenario(kind, total, directory):
    from romulus.detect.bounded import StateBudget
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import _complete, _repo
    from tests.test_windows_c_burst_review import START
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sw, "state_budget", lambda settings, stage_dir: StateBudget(stage_dir, disk_total=total, reserve=0))
        if kind == "linux":
            from tests import throughput_fixture as tf
            tf.patched_sizes(patch)
            snapshot = tf.run_stack(directory, docs=tf.build(1))
            return {"count": len(snapshot["candidates"]), "digest": tf.digests(snapshot)["candidates"]}
        if kind == "ioc":
            from tests.test_bounded_starvation import _Listed
            from tests.test_windows_c_round4 import dns
            rule = _Listed()
            pairs = [dns(n, f"seed{n}.c2.test", pad=4000) for n in range(151)]
        else:
            from romulus.detect.windows_auth_events import WindowsKerberoastDiversity, WindowsPasswordSpray
            from tests.test_windows_c_round3_storage import native_ticket
            rule = WindowsKerberoastDiversity() if kind == "auth" else WindowsPasswordSpray()
            if kind == "auth":
                pairs = [native_ticket(n, f"u{n%50}", f"host/s{n%7}", n) for n in range(4000)]
                pairs += [native_ticket(90000+n, "late", f"mssql/db{n}", 9000+n) for n in range(10)]
            else:
                from romulus.evidence.windows import normalize_windows
                from romulus.evidence.windows_catalog import SECURITY
                from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
                pairs = []
                for n in range(4000):
                    source = f"10.1.{n//250%250}.{n%250}" if n < 3900 else "203.0.113.5"
                    logical = LogicalWindowsEvent("Security", SECURITY, 4625, "dc01.example.test", 200000+n,
                        (START+timedelta(seconds=n)).isoformat().replace("+00:00", "Z"),
                        {"TargetUserName": f"user{n%3000}", "TargetDomainName": "EXAMPLE", "IpAddress": source,
                         "Status": "0xc000006d", "SubStatus": "0xc000006a", "LogonType": "3"})
                    hit = windows_hit(logical, "winlogbeat_8")
                    pairs.append((normalize_windows(hit), hit))
        patch.setattr(sw, "fresh_pack", lambda: [rule])
        repo = _repo()
        sweep = sw.Sweep(repo, None, "h1", Window(start=START, end=START+timedelta(days=1)), {}, stage_dir=directory)
        try:
            for start in range(0, len(pairs), 100):
                batch = pairs[start:start+100]
                patch.setattr(sw, "execute", lambda client, intent, contract, batch=batch:
                              _complete(intent, [hit for _, hit in batch]))
                sweep.run_partition(batch[0][1]["_index"], None, [],
                    Window(start=batch[0][0].ts, end=batch[-1][0].ts+timedelta(seconds=1)), est=len(batch))
            sweep.finalize()
            rows = repo.candidates("h1")
            projection = [{key: row[key] for key in ("id", "rule_id", "lane", "claim", "event_ids", "group_key")}
                          for row in sorted(rows, key=lambda item: item["id"])]
            return {"count": len(rows), "digest": hashlib.sha256(
                json.dumps(projection, sort_keys=True, default=str).encode()).hexdigest()}
        finally:
            sweep.close_stage()
            repo.engine.dispose()


@pytest.mark.parametrize(("kind", "total"), [("linux", 4*2**20), ("linux", 8*2**20),
    ("ioc", 400000), ("auth", 2*2**20), ("spray", 2*2**20)])
def test_stage_candidates_identical_with_real_hash_seeds(kind, total):
    results = []
    root = Path(__file__).resolve().parents[1]
    for seed in (0, 2, 6):
        env = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": os.pathsep.join((str(root/"src"), str(root)))}
        completed = subprocess.run([sys.executable, "-m", "tests.test_stage_determinism", kind, str(total)],
            env=env, cwd=root, capture_output=True, text=True, check=True, timeout=180)
        result = json.loads(completed.stdout)
        assert result.pop("seed") == str(seed)
        assert result.pop("hash_randomization") == int(seed != 0)
        results.append(result)
    assert results[0] == results[1] == results[2]
    assert results[0]["count"] >= (35 if kind == "linux" else 151 if kind == "ioc" else 1)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temporary:
        result = scenario(sys.argv[1], int(sys.argv[2]), Path(temporary))
    print(json.dumps({**result, "seed": os.environ.get("PYTHONHASHSEED"),
                      "hash_randomization": sys.flags.hash_randomization}, sort_keys=True))
