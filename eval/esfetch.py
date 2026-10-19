"""Read-only Elasticsearch fetch by document id, for funnel replay and citation source checks.

Only ``POST /<index>/_search`` with an ``ids`` query is issued (a read). Credentials come from an env file
given at run time and are never printed or logged.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import httpx

_INDEX = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def read_env(path: str | Path) -> dict[str, str]:
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def make_fetcher(env_path: str | Path, timeout: float = 120.0) -> Callable[[str, list[str]], list[dict]]:
    env = read_env(env_path)
    base = env["ES_URL"].rstrip("/")
    auth = (env["ES_USERNAME"], env["ES_PASSWORD"]) if env.get("ES_USERNAME") else None
    verify = env.get("ES_VERIFY_TLS", "true").lower() != "false"
    client = httpx.Client(auth=auth, verify=verify, timeout=timeout)

    def fetch(index: str, ids: list[str]) -> list[dict]:
        if not _INDEX.match(index):
            raise ValueError("refusing unexpected index name")
        out: list[dict] = []
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            r = client.post(f"{base}/{index}/_search", json={"size": len(chunk), "query": {"ids": {"values": chunk}}})
            r.raise_for_status()
            out += r.json()["hits"]["hits"]
        return out

    return fetch
