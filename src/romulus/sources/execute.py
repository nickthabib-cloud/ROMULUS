"""Execute compiled intents against a source and produce complete-or-explicitly-partial outcomes."""
from __future__ import annotations

from datetime import UTC, datetime

from romulus.sources.compile import compile_es
from romulus.sources.es import ElasticClient, SourceError
from romulus.sources.models import Completeness, SearchIntent, SearchOutcome
from romulus.sources.profile import FieldContract

MAX_COMPOSITE_PAGES = 500


def execute(client: ElasticClient, intent: SearchIntent, contract: FieldContract, *, pit=None) -> SearchOutcome:
    q = compile_es(intent, contract, client.settings.es_flavor)
    started = datetime.now(UTC)

    def outcome(**kw) -> SearchOutcome:
        return SearchOutcome(target=intent.target, fingerprint=q.fingerprint, started_at=started,
                             ended_at=datetime.now(UTC), backend_version=client.version, **kw)

    try:
        if intent.kind == "raw":
            records, reasons, total, rel = [], [], None, "unknown"
            for hits, meta in client.iterate(q, intent.max_records, pit=pit):
                reasons += meta["problems"]
                total, rel = meta["total"], meta["total_relation"]
                records += [{
                    "_id": h["_id"], "_index": h["_index"], "_source": h["_source"],
                    "_sort": h.get("sort"),
                } for h in hits]
            if total is not None and len(records) < total:
                reasons.append(f"cap:{intent.max_records}<total:{total}")
            if rel != "eq":
                reasons.append(f"total_relation:{rel}")
            return outcome(completeness=Completeness.partial if reasons else Completeness.complete,
                           reasons=sorted(set(reasons)), total=total, total_relation=rel,
                           returned=len(records), records=records)

        if intent.kind == "aggregate":
            buckets, reasons, total, rel = [], [], None, "unknown"
            body = q.body
            for _ in range(MAX_COMPOSITE_PAGES):
                d = client.search(q.target, body)
                if d.get("timed_out"):
                    reasons.append("timed_out")
                if d.get("_shards", {}).get("failed"):
                    reasons.append("shard_failures")
                t = d.get("hits", {}).get("total", {})
                total, rel = t.get("value"), t.get("relation", "unknown")
                agg = d.get("aggregations", {}).get("g", {})
                for b in agg.get("buckets", []):
                    buckets.append({"key": b["key"], "count": b["doc_count"],
                                    "first": b.get("first", {}).get("value_as_string"),
                                    "last": b.get("last", {}).get("value_as_string")})
                after = agg.get("after_key")
                if not after or not agg.get("buckets"):
                    break
                body = {**body, "aggs": {"g": {**body["aggs"]["g"],
                                               "composite": {**body["aggs"]["g"]["composite"], "after": after}}}}
            else:
                reasons.append(f"composite_page_cap:{MAX_COMPOSITE_PAGES}")
            if sum(b["count"] for b in buckets) != (total or 0) and rel == "eq":
                reasons.append("bucket_sum_mismatch")
            return outcome(completeness=Completeness.partial if reasons else Completeness.complete,
                           reasons=sorted(set(reasons)), total=total, total_relation=rel,
                           returned=len(buckets), buckets=buckets)

        if intent.kind == "histogram":
            shell, d = client.run(q)
            if d is None:
                return shell
            buckets = [{"key": b["key_as_string"], "count": b["doc_count"]}
                       for b in d.get("aggregations", {}).get("h", {}).get("buckets", [])]
            return shell.model_copy(update={"buckets": buckets, "returned": len(buckets)})
    except SourceError as e:
        return outcome(completeness=Completeness.failed, reasons=["source_error"], error=str(e))
    raise ValueError(intent.kind)
