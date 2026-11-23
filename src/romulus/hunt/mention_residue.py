"""The records of a target the sweep's own selection leaves out, read for the mention scan only.

The sweep fetches each target through a selection built for its rules (Linux datasets and content-selected text, the
Windows event classes and channels its rules read, the Zeek logs in the catalog). The records outside it are read by
no rule, which is exactly the text the mention lane exists to surface. After a target's partitions, this pass:

1. counts the window's records outside the selection exactly (`SearchIntent.excluding`: the very query the sweep
   compiled, negated, so the sweep and this pass together read every record of the window once). A count that is
   not exact leaves the sweep's left-out sources named as not offered, with why.
2. reads them, streamed page by page through a point in time (bounded memory), and offers each to the mention scan
   whole: none of them was normalized. Nothing here is normalized or evaluated by a rule, and nothing changes a
   finding, a lane or the detection coverage.
3. stays within a record budget per target (`Settings.mention_residue_records`). Within the budget every record is
   read. Past it, the records are counted by dataset (or channel, provider or module, whichever the target can
   count and search exactly), the smallest datasets are read whole first and the larger ones share what is left
   (each read from its earliest record); when no such key exists, the earliest records by time are read. Every
   record not read is counted per key and makes the pool partial, with the key named.

The pool's coverage holds one row per target (`MentionScanner.note_residue`): records outside the selection,
records read, and the keys not read in full. A target whose outside records were counted exactly no longer lists the
sweep's left-out datasets, shapes and channels as not offered: they are what this pass counted.
"""
from __future__ import annotations

from pydantic import ValidationError

from romulus.evidence.windows import is_windows_source
from romulus.hunt.controls import HuntStopped
from romulus.sources.compile import CompileError, compile_es
from romulus.sources.es import SourceError
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Selection

INTENT_MAX_RECORDS = SearchIntent.model_fields["max_records"].metadata[-1].le

RESIDUE_REASON = "outside the sweep's selection: no rule reads it"
# the keys a target's outside records are counted by when they exceed the budget
KEY_FIELDS = ("event.dataset", "event.channel", "event.provider", "event.module")
MAX_KEYS = 1_000
# keys not read in full named in the coverage row (every one is counted)
KEYS_NAMED = 50
NO_KEY = "(none)"
HISTOGRAM_SECONDS = 300


def allocate(counts: list[int], budget: int) -> list[int]:
    """Records to read per key: the smallest keys whole first, the rest sharing what is left equally."""
    order = sorted(range(len(counts)), key=lambda index: (counts[index], index))
    out = [0] * len(counts)
    left = budget
    for rank, index in enumerate(order):
        share = left // (len(order) - rank)
        out[index] = min(counts[index], share)
        left -= out[index]
    return out


def _exact_key_field(contract) -> str | None:
    """A field the target can count by and search one value of exactly: one native, no alternatives or subfields."""
    for name in KEY_FIELDS:
        spec = contract.spec(name)
        if (spec is not None and spec.aggregatable and not spec.alternatives and not spec.exact
                and len(spec.natives or (spec.native,)) == 1 and (spec.aggregation_native or spec.native) == spec.native
                and {"eq", "missing"} <= set(spec.ops)):
            return name
    return None


def _key_predicate(field: str, value) -> Predicate:
    return Predicate(field=field, op="missing") if value is None else Predicate(field=field, op="eq", value=value)


def _expanded(field: str, value) -> bool:
    """Whether an equality on this key compiles to more than that one value (a logical Linux dataset id, or a
    Suricata per-type dataset name, is expanded to its shipper shapes)."""
    from romulus.evidence.linux_catalog import LINUX_SHIPPER_DATASETS
    return field == "event.dataset" and isinstance(value, str) and (
        value in LINUX_SHIPPER_DATASETS or value.startswith("suricata.eve"))


class ResiduePass:
    """Reads one target's records outside the sweep's selection into the mention scan."""

    def __init__(self, sweep, target: str, filters: list[Predicate], any_of: list[list[Predicate]]):
        self.sweep, self.target = sweep, target
        self.contract = sweep.contracts[target]
        self.scanner = sweep.mentions
        self.excluding = Selection(filters=list(filters), any_of=[list(group) for group in any_of])
        settings = getattr(sweep.client, "settings", None)
        self.budget = int(getattr(settings, "mention_residue_records", 0) or 0)

    def _intent(self, kind: str, filters: list[Predicate] | None = None, **kw) -> SearchIntent:
        return SearchIntent(kind=kind, target=self.target, window=self.sweep.window, filters=filters or [],
                            excluding=self.excluding, purpose="mention residue", **kw)

    def run(self) -> None:
        scanner, target = self.scanner, self.target
        if not self.excluding.filters and not self.excluding.any_of:
            # the sweep reads every record of this target: nothing is outside its selection
            scanner.note_residue(target, records=0, read=0, counted=True)
            return
        try:
            counted = execute(self.sweep.client, self._intent("histogram", interval_seconds=HISTOGRAM_SECONDS),
                              self.contract)
        except (SourceError, CompileError, ValidationError) as error:
            scanner.note_residue(target, records=None, read=0, counted=False,
                                 reason=f"the records outside the sweep's selection could not be counted: {error}")
            return
        if (counted.completeness != Completeness.complete or counted.total_relation != "eq"
                or counted.total is None):
            why = "; ".join([*counted.reasons, *([counted.error] if counted.error else [])]) or "not exact"
            scanner.note_residue(target, records=None, read=0, counted=False,
                                 reason=f"the records outside the sweep's selection could not be counted ({why})"[:300])
            return
        total = int(counted.total)
        if total == 0:
            scanner.note_residue(target, records=0, read=0, counted=True)
            return
        if self.budget <= 0:
            scanner.note_residue(target, records=total, read=0, counted=True,
                                 reason="no budget for records outside the sweep's selection "
                                        "(ROMULUS_MENTION_RESIDUE_RECORDS is 0)")
            return
        # within the budget the read goes on to the end of its point in time, so a record indexed after the count
        # is read too; the point in time's own total is compared with the count
        plan = [(None, None, total, self.budget)]
        how = ""
        if total > self.budget:
            plan, how = self._plan(total)
        read = held_total = 0
        short: list[dict] = []
        problems: list[str] = []
        drift: list[str] = []
        for field, value, records, quota in plan:
            got, problem, seen = self._read(field, value, quota) if quota else (0, "", None)
            key = NO_KEY if field is not None and value is None else "(all)" if field is None else str(value)[:200]
            held = max(records, seen) if seen is not None else records
            held_total += held
            read += got
            if problem:
                problems.append(problem)
            if seen is not None and seen != records:
                drift.append(f"{key}: {seen:,} when read, {records:,} when counted")
            if got < held:
                short.append({"key": key, "key_field": field, "records": held, "read": got})
        reason = ""
        if read < held_total:
            reason = "; ".join([*([how] if how else []), *problems[:3]]) or "not read in full"
        note = ""
        if drift:
            note = ("the source's records outside the selection changed between the count and the read (records "
                    "indexed or removed meanwhile): " + "; ".join(drift[:5])
                    + (f" and {len(drift) - 5} more" if len(drift) > 5 else ""))
        scanner.note_residue(target, records=held_total, read=read, counted=True, reason=reason[:600],
                             short_keys=short, drift=note[:600])

    def _plan(self, total: int) -> tuple[list[tuple], str]:
        """(key field, key value, records, records to read) per key, and how the budget was shared."""
        field = _exact_key_field(self.contract)
        earliest = [(None, None, total, self.budget)]
        why_first = (f"budget {self.budget:,} of {total:,} records: the earliest records by time were read "
                     f"(no exactly searchable dataset, channel, provider or module field to share it by)")
        if field is None:
            return earliest, why_first
        try:
            out = execute(self.sweep.client, self._intent("aggregate", group_by=[field], max_records=MAX_KEYS),
                          self.contract)
        except (SourceError, CompileError, ValidationError):
            return earliest, why_first
        keys = [((bucket.get("key") or {}).get(field), int(bucket.get("count") or 0)) for bucket in out.buckets]
        if (out.completeness != Completeness.complete or sum(count for _key, count in keys) != total
                or any(_expanded(field, key) for key, _count in keys)):
            return earliest, why_first
        shares = allocate([count for _key, count in keys], self.budget)
        how = (f"budget {self.budget:,} of {total:,} records: shared by {field}, the smallest whole first, each "
               f"read from its earliest record")
        return [(field, key, count, share) for (key, count), share in zip(keys, shares, strict=True)], how

    def _read(self, field: str | None, value, quota: int) -> tuple[int, str, int | None]:
        """Stream up to `quota` records of one key into the scan, to the end of the point in time; (records read, a
        problem or "", the point in time's exact total or None when it gave none)."""
        sweep, scanner = self.sweep, self.scanner
        filters = [_key_predicate(field, value)] if field is not None else []
        try:
            # the intent's own record bound is the source layer's largest; the read itself streams to `quota`
            query = compile_es(self._intent("raw", filters, max_records=min(quota, INTENT_MAX_RECORDS)), self.contract,
                               sweep.client.settings.es_flavor)
        except (CompileError, ValidationError) as error:
            return 0, f"the read could not be compiled: {error}"[:300], None
        read = 0
        seen: int | None = None
        pages = sweep.client.iterate(query, quota)
        try:
            for hits, meta in pages:
                stop = getattr(sweep, "stop_check", None)
                if stop is not None and (stopped := stop()):
                    raise HuntStopped(stopped)
                sweep.heartbeat()
                if meta.get("total_relation") == "eq" and meta.get("total") is not None:
                    seen = int(meta["total"])
                entries = []
                for hit in hits[:quota - read]:
                    # the scan reads the record as it may be stored (lone surrogates replaced, credentials masked)
                    source = hit.get("_source")
                    record = {"_id": hit["_id"], "_index": hit["_index"], "_source": source}
                    entries.append((record, RESIDUE_REASON,
                                    is_windows_source(source) if isinstance(source, dict) else False))
                read += len(entries)
                try:
                    scanner.scan(self.target, self.contract, entries, None, residue=True)
                except Exception as exc:  # noqa: BLE001 - the mention pool never ends the sweep
                    scanner.note_scan_failure(self.target, f"residue:{field or 'all'}={value}", exc)
                if meta.get("problems"):
                    return read, "; ".join(meta["problems"])[:300], seen
                if read >= quota:
                    break
        except SourceError as error:
            return read, f"the read failed: {error}"[:300], seen
        finally:
            pages.close()
        return read, "", seen
