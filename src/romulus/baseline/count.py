"""Pure, bounded counting of typed baseline keys into immutable segment rows."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from romulus.baseline.spec import (
    BaselineKey,
    BaselineSpec,
    KeyContext,
    Missing,
    NotApplicable,
    Pending,
)
from romulus.evidence.typed import TypedEvent

# One 120k-record physical partition can legitimately produce two keys per record. The token/pending caps
# therefore admit that full partition plus headroom; the row cap admits the required million-row segment.
# Crossing any cap makes the whole counter partial rather than silently approximating it.
DEFAULT_TOKEN_CAP = 250_000
DEFAULT_ROW_CAP = 1_000_000
DEFAULT_PENDING_CAP = 250_000


def _bucket(ts: datetime, width: str) -> datetime:
    value = ts.astimezone(UTC)
    if width == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    return value.replace(minute=0, second=0, microsecond=0)


class KeyCounter:
    """Count one spec's keys while bounding dedup state to the current bucket.

    The exact bound is ``token_cap`` distinct ``(scope, key_digest, token)``
    triples for one open bucket. Moving to the next bucket releases every token.
    Hitting the cap marks the counter partial; callers must not write its rows.

    With ``span`` (a segment's retrieval interval), every record counts in that segment: a record the source
    returned for the interval whose typed time lies outside it (shipping delay, clock skew) is counted at its
    time clamped into the interval, for its bucket, scope-hour and first/last times. It is never dropped and
    never makes the segment unwritable. Writers of the same hours must use the same rule.
    """

    def __init__(self, segment_id: str, spec: BaselineSpec, *,
                 token_cap: int = DEFAULT_TOKEN_CAP, row_cap: int = DEFAULT_ROW_CAP,
                 material_row_cap: int | None = None,
                 pending_cap: int = DEFAULT_PENDING_CAP,
                 span: tuple[datetime, datetime] | None = None,
                 retain_observations_when_partial: bool = False):
        material_row_cap = row_cap if material_row_cap is None else material_row_cap
        if min(token_cap, row_cap, material_row_cap, pending_cap) < 1:
            raise ValueError("counter caps must be positive")
        if span is not None and not span[0] < span[1]:
            raise ValueError("counter span must be nonempty")
        self.span = None if span is None else (span[0].astimezone(UTC), span[1].astimezone(UTC))
        self.segment_id = segment_id
        self.spec = spec
        self.token_cap = token_cap
        self.row_cap = row_cap
        self.material_row_cap = material_row_cap
        self.pending_cap = pending_cap
        self.retain_observations_when_partial = retain_observations_when_partial
        self._counts: dict[tuple, dict] = {}
        self._material_counts: dict[tuple, dict] = {}
        self._first_event_ids: dict[tuple, str | None] = {}
        self._first_event_refs: dict[tuple, list[dict]] = {}
        self._scope_hours: dict[tuple, int] = defaultdict(int)
        self._event_hours: dict[datetime, int] = defaultdict(int)
        self._scope_first_event_ids: dict[tuple, str | None] = {}
        self._scope_first_event_refs: dict[tuple, list[dict]] = {}
        self._tokens: dict[tuple, set[str]] = defaultdict(set)
        self._token_entries = 0
        self._open_bucket: datetime | None = None
        self._partial_reasons: set[str] = set()
        self._partial_hours: set[datetime] = set()
        self._whole_cell_partial = False
        self._pendings: list[Pending] = []
        self.max_token_entries = 0

    @property
    def partial(self) -> bool:
        return bool(self._partial_reasons)

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(sorted(self._partial_reasons))

    @property
    def partial_hours(self) -> tuple[datetime, ...]:
        return tuple(sorted(self._partial_hours))

    @property
    def whole_cell_partial(self) -> bool:
        return self._whole_cell_partial

    @property
    def pendings(self) -> tuple[Pending, ...]:
        return tuple(self._pendings)

    def take_pendings(self) -> tuple[Pending, ...]:
        """Return and release compact unresolved children before persistence."""
        pending, self._pendings = tuple(self._pendings), []
        return pending

    def mark_partial(self, reason: str, ts: datetime | None = None) -> None:
        """Make incompleteness explicit; partial counters never expose rows."""
        self._partial_reasons.add(reason)
        if ts is None:
            self._whole_cell_partial = True
        else:
            self._partial_hours.add(_bucket(ts, "hour"))

    @property
    def token_entries(self) -> int:
        return self._token_entries

    def bind_segment(self, segment_id: str) -> None:
        """Bind staged counts to their content-derived segment id before persistence."""
        if not segment_id:
            raise ValueError("segment id must be non-empty")
        self.segment_id = segment_id
        for row in self._counts.values():
            row["segment_id"] = segment_id
        for row in self._material_counts.values():
            row["segment_id"] = segment_id

    def restore(self, count_rows: Iterable[dict], scope_hour_rows: Iterable[dict]) -> None:
        """Reload staged rows of this counter's segment so resolved keys can be added to them.

        Dedup tokens are not staged, so a restored counter is only for keys counted once per record (a resolved
        exec-pair key carries no token). The open bucket is the latest restored one, as when they were counted.
        """
        for row in count_rows:
            identity = (row["scope_kind"], row["scope"], row["key_digest"], row["bucket"])
            material_hour = row.get("material_hour") or _bucket(row["first_ts"], "hour")
            source = {name: value for name, value in row.items() if name != "material_hour"}
            existing = self._counts.get(identity)
            if existing is None:
                self._counts[identity] = {**source, "segment_id": self.segment_id}
            else:
                existing["count"] += int(source["count"])
                existing["first_ts"] = min(existing["first_ts"], source["first_ts"])
                existing["last_ts"] = max(existing["last_ts"], source["last_ts"])
            material_identity = (*identity, material_hour)
            self._material_counts[material_identity] = {
                **source, "segment_id": self.segment_id, "material_hour": material_hour,
            }
            self._first_event_ids[identity] = None
            self._first_event_refs[identity] = []
            if self._open_bucket is None or row["bucket"] > self._open_bucket:
                self._open_bucket = row["bucket"]
        for row in scope_hour_rows:
            self._scope_hours[(row["scope_kind"], row["scope"], row["hour"])] += int(row["events"])

    def consume(self, event: TypedEvent, context: KeyContext) -> None:
        if self.partial and not self.retain_observations_when_partial:
            return
        instant = event.ts.astimezone(UTC)
        if self.span is not None:
            instant = min(max(instant, self.span[0]), self.span[1] - timedelta(microseconds=1))
        event_hour = _bucket(instant, "hour")
        if event_hour not in self._event_hours and len(self._event_hours) >= self.row_cap:
            self.mark_partial(f"event-hour row cap {self.row_cap} exceeded")
            if not self.retain_observations_when_partial:
                return
        else:
            self._event_hours[event_hour] += 1
        result = self.spec.keys(event, context)
        if isinstance(result, Missing):
            self.mark_partial(f"{event.id}: {result.reason}", event.ts)
        elif isinstance(result, Pending):
            result = replace(result, raw_refs=tuple((ref.target, ref.native_id) for ref in event.raw))
            if len(self._pendings) >= self.pending_cap:
                self.mark_partial(f"pending parent cap {self.pending_cap} exceeded")
            else:
                self._pendings.append(result)
        elif not isinstance(result, NotApplicable):
            self.add_keys(
                event.ts, result, event_id=event.id,
                event_refs=[{"target": ref.target, "native_id": ref.native_id} for ref in event.raw],
            )

    def add_keys(self, ts: datetime, keys: Iterable[BaselineKey], *, event_id: str | None = None,
                 event_refs: list[dict] | None = None) -> None:
        keys = list({key.key_digest: key for key in keys}.values())
        if not keys or (self.partial and not self.retain_observations_when_partial):
            return
        if self.span is not None:
            ts = min(max(ts.astimezone(UTC), self.span[0]), self.span[1] - timedelta(microseconds=1))
        event_scopes = {(key.scope_kind, key.scope) for key in keys}
        bucket = _bucket(ts, self.spec.bucket)
        if self._open_bucket is None or bucket > self._open_bucket:
            self._tokens.clear()
            self._token_entries = 0
            self._open_bucket = bucket
        elif bucket < self._open_bucket:
            self.mark_partial("events arrived after their bucket was closed")
            return

        identities = {
            (key.scope_kind, key.scope, key.key_digest, bucket) for key in keys
            if (key.scope_kind, key.scope, key.key_digest, bucket) not in self._counts
        }
        if len(self._counts) + len(identities) > self.row_cap:
            self.mark_partial(f"count row cap {self.row_cap} exceeded")
            return
        hour = _bucket(ts, "hour")
        scope_identities = {
            (scope_kind, scope, hour) for scope_kind, scope in event_scopes
            if (scope_kind, scope, hour) not in self._scope_hours
        }
        if len(self._scope_hours) + len(scope_identities) > self.row_cap:
            self.mark_partial(f"scope-hour row cap {self.row_cap} exceeded")
            return

        accepted: list[BaselineKey] = []
        for key in sorted(keys, key=lambda item: (item.scope_kind, item.scope, item.key_digest)):
            if key.dedup_token is not None:
                token_key = (key.scope_kind, key.scope, key.key_digest, bucket)
                tokens = self._tokens[token_key]
                if key.dedup_token in tokens:
                    row = self._counts.get((key.scope_kind, key.scope, key.key_digest, bucket))
                    if row is not None:
                        instant = ts.astimezone(UTC)
                        identity = (key.scope_kind, key.scope, key.key_digest, bucket)
                        if (instant, event_id or "") < (row["first_ts"], self._first_event_ids[identity] or ""):
                            self._first_event_ids[identity] = event_id
                            self._first_event_refs[identity] = list(event_refs or [])
                        row["first_ts"] = min(row["first_ts"], instant)
                        row["last_ts"] = max(row["last_ts"], instant)
                    continue
                if self.token_entries >= self.token_cap:
                    self.mark_partial(
                        f"dedup token cap {self.token_cap} exceeded in an open bucket",
                    )
                    return
                tokens.add(key.dedup_token)
                self._token_entries += 1
                self.max_token_entries = max(self.max_token_entries, self.token_entries)
            accepted.append(key)

        material_identities = {
            (key.scope_kind, key.scope, key.key_digest, bucket, hour) for key in accepted
            if (key.scope_kind, key.scope, key.key_digest, bucket, hour) not in self._material_counts
        }
        if len(self._material_counts) + len(material_identities) > self.material_row_cap:
            self.mark_partial(f"material count row cap {self.material_row_cap} exceeded")
            return

        for key in accepted:
            identity = (key.scope_kind, key.scope, key.key_digest, bucket)
            row = self._counts.get(identity)
            if row is None:
                self._counts[identity] = {
                    "segment_id": self.segment_id,
                    "scope_kind": key.scope_kind,
                    "scope": key.scope,
                    "key_id": key.key_id,
                    "key_digest": key.key_digest,
                    "key": key.key,
                    "bucket": bucket,
                    "count": 1,
                    "first_ts": ts.astimezone(UTC),
                    "last_ts": ts.astimezone(UTC),
                }
                self._first_event_ids[identity] = event_id
                self._first_event_refs[identity] = list(event_refs or [])
            else:
                instant = ts.astimezone(UTC)
                if (instant, event_id or "") < (row["first_ts"], self._first_event_ids[identity] or ""):
                    self._first_event_ids[identity] = event_id
                    self._first_event_refs[identity] = list(event_refs or [])
                row["count"] += 1
                row["first_ts"] = min(row["first_ts"], instant)
                row["last_ts"] = max(row["last_ts"], instant)

            material_identity = (key.scope_kind, key.scope, key.key_digest, bucket, hour)
            material = self._material_counts.get(material_identity)
            if material is None:
                self._material_counts[material_identity] = {
                    "segment_id": self.segment_id,
                    "scope_kind": key.scope_kind,
                    "scope": key.scope,
                    "key_id": key.key_id,
                    "key_digest": key.key_digest,
                    "key": key.key,
                    "bucket": bucket,
                    "material_hour": hour,
                    "count": 1,
                    "first_ts": ts.astimezone(UTC),
                    "last_ts": ts.astimezone(UTC),
                }
            else:
                instant = ts.astimezone(UTC)
                material["count"] += 1
                material["first_ts"] = min(material["first_ts"], instant)
                material["last_ts"] = max(material["last_ts"], instant)

        for scope_kind, scope in sorted(event_scopes):
            identity = (scope_kind, scope, hour)
            self._scope_hours[identity] += 1
            current_id = self._scope_first_event_ids.get(identity)
            if identity not in self._scope_first_event_ids or (
                    event_id is not None and (current_id is None or event_id < current_id)):
                self._scope_first_event_ids[identity] = event_id
                self._scope_first_event_refs[identity] = list(event_refs or [])

    def count_rows(self):
        if self.partial:
            return iter(())
        return iter(self._counts[key] for key in sorted(self._counts))

    def material_count_rows(self):
        """Per-hour count material for a hunt writer; merging all hours reproduces :meth:`count_rows`."""
        if self.partial:
            return iter(())
        return iter(self._material_counts[key] for key in sorted(self._material_counts))

    def event_hour_rows(self):
        """Per-hour evaluated-record totals used for segment metadata at non-aligned cell edges."""
        if self.partial:
            return iter(())
        return iter({"segment_id": self.segment_id, "hour": hour, "events": self._event_hours[hour]}
                    for hour in sorted(self._event_hours))

    def scope_hour_rows(self, *, include_witnesses: bool = False):
        if self.partial:
            return iter(())
        def row(identity):
            scope_kind, scope, hour = identity
            item = {
                "segment_id": self.segment_id,
                "scope_kind": scope_kind,
                "scope": scope,
                "hour": hour,
                "events": self._scope_hours[identity],
            }
            if include_witnesses:
                item.update(
                    first_event_id=self._scope_first_event_ids.get(identity),
                    first_event_refs=self._scope_first_event_refs.get(identity, []),
                )
            return item
        return iter(row(identity) for identity in sorted(self._scope_hours))

    def observation_rows(self):
        """Window observations accumulated so far, including countable keys from a partial cell.

        Immutable history segments still refuse every row when partial through :meth:`count_rows`. Window
        observations are positive facts and remain useful even when another record made the cell incomplete;
        their enclosing rule cell carries the partial reason, so they can never support a complete negative.
        """
        combined: dict[tuple[str, str, str], dict] = {}
        for identity in sorted(self._counts):
            scope_kind, scope, key_digest, _bucket_value = identity
            source = self._counts[identity]
            key = (scope_kind, scope, key_digest)
            row = combined.get(key)
            event_id = self._first_event_ids[identity]
            if row is None:
                combined[key] = {
                    "scope_kind": scope_kind,
                    "scope": scope,
                    "key_id": source["key_id"],
                    "key_digest": key_digest,
                    "key": source["key"],
                    "window_count": source["count"],
                    "first_ts": source["first_ts"],
                    "last_ts": source["last_ts"],
                    "first_event_id": event_id,
                    "first_event_refs": self._first_event_refs.get(identity, []),
                }
                continue
            if (source["first_ts"], event_id or "") < (row["first_ts"], row["first_event_id"] or ""):
                row["first_event_id"] = event_id
                row["first_event_refs"] = self._first_event_refs.get(identity, [])
            row["window_count"] += source["count"]
            row["first_ts"] = min(row["first_ts"], source["first_ts"])
            row["last_ts"] = max(row["last_ts"], source["last_ts"])
        return iter(combined[key] for key in sorted(combined))
