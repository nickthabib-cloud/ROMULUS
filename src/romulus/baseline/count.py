"""Pure, bounded counting of typed baseline keys into immutable segment rows."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime

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
    """

    def __init__(self, segment_id: str, spec: BaselineSpec, *,
                 token_cap: int = DEFAULT_TOKEN_CAP, row_cap: int = DEFAULT_ROW_CAP,
                 pending_cap: int = DEFAULT_PENDING_CAP):
        if min(token_cap, row_cap, pending_cap) < 1:
            raise ValueError("counter caps must be positive")
        self.segment_id = segment_id
        self.spec = spec
        self.token_cap = token_cap
        self.row_cap = row_cap
        self.pending_cap = pending_cap
        self._counts: dict[tuple, dict] = {}
        self._scope_hours: dict[tuple, int] = defaultdict(int)
        self._tokens: dict[tuple, set[str]] = defaultdict(set)
        self._token_entries = 0
        self._open_bucket: datetime | None = None
        self._partial_reasons: set[str] = set()
        self._pendings: list[Pending] = []
        self.max_token_entries = 0

    @property
    def partial(self) -> bool:
        return bool(self._partial_reasons)

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(sorted(self._partial_reasons))

    @property
    def pendings(self) -> tuple[Pending, ...]:
        return tuple(self._pendings)

    def take_pendings(self) -> tuple[Pending, ...]:
        """Return and release compact unresolved children before persistence."""
        pending, self._pendings = tuple(self._pendings), []
        return pending

    def mark_partial(self, reason: str) -> None:
        """Make incompleteness explicit; partial counters never expose rows."""
        self._partial_reasons.add(reason)

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

    def consume(self, event: TypedEvent, context: KeyContext) -> None:
        if self.partial:
            return
        result = self.spec.keys(event, context)
        if isinstance(result, Missing):
            self.mark_partial(f"{event.id}: {result.reason}")
        elif isinstance(result, Pending):
            if len(self._pendings) >= self.pending_cap:
                self.mark_partial(f"pending parent cap {self.pending_cap} exceeded")
            else:
                self._pendings.append(result)
        elif not isinstance(result, NotApplicable):
            self.add_keys(event.ts, result)

    def add_keys(self, ts: datetime, keys: Iterable[BaselineKey]) -> None:
        keys = list({key.key_digest: key for key in keys}.values())
        if not keys or self.partial:
            return
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
            else:
                row["count"] += 1
                row["first_ts"] = min(row["first_ts"], ts.astimezone(UTC))
                row["last_ts"] = max(row["last_ts"], ts.astimezone(UTC))

        for scope_kind, scope in sorted(event_scopes):
            self._scope_hours[(scope_kind, scope, hour)] += 1

    def count_rows(self):
        if self.partial:
            return iter(())
        return iter(self._counts[key] for key in sorted(self._counts))

    def scope_hour_rows(self):
        if self.partial:
            return iter(())
        return iter({
            "segment_id": self.segment_id,
            "scope_kind": scope_kind,
            "scope": scope,
            "hour": hour,
            "events": self._scope_hours[(scope_kind, scope, hour)],
        } for scope_kind, scope, hour in sorted(self._scope_hours))
