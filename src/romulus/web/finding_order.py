"""Bounded finding pages ordered by importance with validated opaque cursors."""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
from datetime import UTC, datetime

from sqlalchemy import Integer, String, and_, func, literal, literal_column, select

from romulus.store import schema as t


def finding_order(row=None, *, cursor=None):
    """Return SQL ordering, four logical cursor keys, and ordered seek ranges.

    Descending priorities naturally put NULL last in SQLite. A tilde sorts
    after every valid persisted ISO datetime, including the maximum year.
    This defines both presentation order and cursor comparisons in one place.
    """
    lanes = {"urgent": 0, "high": 1, "lead": 2}
    rank_sql = "CASE lane " + " ".join(f"WHEN '{lane}' THEN {rank}" for lane, rank in lanes.items())
    rank_sql += " ELSE 3 END"
    rank_key = literal_column(rank_sql, Integer)
    priority_key, id_key = t.candidate.c.priority, t.candidate.c.id
    time_key = literal_column("coalesce(ts, '~')", String)
    order = (rank_key, priority_key.desc(), time_key, id_key)
    values = cursor if cursor is not None else (
        (lanes.get(row["lane"], 3), row["priority"], row["ts"], row["id"]) if row is not None else None)
    if values is None:
        return order, None, None
    if not isinstance(values, (list, tuple)) or len(values) != 4:
        raise ValueError("invalid findings cursor")
    rank, priority, timestamp, row_id = values
    if type(rank) is not int or rank not in {*lanes.values(), 3}:
        raise ValueError("invalid findings cursor")
    if priority is not None:
        try:
            valid_priority = type(priority) in {int, float} and math.isfinite(priority)
        except (OverflowError, ValueError):
            valid_priority = False
        if type(priority) is int and not -(2**63) <= priority < 2**63:
            valid_priority = False
        if not valid_priority:
            raise ValueError("invalid findings cursor")
    if timestamp is not None:
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                raise ValueError("invalid findings cursor") from None
        if not isinstance(timestamp, datetime):
            raise ValueError("invalid findings cursor")
        if timestamp.tzinfo is not None:
            try:
                timestamp = timestamp.astimezone(UTC).replace(tzinfo=None)
            except (OverflowError, ValueError):
                raise ValueError("invalid findings cursor") from None
    if not isinstance(row_id, str) or not 1 <= len(row_id) <= 512 or "\0" in row_id:
        raise ValueError("invalid findings cursor")
    try:
        row_id.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid findings cursor") from None
    values = (rank, priority, timestamp, row_id)
    time_value = timestamp.isoformat(" ", timespec="microseconds") if timestamp else "~"
    equal_rank = rank_key == rank
    equal_priority = priority_key.is_(literal(None)) if priority is None else priority_key == priority
    ranges = [
        (3, and_(equal_rank, equal_priority, time_key == time_value, id_key > row_id)),
        (2, and_(equal_rank, equal_priority, time_key > time_value)),
    ]
    if priority is not None:
        ranges.extend([
            (1, and_(equal_rank, priority_key < priority)),
            # A bound NULL preserves SQLite's equality-index plan even when the
            # current schema declares priority NOT NULL; legacy shapes may not.
            (2, and_(equal_rank, priority_key.is_(literal(None)))),
        ])
    ranges.append((0, rank_key > rank))
    return order, values, ranges


def _decode_cursor(after):
    if not isinstance(after, str) or not 1 <= len(after) <= 2048 or not re.fullmatch(r"[A-Za-z0-9_-]+", after):
        raise ValueError("invalid findings cursor")
    try:
        raw = base64.b64decode(after + "=" * (-len(after) % 4), altchars=b"-_", validate=True)
        values = json.loads(raw)
    except (binascii.Error, UnicodeError, ValueError):
        raise ValueError("invalid findings cursor") from None
    if not isinstance(values, list) or len(values) != 4:
        raise ValueError("invalid findings cursor")
    return finding_order(cursor=values)[1]


def _encode_cursor(row):
    values = finding_order(row)[1]
    raw = json.dumps(values, default=lambda value: value.isoformat(timespec="microseconds"),
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def finding_page(repo, hunt_id, *, after="", limit=50, predicates=(), columns=None):
    """Fetch one importance-ordered page and count its remaining indexed range."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("invalid findings page limit")
    order = finding_order()[0]
    cursor = _decode_cursor(after) if after else None
    where = (t.candidate.c.hunt_id == hunt_id, *predicates)
    projection = list(columns or (t.candidate,))
    if columns:
        present = {column.key for column in columns}
        projection.extend(t.candidate.c[key] for key in ("lane", "priority", "ts", "id") if key not in present)
    with repo.engine.connect() as connection:
        rows = []
        # Separate ranges let SQLite use every equal prefix of the expression
        # index; a row-value comparison would rescan the hunt's earlier pages.
        ranges = finding_order(cursor=cursor)[2] if cursor is not None else [(0, True)]
        for start, remaining_range in ranges:
            rows.extend(dict(row) for row in connection.execute(select(*projection).where(
                *where, remaining_range).order_by(*order[start:]).limit(limit - len(rows))).mappings())
            if len(rows) == limit:
                break
        if not rows:
            return rows, 0, None
        through_ranges = finding_order(rows[-1])[2]
        remaining = sum(int(connection.execute(select(func.count()).select_from(t.candidate).where(
            t.candidate.c.hunt_id == hunt_id, *predicates, remaining_range
        )).scalar_one()) for _, remaining_range in through_ranges)
    return rows, remaining, _encode_cursor(rows[-1]) if remaining else None
