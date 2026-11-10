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


def _decode_values(after):
    if not isinstance(after, str) or not 1 <= len(after) <= 2048 or not re.fullmatch(r"[A-Za-z0-9_-]+", after):
        raise ValueError("invalid findings cursor")
    try:
        raw = base64.b64decode(after + "=" * (-len(after) % 4), altchars=b"-_", validate=True)
        values = json.loads(raw)
    except (binascii.Error, UnicodeError, ValueError):
        raise ValueError("invalid findings cursor") from None
    if not isinstance(values, list) or not values:
        raise ValueError("invalid findings cursor")
    return values


def _decode_cursor(after):
    values = _decode_values(after)
    if len(values) != 4:
        raise ValueError("invalid findings cursor")
    return finding_order(cursor=values)[1]


def _encode_values(values):
    raw = json.dumps(values, default=lambda value: value.isoformat(timespec="microseconds"),
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _encode_cursor(row):
    return _encode_values(list(finding_order(row)[1]))


def finding_page(repo, hunt_id, *, after="", limit=50, predicates=(), columns=None, lane=None):
    """Fetch one importance-ordered page and count its remaining indexed range. With `lane`, the page is bounded to
    that lane's rank in the order's own index, so a sparse lane reads only its rows rather than the whole hunt."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("invalid findings page limit")
    order = finding_order()[0]
    if lane is not None:
        rank = {"urgent": 0, "high": 1, "lead": 2}.get(lane)
        if rank is None:
            raise ValueError("invalid findings lane")
        predicates = (*predicates, order[0] == rank)
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
        if lane is not None and cursor is not None:
            # the last range is "a later rank"; a page bounded to one lane has none
            ranges = ranges[:-1]
        for start, remaining_range in ranges:
            rows.extend(dict(row) for row in connection.execute(select(*projection).where(
                *where, remaining_range).order_by(*order[start:]).limit(limit - len(rows))).mappings())
            if len(rows) == limit:
                break
        if not rows:
            return rows, 0, None
        through_ranges = finding_order(rows[-1])[2]
        if lane is not None:
            through_ranges = through_ranges[:-1]
        remaining = sum(int(connection.execute(select(func.count()).select_from(t.candidate).where(
            t.candidate.c.hunt_id == hunt_id, *predicates, remaining_range
        )).scalar_one()) for _, remaining_range in through_ranges)
    return rows, remaining, _encode_cursor(rows[-1]) if remaining else None


# -- report order -----------------------------------------------------------------------------------------------------
RANKED_LANES = ("urgent", "high", "lead")
# Report sections, in order; a finding stored after the last ranking pass (an AI agent's proposal) follows them all.
SECTIONS = ("confirmed", "reported", "ranked, not reported")
UNRANKED_SECTION = "not ranked (stored after the last ranking pass)"
_RANK_COLUMNS = ("section", "position", "score", "reported", "entity_kind", "entity")
_MAX_POSITION = 2**63


def _ranked_cursor(values):
    """("r", section, position) inside the ranked findings; ("t", shown, *finding_order keys) in the unranked tail,
    where `shown` counts the tail rows already listed."""
    if values[0] == "r" and len(values) == 3:
        section, position = values[1:]
        if type(section) is int and 0 <= section < len(SECTIONS) and type(position) is int \
                and 0 < position < _MAX_POSITION:
            return ("r", section, position)
    elif values[0] == "t" and len(values) == 6:
        shown = values[1]
        if type(shown) is int and 0 < shown < _MAX_POSITION:
            return ("t", shown, finding_order(cursor=values[2:])[1])
    raise ValueError("invalid findings cursor")


def ranked_finding_page(repo, hunt_id, *, pass_no, after="", limit=50, columns=None):
    """One page of a hunt's reportable findings in report order: confirmed, then reported, then ranked but not
    reported, each by rank position (`ix_finding_rank_section`); then every finding in a ranked lane that the pass
    did not rank, in `finding_order` (`ix_candidate_finding_order`). Returns (rows, remaining, cursor); each row carries
    its rank columns, None in the tail. Whether a next page exists is decided by reading one row past the page, so
    no finding is ever left unreachable; `remaining` counts the ranked rows left from the index plus the unranked
    ones (ranked-lane findings less ranked rows)."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("invalid findings page limit")
    cursor = _ranked_cursor(_decode_values(after)) if after else None
    rank, candidate = t.finding_rank, t.candidate
    projection = list(columns or (candidate,))
    present = {column.key for column in projection} if columns else set(candidate.c.keys())
    projection.extend(candidate.c[key] for key in ("lane", "priority", "ts", "id") if key not in present)
    order = finding_order()[0]
    in_ranked_lanes = order[0] < len(RANKED_LANES)
    unranked = ~select(1).where(rank.c.hunt_id == hunt_id, rank.c["pass"] == pass_no,
                                rank.c.candidate_id == candidate.c.id).exists()
    ranked_where = (rank.c.hunt_id == hunt_id, rank.c["pass"] == pass_no)
    want = limit + 1
    rows = []
    with repo.engine.connect() as connection:
        if cursor is None or cursor[0] == "r":
            ranges = [()] if cursor is None else [
                (rank.c.section == cursor[1], rank.c.position > cursor[2]), (rank.c.section > cursor[1],)]
            for remaining_range in ranges:
                rows.extend(dict(row) for row in connection.execute(
                    select(*projection, *(rank.c[key] for key in _RANK_COLUMNS))
                    .select_from(rank.join(candidate, candidate.c.id == rank.c.candidate_id))
                    .where(*ranked_where, *remaining_range)
                    .order_by(rank.c.section, rank.c.position).limit(want - len(rows))).mappings())
                if len(rows) == want:
                    break
        shown_before = cursor[1] if cursor is not None and cursor[0] == "t" else 0
        if len(rows) < want:
            tail_ranges = (finding_order(cursor=cursor[2])[2] if cursor is not None and cursor[0] == "t"
                           else [(0, True)])
            for start, remaining_range in tail_ranges:
                tail = connection.execute(select(*projection).where(
                    candidate.c.hunt_id == hunt_id, in_ranked_lanes, unranked, remaining_range,
                ).order_by(*order[start:]).limit(want - len(rows))).mappings()
                rows.extend({**row, **dict.fromkeys(_RANK_COLUMNS)} for row in tail)
                if len(rows) == want:
                    break
        more = len(rows) > limit
        rows = rows[:limit]
        if not rows:
            return rows, 0, None
        ranked_rows = int(connection.execute(select(func.count()).select_from(rank).where(*ranked_where)).scalar_one())
        lane_rows = int(connection.execute(select(func.count()).select_from(candidate).where(
            candidate.c.hunt_id == hunt_id, candidate.c.lane.in_(RANKED_LANES))).scalar_one())
        unranked_rows = max(0, lane_rows - ranked_rows)
        last = rows[-1]
        tail_shown = shown_before + sum(row["section"] is None for row in rows)
        if last["section"] is not None:
            # two seeks of the section index, as the page's own ranges are
            ranked_left = sum(int(connection.execute(select(func.count()).select_from(rank).where(
                *ranked_where, *remaining_range)).scalar_one()) for remaining_range in (
                    (rank.c.section == last["section"], rank.c.position > last["position"]),
                    (rank.c.section > last["section"],)))
            remaining = ranked_left + unranked_rows
            next_values = ["r", last["section"], last["position"]]
        else:
            remaining = unranked_rows - tail_shown
            next_values = ["t", tail_shown, *finding_order(last)[1]]
    remaining = max(remaining, 1) if more else 0
    return rows, remaining, _encode_values(next_values) if more else None
