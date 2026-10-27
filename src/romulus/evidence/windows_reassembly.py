"""Bounded, disk-backed PowerShell script-block reassembly."""

from __future__ import annotations

import contextlib
import hashlib
import json
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from romulus.detect.bounded import StateBudget
from romulus.evidence.typed import RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows import SCRIPT_BLOCK_MAX_PARTS, WINDOWS_NORMALIZER

if TYPE_CHECKING:
    from romulus.detect.bounded import Account


SCRIPT_TEXT_CAP = 1_048_576
SCRIPT_FINALIZE_BATCH_SIZE = 128
SCRIPT_JOINED_REFS = SCRIPT_BLOCK_MAX_PARTS
SCRIPT_SOURCE_PAGE = 128


class ScriptBlockAssembler:
    """Retain one row per block/part and emit a block exactly once.

    The database is private to one sweep or pivot operation. Completed and incomplete keys remain present until
    close, so out-of-order duplicates cannot make an already-emitted block appear new again.
    """

    def __init__(
        self,
        directory: str | Path | None = None,
        *,
        text_cap: int = SCRIPT_TEXT_CAP,
        max_bytes: int | None = None,
        budget: StateBudget | None = None,
        account: Account | None = None,
    ) -> None:
        self._tempdir = Path(tempfile.mkdtemp(prefix="romulus-script-blocks-")) if directory is None else None
        root = self._tempdir if self._tempdir is not None else Path(directory)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self.path = root / "windows-script-blocks.db"
        self.db = sqlite3.connect(self.path)
        self.path.chmod(0o600)
        self.text_cap = max(1, int(text_cap))
        self.budget = budget if budget is not None else StateBudget(root)
        self.account = account if account is not None else self.budget.account("windows_scripts")
        self.max_bytes = max(1, int(max_bytes if max_bytes is not None else self.budget.disk_total))
        self.refusal_reason = ""
        self._refusal_reasons: dict[str, None] = {}
        self.partial_reasons: list[str] = []
        # A present key with None records that an emitted ref had no source body. Keeping the sentinel until
        # sources_for() drains it lets finalized batches avoid rescanning every still-pending refs row.
        self._emitted_sources: dict[str, dict | None] = {}
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS blocks ("
            "host TEXT NOT NULL, block_id TEXT NOT NULL, total INTEGER NOT NULL, base_number INTEGER NOT NULL, "
            "base_event TEXT NOT NULL, conflicts TEXT NOT NULL, emitted INTEGER NOT NULL DEFAULT 0, "
            "latest_ts TEXT NOT NULL, "
            "PRIMARY KEY (host, block_id)) WITHOUT ROWID;"
            "CREATE TABLE IF NOT EXISTS parts ("
            "host TEXT NOT NULL, block_id TEXT NOT NULL, number INTEGER NOT NULL, text TEXT NOT NULL, "
            "text_digest TEXT NOT NULL, event_id TEXT NOT NULL, "
            "PRIMARY KEY (host, block_id, number)) WITHOUT ROWID;"
            "CREATE TABLE IF NOT EXISTS refs ("
            "host TEXT NOT NULL, block_id TEXT NOT NULL, number INTEGER NOT NULL, target TEXT NOT NULL, "
            "native_id TEXT NOT NULL, digest TEXT NOT NULL, source TEXT, "
            "PRIMARY KEY (host, block_id, target, native_id)) WITHOUT ROWID;"
            "CREATE INDEX IF NOT EXISTS refs_native ON refs(target, native_id);"
        )
        self.db.commit()
        self.db.execute("PRAGMA cache_size = -4096")
        self._page = int(self.db.execute("PRAGMA page_size").fetchone()[0])
        self._size = self._db_size()
        if self._size > self.max_bytes:
            self.refusal_reason = (
                f"script-block reassembly database floor {self._size} exceeds cap {self.max_bytes} bytes"
            )
            self._refusal_reasons[self.refusal_reason] = None
        else:
            headroom = self.budget.headroom()
            ceiling = self.max_bytes if headroom is None else min(self.max_bytes, self._size + headroom)
            pages = max(1, ceiling // self._page)
            self.db.execute(f"PRAGMA max_page_count = {pages}")
        if self.budget is not None and self.account is not None:
            self.budget.charge(self.account, self._size)
            self.budget.grew(self._size)

    def _db_size(self) -> int:
        return int(self.db.execute("PRAGMA page_count").fetchone()[0]) * self._page

    def _checkpoint(self, *, commit: bool = True) -> None:
        if commit:
            self.db.commit()
        size = self._db_size()
        growth = size - self._size
        if growth > 0 and self.budget is not None and self.account is not None:
            self.budget.charge(self.account, growth)
            self.budget.grew(growth)
        self._size = size
        if size > self.max_bytes:
            self.refusal_reason = f"script-block reassembly state exceeded {self.max_bytes} bytes"
            self._refusal_reasons[self.refusal_reason] = None

    @property
    def refusal_reasons(self) -> tuple[str, ...]:
        """Every distinct state refusal observed by this assembler."""
        return tuple(self._refusal_reasons)

    def _note_partial(self, reason: str) -> None:
        if reason not in self.partial_reasons:
            self.partial_reasons.append(reason)

    def _note_refusal(self, reason: str) -> None:
        self._refusal_reasons.setdefault(reason, None)
        self._note_partial(f"PowerShell script-block reassembly state refused: {reason}")

    @staticmethod
    def _text_digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _part_key(event: TypedEvent) -> tuple[str, str, int, int] | None:
        if event.family != "script_block" or event.get("event.code") != 4104:
            return None
        host = str(event.host or "").strip().casefold()
        block = str(event.get("script.block_id") or "").strip().casefold()
        number = event.get("script.message_number")
        total = event.get("script.message_total")
        if (not host or not block or not isinstance(number, int) or isinstance(number, bool)
                or not isinstance(total, int) or isinstance(total, bool)
                or number < 1 or total < 1 or number > total or total > SCRIPT_BLOCK_MAX_PARTS):
            return None
        return host, block, number, total

    @staticmethod
    def _partial(event: TypedEvent, reason: str) -> TypedEvent:
        result = event.model_copy(deep=True)
        origin = result.fields.get("script.text") or result.fields["event.code"]
        result.fields["script.complete"] = fv(False, origin.origin + "#reassembly-refused")
        result.caveats.append(f"script block reassembly state refused: {reason}")
        return result

    @staticmethod
    def _conflicted(event: TypedEvent, reasons: list[str]) -> TypedEvent:
        result = event.model_copy(deep=True)
        origin = result.fields.get("script.text") or result.fields["event.code"]
        result.fields["script.complete"] = fv(False, origin.origin + "#reassembly-conflict")
        result.caveats.extend(reasons)
        return result

    @staticmethod
    def _incomplete_metadata(event: TypedEvent) -> TypedEvent:
        result = event.model_copy(deep=True)
        origin = result.fields.get("script.text") or result.fields["event.code"]
        result.fields["script.complete"] = fv(False, origin.origin + "#reassembly-invalid-metadata")
        caveat = "script block part metadata is incomplete or invalid"
        if caveat not in result.caveats:
            result.caveats.append(caveat)
        total = result.get("script.message_total")
        if (isinstance(total, int) and not isinstance(total, bool)
                and total > SCRIPT_BLOCK_MAX_PARTS):
            limit = f"script block part count exceeds supported maximum {SCRIPT_BLOCK_MAX_PARTS}"
            if limit not in result.caveats:
                result.caveats.append(limit)
        return result

    def _budget_reason(self, *, new_key: bool) -> str:
        if self.refusal_reason:
            return self.refusal_reason
        if new_key and self.budget is not None and self.account is not None:
            return str(self.budget.new_key_reason(self.account) or "")
        if self.budget is not None and self.budget.hard:
            return str(self.budget.hard)
        return ""

    def consume(self, events: list[TypedEvent], raw_sources: dict[str, dict] | None = None) -> list[TypedEvent]:
        """Stream part views with the input batch, and add each completed bounded join once.

        Every multipart record is independently evaluable immediately. Joins can therefore cap text without
        hiding a middle part from rules. A record matching across a boundary beyond the joined prefix remains
        unresolved; the fragment views do not pretend to preserve such cross-part matches.
        """
        raw_sources = raw_sources or {}
        self.partial_reasons = []
        output: list[TypedEvent] = []
        self.db.execute("BEGIN")
        for event in events:
            key = self._part_key(event)
            if key is None:
                if event.family == "script_block" and event.get("event.code") == 4104:
                    output.append(self._incomplete_metadata(event))
                else:
                    output.append(event)
                continue
            host, block, number, total = key
            row = self.db.execute(
                "SELECT total, base_number, base_event, conflicts, emitted, latest_ts FROM blocks "
                "WHERE host = ? AND block_id = ?", (host, block),
            ).fetchone()
            reason = self._budget_reason(new_key=row is None)
            if reason:
                self._note_refusal(reason)
                output.append(self._partial(event, reason))
                continue
            try:
                self.db.execute("SAVEPOINT script_part")
                base = event.model_copy(deep=True)
                base.fields.pop("windows.event_data.ScriptBlockText", None)
                if "script.text" in base.fields:
                    base.fields["script.text"] = fv("", base.fields["script.text"].origin)
                if row is None:
                    self.db.execute(
                        "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                        (host, block, total, number, base.model_dump_json(), "[]", event.ts.isoformat()),
                    )
                    stored_total, base_number, conflicts, emitted = total, number, [], 0
                else:
                    stored_total, base_number, _base_event, conflicts_json, emitted, latest_ts = row
                    if emitted:
                        late_conflicts = []
                        if total != stored_total:
                            late_conflicts.append(
                                f"late conflicting total {total}; first total {stored_total} retained"
                            )
                        existing = self.db.execute(
                            "SELECT text_digest FROM parts WHERE host = ? AND block_id = ? AND number = ?",
                            (host, block, number),
                        ).fetchone()
                        text = str(event.get("script.text") or "")
                        if existing is None:
                            late_conflicts.append(
                                f"late part {number} was absent from the emitted block"
                            )
                        elif existing[0] != self._text_digest(text):
                            late_conflicts.append(
                                f"late conflicting part {number}; first text retained"
                            )
                        if late_conflicts:
                            for conflict in late_conflicts:
                                self._note_partial(
                                    "PowerShell script-block reassembly conflict: " + conflict
                                )
                            output.append(self._conflicted(event, late_conflicts))
                        self.db.execute("RELEASE script_part")
                        continue
                    conflicts = json.loads(conflicts_json)
                    if total != stored_total:
                        conflict = f"conflicting total {total}; first total {stored_total} retained"
                        conflicts.append(conflict)
                        self._note_partial("PowerShell script-block reassembly conflict: " + conflict)
                    if number < base_number:
                        self.db.execute(
                            "UPDATE blocks SET base_number = ?, base_event = ? WHERE host = ? AND block_id = ?",
                            (number, base.model_dump_json(), host, block),
                        )
                        base_number = number
                    latest = max(datetime.fromisoformat(str(latest_ts)), event.ts)
                    self.db.execute(
                        "UPDATE blocks SET latest_ts = ? WHERE host = ? AND block_id = ?",
                        (latest.isoformat(), host, block),
                    )
                existing = self.db.execute(
                    "SELECT text FROM parts WHERE host = ? AND block_id = ? AND number = ?",
                    (host, block, number),
                ).fetchone()
                text = str(event.get("script.text") or "")
                if existing is None:
                    self.db.execute(
                        "INSERT INTO parts VALUES (?, ?, ?, ?, ?, ?)",
                        (host, block, number, text, self._text_digest(text), event.id),
                    )
                elif existing[0] != text:
                    conflict = f"conflicting part {number}; first text retained"
                    conflicts.append(conflict)
                    self._note_partial("PowerShell script-block reassembly conflict: " + conflict)
                if total > 1 or len(text) > self.text_cap:
                    part = event.model_copy(deep=True)
                    part.fields["script.part_number"] = fv(number, "ScriptBlockText#part-view")
                    part.fields["script.complete"] = fv(False, "ScriptBlockText#part-view")
                    part.caveats.append("script block fragment; joined view supplies cross-part context")
                    output.append(part)
                    for ref in part.raw:
                        self._emitted_sources[ref.key] = raw_sources.get(ref.key)
                self.db.execute(
                    "UPDATE blocks SET conflicts = ? WHERE host = ? AND block_id = ?",
                    (json.dumps(sorted(set(conflicts))), host, block),
                )
                for ref in event.raw:
                    source = raw_sources.get(ref.key)
                    self.db.execute(
                        "INSERT OR IGNORE INTO refs VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (host, block, number, ref.target, ref.native_id, ref.digest,
                         json.dumps(source, sort_keys=True, separators=(",", ":"), default=str)
                         if source is not None else None),
                    )
                self.db.execute("RELEASE script_part")
                self._checkpoint(commit=False)
            except sqlite3.OperationalError as exc:
                if self.db.in_transaction:
                    with contextlib.suppress(sqlite3.OperationalError):
                        self.db.execute("ROLLBACK TO script_part")
                        self.db.execute("RELEASE script_part")
                self.refusal_reason = f"writing script-block reassembly state failed ({exc})"
                if self.budget is not None:
                    self.budget.fail(self.refusal_reason)
                self._note_refusal(self.refusal_reason)
                output.append(self._partial(event, self.refusal_reason))
                continue
            count, minimum, maximum = self.db.execute(
                "SELECT count(*), min(number), max(number) FROM parts WHERE host = ? AND block_id = ?",
                (host, block),
            ).fetchone()
            if count == stored_total and minimum == 1 and maximum == stored_total:
                output.append(self._emit(host, block, complete=True))
        self._checkpoint()
        return output

    def _emit(self, host: str, block: str, *, complete: bool) -> TypedEvent:
        total, base_json, conflicts_json, latest_ts = self.db.execute(
            "SELECT total, base_event, conflicts, latest_ts FROM blocks WHERE host = ? AND block_id = ?",
            (host, block),
        ).fetchone()
        base = TypedEvent.model_validate_json(base_json)
        chunks, numbers, part_ids, retained_parts = [], [], [], []
        text_length = 0
        for number, text, part_id in self.db.execute(
            "SELECT number, text, event_id FROM parts WHERE host = ? AND block_id = ? ORDER BY number",
            (host, block),
        ):
            numbers.append(int(number))
            part_ids.append(part_id)
            remaining = max(0, self.text_cap - text_length)
            if remaining and text:
                chunks.append(text[:remaining])
                retained_parts.append(int(number))
            text_length += len(text)
        ref_count = self.db.execute(
            "SELECT count(*) FROM refs WHERE host = ? AND block_id = ?", (host, block),
        ).fetchone()[0]
        ref_query = (
            "SELECT number, target, native_id, digest FROM refs WHERE host = ? AND block_id = ? "
            "ORDER BY number, target, native_id LIMIT ?"
        )
        if ref_count > SCRIPT_JOINED_REFS:
            # One ref per part preserves citation coverage of the entire joined text. Extra shipper copies
            # remain retrievable through the independently persisted fragment events.
            ref_query = (
                "SELECT number, target, native_id, digest FROM ("
                "SELECT number, target, native_id, digest, row_number() OVER ("
                "PARTITION BY number ORDER BY target, native_id) AS ordinal FROM refs "
                "WHERE host = ? AND block_id = ?) WHERE ordinal = 1 ORDER BY number LIMIT ?"
            )
        refs = [RawRef(target=target, native_id=native_id, digest=digest)
                for _number, target, native_id, digest in self.db.execute(
                    ref_query, (host, block, SCRIPT_JOINED_REFS),
                )]
        for ref in refs[:SCRIPT_SOURCE_PAGE]:
            source = self.db.execute(
                "SELECT source FROM refs WHERE host = ? AND block_id = ? AND target = ? AND native_id = ?",
                (host, block, ref.target, ref.native_id),
            ).fetchone()[0]
            self._emitted_sources[ref.key] = json.loads(source) if source is not None else None
        joined = "".join(chunks)
        truncated = text_length > self.text_cap
        result = base.model_copy(deep=True)
        result.normalizer = WINDOWS_NORMALIZER
        if complete:
            # A block becomes evaluable only when its final required part has arrived. Using that completion
            # instant keeps stateful rules monotonic across source partitions; end-of-sweep incomplete blocks
            # retain the lowest available part as their stable event time.
            result.ts = datetime.fromisoformat(str(latest_ts))
        text_origin = (result.fields.get("script.text") or result.fields["event.code"]).origin
        result.fields["script.text"] = fv(joined, text_origin + "#reassembled:message-order")
        result.fields["script.part_count"] = fv(len(numbers), text_origin + "#reassembled:part-count")
        result.fields["script.part_event_ids"] = fv(
            part_ids if int(total) > 1 or truncated else [], text_origin + "#reassembled:part-citations",
        )
        present = set(numbers)
        missing = [number for number in range(1, int(total) + 1) if number not in present]
        conflicts = json.loads(conflicts_json)
        result.fields["script.complete"] = fv(
            complete and not missing and not conflicts and not truncated,
            text_origin + "#reassembled:completeness",
        )
        result.fields["script.missing_parts"] = fv(missing, text_origin + "#reassembled:missing-parts")
        result.fields["script.truncated"] = fv(truncated, text_origin + "#reassembled:text-cap")
        if truncated:
            result.fields["script.retained_parts"] = fv(
                retained_parts, text_origin + "#reassembled:text-cap",
            )
        result.fields.pop("script.message_number", None)
        result.fields.pop("script.message_total", None)
        result.raw = refs
        result.id = event_id("script_block", refs, WINDOWS_NORMALIZER)
        if truncated and len(numbers) == 1:
            result.id += "-joined"
        result.caveats.extend(conflicts)
        for conflict in conflicts:
            self._note_partial("PowerShell script-block reassembly conflict: " + conflict)
        if missing:
            result.caveats.append("script block incomplete; missing parts " + ", ".join(map(str, missing)))
        if truncated:
            reason = (
                f"script block joined text capped at {self.text_cap} characters; ordered prefix retained; "
                "every fragment is evaluated separately and cited by script.part_event_ids; "
                "cross-part matches beyond the prefix are unresolved"
            )
            result.caveats.append(reason)
            self._note_partial(reason)
        self.db.execute("UPDATE parts SET text = '' WHERE host = ? AND block_id = ?", (host, block))
        self.db.execute("DELETE FROM refs WHERE host = ? AND block_id = ?", (host, block))
        self.db.execute(
            "UPDATE blocks SET emitted = 1, base_event = '', conflicts = '[]' "
            "WHERE host = ? AND block_id = ?", (host, block),
        )
        return result

    def finalize(self) -> Iterator[TypedEvent]:
        """Yield every still-incomplete block once, reading only a bounded key page from SQLite at a time."""
        after: tuple[str, str] | None = None
        while True:
            if after is None:
                keys = self.db.execute(
                    "SELECT host, block_id FROM blocks WHERE emitted = 0 "
                    "ORDER BY host, block_id LIMIT ?",
                    (SCRIPT_FINALIZE_BATCH_SIZE,),
                ).fetchall()
            else:
                keys = self.db.execute(
                    "SELECT host, block_id FROM blocks WHERE emitted = 0 "
                    "AND (host > ? OR (host = ? AND block_id > ?)) "
                    "ORDER BY host, block_id LIMIT ?",
                    (after[0], after[0], after[1], SCRIPT_FINALIZE_BATCH_SIZE),
                ).fetchall()
            if not keys:
                return
            for host, block in keys:
                after = (str(host), str(block))
                event = self._emit(host, block, complete=False)
                self._checkpoint()
                yield event

    def sources_for(self, events: list[TypedEvent]) -> dict[str, dict]:
        keys = {raw.key for event in events for raw in event.raw}
        if not keys:
            return {}
        sources: dict[str, dict] = {}
        unresolved: set[str] = set()
        absent = object()
        for key in sorted(keys):
            source = self._emitted_sources.pop(key, absent)
            if source is absent:
                unresolved.add(key)
            elif source is not None:
                sources[key] = source
        if not unresolved:
            return sources
        for key in unresolved:
            target, native_id = key.split("/", 1)
            row = self.db.execute(
                "SELECT source FROM refs WHERE target = ? AND native_id = ? AND source IS NOT NULL LIMIT 1",
                (target, native_id),
            ).fetchone()
            if row:
                sources[key] = json.loads(row[0])
        return sources

    def close(self) -> None:
        db = getattr(self, "db", None)
        if db is not None:
            db.close()
            self.db = None
        if self._tempdir is not None:
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()
