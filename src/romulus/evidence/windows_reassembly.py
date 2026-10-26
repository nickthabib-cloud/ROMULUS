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

from romulus.evidence.typed import RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows import SCRIPT_BLOCK_MAX_PARTS, WINDOWS_NORMALIZER

if TYPE_CHECKING:
    from romulus.detect.bounded import Account, StateBudget


SCRIPT_TEXT_CAP = 1_048_576
SCRIPT_STATE_BYTES = 64 * 1024 * 1024
SCRIPT_FINALIZE_BATCH_SIZE = 128
_TRUNCATION_MARKER = "\n...[Romulus joined-text cap]...\n"


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
        max_bytes: int = SCRIPT_STATE_BYTES,
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
        self.max_bytes = max(1, int(max_bytes))
        self.budget = budget
        self.account = account
        self.refusal_reason = ""
        self._refusal_reasons: dict[str, None] = {}
        self.partial_reasons: list[str] = []
        # A present key with None records that an emitted ref had no source body. Keeping the sentinel until
        # sources_for() drains it lets finalized batches avoid rescanning every still-pending refs row.
        self._emitted_sources: dict[str, dict | None] = {}
        self.db.executescript(
            "CREATE TABLE blocks ("
            "host TEXT NOT NULL, block_id TEXT NOT NULL, total INTEGER NOT NULL, base_number INTEGER NOT NULL, "
            "base_event TEXT NOT NULL, conflicts TEXT NOT NULL, emitted INTEGER NOT NULL DEFAULT 0, "
            "latest_ts TEXT NOT NULL, "
            "PRIMARY KEY (host, block_id)) WITHOUT ROWID;"
            "CREATE TABLE parts ("
            "host TEXT NOT NULL, block_id TEXT NOT NULL, number INTEGER NOT NULL, text TEXT NOT NULL, "
            "text_digest TEXT NOT NULL, "
            "PRIMARY KEY (host, block_id, number)) WITHOUT ROWID;"
            "CREATE TABLE refs ("
            "host TEXT NOT NULL, block_id TEXT NOT NULL, number INTEGER NOT NULL, target TEXT NOT NULL, "
            "native_id TEXT NOT NULL, digest TEXT NOT NULL, source TEXT, "
            "PRIMARY KEY (host, block_id, target, native_id)) WITHOUT ROWID;"
        )
        self.db.commit()
        self._page = int(self.db.execute("PRAGMA page_size").fetchone()[0])
        self._size = self._db_size()
        if self._size > self.max_bytes:
            self.refusal_reason = (
                f"script-block reassembly database floor {self._size} exceeds cap {self.max_bytes} bytes"
            )
            self._refusal_reasons[self.refusal_reason] = None
        else:
            pages = max(1, self.max_bytes // self._page)
            self.db.execute(f"PRAGMA max_page_count = {pages}")
        if self.budget is not None and self.account is not None:
            self.budget.charge(self.account, self._size)
            self.budget.grew(self._size)

    def _db_size(self) -> int:
        return int(self.db.execute("PRAGMA page_count").fetchone()[0]) * self._page

    def _checkpoint(self) -> None:
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
        """Return non-parts immediately and each completed multi-part block once."""
        raw_sources = raw_sources or {}
        self.partial_reasons = []
        output: list[TypedEvent] = []
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
                if row is None:
                    self.db.execute(
                        "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                        (host, block, total, number, event.model_dump_json(), "[]", event.ts.isoformat()),
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
                        continue
                    conflicts = json.loads(conflicts_json)
                    if total != stored_total:
                        conflict = f"conflicting total {total}; first total {stored_total} retained"
                        conflicts.append(conflict)
                        self._note_partial("PowerShell script-block reassembly conflict: " + conflict)
                    if number < base_number:
                        self.db.execute(
                            "UPDATE blocks SET base_number = ?, base_event = ? WHERE host = ? AND block_id = ?",
                            (number, event.model_dump_json(), host, block),
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
                        "INSERT INTO parts VALUES (?, ?, ?, ?, ?)",
                        (host, block, number, text, self._text_digest(text)),
                    )
                elif existing[0] != text:
                    conflict = f"conflicting part {number}; first text retained"
                    conflicts.append(conflict)
                    self._note_partial("PowerShell script-block reassembly conflict: " + conflict)
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
                self._checkpoint()
            except sqlite3.OperationalError as exc:
                self.db.rollback()
                self.refusal_reason = f"writing script-block reassembly state failed ({exc})"
                if self.budget is not None:
                    self.budget.fail(self.refusal_reason)
                self._note_refusal(self.refusal_reason)
                output.append(self._partial(event, self.refusal_reason))
                continue
            numbers = [int(value) for value, in self.db.execute(
                "SELECT number FROM parts WHERE host = ? AND block_id = ? ORDER BY number", (host, block),
            )]
            if (len(numbers) == stored_total
                    and all(number == expected for expected, number in enumerate(numbers, 1))):
                output.append(self._emit(host, block, complete=True))
        return output

    def _emit(self, host: str, block: str, *, complete: bool) -> TypedEvent:
        total, base_json, conflicts_json, latest_ts = self.db.execute(
            "SELECT total, base_event, conflicts, latest_ts FROM blocks WHERE host = ? AND block_id = ?",
            (host, block),
        ).fetchone()
        base = TypedEvent.model_validate_json(base_json)
        parts = [(int(number), str(text)) for number, text in self.db.execute(
            "SELECT number, text FROM parts WHERE host = ? AND block_id = ? ORDER BY number", (host, block),
        )]
        refs = [RawRef(target=target, native_id=native_id, digest=digest)
                for _number, target, native_id, digest in self.db.execute(
                    "SELECT number, target, native_id, digest FROM refs WHERE host = ? AND block_id = ? "
                    "ORDER BY number, target, native_id", (host, block),
                )]
        emitted_sources = {
            f"{target}/{native_id}": json.loads(source) if source is not None else None
            for target, native_id, source in self.db.execute(
                "SELECT target, native_id, source FROM refs WHERE host = ? AND block_id = ?",
                (host, block),
            )
        }
        joined = "".join(text for _number, text in parts)
        truncated = len(joined) > self.text_cap
        if truncated:
            marker = _TRUNCATION_MARKER if self.text_cap > len(_TRUNCATION_MARKER) + 1 else "…"
            remaining = max(0, self.text_cap - len(marker))
            head = (remaining + 1) // 2
            tail = remaining - head
            first_text = parts[0][1]
            last_text = parts[-1][1]
            joined = first_text[:head] + marker + (last_text[-tail:] if tail else "")
        result = base.model_copy(deep=True)
        if complete:
            # A block becomes evaluable only when its final required part has arrived. Using that completion
            # instant keeps stateful rules monotonic across source partitions; end-of-sweep incomplete blocks
            # retain the lowest available part as their stable event time.
            result.ts = datetime.fromisoformat(str(latest_ts))
        text_origin = (result.fields.get("script.text") or result.fields["event.code"]).origin
        result.fields["script.text"] = fv(joined, text_origin + "#reassembled:message-order")
        result.fields["script.part_count"] = fv(len(parts), text_origin + "#reassembled:part-count")
        present = {number for number, _text in parts}
        missing = [number for number in range(1, int(total) + 1) if number not in present]
        conflicts = json.loads(conflicts_json)
        result.fields["script.complete"] = fv(
            complete and not missing and not conflicts,
            text_origin + "#reassembled:completeness",
        )
        result.fields["script.missing_parts"] = fv(missing, text_origin + "#reassembled:missing-parts")
        result.fields["script.truncated"] = fv(truncated, text_origin + "#reassembled:text-cap")
        if truncated:
            result.fields["script.retained_parts"] = fv(
                sorted({parts[0][0], parts[-1][0]}), text_origin + "#reassembled:text-cap",
            )
        result.fields.pop("script.message_number", None)
        result.fields.pop("script.message_total", None)
        result.raw = refs
        result.id = event_id("script_block", refs, WINDOWS_NORMALIZER)
        result.caveats.extend(conflicts)
        for conflict in conflicts:
            self._note_partial("PowerShell script-block reassembly conflict: " + conflict)
        if missing:
            result.caveats.append("script block incomplete; missing parts " + ", ".join(map(str, missing)))
        if truncated:
            result.caveats.append(
                f"script block joined text capped at {self.text_cap} characters; first and last text retained"
            )
        self._emitted_sources.update(emitted_sources)
        self.db.execute("UPDATE parts SET text = '' WHERE host = ? AND block_id = ?", (host, block))
        self.db.execute("DELETE FROM refs WHERE host = ? AND block_id = ?", (host, block))
        self.db.execute(
            "UPDATE blocks SET emitted = 1, base_event = '', conflicts = '[]' "
            "WHERE host = ? AND block_id = ?", (host, block),
        )
        self._checkpoint()
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
                yield self._emit(host, block, complete=False)

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
        for target, native_id, source in self.db.execute(
            "SELECT target, native_id, source FROM refs WHERE source IS NOT NULL",
        ):
            key = f"{target}/{native_id}"
            if key in unresolved:
                sources[key] = json.loads(source)
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
