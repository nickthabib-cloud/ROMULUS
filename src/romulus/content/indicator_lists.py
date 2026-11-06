"""Versioned local indicator lists and bounded, indexed hunt lookups."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from itertools import islice

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.sqlite import insert

from romulus.content.indicator_values import _safe_text, normalize_value
from romulus.detect.base import LANES, SEVERITIES
from romulus.store import schema as t
from romulus.store.db import read_snapshot, utcnow, write_txn

BATCH_SIZE = 1000


def _date(value):
    if not isinstance(value, datetime):
        raise ValueError("Expiry and creation times must be datetimes")  # noqa: TRY004 - public validation API
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _text(value, field, limit, *, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError(f"Invalid {field} (maximum {limit} characters)")
    return _safe_text(value, limit=limit)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _serial(row):
    return {key: _date(value).isoformat() if isinstance(value, datetime) else value
            for key, value in dict(row).items()}


def _where(list_id, version):
    return and_(t.indicator_value.c.list_id == list_id, t.indicator_value.c.list_version == version)


def _latest():
    latest = select(t.indicator_list.c.id, func.max(t.indicator_list.c.version).label("version")).group_by(
        t.indicator_list.c.id).subquery()
    return select(t.indicator_list).join(latest, and_(
        t.indicator_list.c.id == latest.c.id, t.indicator_list.c.version == latest.c.version))


def _metadata(c, row, *, report=True):
    result = _serial(row)
    counts = c.execute(select(t.indicator_value.c.kind, func.count()).where(
        _where(result["id"], result["version"])).group_by(t.indicator_value.c.kind))
    result["kinds"] = {kind: count for kind, count in counts}
    result["value_count"] = sum(result["kinds"].values())
    if report:
        audit = c.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.action == "indicator_list.import",
            t.audit_event.c.detail["id"].as_string() == result["id"],
            t.audit_event.c.detail["version"].as_integer() == result["version"]
        ).order_by(t.audit_event.c.id.desc()).limit(1)).scalar()
        result["import_report"] = audit.get("import_report", {}) if audit else {}
    return result


def _audit(c, *, at, actor, action, detail):
    c.execute(t.audit_event.insert().values(at=at, actor=actor, action=action, detail=detail))


def _merge(left, right):
    """Duplicate comparisons represent a union, including their expiry windows."""
    merged = dict(right)
    expiries = (left["expires_at"], right["expires_at"])
    merged["expires_at"] = max(map(_date, expiries)) if all(x is not None for x in expiries) else None
    merged["lane"] = min((left["lane"], right["lane"]), key=LANES.index)
    merged["severity"] = min((left["severity"], right["severity"]), key=SEVERITIES.index)
    merged["attack"] = sorted(set(left["attack"]) | set(right["attack"]))
    if len(merged["attack"]) > 256:
        raise ValueError("Duplicate indicators exceed ATT&CK label bound")
    # Keep the first label and report the duplicate count rather than grow labels without bound.
    merged["label"] = left["label"] or right["label"]
    return merged


class IndicatorLists:
    def __init__(self, repo):
        self.engine = repo.engine

    def create_version(self, rows, *, name, source, author, expires_at=None, notes="",
                       list_id=None, report=None, now=None):
        now = _date(now or utcnow())
        expires_at = _date(expires_at) if expires_at is not None else now + timedelta(days=90)
        name = _text(name, "name", 256)
        source = _text(source, "source", 2048)
        author = _text(author, "author", 256)
        notes = _text(notes, "notes", 16384, empty=True)
        list_id = _text(list_id, "list id", 128) if list_id is not None else uuid.uuid4().hex
        with write_txn(self.engine) as c:
            c.exec_driver_sql("BEGIN IMMEDIATE")
            previous = c.execute(select(func.max(t.indicator_list.c.version)).where(
                t.indicator_list.c.id == list_id)).scalar()
            version = (previous or 0) + 1
            metadata = {"id": list_id, "version": version, "name": name, "source": source, "author": author,
                        "created_at": now, "expires_at": expires_at, "notes": notes}
            status = "active" if expires_at > now else "expired"
            c.execute(t.indicator_list.insert().values(**metadata, status=status, digest="pending"))
            batch = []
            duplicates = 0
            def flush():
                nonlocal duplicates
                if batch:
                    unique = {}
                    for value in batch:
                        if value["id"] in unique:
                            duplicates += 1
                            value = _merge(unique[value["id"]], value)
                        unique[value["id"]] = value
                    for existing in c.execute(select(t.indicator_value).where(
                            t.indicator_value.c.id.in_(unique))).mappings():
                        duplicates += 1
                        unique[existing["id"]] = _merge(existing, unique[existing["id"]])
                    statement = insert(t.indicator_value)
                    c.execute(statement.on_conflict_do_update(index_elements=["id"], set_={
                        field: getattr(statement.excluded, field) for field in (
                            "label", "attack", "lane", "severity", "expires_at")}), list(unique.values()))
                    batch.clear()
            for item in rows:
                kind = _text(item.kind, "kind", 64)
                value = normalize_value(kind, item.value)
                if item.lane not in LANES or item.severity not in SEVERITIES:
                    raise ValueError("Invalid indicator lane or severity")
                label = _text(item.label, "label", 2048, empty=True)
                attack = list(islice(item.attack, 257))
                if len(attack) > 256 or any(not isinstance(x, str) or len(x) > 128 for x in attack):
                    raise ValueError("Invalid indicator ATT&CK labels")
                attack = [_text(x, "ATT&CK label", 128) for x in attack]
                expiry = _date(item.expires_at) if item.expires_at is not None else None
                identity = hashlib.sha256(_json([list_id, version, kind, value]).encode()).hexdigest()
                batch.append({"id": identity, "list_id": list_id, "list_version": version,
                              "kind": kind, "value": value, "label": label, "attack": attack,
                              "lane": item.lane, "severity": item.severity, "expires_at": expiry})
                if len(batch) == BATCH_SIZE:
                    flush()
            flush()
            # Feed a canonical, indexed SQL stream; never retain the imported value set.
            h = hashlib.sha256((_json(_serial(metadata)) + "\n").encode())
            query = select(t.indicator_value).where(_where(list_id, version)).order_by(
                t.indicator_value.c.kind, t.indicator_value.c.value)
            for row in c.execute(query).mappings():
                h.update((_json(_serial(row)) + "\n").encode())
            content_digest = h.hexdigest()
            c.execute(t.indicator_list.update().where(t.indicator_list.c.id == list_id,
                t.indicator_list.c.version == version).values(digest=content_digest))
            final_report = report() if callable(report) else (report or {})
            if not isinstance(final_report, dict):
                raise ValueError("Import report must be a dictionary")  # noqa: TRY004 - public validation API
            # Encoding inside the transaction makes a bad report roll back the complete import.
            _json(final_report)
            _audit(c, at=now, actor=author, action="indicator_list.import", detail={
                "id": list_id, "version": version, "digest": content_digest,
                "duplicates": duplicates, "import_report": final_report})
            return _metadata(c, {**metadata, "status": status, "digest": content_digest})

    def get(self, list_id, version=None):
        with read_snapshot(self.engine) as c:
            query = select(t.indicator_list).where(t.indicator_list.c.id == list_id)
            if version is not None:
                query = query.where(t.indicator_list.c.version == version)
            row = c.execute(query.order_by(t.indicator_list.c.version.desc()).limit(1)).mappings().first()
            return _metadata(c, row) if row else None

    def lists(self, limit=100, offset=0):
        if not isinstance(limit, int) or not 0 <= limit <= 1000 or not isinstance(offset, int) or offset < 0:
            raise ValueError("Invalid indicator list pagination")
        with read_snapshot(self.engine) as c:
            return [_metadata(c, row) for row in c.execute(_latest().order_by(
                t.indicator_list.c.id).limit(limit).offset(offset)).mappings()]

    def values(self, list_id, version=None, limit=None):
        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise ValueError("Invalid value limit")
        with read_snapshot(self.engine) as c:
            if version is None:
                version = c.execute(select(func.max(t.indicator_list.c.version)).where(
                    t.indicator_list.c.id == list_id)).scalar()
            query = select(t.indicator_value).where(_where(list_id, version)).order_by(
                t.indicator_value.c.kind, t.indicator_value.c.value)
            if limit is not None:
                query = query.limit(limit)
            for row in c.execute(query).mappings():
                yield _serial(row)

    def retire(self, list_id, *, actor, role):
        if role != "lead":
            raise PermissionError("Only a lead may retire indicator lists")
        actor = _text(actor, "actor", 256)
        with write_txn(self.engine) as c:
            c.exec_driver_sql("BEGIN IMMEDIATE")
            row = c.execute(select(t.indicator_list).where(t.indicator_list.c.id == list_id).order_by(
                t.indicator_list.c.version.desc()).limit(1)).mappings().first()
            if row is None:
                raise ValueError("Unknown indicator list")
            if row["status"] != "retired":
                c.execute(t.indicator_list.update().where(t.indicator_list.c.id == list_id,
                    t.indicator_list.c.version == row["version"]).values(status="retired"))
                _audit(c, at=utcnow(), actor=actor, action="indicator_list.retire",
                       detail={"id": list_id, "version": row["version"], "previous_status": row["status"]})
            return _metadata(c, {**row, "status": "retired"})

    def pin(self, now=None):
        now = _date(now or utcnow())
        result = {"as_of": now.isoformat(), "applied": [], "excluded": []}
        with write_txn(self.engine) as c:
            c.exec_driver_sql("BEGIN IMMEDIATE")
            for row in c.execute(_latest().order_by(t.indicator_list.c.id)).mappings():
                status = row["status"]
                expired = _date(row["expires_at"]) <= now
                if expired and status == "active":
                    status = "expired"
                    c.execute(t.indicator_list.update().where(t.indicator_list.c.id == row["id"],
                        t.indicator_list.c.version == row["version"]).values(status=status))
                    _audit(c, at=now, actor="system", action="indicator_list.expire",
                           detail={"id": row["id"], "version": row["version"], "digest": row["digest"]})
                if status != "active" or expired:
                    result["excluded"].append({key: row[key] for key in ("id", "version", "digest")} | {
                        "status": status, "reason": "expired" if expired else status})
                else:
                    result["applied"].append(_metadata(c, row, report=False))
        return result


class PinnedIndicators:
    """Only pinned metadata is held in memory; values stay in the indexed store."""
    def __init__(self, repo, pins):
        self.engine = repo.engine
        self.as_of = _date(datetime.fromisoformat(pins["as_of"]))
        self._lists = {}
        self.kinds = set()
        with read_snapshot(self.engine) as c:
            for pin in pins["applied"]:
                key = (pin["id"], pin["version"])
                row = c.execute(select(t.indicator_list).where(t.indicator_list.c.id == key[0],
                    t.indicator_list.c.version == key[1])).mappings().first()
                if row is None or row["digest"] != pin["digest"]:
                    raise ValueError("Pinned indicator version is missing or its digest differs")
                metadata = _metadata(c, row, report=False)
                # Runtime edits cannot rewrite the attribution/status of an existing hunt pin.
                metadata.update(pin)
                metadata["age_days"] = max(0, (self.as_of - _date(row["created_at"])).days)
                self._lists[key] = metadata
                self.kinds.update(metadata["kinds"])
        self.digest = hashlib.sha256(_json({"as_of": self.as_of.isoformat(), "applied": [
            self._lists[key] for key in sorted(self._lists)]}).encode()).hexdigest()

    def _eligible(self):
        return or_(t.indicator_value.c.expires_at.is_(None), t.indicator_value.c.expires_at > self.as_of)

    def find(self, kind, value):
        value = normalize_value(kind, value)
        with read_snapshot(self.engine) as c:
            for (list_id, version), metadata in self._lists.items():
                query = select(t.indicator_value).where(_where(list_id, version),
                    t.indicator_value.c.kind == kind, t.indicator_value.c.value == value, self._eligible())
                for row in c.execute(query).mappings():
                    yield {**_serial(row), "list": metadata}

    def get(self, value_id):
        with read_snapshot(self.engine) as c:
            row = c.execute(select(t.indicator_value).where(
                t.indicator_value.c.id == value_id, self._eligible())).mappings().first()
            if row is None:
                return None
            metadata = self._lists.get((row["list_id"], row["list_version"]))
            return {**_serial(row), "list": metadata} if metadata is not None else None
