"""SQLite persistence for resumable investigations and an append-only finding event stream."""
import json, sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from .models import utc_now

class Store:
    def __init__(self, data_dir: Path, logs_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True); logs_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "romulus.sqlite3"
        self.checkpoint_path = data_dir / "checkpoints.sqlite3"
        self.events_path = logs_dir / "findings.jsonl"
        self.audit_path = logs_dir / "tool_audit.jsonl"
        with self._db() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, item TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, item TEXT NOT NULL);""")
    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.db_path,timeout=30); db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback(); raise
        finally: db.close()
    def save_state(self, hunt_id: str, state: dict[str, Any]) -> None:
        with self._db() as db:
            db.execute("INSERT INTO investigations VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at", (hunt_id, json.dumps(state), utc_now()))
    def load_state(self, hunt_id: str) -> dict[str, Any] | None:
        with self._db() as db:
            row = db.execute("SELECT state FROM investigations WHERE id=?", (hunt_id,)).fetchone()
            return json.loads(row[0]) if row else None
    def add_evidence(self, hunt_id: str, item: dict[str, Any]) -> None:
        with self._db() as db: db.execute("INSERT OR REPLACE INTO evidence VALUES(?,?,?)", (item["evidence_id"], hunt_id, json.dumps(item)))
    def list_evidence(self, hunt_id: str) -> list[dict[str, Any]]:
        with self._db() as db: return [json.loads(r[0]) for r in db.execute("SELECT item FROM evidence WHERE investigation_id=? ORDER BY rowid", (hunt_id,))]
    def evidence_count(self, hunt_id: str) -> int:
        with self._db() as db:
            row=db.execute("SELECT COUNT(*) FROM evidence WHERE investigation_id=?",(hunt_id,)).fetchone()
            return int(row[0]) if row else 0
    def upsert_finding(self, hunt_id: str, item: dict[str, Any], event: str = "created") -> None:
        with self._db() as db: db.execute("INSERT OR REPLACE INTO findings VALUES(?,?,?)", (item["finding_id"], hunt_id, json.dumps(item)))
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event": event, "investigation_id": hunt_id, "timestamp": utc_now(), "finding": item}, ensure_ascii=False) + "\n")
    def list_findings(self, hunt_id: str) -> list[dict[str, Any]]:
        with self._db() as db: return [json.loads(r[0]) for r in db.execute("SELECT item FROM findings WHERE investigation_id=? ORDER BY rowid", (hunt_id,))]
    def audit(self, record: dict[str, Any]) -> None:
        # Recursively redact credentials, including nested request/config structures.
        scrubbed = _redact(record)
        with self.audit_path.open("a", encoding="utf-8") as f: f.write(json.dumps(scrubbed, ensure_ascii=False) + "\n")
    def audit_records(self, hunt_id: str) -> list[dict[str, Any]]:
        if not self.audit_path.exists(): return []
        rows=[]
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            if item.get("hunt_id")==hunt_id: rows.append(item)
        return rows
    def prune_checkpoints(self, hunt_id: str, keep: int = 1, compact: bool = False) -> dict[str, int]:
        """Keep only the newest resumable checkpoint per namespace.

        LangGraph's SQLite saver stores complete state snapshots. Pruning after
        each node prevents repeated evidence context from multiplying storage.
        """
        if not self.checkpoint_path.exists(): return {"deleted_checkpoints":0,"deleted_writes":0}
        db=sqlite3.connect(self.checkpoint_path,timeout=30)
        try:
            db.execute("PRAGMA busy_timeout=30000")
            tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "checkpoints" not in tables: return {"deleted_checkpoints":0,"deleted_writes":0}
            namespaces=[row[0] for row in db.execute("SELECT DISTINCT checkpoint_ns FROM checkpoints WHERE thread_id=?",(hunt_id,))]
            deleted_checkpoints=0; deleted_writes=0
            for namespace in namespaces:
                ids=[row[0] for row in db.execute(
                    "SELECT checkpoint_id FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? ORDER BY checkpoint_id DESC",
                    (hunt_id,namespace))]
                remove=ids[max(0,keep):]
                if not remove: continue
                marks=",".join("?" for _ in remove)
                if "writes" in tables:
                    cursor=db.execute(
                        f"DELETE FROM writes WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id IN ({marks})",
                        (hunt_id,namespace,*remove))
                    deleted_writes+=max(0,cursor.rowcount)
                cursor=db.execute(
                    f"DELETE FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id IN ({marks})",
                    (hunt_id,namespace,*remove))
                deleted_checkpoints+=max(0,cursor.rowcount)
            db.commit()
            if compact:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                db.execute("VACUUM")
            return {"deleted_checkpoints":deleted_checkpoints,"deleted_writes":deleted_writes}
        finally: db.close()

def _redact(value):
    sensitive=("password","secret","authorization","api_key","token","credential")
    if isinstance(value,dict):
        return {str(k):("[REDACTED]" if any(s in str(k).lower() for s in sensitive) else _redact(v)) for k,v in value.items()}
    if isinstance(value,list): return [_redact(v) for v in value]
    return value
