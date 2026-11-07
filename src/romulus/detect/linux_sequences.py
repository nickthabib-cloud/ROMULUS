"""Disk-backed Linux follow-on observations.

Only compact typed join rows are retained in memory, inside the existing spill's fixed-size write
buffer. The final joins use indexed disk tables and stream one folded group at a time. Time
windows restrict links, never retention: a late batch can still join any earlier accepted row.
"""
from __future__ import annotations

import json
import posixpath
import re
import sqlite3
import weakref
from datetime import UTC, datetime
from itertools import groupby
from urllib.parse import urlsplit

from romulus.detect.base import Match, Playbook, argv_incomplete, pf
from romulus.detect.bounded import (
    CitationUnavailable,
    RecentIds,
    Spill,
    StateExhausted,
    register_store,
    store_refuses,
)
from romulus.detect.correlation import canon_ip, external
from romulus.detect.host import INTERPRETERS
from romulus.detect.linux_argv import normalize_path, program, write_targets
from romulus.detect.linux_direct import (
    BASE_PACKAGE_DIRS,
    PACKAGE_EXTRA_DIRS,
    download_log_paths,
    executed_paths,
    output_paths,
    temporary,
    under,
    web,
)
from romulus.detect.linux_semantics import (
    _DISCOVERY_BY_ABSENCE,
    SANCTIONED_BROKERS,
    _login_user_is_nonroot,
    classify_discovery,
)
from romulus.detect.netdef import assume_direction
from romulus.detect.site_roles import address_member
from romulus.evidence.typed import Outcome
from romulus.hunt.citations import compact_event, expand_event
from romulus.site import absent_site_facts

# Human-driven staging normally follows retrieval within a session; one hour allows interrupted installs.
W_DOWNLOAD_EXEC = 3600
# Persistence may be used days after installation; a full week includes delayed return visits.
W_KEY_LOGIN = 7 * 86400
# Cleanup often occurs at the end of a working day.
W_CLEANUP = 86400
# Uploaded scripts can be requested long after the write; this does not imply that a request ran the file.
W_SHELL_REQUEST = 7 * 86400
# Five independent reconnaissance classes in ten minutes exceed one routine status command.
N_DISCOVERY, W_DISCOVERY = 5, 600
# A half hour covers exploit follow-on work while limiting unrelated service executions.
W_ALERT_EXEC = 1800
# An active server normally emits audit records more frequently; this is an index discontinuity, not host silence.
G_SILENCE = 900
LINEAGE_DEPTH = 32
CITE = 20
SCRIPT_SUFFIXES = frozenset({".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py"})
DOCUMENT_ROOTS = ("/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/opt/lampp/htdocs")
TOMCAT_ROOT = re.compile(r"^/var/lib/tomcat[^/]*/webapps(?:/|$)")
# A narrow working-path exclusion; a download or key link overrides it.
CLEANUP_EXCLUSIONS = ("/var/lib/dpkg/tmp.ci", "/var/cache/yum", "/var/cache/dnf")
SYSTEMD_PRIVATE = re.compile(r"^/tmp/systemd-private-[^/]+(?:/|$)")
LANES = {"context": 0, "lead": 1, "high": 2, "urgent": 3}
FIELDS = ("process.executable", "process.argv", "process.pid", "process.ppid", "process.uid", "process.euid",
          "process.auid", "process.session_id", "process.user", "file.path", "file.change", "file.owner.id",
          "file.owner.name", "auth.service", "auth.method", "auth.phase", "user.name", "user.id", "source.ip",
          "destination.ip", "destination.port", "network.transport", "network.app_proto", "url.path", "url.original",
          "http.response.status_code", "alert.severity", "host.ip", "audit.config.op", "service.unit")


def _key(*parts):
    return json.dumps(parts, ensure_ascii=True, separators=(",", ":"))


def _owner(path, event):
    """Prefer passwd-enriched file ownership; otherwise state the home-component inference."""
    owner = event.get("file.owner.name")
    if owner:
        return str(owner), False
    match = re.match(r"^/home/([^/]+)/\.ssh/authorized_keys2?$", path)
    if match:
        return match[1], True
    if path in {"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"}:
        return "root", True
    return None, True


class _LinuxWitnesses:
    """One budgeted, lossless compressed witness per event across Linux sequence rules.

    Raw source bodies remain on their telemetry source; selected citations use the sweep's
    existing digest-checked source hydration. No partially populated typed event is created.
    """

    # Only selected citation loading reads these bodies; scalar tables own detection state.
    yields = True

    def __init__(self, owner, members):
        self.owner, self.members = owner, {id(member) for member in members}
        self._rules = tuple(weakref.ref(member) for member in members)
        self._spill, self._account = None, None
        self._blocked_generation = None
        self._next_sequence = self._reclaim_cursor = 0
        self.pending = set()
        self.closed = False
        register_store(owner, self)

    def account(self):
        if self._account is None:
            self._account = self.owner.state_budget().account("linux_sequence_witnesses", yields=True)
            # Compact references yield only after a real FULL, never at optional-copy thresholds.
            self._account.evict_references = self._evict_references
            self._account.reclaim_database = lambda: (self._spill.db, self._spill.path) if self._spill else (None, None)
        return self._account

    def store(self):
        if self._spill is None:
            spill = Spill(self.owner.spill_dir, self.owner.state_budget(), owner=self.owner)
            try:
                spill.cap()
                spill.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
                spill.grew()
                spill.table("witnesses", "id TEXT PRIMARY KEY, body BLOB")
            except StateExhausted:
                spill.close()
                raise
            except sqlite3.Error as exc:
                error = spill.failed(exc, report=False)
                spill.close()
                raise error from exc
            self._spill = spill
            _sql, rows = spill._buffers["witnesses"]
            # Explicit rowids never reuse a deleted admission, including after every row was reclaimed.
            spill._buffers["witnesses"] = ("INSERT OR IGNORE INTO witnesses(rowid,id,body) VALUES(?,?,?)", rows)
        return self._spill

    def hold(self, event):
        if event.id in self.pending or self._spill is not None and self._spill.db.execute(
                "SELECT 1 FROM witnesses WHERE id=?", (event.id,)).fetchone():
            return
        if self._blocked_generation is not None and not self.flush(retry=False):
            return
        # These are mandatory compact references, like EventStage._insert_compact. Optional
        # body-cache thresholds must not discard them; Spill enforces the real page ceiling.
        if self.owner.state_budget().new_key_reason(None):
            self.owner.note_limit("linux_witnesses", "the compact Linux witness disk budget is spent; some citations are unresolved")
            return
        body = compact_event(event)
        try:
            spill = self.store()
        except StateExhausted as exc:
            self.owner.note_limit("linux_witnesses", f"compact Linux witness storage could not be created: {exc}")
            return
        # Spill.add appends before its automatic flush. A failed flush keeps this row too.
        self.pending.add(event.id)
        self._next_sequence += 1
        self.owner.state_budget().charge(self.account(), len(body) + len(event.id) + 64)
        try:
            spill.add("witnesses", (self._next_sequence, event.id, body))
        except StateExhausted as exc:
            self._blocked_generation = self.owner.state_budget()._capacity_generation
            self.owner.note_limit("linux_witnesses",
                f"{len(self.pending)} accepted compact Linux witness(es) remain buffered after disk refusal: {exc}; "
                "new witness IDs are not retained until the buffer can be written")
            return
        if not spill._buffers["witnesses"][1]:
            self.pending.clear()

    def flush(self, *, retry=True):
        if self._spill is None:
            return True
        budget = self.owner.state_budget()
        if not retry and self._blocked_generation == budget._capacity_generation:
            return False
        try:
            self._spill.flush()
        except StateExhausted as exc:
            self._blocked_generation = budget._capacity_generation
            self.owner.note_limit("linux_witnesses",
                f"{len(self.pending)} accepted compact Linux witness(es) remain buffered after disk refusal: {exc}; "
                "new witness IDs are not retained until the buffer can be written")
            return False
        self.pending.clear()
        self._blocked_generation = None
        return True

    def load(self, ids):
        if self._spill is None:
            return []
        self.flush(retry=False)
        out = []
        for start in range(0, len(ids), 500):
            batch = ids[start:start + 500]
            out.extend(expand_event(row[0]) for row in self._spill.db.execute(
                f"SELECT body FROM witnesses WHERE id IN ({','.join('?' for _ in batch)})", batch))
        return out

    def count(self):
        self.flush()
        return self._spill.db.execute("SELECT COUNT(*) FROM witnesses").fetchone()[0] if self._spill else 0

    def _evict_references(self, needed):
        """After FULL, inspect at most32 admissions and reclaim only otherwise-unused clock bodies."""
        if self._spill is None:
            return 0
        rules = [rule for ref in self._rules if (rule := ref()) is not None and id(rule) in self.members]
        clock = next((rule for rule in rules if rule.id == "host.telemetry_gap_after_tamper"), None)
        if clock is None or not getattr(clock, "_clock_tables", False):
            return 0
        # If index construction was refused, retain every host conservatively.
        if clock._tables and not getattr(clock, "_tamper_host_index", False):
            return 0
        spill, budget = self._spill, self.owner.state_budget()
        rows = list(spill.db.execute(
            "SELECT rowid,id,body FROM witnesses WHERE rowid>? ORDER BY rowid LIMIT 32", (self._reclaim_cursor,)))
        identities = {identity for _seq, identity, _body in rows}
        pending = {row[1] for rule in rules if rule._spill is not None
                   for row in rule._spill._buffers.get("records", ("", []))[1] if row[1] in identities}
        pending_tamper_hosts = {row[2] for row in clock._spill._buffers.get("records", ("", []))[1]
                                if row[3] == "tamper"}
        removed = []
        for _seq, identity, body in rows:
            if identity in self.pending or identity in pending:
                continue
            prefix = json.dumps([identity], ensure_ascii=True, separators=(",", ":"))[:-1] + ","
            if any(rule._tables and rule.query(
                    "SELECT 1 FROM records WHERE uid>=? AND uid<? LIMIT 1",
                    (prefix, prefix + "\uffff")).fetchone() for rule in rules):
                continue
            # Coalescing changes address.id without changing its original uid.
            event = expand_event(body)
            addresses = event.get("host.ip") or []
            addresses = [addresses] if isinstance(addresses, str) else addresses
            if any(rule.id == "corr.alert_then_host_execution" and getattr(rule, "_address_index", False)
                   and any(rule.query("SELECT 1 FROM records WHERE role='address' AND host=? AND key=? AND id=? LIMIT 1",
                                      (event.host or "", ip, identity)).fetchone()
                           for address in addresses if (ip := canon_ip(address))) for rule in rules):
                continue
            row = clock.query("SELECT host FROM clock WHERE id=?", (identity,)).fetchone()
            if row is None or row[0] in pending_tamper_hosts:
                continue
            if clock._tables and clock.query(
                    "SELECT 1 FROM records WHERE role='tamper' AND host=? LIMIT 1", (row[0],)).fetchone():
                continue
            removed.append((identity, len(body) + len(identity) + 64))
        before = budget.physical_used
        try:
            spill.cap()
            with spill.db:
                spill.db.executemany("DELETE FROM witnesses WHERE id=?", [(identity,) for identity, _size in removed])
        except sqlite3.Error as exc:
            self.owner.note_limit("linux_witness_reclaim", f"clock witness reclamation rolled back: {exc}")
            spill.grew()
            return 0
        if rows:
            self._reclaim_cursor = rows[-1][0]
        if removed:
            budget.charge(self.account(), -sum(size for _identity, size in removed))
            clock.note_limit("linux_clock_witnesses",
                f"{len(removed)} clock-only witness body/bodies released after actual disk FULL; exact clock IDs and "
                "timestamps remain, but some future discontinuity citations may be unresolved")
        try:
            # Also drain leftover free pages after the admission cursor is exhausted.
            spill.db.execute("PRAGMA incremental_vacuum(32)").fetchall()
        except sqlite3.Error as exc:
            self.owner.note_limit("linux_witness_reclaim", f"clock witness page reclamation was limited: {exc}")
        finally:
            spill.grew()
        # A scan step is progress even when protected rows or a foreign file's occupied pages prevent shrinking.
        return max(len(rows), before - budget.physical_used)

    def release(self, member):
        self.members.discard(id(member))
        if not self.members and self._spill is not None:
            self._spill.close()
            self._spill = None
            self.pending.clear()
            self.closed = True
            if self._account is not None:
                self._account.evict_references = self._account.reclaim_database = None


class LinuxSequence(Playbook):
    kind = "aggregate"
    staged = True
    os_families = ("linux",)
    assures_negative = False
    positive_only_reason = "These are positive temporal links in recorded telemetry; unrecorded activity is unresolved."
    argv_prefix_safe = True
    claim_type = "correlated_observation"
    uses_site_facts = True
    site_facts = absent_site_facts()
    HOT = 1024
    holds_state = True
    ROW_BYTES = 256
    name = "linux_join_rows"

    def __init__(self):
        super().__init__()
        self._tables = False
        self._account = None
        self._seen = RecentIds()
        self._pending = []
        self.witnesses = None
        self.load = lambda ids: []
        self.heartbeat = lambda: None
        self.rows_on_disk = 0
        self._last_refused = None
        self._rows_blocked_generation = None
        self.persisted_loader = lambda ids: []
        register_store(self, self)

    def account(self):
        if self._account is None:
            self._account = self.state_budget().account(f"{self.id}:rows")
        return self._account

    @property
    def pending_count(self):
        return len(self._pending)

    def store(self):
        spill = self.spill()
        if not self._tables:
            spill.table("records", "uid TEXT PRIMARY KEY, id, host, role, key, ts REAL, aux, lane, pid, ppid, boot, data")
            sql, rows = spill._buffers["records"]
            spill._buffers["records"] = (sql.replace("INSERT INTO", "INSERT OR IGNORE INTO"), rows)
            self._tables = True
        return spill

    def _row_room(self, event, name="linux_join_rows"):
        if (self._rows_blocked_generation is not None and not self._flush_rows()
                or store_refuses(self, self.account)):
            if self._last_refused != event.id:
                self.refuse(name, "the disk budget for Linux join rows is spent; this record was not joined")
                self._last_refused = event.id
            return False
        return True

    def _pending_row_limit(self, exc):
        self._rows_blocked_generation = self.state_budget()._capacity_generation
        for table, (_sql, rows) in self._spill._buffers.items():
            if rows:
                self.note_limit("linux_clock_rows" if table == "clock" else "linux_join_rows",
                    f"{len(rows)} accepted Linux {table} row(s) remain buffered after disk refusal: {exc}; "
                    "new join rows are refused until the buffer can be written")

    def _append_row(self, table, row):
        try:
            self._spill.add(table, row)
        except StateExhausted as exc:
            # The current row is still in Spill's bounded buffer; it was accepted, not dropped.
            self._pending_row_limit(exc)

    def _flush_rows(self, *, retry=False):
        if self._spill is None:
            return True
        if not retry and self._rows_blocked_generation == self.state_budget()._capacity_generation:
            return False
        try:
            self._spill.flush()
        except StateExhausted as exc:
            self._pending_row_limit(exc)
            return False
        self._rows_blocked_generation = None
        return True

    def add(self, event, role, key="", *, aux="", lane="lead", data=None):
        if not self._row_room(event):
            return False
        row = (_key(event.id, role, key), event.id, event.host or "", role, str(key), event.ts.timestamp(),
               str(aux), lane, event.get("process.pid"), event.get("process.ppid"),
               str(event.get("host.boot.id") or ""), json.dumps(data or {}, sort_keys=True))
        try:
            self.store()
        except StateExhausted as exc:
            if self._last_refused != event.id:
                self.refuse("linux_join_rows", f"Linux join storage refused a record: {exc}; later links are unresolved")
                self._last_refused = event.id
            return False
        self._append_row("records", row)
        self.state_budget().charge(self.account(), self.ROW_BYTES + len(row[-1]))
        self.rows_on_disk += 1
        if self.witnesses is None:
            self.witnesses = _LinuxWitnesses(self, [self])
        self.witnesses.hold(event)
        return True

    def consume(self, events):
        for event in self.applicable(events):
            if event.id in self._seen:
                self.evaluated -= 1
                continue
            self._seen.add(event.id)
            refused = self.capped
            self.observe(event)
            if self.capped > refused:
                self.evaluated -= 1
        return []

    def observe(self, event):
        raise NotImplementedError

    def drain_staged(self):
        self._flush_rows(retry=True)
        if self.witnesses is not None:
            self.witnesses.flush()
        return []

    def retained_events(self):
        return []

    def ready(self):
        if not self._tables:
            return False
        spill = self.spill()
        self._flush_rows(retry=True)
        spill.write("CREATE INDEX IF NOT EXISTS records_join ON records(role,host,key,ts)", [()])
        spill.write("CREATE INDEX IF NOT EXISTS records_cross_host ON records(role,key,ts,host)", [()])
        spill.write("CREATE INDEX IF NOT EXISTS records_pid ON records(host,pid,ts)", [()])
        return True

    def query(self, sql, params=()):
        return self.spill().db.execute(sql, params)

    def events(self, ids):
        ids = list(dict.fromkeys(identity for identity in ids if identity))
        events = self.witnesses.load(ids) if self.witnesses is not None else []
        if len(events) != len(ids):
            loaded = {event.id for event in events}
            events += self.load([identity for identity in ids if identity not in loaded])
        if len(events) != len(ids):
            loaded = {event.id for event in events}
            events += self.persisted_loader([identity for identity in ids if identity not in loaded])
        if len(events) != len(ids):
            self.note_limit("linux_join_citations", "some accepted join evidence could not be loaded for citation")
            raise CitationUnavailable(f"{self.id}: staged citations unavailable")
        return sorted(events, key=lambda event: (event.ts, event.id))

    def finding(self, group, ids, lane, text, count=1, notes=()):
        events = self.events(ids)
        if not events:
            return None
        match = Match(self.id, text, self.claim_type, events,
                      [pf(event, name) for event in events for name in FIELDS if event.has(name)],
                      events[0].ts, "high" if lane in {"urgent", "high"} else "info" if lane == "context" else "medium",
                      lane, "medium", events[0].entities(), list(notes), group_key=group,
                      bounded_revision=True, aggregate_summary={"count": count})
        return match

    def fold(self, sql, params, description, *, inferred=True):
        """SQL streams (group, first-id, second-id, optional-id, lane) in stable group/time order."""
        for group, rows in groupby(self.query(sql, params), key=lambda row: row[0]):
            count, cited, last, lane = 0, [], [], "context"
            for row in rows:
                _group, *witnesses, candidate = row
                count += 1
                current = [value for value in witnesses if value]
                if count <= CITE:
                    cited.extend(current)
                last = current
                if LANES[candidate] > LANES[lane]:
                    lane = candidate
            ids = list(dict.fromkeys(cited + last))
            text = f"{description} {count} linked record combination(s); first and last are cited."
            if inferred:
                text += " The temporal link is inferred, not proof that one action caused the other."
            if count > CITE:
                text += f" Bounded examples are cited ({min(count, CITE)} first combinations and the last)."
            yield self.finding(str(group), ids, lane, text, count)
            self.heartbeat()

    def release_state(self):
        self._pending.clear()
        self.load = lambda ids: []
        self.close_spill()
        if self.witnesses is not None:
            self.witnesses.release(self)


class DownloadThenExecute(LinuxSequence):
    id = "host.download_then_execute"
    title = "A downloader named or wrote a file that was subsequently executed"
    families = ("process_exec", "file_change")
    attack = ("T1105", "T1204.002")

    def observe(self, e):
        if e.outcome == Outcome.failure:
            return
        if e.family == "process_exec":
            downloading, paths = output_paths(e)
            if downloading:
                self.add(e, "downloader", str(e.get("process.pid") or ""),
                         data={"exe": e.get("process.executable"), "log_paths": download_log_paths(e)})
                for path in paths:
                    self.add(e, "download", path)
            for path in executed_paths(e):
                self.add(e, "execute", path, lane="high" if temporary(path) or web(e) else "lead")
            p = program(e)
            if p and p.name == "chmod" and any("x" in a and a.startswith(("+", "a+", "u+", "g+", "o+")) for a in p.args):
                for operand in p.args[1:]:
                    if path := normalize_path(operand, e.get("process.cwd")):
                        self.add(e, "attribute", path)
        elif e.get("file.change") in {"create", "content"} and e.has("file.path"):
            self.add(e, "write", str(e.get("file.path")), aux=str(e.get("process.pid") or ""),
                     data={"exe": e.get("process.executable")})
        elif e.get("file.change") == "attributes" and e.has("file.path"):
            self.add(e, "attribute", str(e.get("file.path")))

    def finalize(self):
        if not self.ready():
            return []
        # Kernel writes provide an output even when stdout redirection or one-liner code is not recoverable.
        self.spill().write(
            "INSERT OR IGNORE INTO records SELECT w.uid||d.uid,w.id,w.host,'download',w.key,w.ts,d.id,'lead',"
            "w.pid,w.ppid,w.boot,w.data FROM records w JOIN records d ON d.role='downloader' AND d.host=w.host "
            "AND d.key=w.aux AND d.key<>'' AND d.ts<=w.ts AND w.ts<=d.ts+? "
            "AND (w.boot='' OR d.boot='' OR w.boot=d.boot) "
            "AND (json_extract(w.data,'$.exe') IS NULL OR json_extract(w.data,'$.exe')=json_extract(d.data,'$.exe')) "
            "AND NOT EXISTS(SELECT 1 FROM json_each(d.data,'$.log_paths') log WHERE log.value=w.key) "
            "AND NOT EXISTS(SELECT 1 FROM records z WHERE z.role='execute' AND z.host=w.host "
            "AND z.pid=w.pid AND z.ts>d.ts AND z.ts<=w.ts) WHERE w.role='write'", [(W_DOWNLOAD_EXEC,)])
        sql = """SELECT x.host||'|'||x.key, COALESCE(NULLIF(d.aux,''),d.id), x.id,d.id,
            (SELECT a.id FROM records a WHERE a.role='attribute' AND a.host=x.host AND a.key=x.key
             AND a.ts BETWEEN d.ts AND x.ts ORDER BY a.ts,a.id LIMIT 1), x.lane
            FROM records x JOIN records d ON d.uid=(SELECT d2.uid FROM records d2
                WHERE d2.role='download' AND d2.host=x.host AND d2.key=x.key
                AND d2.ts<x.ts AND d2.ts>=x.ts-? AND (d2.boot='' OR x.boot='' OR d2.boot=x.boot)
                ORDER BY d2.ts DESC,d2.id LIMIT 1)
            WHERE x.role='execute' ORDER BY x.host,x.key,x.ts,x.id"""
        return self.fold(sql, (W_DOWNLOAD_EXEC,), "A downloader output path and a subsequent exec match on the same host.")


class AuthorizedKeyThenLogin(LinuxSequence):
    id = "host.authorized_key_then_login"
    title = "An authorized-key write preceded a public-key login for the file's account"
    families = ("file_change", "process_exec", "auth")
    attack = ("T1098.004",)

    def observe(self, e):
        if e.outcome == Outcome.failure:
            return
        paths = []
        if e.family == "file_change" and e.get("file.change") in {"create", "content", "link"}:
            paths = [str(e.get("file.path") or "")]
        elif e.family == "process_exec" and (p := program(e)):
            paths = [target.path for target in write_targets(p.name, p.args, e.get("process.cwd"))[0]]
        elif (e.family == "auth" and e.outcome == Outcome.success and e.get("auth.service") == "sshd"
              and e.get("auth.phase") == "authentication" and e.get("auth.method") == "publickey"):
            if e.has("user.name"):
                self.add(e, "login", str(e.get("user.name")))
            else:
                self.missing_required += 1
        for path in paths:
            if not path.endswith(("/.ssh/authorized_keys", "/.ssh/authorized_keys2")):
                continue
            owner, inferred = _owner(path, e)
            if not owner:
                self.missing_required += 1
                continue
            uid, owner_uid = e.get("process.uid"), e.get("file.owner.id")
            different = uid is not None and owner_uid is not None and str(uid) != str(owner_uid)
            self.add(e, "key_write", owner, aux=path, lane="high" if different or web(e) else "lead",
                     data={"owner_inferred": inferred})

    def finalize(self):
        if not self.ready():
            return []
        return self.fold("""SELECT w.host||'|'||w.key,w.id,l.id,NULL,w.lane FROM records l
            JOIN records w ON w.uid=(SELECT w2.uid FROM records w2 WHERE w2.role='key_write'
                AND w2.host=l.host AND w2.key=l.key AND w2.ts<l.ts AND w2.ts>=l.ts-?
                ORDER BY w2.ts DESC,w2.id LIMIT 1)
            WHERE l.role='login' ORDER BY w.host,w.key,l.ts,l.id""", (W_KEY_LOGIN,),
            "An authorized-key write preceded an sshd publickey success for its account; "
            "passwd-derived ownership is preferred, otherwise the home-directory account mapping is inferred.")


class ToolCleanup(DownloadThenExecute):
    id = "host.tool_cleanup"
    title = "An executed file was subsequently deleted"
    attack = ("T1070.004",)
    families = ("process_exec", "file_change", "auth")

    def observe_linked_match(self, match):
        """A published download/key-login link overrides a package working-directory exclusion."""
        for event in match.events:
            paths = [str(event.get("file.path"))] if event.has("file.path") else []
            if match.playbook_id == "host.download_then_execute":
                linked_path = match.group_key.partition("|")[2]
                if linked_path:
                    paths = [linked_path]
            for path in paths:
                if match.playbook_id == "host.download_then_execute" or path.endswith(
                        ("/.ssh/authorized_keys", "/.ssh/authorized_keys2")):
                    self.add(event, "linked", path)

    def observe(self, e):
        if e.outcome == Outcome.failure:
            return
        if e.family == "process_exec":
            for path in executed_paths(e):
                self.add(e, "execute", path)
            downloading, paths = output_paths(e)
            if downloading:
                for path in paths:
                    self.add(e, "linked", path)
        elif e.family == "file_change" and e.has("file.path"):
            path = str(e.get("file.path"))
            kind = e.get("file.change")
            if kind == "create":
                self.add(e, "create", path, lane="high" if temporary(path) or web(e) else "lead")
            elif kind == "delete":
                self.add(e, "delete", path)
            elif kind in {"content", "link"} and path.endswith(("/.ssh/authorized_keys", "/.ssh/authorized_keys2")):
                self.add(e, "linked", path)

    def finalize(self):
        if not self.ready():
            return []
        sql = """SELECT d.host||'|'||d.key,x.id,d.id,
            (SELECT c.id FROM records c WHERE c.role='create' AND c.host=x.host AND c.key=x.key
             AND c.ts BETWEEN d.ts-? AND x.ts ORDER BY c.ts,c.id LIMIT 1),
            CASE WHEN EXISTS(SELECT 1 FROM records c WHERE c.role='create' AND c.host=x.host AND c.key=x.key
                AND c.ts BETWEEN d.ts-? AND x.ts AND c.lane='high') THEN 'high' ELSE 'lead' END
            FROM records d JOIN records x ON x.uid=(SELECT x2.uid FROM records x2 WHERE x2.role='execute'
                AND x2.host=d.host AND x2.key=d.key AND x2.ts<d.ts AND x2.ts>=d.ts-?
                ORDER BY x2.ts DESC,x2.id LIMIT 1)
            WHERE d.role='delete' ORDER BY d.host,d.key,d.ts,d.id"""
        rows = self.query(sql, (W_CLEANUP, W_CLEANUP, W_CLEANUP))
        def allowed():
            for row in rows:
                path = row[0].split("|", 1)[1]
                excluded = under(path, CLEANUP_EXCLUSIONS) or bool(SYSTEMD_PRIVATE.match(path))
                if excluded and not self.query("SELECT 1 FROM records WHERE role='linked' AND host=? AND key=? LIMIT 1",
                                               (row[0].split("|", 1)[0], path)).fetchone():
                    continue
                yield row
        # The fold helper takes SQL; filter groups here without retaining the complete result.
        for group, hits in groupby(allowed(), key=lambda row: row[0]):
            ids, last, count, lane = [], [], 0, "lead"
            for _key_value, a, b, c, level in hits:
                count += 1
                last = [a, b, c]
                if count <= CITE:
                    ids += last
                if level == "high":
                    lane = level
            yield self.finding(group, ids + last, lane,
                f"An executed path was subsequently deleted on the same host ({count} deletion record(s)). "
                "The file identity and cleanup relationship are inferred from path and time; inode reuse is unresolved.",
                count)


class WebShellChain(LinuxSequence):
    id = "host.web_shell_chain"
    title = "A document-root script write was followed by a matching request and optional interpreter exec"
    families = ("file_change", "http_access", "process_exec")
    attack = ("T1505.003",)
    anchor_class = "web_shell"

    def observe(self, e):
        if e.family == "file_change" and e.outcome != Outcome.failure and e.get("file.change") in {"create", "content"}:
            path = str(e.get("file.path") or "")
            if (under(path, DOCUMENT_ROOTS) or TOMCAT_ROOT.match(path)) and posixpath.splitext(path)[1].lower() in SCRIPT_SUFFIXES:
                self.add(e, "script", posixpath.basename(path), aux=path, lane="lead" if web(e) else "context")
        elif e.family == "http_access":
            path = e.get("url.path") or e.get("url.original")
            if path:
                leaf = posixpath.basename(urlsplit(str(path)).path)
                status = e.get("http.response.status_code")
                self.add(e, "request", leaf, lane="lead" if status == 404 else "high")
            else:
                self.missing_required += 1
        elif e.family == "process_exec" and e.outcome != Outcome.failure and web(e):
            p = program(e)
            if p and p.name in INTERPRETERS:
                self.add(e, "interpreter")

    def finalize(self):
        if not self.ready():
            return []
        sql = """SELECT c.host||'|'||c.aux,c.id,r.id,
            (SELECT x.id FROM records x WHERE x.role='interpreter' AND x.host=c.host
             AND x.ts>=r.ts AND x.ts<=r.ts+? ORDER BY x.ts,x.id LIMIT 1),
            CASE WHEN r.id IS NULL THEN 'lead' WHEN r.lane='lead' THEN 'lead'
                 WHEN EXISTS(SELECT 1 FROM records x WHERE x.role='interpreter' AND x.host=c.host
                   AND x.ts>=r.ts AND x.ts<=r.ts+?) THEN 'urgent' ELSE 'high' END
            FROM records c LEFT JOIN records r ON r.uid=(SELECT r2.uid FROM records r2 WHERE r2.role='request'
                AND r2.host=c.host AND r2.key=c.key AND r2.ts>c.ts AND r2.ts<=c.ts+?
                ORDER BY CASE WHEN r2.lane='high' AND EXISTS(SELECT 1 FROM records x
                    WHERE x.role='interpreter' AND x.host=r2.host AND x.ts>=r2.ts AND x.ts<=r2.ts+?)
                    THEN 0 WHEN r2.lane='high' THEN 1 ELSE 2 END,r2.ts,r2.id LIMIT 1)
            WHERE c.role='script' AND (r.id IS NOT NULL OR c.lane='lead') ORDER BY c.host,c.aux,c.ts,c.id"""
        return self.fold(sql, (W_DOWNLOAD_EXEC, W_DOWNLOAD_EXEC, W_SHELL_REQUEST, W_DOWNLOAD_EXEC),
            "A server-side script write under a default document root, its optional HTTP request, and "
            "optional web-service interpreter exec share a host. URL-to-file matching uses basename only; "
            "interpreter evidence is the same typed account/executable evidence as host.web_service_spawns_interpreter.")


class DiscoveryBurst(LinuxSequence):
    id = "host.discovery_burst"
    title = "At least five discovery classes ran in one recorded login session within ten minutes"
    families = ("process_exec",)
    attack = ("T1033", "T1082", "T1016", "T1049", "T1057", "T1083")

    def observe(self, e):
        p = program(e)
        if not p or e.outcome == Outcome.failure:
            return
        if argv_incomplete(e) and p.name in _DISCOVERY_BY_ABSENCE:
            self.missing_required += 1
            return
        found = classify_discovery(p.name, p.args, e.get("process.cwd"))
        if not found:
            return
        session, auid = e.get("process.session_id"), e.get("process.auid")
        if session in (None, 4294967295, "4294967295", -1, "-1") or auid in (None, "4294967295", "-1"):
            self.missing_required += 1
            return
        key = _key(e.host, str(auid), str(session), e.get("host.boot.id"))
        self.add(e, "discovery", key, aux=found[0], lane="high" if web(e) else "lead")

    def finalize(self):
        if not self.ready():
            return []
        for (session,) in self.query("SELECT DISTINCT key FROM records WHERE role='discovery' ORDER BY key"):
            start = self.query("""SELECT a.ts FROM records a WHERE a.role='discovery' AND a.key=?
                AND (SELECT COUNT(DISTINCT b.aux) FROM records b WHERE b.role='discovery' AND b.key=a.key
                     AND b.ts BETWEEN a.ts AND a.ts+?)>=?
                ORDER BY CASE WHEN EXISTS(SELECT 1 FROM records h WHERE h.role='discovery' AND h.key=a.key
                    AND h.ts BETWEEN a.ts AND a.ts+? AND h.lane='high') THEN 0 ELSE 1 END,
                    a.ts,a.id LIMIT 1""", (session, W_DISCOVERY, N_DISCOVERY, W_DISCOVERY)).fetchone()
            if start is None:
                continue
            # At most one representative per fixed discovery class plus span bounds.
            rows = self.query("""SELECT aux,MIN(ts),MIN(id),MAX(lane) FROM records WHERE role='discovery'
                AND key=? AND ts BETWEEN ? AND ? GROUP BY aux ORDER BY aux""",
                (session, start[0], start[0] + W_DISCOVERY))
            ids, classes, lane = [], [], "lead"
            for klass, _when, identity, _level in rows:
                ids.append(identity)
                classes.append(klass)
            high = self.query("SELECT id FROM records WHERE key=? AND role='discovery' AND ts BETWEEN ? AND ? "
                              "AND lane='high' ORDER BY ts,id LIMIT 1",
                              (session, start[0], start[0] + W_DISCOVERY)).fetchone()
            if high:
                lane = "high"
                if high[0] not in ids:
                    ids.append(high[0])
            yield self.finding(session, ids, lane,
                f"One recorded audit login session ran {len(classes)} distinct discovery classes within "
                f"{W_DISCOVERY} seconds: {', '.join(classes)}. Classes share the expansion classifier; "
                "the session identity is recorded, and intent is inferred.", len(classes))


class UnbrokeredPrivilegeTransition(LinuxSequence):
    id = "host.unbrokered_privilege_transition"
    title = "A non-root login identity executed with root privileges without an observed sanctioned broker"
    families = ("process_exec",)
    attack = ("T1068", "T1548")

    def observe(self, e):
        if e.outcome != Outcome.failure and e.has("process.executable") and e.has("process.pid"):
            data = {"exe": e.get("process.executable"),
                    "candidate": _login_user_is_nonroot(e) and str(e.get("process.euid")) == "0"}
            self.add(e, "exec", str(e.get("process.pid")), data=data)

    def finalize(self):
        if not self.ready():
            return []
        for identity, host, when, pid, parent, boot, data in self.query(
                "SELECT id,host,ts,pid,ppid,boot,data FROM records WHERE role='exec' ORDER BY host,ts,id"):
            if not json.loads(data)["candidate"]:
                continue
            ids, complete, broker = [identity], False, False
            visited = {pid}
            for _ in range(LINEAGE_DEPTH):
                if parent in (0, 1):
                    complete = True
                    break
                if parent is None or parent in visited:
                    break
                visited.add(parent)
                row = self.query("""SELECT id,ts,pid,ppid,data FROM records WHERE role='exec' AND host=?
                    AND pid=? AND ts<=? AND (boot='' OR ?='' OR boot=?)
                    ORDER BY ts DESC,id LIMIT 1""", (host, parent, when, boot, boot)).fetchone()
                if row is None:
                    break
                ancestor, when, _pid, parent, body = row
                exe = str(json.loads(body)["exe"])
                ids.append(ancestor)
                name = posixpath.basename(exe)
                if (name in SANCTIONED_BROKERS
                        and posixpath.dirname(exe) in BASE_PACKAGE_DIRS | PACKAGE_EXTRA_DIRS.get(name, frozenset())):
                    broker = True
                    break
            if broker:
                continue
            lane = "high" if complete else "lead"
            reason = ("the observed parent chain reaches its root without a sanctioned broker"
                      if complete else "the parent chain is incomplete (pid table gap or depth bound); whether elevation was brokered is unresolved")
            yield self.finding(f"{host}|{identity}", ids, lane,
                f"On {host}, an exec has root uid/euid and a non-root kernel login identity; {reason}. "
                "Privilege gain is inferred from the recorded credentials and lineage.")


class InteractivePrivilegedLogin(LinuxSequence):
    id = "host.interactive_privileged_login"
    title = "Root or a service account completed interactive SSH authentication"
    families = ("auth",)
    attack = ("T1078", "T1021.004")

    def observe(self, e):
        if (e.outcome != Outcome.success or e.get("auth.service") != "sshd"
                or e.get("auth.phase") != "authentication"):
            return
        user, source = e.get("user.name"), e.get("source.ip")
        if not user or not source:
            self.missing_required += 1
            return
        uid = e.get("user.id")
        service = web(e) or str(uid).isdigit() and 0 < int(uid) < 1000
        if user != "root" and not service:
            return
        lane = "high" if service else "context" if address_member(source, self.site_facts.management_hosts) else "lead"
        self.add(e, "login", _key(e.host, user, source), lane=lane)

    def finalize(self):
        if not self.ready():
            return []
        return self.fold("SELECT key,id,NULL,NULL,lane FROM records WHERE role='login' ORDER BY key,ts,id", (),
                              "Successful sshd interactive authentication by root or a service account.",
                              inferred=False)


class OutboundSSHExternal(LinuxSequence):
    id = "net.outbound_ssh_external"
    title = "An internal source initiated SSH to an external destination"
    os_families = ("linux", "windows")
    families = ("net_flow", "net_session", "net_socket")
    attack = ("T1021.004", "T1572")
    direction_dependent = True

    def observe(self, e):
        source, destination = canon_ip(e.get("source.ip")), canon_ip(e.get("destination.ip"))
        if not source or not destination:
            self.missing_required += 1
            return
        proto = e.get("network.app_proto") or e.get("network.protocol")
        protocols = e.get("network.protocols") or []
        ssh = proto == "ssh" or "ssh" in protocols
        if not (ssh or e.get("network.transport") == "tcp" and e.get("destination.port") == 22):
            return
        assume_direction(self)
        if external(source) or not external(destination):
            return
        lane = "context" if address_member(source, self.site_facts.management_hosts) else "lead"
        self.add(e, "ssh", _key(source, destination), lane=lane)

    def finalize(self):
        if not self.ready():
            return []
        return self.fold("SELECT key,id,NULL,NULL,lane FROM records WHERE role='ssh' ORDER BY key,ts,id", (),
            "Recorded outbound SSH from an internal source to an external destination; connection rows may "
            "come from more than one sensor and are counted as records.", inferred=False)


class AlertThenHostExecution(LinuxSequence):
    id = "corr.alert_then_host_execution"
    title = "An inbound high-severity IDS alert preceded service-account execution on its destination host"
    families = ("net_alert", "process_exec", "auth", "process_observed", "net_socket", "file_change")
    os_families = ("linux", "windows")
    attack = ("T1190", "T1210")
    direction_dependent = True

    def observe(self, e):
        if e.family == "net_alert":
            severity, dst = e.get("alert.severity"), canon_ip(e.get("destination.ip"))
            if type(severity) is int and severity in (1, 2) and dst:
                assume_direction(self)
                if not external(dst):
                    self.add(e, "alert", dst, aux=str(e.get("destination.port") or ""))
            return
        addresses = e.get("host.ip") or []
        addresses = [addresses] if isinstance(addresses, str) else addresses
        for address in addresses:
            if ip := canon_ip(address):
                if not getattr(self, "_address_index", False):
                    self.store().write("CREATE INDEX IF NOT EXISTS records_address ON records(host,key,id) "
                                       "WHERE role='address'", [()])
                    self._address_index = True
                # Ownership is a set, with exactly the minimum event-id witness selected by the join.
                prior = self.store().execute(
                    "SELECT uid,id FROM records WHERE role='address' AND host=? AND key=? ORDER BY id LIMIT 1",
                    (e.host or "", ip)).fetchone()
                if prior is None:
                    self.add(e, "address", ip)
                elif e.id < prior[1]:
                    self.spill().write("UPDATE records SET id=?,ts=? WHERE uid=?",
                                       [(e.id, e.ts.timestamp(), prior[0])])
                    if self.witnesses is None:
                        self.witnesses = _LinuxWitnesses(self, [self])
                    self.witnesses.hold(e)
        if e.family == "process_exec" and e.outcome != Outcome.failure:
            self.add(e, "execution", lane="high" if web(e) else "lead")
        if (e.family == "net_socket" and e.outcome == Outcome.success and e.get("socket.syscall") == "bind"
                and e.has("socket.local.port") and e.has("process.pid")):
            self.add(e, "listener", str(e.get("socket.local.port")), aux=str(e.get("socket.local.ip") or ""))

    def finalize(self):
        if not self.ready():
            return []
        unmapped = self.query("""SELECT COUNT(*) FROM records a WHERE a.role='alert'
            AND (SELECT COUNT(DISTINCT h.host) FROM records h WHERE h.role='address' AND h.key=a.key)<>1""").fetchone()[0]
        if unmapped:
            self.note_coverage("alert_host_unmapped",
                f"{unmapped} inbound alert destination(s) had no unique observed host.ip mapping; host execution linkage was unresolved.")
        sql = """SELECT h.host||'|'||a.key,a.id,x.id,
            (SELECT l.id FROM records l WHERE l.role='listener' AND l.host=x.host AND l.pid=x.ppid
             AND l.key=a.aux AND l.ts<=x.ts AND (l.aux=a.key OR l.aux IN ('0.0.0.0','::'))
             AND (l.boot='' OR x.boot='' OR l.boot=x.boot) ORDER BY l.ts DESC,l.id LIMIT 1),'high' FROM records a
            JOIN records h ON h.uid=(SELECT h2.uid FROM records h2 WHERE h2.role='address' AND h2.key=a.key
                ORDER BY h2.host,h2.id LIMIT 1)
            JOIN records x ON x.uid=(SELECT x2.uid FROM records x2 WHERE x2.role='execution'
                AND x2.host=h.host AND x2.ts>a.ts AND x2.ts<=a.ts+?
                AND (x2.lane='high' OR EXISTS(SELECT 1 FROM records l WHERE l.role='listener'
                    AND l.host=x2.host AND l.pid=x2.ppid AND l.key=a.aux AND l.ts<=x2.ts
                    AND (l.aux=a.key OR l.aux IN ('0.0.0.0','::'))
                    AND (l.boot='' OR x2.boot='' OR l.boot=x2.boot)))
                ORDER BY x2.ts,x2.id LIMIT 1)
            WHERE a.role='alert' AND (SELECT COUNT(DISTINCT h3.host) FROM records h3
                WHERE h3.role='address' AND h3.key=a.key)=1 ORDER BY h.host,a.key,a.ts,a.id"""
        return self.fold(sql, (W_ALERT_EXEC,), "An inbound severity 1-2 IDS alert was followed by a "
            "web-service-account exec or a child of the recorded listening process on the uniquely "
            "host.ip-mapped destination host; exploit success is inferred.")


class TelemetryGapAfterTamper(LinuxSequence):
    id = "host.telemetry_gap_after_tamper"
    title = "Indexed host telemetry has a discontinuity after an observed logging tamper action"
    families = ("process_exec", "process_observed", "file_change", "file_access", "kernel_module", "net_socket",
                "auth", "account_change", "service_change", "audit_config", "system_state", "privilege_use", "http_access")
    attack = ("T1685", "T1070")

    def store(self):
        spill = super().store()
        if not getattr(self, "_tamper_host_index", False):
            spill.write("CREATE INDEX IF NOT EXISTS records_tamper_host ON records(host) WHERE role='tamper'", [()])
            self._tamper_host_index = True
        return spill

    @staticmethod
    def series(e):
        if e.has("audit.serial"):
            return "auditd"
        if e.has("journal.identifier") or e.has("journal.unit"):
            return "journald"
        if e.family == "http_access":
            return "apache"
        return e.family

    def observe(self, e):
        if not self._row_room(e, "linux_clock_rows"):
            return
        host, family = e.host or "", self.series(e)
        spill = self.spill()
        if not getattr(self, "_clock_tables", False):
            spill.table("clock", "id TEXT PRIMARY KEY, host, key, ts REAL")
            sql, rows = spill._buffers["clock"]
            spill._buffers["clock"] = (sql.replace("INSERT INTO", "INSERT OR IGNORE INTO"), rows)
            self._clock_tables = True
        self._append_row("clock", (e.id, host, family, e.ts.timestamp()))
        self.rows_on_disk += 1
        self.state_budget().charge(self.account(), len(e.id) + len(host) + len(family) + 32)
        if self.witnesses is None:
            self.witnesses = _LinuxWitnesses(self, [self])
        self.witnesses.hold(e)

    def observe_tamper_match(self, match):
        """Accept only findings the existing tamper evaluators actually publish."""
        if match.playbook_id not in {"host.audit_rules_tamper", "host.security_or_logging_service_stop",
                                     "host.log_or_history_clearing"}:
            return
        for event in match.events:
            if event.id not in match.context_ids:
                self._tamper_event(event, match.playbook_id)

    def _tamper_event(self, e, rule_id):
        from romulus.detect.tamper import AuditRulesTamper, log_requests, service_requests
        targets = set()
        if e.outcome == Outcome.failure:
            return
        if e.family == "audit_config" and rule_id == "host.audit_rules_tamper" and AuditRulesTamper._config_kind(e):
            targets.add("auditd")
        if e.family == "service_change" and e.get("service.job") == "stop":
            unit = str(e.get("service.unit") or "").split(".", 1)[0]
            if unit in {"auditd", "systemd-journald", "rsyslog"}:
                targets.add("auditd" if unit == "auditd" else "journald")
        if e.family == "process_exec" and (p := program(e)):
            if AuditRulesTamper._requests(p.name, p.args, e.get("process.cwd")):
                targets.add("auditd")
            for _verb, unit, _why in service_requests(p.name, p.args):
                if unit in {"auditd", "systemd-journald", "rsyslog"}:
                    targets.add("auditd" if unit == "auditd" else "journald")
            for _kind, path, _why, _lane in log_requests(p.name, p.args, e.get("process.cwd")):
                if path.startswith("/var/log/audit/"):
                    targets.add("auditd")
                elif path in {"/var/log/syslog", "/var/log/messages"} or path.startswith("/var/log/journal/"):
                    targets.add("journald")
        for target in targets:
            self.add(e, "tamper", target)

    def finalize(self):
        # Without a published tamper there is no gap predicate to evaluate or extra index to build.
        if not self._tables:
            return []
        if not self.ready() or self.capped:
            if self.capped:
                self.note_coverage("telemetry_clock_partial",
                    "Some index-time rows were refused; discontinuity intervals were not judged.")
            return []
        self.spill().write("CREATE INDEX IF NOT EXISTS clock_family_time ON clock(host,key,ts)", [()])
        self.spill().write("CREATE INDEX IF NOT EXISTS clock_host_time ON clock(host,ts,id)", [()])
        for identity, host, family, start in self.query(
                "SELECT id,host,key,ts FROM records WHERE role='tamper' ORDER BY host,ts,id"):
            end_row = self.query("SELECT MIN(ts) FROM clock WHERE host=? AND key=? AND ts>?",
                                 (host, family, start)).fetchone()
            resumed = end_row[0]
            end = resumed
            if end is None:
                end = self.query("SELECT MAX(ts) FROM clock WHERE host=?", (host,)).fetchone()[0]
            if end is None or end - start < G_SILENCE:
                continue
            witnesses = list(self.query("""SELECT id,ts,key FROM clock WHERE host=?
                AND key<>? AND ts>? AND ts<=? ORDER BY ts DESC,id LIMIT 2""", (host, family, start, end)))
            if not witnesses or witnesses[0][1] - start < G_SILENCE:
                continue
            until = datetime.fromtimestamp(end, UTC).isoformat()
            began = datetime.fromtimestamp(start, UTC).isoformat()
            text = (f"No {family} records from {host} were in the swept index records after {began} and before "
                    f"{until}, while other host families continued. This is an index coverage fact after a "
                    "tampering observation; host activity or its absence is not established.")
            if resumed is None:
                text += " The observed host window ends inside the gap."
            yield self.finding(_key(host, family, start), [identity, *(r[0] for r in witnesses)], "lead", text)


SEQUENCE_RULES = [DownloadThenExecute, AuthorizedKeyThenLogin, ToolCleanup, WebShellChain, DiscoveryBurst,
                  UnbrokeredPrivilegeTransition, InteractivePrivilegedLogin, OutboundSSHExternal,
                  AlertThenHostExecution, TelemetryGapAfterTamper]


def share_linux_witnesses(pack):
    """Bind one compact witness store to a hunt's fixed set of Linux sequence evaluators."""
    members = [rule for rule in pack if isinstance(rule, LinuxSequence)]
    if members:
        witnesses = _LinuxWitnesses(members[0], members)
        for rule in members:
            rule.witnesses = witnesses
