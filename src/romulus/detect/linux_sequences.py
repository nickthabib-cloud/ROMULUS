"""Disk-backed Linux follow-on observations.

Only compact typed join rows are retained in memory, inside the existing spill's fixed-size write
buffer. The final joins use indexed disk tables and stream one folded group at a time. Time
windows restrict links, never retention: a late batch can still join any earlier accepted row.
"""
from __future__ import annotations

import hashlib
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
    KeyedStore,
    RecentIds,
    Spill,
    StateExhausted,
    register_store,
    store_refuses,
)
from romulus.detect.citing import uncited_positive
from romulus.detect.correlation import canon_ip, external
from romulus.detect.host import INTERPRETERS, SHELLS, WEB_SERVICE_USERS, ExecLineage
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
from romulus.detect.observed import citation_pointer
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
# Five-minute bins are shorter than one third of the discontinuity threshold. Any later record
# in the tamper bin disproves an immediate 15-minute gap; other bins retain their exact edges.
CLOCK_BIN = 300
LINEAGE_DEPTH = 32
CITE = 20
# Sensor and host clocks differ, and a shell spawned by the request just before the alerting one is the same
# intrusion; five minutes covers both while an hours-old record of a reused pid stays out.
ALERT_SKEW = 300
# Processes walked between lineage trims: amortizes the trim's sampling while bounding what parent walks bring back.
TRIM_EVERY = 512
# Exploitable application-server accounts (Java app servers, CI, search, databases). Their builds and archive
# commands run one-liners routinely, so after an alert they are leads, not HIGH.
APPLICATION_ACCOUNTS = frozenset({"tomcat", "jetty", "jboss", "wildfly", "weblogic", "glassfish", "jenkins", "solr",
                                  "elasticsearch", "opensearch", "confluence", "jira", "bitbucket", "gitlab-www",
                                  "nexus", "sonar", "activemq", "postgres", "mysql", "redis", "mongodb"})
TOMCAT_ACCOUNT = re.compile(r"tomcat\d*")


def application_account(event):
    names = (str(event.get(name) or "") for name in ("process.user", "process.effective_user", "user.name"))
    return any(name in APPLICATION_ACCOUNTS or bool(TOMCAT_ACCOUNT.fullmatch(name)) for name in names)
SCRIPT_SUFFIXES = frozenset({".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh"})
DOCUMENT_ROOTS = ("/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/opt/lampp/htdocs")
TOMCAT_ROOT = re.compile(r"^/var/lib/tomcat[^/]*/webapps(?:/|$)")
# Public leaf directories of a per-site tree under a default root (/var/www/<site>/public_html).
DOCROOT_LEAVES = frozenset({"html", "htdocs", "httpdocs", "public_html", "public", "web", "www", "wwwroot"})
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


# Configuration-management modules are routinely executed and removed from these typed staging paths.
CONFIG_STAGING = (
    re.compile(r"^/(?:home/[^/]+|root)/\.ansible/tmp/ansible-tmp-[^/]+/AnsiballZ_[^/]+$"),
    re.compile(r"^/var/cache/salt/minion(?:/|$)"),
    re.compile(r"^/var/cache/(?:puppet|puppetlabs|chef)(?:/|$)"),
    re.compile(r"^/var/lib/(?:puppet|puppetlabs|chef)/cache(?:/|$)"),
    re.compile(r"^/(?:opt/puppetlabs/puppet|var/chef)/cache(?:/|$)"),
)


def config_staging(path):
    return any(pattern.match(path) for pattern in CONFIG_STAGING)


def cleanup_directory(path):
    match = next((pattern.match(path) for pattern in CONFIG_STAGING if pattern.match(path)), None)
    if match:
        return re.sub(r"/ansible-tmp-[^/]+.*$", "", match[0].rstrip("/"))
    return posixpath.dirname(path)


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
        """Join witnesses remain required; clock bins retain their own bounded source pointers."""
        return 0

    def release(self, member):
        self.members.discard(id(member))
        if not self.members and self._spill is not None:
            self._spill.close()
            self._spill = None
            self.pending.clear()
            self.closed = True
            if self._account is not None:
                self._account.evict_references = self._account.reclaim_database = None


class _SharedLinuxRows:
    """The download, cleanup and alert readers share one execution row and one physical database."""

    def __init__(self, members):
        self.owner, self.members = members[0], {id(rule) for rule in members}
        self.database = None
        self.seen = RecentIds()

    def spill(self):
        if self.database is None:
            self.database = Playbook.spill(self.owner)
        return self.database

    def release(self, member):
        self.members.discard(id(member))
        if not self.members and self.database is not None:
            self.database.close()
            self.database = None


class LinuxSequence(Playbook):
    version = "2"
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
        self.shared_rows = None
        if self.id in {"host.download_then_execute", "host.tool_cleanup", "host.web_shell_chain",
                       "host.unbrokered_privilege_transition", "host.discovery_burst", "corr.alert_then_host_execution"}:
            self.execs = ExecLineage(self, citing=True)
        register_store(self, self)

    def spill(self):
        if self.shared_rows is not None:
            self._spill = self.shared_rows.spill()
            return self._spill
        return super().spill()

    def execution(self, event):
        shared = self.shared_rows
        if shared is not None:
            if event.id in shared.seen:
                return
            shared.seen.add(event.id)
        p = program(event)
        writable = temporary(str(event.get("process.executable") or ""))
        one_liner = bool(p and p.name in INTERPRETERS and any(a in {"-c", "-e", "--eval"} for a in p.args))
        # Root, login and service accounts run shell one-liners routinely (cron, systemd, monitoring agents such as
        # NRPE and Zabbix), so only a web account's one-liner or writable executable is strong without lineage. An
        # exploitable application server's account doing the same is a lead (builds and archive commands are routine).
        strong = web(event) and (writable or one_liner)
        application = (writable or one_liner) and application_account(event)
        for path in executed_paths(event):
            self.add(event, "execute", path, lane="high" if temporary(path) or web(event) else "lead",
                     data={"account": event.get("process.user") or event.get("process.uid"),
                           **({"web": True} if web(event) else {}), **({"writable": True} if writable else {}),
                           **({"application": True} if application else {}), **({"strong": True} if strong else {})})

    def parent_record(self, host, pid, when, boot):
        record = self.execs.latest(host, pid, when)
        return record if record is not None and (not boot or not record.boot or boot == record.boot) else None

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
            if "records" in spill._buffers:
                self._tables = True
                return spill
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
        identity = _key(event.id, role, key)
        # An opaque fixed-size execute key avoids repeating long source IDs and paths in both B-tree indexes.
        uid = hashlib.sha256(identity.encode()).digest() if role == "execute" else identity
        row = (uid, event.id, event.host or "", role, str(key), event.ts.timestamp(),
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
        # The existing shared lineage already keeps a verified-source pointer for each exec.
        # Standalone callers without raw sources retain their complete witness instead.
        if not (event.family == "process_exec" and hasattr(self, "execs") and self.raw_of(event)):
            self.witnesses.hold(event)
        return True

    def consume(self, events):
        for event in self.applicable(events):
            if event.id in self._seen:
                self.evaluated -= 1
                continue
            self._seen.add(event.id)
            if event.family == "process_exec" and hasattr(self, "execs"):
                self.execs.observe(event, self.raw_of(event), self.raw_target())
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
        if len(events) != len(ids) and hasattr(self, "execs"):
            loaded = {event.id for event in events}
            found, _raw = self.execs.cited([identity for identity in ids if identity not in loaded])
            events += list(found.values())
        if len(events) != len(ids):
            missing = sorted(set(ids) - {event.id for event in events})
            self.note_limit("linux_join_citations", "some accepted join evidence could not be loaded for citation")
            raise CitationUnavailable(f"{self.id}: citation(s) {', '.join(missing)} unavailable: "
                                      "not retained, reclaimed, or refused at the disk ceiling")
        return sorted(events, key=lambda event: (event.ts, event.id))

    def finding(self, group, ids, lane, text, count=1, notes=(), span=None):
        ids = list(dict.fromkeys(identity for identity in ids if identity))
        if span is None and self._tables and ids:
            span = self.query(f"SELECT MIN(ts),MAX(ts) FROM records WHERE id IN ({','.join('?' for _ in ids)})", ids).fetchone()
        try:
            events = self.events(ids)
        except CitationUnavailable as error:
            match = uncited_positive(self, group, {"ids": ids, "first": span[0] if span else None})
            match.proposed_lane = lane
            match.severity = "high" if lane in {"urgent", "high"} else "info" if lane == "context" else "medium"
            match.claim = text + " Citation coverage is partial: " + str(error) + "."
            match.notes += [*notes, str(error)]
            match.revision_reason = "The computed temporal positive remains valid; its citation coverage is now partial."
            match.aggregate_summary = {"count": count, "peak": count, "episodes": 1,
                                       "first": span[0] if span and span[0] is not None else 0,
                                       "last": span[1] if span and span[1] is not None else 0}
            match.bounded_revision = True
            return match
        if not events:
            return None
        match = Match(self.id, text, self.claim_type, events,
                      [pf(event, name) for event in events for name in FIELDS if event.has(name)],
                      events[0].ts, "high" if lane in {"urgent", "high"} else "info" if lane == "context" else "medium",
                      lane, "medium", events[0].entities(), list(notes), group_key=group,
                      bounded_revision=True, aggregate_summary={"count": count, "peak": count, "episodes": 1,
                          "first": span[0] if span and span[0] is not None else events[0].ts.timestamp(),
                          "last": span[1] if span and span[1] is not None else events[-1].ts.timestamp()})
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
        if self.shared_rows is None:
            self.close_spill()
        else:
            self.shared_rows.release(self)
            self._spill = None
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
            self.execution(e)
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
            self.execution(e)
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
        self.spill().db.create_function("cleanup_directory", 1, cleanup_directory)
        self.spill().db.create_function("config_staging", 1, config_staging)
        sql = sql.replace("THEN 'high' ELSE 'lead' END", "THEN 'high' WHEN config_staging(d.key) "
                          "AND NOT EXISTS(SELECT 1 FROM records l WHERE l.role='linked' AND l.host=d.host "
                          "AND l.key=d.key) THEN 'context' ELSE 'lead' END")
        sql = sql.replace("d.host||'|'||d.key", "d.host||'|'||cleanup_directory(d.key)||'|'||COALESCE(json_extract(x.data,'$.account'),'')")
        sql = sql.replace("ORDER BY d.host,d.key,d.ts,d.id", "ORDER BY 1,d.ts,d.id")
        rows = self.query(sql, (W_CLEANUP, W_CLEANUP, W_CLEANUP))
        def allowed():
            for row in rows:
                path = self.query("SELECT key FROM records WHERE role='delete' AND id=? LIMIT 1", (row[2],)).fetchone()[0]
                excluded = under(path, CLEANUP_EXCLUSIONS) or bool(SYSTEMD_PRIVATE.match(path))
                if excluded and not self.query("SELECT 1 FROM records WHERE role='linked' AND host=? AND key=? LIMIT 1",
                                               (row[0].split("|", 1)[0], path)).fetchone():
                    continue
                yield row
        # The fold helper takes SQL; filter groups here without retaining the complete result.
        for group, hits in groupby(allowed(), key=lambda row: row[0]):
            ids, last, count, lane = [], [], 0, "context"
            for _key_value, a, b, c, level in hits:
                count += 1
                last = [a, b, c]
                if count <= CITE:
                    ids += last
                if LANES[level] > LANES[lane]:
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

    @staticmethod
    def docroot(event):
        for field in ("http.document_root", "apache.document_root", "nginx.document_root", "web.document_root"):
            value = event.get(field)
            if value and str(value).startswith("/"):
                return posixpath.normpath(str(value))
        return ""

    @staticmethod
    def layout_roots(path):
        """Document roots the packaged server layouts imply for a script path when no root is recorded: the default
        root, a per-site directory under it, and that site's public leaf; for Tomcat, webapps (whose first component
        is the context path) and its ROOT context."""
        found = TOMCAT_ROOT.match(path)
        if found:
            base = found.group(0).rstrip("/")
            return [base, base + "/ROOT"]
        for root in DOCUMENT_ROOTS:
            if under(path, (root,)):
                parts = [part for part in posixpath.relpath(posixpath.dirname(path), root).split("/") if part != "."]
                roots = [root]
                if parts:
                    roots.append(f"{root}/{parts[0]}")
                    if len(parts) > 1 and parts[1] in DOCROOT_LEAVES:
                        roots.append(f"{root}/{parts[0]}/{parts[1]}")
                return roots
        return []

    def observe(self, e):
        if e.family == "file_change" and e.outcome != Outcome.failure and e.get("file.change") in {"create", "content"}:
            path = str(e.get("file.path") or "")
            root = self.docroot(e)
            if (root and under(path, (root,)) or under(path, DOCUMENT_ROOTS) or TOMCAT_ROOT.match(path)) and posixpath.splitext(path)[1].lower() in SCRIPT_SUFFIXES:
                self.add(e, "script", posixpath.basename(path), aux=path, lane="lead" if web(e) else "context",
                         data={"root": root, "created": e.get("file.change") == "create", "web": web(e)})
        elif e.family == "http_access":
            path = e.get("url.path") or e.get("url.original")
            if not path:
                self.missing_required += 1
                return
            path = urlsplit(str(path)).path
            leaf = posixpath.basename(path)
            if posixpath.splitext(leaf)[1].lower() not in SCRIPT_SUFFIXES | {""}:
                return
            self.add(e, "request", leaf, aux=path,
                     lane="lead" if e.get("http.response.status_code") == 404 else "high",
                     data={"root": self.docroot(e)})
        elif e.family == "process_exec" and e.outcome != Outcome.failure:
            p = program(e)
            if p and p.name in INTERPRETERS and web(e):
                self.add(e, "interpreter")
            elif p and (p.name in {"httpd", "apache2", "nginx"} or re.fullmatch(r"php-fpm(?:[0-9.]+)?", p.name)) and not self.raw_of(e):
                if self.witnesses is None:
                    self.witnesses = _LinuxWitnesses(self, [self])
                self.witnesses.hold(e)

    def web_ancestor(self, host, pid, when, boot):
        visited = set()
        for _ in range(LINEAGE_DEPTH):
            if not isinstance(pid, int) or pid in visited or pid in (0, 1):
                return None
            visited.add(pid)
            record = self.parent_record(host, pid, when, boot)
            if record is None:
                return None
            name = posixpath.basename(record.exe)
            if name in {"httpd", "apache2", "nginx"} or re.fullmatch(r"php-fpm(?:[0-9.]+)?", name):
                return record.event_id
            pid, when = record.ppid, record.ts
        return None

    def finalize(self):
        if not self.ready():
            return []
        for host, path in self.query("SELECT DISTINCT host,aux FROM records WHERE role='script' ORDER BY host,aux"):
            count, ids, lane = 0, [], "context"
            roots = self.query("SELECT COUNT(DISTINCT json_extract(data,'$.root')) FROM records "
                               "WHERE role='script' AND host=? AND json_extract(data,'$.root')<>''", (host,)).fetchone()[0]
            seen_before = False
            for identity, ts, body, initial in self.query(
                    "SELECT id,ts,data,lane FROM records WHERE role='script' AND host=? AND aux=? ORDER BY ts,id",
                    (host, path)):
                metadata = json.loads(body)
                root = metadata["root"]
                newly_created = metadata["created"] and (metadata["web"] or not seen_before)
                seen_before = True
                best = None
                for rid, rts, url, request_body, level in self.query(
                        "SELECT id,ts,aux,data,lane FROM records WHERE role='request' AND host=? AND key=? "
                        "AND ts>? AND ts<=? ORDER BY ts,id", (host, posixpath.basename(path), ts, ts + W_SHELL_REQUEST)):
                    request_root = json.loads(request_body)["root"]
                    if root and request_root and root != request_root:
                        continue
                    relative_match = any(posixpath.normpath("/" + posixpath.relpath(path, candidate)) == posixpath.normpath(url)
                                         for candidate in ([root] if root else self.layout_roots(path)))
                    if root and not relative_match:
                        continue
                    exact = relative_match and (not root or request_root == root or roots == 1)
                    current, witnesses = "lead", [identity, rid]
                    if exact and level == "high" and newly_created:
                        current = "high"
                        # A rewrite or another account's deployment never reaches URGENT through a coincident worker
                        # interpreter (PHP mail() runs sh -c sendmail); only a script the web account created does.
                        for xid, xts, parent, boot in () if not metadata["web"] else self.query(
                                "SELECT id,ts,ppid,boot FROM records WHERE role='interpreter' AND host=? AND ts>=? AND ts<=? ORDER BY ts,id",
                                (host, rts, rts + W_DOWNLOAD_EXEC)):
                            ancestor = self.web_ancestor(host, parent, xts, boot)
                            if ancestor:
                                current, witnesses = "urgent", [identity, rid, xid, ancestor]
                                break
                    if best is None or LANES[current] > LANES[best[0]]:
                        best = current, witnesses
                if best is None:
                    if initial != "lead":
                        continue
                    best = "lead", [identity]
                count += 1
                if count <= CITE:
                    ids += best[1]
                elif count > CITE:
                    ids = [*ids[:CITE * 4], *best[1]]
                if LANES[best[0]] > LANES[lane]:
                    lane = best[0]
            if count:
                yield self.finding(f"{host}|{path}", ids, lane,
                    f"A document-root script write and optional later HTTP request form {count} inferred link(s). "
                    "HIGH requires an exact document-root-relative request (recorded root, or the packaged layout's) for "
                    "a newly created script; URGENT also requires that the web account created it and an interpreter "
                    "with ancestry to a recorded web server. Basename-only links and deployment rewrites are leads.",
                    count)


class DiscoveryBurst(LinuxSequence):
    id = "host.discovery_burst"
    title = "At least five discovery classes ran in one recorded login session within ten minutes"
    families = ("process_exec",)
    attack = ("T1033", "T1082", "T1016", "T1049", "T1057", "T1083")

    def service_anchor(self, e):
        """Without a login session, commands group under the topmost recorded web-server ancestor (a web shell's
        commands arrive through separate shells and workers), else the nearest non-shell ancestor, else the last
        ancestor pid the shell chain reaches."""
        pid, when, boot = e.get("process.ppid"), e.ts.timestamp(), e.get("host.boot.id")
        nearest, server, reached, visited = None, None, pid, set()
        for _ in range(LINEAGE_DEPTH):
            if not isinstance(pid, int) or pid in visited:
                break
            reached = pid
            if pid in (0, 1):
                break
            visited.add(pid)
            record = self.parent_record(e.host, pid, when, boot)
            if record is None:
                break
            name = posixpath.basename(record.exe)
            if name in {"httpd", "apache2", "nginx"} or re.fullmatch(r"php-fpm(?:[0-9.]+)?", name):
                server = pid
            elif nearest is None and server is None and record.name not in SHELLS:
                nearest = pid
            pid, when = record.ppid, record.ts
        return server or nearest or reached

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
        if session in (None, 4294967295, "4294967295", -1, "-1") or auid in (None, 4294967295, "4294967295", -1, "-1"):
            uid = e.get("process.uid")
            if uid is None:
                self.missing_required += 1
                return
            key = _key(e.host, str(uid), "service", self.service_anchor(e), e.get("host.boot.id"))
        else:
            key = _key(e.host, str(auid), str(session), e.get("host.boot.id"))
        self.add(e, "discovery", key, aux=found[0], lane="high" if web(e) else "lead")

    def finalize(self):
        if not self.ready():
            return []
        for (session,) in self.query("SELECT DISTINCT key FROM records WHERE role='discovery' ORDER BY key"):
            # A service anchor (a web server's master) lives for the whole boot: every disjoint qualifying window
            # folds into one finding, so a later burst is counted and cited instead of hidden behind the first.
            windows, ids, classes, lane, cursor, last = 0, [], set(), "lead", float("-inf"), []
            while True:
                start = self.query("""SELECT a.ts FROM records a WHERE a.role='discovery' AND a.key=? AND a.ts>?
                    AND (SELECT COUNT(DISTINCT b.aux) FROM records b WHERE b.role='discovery' AND b.key=a.key
                         AND b.ts BETWEEN a.ts AND a.ts+?)>=?
                    ORDER BY a.ts,a.id LIMIT 1""", (session, cursor, W_DISCOVERY, N_DISCOVERY)).fetchone()
                if start is None:
                    break
                windows += 1
                cursor = start[0] + W_DISCOVERY
                # At most one representative per fixed discovery class plus the first HIGH record.
                rows = self.query("""SELECT aux,MIN(ts),MIN(id),MAX(lane) FROM records WHERE role='discovery'
                    AND key=? AND ts BETWEEN ? AND ? GROUP BY aux ORDER BY aux""", (session, start[0], cursor))
                current = []
                for klass, _when, identity, _level in rows:
                    current.append(identity)
                    classes.add(klass)
                high = self.query("SELECT id FROM records WHERE key=? AND role='discovery' AND ts BETWEEN ? AND ? "
                                  "AND lane='high' ORDER BY ts,id LIMIT 1", (session, start[0], cursor)).fetchone()
                if high:
                    lane = "high"
                    if high[0] not in current:
                        current.append(high[0])
                if windows <= CITE:
                    ids += current
                last = current
            if not windows:
                continue
            if windows > CITE:
                ids += last
            yield self.finding(session, ids, lane,
                f"One recorded audit login session or service ancestor ran {len(classes)} distinct discovery classes "
                f"in {windows} separate burst(s) of at least {N_DISCOVERY} classes within {W_DISCOVERY} seconds: "
                f"{', '.join(sorted(classes))}. Classes share the expansion classifier; the first {min(windows, CITE)} "
                "and the latest bursts are cited; the grouping identity is recorded, and intent is inferred.", len(classes))


class UnbrokeredPrivilegeTransition(LinuxSequence):
    id = "host.unbrokered_privilege_transition"
    title = "A non-root login identity executed with root privileges without an observed sanctioned broker"
    families = ("process_exec",)
    attack = ("T1068", "T1548")
    ROOT_SERVICE_BROKERS = frozenset({"sshd", "sshd-session", "cron", "crond", "systemd", "polkit", "polkitd"})

    def observe(self, e):
        # ExecLineage is populated by consume; no second per-exec table or witness body.
        if (e.outcome != Outcome.failure and str(e.get("process.euid")) == "0"
                and _login_user_is_nonroot(e) and not self.raw_of(e)):
            if self.witnesses is None:
                self.witnesses = _LinuxWitnesses(self, [self])
            self.witnesses.hold(e)

    @staticmethod
    def packaged(record):
        return posixpath.dirname(record.exe) in BASE_PACKAGE_DIRS | PACKAGE_EXTRA_DIRS.get(record.name, frozenset())

    def transition(self, host, pid, record):
        helpers = SANCTIONED_BROKERS - self.ROOT_SERVICE_BROKERS
        if record.name in helpers | {"passwd", "chage", "chsh", "chfn", "newgrp", "sg", "gpasswd"} and self.packaged(record):
            return None
        ids, current, current_pid = [record.event_id], record, pid
        visited = {pid}
        for _ in range(LINEAGE_DEPTH):
            parent_pid = current.ppid
            parent = self.parent_record(host, parent_pid, current.ts, current.boot) if isinstance(parent_pid, int) else None
            if parent is None or parent_pid in visited:
                return ("before", parent_pid or current_pid), "lead", ids, "transition before the window; parent lineage is incomplete"
            visited.add(parent_pid)
            ids.append(parent.event_id)
            if (parent.name in SANCTIONED_BROKERS and self.packaged(parent)
                    and (parent.name not in self.ROOT_SERVICE_BROKERS or parent.uid == "0" or parent.euid == "0")):
                return None
            # Only the immediate elevation helper can broker the uid change. A distant sshd is irrelevant.
            if current.uid != "0" or parent.uid != "0":
                # Packaged setuid utilities do not establish an unbrokered root shell.
                if current.uid != "0" and current.name in {"passwd", "chage", "chsh", "chfn", "newgrp", "sg", "gpasswd", "su", "sudo", "pkexec"} and self.packaged(current):
                    return None
                suspicious = temporary(parent.exe) or temporary(current.exe) or not self.packaged(parent) or not self.packaged(current)
                return ("transition", current.event_id), "high" if suspicious else "lead", ids, "an immediate non-root parent precedes this root-privileged exec without a packaged elevation helper"
            current, current_pid = parent, parent_pid
        return ("before", current_pid), "lead", ids, "transition before the window; parent walk reached its depth bound"

    def finalize(self):
        groups = KeyedStore(self, "privilege_sessions", self.HOT)
        for walked, ((host, pid), records) in enumerate(self.execs.store.items()):
            # Parent walks bring spilled processes back to memory; return them to the budget's hot limit every
            # TRIM_EVERY processes. The walk reads a sorted copy of the disk rows, so writing them back does not
            # disturb it.
            if walked % TRIM_EVERY == 0:
                self.execs.trim()
            for record in records:
                if record.euid != "0" or record.auid in {None, "0", "4294967295", "-1"}:
                    continue
                answer = self.transition(host, pid, record)
                if answer is None:
                    continue
                identity, lane, ids, reason = answer
                session = record.session if record.session not in {None, -1, 4294967295} else identity[1]
                key = _key(host, record.boot, session, identity[0], identity[1] if identity[0] == "transition" else "")
                state = groups.get(key)
                if state is None:
                    state = {"count": 0, "ids": [], "first": record.ts, "last": record.ts, "lane": lane, "reason": reason}
                    if not groups.put(key, state):
                        self.note_limit("privilege_sessions", "transition folding refused at the disk ceiling")
                        yield self.finding(key, ids, lane, reason + "; folding state was refused at the disk ceiling",
                                           span=(record.ts, record.ts))
                        continue
                state["count"] += 1
                state["first"] = min(state["first"], record.ts)
                state["last"] = max(state["last"], record.ts)
                state["ids"] = list(dict.fromkeys([*state["ids"][:CITE], *ids[:LINEAGE_DEPTH]]))
                if LANES[lane] > LANES[state["lane"]]:
                    state["lane"], state["reason"] = lane, reason
                groups.trim()
        for key, state in groups.items():
            yield self.finding(key, state["ids"], state["lane"],
                f"Root-privileged execution: {state['reason']}; {state['count']} child exec record(s) in this folded session. "
                "Privilege gain is inferred from recorded credentials and immediate lineage.", state["count"],
                span=(state["first"], state["last"]))




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
                    self.add(e, "alert", dst, aux=str(e.get("destination.port") or ""),
                             data={"signature": e.get("alert.signature") or e.get("alert.signature_id") or "unrecorded"})
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
            self.execution(e)
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
        for host, signature in self.query(
                "SELECT DISTINCT h.host,json_extract(a.data,'$.signature') FROM records a JOIN records h "
                "ON h.role='address' AND h.key=a.key WHERE a.role='alert' AND "
                "(SELECT COUNT(DISTINCT h3.host) FROM records h3 WHERE h3.role='address' AND h3.key=a.key)=1 "
                "ORDER BY h.host,2"):
            count, ids, lane = 0, [], "context"
            for aid, ats, ip, port in self.query(
                    "SELECT a.id,a.ts,a.key,a.aux FROM records a WHERE a.role='alert' "
                    "AND json_extract(a.data,'$.signature')=? AND EXISTS(SELECT 1 FROM records h "
                    "WHERE h.role='address' AND h.key=a.key AND h.host=?) ORDER BY a.ts,a.id", (signature, host)):
                for xid, xts, pid, parent, boot, data in self.query(
                        "SELECT id,ts,pid,ppid,boot,data FROM records WHERE role='execute' AND host=? "
                        "AND ts>? AND ts<=? ORDER BY ts,id", (host, ats, ats + W_ALERT_EXEC)):
                    metadata = json.loads(data)
                    linked, chain = None, []
                    seen, ancestor_pid = set(), parent
                    for _ in range(LINEAGE_DEPTH):
                        if ancestor_pid is None or ancestor_pid in seen:
                            break
                        seen.add(ancestor_pid)
                        listener = self.query(
                            "SELECT id FROM records WHERE role='listener' AND host=? AND pid=? AND key=? "
                            "AND ts<=? AND (aux=? OR aux IN ('0.0.0.0','::')) "
                            "AND (boot='' OR ?='' OR boot=?) ORDER BY ts DESC,id LIMIT 1",
                            (host, ancestor_pid, port, xts, ip, boot, boot)).fetchone()
                        if listener:
                            linked = listener[0]
                            break
                        record = self.parent_record(host, ancestor_pid, xts, boot)
                        if record is None:
                            break
                        chain.append(record.event_id)
                        if not metadata.get("web") and record.user in WEB_SERVICE_USERS and record.ts >= ats - ALERT_SKEW:
                            # Another account's exec descending from a web-account process started about when the
                            # alert fired left the web service. An older record may name a reused pid; it never links.
                            linked = record.event_id
                            break
                        if port in {"80", "443", "8080", "8443"} and (
                                record.name in {"httpd", "apache2", "nginx"} or re.fullmatch(r"php-fpm(?:[0-9.]+)?", record.name)):
                            linked = record.event_id
                            break
                        ancestor_pid, xts = record.ppid, record.ts
                    current = ("high" if linked or metadata.get("strong") else
                               "lead" if metadata.get("web") or metadata.get("writable") or metadata.get("application")
                               else None)
                    if current is None:
                        continue
                    count += 1
                    witnesses = [aid, xid, linked, *chain]
                    witnesses = [value for value in witnesses if value]
                    if count <= CITE or LANES[current] > LANES[lane]:
                        ids += witnesses
                    if LANES[current] > LANES[lane]:
                        lane = current
            if count:
                yield self.finding(_key(host, signature), ids, lane,
                    f"An inbound severity 1-2 IDS alert was followed by {count} exec record(s) on its uniquely mapped host. "
                    "HIGH has listener/web-worker lineage, a web-account ancestor started at most five minutes before "
                    "the alert, or a web account's writable executable or interpreter one-liner; another account's "
                    "writable executable, "
                    "an application-server account's one-liner and web-account host/time coincidence alone are "
                    "inferred LEADs.", count)


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
        host, family, when = e.host or "", self.series(e), e.ts.timestamp()
        spill = self.spill()
        if not getattr(self, "_clock_tables", False):
            spill.table("clock", "host, key, bin INTEGER, first_id, first_ts REAL, first_body BLOB, "
                        "last_id, last_ts REAL, last_body BLOB, PRIMARY KEY(host,key,bin)")
            spill._buffers["clock"] = (
                ("INSERT INTO clock VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host,key,bin) DO UPDATE SET "
                "first_id=CASE WHEN (excluded.first_ts,excluded.first_id)<(first_ts,first_id) THEN excluded.first_id ELSE first_id END,"
                "first_body=CASE WHEN (excluded.first_ts,excluded.first_id)<(first_ts,first_id) THEN excluded.first_body ELSE first_body END,"
                "first_ts=MIN(first_ts,excluded.first_ts),"
                "last_id=CASE WHEN (excluded.last_ts,excluded.last_id)>(last_ts,last_id) THEN excluded.last_id ELSE last_id END,"
                "last_body=CASE WHEN (excluded.last_ts,excluded.last_id)>(last_ts,last_id) THEN excluded.last_body ELSE last_body END,"
                "last_ts=MAX(last_ts,excluded.last_ts)"), [])
            self._clock_tables = True
        pointer = citation_pointer(e, e.raw, self.raw_of(e), "typed", self.raw_target())
        body = b"P" + pointer if pointer is not None else b"E" + compact_event(e)
        self._append_row("clock", (host, family, int(when // CLOCK_BIN), e.id, when, body, e.id, when, body))
        # Physical SQLite pages, not admission count, enforce this coalescing store's ceiling.

    def clock_event(self, identity):
        row = self.query("SELECT first_body FROM clock WHERE first_id=? UNION ALL "
                         "SELECT last_body FROM clock WHERE last_id=? LIMIT 1", (identity, identity)).fetchone()
        if row is None:
            return []
        body = row[0]
        if body[:1] == b"E":
            return [expand_event(body[1:])]
        loader = getattr(self, "_citation_loader", None)
        if loader is None:
            return []
        events, _raw = loader({identity: body[1:]})
        return list(events.values())

    def events(self, ids):
        # Hydration is bounded to the chosen gap edges, never the complete clock population.
        known = {}
        for identity in dict.fromkeys(ids):
            if identity:
                known.update((event.id, event) for event in self.clock_event(identity))
        missing = [identity for identity in dict.fromkeys(ids) if identity and identity not in known]
        if missing:
            known.update((event.id, event) for event in super().events(missing))
        return sorted(known.values(), key=lambda event: (event.ts, event.id))

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
        self.spill().write("CREATE INDEX IF NOT EXISTS clock_first ON clock(first_id)", [()])
        self.spill().write("CREATE INDEX IF NOT EXISTS clock_last ON clock(last_id)", [()])
        for identity, host, family, start in self.query(
                "SELECT id,host,key,ts FROM records WHERE role='tamper' ORDER BY host,ts,id"):
            row = self.query("SELECT first_id,first_ts,last_id,last_ts FROM clock WHERE host=? AND key=? "
                             "AND last_ts>? ORDER BY bin LIMIT 1", (host, family, start)).fetchone()
            resumed_id, resumed = (row[0], row[1]) if row and row[1] > start else (row[2], row[3]) if row else (None, None)
            continued = self.query("SELECT last_id,last_ts FROM clock WHERE host=? AND key<>? AND last_ts>? "
                                   "ORDER BY last_ts DESC,last_id LIMIT 1", (host, family, start)).fetchone()
            if continued is None:
                continue
            end = resumed if resumed is not None else continued[1]
            if resumed is not None:
                continued = self.query("SELECT id,ts FROM (SELECT first_id AS id,first_ts AS ts FROM clock "
                                       "WHERE host=? AND key<>? UNION ALL SELECT last_id,last_ts FROM clock "
                                       "WHERE host=? AND key<>?) WHERE ts>? AND ts<=? ORDER BY ts DESC,id LIMIT 1",
                                       (host, family, host, family, start, end)).fetchone()
                if continued is None:
                    continue
            if end - start < G_SILENCE or continued[1] - start < G_SILENCE:
                continue
            until = datetime.fromtimestamp(end, UTC).isoformat()
            began = datetime.fromtimestamp(start, UTC).isoformat()
            text = (f"No {family} records from {host} were in the swept index records after {began} and before "
                    f"{until}, while other host families continued. This is an index coverage fact after a "
                    "tampering observation; host activity or its absence is not established.")
            if resumed is None:
                text += " The observed host window ends inside the gap."
            yield self.finding(_key(host, family, start), [identity, resumed_id, continued[0]], "lead", text)


SEQUENCE_RULES = [DownloadThenExecute, AuthorizedKeyThenLogin, ToolCleanup, WebShellChain, DiscoveryBurst,
                  UnbrokeredPrivilegeTransition, InteractivePrivilegedLogin, OutboundSSHExternal,
                  AlertThenHostExecution, TelemetryGapAfterTamper]


def share_linux_witnesses(pack):
    """Bind one compact witness store to a hunt's fixed set of Linux sequence evaluators."""
    members = [rule for rule in pack if isinstance(rule, LinuxSequence)]
    shared = [rule for rule in members if rule.id in {
        "host.download_then_execute", "host.tool_cleanup", "corr.alert_then_host_execution"}]
    if shared:
        rows = _SharedLinuxRows(shared)
        for rule in shared:
            rule.shared_rows = rows
    if members:
        witnesses = _LinuxWitnesses(members[0], members)
        for rule in members:
            rule.witnesses = witnesses
