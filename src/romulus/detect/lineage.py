"""Reverse shell by lineage: a shell or interpreter executed by a process that holds an external
network connection.

The behaviour this catches is the shape every reverse shell shares, whatever the tool: a process
connects out (or accepts an inbound connection), and then that same process, or a descendant that
inherits its socket, executes a shell or interpreter. It keys on the kernel-recorded exe and the
recorded process lineage, not on `nc`/`socat`/`bash` argv text, so it survives renaming.

What the evidence shows, and what it does not:
- The connection side is an auditd `connect()` (success, external destination, port not 0) or
  `accept()`/`accept4()` (success, external source) recorded for a process P.
- The execution side is a process_exec whose kernel exe is a shell or interpreter, and whose own PID
  is P (P re-exec'd in place) or whose recorded parent chain reaches P.
- The socket call must fall inside the window in which P could have handed it down: after P's own
  latest recorded exec, and before the exec of P's child on the chain (for P's own PID, before the
  shell exec itself). A socket created after that child was started cannot be inherited by it; the
  child's exec time is the closest recorded bound on its fork.
- PID identity rests on "no other exec recorded for that PID in between". A PID that is reused by a
  forked process with no exec of its own is invisible to exec records, so reuse cannot be ruled out.
  `MAX_GAP` bounds how far apart the two facts may be, which limits the exposure to PID reuse; it
  does not guard against it. Boot identity separates every join when both records carry it (pids restart at
  a reboot); a record without a recorded boot id joins as if boot identity did not exist.
- That the shell's input and output actually use that connection is inferred, never observed, so the
  claim says so and the rule is positive-only.

Lanes. A broad join of this kind is mostly benign (package managers, ACME clients and CI agents call
out and then run shell steps; services accept and shell out), so it is a lead unless the record
carries a specific reverse-shell feature: the owner is a web-service account; the shell's own command
redirects to or from /dev/tcp|/dev/udp; or an interpreter owner's latest external call (not DNS, not
port 0) was followed within `TIGHT_GAP` seconds by a shell reading commands from stdin.

Grouping. A lead hit whose owner is a program off the rule's shell, interpreter, runtime and relay-tool
lists, whose latest call was an outbound connect() (never an accepted connection), and whose shell came
more than `TIGHT_GAP` seconds after that call, is a service running its own helpers after network
activity, or a compiled implant running tasked commands: such hits on one host form one finding per
(host, program path), citing a shell and its socket for every (pid, peer) and listing every peer. Runtime
owners are never grouped this way (one runtime path serves many unrelated programs), and neither is a
shell that replaced the connected process itself.

Relationship to `host.interpreter_external_connection` (correlation.py): that rule reports the
outbound connection itself. This rule reports the subsequent shell execution under the same lineage;
the two reference each other rather than restating the connection.

sshd is modelled by exact kernel path, not by name: an `accept()` owned by the system SSH daemon
binary followed by a shell is an ordinary SSH login, already covered by the auth rules, and is
excluded with a recorded reason. A binary merely named `sshd` elsewhere is reported like any other.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

from romulus.detect.base import Match, Playbook, argv_incomplete, basename, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore, RecentIds, SpillList, StateExhausted
from romulus.detect.correlation import (
    LINEAGE_DEPTH,
    PidTable,
    StageMissing,
    boot_of,
    boots_conflict,
    canon_ip,
    external,
    merge_unknown_boot,
)
from romulus.detect.host import (
    INTERPRETERS,
    WEB_SERVICE_USERS,
    _audit_serial,
    _py_pty_spawn,
    interpreter_name,
    need,
)
from romulus.evidence.shellparse import (
    SHELLS,
    UnknownShellScript,
    network_redirects,
    parse_script,
    shell_dialect,
    shell_script_file_of,
    shell_script_of,
)
from romulus.evidence.typed import Outcome, TypedEvent

# Kernel exe basenames whose execution, downstream of a live external connection, is the reverse-shell
# shape: shells, scripting interpreters, and relay tools that can exec a shell.
SHELL_EXE = INTERPRETERS
# The system SSH daemon, by exact kernel-recorded path. Its accepted connection plus a login shell is an
# SSH login (covered by the auth rules). Any other path, whatever its basename, is not excluded.
SSHD_PATHS = {"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session",
              "/usr/libexec/sshd-session"}
# Outer bound between the owner's latest external socket call and the shell exec (see the module notes:
# it limits, but does not rule out, PID reuse).
MAX_GAP = 3600.0
# A reverse shell connects, duplicates the socket onto stdin/stdout and execs the shell: a handful of
# system calls with no human or network wait in between. Ten seconds leaves room for a loaded host and
# audit timestamp granularity while excluding agents whose shell steps come later in a job.
TIGHT_GAP = 10.0
# Destination ports whose calls are name resolution or route probing, never a shell channel.
NOT_A_CHANNEL = {0, 53}
ACCEPT_SYSCALLS = {"accept", "accept4"}
_FAMILIES = ("process_exec", "net_socket")
CITE_PER_GROUP = 12
HELPER_PAIRS_CITED = 64          # (pid, peer) pairs of a helper group cited with a shell and a socket each
# Language runtimes and script hosts beyond the rule's shell list: one runtime path serves many unrelated programs,
# so a helper group keyed on its path would merge an implant with an application. Names are matched with any
# version suffix removed (node18, tclsh8.6, java via its JVM path's basename).
RUNTIMES = frozenset({
    "node", "nodejs", "deno", "bun", "java", "javaw", "jshell", "groovy", "scala", "kotlin", "jruby", "jython",
    "pwsh", "powershell", "tclsh", "wish", "expect", "rscript", "r", "julia", "ruby", "irb", "erl", "escript",
    "elixir", "iex", "dotnet", "mono", "guile", "racket", "sbcl", "clisp", "ecl", "luajit", "lua", "php", "php-cgi",
    "php-fpm", "perl", "python", "pypy", "pypy3", "ipython", "qjs", "osascript", "swift", "gdb", "vim", "emacs",
    "cscript", "wscript", "mshta", "rundll32", "regsvr32",
})
_VERSION_SUFFIX = re.compile(r"[-_.]?\d+(?:\.\d+)*$")


def runtime_owner(executable: str) -> bool:
    """True when the owning program is a shell, interpreter, relay tool or language runtime (any version)."""
    name = basename(executable).lower()
    stripped = _VERSION_SUFFIX.sub("", name)
    return bool({name, stripped, interpreter_name(name)} & (INTERPRETERS | RUNTIMES))
PEERS_LISTED = 8


def _port(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _devtcp_redirect(argv, executable) -> bool:
    """True when the shell exec's own argv is a `shell -c` whose script redirects to or from a
    /dev/tcp or /dev/udp pseudo-path, read in the dialect of the kernel-recorded shell."""
    if not isinstance(argv, list):
        return False
    script = shell_script_of([str(item) for item in argv])
    if script is None or isinstance(script, UnknownShellScript):
        return False
    parsed = parse_script(script, shell_dialect(executable, argv))
    if not parsed.ok:
        return False
    outbound, inbound = network_redirects(parsed)
    return bool(outbound or inbound)


def _reverse_shell_shaped(argv, executable) -> bool:
    """A shell that reads its commands from stdin (no `-c` script and no script file: `sh`, `sh -i`,
    `bash -li`, a login `-bash`), or python running code that calls pty.spawn."""
    if not isinstance(argv, list) or not argv:
        return False
    argv = [str(item) for item in argv]
    name = interpreter_name(basename(str(executable)))
    if name in SHELLS:
        if shell_script_of(argv) is not None:
            return False                              # a -c script (or an unknown -c layout)
        script_file = shell_script_file_of(argv, shell_name=None if name == "busybox" else name)
        return script_file is None
    if name.startswith("python"):
        return any(a == "-c" and _py_pty_spawn(argv[i + 1]) for i, a in enumerate(argv[:-1]))
    return False


@dataclass
class _Shell:
    ts: float
    host: str
    boot: object
    pid: int
    ppid: object
    exe: str
    event_id: str
    devtcp: bool
    shaped: bool
    incomplete: bool = False              # argv lost arguments: whether it read stdin is unknown
    serial: int | None = None             # the exec's audit serial (orders execs of one instant)


@dataclass
class _Socket:
    ts: float
    syscall: str
    peer_ip: str
    peer_port: object
    exe: str
    user: object
    web: bool
    event_id: str
    boot: str | None = None


@dataclass
class _Hit:
    shell: _Shell
    socket: _Socket                       # the owner's latest external socket call before the exec
    owner_pid: int
    relation: str                         # "own process re-exec" | "descendant"
    gap: float
    window: list[_Socket] = field(default_factory=list)   # every external call of the owner in the window
    judged: bool = False                  # joined when the shell was read: the budget had no room to hold it
    unrecorded: bool = False              # the owner's exec was not recorded (the exec store took no new process)

    @property
    def helper(self) -> bool:
        """A lead hit grouped per (host, program): a descendant shell more than TIGHT_GAP seconds after an outbound
        connect() by a program off the shell, interpreter, runtime and relay-tool lists. Accepted connections,
        any shell within TIGHT_GAP, in-place re-execs and runtime owners never are."""
        if self.high or self.relation != "descendant" or self.socket.syscall != "connect":
            return False
        if self.gap <= TIGHT_GAP:
            return False
        return not runtime_owner(self.socket.exe)

    @property
    def high(self) -> bool:
        if self.socket.web or self.shell.devtcp:
            return True
        owner_interp = interpreter_name(basename(self.socket.exe)) in INTERPRETERS
        return (owner_interp and self.gap <= TIGHT_GAP and self.shell.shaped
                and _port(self.socket.peer_port) not in NOT_A_CHANNEL)


class _Groups(dict):
    """An in-memory stand-in for a keyed store's setdefault (one shell's hits, in the finalize fallback)."""

    def setdefault(self, key, factory):
        if key not in self:
            self[key] = factory()
        return self[key]


class ReverseShellByLineage(Playbook):
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.shell_spawned_by_connected_process"
    anchor_class = "execution"
    version = "5"
    title = "Shell or interpreter executed by a process holding an external connection (reverse shell by lineage)"
    kind = "aggregate"
    staged = True
    claim_type = "correlated_observation"
    families = _FAMILIES
    required_fields = ()
    assures_negative = False
    positive_only_reason = (
        "the connection and the shell execution are each directly recorded, but that the shell's input and "
        "output use that connection is inferred from lineage and timing, not observed; and a reverse shell can "
        "be built in ways these exec and socket records do not show, so absence proves nothing")
    severity, lane = "critical", "high"
    attack = ("T1059.004", "T1059.006", "T1071", "T1095")
    benign = ("package managers, ACME clients and CI or deployment agents that call out and then run shell steps",
              "services that accept connections and shell out to helpers",
              "an ssh client that spawns a local shell after connecting (LocalCommand)")
    next_checks = ("the shell's children (the commands it then ran)",
                   "the session's PCAP or flow records for cleartext commands over that connection",
                   "how the connecting process itself was started (its own lineage and account)",
                   "the connection itself, reported by host.interpreter_external_connection")
    card: ClassVar[dict] = {
        "behavior": "a shell or interpreter (kernel exe) is executed by a process that, or whose recorded "
                    "ancestor, made a successful external connect() (port not 0) or accepted an external "
                    "connection, after its own latest exec and before its child on the chain was started",
        "telemetry": "Linux auditd net_socket (socket.syscall connect/accept/accept4, destination.ip/port or "
                     "source.ip/port, process.pid, process.executable, process.user, outcome, host.boot.id) and "
                     "process_exec (process.executable, process.pid, process.ppid, process.argv), joined by the "
                     "per-host PID table: present in the lab profile. Exec auditing appears to cover euid 0 or "
                     "uid<1000 only, so lineage is often incomplete and the rule is positive-only",
        "fidelity": "direct observation of both stages with their outcomes; the link (that the shell uses the "
                    "socket) is inferred and worded as such; PID identity rests on no other exec recorded for "
                    "that PID in between",
        "benign_and_cost": "package managers, ACME clients, CI/deployment agents and accept-and-shell-out "
                           "services share the broad join and stay at lead. One grouped finding per (host, "
                           "boot, connecting PID, latest peer); a compiled (non-interpreter) owner's descendant "
                           "shells without the reverse-shell timing are one lead per (host, program path) listing "
                           "every pid, peer and gap; the system sshd's accepted logins are excluded by exact kernel "
                           "path",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads; joined events "
                      "are staged on disk",
        "next_pivot": "the shell's children and the session PCAP for cleartext commands",
        "adds": "host.interpreter_external_connection reports the outbound connection; no other rule joins that "
                "connection to the shell the owning process then executed",
        "lanes": "high only for a web-service owner, a /dev/tcp redirect in the shell's own command, or an "
                 "interpreter owner whose latest non-DNS, non-port-0 call is followed within TIGHT_GAP seconds "
                 "by a stdin-reading shell or pty.spawn; everything else is lead",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.004/.006, T1071, T1095; the reverse-shell process shape "
                          "common to the GTFOBins reverse-shell entries and public DFIR reverse-shell reports",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of the net_socket and process_exec records this evaluator reads",
    }

    # Shells, sockets and the exec history are held to finalize, as the join needs them all (a target is read whole
    # before the next, so a shell's socket or ancestor may be read after it). Each lives in a keyed store or list
    # over the rule's on-disk spill: HOT entries in memory, the rest on disk, never forgotten.
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    TRIM_EVERY = 10_000
    # A shell the shells list has no room for is joined when it is read, against the sockets and lineage held then;
    # its hits (only shells that joined a held connection, each a few hundred bytes) wait in memory for finalize,
    # at most this many, and a shell past them is refused.
    JUDGED_CAP = 100_000

    def __init__(self):
        super().__init__()
        self.pids = PidTable(PidTable.CAPACITY, owner=self)
        self.shells = SpillList(self, "rs_shells", self.HOT)
        self.sockets = KeyedStore(self, "rs_sockets", self.HOT)         # (host, pid) -> [_Socket]
        self._judged: list[_Hit] = []
        self._seen = RecentIds()        # bounded re-read guard
        self._staged = RecentIds()      # bounded re-stage guard
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []

    # ---------------------------------------------------------------- staging
    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

    def retained_events(self) -> list[TypedEvent]:
        return []                                       # staged on disk instead

    def _stage(self, event: TypedEvent) -> None:
        if event.id not in self._staged:
            self._staged.add(event.id)
            self._pending.append(event)

    def _trim(self) -> None:
        self.pids.trim()
        self.shells.trim()
        self.sockets.trim()

    # ---------------------------------------------------------------- consume
    def consume(self, events):
        for event in events:
            if event.family not in _FAMILIES or event.id in self._seen:
                continue                                # re-reading a partition must not double count
            self._seen.add(event.id)
            if event.family == "process_exec":
                self.pids.add(event)
                self._consider_shell(event)
            else:
                self._consider_socket(event)
        self._trim()
        return []

    def _disk_full(self, what: str) -> None:
        self.evaluated -= 1
        self.refuse("disk", f"the {what} disk budget is spent; a later record is not evaluated")

    def _consider_shell(self, event: TypedEvent) -> None:
        exe = event.get("process.executable")
        pid = event.get("process.pid")
        if not exe or interpreter_name(basename(str(exe))) not in SHELL_EXE:
            return
        if event.outcome == Outcome.failure:            # a failed exec ran no shell
            return
        if not isinstance(pid, int):
            self.missing_required += 1                  # cannot establish lineage without a PID
            return
        self.evaluated += 1
        argv = event.get("process.argv")
        if argv_incomplete(event):
            # Arguments after a gap are unknown: "no -c script" cannot be established and a redirect may be
            # missing, so neither argv feature is read. The lineage join itself does not depend on argv.
            self.missing_required += 1
            devtcp = shaped = False
        else:
            devtcp, shaped = _devtcp_redirect(argv, exe), _reverse_shell_shaped(argv, exe)
        shell = _Shell(ts=event.ts.timestamp(), host=event.host or "", boot=boot_of(event), pid=pid,
                       ppid=event.get("process.ppid"), exe=str(exe), event_id=event.id, devtcp=devtcp, shaped=shaped,
                       incomplete=argv_incomplete(event), serial=_audit_serial(event))
        if not self.shells.append(shell):
            self._judge_now(shell, event)
            return
        self._stage(event)

    def _judge_now(self, shell: _Shell, event: TypedEvent) -> None:
        """The shells list has no room: join the shell now with the sockets and lineage held, without recording it.
        A hit waits for finalize (cited, grouped as usual); a socket read after the shell cannot join it, and
        coverage says so."""
        self.note_limit("shells_judged", "the shell executions' list took no new record; a later shell was joined "
                                         "when it was read, with the connections held then (a connection read after "
                                         "it is not joined)")
        hits = self._join(shell)
        if not hits:
            return
        if len(self._judged) + len(hits) > self.JUDGED_CAP:
            self._disk_full("shells judged when read'")
            return
        for hit in hits:
            hit.judged = True
        self._judged += hits
        self._stage(event)

    def _consider_socket(self, event: TypedEvent) -> None:
        syscall = event.get("socket.syscall")
        pid = event.get("process.pid")
        exe = event.get("process.executable")
        if syscall not in ({"connect"} | ACCEPT_SYSCALLS):
            return
        if not isinstance(pid, int) or not exe:
            self.missing_required += 1
            return
        if event.outcome != Outcome.success:            # only a completed connection owns a usable socket
            return
        side = "destination" if syscall == "connect" else "source"
        ip = canon_ip(event.get(f"{side}.ip"))
        if ip is None:                                  # SOCKADDR not retrieved: cannot place the peer
            self.missing_required += 1
            return
        port = event.get(f"{side}.port")
        if not external(ip) or (syscall == "connect" and _port(port) == 0):
            return                                      # port 0: a route or address-sort probe, no connection
        self.evaluated += 1
        user = event.get("process.user")
        web = user in WEB_SERVICE_USERS or event.get("process.effective_user") in WEB_SERVICE_USERS
        held = self.sockets.setdefault((event.host or "", pid), list)
        if held is None:
            self._disk_full("sockets'")
            return
        held.append(_Socket(
            ts=event.ts.timestamp(), syscall=str(syscall), peer_ip=ip, peer_port=port, exe=str(exe), user=user,
            web=web, event_id=event.id, boot=boot_of(event)))
        self._stage(event)

    # ---------------------------------------------------------------- finalize
    def _owners(self, shell: _Shell):
        """(pid, window_start, window_end, relation, unrecorded): the shell's own pre-exec identity, then each
        recorded ancestor. An ancestor's window ends at the exec of its child on the chain: a socket it opened later
        was not inherited down that chain.

        Once the exec store has refused any process in the hunt, the lineage may have gaps: then a pid whose exec is
        not recorded (the shell's own earlier image, or the ancestor where the walk stops, named by its child's ppid)
        still joins its held sockets in the MAX_GAP before its child, and the finding says its exec was not
        recorded."""
        owners = []
        incomplete = self.pids.execs.incomplete
        prior = self.pids.exec_before(shell.host, shell.pid, shell.ts, shell.boot, serial=shell.serial,
                                      exclude=shell.event_id)
        if prior is not None:
            owners.append((shell.pid, prior[0], shell.ts, "own process re-exec", False))
        elif incomplete:
            owners.append((shell.pid, shell.ts - MAX_GAP, shell.ts, "own process re-exec", True))
        pid, ts, boot, serial, child_ts = shell.ppid, shell.ts, shell.boot, shell.serial, shell.ts
        for _ in range(LINEAGE_DEPTH):
            if not isinstance(pid, int) or pid in (0, 1):
                break
            record = self.pids._record(shell.host, pid, ts, boot, serial=serial)
            if record is None:
                if incomplete:
                    owners.append((pid, child_ts - MAX_GAP, child_ts, "descendant", True))
                break
            owners.append((pid, record.ts, child_ts, "descendant", False))
            child_ts = record.ts
            pid, ts, serial = record.ppid, record.ts, record.serial
            boot = boot if boot is not None else record.boot
        return owners

    def _events(self, ids: list[str]) -> dict[str, TypedEvent]:
        unique = sorted(set(ids))
        loaded = self.load(unique)
        if len(loaded) != len(unique):
            raise StageMissing(f"{self.id}: {len(unique) - len(loaded)} cited event(s) absent from the stage")
        return {event.id: event for event in loaded}

    def _hits(self, shell: _Shell, groups: KeyedStore) -> None:
        """Join one shell with its owners' external socket calls; every hit goes to its group."""
        for hit in self._join(shell):
            self._add_hit(hit, groups)

    def _add_hit(self, hit: _Hit, groups) -> None:
        shell, latest = hit.shell, hit.socket
        boot = shell.boot if shell.boot is not None else latest.boot
        key = ((shell.host, latest.exe, "helpers") if hit.helper
               else (shell.host, boot, hit.owner_pid, latest.peer_ip))
        need(groups.setdefault(key, list), self, "the joined hits' grouping").append(hit)

    def _join(self, shell: _Shell) -> list[_Hit]:
        """The shell's hits: one per owner with an external socket call in its window."""
        out = []
        for owner_pid, start, end, relation, unrecorded in self._owners(shell):
            held = self.sockets.get((shell.host, owner_pid)) or self.sockets.peek((shell.host, owner_pid), ())
            window = sorted((s for s in held
                             if start <= s.ts < end and shell.ts - s.ts <= MAX_GAP
                             and not boots_conflict(shell.boot, s.boot)),
                            key=lambda s: (s.ts, s.event_id))
            if not window:
                continue
            # The headline socket is the latest one that could be a channel: a DNS or port-0 call made
            # after the real connection must not hide its peer. Only DNS or probes left: the latest call.
            channels = [s for s in window
                        if s.syscall in ACCEPT_SYSCALLS or _port(s.peer_port) not in NOT_A_CHANNEL]
            latest = channels[-1] if channels else window[-1]
            if latest.syscall in ACCEPT_SYSCALLS and latest.exe in SSHD_PATHS:
                continue                            # the system sshd's accepted login: auth rules cover it
            out.append(_Hit(shell, latest, owner_pid, relation, shell.ts - latest.ts, window, unrecorded=unrecorded))
        return out

    def finalize(self):
        groups = KeyedStore(self, "rs_groups", self.HOT)
        for i, shell in enumerate(self.shells):
            self._hits(shell, groups)
            if i % self.TRIM_EVERY == self.TRIM_EVERY - 1:
                self._trim()
                groups.trim()
        for hit in self._judged:                    # shells joined when read (no room to hold them)
            self._add_hit(hit, groups)
        keys = groups.keys()
        merged = {**{k: [k] for k in keys if len(k) == 3},
                  **merge_unknown_boot({k: [k] for k in keys if len(k) == 4}, 1)}
        out = []
        for key in sorted(merged, key=lambda k: tuple("" if part is None else str(part) for part in k)):
            hits = [hit for old in merged[key] for hit in groups.peek(old)]
            out.append(self._helpers(key, hits) if len(key) == 3 else self._finding(key, hits))
        groups.clear()
        return out

    def finalize_fallback(self, reason: str) -> list[Match]:
        """Every joined hit, one shell at a time (grouping hits across shells needed disk); a table on disk that cannot
        be read ends the pass with what was published."""
        out = []

        def publish(local: _Groups) -> None:
            for key, hits in local.items():
                m = self._helpers(key, hits) if len(key) == 3 else self._finding(key, hits)
                m.group_key += f"|alone:{hits[0].shell.event_id}"
                m.notes.append(f"published one shell at a time: grouping the joins needed disk ({reason})")
                out.append(m)
        for hit in self._judged:                    # each shell joined when read, on its own
            local = _Groups()
            self._add_hit(hit, local)
            publish(local)
        try:
            for shell in self.shells:
                local = _Groups()
                self._hits(shell, local)
                publish(local)
        except StateExhausted:
            pass
        return out

    def _helpers(self, key: tuple, hits: list[_Hit]) -> Match:
        """One compiled program's descendant shells on one host, none with the reverse-shell timing (see the
        module notes). Every pid, peer and gap is stated; the shells are cited up to the cap."""
        host, exe, _kind = key
        hits = sorted(hits, key=lambda h: (h.shell.ts, h.shell.event_id))
        shells = sorted({h.shell.event_id: h.shell for h in hits}.values(), key=lambda s: (s.ts, s.event_id))
        pids = sorted({h.owner_pid for h in hits})
        users = sorted({str(h.socket.user) for h in hits if h.socket.user not in (None, "")})
        peers = sorted({f"{s.peer_ip}:{s.peer_port}" for h in hits for s in h.window})
        gaps = [h.gap for h in hits]
        stdin = sum(1 for s in shells if s.shaped)
        unknown = sum(1 for s in shells if s.incomplete)
        shapes = f"{stdin} of them read commands from stdin, " + (
            f"{unknown} {'has' if unknown == 1 else 'have'} an incomplete argv (its shape is unknown), and "
            if unknown else "") + "the rest ran a -c script or a script file"
        names = sorted({interpreter_name(basename(s.exe)) for s in shells})
        listed = ", ".join(peers[:PEERS_LISTED]) + (f" and {len(peers) - PEERS_LISTED} more"
                                                     if len(peers) > PEERS_LISTED else "")
        pid_text = ("pid " if len(pids) == 1 else "pids ") + ", ".join(str(p) for p in pids)
        claim = (
            f"On {host}, '{exe}' ({pid_text}"
            + (f", account(s) {', '.join(repr(u) for u in users)}" if users else "")
            + f") made external socket calls (peers: {listed}), and {len(shells)} shell/interpreter exec(s) "
            f"({', '.join(names)}; pid(s) {', '.join(str(s.pid) for s in shells[:CITE_PER_GROUP])}"
            + (f" and {len(shells) - CITE_PER_GROUP} more" if len(shells) > CITE_PER_GROUP else "")
            + f") were later started as its descendants, {min(gaps):.0f}–{max(gaps):.0f} s after its latest "
            f"external call before each exec, with no other exec recorded for {pid_text} in between. "
            f"'{exe}' is not on this rule's shell, interpreter, runtime or relay-tool list; every latest call was an "
            f"outbound connection and every exec came more than {TIGHT_GAP:.0f}s after it; {shapes}. A "
            f"service running its own helper scripts after network activity looks like this; a compiled implant "
            f"running tasked commands looks the same. The connections and the executions are each directly "
            f"recorded; that a shell's input and output use a connection is inferred from lineage and timing, "
            f"not observed.")
        # one shell and its latest socket for every (pid, peer), so no peer of the group goes uncited
        per_pair: dict[tuple, _Hit] = {}
        for h in hits:
            per_pair.setdefault((h.owner_pid, h.socket.peer_ip, str(h.socket.peer_port)), h)
        pairs = sorted(per_pair.items(), key=lambda kv: (kv[1].shell.ts, kv[1].shell.event_id))
        cited_ids = sorted({i for _k, h in pairs[:HELPER_PAIRS_CITED] for i in (h.shell.event_id, h.socket.event_id)}
                           | {s.event_id for s in shells[:CITE_PER_GROUP]})
        events = self._events(cited_ids)
        cited = sorted(events.values(), key=lambda e: (e.ts, e.id))
        sock_event = events[hits[0].socket.event_id] if hits[0].socket.event_id in events else next(
            e for e in cited if e.family == "net_socket")
        preds = [pf(sock_event, name) for name in
                 ("socket.syscall", "destination.ip", "destination.port", "source.ip", "source.port",
                  "process.pid", "process.executable", "process.user") if sock_event.has(name)]
        shell_event = events[shells[0].event_id]
        preds += [pf(shell_event, name) for name in ("process.executable", "process.pid", "process.ppid",
                                                     "process.argv") if shell_event.has(name)]
        notes = sorted(self.attack)
        notes.append("the outbound connection itself is reported by host.interpreter_external_connection")
        notes.append("lane lead: an owner off the shell, interpreter, runtime and relay-tool lists, no web-service "
                     f"account, no /dev/tcp redirect, an outbound call and every exec more than {TIGHT_GAP:.0f}s "
                     "after it; grouped per (host, program path)")
        if len(pairs) > HELPER_PAIRS_CITED:
            notes.append(f"{len(pairs)} (pid, peer) pairs; a shell and socket are cited for the first "
                         f"{HELPER_PAIRS_CITED}")
        notes += [f"peer: {peer}" for peer in peers]
        notes.append(f"PID reuse by a forked process with no exec record cannot be excluded; the gap is bounded "
                     f"by {MAX_GAP:.0f}s")
        if len(shells) > CITE_PER_GROUP:
            notes.append(f"{len(shells)} shell execs joined; the first {CITE_PER_GROUP} are cited")
        match = Match(self.id, claim, self.claim_type, cited, preds, cited[0].ts, self.severity, "lead", "medium",
                      list(dict.fromkeys(entity for e in cited for entity in e.entities())),
                      group_key=f"{host}|{exe}|helpers")
        match.notes = notes + _budget_notes(hits)
        return match

    def _finding(self, key: tuple, hits: list[_Hit]) -> Match:
        host, boot, owner_pid, peer_ip = key
        hits = sorted(hits, key=lambda h: (h.shell.ts, h.shell.event_id))
        first = hits[0]
        sock = first.socket
        shells = sorted({h.shell.event_id: h.shell for h in hits}.values(), key=lambda s: (s.ts, s.event_id))
        high = [h for h in hits if h.high]
        lane = "high" if high else "lead"
        lead_hit = high[0] if high else first

        verb = "connected out to" if sock.syscall == "connect" else "accepted an inbound connection from"
        port = f":{sock.peer_port}" if sock.peer_port not in (None, "") else ""
        owner_desc = (f"pid {owner_pid} ('{sock.exe}'"
                      + (f", account '{sock.user}'" if sock.user not in (None, "") else "") + ")")
        peers = sorted({f"{s.peer_ip}:{s.peer_port}" for h in hits for s in h.window})
        others = [p for p in peers if p != f"{sock.peer_ip}:{sock.peer_port}"]
        shell_names = sorted({interpreter_name(basename(s.exe)) for s in shells})
        shell_pids = ", ".join(str(s.pid) for s in shells[:CITE_PER_GROUP])
        between = (f"pid {owner_pid}'s own exec was not recorded (the exec store took no new process), so another "
                   f"exec of it in between cannot be excluded" if first.unrecorded
                   else f"with no other exec recorded for pid {owner_pid} in between")
        claim = (
            f"On {host}, {owner_desc} {verb} external address {sock.peer_ip}{port} (its latest external socket "
            f"call before the exec), and {len(shells)} shell/interpreter exec(s) ({', '.join(shell_names)}; "
            f"pid(s) {shell_pids}) followed under the same process lineage ({first.relation}; {first.gap:.2f}s "
            f"after that call, {between}).")
        if others:
            claim += (f" Other external peers of that pid in the same window: {', '.join(others[:PEERS_LISTED])}"
                      + (f" and {len(others) - PEERS_LISTED} more" if len(others) > PEERS_LISTED else "") + ".")
        claim += (" The connection and the execution are each directly recorded; that the shell's input and output "
                  "use that connection is inferred from lineage and timing, not observed.")
        if any(h.shell.devtcp for h in hits):
            claim += " At least one shell was run with a command that redirects to or from a /dev/tcp pseudo-path."

        cited_ids = sorted({s.event_id for h in hits[:CITE_PER_GROUP] for s in h.window[-CITE_PER_GROUP:]}
                           | {s.event_id for s in shells[:CITE_PER_GROUP]}
                           | {lead_hit.socket.event_id, lead_hit.shell.event_id})   # the hit the lane rests on
        events = self._events(cited_ids)
        cited = sorted(events.values(), key=lambda e: (e.ts, e.id))
        sock_event = events[lead_hit.socket.event_id]
        preds = [pf(sock_event, name) for name in
                 ("socket.syscall", "destination.ip", "destination.port", "source.ip", "source.port",
                  "process.pid", "process.executable", "process.user") if sock_event.has(name)]
        shell_event = events[lead_hit.shell.event_id]
        preds += [pf(shell_event, name) for name in ("process.executable", "process.pid", "process.ppid",
                                                     "process.argv") if shell_event.has(name)]
        notes = sorted(self.attack)
        notes.append("the outbound connection itself is reported by host.interpreter_external_connection")
        if lane == "high":
            h = lead_hit
            reason = ("the connecting process runs as a web-service account" if h.socket.web else
                      "the shell's own command redirects to or from /dev/tcp" if h.shell.devtcp else
                      f"an interpreter's latest external call was followed within {TIGHT_GAP:.0f}s by a shell "
                      f"reading commands from stdin (or pty.spawn)")
            notes.append(f"lane high: {reason}")
        else:
            notes.append("lane lead: no web-service owner, no /dev/tcp redirect, and no stdin-reading shell within "
                         f"{TIGHT_GAP:.0f}s of an interpreter's non-DNS call; package managers, CI agents and "
                         "services that shell out share this shape")
        notes.append(f"PID reuse by a forked process with no exec record cannot be excluded; the gap is bounded "
                     f"by {MAX_GAP:.0f}s")
        if len(shells) > CITE_PER_GROUP:
            notes.append(f"{len(shells)} shell execs joined; the first {CITE_PER_GROUP} are cited")
        match = Match(self.id, claim, self.claim_type, cited, preds, cited[0].ts, self.severity, lane,
                      "high" if lane == "high" else "medium", shell_event.entities(),
                      group_key=f"{host}|{boot}|{owner_pid}|{peer_ip}")
        match.notes = notes + _budget_notes(hits)
        return match


def _budget_notes(hits: list[_Hit]) -> list[str]:
    notes = []
    if any(h.judged for h in hits):
        notes.append("a shell was judged when it was read, with the connections held then: the state budget had no "
                     "room to hold it for the whole window")
    if any(h.unrecorded for h in hits):
        notes.append(f"the connecting process's exec was not recorded (the exec store took no new process once its "
                     f"share of the state budget was spent): its window before its child is bounded by "
                     f"{MAX_GAP:.0f}s, and another exec of the same pid in between cannot be excluded")
    return notes


LINEAGE_PLAYBOOKS = [ReverseShellByLineage]
