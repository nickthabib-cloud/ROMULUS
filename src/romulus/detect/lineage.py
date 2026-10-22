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
  does not guard against it. Boot identity is part of every key when the source records it.
- That the shell's input and output actually use that connection is inferred, never observed, so the
  claim says so and the rule is positive-only.

Lanes. A broad join of this kind is mostly benign (package managers, ACME clients and CI agents call
out and then run shell steps; services accept and shell out), so it is a lead unless the record
carries a specific reverse-shell feature: the owner is a web-service account; the shell's own command
redirects to or from /dev/tcp|/dev/udp; or an interpreter owner's latest external call (not DNS, not
port 0) was followed within `TIGHT_GAP` seconds by a shell reading commands from stdin.

Grouping. A compiled program (not a shell, interpreter or relay tool) whose descendant shells are all
leads without the reverse-shell timing (a stdin-reading shell within `TIGHT_GAP` seconds) is a service
running its own helpers after network activity, or a compiled implant running tasked commands: its lead
hits on one host form one finding per (host, program path), listing every pid, peer and gap. Interpreter
owners are never grouped this way (one interpreter path serves many unrelated programs), and neither is a
shell that replaced the connected process itself.

Relationship to `host.interpreter_external_connection` (correlation.py): that rule reports the
outbound connection itself. This rule reports the subsequent shell execution under the same lineage;
the two reference each other rather than restating the connection.

sshd is modelled by exact kernel path, not by name: an `accept()` owned by the system SSH daemon
binary followed by a shell is an ordinary SSH login, already covered by the auth rules, and is
excluded with a recorded reason. A binary merely named `sshd` elsewhere is reported like any other.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import ClassVar

from romulus.detect.base import Match, Playbook, argv_incomplete, basename, pf
from romulus.detect.correlation import PidTable, StageMissing, canon_ip, external
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS, _py_pty_spawn, interpreter_name
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


@dataclass
class _Hit:
    shell: _Shell
    socket: _Socket                       # the owner's latest external socket call before the exec
    owner_pid: int
    relation: str                         # "own process re-exec" | "descendant"
    gap: float
    window: list[_Socket] = field(default_factory=list)   # every external call of the owner in the window

    @property
    def helper(self) -> bool:
        """A lead hit grouped per (host, program): a compiled owner's descendant shell without the reverse-shell
        timing. Interpreter and relay-tool owners, in-place re-execs and stdin shells within TIGHT_GAP are not."""
        if self.high or self.relation != "descendant":
            return False
        if interpreter_name(basename(self.socket.exe)) in INTERPRETERS:
            return False
        return not (self.shell.shaped and self.gap <= TIGHT_GAP)

    @property
    def high(self) -> bool:
        if self.socket.web or self.shell.devtcp:
            return True
        owner_interp = interpreter_name(basename(self.socket.exe)) in INTERPRETERS
        return (owner_interp and self.gap <= TIGHT_GAP and self.shell.shaped
                and _port(self.socket.peer_port) not in NOT_A_CHANNEL)


class ReverseShellByLineage(Playbook):
    id = "host.shell_spawned_by_connected_process"
    anchor_class = "execution"
    version = "4"
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

    def __init__(self):
        super().__init__()
        self.pids = PidTable()
        self.shells: list[_Shell] = []
        self.sockets: dict[tuple, list[_Socket]] = defaultdict(list)
        self._seen: set[str] = set()
        self._staged: set[str] = set()
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
        return []

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
        self.shells.append(_Shell(
            ts=event.ts.timestamp(), host=event.host or "", boot=event.get("host.boot.id"), pid=pid,
            ppid=event.get("process.ppid"), exe=str(exe), event_id=event.id, devtcp=devtcp, shaped=shaped))
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
        self.sockets[(event.host or "", event.get("host.boot.id"), pid)].append(_Socket(
            ts=event.ts.timestamp(), syscall=str(syscall), peer_ip=ip, peer_port=port, exe=str(exe), user=user,
            web=web, event_id=event.id))
        self._stage(event)

    # ---------------------------------------------------------------- finalize
    def _owners(self, shell: _Shell):
        """(pid, window_start, window_end, relation): the shell's own pre-exec identity, then each recorded
        ancestor. An ancestor's window ends at the exec of its child on the chain: a socket it opened later
        was not inherited down that chain."""
        owners = []
        prior = self.pids.exec_before(shell.host, shell.pid, shell.ts)
        if prior is not None:
            owners.append((shell.pid, prior[0], shell.ts, "own process re-exec"))
        child_ts = shell.ts
        for pid, exec_ts, _exe, _raw in self.pids.lineage_entries(shell.host, shell.ppid, shell.ts):
            owners.append((pid, exec_ts, child_ts, "descendant"))
            child_ts = exec_ts
        return owners

    def _events(self, ids: list[str]) -> dict[str, TypedEvent]:
        unique = sorted(set(ids))
        loaded = self.load(unique)
        if len(loaded) != len(unique):
            raise StageMissing(f"{self.id}: {len(unique) - len(loaded)} cited event(s) absent from the stage")
        return {event.id: event for event in loaded}

    def finalize(self):
        groups: dict[tuple, list[_Hit]] = defaultdict(list)
        for shell in sorted(self.shells, key=lambda s: (s.ts, s.event_id)):
            for owner_pid, start, end, relation in self._owners(shell):
                window = sorted((s for s in self.sockets.get((shell.host, shell.boot, owner_pid), ())
                                 if start <= s.ts < end and shell.ts - s.ts <= MAX_GAP),
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
                hit = _Hit(shell, latest, owner_pid, relation, shell.ts - latest.ts, window)
                key = ((shell.host, latest.exe, "helpers") if hit.helper
                       else (shell.host, shell.boot, owner_pid, latest.peer_ip))
                groups[key].append(hit)
        out = []
        for key in sorted(groups, key=lambda k: tuple("" if part is None else str(part) for part in k)):
            hits = groups[key]
            out.append(self._helpers(key, hits) if len(key) == 3 else self._finding(key, hits))
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
            f"'{exe}' is not a shell, interpreter or relay tool; {stdin} of them read commands from stdin, the "
            f"rest ran a -c script or a script file, and none read stdin within {TIGHT_GAP:.0f}s of a call. A "
            f"service running its own helper scripts after network activity looks like this; a compiled implant "
            f"running tasked commands looks the same. The connections and the executions are each directly "
            f"recorded; that a shell's input and output use a connection is inferred from lineage and timing, "
            f"not observed.")
        latest = {h.socket.event_id: h.socket for h in hits}
        cited_ids = sorted({s.event_id for s in shells[:CITE_PER_GROUP]}
                           | {sid for sid in sorted(latest, key=lambda i: (latest[i].ts, i))[:CITE_PER_GROUP]})
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
        notes.append("lane lead: a compiled owner with no web-service account, no /dev/tcp redirect and no "
                     f"stdin-reading shell within {TIGHT_GAP:.0f}s of its call; grouped per (host, program path)")
        notes.append(f"PID reuse by a forked process with no exec record cannot be excluded; the gap is bounded "
                     f"by {MAX_GAP:.0f}s")
        if len(shells) > CITE_PER_GROUP:
            notes.append(f"{len(shells)} shell execs joined; the first {CITE_PER_GROUP} are cited")
        match = Match(self.id, claim, self.claim_type, cited, preds, cited[0].ts, self.severity, "lead", "medium",
                      list(dict.fromkeys(entity for e in cited for entity in e.entities())),
                      group_key=f"{host}|{exe}|helpers")
        match.notes = notes
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
        claim = (
            f"On {host}, {owner_desc} {verb} external address {sock.peer_ip}{port} (its latest external socket "
            f"call before the exec), and {len(shells)} shell/interpreter exec(s) ({', '.join(shell_names)}; "
            f"pid(s) {shell_pids}) followed under the same process lineage ({first.relation}; {first.gap:.2f}s "
            f"after that call, with no other exec recorded for pid {owner_pid} in between).")
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
        match.notes = notes
        return match


LINEAGE_PLAYBOOKS = [ReverseShellByLineage]
