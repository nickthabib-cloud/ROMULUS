"""Reverse shell by lineage: a shell or interpreter executed by a process that holds an external
network connection.

The behaviour this catches is the shape every reverse shell shares, whatever the tool: a process
connects out to an attacker (or accepts an inbound connection), and then that same process — or a
descendant that inherits its socket — executes an interactive shell or interpreter. It keys on the
kernel-recorded exe and the process lineage, not on `nc`/`socat`/`bash` argv text, so it survives
renaming and covers bash `/dev/tcp`, python `pty.spawn`, `socat exec`, perl/php one-liners and
compiled implants alike.

What the evidence shows, and what it does not:
- The connection side is an auditd `connect()` (success, external destination) or `accept()`/
  `accept4()` (external source) recorded for a process P.
- The execution side is a process_exec whose kernel exe is a shell or interpreter, whose own PID is
  P (P re-exec'd in place) or whose recorded parent chain reaches P, executed after the socket call
  and while P was still the live owner of the socket (the socket call falls within P's exec identity
  and before the shell exec replaced or descended from it).
- The two facts are each directly observed and cited to their own record. That the shell's standard
  input and output actually use that connection is an inference the records do not prove, so the
  claim says so and this rule is positive-only.

Relationship to `host.interpreter_external_connection` (correlation.py): that rule reports the
outbound connection itself (an interpreter/shell/web account calling out). This rule reports the
*subsequent shell execution* under the same lineage; the two describe different facts and reference
each other rather than restating the connection.

sshd is modelled, not name-excluded as suspicious: a system `sshd` that `accept()`s an inbound
connection and then runs a login shell is an ordinary SSH login, already covered by the auth rules,
so that exact typed shape (an `accept()` owned by the sshd daemon) is excluded with a recorded
reason. A bind shell — a non-sshd listener (`nc`/`socat`/python) that accepts and spawns a shell —
is not sshd and is still reported.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.correlation import PidTable, StageMissing, canon_ip, external
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS, interpreter_name
from romulus.evidence.shellparse import UnknownShellScript, network_redirects, parse_script, shell_script_of
from romulus.evidence.typed import Outcome, TypedEvent

# Kernel exe basenames whose execution, downstream of a live external connection, is the reverse-shell
# shape. Shells, scripting interpreters, and relay tools that can exec a shell.
SHELL_EXE = INTERPRETERS
# Inbound-accept owners that are a legitimate SSH login rather than a bind shell. The system SSH
# daemon's accepted connection plus a login shell is covered by the auth rules.
SSHD_EXES = {"sshd", "sshd-session"}
# The shell must be executed within this many seconds of the connection. The real bound is lineage
# containment (the socket falls inside the connecting process's live identity and before the shell);
# this cap is an explicit, stated upper limit that also guards against PID reuse within a boot.
MAX_GAP = 3600.0
ACCEPT_SYSCALLS = {"accept", "accept4"}
CITE_PER_GROUP = 12


def _devtcp_redirect(argv) -> bool:
    """True when the shell exec's own argv is a `shell -c` whose script redirects to or from a
    /dev/tcp or /dev/udp pseudo-path (an explicit network redirect in the command that ran it)."""
    if not isinstance(argv, list):
        return False
    script = shell_script_of([str(item) for item in argv])
    if script is None or isinstance(script, UnknownShellScript):
        return False
    parsed = parse_script(script)
    if not parsed.ok:
        return False
    outbound, inbound = network_redirects(parsed)
    return bool(outbound or inbound)


@dataclass
class _Shell:
    ts: float
    host: str
    boot: object
    pid: int
    ppid: object
    exe: str
    user: object
    event_id: str
    devtcp: bool


@dataclass
class _Socket:
    ts: float
    syscall: str
    peer_ip: str
    peer_port: object
    exe: str
    user: object
    event_id: str


@dataclass
class _Hit:
    shell: _Shell
    socket: _Socket
    owner_pid: int
    owner_exe: str
    relation: str                 # "own process re-exec" | "descendant"
    gap: float


class ReverseShellByLineage(Playbook):
    id = "host.shell_spawned_by_connected_process"
    anchor_class = "execution"
    version = "1"
    title = "Shell or interpreter executed by a process holding an external connection (reverse shell by lineage)"
    kind = "aggregate"
    staged = True
    claim_type = "correlated_observation"
    families = ("net_socket", "process_exec")
    required_fields = ()
    assures_negative = False
    positive_only_reason = (
        "the connection and the shell execution are each directly recorded, but that the shell's input and "
        "output use that connection is inferred from lineage and timing, not observed; and a reverse shell can "
        "be built in ways these exec and socket records do not show, so absence proves nothing")
    severity, lane = "critical", "high"
    attack = ("T1059.004", "T1059.006", "T1071", "T1095")
    benign = ("an ssh client that spawns a local shell after connecting (LocalCommand/ProxyCommand)",
              "a deployment or configuration agent that contacts a controller and then runs a shell step",
              "an IDE or orchestration helper that opens a remote session and then a local shell")
    next_checks = ("the shell's children (the commands it then ran)",
                   "the session's PCAP or flow records for cleartext commands over that connection",
                   "how the connecting process itself was started (its own lineage and account)",
                   "the connection itself, reported by host.interpreter_external_connection")
    card: ClassVar[dict] = {
        "behavior": "a shell or interpreter (kernel exe) is executed by a process that, or whose recorded "
                    "ancestor, made a successful outbound connect() to an external address or accepted an "
                    "inbound connection from one, before the exec and while that process owned the socket",
        "telemetry": "Linux auditd net_socket (socket.syscall connect/accept/accept4, destination.ip/port or "
                     "source.ip/port, process.pid, process.executable, process.user, outcome, host.boot.id) and "
                     "process_exec (process.executable, process.pid, process.ppid, process.argv), joined by the "
                     "per-host PID table: present in the lab profile. Exec auditing appears to cover euid 0 or "
                     "uid<1000 only, so a shell run by an unprivileged non-root account may be unrecorded and the "
                     "lineage negative is never complete (hence positive-only)",
        "fidelity": "direct observation of both stages (the connect/accept call and the shell exec), with their "
                    "outcomes stated; the link between them (that the shell uses the socket) is inferred from "
                    "lineage containment and timing and is worded as such",
        "benign_and_cost": "ssh clients spawning local shells, deployment/config agents that call a controller "
                           "then run a shell, IDE remote helpers. One grouped finding per (host, connecting PID, "
                           "peer); sshd-accepted login shells are excluded by exact typed lineage",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the shell's children and the session PCAP for cleartext commands",
        "adds": "host.interpreter_external_connection reports the outbound connection; no other rule joins that "
                "connection to the shell the owning process then executed, which is the reverse-shell behavior",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.004/.006 (command and scripting interpreter), T1071 and "
                          "T1095 (application- and non-application-layer C2); the reverse-shell process shape "
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
            if event.id in self._seen:                  # re-reading a partition must not double count
                continue
            self._seen.add(event.id)
            if event.family == "process_exec":
                self.pids.add(event)
                self._consider_shell(event)
            elif event.family == "net_socket":
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
        self.shells.append(_Shell(
            ts=event.ts.timestamp(), host=event.host or "", boot=event.get("host.boot.id"), pid=pid,
            ppid=event.get("process.ppid"), exe=str(exe), user=event.get("process.user"),
            event_id=event.id, devtcp=_devtcp_redirect(event.get("process.argv"))))
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
        if not external(ip):
            return
        self.evaluated += 1
        self.sockets[(event.host or "", event.get("host.boot.id"), pid)].append(_Socket(
            ts=event.ts.timestamp(), syscall=str(syscall), peer_ip=ip, peer_port=event.get(f"{side}.port"),
            exe=str(exe), user=event.get("process.user"), event_id=event.id))
        self._stage(event)

    # ---------------------------------------------------------------- finalize
    def _owners(self, shell: _Shell):
        """(pid, window_start, owner_exe, relation) for the shell's own pre-exec identity and each
        recorded ancestor. The window end is always the shell's exec time."""
        owners = []
        prior = self.pids.exec_before(shell.host, shell.pid, shell.ts)
        if prior is not None:
            owners.append((shell.pid, prior[0], prior[1], "own process re-exec"))
        for pid, exec_ts, exe, _raw in self.pids.lineage_entries(shell.host, shell.ppid, shell.ts):
            owners.append((pid, exec_ts, exe, "descendant"))
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
            for owner_pid, win_start, owner_exe, relation in self._owners(shell):
                owned = sorted(self.sockets.get((shell.host, shell.boot, owner_pid), ()),
                               key=lambda s: (s.ts, s.event_id))
                for sock in owned:
                    if not (win_start <= sock.ts < shell.ts):
                        continue                        # socket must be in the owner's live window, before the exec
                    gap = shell.ts - sock.ts
                    if gap > MAX_GAP:
                        continue
                    if sock.syscall in ACCEPT_SYSCALLS and basename(sock.exe) in SSHD_EXES:
                        continue                        # sshd accept + login shell: an SSH login (auth rules cover it)
                    key = (shell.host, shell.boot, owner_pid, sock.peer_ip)
                    groups[key].append(_Hit(shell, sock, owner_pid, owner_exe, relation, gap))
                    break                               # one owning socket per (shell, owner) is enough
        out = []
        for key in sorted(groups, key=lambda k: tuple("" if part is None else str(part) for part in k)):
            match = self._finding(key, groups[key])
            if match is not None:
                out.append(match)
        return out

    def _finding(self, key: tuple, hits: list[_Hit]) -> Match | None:
        host, _boot, owner_pid, peer_ip = key
        hits = sorted(hits, key=lambda h: (h.socket.ts, h.shell.ts, h.shell.event_id))
        first = hits[0]
        sock = first.socket
        shells = sorted({h.shell.event_id: h.shell for h in hits}.values(), key=lambda s: (s.ts, s.event_id))

        owner_account = sock.user
        owner_is_web = owner_account in WEB_SERVICE_USERS
        owner_is_interp = interpreter_name(basename(sock.exe)) in INTERPRETERS
        any_devtcp = any(h.shell.devtcp for h in hits)
        lane = "high" if (owner_is_web or owner_is_interp or any_devtcp) else "lead"
        confidence = "high" if (owner_is_web or owner_is_interp or any_devtcp) else "medium"

        verb = "connected out to" if sock.syscall == "connect" else "accepted an inbound connection from"
        port = f":{sock.peer_port}" if sock.peer_port not in (None, "") else ""
        owner_desc = (f"pid {owner_pid} ('{sock.exe}'"
                      + (f", account '{owner_account}'" if owner_account not in (None, "") else "") + ")")
        shell_names = sorted({interpreter_name(basename(s.exe)) for s in shells})
        shell_pids = ", ".join(str(s.pid) for s in shells[:CITE_PER_GROUP])
        claim = (
            f"On {host}, {owner_desc} {verb} external address {sock.peer_ip}{port}, and {len(shells)} "
            f"shell/interpreter exec(s) ({', '.join(shell_names)}; pid(s) {shell_pids}) followed under the same "
            f"process lineage ({first.relation}; {first.gap:.2f}s after the connection, within the connecting "
            f"process's recorded lifetime). The connection and the execution are each directly recorded; that "
            f"the shell's input and output use that connection is inferred from lineage and timing, not observed.")
        if any_devtcp:
            claim += " At least one shell was run with a command that redirects to or from a /dev/tcp pseudo-path."

        cited_ids = [sock.event_id] + [h.socket.event_id for h in hits] + [s.event_id for s in shells]
        events = self._events(cited_ids)
        cited = sorted(events.values(), key=lambda e: (e.ts, e.id))
        preds = [pf(events[sock.event_id], "socket.syscall")]
        for name in ("destination.ip", "source.ip", "process.pid", "process.executable"):
            if events[sock.event_id].has(name):
                preds.append(pf(events[sock.event_id], name))
        shell_event = events[shells[0].event_id]
        for name in ("process.executable", "process.pid", "process.ppid"):
            if shell_event.has(name):
                preds.append(pf(shell_event, name))
        notes = sorted(self.attack)
        notes.append("the outbound connection itself is reported by host.interpreter_external_connection")
        if lane == "lead":
            notes.append("lane lead: the connecting process is not a web-service account or interpreter and no "
                         "/dev/tcp redirect was seen; ssh clients and deployment agents share this shape")
        match = Match(self.id, claim, self.claim_type, cited, preds, cited[0].ts, self.severity, lane,
                      confidence, shell_event.entities(),
                      group_key=f"{host}|{_boot}|{owner_pid}|{peer_ip}")
        match.notes = notes
        if len(shells) > CITE_PER_GROUP:
            match.notes.append(f"{len(shells)} shell execs joined; the first {CITE_PER_GROUP} pid(s) are named")
        return match


LINEAGE_PLAYBOOKS = [ReverseShellByLineage]
