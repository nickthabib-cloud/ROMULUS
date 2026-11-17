"""Analyst controls over a hunt: stop requests, force stop, the worker-process record and agent budget extensions.

Stop. An analyst's stop request is a row in the store (who, when, scope "hunt" or "agent"). The running hunt reads it
at safe points, through `StopWatch` (one indexed lookup at most every STOP_CHECK_SECONDS): before each sweep partition
is read, before each expansion link is fetched, between stages, and in the agent before every model call, before every
read tool call, before every triage call and between rounds. The packet, baseline, site-network and ranking stages
check only at their boundaries: one that is running finishes its current step first (or is ended by a force stop).
A stopped run ends cleanly, keeps everything it stored, records the request as
honoured, and leaves the hunt honestly partial and resumable: what it did not run is named, never reported complete,
and every rule a skipped stage owns reads partial until a resume runs it (`run.mark_unrun_stages`).

Force stop. When a requested stop has not taken effect within the grace period (ROMULUS_HUNT_STOP_GRACE_SECONDS),
a force stop ends the hunt's worker process. Every worker records its own pid with a start marker (the kernel's
process start time and boot id) and its host; a force stop acts only on that recorded process, only on the same
host, only while the pid still has that start marker and runs ROMULUS (and to the process group the worker leads,
so its children end with it), so a pid the system has given to another
process is never signalled. The hunt is then left `partial`, its agent `interrupted`, and a resume continues it.

Roles. A lead may stop or extend any hunt; an analyst may stop or extend the hunts they started. Only a lead may force
a stop, or choose or extend an agent budget above the site ceiling. The command line runs on the server under the
service account, so whoever runs it already controls the hunt processes; it may stop any hunt, and goes above the
ceiling only with a lead account's password. Every stop, force stop, extension and budget choice is audited with
the person as actor.
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from time import monotonic

from romulus.agent import hunt_budget
from romulus.config import Settings
from romulus.store.db import utcnow

log = logging.getLogger("romulus.hunt")

# How long a run trusts its last read of the stop request: a stop takes effect within this of the next safe point.
STOP_CHECK_SECONDS = 2.0
# How long a force stop waits for the process to end after each signal.
KILL_WAIT_SECONDS = 5.0
# A budget grant the web made for a hunt process it starts must be read within this.
GRANT_MAX_AGE_SECONDS = 600
UNVERIFIABLE = "unverifiable"


class HuntStopped(Exception):
    # a control-flow signal, not an error
    """An analyst's stop request ended the run at a safe point. Never a lease loss: its text never says so."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class ControlRefused(ValueError):
    """A control the requester may not use, or that does not apply to the hunt now."""


def describe(row: dict) -> str:
    at = row.get("requested_at")
    when = at.isoformat() if isinstance(at, datetime) else str(at or "")
    return f"requested by {row.get('requested_by')} at {when}"


class StopWatch:
    """Cached reads of a hunt's open stop request of the given scopes. Calling it returns the request's description,
    or None while there is none."""

    def __init__(self, repo, hunt_id: str, scopes: tuple[str, ...], *, ttl: float | None = None,
                 clock: Callable[[], float] = monotonic):
        self.repo, self.hunt_id, self.scopes, self.clock = repo, hunt_id, scopes, clock
        self.ttl = STOP_CHECK_SECONDS if ttl is None else ttl
        self.row: dict | None = None
        self._at: float | None = None

    def request(self) -> dict | None:
        now = self.clock()
        if self._at is None or now - self._at >= self.ttl:
            try:
                self.row = self.repo.active_stop(self.hunt_id, self.scopes)
            except Exception:  # noqa: BLE001 - a store hiccup must not stop a hunt; the next check reads again
                log.exception("could not read hunt %s's stop request", self.hunt_id)
            self._at = now
        return self.row

    def __call__(self) -> str | None:
        row = self.request()
        return describe(row) if row else None

    def honor(self, where: str) -> dict | None:
        """Record that the run stopped for the open request at `where`; returns the request."""
        row = self.row or self.request()
        if row:
            try:
                self.repo.honor_stop(row["id"], where)
            except Exception:  # noqa: BLE001 - the run already stopped; the request stays visible as requested
                log.exception("could not record that hunt %s honoured its stop request", self.hunt_id)
        return row


# ---------------------------------------------------------------------------------------------------- processes
def process_identity(pid: int, *, root: Path = Path("/proc")) -> tuple[str, str] | None:
    """(start marker, command line) of a live process on this host; None when it is gone or the host cannot say
    (only Linux's /proc is read). The marker is the boot id and the process's start time in clock ticks, which a
    later process given the same pid never shares."""
    proc = root / str(int(pid))
    try:
        stat = (proc / "stat").read_text(encoding="ascii", errors="replace")
        boot = (root / "sys" / "kernel" / "random" / "boot_id").read_text(encoding="ascii").strip()
        cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
    except (OSError, ValueError):
        return None
    fields = stat[stat.rfind(")") + 2:].split()
    if len(fields) < 20 or fields[0] == "Z":         # a zombie has ended
        return None
    return f"{boot}:{fields[19]}", cmdline


def own_group() -> int | None:
    """The process group this worker leads, or None. A worker the web starts leads its own session. One started from
    a script (no terminal) is moved into a group of its own, so that signalling the group never reaches the script;
    one run at a terminal stays in the terminal's job, where Ctrl-C still reaches it, and only its pid is signalled."""
    getpgid = getattr(os, "getpgid", None)
    if getpgid is None:
        return None
    pid = os.getpid()
    try:
        if getpgid(0) != pid and not sys.stdin.isatty():
            os.setpgid(0, 0)
        return pid if getpgid(0) == pid else None
    except (OSError, ValueError):
        return None


def own_marker() -> str:
    identity = process_identity(os.getpid())
    return identity[0] if identity else f"{UNVERIFIABLE}:{os.getpid()}"


@contextmanager
def worker(repo, hunt_id: str, command: str):
    """Record this process as the hunt's worker while the block runs, with the process group it leads (its
    children, TShark among them, are in it), so a force stop ends them too."""
    pid, marker = os.getpid(), own_marker()
    try:
        repo.record_hunt_process(hunt_id, pid=pid, start_marker=marker, host=socket.gethostname(), command=command,
                                 pgid=own_group())
    except Exception:  # noqa: BLE001 - without the record a force stop is refused; the hunt still runs
        log.exception("could not record hunt %s's worker process", hunt_id)
    try:
        yield
    finally:
        try:
            repo.end_hunt_process(hunt_id, pid, marker)
        except Exception:  # noqa: BLE001
            log.exception("could not record the end of hunt %s's worker process", hunt_id)


def _signal(pid: int, sig: int, pgid: int | None = None) -> None:
    if pgid is not None and pgid == pid and hasattr(os, "killpg"):
        os.killpg(pgid, sig)             # the worker leads its group: its children end with it
    else:
        os.kill(pid, sig)


def _owner_of(repo, hunt_id: str) -> tuple[str | None, str | None]:
    hunt = repo.get_hunt(hunt_id) or {}
    run = repo.agent_run(hunt_id) or {}
    return hunt.get("lease_owner"), run.get("lease_owner")


def may_control(repo, hunt: dict, actor: str, role: str) -> bool:
    """A lead may control any hunt; an analyst the hunts they started. `actor` is "web:<user>" or "cli:<user>"."""
    if role == "lead":
        return True
    created = str(hunt.get("created_by") or "")
    user = actor.split(":", 1)[1] if ":" in actor else actor
    return created in (actor, f"cli:web:{user}", f"web:{user}")


def request_stop(repo, hunt_id: str, *, scope: str, actor: str, role: str) -> dict:
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    if not may_control(repo, hunt, actor, role):
        raise ControlRefused("only a lead or the analyst who started this hunt may stop it")
    try:
        return repo.request_hunt_stop(hunt_id, scope, actor)
    except ValueError as exc:
        raise ControlRefused(str(exc)) from None


def force_stop(s: Settings, repo, hunt_id: str, *, actor: str, role: str, now: datetime | None = None,
               identify: Callable[[int], tuple[str, str] | None] = process_identity,
               send: Callable[..., None] = _signal, host: str | None = None,
               sleep: Callable[[float], None] = time.sleep) -> dict:
    """End the hunt's worker process after a stop request it has not honoured within the grace period, then leave the
    hunt resumable. Raises ControlRefused when this is not allowed or not safe."""
    if role != "lead":
        raise ControlRefused("only a lead may force a hunt to stop")
    now = now or utcnow()
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    request = repo.active_stop(hunt_id)
    if request is None:
        raise ControlRefused("request a stop first; a force stop is for a run that does not honour it")
    live = repo.run_liveness(hunt_id, now=now)
    if not (live["hunt"] or live["agent"]):
        raise ControlRefused("the hunt is not running: nothing to force")
    if request["scope"] == "agent" and live["hunt"]:
        raise ControlRefused("the deterministic hunt is still running in the same process; request Stop hunt to "
                             "force it")
    ready = request["requested_at"] + timedelta(seconds=s.hunt_stop_grace_seconds)
    if now < ready:
        raise ControlRefused(f"the run has until {ready.isoformat()} to stop at its next safe point; force stop is "
                             "possible after that")
    proc = repo.hunt_process(hunt_id)
    if proc is None or proc["ended_at"] is not None:
        raise ControlRefused("no running worker process is recorded for this hunt")
    if proc["host"] != (host or socket.gethostname()):
        raise ControlRefused(f"the hunt's worker runs on {proc['host']}: force it from that host")
    if proc["start_marker"].startswith(UNVERIFIABLE):
        raise ControlRefused("this host cannot verify the worker process's identity; end it from the shell")
    pid = int(proc["pid"])
    if pid == os.getpid():
        raise ControlRefused("refusing to signal this process itself")
    hunt_owner, agent_owner = _owner_of(repo, hunt_id)
    marker = proc["start_marker"]

    def gone() -> bool:
        current = identify(pid)
        return current is None or current[0] != marker

    identity = identify(pid)
    signalled = False
    if identity is not None and identity[0] == marker:
        if "romulus" not in identity[1]:
            raise ControlRefused(f"process {pid} is not a ROMULUS process; refusing to signal it")
        for sig in (signal.SIGTERM, getattr(signal, "SIGKILL", signal.SIGTERM)):
            if gone():
                break                            # never signal a pid that no longer has the recorded marker
            try:
                send(pid, sig, proc.get("pgid"))
            except ProcessLookupError:
                break
            except PermissionError:
                raise ControlRefused(f"this account may not signal process {pid}; end it as the service account "
                                     "that runs the hunts") from None
            signalled = True
            deadline = monotonic() + KILL_WAIT_SECONDS
            while not gone() and monotonic() < deadline:
                sleep(0.2)
            if gone():
                break
        else:
            raise ControlRefused(f"process {pid} did not end; the hunt is unchanged")
    # otherwise the recorded process is gone already (its pid is free, or another process's): nothing is signalled
    try:
        changed = repo.end_force_stopped(hunt_id, request_id=request["id"], actor=actor, hunt_owner=hunt_owner,
                                         agent_owner=agent_owner, pid=pid, start_marker=marker)
    except ValueError as exc:
        raise ControlRefused(str(exc)) from None
    if changed.get("hunt"):
        # the stages the ended worker had not finished read partial until a resume runs them
        from romulus.hunt.run import mark_unrun_stages
        mark_unrun_stages(repo, hunt_id, f"not run: the hunt was force-stopped by {actor}")
    return {"pid": pid, "signalled": signalled, "changed": changed}


# ---------------------------------------------------------------------------------------------------- budgets
def extend_budget(s: Settings, repo, hunt_id: str, *, actor: str, role: str, profile: str | None = None,
                  amounts: dict | None = None, control_role: str | None = None) -> dict:
    """Record a budget extension for the hunt's agent: explicit amounts or a raise to a profile. `role` holds the new
    totals to the ceiling; `control_role` (default `role`) decides whether the actor may extend this hunt at all.
    Returns the extension, the new limits, and whether the agent needs a continuation to use it (it is not running
    now)."""
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    if not may_control(repo, hunt, actor, control_role or role):
        raise ControlRefused("only a lead or the analyst who started this hunt may extend its agent budget")
    manifest = hunt["manifest"] or {}
    if not (manifest.get("ai_agent") or {}).get("requested"):
        raise ControlRefused("this hunt ran without the AI agent: there is no agent budget to extend")
    planned: dict = {}

    def check(existing: list[dict]) -> tuple[dict, list[str]]:
        # under the write lock, against every extension recorded so far (one made at the same time included)
        current = hunt_budget.resolve(repo, hunt_id, manifest, s, extensions=existing)["limits"]
        planned.update(hunt_budget.extension(s, current, role=role, profile=profile, amounts=amounts))
        return planned["amounts"], planned["above_ceiling"]

    try:
        # a quick check first, so a refusal needs no write lock; the recorded one is the check under the lock
        hunt_budget.extension(s, hunt_budget.resolve(repo, hunt_id, manifest, s)["limits"], role=role,
                              profile=profile, amounts=amounts)
        row = repo.add_budget_extension(hunt_id, added_by=actor, role=role, amounts={}, profile=profile,
                                        above_ceiling=[], max_extensions=hunt_budget.MAX_EXTENSIONS, check=check)
    except ValueError as exc:
        raise ControlRefused(str(exc)) from None
    live = repo.run_liveness(hunt_id)
    return {"extension": row, "limits": planned["totals"], "running": live["agent"] or live["hunt"]}


def continuation_command(env_file: Path | None, hunt_id: str) -> list[str]:
    """The command that continues a hunt's agent from its persisted state (no sweep)."""
    return ([sys.executable, "-m", "romulus.cli"] + (["--env-file", str(env_file)] if env_file else [])
            + ["hunt", "resume", hunt_id, "--agent-only"])
