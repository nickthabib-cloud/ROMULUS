"""Command-line entry point (`romulus ...`). Thin: parses arguments and calls services."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from romulus.config import load_settings

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _env_file(args) -> Path:
    if args.env_file:
        return Path(args.env_file)
    home = os.environ.get("ROMULUS_HOME", str(Path.home() / "romulus"))
    p = Path(home) / ".env"
    return p if p.exists() else Path(".env")


def cmd_doctor(args) -> int:
    from romulus.doctor import run_all
    env = _env_file(args)
    s = load_settings(env)
    checks = run_all(s, env)
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2))
    else:
        for c in checks:
            mark = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}[c.status]
            print(f"[{mark}] {c.name:32} {c.detail}")
    return EXIT_FAIL if any(c.status == "fail" for c in checks) else EXIT_OK


def _ai_agent_line(result: dict) -> str:
    ai = result.get("ai_agent") or {}
    line = f"AI agent: {ai.get('status', 'unknown')}"
    if ai.get("reason"):
        line += f" ({ai['reason']})"
    if ai.get("status") != "completed":
        line += "; the deterministic results do not depend on it"
    return line


def _parse_time(value: str, tz: str):
    from datetime import UTC, datetime
    from zoneinfo import ZoneInfo
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC if tz == "UTC" else ZoneInfo(tz))
    return dt.astimezone(UTC)


def cmd_hunt(args) -> int:
    import logging

    from romulus.hunt.run import ai_agent_entry, create_hunt, open_repo, resume_hunt, run_hunt
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("alembic").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    s = load_settings(_env_file(args))
    if args.action == "start":
        agent_mode = "off" if args.no_agent else (args.agent_mode or s.agent_mode)
        s = s.model_copy(update={"agent_mode": agent_mode})
        start, end = _parse_time(args.start, s.mission_timezone), _parse_time(args.end, s.mission_timezone)
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "cli"
        try:
            hid = create_hunt(s, start, end, created_by=f"cli:{user}", style=args.style,
                              hypothesis=args.hypothesis or "",
                              original_input={"start": args.start, "end": args.end, "tz": s.mission_timezone},
                              expand=not args.no_expand, ai_agent=False if args.no_agent else None)
        except ValueError as e:
            print(f"hunt not created: {e}", file=sys.stderr)
            return EXIT_FAIL
        print(f"hunt {hid} created [{start.isoformat()}, {end.isoformat()})")
        ai = ai_agent_entry(s, False if args.no_agent else None)
        if ai.get("state") == "blocked" and ai.get("requested"):
            print(f"AI agent blocked: {ai.get('reason')}; the hunt runs without it", file=sys.stderr)

        def show(c):
            if c["lane"] in ("urgent", "high"):
                print(f"  [{c['lane'].upper():6}] {c['rule_id']}: {c['claim'][:180]}", flush=True)
        res = run_hunt(s, hid, agent_mode=agent_mode, on_candidate=show, expand=not args.no_expand)
        print(json.dumps(res, indent=2, default=str) if args.json else
              f"done: {res['execution_state']} {res['detection_result']} lanes={res['lanes']} "
              f"stats={ {k: v for k, v in res['stats'].items() if k != 'skips'} }\n" + _ai_agent_line(res))
        return EXIT_OK
    if args.action == "resume":
        agent_mode = "off" if args.no_agent else args.agent_mode
        kwargs = {"agent_mode": agent_mode} if agent_mode else {}
        if args.no_agent:
            kwargs["ai_agent"] = False
        result = resume_hunt(s, args.hunt_id, **kwargs)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            agent = result["agent"]
            print(f"resumed: {result['execution_state']} agent={agent['status']} "
                  f"unworked={agent.get('unworked_count', 0)} "
                  f"analyst_flags={len(agent.get('analyst_flags') or [])}\n" + _ai_agent_line(result))
        return EXIT_OK
    if args.action == "status":
        from romulus.report.manifest import investigations_for_hunt
        repo = open_repo(s)
        hunts = [repo.get_hunt(args.hunt_id)] if args.hunt_id else repo.list_hunts()
        for h in hunts:
            if h:
                agent_audit = repo.latest_audit(h["id"], "hunt.agent_summary")
                agent = agent_audit["detail"] if agent_audit else {}
                investigations = investigations_for_hunt(repo, h["id"])
                inv_summary = investigations["summary"]
                print(f"{h['id']}  {h['execution_state']:24} {h['detection_result'] or '-':40} "
                      f"lanes={repo.lane_counts(h['id'])} " + _stage_status(repo, h["id"], agent, inv_summary))
                for case in investigations["cases"]:
                    descriptions = [choice["description"] for choice in case["chosen_options"]]
                    if descriptions:
                        print(f"  {case['id']} options: " + " -> ".join(descriptions))
                    for choice in case["chosen_options"]:
                        if choice["fallback_note"]:
                            print(f"    fallback: {choice['fallback_note']}")
        return EXIT_OK
    return EXIT_USAGE


def cmd_findings(args) -> int:
    from romulus.decide.policy import LANE_ORDER
    from romulus.hunt.run import open_repo
    repo = open_repo(load_settings(_env_file(args)))
    rows = repo.candidates(args.hunt_id, args.lane or None)
    rows.sort(key=lambda r: (LANE_ORDER.get(r["lane"], 9), -r["priority"], str(r["ts"])))
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return EXIT_OK
    for r in rows:
        print(f"{r['id']}  [{r['lane']:7}] sev={r['severity']:6} conf={r['confidence']:6} {r['ts']}  {r['rule_id']}")
        print(f"    {r['claim']}")
    return EXIT_OK


def cmd_report(args) -> int:
    from romulus.hunt.run import open_repo
    from romulus.report.manifest import publish_revision
    from romulus.report.markdown import render
    s = load_settings(_env_file(args))
    repo = open_repo(s)
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "cli"
    m = publish_revision(repo, args.hunt_id, actor=f"cli:{user}")
    out_dir = s.reports_dir / args.hunt_id
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{m['revision']['id']}"
    jpath, mpath = out_dir / f"{stem}.json", out_dir / f"{stem}.md"
    jpath.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
    mpath.write_text(render(m), encoding="utf-8")
    print(f"revision {m['revision']['number']}: {len(m['findings'])} findings/leads, "
          f"broken citations={m['integrity']['broken_citations']}")
    print(f"  {jpath}\n  {mpath}")
    return EXIT_OK if m["integrity"]["finalizable"] else EXIT_FAIL


def cmd_user(args) -> int:
    import getpass

    from romulus.hunt.run import open_repo
    from romulus.web.auth import create_user
    repo = open_repo(load_settings(_env_file(args)))
    pw = getpass.getpass(f"Password for {args.username} (12+ chars): ")
    if pw != getpass.getpass("Repeat password: "):
        print("passwords do not match", file=sys.stderr)
        return EXIT_USAGE
    try:
        create_user(repo.engine, args.username, pw, args.role)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return EXIT_USAGE
    repo.audit("cli", "user.create", detail={"username": args.username, "role": args.role})
    print(f"created {args.role} account '{args.username}'")
    return EXIT_OK


def cmd_web(args) -> int:
    import uvicorn

    from romulus.web.app import create_app
    env = _env_file(args)
    s = load_settings(env)
    host, _, port = s.web_bind.rpartition(":")
    if not s.web_tls_enabled and host not in ("127.0.0.1", "localhost"):
        print(f"WARNING: serving on {host} without TLS (lab exception). Set ROMULUS_WEB_TLS_CERT/KEY for TLS.",
              file=sys.stderr)
    uvicorn.run(create_app(s, env), host=host, port=int(port), log_level="info",
                ssl_certfile=s.web_tls_cert or None, ssl_keyfile=s.web_tls_key or None, proxy_headers=False)
    return EXIT_OK


def cmd_db(args) -> int:
    from romulus.hunt.run import open_repo
    from romulus.store.db import compact
    s = load_settings(_env_file(args))
    repo = open_repo(s)
    active = repo.hunts_with_live_lease()
    if active:
        print(f"refusing to compact while hunts hold an active lease: {', '.join(active)}", file=sys.stderr)
        return EXIT_FAIL
    purged = repo.purge_orphan_audit()
    res = compact(repo.engine)
    res["orphan_audit_records_removed"] = purged
    b, a = res["before"], res["after"]
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"database {b['file_bytes'] / 1e6:.0f} MB + log {b['wal_bytes'] / 1e6:.0f} MB -> "
              f"{a['file_bytes'] / 1e6:.0f} MB + log {a['wal_bytes'] / 1e6:.0f} MB; "
              f"{purged} system record(s) of deleted hunts removed")
    repo.audit(f"cli:{os.environ.get('USER', '?')}", "db.compact",
               detail={"before": b, "after": a, "orphan_audit_records_removed": purged})
    return EXIT_OK


def cmd_replay(args) -> int:
    from romulus.replay.export import export_tasks, read_jsonl, readonly_repo, write_jsonl
    from romulus.replay.runner import run_replay, summarize
    s = load_settings(_env_file(args))
    if args.action == "export":
        variants = read_jsonl(args.variants) if args.variants else None
        with readonly_repo(s.db_path) as repo:
            tasks, stats = export_tasks(repo, args.hunt, args.num_ctx or [s.ollama_num_ctx], variants)
        write_jsonl(args.out, tasks)
        print(json.dumps(stats, indent=2) if args.json else
              f"{stats['tasks']} tasks from {stats['model_calls']} model calls "
              f"(digest match {stats['digest_match']}, mismatch {stats['digest_mismatch']}, "
              f"variants {stats['variants']}, unfit briefs {stats['unfit_briefs']}) -> {args.out}")
        return EXIT_OK
    if args.action == "run":
        tasks = read_jsonl(args.tasks)
        if args.task:
            wanted = set(args.task)
            tasks = [task for task in tasks if task["task_id"] in wanted]
        if args.limit:
            tasks = tasks[:args.limit]
        think = {"off": [False], "on": [True], "both": [False, True]}[args.think]
        counts = run_replay(s, tasks, args.model or [s.ollama_model_triage], args.num_ctx or [s.ollama_num_ctx],
                            think, args.seed or [7], args.out, args.run_id, max_out=args.max_out,
                            retry=not args.no_retry, progress=None if args.json else print)
        print(json.dumps(counts) if args.json else f"done: {counts} -> {args.out}")
        return EXIT_OK
    rows = summarize(read_jsonl(args.results))
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    print(f"{'model':28} {'ctx':>6} {'think':>5} {'n':>4} {'schema':>6} {'valid1':>6} {'valid2':>6} "
          f"{'trunc':>5} {'limit':>5} {'err':>4} {'p50 ms':>8} {'tok/s':>6}")
    for row in rows:
        print(f"{row['model']:28} {row['num_ctx']:>6} {row['think']!s:>5} {row['n']:>4} {row['schema_valid']:>6} "
              f"{row['valid_first']:>6} {row['valid_with_retry']:>6} {row['truncated']:>5} {row['output_limit']:>5} "
              f"{row['errors']:>4} {row['median_latency_ms'] or '-':>8} {row['median_decode_tokens_per_s'] or '-':>6}")
    return EXIT_OK


def _stage_status(repo, hunt_id: str, agent: dict, inv_summary: dict) -> str:
    """One status line per stage. With the investigator off, its 'unworked' count would list every finding;
    expansion and packet accounting say what the deterministic stages did instead."""
    parts = []
    packet_audit = repo.latest_audit(hunt_id, "hunt.packet_summary")
    if packet_audit:
        packet = packet_audit["detail"]
        parts.append(f"packets={packet.get('status', '-')} responses={packet.get('responses', 0)} "
                     f"matched={packet.get('matched', 0)}")
    expansion_audit = repo.latest_audit(hunt_id, "hunt.expansion_summary")
    if expansion_audit:
        expansion = expansion_audit["detail"]
        parts.append(f"expansion={expansion.get('status', '-')} anchors={expansion.get('anchors', 0)} "
                     f"(complete {expansion.get('expanded_complete', 0)}, partial {expansion.get('expanded_partial', 0)}, "
                     f"unexpanded {len(expansion.get('unexpanded') or [])}) queries={expansion.get('source_queries', '-')}")
    if agent.get("status") in (None, "disabled"):
        parts.append("agent=off")
    else:
        parts.append(f"agent={agent.get('status', '-')} mode={inv_summary.get('mode', 'model')} "
                     f"unworked={agent.get('unworked_count', '-')} partial_pivots={agent.get('partial_pivots', 0)} "
                     f"fallbacks={inv_summary.get('deterministic_fallbacks', 0)} "
                     f"menu_hidden={inv_summary.get('menu_hidden_options', 0)} "
                     f"analyst_flags={len(agent.get('analyst_flags') or [])}")
    return " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="romulus", description="ROMULUS threat hunting")
    p.add_argument("--env-file", help="path to .env (default: $ROMULUS_HOME/.env)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check sources, privileges, model endpoint, tools and storage")
    hp = sub.add_parser("hunt", help="create/run hunts and show status")
    hp.add_argument("action", choices=["start", "resume", "status"])
    hp.add_argument("hunt_id", nargs="?")
    hp.add_argument("--start")
    hp.add_argument("--end")
    hp.add_argument("--style", default="broad", choices=["broad", "directed"])
    hp.add_argument("--hypothesis")
    hp.add_argument("--no-agent", action="store_true", help="deterministic sweep only (model-off)")
    hp.add_argument("--agent-mode", choices=["model", "deterministic", "off"],
                    help="investigator mode (default: AGENT_MODE or off)")
    hp.add_argument("--no-expand", action="store_true", help=argparse.SUPPRESS)
    fp = sub.add_parser("findings", help="list candidates of a hunt, ranked by lane and priority")
    fp.add_argument("hunt_id")
    fp.add_argument("--lane", action="append", choices=["urgent", "high", "lead", "context"])
    rp = sub.add_parser("report", help="publish a new immutable report revision (JSON + technical Markdown)")
    rp.add_argument("hunt_id")
    up = sub.add_parser("user", help="manage web UI accounts")
    up.add_argument("action", choices=["add"])
    up.add_argument("username")
    up.add_argument("--role", choices=["lead", "analyst"], default="analyst")
    sub.add_parser("web", help="serve the browser UI on ROMULUS_WEB_BIND")
    dp = sub.add_parser("db", help="database maintenance")
    dp.add_argument("action", choices=["compact"], help="compact: return space freed by deleted hunts to the disk")
    replay = sub.add_parser("replay", help="export frozen investigator briefs, run them, and summarize results")
    replay.add_argument("action", choices=["export", "run", "summary"])
    replay.add_argument("--hunt", help="export: hunt whose investigator calls become tasks")
    replay.add_argument("--variants", help="export: JSONL of {variant, task_id, mutations[]}")
    replay.add_argument("--tasks", help="run: task JSONL from replay export")
    replay.add_argument("--task", action="append", help="run: run only this task id (repeatable)")
    replay.add_argument("--limit", type=int, help="run: run only the first N tasks")
    replay.add_argument("--model", action="append", help="run: candidate model (repeatable)")
    replay.add_argument("--num-ctx", type=int, action="append", help="num_ctx value (repeatable)")
    replay.add_argument("--think", choices=["off", "on", "both"], default="off")
    replay.add_argument("--seed", type=int, action="append", help="run: seed (7 = production; repeatable)")
    replay.add_argument("--max-out", type=int, default=900, help="run: output token budget (production 900)")
    replay.add_argument("--no-retry", action="store_true", help="run: no second attempt after a rejection")
    replay.add_argument("--run-id", default="replay", help="run: label recorded on every row")
    replay.add_argument("--results", help="summary: result JSONL")
    replay.add_argument("--out", help="output JSONL (run appends and resumes)")
    args = p.parse_args(argv)
    if args.cmd == "replay":
        needed = {"export": ("hunt", "out"), "run": ("tasks", "out"), "summary": ("results",)}
        missing = [name for name in needed[args.action] if not getattr(args, name)]
        if missing:
            p.error(f"replay {args.action} needs " + ", ".join(f"--{name}" for name in missing))
    if args.cmd == "hunt" and args.action == "start" and not (args.start and args.end):
        p.error("hunt start needs --start and --end")
    if args.cmd == "hunt" and args.action == "resume" and not args.hunt_id:
        p.error("hunt resume needs a hunt id")
    handlers = {"doctor": cmd_doctor, "hunt": cmd_hunt, "findings": cmd_findings, "report": cmd_report,
                "user": cmd_user, "web": cmd_web, "replay": cmd_replay, "db": cmd_db}
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
