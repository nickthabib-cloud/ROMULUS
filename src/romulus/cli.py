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
    home = os.environ.get("ROMULUS_HOME", "/home/user/romulus-v2")
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


def _parse_time(value: str, tz: str):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(tz))
    return dt.astimezone(ZoneInfo("UTC"))


def cmd_hunt(args) -> int:
    import logging

    from romulus.hunt.run import create_hunt, open_repo, resume_hunt, run_hunt
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("alembic").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    s = load_settings(_env_file(args))
    if args.action == "start":
        start, end = _parse_time(args.start, s.mission_timezone), _parse_time(args.end, s.mission_timezone)
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "cli"
        try:
            hid = create_hunt(s, start, end, created_by=f"cli:{user}", style=args.style,
                              hypothesis=args.hypothesis or "",
                              original_input={"start": args.start, "end": args.end, "tz": s.mission_timezone})
        except ValueError as e:
            print(f"hunt not created: {e}", file=sys.stderr)
            return EXIT_FAIL
        print(f"hunt {hid} created [{start.isoformat()}, {end.isoformat()})")

        def show(c):
            if c["lane"] in ("urgent", "high"):
                print(f"  [{c['lane'].upper():6}] {c['rule_id']}: {c['claim'][:180]}", flush=True)
        res = run_hunt(s, hid, agent=not args.no_agent, on_candidate=show)
        print(json.dumps(res, indent=2, default=str) if args.json else
              f"done: {res['execution_state']} {res['detection_result']} lanes={res['lanes']} "
              f"stats={ {k: v for k, v in res['stats'].items() if k != 'skips'} }")
        return EXIT_OK
    if args.action == "resume":
        result = resume_hunt(s, args.hunt_id)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            agent = result["agent"]
            print(f"resumed: {result['execution_state']} agent={agent['status']} "
                  f"unworked={agent.get('unworked_count', 0)} "
                  f"analyst_flags={len(agent.get('analyst_flags') or [])}")
        return EXIT_OK
    if args.action == "status":
        repo = open_repo(s)
        hunts = [repo.get_hunt(args.hunt_id)] if args.hunt_id else repo.list_hunts()
        for h in hunts:
            if h:
                agent_audit = repo.latest_audit(h["id"], "hunt.agent_summary")
                agent = agent_audit["detail"] if agent_audit else {}
                print(f"{h['id']}  {h['execution_state']:24} {h['detection_result'] or '-':40} "
                      f"lanes={repo.lane_counts(h['id'])} agent={agent.get('status', '-')} "
                      f"unworked={agent.get('unworked_count', '-')} "
                      f"partial_pivots={agent.get('partial_pivots', 0)} "
                      f"analyst_flags={len(agent.get('analyst_flags') or [])}")
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
    args = p.parse_args(argv)
    if args.cmd == "hunt" and args.action == "start" and not (args.start and args.end):
        p.error("hunt start needs --start and --end")
    if args.cmd == "hunt" and args.action == "resume" and not args.hunt_id:
        p.error("hunt resume needs a hunt id")
    handlers = {"doctor": cmd_doctor, "hunt": cmd_hunt, "findings": cmd_findings, "report": cmd_report,
                "user": cmd_user, "web": cmd_web}
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
