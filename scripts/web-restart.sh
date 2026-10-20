#!/usr/bin/env bash
# (Re)start the ROMULUS web UI, tracked by PID file (never by pattern-matching process names).
# ROMULUS_HOME defaults to the install this script belongs to ($ROMULUS_HOME/app/scripts/web-restart.sh).
set -euo pipefail
H=${ROMULUS_HOME:-$(cd "$(dirname "$0")/../.." && pwd)}
PIDF="$H/web.pid"
if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  kill "$(cat "$PIDF")"; sleep 1
fi
mkdir -p "$H/logs"
setsid "$H/venv/bin/romulus" --env-file "$H/.env" web >> "$H/logs/web.log" 2>&1 < /dev/null &
echo $! > "$PIDF"
sleep 3
if kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "web running (pid $(cat "$PIDF"))"; else echo "web failed to start"; tail -20 "$H/logs/web.log"; exit 1; fi
