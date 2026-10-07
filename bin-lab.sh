#!/usr/bin/env bash
# lab start <runDir> [chain] [owner]  |  lab stop  |  lab <cmd> [k=v ...]
set -euo pipefail
cd "$(dirname "$0")"
P=${LAB_PORT:-9333}; MP=${MITM_PORT:-8081}
case "${1:-}" in
  start)
    RUN=$2; mkdir -p "$RUN"
    nohup mitmdump -q -p "$MP" -s capture/record.py --set out="$RUN/flows.jsonl" > "$RUN/mitm.log" 2>&1 & echo $! > "$RUN/mitm.pid"
    sleep 2
    nohup xvfb-run -a -s "-screen 0 1440x900x24" npx tsx driver/session.ts "$RUN" "http://127.0.0.1:$MP" "${3:-sepolia}" "${4:-A}" "$P" > "$RUN/session.log" 2>&1 &
    for i in $(seq 1 60); do grep -q ready "$RUN/session.log" 2>/dev/null && break; sleep 1; done; cat "$RUN/session.log" ;;
  stop)
    RUN=$2; curl -s "127.0.0.1:$P/close" || true; sleep 1; kill "$(cat "$RUN/mitm.pid")" 2>/dev/null || true; echo stopped ;;
  *)
    cmd=$1; shift; args=(); for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    curl -s -G "127.0.0.1:$P/$cmd" "${args[@]}"; echo ;;
esac
