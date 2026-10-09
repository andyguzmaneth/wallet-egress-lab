#!/usr/bin/env bash
# Run one capture: scripts/run.sh <plan> [label]   (plan: sepolia | mainnet | baseline)
# UPSTREAM=http://127.0.0.1:9080 sends all app traffic onward through an HTTP CONNECT proxy, e.g. Tor's HTTPTunnelPort.
set -euo pipefail
cd "$(dirname "$0")/.."
PLAN=$1; LABEL=${2:-$PLAN}
RUN=runs/$(date -u +%Y%m%dT%H%M%SZ)-$LABEL
MP=${MITM_PORT:-8082}
mkdir -p "$RUN"
mitmdump -q -p "$MP" ${UPSTREAM:+--mode upstream:$UPSTREAM} -s capture/record.py --set out="$RUN/flows.jsonl" > "$RUN/mitm.log" 2>&1 &
MITM=$!
trap 'kill $MITM 2>/dev/null || true' EXIT
sleep 2
xvfb-run -a -s "-screen 0 1440x900x24" npx tsx driver/journey.ts "$RUN" "http://127.0.0.1:$MP" "$PLAN" 2>&1 | tee "$RUN/journey.log"
sleep 2
echo "$RUN"
