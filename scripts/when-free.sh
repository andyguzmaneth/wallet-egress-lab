#!/usr/bin/env bash
# Start a capture only when the shared `heavy` pool has room, so a run does not compete with
# another heavy job (the pool has one 12 GB ceiling and throttles past 10 GB).
# Usage: scripts/when-free.sh <run.sh args...>     e.g. DRIVER=metamask scripts/when-free.sh sepolia mm-sepolia-7
# FREE_MB (default 5000): start when the pool uses at most this much for QUIET_MIN (default 3)
# consecutive minutes. During the run it logs the pool's memory and throttle count to the run's pool.log,
# so a run that was slowed by another job shows it.
set -euo pipefail
cd "$(dirname "$0")/.."
H=/sys/fs/cgroup/system.slice/pm2-andy.service/heavy
FREE_MB=${FREE_MB:-5000}; QUIET_MIN=${QUIET_MIN:-3}
mb() { [ -f "$H/memory.current" ] && echo $(( $(cat "$H/memory.current") / 1048576 )) || echo 0; }
high() { [ -f "$H/memory.events" ] && awk '$1=="high"{print $2}' "$H/memory.events" || echo 0; }
quiet=0
while [ "$quiet" -lt "$QUIET_MIN" ]; do
  if [ "$(mb)" -le "$FREE_MB" ]; then quiet=$((quiet + 1)); else quiet=0; fi
  echo "$(date -u +%FT%TZ) waiting pool=$(mb)MB quiet=${quiet}/${QUIET_MIN}"
  [ "$quiet" -lt "$QUIET_MIN" ] && sleep 60
done
echo "$(date -u +%FT%TZ) starting pool=$(mb)MB"
[ -n "${BEFORE:-}" ] && bash -c "$BEFORE"
h0=$(high)
POOL=$(mktemp)
( while true; do echo "$(date -u +%FT%TZ) pool=$(mb)MB high_events=$(( $(high) - h0 ))" >> "$POOL"; sleep 60; done ) &
W=$!
trap 'kill $W 2>/dev/null || true' EXIT
~/bin/heavy scripts/run.sh "$@" | tee /dev/stderr | tail -1 > "$POOL.run"
RUN=$(cat "$POOL.run")
mv "$POOL" "$RUN/pool.log"
echo "$(date -u +%FT%TZ) done $RUN throttle_events=$(( $(high) - h0 ))"
