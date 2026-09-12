#!/usr/bin/env bash
set -euo pipefail
cd /home/dq/project-holocron
timeout --signal=TERM --kill-after=5s 300s tools/launch-isolated-client.sh >/tmp/holocron-dialog-run.log 2>&1 &
runner_pid=$!
trap 'kill -TERM "$runner_pid" 2>/dev/null || true; wait "$runner_pid" 2>/dev/null || true' EXIT
for attempt in $(seq 1 280); do
  if ! kill -0 "$runner_pid" 2>/dev/null; then
    wait "$runner_pid"
    echo "Runner exited without a captured dialog."
    exit 0
  fi
  # Windows may disappear while X11 enumerates them; retry on that race.
  dialog_id=$( { xwininfo -root -tree 2>/dev/null || true; } | awk '/"SWTOR":/ && !found {print $1; found=1}')
  if [[ -n "$dialog_id" ]]; then
    if timeout 5s xwd -silent -id "$dialog_id" -out /tmp/holocron-dialog.xwd; then
      convert /tmp/holocron-dialog.xwd /tmp/holocron-dialog.png
      echo "Captured SWTOR dialog."
      exit 0
    fi
  fi
  sleep 1
done
echo "No SWTOR dialog found during bounded launch." >&2
exit 1
