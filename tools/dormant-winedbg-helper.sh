#!/usr/bin/env bash
set -euo pipefail

test_root=/opt/holocron-test
trigger="$test_root/debug-trigger"
ready="$test_root/debug-ready"
log="$test_root/logs/dormant-winedbg.log"
wine=/opt/private-proton/files/bin/wine
gdb_port=27979

: > "$log"
# Proton's `run` verb always starts its Steam bootstrap executable before the
# requested Windows program.  That is appropriate for starting SWTOR, but not
# for adding a debugger to SWTOR's already-running wineserver.  At wake-up,
# copy only the Wine/Proton session values from SWTOR itself and run the
# private Wine loader directly.  Nothing here records the rest of SWTOR's
# environment (which can contain unrelated Steam state).
inherit_runtime_context() {
  local pid entry name value allowed_name
  local -a allowed=(
    WINEPREFIX WINESERVER WINELOADER WINEDLLPATH PATH LD_LIBRARY_PATH
    STEAM_COMPAT_CLIENT_INSTALL_PATH STEAM_COMPAT_DATA_PATH
    STEAM_COMPAT_TOOL_PATHS STEAM_COMPAT_MOUNTS SteamAppId SteamGameId
  )

  for _ in $(seq 1 120); do
    pid=$(pgrep -n -x swtor.exe || true)
    [[ -n "$pid" && -r "/proc/$pid/environ" ]] && break
    sleep 0.25
  done
  [[ -n "${pid:-}" && -r "/proc/$pid/environ" ]] || {
    printf '%s\n' 'no-readable-swtor-environment' >> "$log"
    return 1
  }

  while IFS= read -r -d '' entry; do
    name=${entry%%=*}
    value=${entry#*=}
    for allowed_name in "${allowed[@]}"; do
      if [[ "$name" == "$allowed_name" ]]; then
        export "$name=$value"
        break
      fi
    done
  done < "/proc/$pid/environ"

  # Log only the allowlisted context requested for this diagnostic.  Values
  # are paths/app IDs, never Steam credentials or arbitrary process variables.
  printf 'swtor-unix-pid=%s\n' "$pid" >> "$log"
  for name in "${allowed[@]}"; do
    printf '%s=%s\n' "$name" "${!name-<unset>}" >> "$log"
  done
}

windows_pid_from_info_proc() {
  "$wine" winedbg.exe --command "info proc" 2>&1 | tee -a "$log" |
    awk "/'swtor\\.exe'/ { sub(/^ /, \"\"); print \$1; exit }"
}

rm -f "$ready"
printf 'helper-ready\n' > "$ready"
while [[ ! -e "$trigger" ]]; do sleep 0.25; done

printf 'triggered\n' >> "$log"
inherit_runtime_context >> "$log" 2>&1 || true
cd /opt/holocron-test/game/swtor/retailclient
windows_pid_hex=$(windows_pid_from_info_proc || true)
[[ -n "$windows_pid_hex" ]] || {
  printf '%s\n' 'swtor-windows-pid-not-found' >> "$log"
  printf 'enumeration-complete\n' >> "$test_root/debug-complete"
  exit 1
}
windows_pid=$((16#$windows_pid_hex))
printf 'swtor-windows-pid=%s\n' "$windows_pid" >> "$log"

if [[ -n "${HOLOCRON_DORMANT_NATIVE:-}" ]]; then
  # Invoke WineDbg's own debugger engine, not its GDB remote proxy.  The
  # command file establishes one post-envelope breakpoint and then continues;
  # its stdout/stderr is the bounded trace channel.
  printf '%s\n' 'native-breakpoint-requested=0x14043cf98' >> "$log"
  "$wine" winedbg.exe --file /home/dq/project-holocron/tools/native-winedbg-cf98.cmd \
    "$windows_pid" >> "$log" 2>&1 || true
elif [[ -n "${HOLOCRON_DORMANT_GDB:-}" ]]; then
  "$wine" winedbg.exe --gdb --no-start --port "$gdb_port" "$windows_pid" >> "$log" 2>&1 &
  proxy=$!
  for _ in $(seq 1 80); do
    ss -ltn 2>/dev/null | grep -q ":$gdb_port" && break
    sleep 0.25
  done
  if ss -ltn 2>/dev/null | grep -q ":$gdb_port"; then
    printf 'gdb-proxy-listening=%s\n' "$gdb_port" >> "$log"
    if [[ -n "${HOLOCRON_DORMANT_TRACE:-}" ]]; then
      printf '%s\n' 'filtered-trace-armed' >> "$log"
      gdb -q -nx -x /home/dq/project-holocron/tools/late-attach-trace.gdb >> "$log" 2>&1 || true
    else
      # The initial attach-stability probe touches no breakpoints.
      gdb -q -nx -batch \
        -ex "target remote 127.0.0.1:$gdb_port" \
        -ex 'x/2i 0x14043cf98' \
        -ex 'x/2i 0x140434770' >> "$log" 2>&1 || true
    fi
  else
    printf '%s\n' 'gdb-proxy-not-listening' >> "$log"
  fi
  kill "$proxy" 2>/dev/null || true
fi
printf 'enumeration-complete\n' >> "$test_root/debug-complete"
