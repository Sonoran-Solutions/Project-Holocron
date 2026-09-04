#!/usr/bin/env bash
set -euo pipefail

STEAM_BASE="/home/dq/snap/steam/common/.local/share/Steam"
COMPAT_DATA="$STEAM_BASE/steamapps/compatdata/1286830"
PROTON_DIR="$STEAM_BASE/steamapps/common/Proton - Experimental"
SWTOR_DIR="$STEAM_BASE/steamapps/common/Star Wars - The Old Republic/swtor/retailclient"
SWTOR_EXE="$SWTOR_DIR/swtor.exe"
WINESERVER="$PROTON_DIR/files/bin/wineserver"

SERVER_HOST="${1:-127.0.0.1}"
SERVER_PORT="${2:-20061}"

echo "========================================================"

LOCK_FILE="/tmp/holocron-swtor-client-${UID}.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "[ERROR] A Holocron SWTOR client launch is already running."
    echo "        Return to its terminal and press Ctrl+C before trying again."
    exit 1
fi
echo "          Project Holocron - SWTOR Client Launcher"
echo "========================================================"
echo "Target Executable: $SWTOR_EXE"
echo "Proton Version:    $PROTON_DIR"
echo "Server Target:     @$SERVER_HOST:$SERVER_PORT:1"
echo "Compat Data:       $COMPAT_DATA"
echo "========================================================"

export SteamAppId=1286830
export SteamGameId=1286830
export STEAM_COMPAT_DATA_PATH="$COMPAT_DATA"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM_BASE"
export WINEDEBUG="-all"
export WINEPREFIX="$COMPAT_DATA/pfx"

# The ICB bootstrap currently exits with SWTOR C2 before producing a client log.
# Direct arguments reach the network connection stage and give us diagnostics.
ARGS=(
    "shardaddress=@${SERVER_HOST}:${SERVER_PORT}:1"
    "server=${SERVER_HOST}"
    "port=${SERVER_PORT}"
    "instance=1"
    "username=dq"
    "password=holocron"
    "token=local"
    "environment=dev"
    "platform=pc"
    "lang=en-us"
    "torsets=1"
    "skipgamemovies=true"
)

client_pid=""
cleanup_client() {
    trap - HUP INT TERM
    if [[ -n "$client_pid" ]] && kill -0 "$client_pid" 2>/dev/null; then
        kill -TERM "$client_pid" 2>/dev/null || true
        "$WINESERVER" -k 2>/dev/null || true
    fi
    exit 130
}
trap cleanup_client HUP INT TERM

echo "[LAUNCHER] Starting the local-test client (separate from the server)..."
echo "[LAUNCHER] Steam may display Running, but this terminal owns the client."
echo "[LAUNCHER] Press Ctrl+C here to stop it cleanly."
cd "$SWTOR_DIR"

"$PROTON_DIR/proton" run "$SWTOR_EXE" "${ARGS[@]}" &
client_pid=$!

set +e
wait "$client_pid"
client_status=$?
set -e

client_pid=""
trap - HUP INT TERM
exit "$client_status"
