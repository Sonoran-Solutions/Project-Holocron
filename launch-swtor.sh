#!/usr/bin/env bash
set -e

STEAM_BASE="/home/dq/snap/steam/common/.local/share/Steam"
COMPAT_DATA="$STEAM_BASE/steamapps/compatdata/1286830"
PROTON_DIR="$STEAM_BASE/steamapps/common/Proton - Experimental"
SWTOR_DIR="$STEAM_BASE/steamapps/common/Star Wars - The Old Republic/swtor/retailclient"
SWTOR_EXE="$SWTOR_DIR/swtor.exe"

SERVER_HOST="${1:-127.0.0.1}"
SERVER_PORT="${2:-20061}"

echo "========================================================"
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

# HeroEngine bootstrap arguments for swtor.exe
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

echo "[LAUNCHER] Starting swtor.exe with Proton..."
cd "$SWTOR_DIR"

exec "$PROTON_DIR/proton" run "$SWTOR_EXE" "${ARGS[@]}"
