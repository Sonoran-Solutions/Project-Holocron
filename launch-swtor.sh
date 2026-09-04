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

# Write out holocron.icb dynamically with current host and port
cat << ICB_EOF > "$SWTOR_DIR/holocron.icb"
set server ${SERVER_HOST}
set port ${SERVER_PORT}
set instance 1
set username dq
set password holocron
set token local
set environment dev
set platform pc
set lang en-us
set torsets 1
set skipgamemovies true

set shardaddress @\${server}:\${port}:\${instance}

server install RemoteRenderer
server start RemoteRenderer://test1@local::IpcConsole:1

server install HeroEngine
server start HeroEngine://test1@null::IpcConsole:1 username=\${username} password=\${password} token=\\"\${token}\\" environment=\${environment} platform=\${platform} shardaddress=\${shardaddress} lang=\${lang} torsets=\${torsets} skipgamemovies=\${skipgamemovies}

autotick

server stop RemoteRenderer://test1@local::IpcConsole:1
server uninstall RemoteRenderer

server stop HeroEngine://test1@null::IpcConsole:1
server uninstall HeroEngine

exit
ICB_EOF

echo "[LAUNCHER] Starting swtor.exe with Holocron bootstrap..."
cd "$SWTOR_DIR"

exec "$PROTON_DIR/proton" run "$SWTOR_EXE" @holocron.icb
