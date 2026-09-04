#!/usr/bin/env bash
set -euo pipefail

export DOTNET_ROOT="/home/dq/.dotnet"
export PATH="/home/dq/.dotnet:$PATH"

echo "[SERVER] Starting Holocron.World only. This command does not launch SWTOR."
echo "[SERVER] Start ./launch-swtor.sh separately when the server is ready."
exec /home/dq/project-holocron/src/Holocron.World/bin/Release/net8.0/Holocron.World "$@"
