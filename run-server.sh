#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
dotnet_bin="$(command -v dotnet || true)"
if [[ -z "$dotnet_bin" ]]; then
    dotnet_bin="${DOTNET_ROOT:-$HOME/.dotnet}/dotnet"
fi
if [[ ! -x "$dotnet_bin" ]]; then
    echo "[SERVER] .NET SDK not found. Install .NET 8 or set DOTNET_ROOT." >&2
    exit 1
fi
cd "$project_dir"
"$dotnet_bin" build src/Holocron.World/Holocron.World.csproj -c Release --nologo

echo "[SERVER] Starting Holocron.World only. This command does not launch SWTOR."
echo "[SERVER] Experimental transport: retail-client login/gameplay is not implemented end to end."
exec "$dotnet_bin" "$project_dir/src/Holocron.World/bin/Release/net8.0/Holocron.World.dll" "$@"
