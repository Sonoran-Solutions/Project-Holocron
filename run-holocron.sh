#!/usr/bin/env bash
set -e

echo "================================================="
echo "       Starting Project Holocron Server Stack    "
echo "================================================="

export PATH="/home/dq/.dotnet:$PATH"
export DOTNET_ROOT="/home/dq/.dotnet"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[1/3] Building Holocron .NET 8 Solution..."
dotnet build Holocron.sln -c Release

echo "[2/3] Checking Docker MariaDB..."
if command -v docker >/dev/null 2>&1; then
    docker compose up -d holocron-db || echo "Note: Run docker compose if container database is desired."
fi

echo "[3/3] Ready! Run any of the following services:"
echo "  - Data Extractor: dotnet run -c Release --project src/Holocron.DataExtractor"
echo "  - Packet Proxy:   dotnet run -c Release --project tools/Holocron.PacketProxy"
echo "  - Auth Server:    dotnet run -c Release --project src/Holocron.Auth"
echo "  - World Server:   dotnet run -c Release --project src/Holocron.World"
echo "  - Test Suite:     dotnet test tests/Holocron.Tests"
