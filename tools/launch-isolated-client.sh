#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST="$ROOT/.local-test/client-v1"
RUNTIME="$TEST/game/swtor/retailclient"
ASSETS="/home/dq/snap/steam/common/.local/share/Steam/steamapps/common/Star Wars - The Old Republic/Assets"
PROTON="/home/dq/snap/steam/common/.local/share/Steam/steamapps/common/Proton - Experimental"
DOTNET="/home/dq/.dotnet/dotnet"

[[ -x "$RUNTIME/swtor.exe" && -d "$ASSETS" && -x "$PROTON/proton" ]] || {
  echo "Prepared runtime, read-only assets, or Proton not found." >&2; exit 1;
}
PROTON_COPY="$TEST/proton"
[[ -x "$PROTON_COPY/proton" ]] || { echo "Private Proton copy missing: $PROTON_COPY" >&2; exit 1; }
[[ -r "$TEST/platform-ca.der" && -r "$TEST/platform-server-cert.pem" && -r "$TEST/platform-server-key.pem" ]] || {
  echo "Private platform TLS diagnostic certificate/key missing." >&2; exit 1;
}
mkdir -p "$TEST/compatdata" "$TEST/logs"

# Everything below runs in one private network namespace. The original assets
# are mounted read-only; only the prepared test directory is writable.
exec flock -n -E 75 "$TEST/runner.lock" bwrap --unshare-user --unshare-net --unshare-pid --die-with-parent \
  --ro-bind / / \
  --tmpfs /opt \
  --tmpfs /tmp \
  --ro-bind "$TEST/hosts" /etc/hosts \
  --ro-bind /tmp/.X11-unix /tmp/.X11-unix \
  --ro-bind "$ASSETS" /opt/swtor-assets \
  --bind "$PROTON_COPY" /opt/private-proton \
  --bind "$TEST" /opt/holocron-test \
  --ro-bind "$ASSETS" /opt/holocron-test/game/Assets \
  --proc /proc --dev-bind /dev /dev \
  --tmpfs /dev/shm \
  /bin/bash -c '
    set -euo pipefail
    mkdir -p /opt/holocron-test/compatdata /opt/holocron-test/logs
    export DOTNET_ROOT="/home/dq/.dotnet"
    export WINEDEBUG="${HOLOCRON_WINEDEBUG:--all,err+all}"
    export STEAM_COMPAT_CLIENT_INSTALL_PATH="/home/dq/snap/steam/common/.local/share/Steam"
    export STEAM_COMPAT_DATA_PATH="/opt/holocron-test/compatdata"
    export WINEPREFIX="/opt/holocron-test/compatdata/pfx"
    export XDG_CACHE_HOME="/opt/holocron-test/cache"
    mkdir -p "$XDG_CACHE_HOME"
    export SteamAppId=1286830 SteamGameId=1286830

    # Read-only bind of assets at the location expected by the executable.
    test -f /opt/holocron-test/game/Assets/swtor_main_area_alderaan_1.tor || test -n "$(ls /opt/holocron-test/game/Assets/*.tor | head -1)"

    "$DOTNET_ROOT/dotnet" /home/dq/project-holocron/src/Holocron.World/bin/Debug/net8.0/Holocron.World.dll > /opt/holocron-test/logs/world.log 2>&1 &
    world=$!
    "$DOTNET_ROOT/dotnet" /home/dq/project-holocron/src/Holocron.Auth/bin/Debug/net8.0/Holocron.Auth.dll --test-key /opt/holocron-test/local-auth-key.pem ${HOLOCRON_AUTH_CAPTURE:+--capture-post-handshake} ${HOLOCRON_AUTH_LOGIN_REPLY:+--probe-login-reply-envelope} > /opt/holocron-test/logs/auth.log 2>&1 &
    auth=$!
    python3 /home/dq/project-holocron/tools/install-private-platform-ca.py --prefix /opt/holocron-test/compatdata/pfx --proton /opt/private-proton/proton --certificate /opt/holocron-test/platform-ca.der > /opt/holocron-test/logs/platform-ca.log 2>&1
    python3 /home/dq/project-holocron/tools/local-platform.py --tls-cert /opt/holocron-test/platform-server-cert.pem --tls-key /opt/holocron-test/platform-server-key.pem --responses /home/dq/project-holocron/tools/fixtures/platform-responses.json > /opt/holocron-test/logs/platform.log 2>&1 &
    platform=$!
    trap "kill $auth $world $platform 2>/dev/null || true" EXIT INT TERM
    sleep 2
    kill -0 "$auth" "$world" "$platform" || {
      echo "A local test service failed to start; inspect auth/world/platform logs." >&2
      exit 1
    }

    if [[ -n "${HOLOCRON_DORMANT_DEBUG:-}" ]]; then
      rm -f /opt/holocron-test/debug-trigger /opt/holocron-test/debug-ready /opt/holocron-test/debug-complete
      /home/dq/project-holocron/tools/dormant-winedbg-helper.sh &
    fi

    cd /opt/holocron-test/game/swtor/retailclient
    /opt/private-proton/proton run reg.exe add "HKCU\SOFTWARE\Broadsword\Star Wars - The Old Republic" /v Token /t REG_SZ /d holocron-local-test-only /f >/opt/holocron-test/logs/token-setup.log 2>&1
    if [[ -n "${HOLOCRON_WINEDBG_GDB:-}" ]]; then
      /opt/private-proton/proton run winedbg.exe --gdb --no-start --port 27979 ./swtor.exe \
        -set server 127.0.0.1 -set port 7979 -set instance 1 \
        -set username local-test -set password not-a-real-password \
        -set token 1AAAAAAAAAAAAAAAAAAAAAA== -set environment swtor -set platform 127.0.0.1:7978 -set lang en-us \
        -set torsets main,en-us -set skipgamemovies true @swtor.icb > /opt/holocron-test/logs/winedbg-proxy.log 2>&1 &
      proxy=$!
      for _ in $(seq 1 80); do
        ss -ltn 2>/dev/null | grep -q ':27979' && break
        sleep 0.25
      done
      ss -ltn 2>/dev/null | grep -q ':27979' || { echo "WineDbg proxy did not listen on 27979." >&2; kill "$proxy" 2>/dev/null || true; exit 1; }
      exec gdb -q -nx -ex "target remote 127.0.0.1:27979"
    elif [[ -n "${HOLOCRON_WINEDBG_TRACE:-}" ]]; then
      /opt/private-proton/proton run winedbg.exe ./swtor.exe \
        -set server 127.0.0.1 -set port 7979 -set instance 1 \
        -set username local-test -set password not-a-real-password \
        -set token 1AAAAAAAAAAAAAAAAAAAAAA== -set environment swtor -set platform 127.0.0.1:7978 -set lang en-us \
        -set torsets main,en-us -set skipgamemovies true @swtor.icb
    elif [[ -n "${HOLOCRON_GDB_PARENT:-}" ]]; then
      # GDB is the direct parent of Proton here.  This is deliberately separate
      # from both the normal runner and the host-attach trace mode.
      exec gdb -q -nx --args /usr/bin/python3 /opt/private-proton/proton run ./swtor.exe \
        -set server 127.0.0.1 -set port 7979 -set instance 1 \
        -set username local-test -set password not-a-real-password \
        -set token 1AAAAAAAAAAAAAAAAAAAAAA== -set environment swtor -set platform 127.0.0.1:7978 -set lang en-us \
        -set torsets main,en-us -set skipgamemovies true @swtor.icb
    elif [[ -n "${HOLOCRON_GDB_INNER:-}" ]]; then
      # Attaching from the host crosses the bubblewrap PID namespace and gives
      # GDB unreliable thread events.  This trace-only branch runs the debugger
      # in that namespace after the private client has started.
      /opt/private-proton/proton run ./swtor.exe \
        -set server 127.0.0.1 -set port 7979 -set instance 1 \
        -set username local-test -set password not-a-real-password \
        -set token 1AAAAAAAAAAAAAAAAAAAAAA== -set environment swtor -set platform 127.0.0.1:7978 -set lang en-us \
        -set torsets main,en-us -set skipgamemovies true @swtor.icb > /opt/holocron-test/logs/client.log 2>&1 &
      client_launcher=$!
      for _ in $(seq 1 120); do
        client_pid=$(pgrep -n -x swtor.exe || true)
        [[ -n "$client_pid" ]] && break
        sleep 0.25
      done
      [[ -n "${client_pid:-}" ]] || { echo "Private client did not start." >&2; exit 1; }
      gdb -q -nx -p "$client_pid"
      wait "$client_launcher" || true
    elif [[ -n "${HOLOCRON_GDB_TRACE:-}" ]]; then
      /opt/private-proton/proton run ./swtor.exe \
        -set server 127.0.0.1 -set port 7979 -set instance 1 \
        -set username local-test -set password not-a-real-password \
        -set token 1AAAAAAAAAAAAAAAAAAAAAA== -set environment swtor -set platform 127.0.0.1:7978 -set lang en-us \
        -set torsets main,en-us -set skipgamemovies true @swtor.icb 2>&1 | tee /opt/holocron-test/logs/client.log
    else
      /opt/private-proton/proton run ./swtor.exe \
      -set server 127.0.0.1 -set port 7979 -set instance 1 \
      -set username local-test -set password not-a-real-password \
      -set token 1AAAAAAAAAAAAAAAAAAAAAA== -set environment swtor -set platform 127.0.0.1:7978 -set lang en-us \
      -set torsets main,en-us -set skipgamemovies true @swtor.icb 2>&1 | tee /opt/holocron-test/logs/client.log
    fi
  '
