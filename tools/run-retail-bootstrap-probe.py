#!/usr/bin/env python3
"""Canonical retail bootstrap reproduction entrypoint.

Why this wrapper exists
-----------------------
The isolated runtime lives in a network namespace that contains only ``lo``.
The retail client's TCP hint builder sets ``AI_ADDRCONFIG`` (``0x400``) at
RVA ``0x4507C9``, and in that namespace the flag makes ``getaddrinfo`` reject
every IPv4 result -- including ``127.0.0.1``. The client then never opens an
Auth socket and fails at ``0x140427F10`` on a missing ``[ServerProxy+0x80]``.

That is an **environment artifact**, not the historical protocol boundary.
Every known-good bootstrap run therefore cleared exactly that one immediate:

    0x4507C9:  c7 06 00 04 00 00   (mov dword ptr [rsi], 0x400)
            -> c7 06 00 00 00 00   (mov dword ptr [rsi], 0)

This script is the single supported way to do that. It:

* operates only on the prepared private client under ``.local-test/``;
* refuses an unrecognized executable build (hash + byte assertion);
* patches only that one immediate, and nothing else;
* restores the original bytes in a ``finally`` path, unconditionally;
* verifies the restoration is byte-for-byte, and exits non-zero if it is not;
* never touches the Steam installation;
* sanitizes every ``HOLOCRON_*`` mode variable it knows about before setting the
  modes this invocation actually asked for.

Mode-variable sanitization
--------------------------
The launcher and the dormant/attach helpers select their execution path from
environment variables. A value exported in the calling shell would otherwise
silently change this script's run (for example an inherited
``HOLOCRON_AUTH_ID_BOOTSTRAP=1`` would defeat ``--no-bootstrap-probe``, and an
inherited ``HOLOCRON_GDB_TRACE=1`` would replace the normal client launch with a
debug trace). ``sanitize_mode_environment`` clears that whole family first, and
only then does ``main`` set the flags selected by the command line.

Time bounds
-----------
The isolated launcher has no time limit of its own: it runs the client until the
client exits. ``--seconds`` is therefore the **wrapper's** bound on how long the
launcher may run before this script terminates it, plus a fixed grace period for
shutdown. No time-limit value is passed into the launcher.

Usage
-----
    python3 tools/run-retail-bootstrap-probe.py                 # bounded run
    python3 tools/run-retail-bootstrap-probe.py --seconds 300   # longer window
    python3 tools/run-retail-bootstrap-probe.py --winedbg-gdb   # attach a debugger
    python3 tools/run-retail-bootstrap-probe.py --dry-run       # checks only

Reverse-engineering runs that need scripted instrumentation pass ``--launcher``
plus ``--env``/``--mode-env`` so that the canonical patch/restore path and the
mode-variable sanitization still apply:

    python3 tools/run-retail-bootstrap-probe.py \
        --launcher scratch/<run>/witness-launcher.sh \
        --env WITNESS_GDB_SCRIPT=scratch/<run>/witness.gdb \
        --env WITNESS_RUN_DIR=scratch/<run>/out
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import signal
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEST = ROOT / '.local-test' / 'client-v1'
EXE = TEST / 'game' / 'swtor' / 'retailclient' / 'swtor.exe'
LAUNCHER = ROOT / 'tools' / 'launch-isolated-client.sh'

# The private client is the retail executable with only the 256-byte RSA test-key
# region substituted (file offsets 0x1AB50D1-0x1AB51D0).
EXPECTED_CLIENT_SHA256 = '47d8c8f03242606819fe7afe711bfd8186e83811a178613a89f944ccb1ac4f14'

RVA = 0x4507C9
INSTRUCTION_LENGTH = 6
ORIGINAL = bytes.fromhex('c70600040000')
PATCHED = bytes.fromhex('c70600000000')
FILE_OFFSET = RVA - 0x1000 + 0x400  # .text RVA -> file offset

# Every environment variable that can steer the launcher (or a helper it starts)
# onto a different execution path. Clearing all of them is what makes a run
# reproducible when the calling shell is not pristine.
MODE_ENVIRONMENT_VARIABLES = (
    # Auth-server behaviour. HOLOCRON_AUTH_LOGIN_REPLY selects the
    # HISTORICAL/INVALID direct-D4 probe, which answers RequestIDSignature
    # (0xA609E6A7) with D4 and bypasses the proven identification exchange.
    'HOLOCRON_AUTH_CAPTURE',
    'HOLOCRON_AUTH_LOGIN_REPLY',
    'HOLOCRON_AUTH_ID_BOOTSTRAP',
    # Debugger / tracing modes. These are mutually exclusive branches in
    # tools/launch-isolated-client.sh; any inherited value pre-empts the normal
    # client launch.
    'HOLOCRON_WINEDBG_GDB',
    'HOLOCRON_WINEDBG_TRACE',
    'HOLOCRON_GDB_PARENT',
    'HOLOCRON_GDB_INNER',
    'HOLOCRON_GDB_TRACE',
    'HOLOCRON_DORMANT_DEBUG',
)

# Fixed grace period added to --seconds before the wrapper force-terminates the
# launcher. The launcher itself is given no time limit.
SHUTDOWN_GRACE_SECONDS = 120.0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_mode_environment(environ: dict) -> list:
    """Clear every mode-changing Holocron variable, returning the cleared names.

    Mutates ``environ`` in place. Called before this invocation sets the flags it
    actually wants, so an inherited value can never select a different path.
    """
    cleared = []
    for name in MODE_ENVIRONMENT_VARIABLES:
        if environ.pop(name, None) is not None:
            cleared.append(name)
    return cleared


def launcher_deadline_seconds(seconds: float, grace: float = SHUTDOWN_GRACE_SECONDS) -> float:
    """Seconds this wrapper waits for the launcher before terminating it."""
    return seconds + grace


def fail(message: str) -> None:
    print(f'[bootstrap] ERROR: {message}', file=sys.stderr)
    raise SystemExit(2)


def load_and_verify_client() -> bytes:
    if not EXE.is_file():
        fail(f'prepared private client not found: {EXE}')
    original = EXE.read_bytes()

    digest = sha256(original)
    if digest != EXPECTED_CLIENT_SHA256:
        fail(
            'unrecognized private client build; refusing to patch.\n'
            f'  expected sha256 {EXPECTED_CLIENT_SHA256}\n'
            f'  actual   sha256 {digest}\n'
            'Re-run tools/prepare-local-client.py, or update this script after '
            're-verifying the resolver instruction offset.'
        )

    actual = original[FILE_OFFSET:FILE_OFFSET + INSTRUCTION_LENGTH]
    if actual != ORIGINAL:
        fail(
            'resolver immediate is not in the expected state; refusing to patch.\n'
            f'  at file offset {FILE_OFFSET:#x} (RVA {RVA:#x})\n'
            f'  expected {ORIGINAL.hex()}\n'
            f'  actual   {actual.hex()}\n'
            'The client may still be patched from an interrupted run.'
        )
    return original


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--seconds', type=float, default=240.0,
                        help='how long the wrapper lets the launcher run before '
                             'terminating it (default 240; the launcher has no '
                             'time limit of its own and this value is not passed '
                             'to it)')
    parser.add_argument('--winedbg-gdb', action='store_true',
                        help='start the WineDbg GDB proxy (port 27979) instead of a normal run')
    parser.add_argument('--winedbg-trace', action='store_true',
                        help='run the client directly under winedbg')
    parser.add_argument('--no-bootstrap-probe', action='store_true',
                        help='do not pass --probe-id-bootstrap to the auth server')
    parser.add_argument('--launcher', default=None, metavar='PATH',
                        help='override the isolated launcher, e.g. a scripted GDB '
                             'witness launcher. The client verification, the '
                             'single AI_ADDRCONFIG patch, the mode-variable '
                             'sanitization and the byte-exact restore all still '
                             'apply, so instrumentation never bypasses the '
                             'canonical patch/restore path. The named script is '
                             'responsible for providing the isolated runtime.')
    parser.add_argument('--env', action='append', default=[], metavar='NAME=VALUE',
                        help='export an extra variable into the launcher (repeatable). '
                             'Applied after sanitization, so it cannot silently '
                             're-enable a mode variable: use --mode-env for those.')
    parser.add_argument('--mode-env', action='append', default=[], metavar='NAME=VALUE',
                        help='set a mode variable explicitly (repeatable); the name '
                             'must be one of the known mode variables')
    parser.add_argument('--dry-run', action='store_true',
                        help='verify the client and environment, then exit without running')
    args = parser.parse_args()

    launcher = pathlib.Path(args.launcher).resolve() if args.launcher else LAUNCHER
    if not launcher.is_file():
        fail(f'launcher not found: {launcher}')

    original = load_and_verify_client()
    print(f'[bootstrap] private client sha256 {sha256(original)}')
    print(f'[bootstrap] resolver immediate at file offset {FILE_OFFSET:#x} is {ORIGINAL.hex()}')

    if args.dry_run:
        print('[bootstrap] dry run: client and launcher verified; nothing executed.')
        return 0

    env = dict(os.environ)
    cleared = sanitize_mode_environment(env)
    if cleared:
        print('[bootstrap] cleared inherited mode variables: ' + ', '.join(cleared))
    # Only now select the modes this invocation asked for.
    if not args.no_bootstrap_probe:
        env['HOLOCRON_AUTH_ID_BOOTSTRAP'] = '1'
    if args.winedbg_gdb:
        env['HOLOCRON_WINEDBG_GDB'] = '1'
    if args.winedbg_trace:
        env['HOLOCRON_WINEDBG_TRACE'] = '1'
    for assignment in args.mode_env:
        name, _, value = assignment.partition('=')
        if name not in MODE_ENVIRONMENT_VARIABLES:
            fail(f'--mode-env {name} is not a known mode variable')
        env[name] = value
    for assignment in args.env:
        name, _, value = assignment.partition('=')
        if not name or not _:
            fail(f'--env expects NAME=VALUE, got {assignment!r}')
        if name in MODE_ENVIRONMENT_VARIABLES:
            fail(f'--env {name} is a mode variable; use --mode-env instead')
        env[name] = value
    print(f'[bootstrap] launcher {launcher}')

    process = None
    restored_ok = False
    started = time.monotonic()
    try:
        patched = bytearray(original)
        patched[FILE_OFFSET:FILE_OFFSET + INSTRUCTION_LENGTH] = PATCHED
        EXE.write_bytes(patched)
        print('[bootstrap] AI_ADDRCONFIG cleared (0x400 -> 0) for this bounded run')

        process = subprocess.Popen([str(launcher)], env=env, start_new_session=True)
        try:
            process.wait(timeout=launcher_deadline_seconds(args.seconds))
        except subprocess.TimeoutExpired:
            print('[bootstrap] launcher exceeded its window; terminating')
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
            except Exception:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=15)
                except Exception:
                    pass

        # Canonical runs always restore the private executable. There is no
        # supported "leave the patch applied" mode.
        EXE.write_bytes(original)
        after = sha256(EXE.read_bytes())
        if after != sha256(original):
            fail('client was NOT restored byte-exactly; investigate immediately')
        restored_ok = True
        print(f'[bootstrap] client restored byte-exactly (sha256 {after})')

    print(f'[bootstrap] elapsed {time.monotonic() - started:.1f}s')
    if restored_ok:
        auth_log = TEST / 'logs' / 'auth.log'
        if auth_log.is_file():
            print(f'[bootstrap] auth log: {auth_log}')
            print('[bootstrap] expected success shape: RequestIDSignature -> '
                  'ReplyIDSignature -> IntroduceConnectionSignature -> Close 0x43DB3479')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
