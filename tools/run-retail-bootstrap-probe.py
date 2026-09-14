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
* restores the original bytes in a ``finally`` path;
* verifies the restoration is byte-for-byte, and exits non-zero if it is not;
* never touches the Steam installation.

Expected success shape (see ``docs/CURRENT-RETAIL-STATE.md``): the Auth log
shows RequestIDSignature -> ReplyIDSignature -> IntroduceConnectionSignature ->
Close 0x43DB3479.

Usage
-----
    python3 tools/run-retail-bootstrap-probe.py                 # bounded run
    python3 tools/run-retail-bootstrap-probe.py --seconds 300   # longer window
    python3 tools/run-retail-bootstrap-probe.py --winedbg-gdb   # attach a debugger
    python3 tools/run-retail-bootstrap-probe.py --dry-run       # checks only
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


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
                        help='bounded run length passed to the launcher (default 240)')
    parser.add_argument('--winedbg-gdb', action='store_true',
                        help='start the WineDbg GDB proxy (port 27979) instead of a normal run')
    parser.add_argument('--winedbg-trace', action='store_true',
                        help='run the client directly under winedbg')
    parser.add_argument('--no-bootstrap-probe', action='store_true',
                        help='do not pass --probe-id-bootstrap to the auth server')
    parser.add_argument('--keep-patched', action='store_true',
                        help='DANGEROUS: leave the resolver patch applied (debugging only)')
    parser.add_argument('--dry-run', action='store_true',
                        help='verify the client and environment, then exit without running')
    args = parser.parse_args()

    if not LAUNCHER.is_file():
        fail(f'launcher not found: {LAUNCHER}')

    original = load_and_verify_client()
    print(f'[bootstrap] private client sha256 {sha256(original)}')
    print(f'[bootstrap] resolver immediate at file offset {FILE_OFFSET:#x} is {ORIGINAL.hex()}')

    if args.dry_run:
        print('[bootstrap] dry run: client and launcher verified; nothing executed.')
        return 0

    env = dict(os.environ)
    env['HOLOCRON_RUN_SECONDS'] = str(int(args.seconds))
    env.pop('HOLOCRON_AUTH_CAPTURE', None)
    # The canonical bootstrap probe. HOLOCRON_AUTH_LOGIN_REPLY selects the
    # HISTORICAL/INVALID direct-D4 flow and must not be set here.
    env.pop('HOLOCRON_AUTH_LOGIN_REPLY', None)
    if not args.no_bootstrap_probe:
        env['HOLOCRON_AUTH_ID_BOOTSTRAP'] = '1'
    if args.winedbg_gdb:
        env['HOLOCRON_WINEDBG_GDB'] = '1'
    if args.winedbg_trace:
        env['HOLOCRON_WINEDBG_TRACE'] = '1'

    process = None
    restored_ok = False
    try:
        patched = bytearray(original)
        patched[FILE_OFFSET:FILE_OFFSET + INSTRUCTION_LENGTH] = PATCHED
        EXE.write_bytes(patched)
        print('[bootstrap] AI_ADDRCONFIG cleared (0x400 -> 0) for this bounded run')

        started = time.monotonic()
        process = subprocess.Popen([str(LAUNCHER)], env=env, start_new_session=True)
        try:
            process.wait(timeout=args.seconds + 120)
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

        if args.keep_patched:
            print('[bootstrap] WARNING: --keep-patched set; resolver patch left applied')
        else:
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
