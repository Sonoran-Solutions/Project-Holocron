#!/usr/bin/env python3
"""Test loopback-only name resolution in the copied client, then restore it.

The retail TCP hint builder sets AI_ADDRCONFIG. A network namespace containing
only `lo` makes that flag reject every IPv4 result, including 127.0.0.1. This
changes only the copied client's hint from 0x400 to 0 for one bounded test.
It does not target or modify the Steam installation.  Pass ``--manual`` for a
user-synchronized run: no timer is armed and the patch remains active until
the private client exits.
"""
import fcntl
from pathlib import Path
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / '.local-test/client-v1'
EXE = TEST / 'game/swtor/retailclient/swtor.exe'
RVA = 0x4507C9
ORIGINAL = bytes.fromhex('c70600040000')
PATCHED = bytes.fromhex('c70600000000')


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != '--manual'):
        raise SystemExit('Usage: probe-loopback-resolver.py [--manual]')
    manual = len(sys.argv) == 2
    with (TEST / 'runner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original_file = EXE.read_bytes()
        offset = RVA - 0xC00
        if original_file[offset:offset + len(ORIGINAL)] != ORIGINAL:
            raise SystemExit('Unexpected copied-client bytes; refusing patch.')
        modified = bytearray(original_file)
        modified[offset:offset + len(PATCHED)] = PATCHED
        EXE.write_bytes(modified)

    process = None
    try:
        print('Private client: AI_ADDRCONFIG temporarily disabled for loopback probe.', flush=True)
        command = [str(ROOT / 'tools/launch-isolated-client.sh')]
        if not manual:
            command = ['timeout', '--signal=TERM', '--kill-after=5s', '600s', *command]
        print(
            'Manual user-synchronized run: no timeout is armed.' if manual
            else 'Bounded run: 600-second timeout is armed.',
            flush=True)
        process = subprocess.Popen(command, start_new_session=True)
        process.wait()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        EXE.write_bytes(original_file)
        print('Restored private-client resolver bytes.', flush=True)


if __name__ == '__main__':
    main()
