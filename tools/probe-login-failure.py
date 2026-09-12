#!/usr/bin/env python3
"""Label the three synchronous login failures in the private client, then restore.

No conditional branch is changed and no failed check is bypassed. Labels:
6101 address resolution, 6102 connection construction, 6103 transport setup.
"""
import fcntl
from pathlib import Path
import signal
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / '.local-test/client-v1'
EXE = TEST / 'game/swtor/retailclient/swtor.exe'


def main():
    with (TEST / 'diagnostic.lock').open('a') as diagnostic_lock:
        fcntl.flock(diagnostic_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (TEST / 'runner.lock').open('a') as runner_lock:
            fcntl.flock(runner_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original = EXE.read_bytes()
            patched = bytearray(original)
            for rva, expected, label in (
                (0x42804A, 'c74570eb030000', 6101),
                (0x4280D5, 'c74578eb030000', 6102),
                (0x4280F8, 'c78580000000eb030000', 6103),
            ):
                offset = rva - 0xC00
                instruction = bytes.fromhex(expected)
                if original[offset:offset + len(instruction)] != instruction:
                    raise SystemExit('Unexpected private executable bytes; refusing diagnostic.')
                patched[offset + len(instruction) - 4:offset + len(instruction)] = label.to_bytes(4, 'little')
            # Keep a recoverable copy if this process is forcibly killed.
            backup = TEST / 'login-diagnostic-original.exe'
            with backup.open('xb') as stream:
                stream.write(original)
            EXE.write_bytes(patched)

        def interrupted(*_):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, interrupted)
        process = None
        try:
            print('Failure labels: 6101 address, 6102 connection, 6103 transport setup.', flush=True)
            process = subprocess.Popen(
                ['timeout', '--signal=TERM', '--kill-after=5s', '600s', str(ROOT / 'tools/launch-isolated-client.sh')],
                start_new_session=True)
            process.wait()
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # timeout's own kill-after guard normally handles this.
                    process.kill()
                    process.wait()
            EXE.write_bytes(original)
            backup.unlink()
            print('Restored private executable; no failure-label patch remains.', flush=True)


if __name__ == '__main__':
    main()
