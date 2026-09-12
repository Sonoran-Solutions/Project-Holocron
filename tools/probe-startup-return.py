#!/usr/bin/env python3
"""Temporarily label a failure return in the private client; restore in finally.

Changes only -1 to -101 on the failed platform-initialization branch. It does
not change the branch or make a failed check pass. Never targets Steam files.
"""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
exe = root / '.local-test/client-v1/game/swtor/retailclient/swtor.exe'
original = exe.read_bytes()
patched = bytearray(original)
label_token = '--label-token-error' in sys.argv
if label_token:
    for address, label in [(0xBDAA9, 42), (0xBE4DD, 43), (0xCFB02, 44)]:
        offset = address - 0xC00
        assert original[offset:offset+5] == bytes.fromhex('b902000000')
        patched[offset+1:offset+5] = label.to_bytes(4, 'little')
else:
    offset = 0xD03FB - 0xC00
    assert original[offset:offset+6] == bytes.fromhex('41bfffffffff')
    patched[offset+2:offset+6] = (-101).to_bytes(4, 'little', signed=True)
try:
    exe.write_bytes(patched)
    command = ['bash', str(root / 'tools/capture-isolated-dialog.sh')] if label_token else [
        'timeout', '--signal=TERM', '--kill-after=5s', '25s', str(root / 'tools/launch-isolated-client.sh')]
    result = subprocess.run(command,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('Runner exit status:', result.returncode)
    print('155 identifies failed platform initialization; 255 indicates another -1 return.')
finally:
    exe.write_bytes(original)
    print('Restored original test executable bytes.')
