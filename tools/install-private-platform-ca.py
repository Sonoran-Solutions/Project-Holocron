#!/usr/bin/env python3
"""Install one test CA into an explicitly supplied *private* Wine prefix.

The caller supplies a Proton executable and a prefix that must reside below the
local test directory. It never touches the host/system certificate store.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys


def certificate_blob(der: bytes) -> bytes:
    thumbprint = hashlib.sha1(der).digest()
    return (b'\x03\0\0\0\x01\0\0\0\x14\0\0\0' + thumbprint +
            b'\x20\0\0\0\x01\0\0\0' + len(der).to_bytes(4, 'little') + der)


def add_to_store(proton: Path, key: str, thumbprint: str, blob: bytes) -> None:
    command = [str(proton), 'run', 'reg.exe', 'add', key + '\\' + thumbprint,
               '/v', 'Blob', '/t', 'REG_BINARY', '/d', blob.hex(), '/f']
    completed = subprocess.run(command, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
    if completed.returncode:
        raise RuntimeError(f'private-prefix registry import failed ({completed.returncode})')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--proton', type=Path, required=True)
    parser.add_argument('--certificate', type=Path, required=True)
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    certificate = args.certificate.resolve()
    # The caller should never accidentally point this helper at a Steam prefix.
    expected = Path('/opt/holocron-test/compatdata/pfx')
    if prefix != expected or not certificate.is_file() or not args.proton.is_file():
        raise SystemExit('Refusing: expected the isolated test prefix and a readable test CA.')
    der = certificate.read_bytes()
    if not der.startswith(b'0'):
        raise SystemExit('Expected DER-encoded CA certificate.')
    thumbprint = hashlib.sha1(der).hexdigest().upper()
    blob = certificate_blob(der)
    add_to_store(args.proton, r'HKLM\Software\Microsoft\SystemCertificates\Root\Certificates', thumbprint, blob)
    add_to_store(args.proton, r'HKCU\Software\Microsoft\SystemCertificates\Root\Certificates', thumbprint, blob)
    print(f'Installed private test CA {thumbprint} into the isolated Wine prefix only.')


if __name__ == '__main__':
    main()
