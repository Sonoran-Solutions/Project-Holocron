#!/usr/bin/env python3
"""Read-only verification for the documented retail binary; prints no key material.

Requires cryptography. Usage: python3 tools/inspect-retail-key.py /path/to/swtor.exe
"""
import argparse
import base64
import hashlib
from pathlib import Path
import re

from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    binary = args.executable.read_bytes()
    fingerprint = hashlib.sha256(binary).hexdigest()
    expected = "ad541a742a62500c2095f87c3cff116def462ebd26d1de95de32bc7293eb596b"
    if fingerprint != expected:
        parser.error("Unrecognized executable fingerprint; offsets must be re-analyzed.")
    offset = 0x1AB50B0
    # Handshake assigns this inverted SubjectPublicKeyInfo at VA 0x14043e339.
    der = bytes(value ^ 255 for value in binary[offset:offset + 0x124])
    public = load_der_public_key(der)
    source = (Path(__file__).resolve().parents[1] /
              "src/Holocron.Common/Crypto/SwtorLoginKeyExchange.cs").read_text()
    match = re.search(r'"(MII[^\"]+)"', source)
    if match is None:
        parser.error("Historical emulator key constant not found.")
    historical = load_der_private_key(base64.b64decode(match[1]), password=None)
    print("Executable SHA-256:", fingerprint)
    print("Public-key DER SHA-256:", hashlib.sha256(der).hexdigest())
    print("RSA bits:", public.key_size)
    print("Public exponent:", public.public_numbers().e)
    print("Matches historical emulator key:",
          public.public_numbers() == historical.public_key().public_numbers())


if __name__ == "__main__":
    main()
