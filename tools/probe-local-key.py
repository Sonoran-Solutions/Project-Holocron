#!/usr/bin/env python3
"""Synthetic loopback handshake using the public key from the prepared executable.

Starts and stops only its own handshake-only server. No real credentials, game
launch, saved accounts, payload logging, or official connections are used.
"""
import argparse
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("test_directory", type=Path)
    parser.add_argument("--dotnet", required=True)
    args = parser.parse_args()
    manifest = json.loads((args.test_directory / "manifest.json").read_text())
    binary = (Path(manifest["runtime"]) / "swtor.exe").read_bytes()
    import hashlib
    if hashlib.sha256(binary).hexdigest() != manifest["test_executable_sha256"]:
        parser.error("Prepared executable fingerprint mismatch.")
    offset, length = manifest["key_offset"], manifest["key_length"]
    public = serialization.load_der_public_key(bytes(b ^ 255 for b in binary[offset:offset + length]))
    # Refuse to send even dummy data to an unrelated service already on this port.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 7979))
    assembly = Path(__file__).resolve().parents[1] / "src/Holocron.Auth/bin/Debug/net8.0/Holocron.Auth.dll"
    process = subprocess.Popen([
        args.dotnet, str(assembly), "--test-key", manifest["private_key"],
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for attempt in range(100):
            if process.poll() is not None:
                raise RuntimeError("Probe server exited before accepting a connection.")
            try:
                client = socket.create_connection(("127.0.0.1", 7979), timeout=1)
                break
            except ConnectionRefusedError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Probe server did not start.")
        with client:
            client.settimeout(5)
            greeting = bytearray()
            while len(greeting) < 22:
                part = client.recv(22 - len(greeting))
                if not part:
                    raise RuntimeError("Truncated greeting.")
                greeting.extend(part)
            if greeting[:14] != bytes.fromhex("0316000000151200000008000000"):
                raise RuntimeError("Unexpected greeting.")
            clear = bytearray()
            for value in (b"holocron-local-test", b"synthetic-not-an-account-token"):
                clear.extend(struct.pack("<I", len(value)) + value)
            clear.extend(secrets.token_bytes(80))
            ciphertext = b"".join(public.encrypt(bytes(clear[i:i+245]).ljust(245, b"\0"),
                                                  padding.PKCS1v15())
                                  for i in range(0, len(clear), 245))
            payload = struct.pack("<I", len(clear)) + ciphertext.hex().upper().encode("ascii")
            header = bytes([4]) + struct.pack("<I", len(payload) + 6)
            checksum = 0
            for value in header:
                checksum ^= value
            client.sendall(header + bytes([checksum]) + payload)
            if client.recv(1) != b"":
                raise RuntimeError("Handshake-only server unexpectedly sent application data.")
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
    if "Handshake-only probe complete" not in output:
        raise RuntimeError("Handshake validation failed; no raw server output or payload is printed.")
    print("PASS: prepared executable public key -> local auth private key -> parsed synthetic handshake.")
    print("No game launched. Retail key-field layout and game interoperability remain unverified.")


if __name__ == "__main__":
    main()
