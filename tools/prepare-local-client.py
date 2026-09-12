#!/usr/bin/env python3
"""Prepare a separate, non-launching SWTOR client with an ephemeral local RSA key.

No source files, Steam prefix, hosts entries or network settings are modified.
Requires openssl and Python cryptography. The destination must not already exist.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from cryptography.hazmat.primitives import serialization

EXPECTED_SHA256 = "ad541a742a62500c2095f87c3cff116def462ebd26d1de95de32bc7293eb596b"
KEY_OFFSET = 0x1AB50B0
KEY_LENGTH = 0x124


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original retailclient directory")
    parser.add_argument("destination", type=Path, help="New private test directory")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    destination = args.destination.absolute()
    if destination.exists() or destination.is_symlink():
        parser.error("Destination already exists; refusing to overwrite it.")
    if source == destination or source in destination.parents:
        parser.error("Destination must be outside the original installation.")
    original = (source / "swtor.exe").read_bytes()
    if sha256(original) != EXPECTED_SHA256:
        parser.error("Unrecognized executable; re-analyze key offsets before modifying a copy.")
    original_der = bytes(b ^ 255 for b in original[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH])
    serialization.load_der_public_key(original_der)  # Validate the expected key region.
    os.umask(0o077)
    destination.mkdir(parents=True, mode=0o700)
    private_path = destination / "local-auth-key.pem"
    # Exponent 17 preserves the original 292-byte public-key encoding size.
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-pkeyopt", "rsa_keygen_pubexp:17", "-out", str(private_path),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    test_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if len(test_der) != KEY_LENGTH or test_der == original_der:
        raise RuntimeError("Generated test key is not a valid same-size replacement.")

    runtime = destination / "game" / "swtor" / "retailclient"
    runtime.mkdir(parents=True)
    # Only runtime files; do not copy saved accounts, logs, launcher, Steam DLL,
    # bootstrap backups, or the user's existing Proton prefix.
    allowed_names = {"swtor.exe", "main_gfx_1.tor", "client_defaults.ini",
                     "RemoteRendererServer.icb"}
    for item in source.iterdir():
        if item.is_symlink():
            continue
        if item.is_file() and (item.name in allowed_names or item.suffix.lower() == ".dll"):
            shutil.copyfile(item, runtime / item.name)
        elif item.is_dir() and item.name in {"LoadingScreens", "shaders", "swtor"}:
            shutil.copytree(item, runtime / item.name, copy_function=shutil.copyfile)
    for name in ("swtor.icb", "swtor_dual.icb"):
        bootstrap = (source / name).read_text()
        bootstrap, count = re.subn(r"(?m)^set shardaddress[^\r\n]*", "set shardaddress @::",
                                   bootstrap)
        if count != 1:
            raise RuntimeError("Unexpected bootstrap; refusing to guess its structure.")
        (runtime / name).write_text(bootstrap)
    (runtime / "steam_appid.txt").write_text("1286830\n")

    patched = bytearray(original)
    patched[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH] = bytes(b ^ 255 for b in test_der)
    executable = runtime / "swtor.exe"
    executable.write_bytes(patched)
    executable.chmod(0o700)
    if (source / "swtor.exe").read_bytes() != original:
        raise RuntimeError("Original executable changed during preparation; investigate before testing.")
    # Assert the whole binary outside the key region is byte-for-byte identical.
    assert patched[:KEY_OFFSET] == original[:KEY_OFFSET]
    assert patched[KEY_OFFSET + KEY_LENGTH:] == original[KEY_OFFSET + KEY_LENGTH:]
    assert serialization.load_der_public_key(bytes(
        b ^ 255 for b in executable.read_bytes()[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
    )).public_numbers() == private.public_key().public_numbers()
    (destination / "compatdata").mkdir()
    manifest = {
        "source_executable": str(source / "swtor.exe"),
        "source_sha256": EXPECTED_SHA256,
        "test_executable_sha256": sha256(patched),
        "test_public_key_sha256": sha256(test_der),
        "key_offset": KEY_OFFSET, "key_length": KEY_LENGTH,
        "runtime": str(runtime), "private_key": str(private_path),
        "source_assets": str(source.parent.parent / "Assets"),
        "network_isolation_required": True,
        "assets_not_copied": True,
        "status": "prepared-not-launched",
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Prepared isolated runtime:", runtime)
    print("Verified matching test key and unchanged source executable.")
    print("Not launched. Network isolation and read-only asset mounting are required.")


if __name__ == "__main__":
    main()
