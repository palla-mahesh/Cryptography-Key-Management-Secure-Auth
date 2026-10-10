"""Command-line interface for CryptoGuard."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from cryptoguard.crypto import (
    decrypt_file, encrypt_file, generate_rsa_keypair, hmac_sha256,
    load_private_key, load_public_key, password_hash, password_verify,
    sign_data, verify_signature,
)
from cryptoguard.key_manager import LocalKeyManager


def read_passphrase(password_file: str | None) -> bytes:
    if password_file:
        value = Path(password_file).read_text(encoding="utf-8").splitlines()[0]
    else:
        value = getpass.getpass("Private-key passphrase: ")
    if not value:
        raise ValueError("Passphrase must not be empty")
    return value.encode("utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cryptoguard", description="Cryptography and secure-authentication toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate-rsa", help="Generate an encrypted RSA-2048 key pair")
    p.add_argument("--private-key", default="private.pem")
    p.add_argument("--public-key", default="public.pem")
    p.add_argument("--password-file", help="Passphrase file; protect it with chmod 600")

    for name, fn in (("encrypt-file", encrypt_file), ("decrypt-file", decrypt_file)):
        p = sub.add_parser(name, help=f"{name.replace('-', ' ').title()} using AES-256-GCM")
        p.add_argument("--key-file", required=True)
        p.add_argument("--input", required=True)
        p.add_argument("--output", required=True)

    p = sub.add_parser("sign-file", help="Sign a file with RSA-PSS/SHA-256")
    p.add_argument("--private-key", required=True)
    p.add_argument("--password-file")
    p.add_argument("--input", required=True)
    p.add_argument("--signature", required=True)

    p = sub.add_parser("verify-file", help="Verify an RSA-PSS/SHA-256 signature")
    p.add_argument("--public-key", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--signature", required=True)

    sub.add_parser("hash-password", help="Create a bcrypt password hash")
    sub.add_parser("verify-password", help="Verify a password against a bcrypt hash")

    p = sub.add_parser("hmac", help="Calculate HMAC-SHA-256 for a file")
    p.add_argument("--key-file", required=True)
    p.add_argument("--input", required=True)

    p = sub.add_parser("rotate-key", help="Create a new versioned local AES key")
    p.add_argument("--store", default="keys/key-store.json")

    args = parser.parse_args(argv)
    try:
        if args.command == "generate-rsa":
            passphrase = read_passphrase(args.password_file)
            generate_rsa_keypair(args.private_key, args.public_key, passphrase)
            print(f"RSA key pair created: {args.private_key}, {args.public_key}")
        elif args.command in ("encrypt-file", "decrypt-file", "hmac"):
            key_hex = Path(args.key_file).read_text(encoding="utf-8").strip()
            key = bytes.fromhex(key_hex)
            if len(key) != 32:
                raise ValueError("Key file must contain exactly 64 hexadecimal characters")
            if args.command == "encrypt-file":
                encrypt_file(args.input, args.output, key)
                print(f"Encrypted file written to {args.output}")
            elif args.command == "decrypt-file":
                decrypt_file(args.input, args.output, key)
                print(f"Decrypted file written to {args.output}")
            else:
                print(hmac_sha256(Path(args.input).read_bytes(), key))
        elif args.command == "sign-file":
            private = load_private_key(args.private_key, read_passphrase(args.password_file))
            signature = sign_data(Path(args.input).read_bytes(), private)
            Path(args.signature).write_bytes(signature)
            try:
                os.chmod(args.signature, 0o600)
            except OSError:
                pass
            print(f"Signature written to {args.signature}")
        elif args.command == "verify-file":
            public = load_public_key(args.public_key)
            ok = verify_signature(Path(args.input).read_bytes(), Path(args.signature).read_bytes(), public)
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1
        elif args.command == "hash-password":
            password = getpass.getpass("Password to hash: ")
            confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                raise ValueError("Passwords do not match")
            print(password_hash(password).decode("utf-8"))
        elif args.command == "verify-password":
            password = getpass.getpass("Password to verify: ")
            stored = input("Paste stored bcrypt hash: ").strip()
            print("MATCH" if password_verify(password, stored) else "NO MATCH")
            return 0 if password_verify(password, stored) else 1
        elif args.command == "rotate-key":
            manager = LocalKeyManager(args.store)
            version = manager.rotate()
            print(f"Created key version {version}; active version is now {version}. Store: {args.store}")
            print("Protect this file: it contains plaintext key material.")
        return 0
    except (ValueError, OSError, IndexError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
