"""Core cryptographic functions for CryptoGuard."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Union

import bcrypt
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BytesLike = Union[bytes, bytearray]


def _read_key_hex(path: str | Path, expected_bytes: int = 32) -> bytes:
    try:
        key = bytes.fromhex(Path(path).read_text(encoding="utf-8").strip())
    except (ValueError, OSError) as exc:
        raise ValueError(f"Could not read a valid hexadecimal key from {path}") from exc
    if len(key) != expected_bytes:
        raise ValueError(f"Key must be exactly {expected_bytes} bytes ({expected_bytes * 2} hex characters)")
    return key


def aes_gcm_encrypt(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """Return a versioned envelope: magic + 12-byte nonce + AES-GCM ciphertext/tag."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return b"CGUA1" + nonce + ciphertext


def aes_gcm_decrypt(envelope: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    if len(envelope) < 5 + 12 + 16 or envelope[:5] != b"CGUA1":
        raise ValueError("Invalid or unsupported CryptoGuard encrypted envelope")
    nonce, ciphertext = envelope[5:17], envelope[17:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise ValueError("Decryption failed: wrong key or encrypted data was modified") from exc


def generate_rsa_keypair(private_path: str | Path, public_path: str | Path,
                         passphrase: bytes, key_size: int = 2048) -> None:
    if not passphrase:
        raise ValueError("A non-empty private-key passphrase is required")
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_path).write_bytes(encrypted_pem)
    Path(public_path).write_bytes(public_pem)
    try:
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
    except OSError:
        pass


def load_private_key(path: str | Path, passphrase: bytes):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)


def load_public_key(path: str | Path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def sign_data(data: bytes, private_key) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def password_hash(password: str, rounds: int = 12) -> bytes:
    if not password:
        raise ValueError("Password must not be empty")
    if not 10 <= rounds <= 16:
        raise ValueError("bcrypt rounds must be between 10 and 16")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))


def password_verify(password: str, stored_hash: bytes | str) -> bool:
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except (ValueError, TypeError):
        return False


def hmac_sha256(data: bytes, key: bytes) -> str:
    if len(key) < 32:
        raise ValueError("Use an HMAC key of at least 32 bytes")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, key: bytes, expected_hex: str) -> bool:
    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    actual = bytes.fromhex(hmac_sha256(data, key))
    return hmac.compare_digest(actual, expected)


def encrypt_file(input_path: str | Path, output_path: str | Path, key: bytes) -> None:
    plaintext = Path(input_path).read_bytes()
    envelope = aes_gcm_encrypt(plaintext, key)
    Path(output_path).write_bytes(envelope)


def decrypt_file(input_path: str | Path, output_path: str | Path, key: bytes) -> None:
    envelope = Path(input_path).read_bytes()
    plaintext = aes_gcm_decrypt(envelope, key)
    Path(output_path).write_bytes(plaintext)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
