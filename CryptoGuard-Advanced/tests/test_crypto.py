import tempfile
import unittest
from pathlib import Path

from cryptoguard.crypto import (
    aes_gcm_decrypt, aes_gcm_encrypt, hmac_sha256, verify_hmac,
    password_hash, password_verify, generate_rsa_keypair, load_private_key,
    load_public_key, sign_data, verify_signature,
)
from cryptoguard.key_manager import LocalKeyManager


class CryptoGuardTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))

    def test_aes_gcm_round_trip(self):
        message = b"private message"
        encrypted = aes_gcm_encrypt(message, self.key)
        self.assertNotEqual(encrypted, message)
        self.assertEqual(aes_gcm_decrypt(encrypted, self.key), message)

    def test_aes_gcm_tamper_detected(self):
        encrypted = bytearray(aes_gcm_encrypt(b"message", self.key))
        encrypted[-1] ^= 1
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(bytes(encrypted), self.key)

    def test_hmac(self):
        data = b"payload"
        tag = hmac_sha256(data, self.key)
        self.assertTrue(verify_hmac(data, self.key, tag))
        self.assertFalse(verify_hmac(data + b"x", self.key, tag))

    def test_password_hash(self):
        hashed = password_hash("Correct horse battery staple", rounds=10)
        self.assertTrue(password_verify("Correct horse battery staple", hashed))
        self.assertFalse(password_verify("wrong", hashed))

    def test_rsa_sign_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            private_path = Path(tmp) / "private.pem"
            public_path = Path(tmp) / "public.pem"
            generate_rsa_keypair(private_path, public_path, b"test-passphrase")
            private = load_private_key(private_path, b"test-passphrase")
            public = load_public_key(public_path)
            signature = sign_data(b"payload", private)
            self.assertTrue(verify_signature(b"payload", signature, public))
            self.assertFalse(verify_signature(b"changed", signature, public))

    def test_key_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = LocalKeyManager(Path(tmp) / "key-store.json")
            v1 = manager.rotate()
            k1 = manager.get_key(v1)
            v2 = manager.rotate()
            self.assertGreater(v2, v1)
            self.assertEqual(manager.active_key(), (v2, manager.get_key(v2)))
            self.assertNotEqual(k1, manager.get_key(v2))


if __name__ == "__main__":
    unittest.main()
