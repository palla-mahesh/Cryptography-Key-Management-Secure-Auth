# Implementation Mapping

| Task requirement | Project module | How to demonstrate |
|---|---|---|
| AES-256-GCM encryption/decryption | `cryptoguard/crypto.py` | Run `encrypt-file` and `decrypt-file` |
| Fresh random nonce | `cryptoguard/crypto.py` | Encrypt the same input twice and compare outputs |
| RSA-2048 key generation | `cryptoguard/crypto.py`, `cryptoguard/cli.py` | Run `generate-rsa` |
| Digital signature verification | `cryptoguard/crypto.py`, `cryptoguard/cli.py` | Run `sign-file` and `verify-file` |
| bcrypt password hashing | `cryptoguard/crypto.py`, `cryptoguard/cli.py` | Run `hash-password` and `verify-password` |
| HMAC-SHA-256 | `cryptoguard/crypto.py`, `cryptoguard/cli.py` | Run `hmac`; verification helper is in `crypto.py` |
| Key storage/rotation guidance | `cryptoguard/key_manager.py`, `README.md` | Run `rotate-key` twice and inspect the versioned store |
| Secure storage documentation | `docs/SECURITY.md` | Review key lifecycle and limitations |
| Quality checks | `tests/test_crypto.py` | Run the unittest suite |
