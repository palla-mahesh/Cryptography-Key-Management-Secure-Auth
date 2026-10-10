# Security Design and Best Practices

## Algorithms
- **AES-256-GCM:** confidentiality and authenticated integrity for data.
- **RSA-2048 + RSA-PSS/SHA-256:** digital signatures; signatures do not encrypt data.
- **bcrypt:** salted password hashing with a configurable computational work factor.
- **HMAC-SHA-256:** message authentication using a shared secret key.
- **SHA-256:** file fingerprinting; a bare digest alone does not authenticate content.

## Key lifecycle
1. Generate keys using cryptographically secure randomness.
2. Restrict permissions on secret and private-key files.
3. Use separate keys for encryption and HMAC.
4. Never commit keys, passwords, local key stores, or real secrets.
5. Define rotation, backup, recovery, revocation, and retirement procedures.
6. Track key versions and retain old keys only as long as authorized decryption/migration requires.
7. Re-encrypt data as needed before retiring old keys.

## AES-GCM notes
The project uses a 32-byte key and a fresh random 12-byte nonce for each encryption. Never reuse a nonce with the same key. Decryption must fail if the ciphertext is modified or the wrong key is used.

## Limitations
The local JSON key store is not encrypted and is for lab use only. The project is not a production KMS or complete web authentication system. Production use requires a managed KMS/HSM or OS key store, access controls, monitoring, recovery plans, and independent review.
