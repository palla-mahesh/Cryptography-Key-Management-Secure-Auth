from pathlib import Path
import secrets

from cryptoguard.crypto import (
    aes_gcm_decrypt, aes_gcm_encrypt, generate_rsa_keypair,
    load_private_key, load_public_key, password_hash, password_verify,
    sign_data, verify_signature, hmac_sha256, verify_hmac,
)

out = Path("demo-output")
out.mkdir(exist_ok=True)
key = secrets.token_bytes(32)
message = b"CryptoGuard demonstration: confidentiality, integrity, authentication."
envelope = aes_gcm_encrypt(message, key)
(out / "message.cgua").write_bytes(envelope)
print("AES-GCM round trip:", aes_gcm_decrypt(envelope, key) == message)

passphrase = b"demo-only-passphrase-change-me"
generate_rsa_keypair(out / "private.pem", out / "public.pem", passphrase)
private = load_private_key(out / "private.pem", passphrase)
public = load_public_key(out / "public.pem")
signature = sign_data(message, private)
(out / "message.sig").write_bytes(signature)
print("RSA signature valid:", verify_signature(message, signature, public))

stored = password_hash("DemoPassword-Only", rounds=10)
print("bcrypt password matches:", password_verify("DemoPassword-Only", stored))

tag = hmac_sha256(message, key)
print("HMAC valid:", verify_hmac(message, key, tag))
print(f"Demo output created in: {out.resolve()}")
