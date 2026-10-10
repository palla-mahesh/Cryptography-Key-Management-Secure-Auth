# Cryptography-Key-Management-Secure-Auth
# CryptoGuard Advanced
## Cryptography, Key Management & Secure Authentication

A Python command-line toolkit demonstrating the cryptographic requirements of the task brief, with documentation, examples, and automated tests.

### Requirements covered
- AES-256-GCM authenticated encryption/decryption with a fresh random 96-bit nonce.
- RSA-2048 public/private key generation and RSA-PSS/SHA-256 digital signatures.
- bcrypt password hashing and verification with automatic salts and configurable work factor.
- HMAC-SHA-256 generation and verification.
- Local versioned key rotation helper and secure file permission guidance.
- Automated tests, command-line utilities, example workflow, and security documentation.

### Advanced additions
File encryption/decryption, file signing/verification, tamper detection, wrong-key rejection, key versioning, SHA-256 file fingerprinting, restrictive private-key permissions, and a GitHub Actions test workflow.

### Repository structure
```text
CryptoGuard-Advanced/
├── cryptoguard/
│   ├── __init__.py
│   ├── crypto.py
│   ├── key_manager.py
│   └── cli.py
├── tests/test_crypto.py
├── examples/demo.py
├── docs/
│   ├── SECURITY.md
│   ├── IMPLEMENTATION.md
│   └── TESTING.md
├── .github/workflows/tests.yml
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
└── .gitignore
```

## Kali Linux: installation and execution

### 1. Install prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip git
python3 --version
```

### 2. Extract the ZIP
If the archive is in `~/Downloads`:
```bash
cd ~/Downloads
unzip CryptoGuard-Advanced.zip
cd cryptoguard
ls -la
```
The project root contains `README.md`, `requirements.txt`, `pyproject.toml`, and the inner `cryptoguard/`, `tests/`, and `examples/` directories.

### 3. Install dependencies in a virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pip install -e .
```
Do not use `sudo pip`; use the virtual environment.

### 4. Run the demo
```bash
python examples/demo.py
```
Expected lines report successful AES round-trip, RSA signature verification, bcrypt verification, and HMAC verification.

### 5. Run tests
```bash
python -m unittest discover -s tests -v
```

## Run each task requirement

### AES-256-GCM file encryption
```bash
printf 'Confidential sample data\n' > sample.txt
python -c "import secrets; print(secrets.token_hex(32))" > aes-key.hex
chmod 600 aes-key.hex
python -m cryptoguard.cli encrypt-file --key-file aes-key.hex --input sample.txt --output sample.cgua
python -m cryptoguard.cli decrypt-file --key-file aes-key.hex --input sample.cgua --output restored.txt
cmp sample.txt restored.txt && echo "Encryption/decryption verified"
```

### RSA key generation and digital signature
```bash
printf '%s\n' 'Replace-With-A-Unique-Strong-Lab-Passphrase' > key-password.txt
chmod 600 key-password.txt
python -m cryptoguard.cli generate-rsa --private-key private.pem --public-key public.pem --password-file key-password.txt
python -m cryptoguard.cli sign-file --private-key private.pem --password-file key-password.txt --input sample.txt --signature sample.sig
python -m cryptoguard.cli verify-file --public-key public.pem --input sample.txt --signature sample.sig
```
A valid signature prints `VALID`. Modify the file and verify again; it should print `INVALID`.

### bcrypt password hashing
```bash
python -m cryptoguard.cli hash-password
python -m cryptoguard.cli verify-password
```
Use a disposable lab password, not a real account password.

### HMAC-SHA-256
```bash
python -c "import secrets; print(secrets.token_hex(32))" > hmac-key.hex
chmod 600 hmac-key.hex
python -m cryptoguard.cli hmac --key-file hmac-key.hex --input sample.txt
```
The core module provides HMAC verification. Use a dedicated HMAC key, separate from the AES key.

### Key rotation
```bash
python -m cryptoguard.cli rotate-key --store keys/key-store.json
python -m cryptoguard.cli rotate-key --store keys/key-store.json
```
The local key store contains plaintext key material. It is a teaching example, not a production key vault.

### SHA-256 file fingerprint
```bash
python -c "from cryptoguard.crypto import sha256_file; print(sha256_file('sample.txt'))"
```

## GitHub submission
Create a public repository named `CryptoGuard-Advanced`, then run from the project root:
```bash
git init
git add .
git status
git commit -m "Add CryptoGuard Advanced security toolkit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/CryptoGuard-Advanced.git
git push -u origin main
```
Replace `YOUR-USERNAME`. Inspect staged files and never commit private keys, password files, generated key stores, or real secrets.

## Security disclaimer
This is an educational project, not a production key-management service or complete authentication server. The local key manager stores raw key material on disk. For production, use an OS key store or managed KMS/HSM, access controls, backup/recovery procedures, and independent security review.
