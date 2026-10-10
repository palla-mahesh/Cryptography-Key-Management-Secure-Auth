# Contributing

1. Create and activate a Python virtual environment.
2. Install `requirements.txt` and run `python -m unittest discover -s tests -v`.
3. Add tests for new features, invalid inputs, and tampering cases.
4. Do not implement custom cryptographic primitives; use established libraries.
5. Never commit private keys, password files, key stores, or real secrets.
6. Update README and security documentation when behavior or limitations change.
