# Testing Guide

Run from the repository root after activating `.venv` and installing requirements:

```bash
python -m unittest discover -s tests -v
python examples/demo.py
```

Tests cover AES-GCM round trips, tamper detection, HMAC, bcrypt, RSA signatures, and key rotation. Run these commands in the target Kali environment before reporting results. Do not claim the suite passed until you have run it.
