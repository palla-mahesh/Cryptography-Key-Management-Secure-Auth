"""Simple versioned local key store for demonstrations, not a production KMS."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path


class LocalKeyManager:
    """Store versioned 256-bit keys as hex with restrictive filesystem permissions."""

    def __init__(self, store_path: str | Path):
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if not self.store_path.exists():
            return {"active_version": 0, "keys": {}}
        data = json.loads(self.store_path.read_text(encoding="utf-8"))
        if not isinstance(data.get("keys"), dict):
            raise ValueError("Invalid key-store format")
        return data

    def _save(self, data: dict) -> None:
        temp = self.store_path.with_suffix(self.store_path.suffix + ".tmp")
        temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        temp.replace(self.store_path)
        try:
            os.chmod(self.store_path, 0o600)
        except OSError:
            pass

    def rotate(self) -> int:
        data = self._load()
        version = max([int(v) for v in data["keys"]] or [0]) + 1
        data["keys"][str(version)] = secrets.token_bytes(32).hex()
        data["active_version"] = version
        self._save(data)
        return version

    def active_key(self) -> tuple[int, bytes]:
        data = self._load()
        version = int(data.get("active_version", 0))
        if not version or str(version) not in data["keys"]:
            raise ValueError("No active key. Run the rotate command first.")
        return version, bytes.fromhex(data["keys"][str(version)])

    def get_key(self, version: int) -> bytes:
        data = self._load()
        try:
            return bytes.fromhex(data["keys"][str(version)])
        except KeyError as exc:
            raise ValueError(f"Key version {version} does not exist") from exc
