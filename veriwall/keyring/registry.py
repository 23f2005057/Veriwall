"""
veriwall.keyring.registry
Persistent keyring — maps admin_id → Ed25519 public key (base64).
"""
import json
from pathlib import Path

KEYRING_PATH = Path("veriwall_data/keyring.json")


class Keyring:
    def __init__(self):
        self._data: dict[str, str] = {}
        self._load()

    def _load(self):
        if KEYRING_PATH.exists():
            self._data = json.loads(KEYRING_PATH.read_text())

    def _save(self):
        KEYRING_PATH.parent.mkdir(parents=True, exist_ok=True)
        KEYRING_PATH.write_text(json.dumps(self._data, indent=2))

    def add(self, admin_id: str, pub_b64: str):
        self._data[admin_id] = pub_b64
        self._save()

    def get(self, admin_id: str) -> str | None:
        return self._data.get(admin_id)

    def all(self) -> dict[str, str]:
        return dict(self._data)

    def __len__(self) -> int:
        return len(self._data)
