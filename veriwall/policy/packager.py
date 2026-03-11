"""
veriwall.policy.packager
Create, sign, save, and load policy bundles + system state.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from veriwall.core.hasher import hash_content

DATA_DIR   = Path("veriwall_data")
STATE_PATH = DATA_DIR / "state.json"
BUNDLES_DIR = DATA_DIR / "bundles"

GENESIS_HASH = "0" * 64

_DEFAULT_STATE = {
    "active_version":      0,
    "active_content_hash": None,
    "active_policy_path":  None,
}


# ── State helpers ─────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return dict(_DEFAULT_STATE)


def save_state(state: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


# ── Bundle helpers ────────────────────────────────────────────────────────────

def create_bundle(policy_content: dict, author: str, description: str) -> dict:
    """Build a new unsigned bundle linked to the current active state."""
    state    = load_state()
    prev     = state["active_content_hash"] or GENESIS_HASH
    version  = state["active_version"] + 1
    ts       = datetime.now(timezone.utc).isoformat()

    return {
        "version":       version,
        "author":        author,
        "description":   description,
        "timestamp":     ts,
        "content":       policy_content,
        "content_hash":  hash_content(policy_content),
        "previous_hash": prev,
        "signatures":    [],
    }


def add_signature(bundle: dict, admin_id: str, sig_b64: str):
    """Append a signature entry (mutates bundle in place)."""
    # Remove any existing entry for this admin (allow re-sign)
    bundle["signatures"] = [s for s in bundle["signatures"] if s["admin_id"] != admin_id]
    bundle["signatures"].append({"admin_id": admin_id, "signature": sig_b64})


def save_bundle(bundle: dict, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2))


def load_bundle(path) -> dict:
    return json.loads(Path(path).read_text())
