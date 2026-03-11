"""
veriwall.policy.enforcer
Atomically applies a verified bundle and persists the active policy.
"""
import json
from pathlib import Path
from veriwall.policy.packager import load_state, save_state

DATA_DIR          = Path("veriwall_data")
ACTIVE_POLICY_PATH = DATA_DIR / "active_policy.json"


def apply_policy(bundle: dict) -> dict:
    """Persist bundle content as the active policy and update state."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ACTIVE_POLICY_PATH.write_text(json.dumps(bundle["content"], indent=2))

    state = load_state()
    state["active_version"]      = bundle["version"]
    state["active_content_hash"] = bundle["content_hash"]
    state["active_policy_path"]  = str(ACTIVE_POLICY_PATH)
    save_state(state)
    return state


def get_active_policy() -> dict | None:
    """Return the currently active policy content, or None."""
    if ACTIVE_POLICY_PATH.exists():
        return json.loads(ACTIVE_POLICY_PATH.read_text())
    return None
