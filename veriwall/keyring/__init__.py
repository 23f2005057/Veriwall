"""
veriwall.audit
Append-only hash-chained audit log.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path("veriwall_data/audit.jsonl")


class AuditLog:
    def append(
        self,
        event: str,
        policy_version: int,
        policy_hash: str,
        signers: list,
        detail: str = "",
        checks: list = None,
    ):
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Chain hash: SHA-256 of last line (or zeros for first entry)
        prev_hash = "0" * 64
        if LOG_PATH.exists():
            lines = LOG_PATH.read_text().strip().splitlines()
            if lines:
                prev_hash = hashlib.sha256(lines[-1].encode()).hexdigest()

        entry = {
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "event":          event,
            "policy_version": policy_version,
            "policy_hash":    policy_hash,
            "signers":        signers,
            "detail":         detail,
            "prev_hash":      prev_hash,
        }

        with LOG_PATH.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def read_all(self) -> list[dict]:
        if not LOG_PATH.exists():
            return []
        return [json.loads(l) for l in LOG_PATH.read_text().strip().splitlines() if l]

    def verify_log_integrity(self) -> tuple[bool, list[str]]:
        """Verify that every entry's prev_hash matches the hash of the previous line."""
        if not LOG_PATH.exists():
            return True, []

        lines  = LOG_PATH.read_text().strip().splitlines()
        issues = []

        for i, line in enumerate(lines):
            entry = json.loads(line)
            if i == 0:
                expected = "0" * 64
            else:
                expected = hashlib.sha256(lines[i - 1].encode()).hexdigest()

            if entry.get("prev_hash") != expected:
                issues.append(f"Entry {i}: prev_hash mismatch (possible tampering)")

        return len(issues) == 0, issues


# Module-level singleton
log = AuditLog()
