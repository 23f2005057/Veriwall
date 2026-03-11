"""
veriwall.core.verifier
6-check verification pipeline for policy bundles.
"""
from dataclasses import dataclass, field
from typing import Optional
from .hasher import canonical_json, hash_content
from .signer import verify_signature

GENESIS_HASH = "0" * 64  # sentinel for the very first policy


@dataclass
class VerifyResult:
    passed:  bool
    checks:  list = field(default_factory=list)
    signers: list = field(default_factory=list)
    error:   Optional[str] = None


def _check(checks: list, name: str, passed: bool, detail: str) -> bool:
    checks.append({"check": name, "passed": passed, "detail": detail})
    return passed


def verify_bundle(
    bundle: dict,
    keyring: dict,
    active_content_hash: Optional[str],
    active_version: int,
    threshold_k: int,
) -> VerifyResult:
    checks:  list[dict] = []
    signers: list[str]  = []

    # ── Check 1: Content hash integrity ──────────────────────────────────────
    expected_hash = hash_content(bundle["content"])
    ok1 = _check(
        checks, "content_hash_valid",
        bundle["content_hash"] == expected_hash,
        f"stored={bundle['content_hash'][:16]}… computed={expected_hash[:16]}…",
    )

    # ── Check 2: Hash-chain linkage ───────────────────────────────────────────
    expected_prev = active_content_hash if active_content_hash else GENESIS_HASH
    ok2 = _check(
        checks, "hash_chain_valid",
        bundle["previous_hash"] == expected_prev,
        f"bundle.prev={bundle['previous_hash'][:16]}… active={expected_prev[:16]}…",
    )

    # ── Check 3: Monotonic version sequence ──────────────────────────────────
    ok3 = _check(
        checks, "version_sequence_valid",
        bundle["version"] == active_version + 1,
        f"bundle.version={bundle['version']}  expected={active_version + 1}",
    )

    # ── Check 4: No-replay (content hash must differ from current active) ─────
    ok4 = _check(
        checks, "no_replay",
        bundle["content_hash"] != active_content_hash,
        "content hash differs from active" if bundle["content_hash"] != active_content_hash else "REPLAY: same hash as active",
    )

    # ── Check 5: Signature authenticity ──────────────────────────────────────
    message = canonical_json({
        "version":       bundle["version"],
        "content_hash":  bundle["content_hash"],
        "previous_hash": bundle["previous_hash"],
        "timestamp":     bundle["timestamp"],
    })

    valid_signers = []
    sig_details   = []
    for entry in bundle.get("signatures", []):
        admin_id = entry["admin_id"]
        sig_b64  = entry["signature"]
        pub_b64  = keyring.get(admin_id)
        if pub_b64 and verify_signature(pub_b64, message, sig_b64):
            valid_signers.append(admin_id)
            sig_details.append(f"{admin_id}✓")
        else:
            sig_details.append(f"{admin_id}✗")

    ok5 = _check(
        checks, "signatures_authentic",
        len(valid_signers) > 0,
        f"valid={', '.join(sig_details) or 'none'}",
    )

    # ── Check 6: Threshold met ────────────────────────────────────────────────
    ok6 = _check(
        checks, "threshold_met",
        len(valid_signers) >= threshold_k,
        f"{len(valid_signers)} valid signature(s) ≥ threshold k={threshold_k}" if len(valid_signers) >= threshold_k
        else f"only {len(valid_signers)} valid signature(s), need k={threshold_k}",
    )

    passed = all([ok1, ok2, ok3, ok4, ok5, ok6])
    error  = None
    if not passed:
        failed = [c["check"] for c in checks if not c["passed"]]
        error  = f"Failed checks: {', '.join(failed)}"

    return VerifyResult(passed=passed, checks=checks, signers=valid_signers, error=error)
