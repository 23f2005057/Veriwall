#!/usr/bin/env python3
"""
VeriWall CLI — veriwall.py
Commands: keygen, register, propose, sign, apply, status, audit, demo
"""
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# ── Colour helpers ────────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
C  = "\033[96m"   # cyan
M  = "\033[95m"   # magenta
W  = "\033[97m"   # white
DIM= "\033[2m"
BO = "\033[1m"
RST= "\033[0m"

BANNER = f"""
{B}╔══════════════════════════════════════════════════════════╗
║  {W}{BO}VeriWall{RST}{B}  —  Threshold-Signed Policy Enforcement System  ║
╚══════════════════════════════════════════════════════════╝{RST}
"""

def info(msg):  print(f"  {G}✓{RST}  {msg}")
def warn(msg):  print(f"  {Y}⚠{RST}  {msg}")
def error(msg): print(f"  {R}✗{RST}  {msg}")
def step(msg):  print(f"\n{C}▶{RST} {BO}{msg}{RST}")
def box(title, lines, color=C):
    w = max(len(l) for l in lines + [title]) + 4
    print(f"{color}┌─ {title} {'─' * (w - len(title) - 3)}┐{RST}")
    for l in lines:
        print(f"{color}│{RST}  {l:<{w-2}}{color}│{RST}")
    print(f"{color}└{'─' * (w)}┘{RST}")

# ── Imports ───────────────────────────────────────────────────────────────────
from veriwall.core.signer import generate_keypair, sign
from veriwall.core.hasher import canonical_json
from veriwall.core.verifier import verify_bundle
from veriwall.keyring.registry import Keyring
from veriwall.policy.packager import (
    create_bundle, add_signature, save_bundle,
    load_bundle, load_state
)
from veriwall.policy.enforcer import apply_policy, get_active_policy
from veriwall import audit

DATA_DIR  = Path("veriwall_data")
KEYS_DIR  = DATA_DIR / "keys"
BUNDLES_DIR = DATA_DIR / "bundles"


# ─────────────────────────────────────────────────────────────────────────────
def cmd_keygen(admin_id: str):
    """Generate an Ed25519 key pair for an administrator."""
    step(f"Generating Ed25519 key pair for: {W}{admin_id}{RST}")
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    priv_path = KEYS_DIR / f"{admin_id}.priv"
    pub_path  = KEYS_DIR / f"{admin_id}.pub"

    if priv_path.exists():
        warn(f"Key already exists for {admin_id}. Use --force to overwrite.")
        return

    priv_b64, pub_b64 = generate_keypair()
    priv_path.write_text(priv_b64)
    pub_path.write_text(pub_b64)

    info(f"Private key → {priv_path}  {DIM}(KEEP SECRET){RST}")
    info(f"Public key  → {pub_path}")


def cmd_register(admin_id: str, keyring: Keyring):
    """Register an administrator's public key in the keyring."""
    step(f"Registering {W}{admin_id}{RST} in keyring")
    pub_path = KEYS_DIR / f"{admin_id}.pub"
    if not pub_path.exists():
        error(f"No public key found at {pub_path}. Run keygen first.")
        return
    pub_b64 = pub_path.read_text().strip()
    keyring.add(admin_id, pub_b64)
    info(f"Registered {admin_id} — public key: {pub_b64[:20]}…")
    info(f"Keyring now has {len(keyring)} administrator(s)")


def cmd_propose(policy_file: str, author: str, description: str):
    """Create a new unsigned policy bundle."""
    step(f"Proposing policy: {W}{policy_file}{RST}")
    with open(policy_file) as f:
        policy_content = json.load(f)

    bundle = create_bundle(policy_content, author, description)
    bundle_name = f"bundle_v{bundle['version']}.json"
    bundle_path = BUNDLES_DIR / bundle_name
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    save_bundle(bundle, bundle_path)

    info(f"Bundle created → {bundle_path}")
    info(f"Version:       v{bundle['version']}")
    info(f"Content hash:  {bundle['content_hash'][:32]}…")
    info(f"Previous hash: {bundle['previous_hash'][:32]}…")
    info(f"Signatures:    0 (needs signing)")
    return bundle_path


def cmd_sign(bundle_path: str, admin_id: str):
    """Sign a policy bundle as an administrator."""
    step(f"Signing bundle as {W}{admin_id}{RST}")
    bundle = load_bundle(bundle_path)

    priv_path = KEYS_DIR / f"{admin_id}.priv"
    if not priv_path.exists():
        error(f"No private key for {admin_id}. Run keygen first.")
        return

    priv_b64 = priv_path.read_text().strip()

    # Sign the canonical message (same as verifier expects)
    message = canonical_json({
        "version":       bundle["version"],
        "content_hash":  bundle["content_hash"],
        "previous_hash": bundle["previous_hash"],
        "timestamp":     bundle["timestamp"],
    })

    sig_b64 = sign(priv_b64, message)
    add_signature(bundle, admin_id, sig_b64)
    save_bundle(bundle, bundle_path)

    current_sigs = len(bundle["signatures"])
    info(f"Signature added by {admin_id}")
    info(f"Signature: {sig_b64[:32]}…")
    info(f"Total signatures on bundle: {current_sigs}")


def cmd_apply(bundle_path: str, keyring: Keyring, threshold_k: int):
    """Verify and atomically apply a signed policy bundle."""
    step(f"Verifying & applying bundle: {W}{bundle_path}{RST}")
    bundle = load_bundle(bundle_path)
    state  = load_state()

    print(f"\n  {DIM}Running 6-check verification pipeline…{RST}\n")

    result = verify_bundle(
        bundle         = bundle,
        keyring        = keyring.all(),
        active_content_hash = state["active_content_hash"],
        active_version = state["active_version"],
        threshold_k    = threshold_k,
    )

    # Print check results
    for chk in result.checks:
        icon  = f"{G}✓{RST}" if chk["passed"] else f"{R}✗{RST}"
        color = G if chk["passed"] else R
        name  = chk["check"].replace("_", " ")
        print(f"    {icon}  {color}{name:<25}{RST}  {DIM}{chk['detail']}{RST}")

    if result.passed:
        print()
        new_state = apply_policy(bundle)
        audit.log.append(
            event          = "POLICY_APPLIED",
            policy_version = bundle["version"],
            policy_hash    = bundle["content_hash"],
            signers        = result.signers,
            detail         = f"Applied by threshold-signed bundle. Signers: {result.signers}",
            checks         = result.checks,
        )
        print()
        info(f"{G}{BO}Policy APPLIED ✓{RST}")
        info(f"Active version: v{new_state['active_version']}")
        info(f"Active hash:    {new_state['active_content_hash'][:32]}…")
        info(f"Valid signers:  {', '.join(result.signers)}")
    else:
        audit.log.append(
            event          = "POLICY_REJECTED",
            policy_version = bundle.get("version", 0),
            policy_hash    = bundle.get("content_hash", ""),
            signers        = result.signers,
            detail         = result.error or "Unknown failure",
            checks         = result.checks,
        )
        print()
        error(f"{R}{BO}Policy REJECTED ✗{RST}")
        error(f"Reason: {result.error}")


def cmd_status(keyring: Keyring):
    """Show current system status."""
    step("System Status")
    state = load_state()
    active = get_active_policy()

    box("Active Policy", [
        f"Version : v{state['active_version']}",
        f"Hash    : {(state['active_content_hash'] or 'none')[:48]}…" if state['active_content_hash'] else "Hash    : none (no policy applied yet)",
        f"Policy  : {json.dumps(active, indent=None)[:60]}…" if active else "Policy  : none",
    ], color=G)

    box("Keyring", [
        f"Administrators ({len(keyring)}):",
        *[f"  • {aid}: {pub[:28]}…" for aid, pub in keyring.all().items()],
    ], color=B)

    entries = audit.log.read_all()
    box("Audit Log", [
        f"Entries: {len(entries)}",
        f"Last event: {entries[-1]['event']} at {entries[-1]['timestamp'][:19]}" if entries else "No entries yet",
    ], color=M)


def cmd_audit():
    """Display the audit log with integrity check."""
    step("Audit Log")
    entries = audit.log.read_all()

    if not entries:
        warn("Audit log is empty.")
        return

    ok, issues = audit.log.verify_log_integrity()
    if ok:
        info(f"{G}Log chain integrity: VERIFIED ✓{RST}  ({len(entries)} entries)")
    else:
        error(f"Log chain integrity: BROKEN ✗")
        for issue in issues:
            error(f"  → {issue}")

    print()
    for i, e in enumerate(entries):
        color = G if "APPLIED" in e["event"] else R
        ts = e["timestamp"][:19]
        print(f"  {color}{BO}{e['event']:<20}{RST}  {DIM}v{e['policy_version']}  {ts}{RST}")
        print(f"    {DIM}Hash: {e['policy_hash'][:32]}…{RST}")
        if e["signers"]:
            print(f"    {DIM}Signers: {', '.join(e['signers'])}{RST}")
        if e.get("detail"):
            print(f"    {Y}{e['detail']}{RST}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
def run_demo():
    """
    Full automated demo:
    - Creates 3 admins, sets threshold k=2
    - Proposes a firewall policy
    - Signs with 2 admins (meets threshold)
    - Applies policy (all 6 checks pass)
    - Tries to replay the same bundle (should fail)
    - Tries to tamper with content (should fail)
    - Shows audit log
    """
    import shutil
    # Clean slate
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir(parents=True)

    keyring = Keyring()
    K = 2  # threshold: 2 of 3

    print(BANNER)
    print(f"{BO}Running full VeriWall demonstration (k={K} of n=3){RST}\n")
    print("─" * 60)

    # ── Step 1: Key generation ────────────────────────────────
    step("Step 1 — Key Generation (3 administrators)")
    for admin in ["alice", "bob", "carol"]:
        cmd_keygen(admin)

    # ── Step 2: Keyring registration ──────────────────────────
    step("Step 2 — Register administrators in keyring")
    for admin in ["alice", "bob", "carol"]:
        cmd_register(admin, keyring)

    # ── Step 3: Propose a policy ──────────────────────────────
    step("Step 3 — Propose a firewall policy")
    policy = {
        "name": "firewall-v1",
        "rules": [
            {"action": "ALLOW", "port": 443, "protocol": "TCP", "from": "0.0.0.0/0"},
            {"action": "ALLOW", "port": 22,  "protocol": "TCP", "from": "10.0.0.0/8"},
            {"action": "DENY",  "port": "*",  "protocol": "*",   "from": "0.0.0.0/0"},
        ],
        "description": "Production firewall baseline",
    }
    policy_path = DATA_DIR / "firewall_v1.json"
    policy_path.write_text(json.dumps(policy, indent=2))
    bundle_path = cmd_propose(str(policy_path), "alice", "Initial firewall policy")

    # ── Step 4: Sign with 2 admins ────────────────────────────
    step("Step 4 — Alice signs the bundle")
    cmd_sign(str(bundle_path), "alice")

    step("Step 5 — Bob signs the bundle")
    cmd_sign(str(bundle_path), "bob")

    # ── Step 5: Apply ─────────────────────────────────────────
    step("Step 6 — Apply bundle (threshold k=2 met: alice + bob)")
    cmd_apply(str(bundle_path), keyring, K)

    print("\n" + "─" * 60)
    print(f"\n{M}{BO}ATTACK SIMULATION 1: Replay Attack{RST}")
    step("Try to replay the same bundle (should fail: hash chain break)")
    cmd_apply(str(bundle_path), keyring, K)

    print("\n" + "─" * 60)
    print(f"\n{M}{BO}ATTACK SIMULATION 2: Content Tampering{RST}")
    step("Tamper with bundle content hash then try to apply")
    bundle = load_bundle(str(bundle_path))

    # Propose v2 properly, then tamper before applying
    policy2 = dict(policy)
    policy2["rules"][2] = {"action": "ALLOW", "port": "*", "protocol": "*", "from": "0.0.0.0/0"}
    policy2["description"] = "TAMPERED — open all ports"
    policy_path2 = DATA_DIR / "tampered.json"
    policy_path2.write_text(json.dumps(policy2, indent=2))
    bundle2_path = cmd_propose(str(policy_path2), "eve", "malicious change")
    cmd_sign(str(bundle2_path), "alice")
    cmd_sign(str(bundle2_path), "bob")

    # Tamper the content after signing
    bundle2 = load_bundle(str(bundle2_path))
    bundle2["content"]["rules"][0]["action"] = "DENY_ALL_HACKED"
    save_bundle(bundle2, bundle2_path)
    warn("Content was tampered AFTER signing!")
    cmd_apply(str(bundle2_path), keyring, K)

    print("\n" + "─" * 60)
    print(f"\n{M}{BO}ATTACK SIMULATION 3: Insufficient Signatures{RST}")
    step("Propose v3 but only get 1 signature (below k=2 threshold)")
    policy3 = {"name": "firewall-v3", "rules": [], "description": "Sparse policy"}
    policy_path3 = DATA_DIR / "firewall_v3.json"
    policy_path3.write_text(json.dumps(policy3, indent=2))
    bundle3_path = cmd_propose(str(policy_path3), "carol", "Under-signed attempt")
    cmd_sign(str(bundle3_path), "carol")
    warn("Only 1 signature — threshold is k=2!")
    cmd_apply(str(bundle3_path), keyring, K)

    print("\n" + "─" * 60)
    cmd_status(keyring)
    print()
    cmd_audit()

    print(f"\n{G}{BO}Demo complete.{RST}")
    print(f"{DIM}Data stored in: {DATA_DIR.resolve()}{RST}\n")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    keyring = Keyring()

    if not args or args[0] == "demo":
        run_demo()
    elif args[0] == "keygen" and len(args) == 2:
        cmd_keygen(args[1])
    elif args[0] == "register" and len(args) == 2:
        cmd_register(args[1], keyring)
    elif args[0] == "propose" and len(args) >= 3:
        desc = args[3] if len(args) > 3 else ""
        cmd_propose(args[1], args[2], desc)
    elif args[0] == "sign" and len(args) == 3:
        cmd_sign(args[1], args[2])
    elif args[0] == "apply" and len(args) >= 2:
        k = int(args[2]) if len(args) > 2 else 2
        cmd_apply(args[1], keyring, k)
    elif args[0] == "status":
        cmd_status(keyring)
    elif args[0] == "audit":
        cmd_audit()
    else:
        print(BANNER)
        print("Usage:")
        print("  python veriwall.py demo                          — Run full automated demo")
        print("  python veriwall.py keygen <admin_id>             — Generate key pair")
        print("  python veriwall.py register <admin_id>           — Register in keyring")
        print("  python veriwall.py propose <policy.json> <author> [desc]")
        print("  python veriwall.py sign <bundle.json> <admin_id>")
        print("  python veriwall.py apply <bundle.json> [k]       — k = threshold (default 2)")
        print("  python veriwall.py status                        — Show system status")
        print("  python veriwall.py audit                         — Show audit log")
