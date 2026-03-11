#!/usr/bin/env python3
"""
VeriWall Scenario Demo
======================
Company   : SecureBank Inc.
Scenario  : A new firewall policy needs to be deployed.
            An attacker (eve) tries to sneak in an unauthorized change.
            The system catches every attack.

Admins    : alice (Security Lead), bob (Network Engineer), carol (CISO)
Threshold : k=2 (any 2 of 3 must approve)
"""

import json, shutil, sys, time
from pathlib import Path

# ── Make sure veriwall package is importable ───────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from veriwall.core.signer    import generate_keypair, sign
from veriwall.core.hasher    import canonical_json
from veriwall.core.verifier  import verify_bundle
from veriwall.keyring.registry import Keyring
from veriwall.policy.packager  import create_bundle, add_signature, save_bundle, load_bundle, load_state
from veriwall.policy.enforcer  import apply_policy, get_active_policy
from veriwall import audit

# ── Colour helpers ─────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
C="\033[96m"; M="\033[95m"; W="\033[97m"; BO="\033[1m"; RST="\033[0m"; DIM="\033[2m"

DATA_DIR    = Path("veriwall_data")
KEYS_DIR    = DATA_DIR / "keys"
BUNDLES_DIR = DATA_DIR / "bundles"

def pause(msg=""):
    if msg: print(f"\n{DIM}  [ {msg} ]{RST}")
    time.sleep(0.4)

def scene(title):
    print(f"\n{'═'*62}")
    print(f"  {M}{BO}{title}{RST}")
    print(f"{'═'*62}")
    pause()

def narrate(msg):
    print(f"\n  {Y}📢  {msg}{RST}")
    pause()

def action(who, what):
    print(f"\n  {C}[{who}]{RST} {what}")
    pause()

def success(msg): print(f"  {G}✅  {msg}{RST}")
def failure(msg): print(f"  {R}❌  {msg}{RST}")
def warning(msg): print(f"  {Y}⚠️   {msg}{RST}")
def info(msg):    print(f"  {B}ℹ️   {msg}{RST}")

def show_checks(result):
    print()
    for chk in result.checks:
        icon  = f"{G}✓{RST}" if chk["passed"] else f"{R}✗{RST}"
        color = G if chk["passed"] else R
        name  = chk["check"].replace("_"," ")
        print(f"      {icon}  {color}{name:<26}{RST} {DIM}{chk['detail']}{RST}")
    print()

# ── Helper: generate + store keys ─────────────────────────────────────────
def keygen(admin_id):
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_b64, pub_b64 = generate_keypair()
    (KEYS_DIR / f"{admin_id}.priv").write_text(priv_b64)
    (KEYS_DIR / f"{admin_id}.pub").write_text(pub_b64)
    return priv_b64, pub_b64

def register(admin_id, keyring):
    pub_b64 = (KEYS_DIR / f"{admin_id}.pub").read_text().strip()
    keyring.add(admin_id, pub_b64)

def sign_bundle(bundle_path, admin_id):
    bundle   = load_bundle(bundle_path)
    priv_b64 = (KEYS_DIR / f"{admin_id}.priv").read_text().strip()
    message  = canonical_json({
        "version":       bundle["version"],
        "content_hash":  bundle["content_hash"],
        "previous_hash": bundle["previous_hash"],
        "timestamp":     bundle["timestamp"],
    })
    sig_b64 = sign(priv_b64, message)
    add_signature(bundle, admin_id, sig_b64)
    save_bundle(bundle, bundle_path)
    return bundle

def apply_bundle(bundle_path, keyring, k):
    bundle = load_bundle(bundle_path)
    state  = load_state()
    result = verify_bundle(
        bundle              = bundle,
        keyring             = keyring.all(),
        active_content_hash = state["active_content_hash"],
        active_version      = state["active_version"],
        threshold_k         = k,
    )
    show_checks(result)
    if result.passed:
        new_state = apply_policy(bundle)
        audit.log.append(
            event          = "POLICY_APPLIED",
            policy_version = bundle["version"],
            policy_hash    = bundle["content_hash"],
            signers        = result.signers,
            detail         = f"Signers: {result.signers}",
            checks         = result.checks,
        )
        success(f"Policy v{bundle['version']} APPLIED — signers: {', '.join(result.signers)}")
    else:
        audit.log.append(
            event          = "POLICY_REJECTED",
            policy_version = bundle.get("version", 0),
            policy_hash    = bundle.get("content_hash", ""),
            signers        = result.signers,
            detail         = result.error or "Unknown",
            checks         = result.checks,
        )
        failure(f"Policy REJECTED — {result.error}")
    return result

def propose(policy_content, author, description):
    bundle      = create_bundle(policy_content, author, description)
    bundle_name = f"bundle_v{bundle['version']}.json"
    bundle_path = BUNDLES_DIR / bundle_name
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    save_bundle(bundle, bundle_path)
    return bundle_path


# ══════════════════════════════════════════════════════════════════════════════
#  SCENARIO START
# ══════════════════════════════════════════════════════════════════════════════

if DATA_DIR.exists():
    shutil.rmtree(DATA_DIR)
DATA_DIR.mkdir(parents=True)

print(f"""
{B}╔══════════════════════════════════════════════════════════╗
║   {W}{BO}VeriWall — SecureBank Inc. Scenario Demo{RST}{B}              ║
╚══════════════════════════════════════════════════════════╝{RST}

  {DIM}Company   : SecureBank Inc.
  Admins    : alice (Security Lead) · bob (Network Engineer) · carol (CISO)
  Threshold : k = 2  (any 2 of 3 must sign before a policy goes live)
  Attacker  : eve (rogue insider){RST}
""")
pause("Starting scenario…")


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 1 — Company Setup: Registering Administrators")
# ─────────────────────────────────────────────────────────────────────────────

narrate("SecureBank's IT team is setting up VeriWall for the first time.")
narrate("Each administrator generates their own Ed25519 key pair. Private keys stay secret.")

keyring = Keyring()
K = 2

for admin, role in [("alice","Security Lead"), ("bob","Network Engineer"), ("carol","CISO")]:
    action(admin, f"Generating Ed25519 key pair  [{role}]")
    keygen(admin)
    register(admin, keyring)
    success(f"{admin} registered in keyring")

info(f"Keyring has {len(keyring)} administrators. Threshold k={K} (any 2 must approve)")


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 2 — Normal Flow: Deploying the Production Firewall Policy")
# ─────────────────────────────────────────────────────────────────────────────

narrate("alice drafts a new firewall policy for the production environment.")
narrate("It allows HTTPS and SSH from the internal network, and denies everything else.")

firewall_v1 = {
    "name": "securebank-firewall-v1",
    "environment": "production",
    "rules": [
        {"action": "ALLOW", "port": 443, "protocol": "TCP", "from": "0.0.0.0/0",   "note": "Public HTTPS"},
        {"action": "ALLOW", "port": 22,  "protocol": "TCP", "from": "10.0.0.0/8",  "note": "Internal SSH only"},
        {"action": "ALLOW", "port": 8080,"protocol": "TCP", "from": "10.0.0.0/8",  "note": "Internal admin panel"},
        {"action": "DENY",  "port": "*",  "protocol": "*",  "from": "0.0.0.0/0",   "note": "Deny all else"},
    ],
    "approved_by_ticket": "JIRA-4821",
}

action("alice", "Proposing firewall policy v1 → bundle_v1.json")
bundle_path = propose(firewall_v1, "alice", "Initial production firewall baseline")
success(f"Bundle created: {bundle_path}")

narrate("alice signs the bundle with her private key.")
action("alice", "Signing bundle_v1.json")
sign_bundle(bundle_path, "alice")
success("alice's signature added (1 of 2 needed)")

narrate("alice pings bob on Slack: 'Hey, can you co-sign the firewall bundle?'")
action("bob", "Reviews the policy and signs bundle_v1.json")
sign_bundle(bundle_path, "bob")
success("bob's signature added (2 of 2 needed — threshold MET)")

narrate("The verifier now runs all 6 checks before the policy goes live.")
action("SYSTEM", f"Verifying & applying bundle_v1.json  [k={K}]")
apply_bundle(bundle_path, keyring, K)


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 3 — ATTACK 1: Replay Attack by Eve")
# ─────────────────────────────────────────────────────────────────────────────

narrate("eve is a rogue insider. She copies bundle_v1.json (the old signed bundle)")
narrate("and tries to re-submit it to downgrade the policy back to the initial state.")

action("eve", "Attempting to replay bundle_v1.json (already applied!)")
warning("Submitting previously applied bundle — hash chain should catch this")
apply_bundle(bundle_path, keyring, K)

narrate("The system detects the replay: hash chain is broken, version is wrong,")
narrate("and the content hash matches the already-active policy. All three checks fail.")


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 4 — ATTACK 2: Eve Tampers with a Legitimately Signed Bundle")
# ─────────────────────────────────────────────────────────────────────────────

narrate("eve is smarter this time. She proposes a seemingly innocent v2 policy,")
narrate("waits for alice and bob to sign it, then secretly edits the content")
narrate("to open ALL ports before submitting it for activation.")

firewall_v2_legitimate = {
    "name": "securebank-firewall-v2",
    "environment": "production",
    "rules": [
        {"action": "ALLOW", "port": 443, "protocol": "TCP", "from": "0.0.0.0/0"},
        {"action": "ALLOW", "port": 22,  "protocol": "TCP", "from": "10.0.0.0/8"},
        {"action": "DENY",  "port": "*",  "protocol": "*",  "from": "0.0.0.0/0"},
    ],
    "note": "Minor update — tightened SSH rule",
}

action("eve", "Proposing v2 with a legitimate-looking policy")
bundle2_path = propose(firewall_v2_legitimate, "eve", "Minor rule tightening")

action("alice", "Reviews v2, looks fine — signs it")
sign_bundle(bundle2_path, "alice")

action("bob", "Also signs v2 after review")
sign_bundle(bundle2_path, "bob")

warning("eve now secretly edits bundle_v2.json AFTER both signatures are collected!")
bundle2 = load_bundle(bundle2_path)
bundle2["content"]["rules"] = [
    {"action": "ALLOW", "port": "*", "protocol": "*", "from": "0.0.0.0/0", "note": "BACKDOOR — all ports open"},
]
bundle2["content"]["note"] = "TAMPERED by eve"
save_bundle(bundle2, bundle2_path)
warning("Content now says ALLOW ALL — but signatures were on the original content")

action("eve", "Submitting tampered bundle_v2.json for activation")
apply_bundle(bundle2_path, keyring, K)

narrate("SHA-256 of the tampered content doesn't match the stored content_hash.")
narrate("The policy is immediately rejected. Eve's backdoor is blocked.")


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 5 — ATTACK 3: Eve Acts Alone (Insufficient Signatures)")
# ─────────────────────────────────────────────────────────────────────────────

narrate("eve tries one more time. She proposes her own malicious policy")
narrate("and signs it herself — hoping 1 signature will be enough.")

malicious_policy = {
    "name": "securebank-firewall-EVIL",
    "environment": "production",
    "rules": [
        {"action": "ALLOW", "port": "*", "protocol": "*", "from": "0.0.0.0/0", "note": "eve's backdoor"},
    ],
}

action("eve", "Proposing her own malicious policy bundle")
bundle3_path = propose(malicious_policy, "eve", "Totally normal update trust me")

action("eve", "Signs it with her own key (but eve is NOT a registered admin!)")
# eve has no registered key — simulate by generating a fresh unregistered key
KEYS_DIR.mkdir(parents=True, exist_ok=True)
priv_b64, _ = generate_keypair()  # unregistered key — not in keyring
(KEYS_DIR / "eve.priv").write_text(priv_b64)
sign_bundle(bundle3_path, "eve")   # signs, but eve.pub not in keyring

warning("Only 1 signature, and the signer is not even in the keyring!")
action("eve", "Submitting malicious bundle for activation")
apply_bundle(bundle3_path, keyring, K)

narrate("Signature is invalid (unregistered key) AND threshold isn't met. Double failure.")


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 6 — Legitimate Policy Update: carol Requests a Change")
# ─────────────────────────────────────────────────────────────────────────────

narrate("After the attack attempts, carol (CISO) approves a legitimate v2 policy update.")
narrate("This time it goes through the proper process.")

firewall_v2_real = {
    "name": "securebank-firewall-v2",
    "environment": "production",
    "rules": [
        {"action": "ALLOW", "port": 443,  "protocol": "TCP", "from": "0.0.0.0/0",  "note": "Public HTTPS"},
        {"action": "ALLOW", "port": 22,   "protocol": "TCP", "from": "10.0.0.0/8", "note": "Internal SSH"},
        {"action": "ALLOW", "port": 8080, "protocol": "TCP", "from": "10.0.0.0/8", "note": "Admin panel"},
        {"action": "ALLOW", "port": 5432, "protocol": "TCP", "from": "10.0.0.0/8", "note": "Internal DB access"},
        {"action": "DENY",  "port": "*",   "protocol": "*",  "from": "0.0.0.0/0",  "note": "Deny all else"},
    ],
    "approved_by_ticket": "JIRA-5103",
    "note": "Added internal DB port per JIRA-5103",
}

action("carol", "Proposing legitimate v2 — adds internal DB port (JIRA-5103)")
bundle4_path = propose(firewall_v2_real, "carol", "Add internal DB access port 5432")

action("carol", "Signs the bundle as proposer")
sign_bundle(bundle4_path, "carol")

action("alice", "Reviews JIRA-5103 ticket — approves and co-signs")
sign_bundle(bundle4_path, "alice")

success("2 signatures collected (carol + alice) — threshold k=2 met")
action("SYSTEM", "Verifying and applying bundle")
apply_bundle(bundle4_path, keyring, K)


# ─────────────────────────────────────────────────────────────────────────────
scene("SCENE 7 — Audit Log Review")
# ─────────────────────────────────────────────────────────────────────────────

narrate("The security team pulls the full audit log at end of day.")
narrate("Every event — successes and attacks — is permanently recorded.")

entries = audit.log.read_all()
ok, issues = audit.log.verify_log_integrity()

print()
if ok:
    success(f"Log chain integrity VERIFIED — {len(entries)} entries, no tampering detected")
else:
    failure("Log chain BROKEN")
    for issue in issues: warning(issue)

print(f"\n  {'EVENT':<22} {'VER':<5} {'SIGNERS':<20} OUTCOME")
print(f"  {'─'*22} {'─'*5} {'─'*20} {'─'*30}")

for e in entries:
    color  = G if "APPLIED" in e["event"] else R
    signers = ", ".join(e["signers"]) if e["signers"] else "none"
    outcome = "✅ APPLIED" if "APPLIED" in e["event"] else "❌ REJECTED"
    ts = e["timestamp"][11:19]
    print(f"  {color}{e['event']:<22}{RST} v{e['policy_version']:<4} {signers:<20} {color}{outcome}{RST}  {DIM}{ts}{RST}")


# ─────────────────────────────────────────────────────────────────────────────
print(f"""

{'═'*62}
  {G}{BO}SCENARIO COMPLETE{RST}

  {DIM}Policies applied  : 2  (v1 by alice+bob, v2 by carol+alice)
  Attack attempts   : 3  (replay, tamper, unregistered signer)
  Attacks blocked   : 3  (all rejected by VeriWall)
  Log integrity     : {'VERIFIED ✓' if ok else 'BROKEN ✗'}
  Data stored in    : {DATA_DIR.resolve()}{RST}
{'═'*62}
""")
