#!/usr/bin/env python3
"""
VeriWall Web Server v2 — Superadmin + Threshold-Voted Registration
──────────────────────────────────────────────────────────────────
Flow:
  1. Superadmin generates keys + registers (SUPERADMIN_SECRET, no vote)
  2. Superadmin invites new admin → creates a vote bundle (auto-signs it)
  3. Other registered admins sign the vote bundle
  4. Once k valid signatures → "Admit Admin" button appears → admin joins keyring
  5. Normal policy workflow: propose → sign (k admins) → apply

Env vars:
  SUPERADMIN_ID      (default: superadmin)
  SUPERADMIN_SECRET  (default: veriwall-root-2026)
  POLICY_THRESHOLD   (default: 2)
"""

from flask import Flask, request, jsonify, render_template_string
import json, sys, shutil, os
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from veriwall.core.signer      import generate_keypair, sign, verify_signature
from veriwall.core.hasher      import canonical_json
from veriwall.core.verifier    import verify_bundle
from veriwall.keyring.registry import Keyring
from veriwall.policy.packager  import create_bundle, add_signature, save_bundle, load_bundle, load_state
from veriwall.policy.enforcer  import apply_policy, get_active_policy
from veriwall import audit

app = Flask(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_IS_CLOUD   = bool(os.getenv("RENDER") or os.getenv("RAILWAY_ENVIRONMENT"))
BASE        = Path("/tmp/veriwall_data") if _IS_CLOUD else Path("veriwall_data")
KEYS_DIR    = BASE / "keys"
BUNDLES_DIR = BASE / "bundles"
VOTES_DIR   = BASE / "votes"
BASE.mkdir(parents=True, exist_ok=True)

import veriwall.keyring.registry as _kr
import veriwall.policy.packager  as _pk
import veriwall.policy.enforcer  as _en
import veriwall.audit            as _au

def _patch_paths():
    _kr.KEYRING_PATH        = BASE / "keyring.json"
    _pk.DATA_DIR            = BASE
    _pk.STATE_PATH          = BASE / "state.json"
    _pk.BUNDLES_DIR         = BUNDLES_DIR
    _en.DATA_DIR            = BASE
    _en.ACTIVE_POLICY_PATH  = BASE / "active_policy.json"
    _au.LOG_PATH            = BASE / "audit.jsonl"
    _au.log.__class__._log_path = BASE / "audit.jsonl"

_patch_paths()

# ── Config ────────────────────────────────────────────────────────────────────
SUPERADMIN_ID     = os.getenv("SUPERADMIN_ID",     "superadmin")
SUPERADMIN_SECRET = os.getenv("SUPERADMIN_SECRET", "veriwall-root-2026")
POLICY_THRESHOLD  = int(os.getenv("POLICY_THRESHOLD", "2"))

# ── Helpers ───────────────────────────────────────────────────────────────────
def ts():
    return datetime.now(timezone.utc).isoformat()

def vote_message(vote):
    return canonical_json({
        "action":     vote["action"],
        "target_id":  vote["target_id"],
        "target_pub": vote["target_pub"],
        "vote_id":    vote["vote_id"],
        "timestamp":  vote["timestamp"],
    })

def load_votes():
    VOTES_DIR.mkdir(parents=True, exist_ok=True)
    return [json.loads(p.read_text()) for p in sorted(VOTES_DIR.glob("*.json"))]

def save_vote(vote):
    VOTES_DIR.mkdir(parents=True, exist_ok=True)
    (VOTES_DIR / f"{vote['vote_id']}.json").write_text(json.dumps(vote, indent=2))

def load_vote(vote_id):
    p = VOTES_DIR / f"{vote_id}.json"
    return json.loads(p.read_text()) if p.exists() else None

def count_valid_votes(vote):
    keyring = Keyring().all()
    msg     = vote_message(vote)
    valid, invalid = [], []
    for entry in vote.get("signatures", []):
        aid = entry["admin_id"]
        pub = keyring.get(aid)
        if pub and verify_signature(pub, msg, entry["signature"]):
            valid.append(aid)
        else:
            invalid.append(aid)
    return valid, invalid

# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VeriWall</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#050810;--surf:#0c1120;--border:#1a2540;
  --accent:#00e5ff;--green:#00ff9d;--red:#ff3d5a;
  --yellow:#ffd93d;--purple:#b388ff;--orange:#ffab40;
  --text:#e2e8f0;--dim:#718096;--muted:#4a5568;
  --mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;
  background-image:radial-gradient(ellipse at 15% 15%,rgba(0,229,255,.05) 0%,transparent 55%),
  radial-gradient(ellipse at 85% 85%,rgba(179,136,255,.04) 0%,transparent 55%)}
header{border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;gap:16px;
  background:rgba(12,17,32,.9);backdrop-filter:blur(12px);position:sticky;top:0;z-index:100}
.logo{font-family:var(--sans);font-weight:800;font-size:1.3rem;color:var(--accent)}
.logo span{color:var(--green)}
.tagline{font-size:.6rem;color:var(--dim);letter-spacing:2px;text-transform:uppercase}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.who{background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.25);color:var(--accent);
  padding:4px 12px;border-radius:4px;font-size:.72rem}
.who.sa{background:rgba(255,171,64,.1);border-color:rgba(255,171,64,.3);color:var(--orange)}
.layout{display:grid;grid-template-columns:240px 1fr 280px;min-height:calc(100vh - 57px)}
.sidebar{border-right:1px solid var(--border);padding:20px 12px;display:flex;flex-direction:column;gap:4px}
.sl{font-size:.58rem;letter-spacing:2px;color:var(--muted);text-transform:uppercase;padding:14px 8px 5px}
.nb{background:none;border:1px solid transparent;color:var(--dim);padding:9px 11px;border-radius:6px;
  cursor:pointer;font-family:var(--mono);font-size:.75rem;text-align:left;transition:all .15s;
  display:flex;align-items:center;gap:9px;width:100%}
.nb:hover{border-color:var(--border);color:var(--text);background:var(--surf)}
.nb.active{border-color:var(--accent);color:var(--accent);background:rgba(0,229,255,.05)}
.nb.sa{color:var(--orange)}.nb.sa.active{border-color:var(--orange);background:rgba(255,171,64,.05)}
.bc{margin-left:auto;background:var(--red);color:#fff;border-radius:10px;padding:1px 7px;
  font-size:.6rem;font-weight:700;display:none}
.bc.show{display:inline-block}
.idbox{margin-top:auto;border-top:1px solid var(--border);padding-top:14px}
.idbox select,.idbox input{width:100%;background:var(--bg);border:1px solid var(--border);
  color:var(--text);padding:8px 10px;border-radius:6px;font-family:var(--mono);font-size:.74rem;
  cursor:pointer;margin-bottom:8px}
.idbox select:focus,.idbox input:focus{outline:none;border-color:var(--accent)}
main{padding:26px 28px;overflow-y:auto}
.page{display:none}.page.active{display:block}
h2{font-family:var(--sans);font-size:1.2rem;font-weight:800;margin-bottom:5px}
.pd{color:var(--dim);font-size:.73rem;margin-bottom:22px;line-height:1.65}
.card{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:14px}
.ct{font-size:.62rem;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:12px}
.ct.o{color:var(--orange)}.ct.p{color:var(--purple)}
.vc{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:10px;transition:border-color .15s}
.vc:hover{border-color:var(--purple)}
.vc.done{border-color:rgba(0,255,157,.3)}.vc.rj{border-color:rgba(255,61,90,.3)}
.vc-h{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.vcp{margin:10px 0;display:flex;align-items:center;gap:8px}
.pb{flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden}
.pf{height:100%;background:var(--purple);border-radius:3px;transition:width .3s}
.pf.met{background:var(--green)}
.field{margin-bottom:12px}
.field label{display:block;font-size:.65rem;color:var(--dim);letter-spacing:1px;text-transform:uppercase;margin-bottom:5px}
input[type=text],input[type=password],input[type=number],textarea,select.fs{
  width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);
  padding:9px 11px;border-radius:6px;font-family:var(--mono);font-size:.8rem;transition:border-color .15s}
input:focus,textarea:focus,select.fs:focus{outline:none;border-color:var(--accent)}
textarea{resize:vertical;min-height:110px;line-height:1.5}
.btn{padding:9px 18px;border-radius:6px;border:none;font-family:var(--mono);font-size:.78rem;
  font-weight:600;cursor:pointer;transition:all .15s}
.bp{background:var(--accent);color:var(--bg)}.bp:hover{background:#33eaff;box-shadow:0 0 18px rgba(0,229,255,.3)}
.bg{background:var(--green);color:var(--bg)}.bg:hover{box-shadow:0 0 18px rgba(0,255,157,.3)}
.br{background:var(--red);color:#fff}.bo{background:var(--orange);color:var(--bg)}
.bpu{background:var(--purple);color:var(--bg)}
.btn:disabled{opacity:.35;cursor:not-allowed}
.bsm{padding:5px 12px;font-size:.7rem}
.rbox{background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:12px 14px;
  margin-top:12px;font-size:.73rem;line-height:1.7;white-space:pre-wrap;word-break:break-all;
  max-height:220px;overflow-y:auto;color:var(--dim);display:none}
.rbox.v{display:block}.rbox.ok{border-color:var(--green);color:var(--green)}
.rbox.err{border-color:var(--red);color:var(--red)}
.checks{display:flex;flex-direction:column;gap:5px;margin:8px 0}
.chk{display:flex;align-items:center;gap:9px;font-size:.73rem;padding:6px 9px;
  border-radius:5px;background:rgba(255,255,255,.02);border:1px solid var(--border)}
.chk.pass{border-color:rgba(0,255,157,.2)}.chk.fail{border-color:rgba(255,61,90,.2)}
.chk-n{flex:1}.chk-d{color:var(--dim);font-size:.65rem}
.panel{border-left:1px solid var(--border);padding:20px 16px;overflow-y:auto}
.pt{font-family:var(--sans);font-size:.82rem;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:7px}
.sc{background:var(--surf);border:1px solid var(--border);border-radius:7px;padding:12px;margin-bottom:10px}
.sc .lbl{font-size:.58rem;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.sc .val{font-size:.78rem;word-break:break-all;line-height:1.4}
.badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:.62rem;font-weight:600;letter-spacing:1px;text-transform:uppercase}
.bdg{background:rgba(0,255,157,.15);color:var(--green);border:1px solid rgba(0,255,157,.3)}
.bdr{background:rgba(255,61,90,.15);color:var(--red);border:1px solid rgba(255,61,90,.3)}
.bdb{background:rgba(0,229,255,.15);color:var(--accent);border:1px solid rgba(0,229,255,.3)}
.bdo{background:rgba(255,171,64,.15);color:var(--orange);border:1px solid rgba(255,171,64,.3)}
.bdp{background:rgba(179,136,255,.15);color:var(--purple);border:1px solid rgba(179,136,255,.3)}
.le{border-left:2px solid var(--border);padding:6px 10px;margin-bottom:8px;font-size:.7rem;line-height:1.5}
.le.ap{border-color:var(--green)}.le.rj{border-color:var(--red)}.le.sa{border-color:var(--orange)}.le.vt{border-color:var(--purple)}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.mt16{margin-top:16px}
.ib{padding:9px 12px;border-radius:6px;font-size:.7rem;color:var(--dim);line-height:1.6;margin-bottom:14px;border:1px solid}
.ib.a{background:rgba(0,229,255,.04);border-color:rgba(0,229,255,.12)}
.ib.o{background:rgba(255,171,64,.04);border-color:rgba(255,171,64,.15)}
.ib.p{background:rgba(179,136,255,.04);border-color:rgba(179,136,255,.15)}
.ar{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:.75rem}
.ar:last-child{border:none}
#toast{position:fixed;bottom:20px;right:20px;background:var(--surf);border:1px solid var(--border);
  border-radius:8px;padding:11px 16px;font-size:.76rem;opacity:0;transform:translateY(8px);
  transition:all .22s;z-index:999;max-width:300px}
#toast.show{opacity:1;transform:translateY(0)}
#toast.ok{border-color:var(--green);color:var(--green)}
#toast.err{border-color:var(--red);color:var(--red)}
#toast.info{border-color:var(--purple);color:var(--purple)}
@media(max-width:900px){.layout{grid-template-columns:1fr}.sidebar,.panel{display:none}}
</style>
</head>
<body>
<header>
  <div><div class="logo">Veri<span>Wall</span></div>
  <div class="tagline">Threshold-Signed Policy Enforcement</div></div>
  <div class="hdr-right">
    <div id="hdr-who" class="who">👤 Not identified</div>
  </div>
</header>
<div class="layout">
<nav class="sidebar">
  <div class="sl">🔐 Superadmin</div>
  <button class="nb sa" id="nav-sasetup" onclick="showPage('sasetup')"><span>⚙️</span> SA Setup</button>
  <button class="nb sa" id="nav-invite"  onclick="showPage('invite')"><span>➕</span> Invite Admin</button>
  <div class="sl">🗳 Voting</div>
  <button class="nb" id="nav-votes" onclick="showPage('votes')">
    <span>🗳️</span> Vote on Admins <span class="bc" id="vote-badge">0</span>
  </button>
  <div class="sl">📋 Policy</div>
  <button class="nb" id="nav-keygen"  onclick="showPage('keygen')"><span>🔑</span> Key Generation</button>
  <button class="nb" id="nav-propose" onclick="showPage('propose')"><span>📄</span> Propose Policy</button>
  <button class="nb" id="nav-sign"    onclick="showPage('sign')"><span>✍️</span> Sign Bundle</button>
  <button class="nb" id="nav-apply"   onclick="showPage('apply')"><span>🚀</span> Apply Bundle</button>
  <div class="sl">🔍 Inspect</div>
  <button class="nb" id="nav-status" onclick="showPage('status')"><span>📊</span> Status</button>
  <button class="nb" id="nav-audit"  onclick="showPage('audit')"><span>📜</span> Audit Log</button>
  <button class="nb" id="nav-demo"   onclick="showPage('demo')"><span>⚡</span> Full Demo</button>
  <div class="idbox">
    <div class="sl">Identity</div>
    <select id="idSel" onchange="switchId()">
      <option value="">— who are you? —</option>
      <option value="superadmin">👑 superadmin</option>
      <option value="custom">type your admin ID…</option>
    </select>
    <input type="text" id="customId" placeholder="type your admin ID here" style="display:block"/>
    <input type="password" id="idSec" placeholder="superadmin secret" style="display:none"/>
  </div>
</nav>

<main>
  <!-- SA Setup -->
  <div class="page active" id="page-sasetup">
    <h2>Superadmin Setup</h2>
    <p class="pd">The superadmin is the root of trust. They register once using a special secret — no vote required. After that, they invite admins whose additions require threshold voting.</p>
    <div class="ib o">👑 Superadmin ID: <strong id="sa-id-disp">…</strong>
      &nbsp;·&nbsp; Set via <code>SUPERADMIN_ID</code> env var.<br/>
      Secret set via <code>SUPERADMIN_SECRET</code> env var (never shown in UI).
    </div>
    <div class="card">
      <div class="ct o">Step 1 — Generate Superadmin Keys</div>
      <div class="field"><label>Superadmin Secret</label>
        <input type="password" id="sa-sk1" placeholder="superadmin secret"/></div>
      <button class="btn bo" onclick="doSAKeygen()">Generate SA Key Pair</button>
      <div class="rbox" id="sa-kg-r"></div>
    </div>
    <div class="card">
      <div class="ct o">Step 2 — Self-Register (No Vote Needed)</div>
      <div class="field"><label>Superadmin Secret</label>
        <input type="password" id="sa-sk2" placeholder="superadmin secret"/></div>
      <button class="btn bo" onclick="doSAReg()">Register as Superadmin</button>
      <div class="rbox" id="sa-rg-r"></div>
    </div>
  </div>

  <!-- Invite -->
  <div class="page" id="page-invite">
    <h2>Invite Admin</h2>
    <p class="pd">Superadmin proposes adding a new admin. A vote bundle is created and auto-signed by the superadmin. Other registered admins must vote to reach threshold k.</p>
    <div class="ib p">🗳️ The invitee should first run <strong>Key Generation</strong> and share their public key with you.<br/>
      Threshold: <strong id="inv-thresh">k=?</strong> valid votes from registered admins required.
    </div>
    <div class="card">
      <div class="ct o">Create Invitation</div>
      <div class="field"><label>Superadmin Secret</label>
        <input type="password" id="inv-sas" placeholder="superadmin secret"/></div>
      <div class="g2">
        <div class="field"><label>New Admin ID</label>
          <input type="text" id="inv-id" placeholder="your admin ID"/></div>
        <div class="field"><label>New Admin's Public Key (base64)</label>
          <input type="text" id="inv-pub" placeholder="paste from keygen output"/></div>
      </div>
      <button class="btn bo" onclick="doInvite()">Create Invitation + Vote Bundle</button>
      <div class="rbox" id="inv-r"></div>
    </div>
  </div>

  <!-- Votes -->
  <div class="page" id="page-votes">
    <h2>Vote on Admin Invitations</h2>
    <p class="pd">Sign a vote bundle to approve a new admin. Once k valid signatures are collected, the "Admit Admin" button appears.</p>
    <div class="field" style="margin-bottom:16px">
      <label>Your Admin ID</label>
      <input type="text" id="v-signer" placeholder="your admin ID"/>
    </div>
    <div id="vote-list"><div style="color:var(--dim);font-size:.75rem">Loading…</div></div>
  </div>

  <!-- Keygen -->
  <div class="page" id="page-keygen">
    <h2>Key Generation</h2>
    <p class="pd">Generate your Ed25519 key pair. Copy the public key and share it with the superadmin so they can create your invitation.</p>
    <div class="card">
      <div class="ct">Generate Keys</div>
      <div class="field"><label>Admin ID</label>
        <input type="text" id="kg-id" placeholder="your admin ID"/></div>
      <button class="btn bp" onclick="doKeygen()">Generate Key Pair</button>
      <div class="rbox" id="kg-r"></div>
    </div>
  </div>

  <!-- Propose -->
  <div class="page" id="page-propose">
    <h2>Propose Policy</h2>
    <p class="pd">Create an unsigned policy bundle. Only registered admins can propose.</p>
    <div class="card">
      <div class="ct">New Policy Bundle</div>
      <div class="g2">
        <div class="field"><label>Author (your Admin ID)</label>
          <input type="text" id="pr-auth" placeholder="your admin ID"/></div>
        <div class="field"><label>Description</label>
          <input type="text" id="pr-desc" placeholder="e.g. Initial firewall rules"/></div>
      </div>
      <div class="field"><label>Policy Content (JSON)</label>
        <textarea id="pr-content"></textarea></div>
      <button class="btn bp" onclick="doPropose()">Create Bundle</button>
      <div class="rbox" id="pr-r"></div>
    </div>
  </div>

  <!-- Sign -->
  <div class="page" id="page-sign">
    <h2>Sign Policy Bundle</h2>
    <p class="pd">Sign a policy bundle as a registered admin.</p>
    <div class="card">
      <div class="ct">Available Bundles</div>
      <div id="bundle-list"><div style="color:var(--dim);font-size:.75rem">Loading…</div></div>
      <div class="field mt16"><label>Your Admin ID</label>
        <input type="text" id="sg-admin" placeholder="your admin ID"/></div>
      <button class="btn bg" onclick="doSign()">Sign Selected Bundle</button>
      <div class="rbox" id="sg-r"></div>
    </div>
  </div>

  <!-- Apply -->
  <div class="page" id="page-apply">
    <h2>Apply Policy Bundle</h2>
    <p class="pd">Run all 6 verification checks and atomically apply a policy.</p>
    <div class="card">
      <div class="ct">Select Bundle</div>
      <div id="apply-bundle-list"><div style="color:var(--dim);font-size:.75rem">Loading…</div></div>
      <div class="field mt16"><label>Threshold k</label>
        <input type="number" id="ap-k" value="2" min="1" max="10" style="width:80px"/></div>
      <button class="btn br" onclick="doApply()">Verify &amp; Apply</button>
      <div id="ap-checks" class="checks mt16" style="display:none"></div>
      <div class="rbox" id="ap-r"></div>
    </div>
  </div>

  <!-- Status -->
  <div class="page" id="page-status">
    <h2>System Status</h2>
    <p class="pd">Current keyring, policy, and vote state.</p>
    <div id="status-content"><div style="color:var(--dim);font-size:.75rem">Loading…</div></div>
  </div>

  <!-- Audit -->
  <div class="page" id="page-audit">
    <h2>Audit Log</h2>
    <p class="pd">Hash-chained record of every event — registrations, votes, policy changes.</p>
    <div id="audit-integ" class="card" style="margin-bottom:14px"></div>
    <div id="audit-entries"></div>
  </div>

  <!-- Demo -->
  <div class="page" id="page-demo">
    <h2>Full Automated Demo</h2>
    <p class="pd">Wipes all data. Runs full flow with 3 auto-named admins (admin1/admin2/admin3) to show the complete workflow.</p>
    <div class="card">
      <div class="ct" style="color:var(--red)">⚠ Destructive — deletes all data</div>
      <button class="btn br" onclick="doDemo()">Run Full Demo</button>
      <div class="rbox" id="dm-r"></div>
    </div>
  </div>
</main>

<aside class="panel">
  <div class="pt">⚡ Live State</div>
  <div class="sc"><div class="lbl">Superadmin</div><div class="val" id="lv-sa">checking…</div></div>
  <div class="sc"><div class="lbl">Keyring</div><div class="val" id="lv-kr">—</div></div>
  <div class="sc"><div class="lbl">Active Policy</div><div class="val" id="lv-pol">none</div></div>
  <div class="sc"><div class="lbl">Pending Votes</div><div class="val" id="lv-vt">0</div></div>
  <div class="pt mt16">📋 Recent Events</div>
  <div id="recent-ev"><div style="color:var(--dim);font-size:.7rem">No events yet.</div></div>
</aside>
</div>
<div id="toast"></div>

<script>
let selBundle=null;

function showPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  const nb=document.getElementById('nav-'+id); if(nb) nb.classList.add('active');
  if(id==='votes') loadVotes();
  if(id==='sign'||id==='apply') loadBundles(id);
  if(id==='status') loadStatus();
  if(id==='audit')  loadAudit();
}

function switchId(){
  const v=document.getElementById('idSel').value;
  const ci=document.getElementById('customId');
  const sec=document.getElementById('idSec');
  // custom input always shown unless superadmin selected
  ci.style.display=v==='superadmin'?'none':'block';
  sec.style.display=v==='superadmin'?'block':'none';
  if(v==='superadmin'){
    applyIdentity('superadmin',true);
  }
  // for custom, wait for user to type
}
function applyIdentity(id, isSA){
  if(!id.trim()) return;
  const badge=document.getElementById('hdr-who');
  badge.textContent=(isSA?'👑 ':'👤 ')+id;
  badge.className='who'+(isSA?' sa':'');
  ['kg-id','sg-admin','pr-auth','v-signer'].forEach(fid=>{
    const el=document.getElementById(fid); if(el) el.value=id;
  });
}

function toast(msg,type='ok'){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className='show '+type;
  setTimeout(()=>t.className='',3200);
}
function setRes(id,msg,ok){
  const el=document.getElementById(id);
  el.textContent=msg; el.className='rbox v '+(ok?'ok':'err');
}
async function api(path,body={}){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  return r.json();
}

// SA Setup
async function doSAKeygen(){
  const s=document.getElementById('sa-sk1').value.trim();
  if(!s) return toast('Enter superadmin secret','err');
  const r=await api('/api/sa/keygen',{secret:s});
  setRes('sa-kg-r',r.message,r.ok);
  toast(r.ok?'SA keys generated':r.message,r.ok?'ok':'err');
  refreshPanel();
}
async function doSAReg(){
  const s=document.getElementById('sa-sk2').value.trim();
  if(!s) return toast('Enter superadmin secret','err');
  const r=await api('/api/sa/register',{secret:s});
  setRes('sa-rg-r',r.message,r.ok);
  toast(r.ok?'Superadmin registered!':r.message,r.ok?'ok':'err');
  refreshPanel();
}

// Invite
async function doInvite(){
  const secret=document.getElementById('inv-sas').value.trim();
  const admin_id=document.getElementById('inv-id').value.trim();
  const pub_key=document.getElementById('inv-pub').value.trim();
  if(!secret) return toast('Enter superadmin secret','err');
  if(!admin_id||!pub_key) return toast('Fill in admin ID and public key','err');
  const r=await api('/api/sa/invite',{secret,admin_id,pub_key});
  setRes('inv-r',r.message,r.ok);
  toast(r.ok?'Invitation created!':r.message,r.ok?'info':'err');
  refreshPanel();
}

// Votes
async function loadVotes(){
  const res=await api('/api/votes');
  const el=document.getElementById('vote-list');
  const badge=document.getElementById('vote-badge');
  if(!res.votes||!res.votes.length){
    el.innerHTML='<div style="color:var(--dim);font-size:.75rem">No vote bundles yet. Superadmin must invite admins first.</div>';
    badge.classList.remove('show'); return;
  }
  const pending=res.votes.filter(v=>v.status==='pending'||v.status==='ready');
  badge.textContent=pending.length;
  pending.length?badge.classList.add('show'):badge.classList.remove('show');

  el.innerHTML=res.votes.map(v=>{
    const pct=Math.min(100,Math.round((v.valid_sigs/v.threshold)*100));
    const met=v.valid_sigs>=v.threshold;
    const isDone=v.status==='approved';
    return `<div class="vc ${isDone?'done':v.status==='rejected'?'rj':''}">
      <div class="vc-h">
        <span class="badge ${isDone?'bdg':met?'bdg':'bdp'}">${v.status.toUpperCase()}</span>
        <span style="font-size:.9rem;font-weight:600">➕ ${v.target_id}</span>
        <span style="font-size:.65rem;color:var(--dim);margin-left:auto">${v.timestamp.slice(0,16).replace('T',' ')}</span>
      </div>
      <div style="font-size:.67rem;color:var(--dim);margin-bottom:8px">
        Proposed by: <span style="color:var(--orange)">${v.proposed_by}</span>
        &nbsp;·&nbsp; Pub: <span style="color:var(--accent)">${v.target_pub.slice(0,24)}…</span>
      </div>
      <div class="vcp">
        <span style="font-size:.65rem;color:var(--dim)">${v.valid_sigs}/${v.threshold}</span>
        <div class="pb"><div class="pf ${met?'met':''}" style="width:${pct}%"></div></div>
        <span style="font-size:.65rem;color:${met?'var(--green)':'var(--purple)'}">${met?'✓ THRESHOLD MET':'waiting…'}</span>
      </div>
      <div style="font-size:.68rem;color:var(--dim);margin-bottom:8px">
        Signed by: <span style="color:var(--accent)">${v.signers.join(', ')||'none yet'}</span>
      </div>
      ${!isDone?`<div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn bpu bsm" onclick="doVoteSign('${v.vote_id}')">✍️ Sign as <span id="vsw-${v.vote_id}">${document.getElementById('v-signer').value||'…'}</span></button>
        ${met?`<button class="btn bg bsm" onclick="doApprove('${v.vote_id}')">✅ Admit Admin</button>`:''}
      </div>`:'<span class="badge bdg">✓ Admitted</span>'}
    </div>`;
  }).join('');
}

async function doVoteSign(vote_id){
  const signer=document.getElementById('v-signer').value.trim();
  if(!signer) return toast('Enter your admin ID first','err');
  const r=await api('/api/votes/sign',{vote_id,admin_id:signer});
  toast(r.ok?'Vote signed!':r.message,r.ok?'ok':'err');
  loadVotes(); refreshPanel();
}
async function doApprove(vote_id){
  const r=await api('/api/votes/approve',{vote_id});
  toast(r.ok?'✅ Admin admitted!':r.message,r.ok?'ok':'err');
  loadVotes(); refreshPanel();
}

// Keygen
async function doKeygen(){
  const id=document.getElementById('kg-id').value.trim();
  if(!id) return toast('Enter admin ID','err');
  const r=await api('/api/keygen',{admin_id:id});
  setRes('kg-r',r.message,r.ok);
  toast(r.ok?'Keys generated for '+id:r.message,r.ok?'ok':'err');
}

// Propose
async function doPropose(){
  const author=document.getElementById('pr-auth').value.trim();
  const desc=document.getElementById('pr-desc').value.trim();
  const raw=document.getElementById('pr-content').value.trim();
  if(!author||!raw) return toast('Fill in author and JSON','err');
  let content; try{content=JSON.parse(raw)}catch(e){return toast('Invalid JSON: '+e.message,'err')}
  const r=await api('/api/propose',{author,description:desc,content});
  setRes('pr-r',r.message,r.ok);
  toast(r.ok?'Bundle created':r.message,r.ok?'ok':'err');
  refreshPanel();
}

// Bundles
async function loadBundles(page){
  const r=await api('/api/bundles');
  const lid=page==='sign'?'bundle-list':'apply-bundle-list';
  const el=document.getElementById(lid);
  if(!r.bundles||!r.bundles.length){el.innerHTML='<div style="color:var(--dim);font-size:.75rem">No bundles yet.</div>';return}
  el.innerHTML=r.bundles.map(b=>`
    <div style="background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:11px 13px;
      margin-bottom:8px;cursor:pointer;transition:border-color .15s" id="bi-${b.name}"
      onclick="selBun('${b.path}','${b.name}','${page}')">
      <div style="font-size:.8rem">${b.name}</div>
      <div style="font-size:.65rem;color:var(--dim)">v${b.version} · ${b.author} · ${b.timestamp}</div>
      <div style="font-size:.65rem;margin-top:3px">${b.sig_count} sig(s): <span style="color:var(--accent)">${b.signers}</span></div>
    </div>`).join('');
}
function selBun(path,name,page){
  selBundle=path;
  const lid=page==='sign'?'bundle-list':'apply-bundle-list';
  document.querySelectorAll('#'+lid+' [id^="bi-"]').forEach(e=>e.style.borderColor='');
  const el=document.getElementById('bi-'+name); if(el) el.style.borderColor='var(--accent)';
}

// Sign
async function doSign(){
  const admin=document.getElementById('sg-admin').value.trim();
  if(!admin) return toast('Enter your admin ID','err');
  if(!selBundle) return toast('Select a bundle','err');
  const r=await api('/api/sign',{bundle_path:selBundle,admin_id:admin});
  setRes('sg-r',r.message,r.ok);
  toast(r.ok?admin+' signed bundle':r.message,r.ok?'ok':'err');
  loadBundles('sign'); refreshPanel();
}

// Apply
async function doApply(){
  const k=parseInt(document.getElementById('ap-k').value)||2;
  if(!selBundle) return toast('Select a bundle','err');
  const r=await api('/api/apply',{bundle_path:selBundle,threshold_k:k});
  const ce=document.getElementById('ap-checks');
  if(r.checks){
    ce.style.display='flex';
    ce.innerHTML=r.checks.map(c=>`
      <div class="chk ${c.passed?'pass':'fail'}">
        <span style="width:18px;text-align:center">${c.passed?'✓':'✗'}</span>
        <span class="chk-n">${c.check.replace(/_/g,' ')}</span>
        <span class="chk-d">${c.detail}</span>
      </div>`).join('');
  }
  setRes('ap-r',r.message,r.ok);
  toast(r.ok?'✅ Policy APPLIED':'❌ Rejected',r.ok?'ok':'err');
  loadBundles('apply'); refreshPanel();
}

// Status
async function loadStatus(){
  const r=await api('/api/status');
  const el=document.getElementById('status-content');
  if(!r.ok){el.innerHTML='<div style="color:var(--red)">Error</div>';return}
  el.innerHTML=`
    <div class="card">
      <div class="ct">Keyring — ${r.keyring.length} Admin(s)</div>
      ${r.keyring.map(a=>`
        <div class="ar">
          <span style="color:var(--accent);font-weight:600;width:110px">${a.id}</span>
          <span style="color:var(--dim);font-size:.65rem;flex:1">${a.pub.slice(0,28)}…</span>
          <span class="badge ${a.is_sa?'bdo':'bdb'}">${a.is_sa?'SUPERADMIN':'ADMIN'}</span>
        </div>`).join('')||'<div style="color:var(--dim);font-size:.75rem">Empty</div>'}
    </div>
    <div class="card">
      <div class="ct">Active Policy</div>
      <span class="badge bdb">v${r.state.active_version}</span>
      <span class="badge ${r.state.active_content_hash?'bdg':'bdr'}" style="margin-left:6px">${r.state.active_content_hash?'ACTIVE':'NONE'}</span>
      ${r.active_policy?`<pre style="font-size:.67rem;color:var(--dim);margin-top:10px;overflow:auto;max-height:180px">${JSON.stringify(r.active_policy,null,2)}</pre>`:''}
    </div>
    <div class="card">
      <div class="ct p">Votes</div>
      Pending: <span style="color:var(--purple)">${r.votes_pending}</span> &nbsp;
      Approved: <span style="color:var(--green)">${r.votes_approved}</span>
    </div>`;
}

// Audit
async function loadAudit(){
  const r=await api('/api/audit');
  document.getElementById('audit-integ').innerHTML=r.integrity_ok
    ?`<div class="ct">Log Chain Integrity</div><span class="badge bdg">VERIFIED ✓</span> <span style="color:var(--dim);font-size:.7rem">${r.entries.length} entries</span>`
    :`<div class="ct">Log Chain Integrity</div><span class="badge bdr">BROKEN ✗</span>`;
  const el=document.getElementById('audit-entries');
  if(!r.entries.length){el.innerHTML='<div style="color:var(--dim);font-size:.75rem">Empty.</div>';return}
  const cm={POLICY_APPLIED:'ap',POLICY_REJECTED:'rj',ADMIN_REGISTERED:'sa',
    VOTE_SIGNED:'vt',ADMIN_ADMITTED:'sa',SA_REGISTERED:'sa',VOTE_CREATED:'vt'};
  el.innerHTML=r.entries.slice().reverse().map(e=>`
    <div class="le ${cm[e.event]||''}">
      <div style="font-weight:600;margin-bottom:2px">
        <span class="badge ${['POLICY_APPLIED','ADMIN_ADMITTED','SA_REGISTERED','ADMIN_REGISTERED'].includes(e.event)?'bdg':'bdr'}" style="font-size:.6rem">${e.event}</span>
        ${e.policy_version?'v'+e.policy_version:''}
      </div>
      <div style="color:var(--dim);font-size:.63rem">${e.timestamp.slice(0,19).replace('T',' ')} · ${e.signers.join(', ')||'—'}</div>
      ${e.detail?`<div style="color:var(--dim);font-size:.65rem;margin-top:2px">${e.detail}</div>`:''}
    </div>`).join('');
}

// Demo
async function doDemo(){
  document.getElementById('dm-r').textContent='Running…';
  document.getElementById('dm-r').className='rbox v';
  const r=await api('/api/demo');
  setRes('dm-r',r.output,r.ok);
  toast(r.ok?'Demo complete!':'Failed',r.ok?'ok':'err');
  refreshPanel();
}

// Panel refresh
async function refreshPanel(){
  try{
    const [sr,vr,ar]=await Promise.all([api('/api/status'),api('/api/votes'),api('/api/audit')]);
    const saReg=sr.keyring.some(a=>a.is_sa);
    document.getElementById('lv-sa').innerHTML=saReg?`<span class="badge bdo">REGISTERED</span>`:`<span class="badge bdr">NOT YET</span>`;
    document.getElementById('lv-kr').textContent=sr.keyring.length+' admin(s): '+sr.keyring.map(a=>a.id).join(', ');
    document.getElementById('lv-pol').innerHTML=sr.state.active_content_hash
      ?`<span class="badge bdb">v${sr.state.active_version} active</span>`
      :`<span style="color:var(--dim)">none</span>`;
    const pending=(vr.votes||[]).filter(v=>v.status==='pending'||v.status==='ready').length;
    document.getElementById('lv-vt').innerHTML=`<span class="badge ${pending?'bdp':'bdg'}">${pending} pending</span>`;
    const vb=document.getElementById('vote-badge');
    vb.textContent=pending; pending?vb.classList.add('show'):vb.classList.remove('show');
    // SA id + threshold displays
    const s=document.getElementById('sa-id-disp'); if(s) s.textContent=sr.superadmin_id;
    const it=document.getElementById('inv-thresh'); if(it) it.textContent='k='+sr.threshold;
    // Recent events
    const recent=(ar.entries||[]).slice(-5).reverse();
    const cm={POLICY_APPLIED:'ap',POLICY_REJECTED:'rj',ADMIN_REGISTERED:'sa',
      VOTE_SIGNED:'vt',ADMIN_ADMITTED:'sa',SA_REGISTERED:'sa',VOTE_CREATED:'vt'};
    document.getElementById('recent-ev').innerHTML=recent.length
      ?recent.map(e=>`
        <div class="le ${cm[e.event]||''}">
          <div style="font-weight:600;font-size:.68rem">
            <span class="badge ${['POLICY_APPLIED','ADMIN_ADMITTED','SA_REGISTERED'].includes(e.event)?'bdg':'bdr'}" style="font-size:.58rem">
              ${e.event.replace('POLICY_','').replace('ADMIN_','').replace('SA_','')}
            </span>
          </div>
          <div style="color:var(--dim);font-size:.62rem">${e.timestamp.slice(11,19)}</div>
        </div>`).join('')
      :'<div style="color:var(--dim);font-size:.7rem">No events yet.</div>';
  }catch(e){}
}

document.getElementById('pr-content').value=JSON.stringify({
  "name":"firewall-v1","rules":[
    {"action":"ALLOW","port":443,"protocol":"TCP","from":"0.0.0.0/0"},
    {"action":"ALLOW","port":22,"protocol":"TCP","from":"10.0.0.0/8"},
    {"action":"DENY","port":"*","protocol":"*","from":"0.0.0.0/0"}
  ]},null,2);

refreshPanel();
setInterval(refreshPanel,5000);

// When user types in custom ID field, auto-fill all admin ID inputs
document.getElementById('customId').addEventListener('input', function(){
  const id = this.value.trim();
  if(id) applyIdentity(id, false);
});
</script>
</body>
</html>"""

# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/sa/keygen', methods=['POST'])
def api_sa_keygen():
    if request.json.get('secret') != SUPERADMIN_SECRET:
        return jsonify(ok=False, message='❌ Invalid superadmin secret.')
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEYS_DIR / f"{SUPERADMIN_ID}.priv"
    pub_path  = KEYS_DIR / f"{SUPERADMIN_ID}.pub"
    if priv_path.exists():
        return jsonify(ok=True, message=f'Keys already exist.\nPublic: {pub_path.read_text().strip()[:32]}…')
    priv_b64, pub_b64 = generate_keypair()
    priv_path.write_text(priv_b64)
    pub_path.write_text(pub_b64)
    return jsonify(ok=True, message=f'✅ Keys generated for {SUPERADMIN_ID}\nPublic key: {pub_b64[:32]}…')

@app.route('/api/sa/register', methods=['POST'])
def api_sa_register():
    if request.json.get('secret') != SUPERADMIN_SECRET:
        audit.log.append(event='REGISTRATION_DENIED', policy_version=0, policy_hash='',
            signers=[], detail='Wrong SA secret')
        return jsonify(ok=False, message='❌ Invalid superadmin secret.')
    pub_path = KEYS_DIR / f"{SUPERADMIN_ID}.pub"
    if not pub_path.exists():
        return jsonify(ok=False, message='❌ No keys found. Run SA keygen first.')
    keyring = Keyring()
    if keyring.get(SUPERADMIN_ID):
        return jsonify(ok=True, message=f'✅ {SUPERADMIN_ID} already registered.')
    pub_b64 = pub_path.read_text().strip()
    keyring.add(SUPERADMIN_ID, pub_b64)
    audit.log.append(event='SA_REGISTERED', policy_version=0, policy_hash='',
        signers=[SUPERADMIN_ID], detail=f'{SUPERADMIN_ID} self-registered as root of trust.')
    return jsonify(ok=True, message=f'✅ Superadmin ({SUPERADMIN_ID}) registered as root of trust.\nKeyring: {len(keyring)} member(s).')

@app.route('/api/sa/invite', methods=['POST'])
def api_sa_invite():
    data     = request.json
    if data.get('secret') != SUPERADMIN_SECRET:
        return jsonify(ok=False, message='❌ Invalid superadmin secret.')
    keyring  = Keyring()
    if not keyring.get(SUPERADMIN_ID):
        return jsonify(ok=False, message='❌ Superadmin not registered. Complete SA Setup first.')
    admin_id = data.get('admin_id', '').strip()
    pub_key  = data.get('pub_key', '').strip()
    if not admin_id or not pub_key:
        return jsonify(ok=False, message='❌ admin_id and pub_key required.')
    if keyring.get(admin_id):
        return jsonify(ok=False, message=f'❌ {admin_id} already in keyring.')
    # Check no active pending vote for this admin
    for v in load_votes():
        if v['target_id'] == admin_id and v['status'] in ('pending', 'ready'):
            return jsonify(ok=False, message=f'❌ A pending vote for {admin_id} already exists.')
    vote_id = f"vote_{admin_id}_{int(datetime.now(timezone.utc).timestamp())}"
    vote = {
        "vote_id":     vote_id,
        "action":      "ADD_ADMIN",
        "target_id":   admin_id,
        "target_pub":  pub_key,
        "threshold":   POLICY_THRESHOLD,
        "timestamp":   ts(),
        "status":      "pending",
        "signatures":  [],
        "proposed_by": SUPERADMIN_ID,
    }
    sa_priv = KEYS_DIR / f"{SUPERADMIN_ID}.priv"
    if sa_priv.exists():
        sig = sign(sa_priv.read_text().strip(), vote_message(vote))
        vote["signatures"].append({"admin_id": SUPERADMIN_ID, "signature": sig})
    valid, _ = count_valid_votes(vote)
    if len(valid) >= POLICY_THRESHOLD:
        vote["status"] = "ready"
    save_vote(vote)
    audit.log.append(event='VOTE_CREATED', policy_version=0, policy_hash='',
        signers=[SUPERADMIN_ID], detail=f'Invited {admin_id}. Vote: {vote_id}')
    return jsonify(ok=True,
        message=f'✅ Invitation created for {admin_id}\nVote ID: {vote_id}\n'
                f'Threshold: k={POLICY_THRESHOLD}\nSuperadmin auto-signed (1 vote cast).\n\n'
                f'Share the vote page URL with other admins to collect votes.')

@app.route('/api/votes', methods=['POST'])
def api_votes():
    votes = load_votes()
    result = []
    for v in votes:
        valid, _ = count_valid_votes(v)
        result.append({
            "vote_id":    v["vote_id"],
            "target_id":  v["target_id"],
            "target_pub": v["target_pub"],
            "threshold":  v["threshold"],
            "status":     v["status"],
            "timestamp":  v["timestamp"],
            "valid_sigs": len(valid),
            "signers":    valid,
            "proposed_by": v.get("proposed_by", ""),
        })
    return jsonify(ok=True, votes=result)

@app.route('/api/votes/sign', methods=['POST'])
def api_vote_sign():
    data     = request.json
    vote_id  = data.get('vote_id', '')
    admin_id = data.get('admin_id', '').strip()
    vote     = load_vote(vote_id)
    if not vote:
        return jsonify(ok=False, message='Vote bundle not found.')
    if vote["status"] == "approved":
        return jsonify(ok=False, message='Already approved.')
    keyring = Keyring()
    if not keyring.get(admin_id):
        return jsonify(ok=False, message=f'❌ {admin_id} is not a registered admin. Cannot vote.')
    if any(s["admin_id"] == admin_id for s in vote["signatures"]):
        return jsonify(ok=False, message=f'❌ {admin_id} already signed this vote.')
    priv_path = KEYS_DIR / f"{admin_id}.priv"
    if not priv_path.exists():
        return jsonify(ok=False, message=f'❌ No private key for {admin_id} on this server.')
    sig = sign(priv_path.read_text().strip(), vote_message(vote))
    vote["signatures"].append({"admin_id": admin_id, "signature": sig})
    valid, _ = count_valid_votes(vote)
    if len(valid) >= vote["threshold"]:
        vote["status"] = "ready"
    save_vote(vote)
    audit.log.append(event='VOTE_SIGNED', policy_version=0, policy_hash='',
        signers=[admin_id], detail=f'{admin_id} voted for {vote["target_id"]}. {len(valid)}/{vote["threshold"]}')
    msg = f'✅ {admin_id} signed vote for {vote["target_id"]}\n{len(valid)}/{vote["threshold"]} valid signatures'
    if len(valid) >= vote["threshold"]:
        msg += '\n\n🎉 Threshold met! Click "Admit Admin" to finalize.'
    return jsonify(ok=True, message=msg, threshold_met=len(valid) >= vote["threshold"])

@app.route('/api/votes/approve', methods=['POST'])
def api_vote_approve():
    vote_id = request.json.get('vote_id', '')
    vote    = load_vote(vote_id)
    if not vote:
        return jsonify(ok=False, message='Vote bundle not found.')
    if vote["status"] == "approved":
        return jsonify(ok=False, message='Already approved.')
    if vote["status"] == "pending":
        return jsonify(ok=False, message='Threshold not met yet.')
    valid, _ = count_valid_votes(vote)
    if len(valid) < vote["threshold"]:
        return jsonify(ok=False, message=f'Only {len(valid)}/{vote["threshold"]} valid signatures.')
    keyring = Keyring()
    if keyring.get(vote["target_id"]):
        return jsonify(ok=False, message=f'{vote["target_id"]} already in keyring.')
    keyring.add(vote["target_id"], vote["target_pub"])
    (KEYS_DIR / f"{vote['target_id']}.pub").write_text(vote["target_pub"])
    vote["status"] = "approved"
    save_vote(vote)
    audit.log.append(event='ADMIN_ADMITTED', policy_version=0, policy_hash='',
        signers=valid, detail=f'{vote["target_id"]} admitted. Approved by: {", ".join(valid)}')
    return jsonify(ok=True,
        message=f'✅ {vote["target_id"]} admitted to keyring!\nApproved by: {", ".join(valid)}\nKeyring: {len(keyring)} members.')

@app.route('/api/keygen', methods=['POST'])
def api_keygen():
    admin_id = request.json.get('admin_id', '').strip()
    if not admin_id:
        return jsonify(ok=False, message='admin_id required')
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEYS_DIR / f"{admin_id}.priv"
    pub_path  = KEYS_DIR / f"{admin_id}.pub"
    if priv_path.exists():
        pub = pub_path.read_text().strip()
        return jsonify(ok=True, message=f'Keys exist.\n\nPublic key (share with superadmin):\n{pub}')
    priv_b64, pub_b64 = generate_keypair()
    priv_path.write_text(priv_b64)
    pub_path.write_text(pub_b64)
    return jsonify(ok=True,
        message=f'✅ Keys generated for {admin_id}\n\nPublic key (share with superadmin to get invited):\n{pub_b64}')

@app.route('/api/propose', methods=['POST'])
def api_propose():
    data    = request.json
    author  = data.get('author', '').strip()
    content = data.get('content', {})
    if not Keyring().get(author):
        return jsonify(ok=False, message=f'❌ {author} is not registered. Get admitted via voting first.')
    bundle      = create_bundle(content, author, data.get('description', ''))
    bundle_name = f"bundle_v{bundle['version']}.json"
    bundle_path = BUNDLES_DIR / bundle_name
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    save_bundle(bundle, bundle_path)
    return jsonify(ok=True,
        message=f'Bundle created: {bundle_name}\nv{bundle["version"]} · hash: {bundle["content_hash"][:32]}…',
        bundle_path=str(bundle_path))

@app.route('/api/bundles', methods=['POST'])
def api_bundles():
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    bundles = []
    for p in sorted(BUNDLES_DIR.glob('bundle_v*.json')):
        try:
            b = load_bundle(p)
            bundles.append({'name':p.name,'path':str(p),'version':b['version'],
                'author':b['author'],'timestamp':b['timestamp'][:16].replace('T',' '),
                'sig_count':len(b['signatures']),'signers':', '.join(s['admin_id'] for s in b['signatures']) or 'none'})
        except Exception: pass
    return jsonify(ok=True, bundles=bundles)

@app.route('/api/sign', methods=['POST'])
def api_sign():
    data        = request.json
    bundle_path = data.get('bundle_path', '')
    admin_id    = data.get('admin_id', '').strip()
    if not Keyring().get(admin_id):
        return jsonify(ok=False, message=f'❌ {admin_id} not registered.')
    priv_path = KEYS_DIR / f"{admin_id}.priv"
    if not priv_path.exists():
        return jsonify(ok=False, message=f'No private key for {admin_id}.')
    try:
        bundle = load_bundle(bundle_path)
        msg    = canonical_json({'version':bundle['version'],'content_hash':bundle['content_hash'],
            'previous_hash':bundle['previous_hash'],'timestamp':bundle['timestamp']})
        sig    = sign(priv_path.read_text().strip(), msg)
        add_signature(bundle, admin_id, sig)
        save_bundle(bundle, bundle_path)
        return jsonify(ok=True, message=f'✅ {admin_id} signed bundle.\nSig: {sig[:32]}…\nTotal: {len(bundle["signatures"])}')
    except Exception as e:
        return jsonify(ok=False, message=str(e))

@app.route('/api/apply', methods=['POST'])
def api_apply():
    data = request.json
    k    = int(data.get('threshold_k', POLICY_THRESHOLD))
    try:
        bundle  = load_bundle(data.get('bundle_path', ''))
        state   = load_state()
        result  = verify_bundle(bundle=bundle, keyring=Keyring().all(),
            active_content_hash=state['active_content_hash'],
            active_version=state['active_version'], threshold_k=k)
        evt = 'POLICY_APPLIED' if result.passed else 'POLICY_REJECTED'
        if result.passed: apply_policy(bundle)
        audit.log.append(event=evt, policy_version=bundle.get('version',0),
            policy_hash=bundle.get('content_hash',''), signers=result.signers,
            detail=result.error or f'Signers: {result.signers}', checks=result.checks)
        msg = (f'✅ Policy v{bundle["version"]} APPLIED\nSigners: {", ".join(result.signers)}'
               if result.passed else f'❌ REJECTED\n{result.error}')
        return jsonify(ok=result.passed, message=msg,
            checks=[{'check':c['check'],'passed':c['passed'],'detail':c['detail']} for c in result.checks])
    except Exception as e:
        return jsonify(ok=False, message=str(e), checks=[])

@app.route('/api/status', methods=['POST'])
def api_status():
    try:
        state  = load_state()
        kr     = Keyring()
        votes  = load_votes()
        return jsonify(ok=True, state=state,
            keyring=[{'id':k,'pub':v,'is_sa':k==SUPERADMIN_ID} for k,v in kr.all().items()],
            active_policy=get_active_policy(), superadmin_id=SUPERADMIN_ID,
            threshold=POLICY_THRESHOLD,
            votes_pending=sum(1 for v in votes if v['status'] in ('pending','ready')),
            votes_approved=sum(1 for v in votes if v['status']=='approved'))
    except Exception as e:
        return jsonify(ok=False, message=str(e))

@app.route('/api/audit', methods=['POST'])
def api_audit():
    entries    = audit.log.read_all()
    ok, issues = audit.log.verify_log_integrity()
    return jsonify(ok=True, entries=entries, integrity_ok=ok, issues=issues)

@app.route('/api/demo', methods=['POST'])
def api_demo():
    try:
        global BASE, KEYS_DIR, BUNDLES_DIR, VOTES_DIR
        if BASE.exists(): shutil.rmtree(BASE)
        BASE.mkdir(parents=True)
        KEYS_DIR    = BASE / "keys";    KEYS_DIR.mkdir()
        BUNDLES_DIR = BASE / "bundles"; BUNDLES_DIR.mkdir()
        VOTES_DIR   = BASE / "votes";   VOTES_DIR.mkdir()
        _patch_paths()

        out = []
        K   = POLICY_THRESHOLD

        # 1. Superadmin setup
        sa_priv, sa_pub = generate_keypair()
        (KEYS_DIR/f"{SUPERADMIN_ID}.priv").write_text(sa_priv)
        (KEYS_DIR/f"{SUPERADMIN_ID}.pub").write_text(sa_pub)
        Keyring().add(SUPERADMIN_ID, sa_pub)
        audit.log.append(event='SA_REGISTERED',policy_version=0,policy_hash='',
            signers=[SUPERADMIN_ID],detail=f'{SUPERADMIN_ID} self-registered.')
        out.append(f'✅ SUPERADMIN ({SUPERADMIN_ID}) registered')

        # 2. Keys for admin1, admin2, admin3
        keys = {}
        for a in ['admin1','admin2','admin3']:
            p, pub = generate_keypair()
            (KEYS_DIR/f'{a}.priv').write_text(p)
            (KEYS_DIR/f'{a}.pub').write_text(pub)
            keys[a] = (p, pub)
        out.append('✅ Keys generated for admin1, admin2, admin3')

        # 3. SA invites each; existing admins vote; admit
        for admin in ['admin1','admin2','admin3']:
            _, pub = keys[admin]
            vid = f"vote_{admin}_demo"
            vote = {"vote_id":vid,"action":"ADD_ADMIN","target_id":admin,"target_pub":pub,
                    "threshold":K,"timestamp":ts(),"status":"pending","signatures":[],"proposed_by":SUPERADMIN_ID}
            sig = sign(sa_priv, vote_message(vote))
            vote["signatures"].append({"admin_id":SUPERADMIN_ID,"signature":sig})
            out.append(f'  📨 SA invited {admin} → vote created + SA signed')
            # other registered admins sign
            for existing in Keyring().all():
                if existing in (admin, SUPERADMIN_ID): continue
                ep = KEYS_DIR/f'{existing}.priv'
                if ep.exists():
                    vote["signatures"].append({"admin_id":existing,"signature":sign(ep.read_text().strip(), vote_message(vote))})
            valid, _ = count_valid_votes(vote)
            if len(valid) >= K:
                vote["status"] = "approved"
                Keyring().add(admin, pub)
                (KEYS_DIR/f'{admin}.pub').write_text(pub)
                audit.log.append(event='ADMIN_ADMITTED',policy_version=0,policy_hash='',
                    signers=valid,detail=f'{admin} admitted by {len(valid)}/{K} votes.')
                out.append(f'  🗳️  {len(valid)}/{K} votes → {admin} ADMITTED')
            save_vote(vote)

        out.append(f'\n✅ Keyring: {list(Keyring().all().keys())}')

        # 4. Policy
        policy = {"name":"fw-v1","rules":[
            {"action":"ALLOW","port":443},{"action":"ALLOW","port":22,"from":"10.0.0.0/8"},
            {"action":"DENY","port":"*"}]}
        bundle = create_bundle(policy,'admin1','Initial firewall')
        bp = BUNDLES_DIR/f"bundle_v{bundle['version']}.json"
        save_bundle(bundle, bp)
        for a in ['admin1','admin2']:
            b = load_bundle(bp); pk=(KEYS_DIR/f'{a}.priv').read_text().strip()
            msg=canonical_json({'version':b['version'],'content_hash':b['content_hash'],
                'previous_hash':b['previous_hash'],'timestamp':b['timestamp']})
            add_signature(b, a, sign(pk,msg)); save_bundle(b,bp)
        state=load_state()
        r=verify_bundle(bundle=load_bundle(bp),keyring=Keyring().all(),
            active_content_hash=state['active_content_hash'],active_version=state['active_version'],threshold_k=K)
        if r.passed:
            apply_policy(load_bundle(bp))
            audit.log.append(event='POLICY_APPLIED',policy_version=bundle['version'],
                policy_hash=bundle['content_hash'],signers=r.signers,detail=f'Signers:{r.signers}')
            out.append(f'\n✅ Policy v1 APPLIED (admin1+admin2)')

        # 5. Attacks
        for label, setup in [
            ('Replay',   lambda: (load_bundle(bp), load_state())),
            ('Tamper',   None),
            ('Unsigned', None),
        ]:
            if label == 'Replay':
                b2, st = load_bundle(bp), load_state()
            elif label == 'Tamper':
                p2={"name":"tampered","rules":[{"action":"ALLOW_ALL","port":"*"}]}
                b2=create_bundle(p2,'eve','hack'); bp2=BUNDLES_DIR/f"bundle_v{b2['version']}.json"
                save_bundle(b2,bp2)
                for a in ['admin1','admin2']:
                    bx=load_bundle(bp2); pk=(KEYS_DIR/f'{a}.priv').read_text().strip()
                    msg=canonical_json({'version':bx['version'],'content_hash':bx['content_hash'],'previous_hash':bx['previous_hash'],'timestamp':bx['timestamp']})
                    add_signature(bx,a,sign(pk,msg)); save_bundle(bx,bp2)
                bx=load_bundle(bp2); bx['content']['rules'][0]['action']='BACKDOOR'; save_bundle(bx,bp2)
                b2=load_bundle(bp2); st=load_state()
            else:
                p3={"name":"evil","rules":[{"action":"ALLOW","port":"*"}]}
                b3=create_bundle(p3,'eve','evil'); bp3=BUNDLES_DIR/f"bundle_v{b3['version']}.json"
                save_bundle(b3,bp3)
                eve_pk,_=generate_keypair(); bx3=load_bundle(bp3)
                msg3=canonical_json({'version':bx3['version'],'content_hash':bx3['content_hash'],'previous_hash':bx3['previous_hash'],'timestamp':bx3['timestamp']})
                add_signature(bx3,'eve',sign(eve_pk,msg3)); save_bundle(bx3,bp3)
                b2=load_bundle(bp3); st=load_state()
            r2=verify_bundle(bundle=b2,keyring=Keyring().all(),
                active_content_hash=st['active_content_hash'],active_version=st['active_version'],threshold_k=K)
            audit.log.append(event='POLICY_REJECTED',policy_version=b2.get('version',0),
                policy_hash=b2.get('content_hash',''),signers=r2.signers,detail=r2.error or '')
            out.append(f'❌ {label} attack REJECTED: {r2.error}')

        out.append('\n🏁 Demo complete.')
        return jsonify(ok=True, output='\n'.join(out))
    except Exception as e:
        import traceback
        return jsonify(ok=False, output=traceback.format_exc())


@app.route('/api/bundle_info', methods=['POST'])
def api_bundle_info():
    """Return the signable message fields for a bundle — used by local_sign.py."""
    bundle_name = request.json.get('bundle_name', '').strip()
    # Accept either a name like "bundle_v1.json" or a full path
    if '/' in bundle_name or '\\' in bundle_name:
        bp = Path(bundle_name)
    else:
        bp = BUNDLES_DIR / bundle_name
    if not bp.exists():
        # list available
        available = [p.name for p in sorted(BUNDLES_DIR.glob('bundle_v*.json'))]
        return jsonify(ok=False, message=f'Bundle not found. Available: {available}')
    bundle = load_bundle(bp)
    # The exact message that must be signed (same as api/sign)
    msg_dict = {
        'version':       bundle['version'],
        'content_hash':  bundle['content_hash'],
        'previous_hash': bundle['previous_hash'],
        'timestamp':     bundle['timestamp'],
    }
    return jsonify(
        ok=True,
        bundle_name=bp.name,
        bundle_path=str(bp),
        version=bundle['version'],
        author=bundle['author'],
        description=bundle.get('description',''),
        content_hash=bundle['content_hash'],
        previous_hash=bundle['previous_hash'],
        timestamp=bundle['timestamp'],
        sig_count=len(bundle['signatures']),
        signers=[s['admin_id'] for s in bundle['signatures']],
        message_to_sign=canonical_json(msg_dict).decode(),
    )


@app.route('/api/sign_external', methods=['POST'])
def api_sign_external():
    """Accept a pre-computed signature from a local key (local_sign.py flow)."""
    data      = request.json
    admin_id  = data.get('admin_id', '').strip()
    bundle_path = data.get('bundle_path', '').strip()
    signature = data.get('signature', '').strip()

    if not admin_id or not bundle_path or not signature:
        return jsonify(ok=False, message='admin_id, bundle_path, and signature are required.')

    # Admin must be in keyring
    keyring = Keyring()
    pub_b64 = keyring.get(admin_id)
    if not pub_b64:
        return jsonify(ok=False, message=f'❌ {admin_id} is not a registered admin.')

    bp = Path(bundle_path)
    if not bp.exists():
        bp = BUNDLES_DIR / bundle_path
    if not bp.exists():
        return jsonify(ok=False, message=f'Bundle not found: {bundle_path}')

    bundle = load_bundle(bp)

    # Verify the signature is valid BEFORE accepting it
    msg = canonical_json({
        'version':       bundle['version'],
        'content_hash':  bundle['content_hash'],
        'previous_hash': bundle['previous_hash'],
        'timestamp':     bundle['timestamp'],
    })

    if not verify_signature(pub_b64, msg, signature):
        audit.log.append(event='POLICY_REJECTED', policy_version=bundle.get('version',0),
            policy_hash=bundle.get('content_hash',''), signers=[],
            detail=f'Invalid external signature from {admin_id}')
        return jsonify(ok=False, message=f'❌ Signature verification failed. The signature does not match {admin_id}\'s registered public key.')

    # Check not already signed
    if any(s['admin_id'] == admin_id for s in bundle['signatures']):
        return jsonify(ok=False, message=f'❌ {admin_id} has already signed this bundle.')

    add_signature(bundle, admin_id, signature)
    save_bundle(bundle, bp)

    total = len(bundle['signatures'])
    return jsonify(
        ok=True,
        message=f'✅ External signature from {admin_id} verified and accepted.\nSig: {signature[:32]}…\nTotal signatures: {total}'
    )

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    import socket
    try: ip = socket.gethostbyname(socket.gethostname())
    except: ip = '127.0.0.1'
    print(f"""
╔══════════════════════════════════════════════════════╗
║   VeriWall v2 — Superadmin + Threshold Registration  ║
╚══════════════════════════════════════════════════════╝
  Superadmin: {SUPERADMIN_ID}   Threshold: k={POLICY_THRESHOLD}
  Local  →  http://127.0.0.1:{port}
  Network → http://{ip}:{port}
""")
    app.run(host='0.0.0.0', port=port, debug=False)
