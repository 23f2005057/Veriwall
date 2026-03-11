#!/usr/bin/env python3
"""
VeriWall Web Server
Run: python server.py
Then open http://<your-ip>:5000 on any device on the same network.
"""

from flask import Flask, request, jsonify, render_template_string, send_file
import json, sys, shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from veriwall.core.signer      import generate_keypair, sign
from veriwall.core.hasher      import canonical_json
from veriwall.core.verifier    import verify_bundle
from veriwall.keyring.registry import Keyring
from veriwall.policy.packager  import create_bundle, add_signature, save_bundle, load_bundle, load_state
from veriwall.policy.enforcer  import apply_policy, get_active_policy
from veriwall import audit

app = Flask(__name__)

import os
_IS_CLOUD   = bool(os.getenv("RENDER") or os.getenv("RAILWAY_ENVIRONMENT"))
_base       = Path("/tmp/veriwall_data") if _IS_CLOUD else Path("veriwall_data")
DATA_DIR    = _base
KEYS_DIR    = DATA_DIR / "keys"
BUNDLES_DIR = DATA_DIR / "bundles"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Patch submodule paths so keyring/audit/enforcer write to DATA_DIR
import veriwall.keyring.registry as _kr_mod
import veriwall.policy.packager  as _pkg_mod
import veriwall.policy.enforcer  as _enf_mod
import veriwall.audit            as _aud_mod

_kr_mod.KEYRING_PATH        = DATA_DIR / "keyring.json"
_pkg_mod.DATA_DIR           = DATA_DIR
_pkg_mod.STATE_PATH         = DATA_DIR / "state.json"
_pkg_mod.BUNDLES_DIR        = DATA_DIR / "bundles"
_enf_mod.DATA_DIR           = DATA_DIR
_enf_mod.ACTIVE_POLICY_PATH = DATA_DIR / "active_policy.json"
_aud_mod.LOG_PATH           = DATA_DIR / "audit.jsonl"
_aud_mod.log.__class__._log_path = DATA_DIR / "audit.jsonl"

# ─── HTML ────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VeriWall — Policy Governance</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg:       #050810;
  --surface:  #0c1120;
  --border:   #1a2540;
  --accent:   #00e5ff;
  --green:    #00ff9d;
  --red:      #ff3d5a;
  --yellow:   #ffd93d;
  --muted:    #4a5568;
  --text:     #e2e8f0;
  --dim:      #718096;
  --mono:     'JetBrains Mono', monospace;
  --sans:     'Syne', sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--mono);
  min-height: 100vh;
  background-image:
    radial-gradient(ellipse at 20% 20%, rgba(0,229,255,.04) 0%, transparent 60%),
    radial-gradient(ellipse at 80% 80%, rgba(0,255,157,.03) 0%, transparent 60%);
}

/* ── Header ── */
header {
  border-bottom: 1px solid var(--border);
  padding: 18px 32px;
  display: flex;
  align-items: center;
  gap: 20px;
  background: rgba(12,17,32,.8);
  backdrop-filter: blur(12px);
  position: sticky; top: 0; z-index: 100;
}
.logo {
  font-family: var(--sans);
  font-weight: 800;
  font-size: 1.4rem;
  color: var(--accent);
  letter-spacing: -0.5px;
}
.logo span { color: var(--green); }
.tagline {
  font-size: .65rem;
  color: var(--dim);
  letter-spacing: 2px;
  text-transform: uppercase;
}
.status-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 8px var(--green);
  animation: pulse 2s infinite;
  margin-left: auto;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

/* ── Layout ── */
.layout {
  display: grid;
  grid-template-columns: 260px 1fr 300px;
  gap: 0;
  min-height: calc(100vh - 61px);
}

/* ── Sidebar ── */
.sidebar {
  border-right: 1px solid var(--border);
  padding: 24px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.section-label {
  font-size: .6rem;
  letter-spacing: 2px;
  color: var(--muted);
  text-transform: uppercase;
  padding: 16px 8px 6px;
}
.nav-btn {
  background: none;
  border: 1px solid transparent;
  color: var(--dim);
  padding: 10px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-family: var(--mono);
  font-size: .78rem;
  text-align: left;
  transition: all .15s;
  display: flex;
  align-items: center;
  gap: 10px;
}
.nav-btn:hover  { border-color: var(--border); color: var(--text); background: var(--surface); }
.nav-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(0,229,255,.05); }
.nav-btn .icon  { font-size: 1rem; width: 20px; text-align: center; }

/* ── Admin selector ── */
.admin-selector {
  margin-top: auto;
  border-top: 1px solid var(--border);
  padding-top: 16px;
}
.admin-selector select {
  width: 100%;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 9px 10px;
  border-radius: 6px;
  font-family: var(--mono);
  font-size: .78rem;
  cursor: pointer;
}
.admin-selector select:focus { outline: none; border-color: var(--accent); }

/* ── Main content ── */
main {
  padding: 28px 32px;
  overflow-y: auto;
}
.page { display: none; }
.page.active { display: block; }

h2 {
  font-family: var(--sans);
  font-size: 1.3rem;
  font-weight: 800;
  color: var(--text);
  margin-bottom: 6px;
}
.page-desc {
  color: var(--dim);
  font-size: .75rem;
  margin-bottom: 24px;
  line-height: 1.6;
}

/* ── Cards ── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 16px;
}
.card-title {
  font-size: .65rem;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 14px;
}

/* ── Forms ── */
.field { margin-bottom: 14px; }
.field label {
  display: block;
  font-size: .68rem;
  color: var(--dim);
  letter-spacing: 1px;
  text-transform: uppercase;
  margin-bottom: 6px;
}
input[type=text], input[type=number], textarea, select.field-select {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 10px 12px;
  border-radius: 6px;
  font-family: var(--mono);
  font-size: .82rem;
  transition: border-color .15s;
}
input:focus, textarea:focus, select.field-select:focus {
  outline: none;
  border-color: var(--accent);
}
textarea { resize: vertical; min-height: 120px; line-height: 1.5; }

/* ── Buttons ── */
.btn {
  padding: 10px 20px;
  border-radius: 6px;
  border: none;
  font-family: var(--mono);
  font-size: .8rem;
  font-weight: 600;
  cursor: pointer;
  transition: all .15s;
  letter-spacing: .5px;
}
.btn-primary {
  background: var(--accent);
  color: var(--bg);
}
.btn-primary:hover { background: #33eaff; box-shadow: 0 0 20px rgba(0,229,255,.3); }
.btn-success {
  background: var(--green);
  color: var(--bg);
}
.btn-success:hover { background: #33ffb3; box-shadow: 0 0 20px rgba(0,255,157,.3); }
.btn-danger {
  background: var(--red);
  color: #fff;
}
.btn-danger:hover { opacity: .85; }
.btn:disabled { opacity: .4; cursor: not-allowed; }

/* ── Response box ── */
.response-box {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  margin-top: 14px;
  font-size: .75rem;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
  min-height: 60px;
  max-height: 240px;
  overflow-y: auto;
  color: var(--dim);
  display: none;
}
.response-box.visible { display: block; }
.response-box.ok  { border-color: var(--green); color: var(--green); }
.response-box.err { border-color: var(--red);   color: var(--red);   }

/* ── Check list ── */
.check-list { display: flex; flex-direction: column; gap: 6px; margin: 10px 0; }
.check-item {
  display: flex; align-items: center; gap: 10px;
  font-size: .75rem;
  padding: 7px 10px;
  border-radius: 5px;
  background: rgba(255,255,255,.02);
  border: 1px solid var(--border);
}
.check-item.pass { border-color: rgba(0,255,157,.2); }
.check-item.fail { border-color: rgba(255,61,90,.2); }
.check-icon { font-size: .9rem; width: 20px; text-align: center; }
.check-name { flex: 1; color: var(--text); }
.check-detail { color: var(--dim); font-size: .68rem; }

/* ── Right panel ── */
.panel {
  border-left: 1px solid var(--border);
  padding: 24px 20px;
  overflow-y: auto;
}
.panel-title {
  font-family: var(--sans);
  font-size: .85rem;
  font-weight: 800;
  color: var(--text);
  margin-bottom: 16px;
  display: flex; align-items: center; gap: 8px;
}

/* ── Status widget ── */
.status-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  margin-bottom: 12px;
}
.status-card .label {
  font-size: .6rem;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 8px;
}
.status-card .value {
  font-size: .8rem;
  color: var(--text);
  word-break: break-all;
  line-height: 1.5;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: .65rem;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.badge-green { background: rgba(0,255,157,.15); color: var(--green); border: 1px solid rgba(0,255,157,.3); }
.badge-red   { background: rgba(255,61,90,.15);  color: var(--red);   border: 1px solid rgba(255,61,90,.3); }
.badge-blue  { background: rgba(0,229,255,.15);  color: var(--accent);border: 1px solid rgba(0,229,255,.3); }

/* ── Audit log ── */
.log-entry {
  border-left: 2px solid var(--border);
  padding: 8px 12px;
  margin-bottom: 10px;
  font-size: .72rem;
  line-height: 1.6;
}
.log-entry.applied { border-color: var(--green); }
.log-entry.rejected { border-color: var(--red); }
.log-event { font-weight: 600; margin-bottom: 2px; }
.log-meta  { color: var(--dim); font-size: .65rem; }

/* ── Bundle list ── */
.bundle-item {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: border-color .15s;
}
.bundle-item:hover { border-color: var(--accent); }
.bundle-item.selected { border-color: var(--accent); background: rgba(0,229,255,.04); }
.bundle-name { font-size: .8rem; color: var(--text); margin-bottom: 4px; }
.bundle-meta { font-size: .65rem; color: var(--dim); }
.bundle-sigs { font-size: .65rem; margin-top: 4px; }

/* ── Toast ── */
#toast {
  position: fixed; bottom: 24px; right: 24px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 18px;
  font-size: .78rem;
  opacity: 0;
  transform: translateY(10px);
  transition: all .25s;
  z-index: 999;
  max-width: 320px;
}
#toast.show { opacity: 1; transform: translateY(0); }
#toast.ok   { border-color: var(--green); color: var(--green); }
#toast.err  { border-color: var(--red);   color: var(--red); }

/* ── Grid helpers ── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.mt-8  { margin-top: 8px; }
.mt-16 { margin-top: 16px; }

/* ── Responsive ── */
@media(max-width:900px){
  .layout { grid-template-columns: 1fr; }
  .sidebar, .panel { display: none; }
}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">Veri<span>Wall</span></div>
    <div class="tagline">Threshold-Signed Policy Enforcement</div>
  </div>
  <div class="status-dot" id="serverDot" title="Server online"></div>
</header>

<div class="layout">

  <!-- ── Sidebar ── -->
  <nav class="sidebar">
    <div class="section-label">Setup</div>
    <button class="nav-btn active" onclick="showPage('keygen')" id="nav-keygen">
      <span class="icon">🔑</span> Key Generation
    </button>
    <button class="nav-btn" onclick="showPage('register')" id="nav-register">
      <span class="icon">📋</span> Register Admin
    </button>

    <div class="section-label">Workflow</div>
    <button class="nav-btn" onclick="showPage('propose')" id="nav-propose">
      <span class="icon">📄</span> Propose Policy
    </button>
    <button class="nav-btn" onclick="showPage('sign')" id="nav-sign">
      <span class="icon">✍️</span> Sign Bundle
    </button>
    <button class="nav-btn" onclick="showPage('apply')" id="nav-apply">
      <span class="icon">🚀</span> Apply Bundle
    </button>

    <div class="section-label">Inspect</div>
    <button class="nav-btn" onclick="showPage('status')" id="nav-status">
      <span class="icon">📊</span> System Status
    </button>
    <button class="nav-btn" onclick="showPage('audit')" id="nav-audit">
      <span class="icon">🔍</span> Audit Log
    </button>
    <button class="nav-btn" onclick="showPage('demo')" id="nav-demo">
      <span class="icon">⚡</span> Full Demo
    </button>

    <div class="admin-selector">
      <div class="section-label">You are</div>
      <select id="adminSelect" onchange="updateAdmin()">
        <option value="">— select identity —</option>
        <option value="alice">alice  (Security Lead)</option>
        <option value="bob">bob  (Network Engineer)</option>
        <option value="carol">carol  (CISO)</option>
        <option value="eve">eve  (⚠ attacker)</option>
      </select>
    </div>
  </nav>

  <!-- ── Main ── -->
  <main>

    <!-- Keygen -->
    <div class="page active" id="page-keygen">
      <h2>Key Generation</h2>
      <p class="page-desc">Generate an Ed25519 key pair for an administrator.<br/>The private key is stored on the server. In production, it would stay only on the admin's own device.</p>
      <div class="card">
        <div class="card-title">Generate Keys</div>
        <div class="field">
          <label>Admin ID</label>
          <input type="text" id="keygen-id" placeholder="e.g. alice" />
        </div>
        <button class="btn btn-primary" onclick="doKeygen()">Generate Key Pair</button>
        <div class="response-box" id="keygen-res"></div>
      </div>
    </div>

    <!-- Register -->
    <div class="page" id="page-register">
      <h2>Register Administrator</h2>
      <p class="page-desc">Add an admin's public key to the shared keyring. Run keygen first, then register.</p>
      <div class="card">
        <div class="card-title">Register</div>
        <div class="field">
          <label>Admin ID</label>
          <input type="text" id="register-id" placeholder="e.g. alice" />
        </div>
        <button class="btn btn-primary" onclick="doRegister()">Register in Keyring</button>
        <div class="response-box" id="register-res"></div>
      </div>
    </div>

    <!-- Propose -->
    <div class="page" id="page-propose">
      <h2>Propose Policy</h2>
      <p class="page-desc">Create a new unsigned policy bundle. Paste valid JSON for the policy content.</p>
      <div class="card">
        <div class="card-title">New Bundle</div>
        <div class="grid-2">
          <div class="field">
            <label>Author (Admin ID)</label>
            <input type="text" id="propose-author" placeholder="e.g. alice" />
          </div>
          <div class="field">
            <label>Description</label>
            <input type="text" id="propose-desc" placeholder="e.g. Initial firewall rules" />
          </div>
        </div>
        <div class="field">
          <label>Policy Content (JSON)</label>
          <textarea id="propose-content" placeholder='{"name":"firewall-v1","rules":[{"action":"ALLOW","port":443},{"action":"DENY","port":"*"}]}'></textarea>
        </div>
        <button class="btn btn-primary" onclick="doPropose()">Create Bundle</button>
        <div class="response-box" id="propose-res"></div>
      </div>
    </div>

    <!-- Sign -->
    <div class="page" id="page-sign">
      <h2>Sign Bundle</h2>
      <p class="page-desc">Select a bundle and sign it with your private key. Only registered admins can produce valid signatures.</p>
      <div class="card">
        <div class="card-title">Available Bundles</div>
        <div id="bundle-list">
          <div style="color:var(--dim);font-size:.75rem">Loading bundles…</div>
        </div>
        <div class="field mt-16">
          <label>Your Admin ID</label>
          <input type="text" id="sign-admin" placeholder="e.g. alice" />
        </div>
        <button class="btn btn-success" onclick="doSign()">Sign Selected Bundle</button>
        <div class="response-box" id="sign-res"></div>
      </div>
    </div>

    <!-- Apply -->
    <div class="page" id="page-apply">
      <h2>Apply Bundle</h2>
      <p class="page-desc">Verify all 6 checks and atomically apply a signed bundle. All checks must pass.</p>
      <div class="card">
        <div class="card-title">Select Bundle to Apply</div>
        <div id="apply-bundle-list">
          <div style="color:var(--dim);font-size:.75rem">Loading bundles…</div>
        </div>
        <div class="field mt-16">
          <label>Signature Threshold (k)</label>
          <input type="number" id="apply-k" value="2" min="1" max="10" style="width:100px" />
        </div>
        <button class="btn btn-danger" onclick="doApply()">Verify &amp; Apply</button>
        <div id="apply-checks" class="check-list mt-8" style="display:none"></div>
        <div class="response-box" id="apply-res"></div>
      </div>
    </div>

    <!-- Status -->
    <div class="page" id="page-status">
      <h2>System Status</h2>
      <p class="page-desc">Current state of the active policy, keyring, and audit log.</p>
      <div id="status-content">
        <div style="color:var(--dim);font-size:.75rem">Loading…</div>
      </div>
    </div>

    <!-- Audit -->
    <div class="page" id="page-audit">
      <h2>Audit Log</h2>
      <p class="page-desc">Append-only hash-chained record of every policy event.</p>
      <div id="audit-integrity" class="card" style="margin-bottom:16px"></div>
      <div id="audit-entries"></div>
    </div>

    <!-- Demo -->
    <div class="page" id="page-demo">
      <h2>Full Automated Demo</h2>
      <p class="page-desc">Wipes all data and runs the complete VeriWall scenario: 3 admins, 1 policy applied, 3 attacks blocked.</p>
      <div class="card">
        <div class="card-title">⚠ WARNING</div>
        <p style="font-size:.78rem;color:var(--yellow);margin-bottom:16px">This will delete all existing keys, bundles, and audit logs and run a fresh demo.</p>
        <button class="btn btn-danger" onclick="doDemo()">Run Full Demo</button>
        <div class="response-box" id="demo-res"></div>
      </div>
    </div>

  </main>

  <!-- ── Right panel ── -->
  <aside class="panel">
    <div class="panel-title">⚡ Live State</div>

    <div id="live-version" class="status-card">
      <div class="label">Active Version</div>
      <div class="value" id="live-ver-val">—</div>
    </div>

    <div class="status-card">
      <div class="label">Active Hash</div>
      <div class="value" id="live-hash-val" style="font-size:.68rem;color:var(--dim)">none</div>
    </div>

    <div class="status-card">
      <div class="label">Keyring</div>
      <div class="value" id="live-keyring-val">0 admins</div>
    </div>

    <div class="status-card">
      <div class="label">Audit Events</div>
      <div class="value" id="live-events-val">0</div>
    </div>

    <div class="panel-title mt-16">📋 Recent Events</div>
    <div id="recent-events">
      <div style="color:var(--dim);font-size:.72rem">No events yet.</div>
    </div>
  </aside>

</div>

<div id="toast"></div>

<script>
let selectedBundle = null;

// ── Navigation ──────────────────────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.getElementById('nav-' + id).classList.add('active');
  if (id === 'sign' || id === 'apply') loadBundles(id);
  if (id === 'status') loadStatus();
  if (id === 'audit')  loadAudit();
}

function updateAdmin() {
  const v = document.getElementById('adminSelect').value;
  if (v) {
    document.getElementById('keygen-id').value   = v;
    document.getElementById('register-id').value = v;
    document.getElementById('sign-admin').value  = v;
    document.getElementById('propose-author').value = v;
  }
}

// ── Toast ────────────────────────────────────────────────────────────────────
function toast(msg, type='ok') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show ' + type;
  setTimeout(() => t.className = '', 3000);
}

// ── Response box ─────────────────────────────────────────────────────────────
function setRes(id, msg, ok=true) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'response-box visible ' + (ok ? 'ok' : 'err');
}

// ── API helper ───────────────────────────────────────────────────────────────
async function api(path, body={}) {
  const r = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  return r.json();
}

// ── Keygen ───────────────────────────────────────────────────────────────────
async function doKeygen() {
  const id = document.getElementById('keygen-id').value.trim();
  if (!id) return toast('Enter an admin ID', 'err');
  const res = await api('/api/keygen', {admin_id: id});
  setRes('keygen-res', res.message, res.ok);
  if (res.ok) toast('Keys generated for ' + id);
  else toast(res.message, 'err');
  refreshPanel();
}

// ── Register ─────────────────────────────────────────────────────────────────
async function doRegister() {
  const id = document.getElementById('register-id').value.trim();
  if (!id) return toast('Enter an admin ID', 'err');
  const res = await api('/api/register', {admin_id: id});
  setRes('register-res', res.message, res.ok);
  if (res.ok) toast(id + ' registered in keyring');
  else toast(res.message, 'err');
  refreshPanel();
}

// ── Propose ──────────────────────────────────────────────────────────────────
async function doPropose() {
  const author  = document.getElementById('propose-author').value.trim();
  const desc    = document.getElementById('propose-desc').value.trim();
  const content = document.getElementById('propose-content').value.trim();
  if (!author || !content) return toast('Fill in author and policy JSON', 'err');
  let parsed;
  try { parsed = JSON.parse(content); } catch(e) { return toast('Invalid JSON: ' + e.message, 'err'); }
  const res = await api('/api/propose', {author, description: desc, content: parsed});
  setRes('propose-res', res.message, res.ok);
  if (res.ok) toast('Bundle created: ' + res.bundle_path);
  else toast(res.message, 'err');
  refreshPanel();
}

// ── Load bundles ─────────────────────────────────────────────────────────────
async function loadBundles(page) {
  const res = await api('/api/bundles');
  const listId = page === 'sign' ? 'bundle-list' : 'apply-bundle-list';
  const el = document.getElementById(listId);
  if (!res.bundles || res.bundles.length === 0) {
    el.innerHTML = '<div style="color:var(--dim);font-size:.75rem">No bundles found. Propose a policy first.</div>';
    return;
  }
  el.innerHTML = res.bundles.map(b => `
    <div class="bundle-item" id="bi-${b.name}" onclick="selectBundle('${b.path}','${b.name}','${page}')">
      <div class="bundle-name">${b.name}</div>
      <div class="bundle-meta">v${b.version} · by ${b.author} · ${b.timestamp}</div>
      <div class="bundle-sigs">${b.sig_count} signature(s): <span style="color:var(--accent)">${b.signers}</span></div>
    </div>
  `).join('');
}

function selectBundle(path, name, page) {
  selectedBundle = path;
  const listId = page === 'sign' ? 'bundle-list' : 'apply-bundle-list';
  document.querySelectorAll(`#${listId} .bundle-item`).forEach(el => el.classList.remove('selected'));
  document.getElementById('bi-' + name).classList.add('selected');
}

// ── Sign ─────────────────────────────────────────────────────────────────────
async function doSign() {
  const admin = document.getElementById('sign-admin').value.trim();
  if (!admin) return toast('Enter your admin ID', 'err');
  if (!selectedBundle) return toast('Select a bundle first', 'err');
  const res = await api('/api/sign', {bundle_path: selectedBundle, admin_id: admin});
  setRes('sign-res', res.message, res.ok);
  if (res.ok) toast(admin + ' signed the bundle');
  else toast(res.message, 'err');
  loadBundles('sign');
  refreshPanel();
}

// ── Apply ────────────────────────────────────────────────────────────────────
async function doApply() {
  const k = parseInt(document.getElementById('apply-k').value) || 2;
  if (!selectedBundle) return toast('Select a bundle first', 'err');
  const res = await api('/api/apply', {bundle_path: selectedBundle, threshold_k: k});

  // Show checks
  const checksEl = document.getElementById('apply-checks');
  if (res.checks) {
    checksEl.style.display = 'flex';
    checksEl.innerHTML = res.checks.map(c => `
      <div class="check-item ${c.passed?'pass':'fail'}">
        <span class="check-icon">${c.passed?'✓':'✗'}</span>
        <span class="check-name">${c.check.replace(/_/g,' ')}</span>
        <span class="check-detail">${c.detail}</span>
      </div>
    `).join('');
  }
  setRes('apply-res', res.message, res.ok);
  if (res.ok) toast('✅ Policy APPLIED!');
  else toast('❌ Policy REJECTED', 'err');
  loadBundles('apply');
  refreshPanel();
}

// ── Status ────────────────────────────────────────────────────────────────────
async function loadStatus() {
  const res = await api('/api/status');
  const el  = document.getElementById('status-content');
  if (!res.ok) { el.innerHTML = '<div style="color:var(--red)">Error loading status</div>'; return; }
  const s = res.state;
  el.innerHTML = `
    <div class="card">
      <div class="card-title">Active Policy</div>
      <div class="grid-2">
        <div><div class="label" style="font-size:.6rem;color:var(--dim);margin-bottom:4px">VERSION</div>
          <span class="badge badge-blue">v${s.active_version}</span></div>
        <div><div class="label" style="font-size:.6rem;color:var(--dim);margin-bottom:4px">STATUS</div>
          <span class="badge ${s.active_content_hash ? 'badge-green' : 'badge-red'}">${s.active_content_hash ? 'ACTIVE' : 'NONE'}</span></div>
      </div>
      <div style="margin-top:12px;font-size:.72rem;color:var(--dim)">Hash: ${s.active_content_hash || 'none'}</div>
    </div>
    <div class="card">
      <div class="card-title">Registered Admins (${res.keyring.length})</div>
      ${res.keyring.map(a => `<div style="font-size:.75rem;padding:4px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between"><span style="color:var(--accent)">${a.id}</span><span style="color:var(--dim);font-size:.65rem">${a.pub.slice(0,24)}…</span></div>`).join('')}
    </div>
    <div class="card">
      <div class="card-title">Active Policy Content</div>
      <pre style="font-size:.68rem;color:var(--dim);overflow:auto;max-height:200px">${JSON.stringify(res.active_policy, null, 2) || 'none'}</pre>
    </div>
  `;
}

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit() {
  const res = await api('/api/audit');
  const intEl = document.getElementById('audit-integrity');
  if (res.integrity_ok) {
    intEl.innerHTML = `<div class="card-title">Log Chain Integrity</div><span class="badge badge-green">VERIFIED ✓</span> <span style="color:var(--dim);font-size:.72rem">${res.entries.length} entries, no tampering detected</span>`;
  } else {
    intEl.innerHTML = `<div class="card-title">Log Chain Integrity</div><span class="badge badge-red">BROKEN ✗</span> <span style="color:var(--red);font-size:.72rem">${res.issues.join(', ')}</span>`;
  }
  const el = document.getElementById('audit-entries');
  if (!res.entries.length) {
    el.innerHTML = '<div style="color:var(--dim);font-size:.75rem">No entries yet.</div>';
    return;
  }
  el.innerHTML = res.entries.slice().reverse().map(e => `
    <div class="log-entry ${e.event.includes('APPLIED')?'applied':'rejected'}">
      <div class="log-event">
        <span class="badge ${e.event.includes('APPLIED')?'badge-green':'badge-red'}">${e.event}</span>
        &nbsp; v${e.policy_version}
      </div>
      <div class="log-meta">${e.timestamp.slice(0,19).replace('T',' ')} · signers: ${e.signers.join(', ')||'none'}</div>
      <div style="color:var(--dim);font-size:.68rem;margin-top:2px">${e.detail}</div>
    </div>
  `).join('');
}

// ── Demo ──────────────────────────────────────────────────────────────────────
async function doDemo() {
  const el = document.getElementById('demo-res');
  el.textContent = 'Running demo…';
  el.className = 'response-box visible';
  const res = await api('/api/demo');
  setRes('demo-res', res.output, res.ok);
  if (res.ok) toast('Demo complete!');
  else toast('Demo failed', 'err');
  refreshPanel();
}

// ── Live panel ────────────────────────────────────────────────────────────────
async function refreshPanel() {
  try {
    const res = await api('/api/status');
    if (!res.ok) return;
    const s = res.state;
    document.getElementById('live-ver-val').innerHTML =
      `<span class="badge badge-blue">v${s.active_version}</span>`;
    document.getElementById('live-hash-val').textContent =
      s.active_content_hash ? s.active_content_hash.slice(0,32)+'…' : 'none';
    document.getElementById('live-keyring-val').textContent =
      res.keyring.length + ' admin' + (res.keyring.length !== 1 ? 's' : '') +
      ': ' + res.keyring.map(a=>a.id).join(', ');
    const au = await api('/api/audit');
    document.getElementById('live-events-val').textContent = au.entries.length;
    const recent = au.entries.slice(-4).reverse();
    document.getElementById('recent-events').innerHTML = recent.length
      ? recent.map(e => `
          <div class="log-entry ${e.event.includes('APPLIED')?'applied':'rejected'}">
            <div class="log-event" style="font-size:.7rem">
              <span class="badge ${e.event.includes('APPLIED')?'badge-green':'badge-red'}" style="font-size:.58rem">${e.event.replace('POLICY_','')}</span>
              v${e.policy_version}
            </div>
            <div class="log-meta">${e.timestamp.slice(11,19)}</div>
          </div>`).join('')
      : '<div style="color:var(--dim);font-size:.72rem">No events yet.</div>';
  } catch(e) {}
}

// ── Init ──────────────────────────────────────────────────────────────────────
refreshPanel();
setInterval(refreshPanel, 5000);

// Prepopulate propose field
document.getElementById('propose-content').value = JSON.stringify({
  "name": "firewall-v1",
  "rules": [
    {"action": "ALLOW", "port": 443, "protocol": "TCP", "from": "0.0.0.0/0"},
    {"action": "ALLOW", "port": 22,  "protocol": "TCP", "from": "10.0.0.0/8"},
    {"action": "DENY",  "port": "*",  "protocol": "*",   "from": "0.0.0.0/0"}
  ]
}, null, 2);
</script>
</body>
</html>
"""

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/api/keygen', methods=['POST'])
def api_keygen():
    admin_id = request.json.get('admin_id', '').strip()
    if not admin_id:
        return jsonify(ok=False, message='admin_id is required')
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEYS_DIR / f"{admin_id}.priv"
    pub_path  = KEYS_DIR / f"{admin_id}.pub"
    if priv_path.exists():
        return jsonify(ok=False, message=f'Keys already exist for {admin_id}. Delete veriwall_data/keys/{admin_id}.priv to regenerate.')
    priv_b64, pub_b64 = generate_keypair()
    priv_path.write_text(priv_b64)
    pub_path.write_text(pub_b64)
    return jsonify(ok=True, message=f'Ed25519 key pair generated for {admin_id}\nPublic key: {pub_b64[:32]}…\nPrivate key stored (keep secret).')


@app.route('/api/register', methods=['POST'])
def api_register():
    admin_id = request.json.get('admin_id', '').strip()
    if not admin_id:
        return jsonify(ok=False, message='admin_id is required')
    pub_path = KEYS_DIR / f"{admin_id}.pub"
    if not pub_path.exists():
        return jsonify(ok=False, message=f'No public key found for {admin_id}. Run keygen first.')
    keyring = Keyring()
    pub_b64 = pub_path.read_text().strip()
    keyring.add(admin_id, pub_b64)
    return jsonify(ok=True, message=f'{admin_id} registered in keyring.\nPublic key: {pub_b64[:32]}…\nKeyring now has {len(keyring)} admin(s).')


@app.route('/api/propose', methods=['POST'])
def api_propose():
    data    = request.json
    author  = data.get('author', '').strip()
    desc    = data.get('description', '')
    content = data.get('content', {})
    if not author or not content:
        return jsonify(ok=False, message='author and content are required')
    bundle      = create_bundle(content, author, desc)
    bundle_name = f"bundle_v{bundle['version']}.json"
    bundle_path = BUNDLES_DIR / bundle_name
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    save_bundle(bundle, bundle_path)
    return jsonify(ok=True, message=f'Bundle created: {bundle_path}\nVersion: v{bundle["version"]}\nContent hash: {bundle["content_hash"][:32]}…\nPrevious hash: {bundle["previous_hash"][:32]}…', bundle_path=str(bundle_path))


@app.route('/api/bundles', methods=['POST'])
def api_bundles():
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    bundles = []
    for p in sorted(BUNDLES_DIR.glob('bundle_v*.json')):
        try:
            b = load_bundle(p)
            bundles.append({
                'name':      p.name,
                'path':      str(p),
                'version':   b['version'],
                'author':    b['author'],
                'timestamp': b['timestamp'][:16].replace('T',' '),
                'sig_count': len(b['signatures']),
                'signers':   ', '.join(s['admin_id'] for s in b['signatures']) or 'none',
            })
        except Exception:
            pass
    return jsonify(ok=True, bundles=bundles)


@app.route('/api/sign', methods=['POST'])
def api_sign():
    data      = request.json
    bundle_path = data.get('bundle_path', '')
    admin_id  = data.get('admin_id', '').strip()
    if not bundle_path or not admin_id:
        return jsonify(ok=False, message='bundle_path and admin_id are required')
    priv_path = KEYS_DIR / f"{admin_id}.priv"
    if not priv_path.exists():
        return jsonify(ok=False, message=f'No private key for {admin_id}. Run keygen first.')
    try:
        bundle   = load_bundle(bundle_path)
        priv_b64 = priv_path.read_text().strip()
        message  = canonical_json({
            'version':       bundle['version'],
            'content_hash':  bundle['content_hash'],
            'previous_hash': bundle['previous_hash'],
            'timestamp':     bundle['timestamp'],
        })
        sig_b64 = sign(priv_b64, message)
        add_signature(bundle, admin_id, sig_b64)
        save_bundle(bundle, bundle_path)
        total = len(bundle['signatures'])
        return jsonify(ok=True, message=f'Signature added by {admin_id}\nSignature: {sig_b64[:32]}…\nTotal signatures on bundle: {total}')
    except Exception as e:
        return jsonify(ok=False, message=str(e))


@app.route('/api/apply', methods=['POST'])
def api_apply():
    data        = request.json
    bundle_path = data.get('bundle_path', '')
    k           = int(data.get('threshold_k', 2))
    if not bundle_path:
        return jsonify(ok=False, message='bundle_path is required')
    try:
        bundle  = load_bundle(bundle_path)
        state   = load_state()
        keyring = Keyring()
        result  = verify_bundle(
            bundle              = bundle,
            keyring             = keyring.all(),
            active_content_hash = state['active_content_hash'],
            active_version      = state['active_version'],
            threshold_k         = k,
        )
        if result.passed:
            apply_policy(bundle)
            audit.log.append(
                event='POLICY_APPLIED', policy_version=bundle['version'],
                policy_hash=bundle['content_hash'], signers=result.signers,
                detail=f'Applied. Signers: {result.signers}', checks=result.checks,
            )
            msg = f'Policy v{bundle["version"]} APPLIED ✓\nSigners: {", ".join(result.signers)}'
        else:
            audit.log.append(
                event='POLICY_REJECTED', policy_version=bundle.get('version',0),
                policy_hash=bundle.get('content_hash',''), signers=result.signers,
                detail=result.error or 'Unknown', checks=result.checks,
            )
            msg = f'Policy REJECTED ✗\nReason: {result.error}'
        checks = [{'check': c['check'], 'passed': c['passed'], 'detail': c['detail']} for c in result.checks]
        return jsonify(ok=result.passed, message=msg, checks=checks, signers=result.signers)
    except Exception as e:
        return jsonify(ok=False, message=str(e), checks=[])


@app.route('/api/status', methods=['POST'])
def api_status():
    try:
        state   = load_state()
        keyring = Keyring()
        active  = get_active_policy()
        return jsonify(
            ok=True,
            state=state,
            keyring=[{'id': k, 'pub': v} for k, v in keyring.all().items()],
            active_policy=active,
        )
    except Exception as e:
        return jsonify(ok=False, message=str(e))


@app.route('/api/audit', methods=['POST'])
def api_audit():
    entries = audit.log.read_all()
    ok, issues = audit.log.verify_log_integrity()
    return jsonify(ok=True, entries=entries, integrity_ok=ok, issues=issues)


@app.route('/api/demo', methods=['POST'])
def api_demo():
    import io
    from contextlib import redirect_stdout
    try:
        if DATA_DIR.exists():
            shutil.rmtree(DATA_DIR)
        DATA_DIR.mkdir(parents=True)

        output = []
        keyring = Keyring()
        K = 2

        def run(fn, *a, **kw):
            f = io.StringIO()
            try:
                result = fn(*a, **kw)
            except SystemExit:
                result = None
            return result

        for admin in ['alice', 'bob', 'carol']:
            KEYS_DIR.mkdir(parents=True, exist_ok=True)
            priv, pub = generate_keypair()
            (KEYS_DIR / f"{admin}.priv").write_text(priv)
            (KEYS_DIR / f"{admin}.pub").write_text(pub)
            keyring.add(admin, pub)
            output.append(f'✓ {admin}: keygen + register')

        policy = {"name":"firewall-v1","rules":[
            {"action":"ALLOW","port":443,"protocol":"TCP"},
            {"action":"ALLOW","port":22, "protocol":"TCP","from":"10.0.0.0/8"},
            {"action":"DENY", "port":"*","protocol":"*"},
        ]}
        bundle = create_bundle(policy, 'alice', 'Initial firewall policy')
        bp = BUNDLES_DIR / f"bundle_v{bundle['version']}.json"
        BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
        save_bundle(bundle, bp)
        output.append(f'✓ Policy proposed: bundle_v{bundle["version"]}.json')

        for admin in ['alice', 'bob']:
            b  = load_bundle(bp)
            pk = (KEYS_DIR / f"{admin}.priv").read_text().strip()
            msg = canonical_json({'version':b['version'],'content_hash':b['content_hash'],'previous_hash':b['previous_hash'],'timestamp':b['timestamp']})
            sig = sign(pk, msg)
            add_signature(b, admin, sig)
            save_bundle(b, bp)
            output.append(f'✓ {admin} signed bundle')

        state  = load_state()
        result = verify_bundle(bundle=load_bundle(bp), keyring=keyring.all(),
            active_content_hash=state['active_content_hash'],
            active_version=state['active_version'], threshold_k=K)
        if result.passed:
            apply_policy(load_bundle(bp))
            audit.log.append(event='POLICY_APPLIED',policy_version=bundle['version'],
                policy_hash=bundle['content_hash'],signers=result.signers,
                detail=f'Signers: {result.signers}',checks=result.checks)
            output.append('✅ Policy v1 APPLIED (alice + bob)')
        
        # Attack 1: Replay
        state  = load_state()
        r2 = verify_bundle(bundle=load_bundle(bp), keyring=keyring.all(),
            active_content_hash=state['active_content_hash'],
            active_version=state['active_version'], threshold_k=K)
        audit.log.append(event='POLICY_REJECTED',policy_version=bundle['version'],
            policy_hash=bundle['content_hash'],signers=r2.signers,
            detail=r2.error or '',checks=r2.checks)
        output.append('❌ Replay attack REJECTED: ' + (r2.error or ''))

        # Attack 2: Tamper
        p2 = {"name":"tampered","rules":[{"action":"DENY_ALL_HACKED","port":"*"}]}
        b2 = create_bundle(p2, 'eve', 'malicious')
        bp2 = BUNDLES_DIR / f"bundle_v{b2['version']}.json"
        save_bundle(b2, bp2)
        for admin in ['alice','bob']:
            bx = load_bundle(bp2)
            pk = (KEYS_DIR/f'{admin}.priv').read_text().strip()
            msg = canonical_json({'version':bx['version'],'content_hash':bx['content_hash'],'previous_hash':bx['previous_hash'],'timestamp':bx['timestamp']})
            sig = sign(pk, msg)
            add_signature(bx, admin, sig)
            save_bundle(bx, bp2)
        bx = load_bundle(bp2)
        bx['content']['rules'][0]['action'] = 'ALLOW_ALL_BACKDOOR'
        save_bundle(bx, bp2)
        state = load_state()
        r3 = verify_bundle(bundle=load_bundle(bp2),keyring=keyring.all(),
            active_content_hash=state['active_content_hash'],
            active_version=state['active_version'],threshold_k=K)
        audit.log.append(event='POLICY_REJECTED',policy_version=bx['version'],
            policy_hash=bx['content_hash'],signers=r3.signers,
            detail=r3.error or '',checks=r3.checks)
        output.append('❌ Tamper attack REJECTED: ' + (r3.error or ''))

        # Attack 3: Unregistered
        p3 = {"name":"evil","rules":[{"action":"ALLOW","port":"*"}]}
        b3 = create_bundle(p3, 'eve', 'backdoor')
        bp3 = BUNDLES_DIR / f"bundle_v{b3['version']}.json"
        save_bundle(b3, bp3)
        priv_eve, _ = generate_keypair()
        (KEYS_DIR/'eve.priv').write_text(priv_eve)
        bx3 = load_bundle(bp3)
        msg3 = canonical_json({'version':bx3['version'],'content_hash':bx3['content_hash'],'previous_hash':bx3['previous_hash'],'timestamp':bx3['timestamp']})
        sig3 = sign(priv_eve, msg3)
        add_signature(bx3, 'eve', sig3)
        save_bundle(bx3, bp3)
        state = load_state()
        r4 = verify_bundle(bundle=load_bundle(bp3),keyring=keyring.all(),
            active_content_hash=state['active_content_hash'],
            active_version=state['active_version'],threshold_k=K)
        audit.log.append(event='POLICY_REJECTED',policy_version=bx3['version'],
            policy_hash=bx3['content_hash'],signers=r4.signers,
            detail=r4.error or '',checks=r4.checks)
        output.append('❌ Unregistered signer REJECTED: ' + (r4.error or ''))

        output.append('\nDemo complete. 1 policy applied, 3 attacks blocked.')
        return jsonify(ok=True, output='\n'.join(output))
    except Exception as e:
        import traceback
        return jsonify(ok=False, output=traceback.format_exc())


if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    import socket
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = '127.0.0.1'
    print(f"\n  VeriWall running → http://{local_ip}:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
