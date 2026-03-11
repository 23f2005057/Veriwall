# VeriWall — Deployment Guide

## Project Structure (upload all of this)
```
veriwall/
├── __init__.py
├── audit/__init__.py
├── core/__init__.py
├── core/hasher.py
├── core/signer.py
├── core/verifier.py
├── keyring/__init__.py
├── keyring/registry.py
├── policy/__init__.py
├── policy/enforcer.py
└── policy/packager.py
veriwall.py
server.py
requirements.txt
Procfile          ← for Render
railway.toml      ← for Railway
```

---

## Deploy to Render (Free)

1. Push all files to a GitHub repo
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Settings:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn server:app --bind 0.0.0.0:$PORT --workers 1`
5. Click **Deploy**
6. Your URL will be: `https://veriwall-xxxx.onrender.com`

> Note: Render free tier spins down after 15min of inactivity.
> Data resets on each deploy (cloud filesystem is ephemeral).

---

## Deploy to Railway (Recommended — faster)

1. Push all files to a GitHub repo
2. Go to https://railway.app → New Project → Deploy from GitHub
3. Select your repo — Railway auto-detects Python
4. It uses `railway.toml` automatically
5. Your URL will be: `https://veriwall-xxxx.up.railway.app`

> Railway gives $5 free credit/month — enough for demos.

---

## Important: Cloud Data is Temporary

Both Render and Railway have **ephemeral filesystems** — data is lost when
the server restarts. This is fine for demos! Every `Full Demo` run starts fresh.

For persistent storage, you would need to add a database (PostgreSQL on Railway
is one click) — not needed for academic demo purposes.

---

## Local Run

```bash
pip install flask cryptography gunicorn
python server.py
# Open http://localhost:5000
```
