# ISEC — Build Guide (Packaged Installer)

This guide creates a standalone `.exe` (Windows), `.dmg` (Mac), or `.AppImage` (Linux)
that the buyer can install without any developer setup.

---

## Prerequisites (on your BUILD machine only — not the buyer's)

- **Node.js 18+** → https://nodejs.org
- **Python 3.10+** → https://python.org
- **Windows**: additionally install [NSIS](https://nsis.sourceforge.io) for the `.exe` installer

---

## Step 1 — Build the Python backend binary

```bash
# This bundles Python + all dependencies into a single executable
python build_backend.py --platform windows   # for Windows build
python build_backend.py --platform mac       # for Mac build
python build_backend.py --platform linux     # for Linux build
```

Output: `ui/backend_dist/isec-backend` (or `isec-backend.exe` on Windows)

---

## Step 2 — Update package.json extraResources

The `ui/package.json` already includes `extraResources` for the Python backend.
After building, the binary will be auto-included in the Electron package.

Add this to `ui/package.json` under `"build"` → `"extraResources"`:

```json
{
  "from": "backend_dist/isec-backend",
  "to": "backend/isec-backend"
}
```

---

## Step 3 — Install Electron dependencies

```bash
cd ui
npm install
```

---

## Step 4 — Build the installer

```bash
cd ui

# Windows .exe installer
npx electron-builder --win

# Mac .dmg
npx electron-builder --mac

# Linux .AppImage
npx electron-builder --linux
```

Output: `ui/dist/` — contains the installer file ready to send to buyer.

---

## Step 5 — Generate buyer license

Each buyer gets a license locked to THEIR machine fingerprint:

```bash
python generate_license.py \
  --customer "Acme Corp" \
  --plan Enterprise \
  --private-key keys/license_private_key.pem
```

The buyer runs ISEC once, it shows their machine fingerprint,
they send it to you, you generate the license and send back `license.json`.

---

## What the Buyer Receives

```
📦 ISEC-Setup-2.0.0.exe         ← Windows installer (or .dmg / .AppImage)
📄 license.json                  ← Their machine-specific license
📄 QUICK_START.pdf               ← One-page guide
```

**Buyer experience:**
1. Run `ISEC-Setup-2.0.0.exe` → installs to Program Files
2. Launch ISEC → Setup wizard opens automatically
3. Paste `license.json` contents → validated
4. Admin token auto-generated → save it
5. Click "Launch ISEC" → ready to use

**Zero Python. Zero npm. Zero command line.**
