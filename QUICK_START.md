# ISEC v2.0 Enterprise — Quick Start Guide

## Installation (2 minutes)

### Windows
1. Double-click **ISEC-Setup-2.0.0.exe**
2. Follow the installer — click Next → Install → Finish
3. Launch **ISEC** from the desktop shortcut

### Mac
1. Open **ISEC-2.0.0.dmg**
2. Drag ISEC to your Applications folder
3. Right-click → Open (first launch only, to bypass Gatekeeper)

### Linux
1. `chmod +x ISEC-2.0.0.AppImage`
2. `./ISEC-2.0.0.AppImage`

---

## First Launch — Setup Wizard

ISEC will automatically open the **Setup Wizard** on first launch.

**Step 1 — Welcome:** Read the overview, click "Get Started"

**Step 2 — License:** Paste your `license.json` contents (provided by your ISEC vendor)
or click "Browse" to load the file directly.

**Step 3 — System Verification:** ISEC checks Python and all dependencies automatically.
If anything fails, contact support with the error message shown.

**Step 4 — Admin Token:** ISEC generates a secure admin token automatically.
**⚠️ Copy this token and save it** in a password manager — it is needed to switch user roles.

**Step 5 — Launch:** Click "Launch ISEC" — the main application opens.

---

## User Roles

| Role | Can Collect | Can Export | Can Report |
|---|---|---|---|
| **Collector** | ✅ | ✗ | ✗ |
| **Reviewer** | ✗ | ✗ | ✗ |
| **Exporter** | ✗ | ✅ | ✅ |

Switch roles via the dropdown in the bottom-left sidebar.
The admin token is required for role changes.

---

## Collecting Evidence

1. Click **"Collect Evidence"** on the Dashboard, or
2. Use the quick-collect buttons (System / Browser / Network / Files), or
3. Press **Ctrl+K** → type "collect" → select a collection type

Evidence is automatically:
- HMAC-signed with a unique key
- Linked into an immutable SHA-256 hash chain
- Stored in an encrypted SQLite database

---

## Generating a Report

1. Click **Report Export** in the left sidebar
2. Select evidence types and report sections
3. Enter a case name and analyst name
4. Click **Generate Report**

Reports are saved to your Documents folder as PDF.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| **Ctrl+K** | Open Command Palette |
| **?** | Show all keyboard shortcuts |
| **G + D** | Go to Dashboard |
| **G + T** | Go to Timeline |
| **G + C** | Go to Cases |
| **G + A** | Go to Threat Analysis |
| **Ctrl+Enter** | Start evidence collection |

---

## Support

For technical support, contact your ISEC vendor with:
- Your License ID (visible in the Dashboard → License Details panel)
- Your OS version and ISEC version (v2.0 Enterprise)
- A description of the issue
