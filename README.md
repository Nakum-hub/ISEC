# ISEC — Internal Security Evidence Collector v2.0

> **Enterprise-grade forensic evidence collection platform** with a full-featured Electron UI, immutable chain of custody, cryptographic integrity verification, and automated threat intelligence.

---

## 🔍 What is ISEC?

ISEC is a forensic-grade desktop application that collects, secures, and analyses digital evidence from a Windows/Linux workstation. It is designed for internal security investigations, HR misconduct reviews, and incident response — with court-admissible chain of custody documentation.

---

## ✨ Key Features (v2.0)

### Evidence Collection
- **System Logs** — Windows Event Log / journald entries with severity classification
- **Browser History** — Chrome, Firefox, Edge history with consent management
- **Network Connections** — Active and historical TCP/UDP connections with IP attribution
- **File Metadata** — Filesystem access patterns, timestamps, and ownership

### Security & Integrity
- **HMAC-signed records** — every evidence item is cryptographically signed on collection
- **SHA-256 hash chain** — each record links to its predecessor, forming an unbreakable chain
- **Tampering detection** — automatic alerts if the evidence store is modified externally
- **Encrypted SQLite** — evidence database protected at rest

### UI (Electron v2.0)
| View | Description |
|------|-------------|
| **Dashboard** | Live stat cards, Canvas donut/line/gauge charts, quick-collect buttons |
| **Evidence Timeline** | Full-text search, type/severity filter pills, expandable chain-of-custody detail |
| **Threat Analysis** | Automated risk scoring (0–100), anomaly detection, pattern recognition, recommendations |
| **Audit Log** | Immutable action history, filterable table, CSV export |
| **Report Export** | Live preview, PDF/JSON/CSV/HTML output, report history |

### Compliance & Access Control
- **Role-based access** — `collector`, `reviewer`, `exporter` roles with enforced permissions
- **Admin token authentication** — role changes require a secure admin token
- **Retention policy engine** — configurable evidence expiry with automated enforcement
- **Offline license validation** — Ed25519 signed license with system fingerprint binding

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+ with packages in `requirements.txt`
- Node.js 18+ and npm
- Electron 28+

### Installation

```bash
# 1. Clone repository
git clone https://github.com/Nakum-hub/ISEC.git
cd ISEC

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Electron UI dependencies
cd ui && npm install

# 4. Place your license file
cp your-license.json license.json

# 5. Configure admin token (for role switching)
mkdir -p ~/.config/isec-desktop-app/state/keys/
echo "your-secure-token" > ~/.config/isec-desktop-app/state/keys/role_admin_token.txt

# 6. Start the application
npm start
```

---

## 🏗 Architecture

```
ISEC/
├── main.py                          # Python backend entry point
├── license.json                     # Ed25519-signed license file
├── keys/
│   └── license_public_key.pem       # License verification key
├── src/
│   ├── collectors/                  # Evidence collection modules
│   │   ├── system_logs.py
│   │   ├── browser_history.py
│   │   ├── network_connections.py
│   │   └── file_metadata.py
│   ├── core/collector.py            # Orchestration & HMAC signing
│   ├── storage/database.py          # Encrypted SQLite + hash chain
│   ├── reporting/report_generator.py# PDF / JSON / CSV export
│   └── utils/
│       ├── license_manager.py       # Ed25519 license validation
│       ├── role_manager.py          # RBAC with admin token auth
│       └── retention_engine.py      # Evidence lifecycle management
└── ui/                              # Electron application
    ├── main.js                      # Electron main process + IPC handlers
    ├── index.html                   # App shell
    ├── js/
    │   ├── charts.js                # Canvas charting engine (no external deps)
    │   ├── notifications.js         # Toast notification system
    │   ├── dashboard.js             # Dashboard logic & chart rendering
    │   ├── timeline.js              # Evidence timeline (search/filter/paginate)
    │   ├── detail-view.js           # Chain-of-custody & integrity viewer
    │   ├── threat-analysis.js       # Risk scoring & anomaly detection
    │   ├── audit-log.js             # System action history
    │   └── report-export.js         # Report generation & history
    ├── views/                       # HTML view fragments
    └── css/                         # Scoped stylesheets
```

---

## 🔐 License

ISEC uses **Ed25519-signed licenses** with system fingerprint binding to prevent unauthorised redistribution. Contact your ISEC vendor to obtain a valid license file.

---

## 📜 Chain of Custody

Every evidence record follows this custody chain:

```
Capture → HMAC Sign → Hash Chain Link → Encrypt → Store → Verify → Report
```

All steps are logged in the immutable audit trail and can be exported as a forensic PDF report suitable for legal proceedings.

---

*ISEC v2.0 — Built for forensic integrity. Designed for security professionals.*
