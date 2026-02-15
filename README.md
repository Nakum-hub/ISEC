# Internal Security Evidence Collector (ISEC)
![Version](https://img.shields.io/badge/version-v1.0.0-0ea5e9)
![Coverage Gate](https://img.shields.io/badge/coverage%20gate-85%25%2B-brightgreen)

A forensic-grade evidence collection tool for internal security investigations. This application runs completely offline and collects system logs, browser history, network connections, and file metadata with full chain of custody tracking. Enhanced with advanced security measures to protect evidence integrity.

## Features

- **Offline Operation**: Runs completely offline with no internet connectivity required
- **Cross-Platform**: Supports Windows and Linux operating systems
- **Comprehensive Collection**: Gathers system logs, browser history, network connections, and file metadata
- **Immutable Storage**: Uses encrypted SQLite database with multiple hash algorithms for integrity
- **Chain of Custody**: Tracks all evidence handling with timestamps, actors, and digital signatures
- **Forensic Reports**: Generates PDF reports suitable for legal proceedings
- **Secure Export**: Creates ZIP archives with checksum manifests
- **Enhanced Security**: Implements database encryption, input validation, and tamper detection

## Security Enhancements

- **Database Encryption**: All evidence stored using Fernet symmetric encryption
- **Multiple Hash Algorithms**: SHA-256, SHA-512, and HMAC-SHA256 for collision resistance
- **Input Validation**: Multi-layered validation with dangerous pattern blocking
- **Parameterized Queries**: Prevents SQL injection vulnerabilities
- **Secure Temp Files**: Restricted permissions (0o600) for temporary files
- **Integrity Verification**: Real-time integrity checking with automatic verification
- **Chain of Custody**: Detailed tracking with actor, workstation, IP, and digital signatures
- **Thread Safety**: Threading locks for concurrent access protection
- **Access Logging**: Comprehensive security logging for all operations

## Requirements

- Python 3.10 or higher
- Windows or Linux operating system
- Administrative/root privileges for accessing system logs and browser data
- cryptography library for encryption features

## Installation

1. Clone or download this repository
2. Navigate to the project directory
3. If you cloned from GitHub, install Git LFS and pull large files:

```bash
git lfs install
git lfs pull
```
4. Install dependencies:

```bash
pip install -r requirements.txt
```

Deterministic install for release builds (Windows CPython 3.10 lock):
```bash
pip install --require-hashes -r requirements.lock.txt
```

## Usage

Basic usage:
```bash
python main.py
```

With custom output directory:
```bash
python main.py --output-dir /path/to/evidence
```

Skip PDF report generation:
```bash
python main.py --no-report
```

Export evidence as ZIP with checksum manifest:
```bash
python main.py --export-dir ./exports
```

Enable file logging and set log level:
```bash
python main.py --log-file ./logs/isec.log --log-level DEBUG
```

Disable file logging:
```bash
python main.py --no-log-file
```

All options combined:
```bash
python main.py --output-dir ./my_evidence --export-dir ./exports
```

## Licensing (Offline)

ISEC enforces an offline license for collection, reporting, and export. Place a signed `license.json` file in the project root (or pass `--license-file`).

Generate a keypair (keep the private key offline):
```bash
python scripts/generate_license_keypair.py --output-dir keys
```
Place the public key in `keys/license_public_key.pem` so the app can verify licenses.

Generate a license:
```bash
python scripts/generate_license.py --private-key keys/license_private_key.pem \
  --license-id LIC-001 --customer "Acme Corp" --plan enterprise \
  --features collect,report,export,view --expires-at 2026-12-31T23:59:59Z \
  --output license.json
```

Print the machine fingerprint for node-locked licenses:
```bash
python scripts/print_fingerprint.py
```

## Offline Updates

Drop a `manifest.json` and installer package into `updates/` to enable offline updates via the UI. See `updates/README.md` and `updates/manifest.example.json`.
For the packaged Electron app, the updates folder is located under the state directory: `<state-dir>/updates`.

## Logging & Monitoring

Backend logging defaults to `<output-dir>/isec.log`. Customize with `--log-file` and `--log-level`, or disable with `--no-log-file`.

UI logs are written to the Electron userData directory:
- Windows: `%APPDATA%\\isec-desktop-app\\logs\\isec-ui.log`
- Linux: `~/.config/isec-desktop-app/logs/isec-ui.log`

## Automated Tests

Install development dependencies and run:
```bash
pip install -r requirements-dev.txt
python -m pytest
```

Run the release quality gate (dependency audit + tests + coverage threshold enforcement):
```bash
python scripts/run_quality_gate.py
```

Coverage reports:
- HTML: `coverage/index.html`
- JSON: `coverage/coverage.json`

Per-module release gate:
- `src/utils/license_manager.py` >= 85%
- `src/utils/role_manager.py` >= 85%
- `src/storage/database.py` >= 85%
- `verify_export.py` >= 85%

Manually enforce coverage from an existing JSON report:
```bash
python scripts/enforce_coverage.py --coverage-json coverage/coverage.json
```

## Local State (Roles, Consents, Keys)

ISEC stores local state outside the repo by default (roles, consent records, encryption/HMAC keys). Override with:
```bash
python main.py --state-dir /path/to/state
```
Or set `ISEC_STATE_DIR`.

Default locations:
- Windows: `%APPDATA%\\ISEC`
- macOS: `~/Library/Application Support/ISEC`
- Linux: `~/.config/ISEC`

## Role Change Authorization

Role changes via Electron UI now require an admin token.

Configure one of:
- `ISEC_ROLE_ADMIN_TOKEN` environment variable (recommended)
- `ISEC_ROLE_ADMIN_TOKEN_FILE` pointing to a file containing the token
- Default token file: `<state-dir>/keys/role_admin_token.txt`

Example (PowerShell):
```powershell
$env:ISEC_ROLE_ADMIN_TOKEN="replace-with-strong-token"
```

Role authorization hardening:
- Token validation is rate-limited with exponential backoff.
- Session lock occurs after 5 failed attempts.
- All role auth attempts are written to the local audit trail.

## Encryption Keys

Evidence encryption keys are now generated randomly for new databases and stored in the state key directory by default.
Legacy deterministic key derivation is used only to preserve access to existing databases created before key files were introduced.

Override key locations with:
- `EVIDENCE_ENCRYPTION_KEY`
- `EVIDENCE_ENCRYPTION_KEY_FILE`
- `ISEC_HMAC_KEY`
- `ISEC_HMAC_KEY_FILE`

## Packaging & Signed Installers

Electron build configuration lives in `ui/package.json`. Use the release script for production builds:
```powershell
python scripts/release_build.py
```

This workflow enforces:
- `ISEC_ENV=production`
- no insecure dev bypass environment flags
- signed installer verification (Authenticode on Windows)
- SHA256 checksums for release artifacts
- generated `build_manifest.json` with commit + dependency traceability

Release governance docs:
- `docs/release_checklist.md`
- `docs/deterministic_build.md`
- `docs/security_architecture_v1.0.md`
- `docs/tamper_validation_report_v1.0.md`
- `docs/internal_red_team_report_v1.0.md`
- `docs/release_notes_v1.0.0.md`
- `CHANGELOG.md`

Manual Electron build (without release verification):
```bash
cd ui
npm ci
npm run build
```

Signing is driven by environment variables:
- `WIN_CERT_FILE`, `WIN_CERT_PASSWORD`
- `MAC_SIGN_IDENTITY`

macOS entitlements are defined in `ui/build/entitlements.mac.plist`.

## Export Verification CLI

Use `verify_export.py` to independently validate exported ZIP archives:

```bash
python verify_export.py /path/to/evidence_export_YYYYMMDD_HHMMSS.zip
```

JSON output:
```bash
python verify_export.py /path/to/export.zip --json
```

Verification covers:
- Manifest integrity (`checksum_manifest.json`)
- Exported file checksums
- Evidence database hash
- Chain-of-custody integrity (hash chain + HMAC signatures)
- PDF signature validation (report + sidecar + public key)

## Collected Evidence Types

1. **System Logs**: Event logs from Windows/Linux systems
2. **Browser History**: Metadata from Chrome, Edge, and Firefox browsers
3. **Network Connections**: Active connections and network configuration
4. **File Metadata**: Permissions, timestamps, and attributes of files

## Security Constraints

- No cloud calls or internet connectivity
- No telemetry or data transmission
- No automatic updates
- Strict file permission handling
- Immutable evidence storage
- Complete offline operation

## Architecture

The application follows a modular architecture:

- `core/`: Main collector orchestration
- `collectors/`: Individual evidence collection modules
- `storage/`: Database and evidence storage with encryption
- `reporting/`: Report generation
- `utils/`: Utility functions

## Output

The application generates:

1. Encrypted SQLite database with all evidence
2. Chain of custody logs with digital signatures
3. Forensic-grade PDF report
4. ZIP export with checksum manifest (optional)

## Sample Output Structure

```
evidence_collection/
├── evidence.db              # Encrypted SQLite database with all evidence
├── checksum_manifest.txt    # Manifest with integrity verification
├── forensic_report_YYYYMMDD_HHMMSS.pdf
└── evidence_export_YYYYMMDD_HHMMSS.zip
```

## Legal Compliance

This tool is designed to maintain the integrity of digital evidence according to forensic standards:
- AES-256 equivalent encryption for evidence protection
- Multiple cryptographic hashing for integrity verification
- Immutable storage in encrypted SQLite database
- Chain of custody tracking with digital signatures
- Secure export mechanisms with integrity verification
