# Changelog

All notable changes to ISEC are documented in this file.

## [Unreleased]

### Security

- **Role state is now cryptographically authenticated (fixes privilege escalation).**
  Privileged roles (collector/exporter) are only honored when the persisted role
  payload carries a valid HMAC-SHA256 tag keyed by the admin token. Forged,
  tampered, or wrong-token role files are rejected and the session falls back to
  the read-only reviewer role; rejections are logged as `role_integrity_failure`
  audit events. Previously the role file's key was derived from public system
  information, so a privileged role could be forged offline.
- **License trust anchor embedded.** The real Ed25519 verification public key is
  now embedded in the application (removing the `REPLACE_WITH_YOUR_PUBLIC_KEY`
  placeholder), so packaged builds verify licenses even when the loose
  `keys/license_public_key.pem` is absent.

### Added

- Regression suite `tests/test_role_forgery.py` proving forged/unsigned/wrong-token
  privileged roles cannot escalate and that tampering raises an audit event.
- `docs/THREAT_MODEL.md` — STRIDE-based threat model and chain-of-custody guarantees.
- `docs/PRODUCT_ONEPAGER.md` — positioning, target buyers, and pricing tiers.
- `docs/PILOT_AND_LICENSING.md` — pilot playbook and licensing/EULA outline.

### Changed

- `SECURITY.md` now documents role-state authentication, random HMAC key handling,
  and the embedded license trust anchor.

### Removed

- Leaked runtime/evidence sample files removed from the working tree. NOTE: git
  history still retains older copies until history is rewritten or the repository
  is made private.

## [1.0.0] - 2026-02-14

### Added

- Production release gate tooling:
  - `scripts/release_build.py`
  - `scripts/create_build_manifest.py`
  - `scripts/enforce_coverage.py`
  - `scripts/run_quality_gate.py`
- Deterministic dependency artifacts:
  - `requirements.lock.txt`
  - `pytest.ini` coverage gating config
- Tamper and security documentation:
  - `docs/tamper_validation_report_v1.0.md`
  - `docs/internal_red_team_report_v1.0.md`
  - `docs/security_architecture_v1.0.md`
  - `docs/release_notes_v1.0.0.md`
  - `docs/release_checklist.md`
  - `docs/deterministic_build.md`

### Changed

- Release build path now enforces signed artifacts and traceability manifest generation.
- Build metadata now includes explicit `version` in `build_manifest.json`.
- Electron build scripts now default to release workflow (`npm run build` runs release gate).
- Production runtime hardening via `src/utils/runtime_config.py` integrated into backend startup.
- License verifier now ignores inline public key override in production.
- Export verifier now uses isolated runtime environment for integrity checks.
- Offline update check now requires checksum presence and validation.

### Fixed

- Fixed electron-builder failure caused by empty `ui/assets/icon.png` / `ui/assets/logo.svg`.
- Fixed renderer IPC trust boundary fallback in `ui/js/evidence-viewer.js`.
- Fixed checksum index self-reference inconsistency in `SHA256SUMS.txt` generation.

### Security

- Confirmed tamper detection behavior: clean export passes, tampered exports fail with explicit reasons.
- Confirmed role auth backoff and lockout behavior under repeated invalid token attempts.
- Confirmed production startup blocks insecure env overrides and insecure logging mode.
