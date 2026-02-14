# Changelog

All notable changes to ISEC are documented in this file.

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
