# ISEC Release Notes v1.0.0

Release date: February 14, 2026

## Highlights

- Signed Windows installer release pipeline executed end-to-end.
- Build traceability enforced with `build_manifest.json` and `ui/dist/SHA256SUMS.txt`.
- Production runtime hardening:
  - fail-closed startup validation
  - strict production env guardrails
  - unsafe bypass env vars blocked
- Export verification strengthened:
  - independent verification context isolation
  - deterministic tamper detection outcomes
- Red-team pass completed with remediation of trust-boundary and env override risks.

## Evidence Produced

- Installer: `ui/dist/ISEC Evidence Collector Setup 1.0.0.exe`
- Build manifest: `build_manifest.json`
- Checksums: `ui/dist/SHA256SUMS.txt`
- Tamper proof report: `docs/tamper_validation_report_v1.0.md`
- Internal red-team report: `docs/internal_red_team_report_v1.0.md`

## Security Fixes Included in v1.0.0

- Removed renderer fallback direct IPC path in `ui/js/evidence-viewer.js`.
- Blocked inline production trust-root override via `ISEC_LICENSE_PUBLIC_KEY`.
- Enforced checksum requirement for offline update package manifest.
- Isolated verifier runtime from host-local key overrides in `verify_export.py`.

## Operational Notes

- The signed build demonstration used a local self-signed certificate for workflow validation.
- Production distribution should replace demo certificate with enterprise CA-backed signing material.
