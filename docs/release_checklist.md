# ISEC Enterprise Release Checklist

## 1. Test and Coverage Gates

- [ ] `python -m pip install -r requirements-dev.txt`
- [ ] `python -m pip_audit -r requirements.txt` (no known vulnerabilities)
- [ ] `cd ui && npm audit --audit-level=moderate` (0 vulnerabilities)
- [ ] `python -m pytest`
- [ ] `python scripts/enforce_coverage.py --coverage-json coverage/coverage.json`
- [ ] Coverage is >= 85% for:
  - `src/utils/license_manager.py`
  - `src/utils/role_manager.py`
  - `src/storage/database.py`
  - `verify_export.py`

## 2. License and Access Control Validation

- [ ] Valid signed license accepted
- [ ] Invalid license signature rejected
- [ ] Expired license rejected
- [ ] Feature flags enforced (no feature, no module path)
- [ ] Role auth brute-force lock works (5 failures, lockout)

## 3. Integrity and Export Validation

- [ ] `python verify_export.py <valid_export.zip>` succeeds
- [ ] `python scripts/simulate_tamper.py <valid_export.zip>` detects all tamper scenarios
- [ ] DB tamper simulation detected
- [ ] Manifest checksum tamper simulation detected
- [ ] PDF signature tamper simulation detected

## 4. Release Build and Signing

- [ ] `ISEC_ENV=production` set for release run
- [ ] `python scripts/release_build.py` completes
- [ ] Installer signatures verified (Authenticode/codesign)
- [ ] `build_manifest.json` generated
- [ ] `ui/dist/SHA256SUMS.txt` generated

## 5. Production Safety Checks

- [ ] No bypass env vars set:
  - `ISEC_ALLOW_UNLICENSED`
  - `ISEC_DEV_ALLOW_UNLICENSED`
  - `ISEC_ROLE_AUTH_BYPASS`
- [ ] Production logging is not `DEBUG`/`TRACE`
- [ ] Log file is enabled in production
- [ ] Startup validator checks pass (`output_dir_writable`, `database_accessible`)

## 6. Final Release Hygiene

- [ ] `README.md` updated with current build/test commands
- [ ] `docs/security_architecture_v1.0.md` is current
- [ ] Release artifacts stored with immutable checksum records
- [ ] Git commit hash in `build_manifest.json` matches release tag
