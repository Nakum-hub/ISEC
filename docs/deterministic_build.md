# Deterministic Build Guide

## Objective

Produce reproducible ISEC release artifacts with pinned dependencies, integrity metadata, and signature enforcement.

## 1. Python Dependency Reproducibility

- `requirements.txt` pins exact package versions.
- `requirements.lock.txt` enforces hash-verified installs (`--require-hashes`) for release environment.

Install deterministic Python dependencies:

```bash
python -m pip install --require-hashes -r requirements.lock.txt
```

## 2. Node Dependency Reproducibility

- `ui/package-lock.json` is committed and treated as source of truth.
- Use `npm ci` instead of `npm install` for deterministic package tree resolution.

```bash
cd ui
npm ci
```

## 3. Production Build Enforcement

- Set `ISEC_ENV=production`.
- Ensure no insecure bypass variables are set:
  - `ISEC_ALLOW_UNLICENSED`
  - `ISEC_DEV_ALLOW_UNLICENSED`
  - `ISEC_ROLE_AUTH_BYPASS`
- Run release workflow:

```bash
python scripts/release_build.py
```

## 4. Release Artifact Traceability

The release workflow generates:

- `build_manifest.json`:
  - build timestamp (UTC)
  - git commit hash
  - python and node dependency versions
  - per-artifact SHA256 hashes
  - installer signature verification status
- `ui/dist/SHA256SUMS.txt`:
  - SHA256 digest list for built artifacts and manifest file

## 5. Verification Before Distribution

- Test gate:

```bash
python scripts/run_quality_gate.py
```

- Export verification:

```bash
python verify_export.py <export.zip>
```

- Tamper simulation proof:

```bash
python scripts/simulate_tamper.py <export.zip>
```
