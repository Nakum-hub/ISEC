# Supply Chain & Trust Foundation

This document describes how ISEC's software supply chain is made auditable and
verifiable. It is written for security reviewers, prospective adopters, and
anyone who needs to independently confirm what ISEC ships.

Nothing here requires trusting the maintainer's word: every claim below maps to
an artifact you can regenerate or verify yourself.

---

## 1. Software Bill of Materials (SBOM)

ISEC ships a CycloneDX 1.5 SBOM for its pinned Python dependencies.

Generate it from the pinned lockfile:

```bash
python scripts/generate_sbom.py -i requirements.lock.txt -o sbom/isec-python.cdx.json
```

Properties:

- **Format:** CycloneDX 1.5 (JSON), consumable by Dependency-Track, Grype,
  Trivy, `cyclonedx-cli`, and most SCA tooling.
- **Integrity:** each component carries the SHA-256 hash pinned in
  `requirements.lock.txt` (the lock is generated with `--require-hashes`).
- **Reproducible:** set `SOURCE_DATE_EPOCH` to a fixed UNIX timestamp to get a
  byte-identical SBOM (deterministic timestamp + content-derived serial), so
  the SBOM can be diffed in CI and across rebuilds.

```bash
SOURCE_DATE_EPOCH=1700000000 python scripts/generate_sbom.py
```

## 2. Release checksum manifest

Every release artifact set is accompanied by checksums so downloads can be
verified offline.

```bash
python scripts/generate_release_manifest.py dist/
```

This writes two files into the artifact directory:

- `SHA256SUMS` -- coreutils-compatible; verify with:
  ```bash
  sha256sum -c SHA256SUMS
  ```
- `release-manifest.json` -- structured manifest with size, SHA-256, and
  SHA-512 for each artifact.

## 3. Dependency pinning

- `requirements.txt` -- direct runtime dependencies (minimum versions).
- `requirements-dev.txt` -- test/audit tooling (`pytest`, `pytest-cov`,
  `pip-audit`).
- `requirements.lock.txt` -- fully pinned, hash-locked dependency set used for
  reproducible release builds (`--require-hashes`).

**Known follow-up (tracked):** the hash-locked versions in
`requirements.lock.txt` currently trail the floors declared in
`requirements.txt` for a few packages (e.g. `cryptography`, `Pillow`,
`reportlab`). The lock must be regenerated against the current `requirements.txt`
before the next tagged release so the shipped SBOM matches the runtime
floors. Until then, treat `requirements.txt` as the source of truth for runtime
and the lock as the reproducible-build pin.

## 4. Dependency vulnerability scanning

CI runs dependency audits on every push and pull request:

- **Python:** `pip-audit` against `requirements.txt` (informational signal).
- **Node (UI):** `npm audit --audit-level=moderate` (informational signal).

These are intentionally non-blocking so a newly disclosed upstream CVE does not
break unrelated builds; they surface findings for triage. The blocking gate is
the test + coverage suite.

## 5. Build provenance (in progress)

The trust roadmap adds, via CI on tagged releases:

- **SBOM publication** -- the CycloneDX SBOM attached to each GitHub Release.
- **SLSA build provenance** -- signed attestation of how/where artifacts were
  built, using GitHub's OIDC-based artifact attestations.
- **Checksum manifest** -- `SHA256SUMS` + `release-manifest.json` attached to
  each release.

These live in release workflows under `.github/workflows/`.

## 6. Code signing (planned, not yet enabled)

Windows Authenticode and macOS notarization require paid certificates and are
**not** enabled yet. Until they are, verify downloads using the published
checksums and (once available) the SLSA provenance attestation. This limitation
is stated plainly rather than implied to be solved.

---

## Quick verification checklist

| Goal | Command |
| --- | --- |
| Regenerate the SBOM | `python scripts/generate_sbom.py` |
| Reproduce the SBOM byte-for-byte | `SOURCE_DATE_EPOCH=<epoch> python scripts/generate_sbom.py` |
| Verify release downloads | `sha256sum -c SHA256SUMS` |
| Scan dependencies for CVEs | `python -m pip_audit -r requirements.txt` |
| Confirm hash-locked installs | `pip install --require-hashes -r requirements.lock.txt` |
