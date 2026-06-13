# CI Workflow Templates

These are ready-to-use GitHub Actions workflows. They live here (not under
`.github/workflows/`) because the automated tooling that authored them cannot
write into `.github/workflows/*`. **Enabling them is a one-step move you do
yourself.**

## How to enable

From a local clone:

```bash
git mv ci-templates/release.yml .github/workflows/release.yml
git mv ci-templates/test-os.yml .github/workflows/test-os.yml
git commit -m "ci: enable release + cross-platform workflows"
git push
```

Or in the GitHub web UI: open each file, copy its contents into a new file at
`.github/workflows/<name>.yml`, and commit.

## What each workflow does

### `release.yml`
Triggered on a pushed tag matching `v*`. Produces and publishes to the GitHub
Release:
- a CycloneDX SBOM (`scripts/generate_sbom.py`),
- a reproducible source tarball,
- `SHA256SUMS` + `release-manifest.json` (`scripts/generate_release_manifest.py`),
- a keyless **SLSA build-provenance attestation** (GitHub OIDC).

Cut a release with, e.g.:
```bash
git tag v2.0.1
git push origin v2.0.1
```

### `test-os.yml`
Runs the test + coverage suite on **Linux, macOS, and Windows** on every push
and pull request to `main`. This is what catches platform-specific collector
bugs before they ship.

## User-side steps the tooling cannot do for you

1. **Branch protection on `main`** (Settings -> Branches -> Add rule):
   - Require pull requests before merging.
   - Require status checks to pass: select `python-security-and-tests` (from
     `security-gate.yml`) and the three `test-os.yml` jobs once they have run
     at least once.
   - Require branches to be up to date before merging.
   - (Recommended) Require signed commits.
2. **Enable the workflows** by moving the files as shown above.
3. **Tag a release** to exercise `release.yml` end-to-end.

These are intentionally manual: they change repository security posture and
should be reviewed by a human.
