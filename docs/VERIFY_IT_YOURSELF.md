# Verify ISEC Yourself

This guide lets you independently confirm that ISEC actually works end-to-end on
a real machine. Nothing here uses mock or sample data — every step exercises the
real collectors, the encrypted store, the hash chain, and the signed export.

For installation of a packaged build and the in-app workflow, see
[`QUICK_START.md`](../QUICK_START.md). For building installers, see
[`BUILD.md`](../BUILD.md).

## Prerequisites

- Python 3.11+ and `pip`
- Node.js 18+ and `npm` (for the Electron UI)
- Git

```bash
git clone https://github.com/Nakum-hub/ISEC.git
cd ISEC
pip install -r requirements.txt
```

## 1. Run the automated test suite

The repository ships with a real pytest suite (see `tests/` and `pytest.ini`),
including the role-forgery security regression tests.

```bash
pip install -r requirements-dev.txt
pytest
```

A green run confirms the storage hash chain, role-based access control,
license verification, and chain-of-custody logic behave as expected.

## 2. Launch the application

**Windows (PowerShell):**

```powershell
./run_isec.ps1
```

This installs UI dependencies if needed, creates the `evidence_output/`
directory, and starts the Electron interface, which launches the Python backend.
Use `./run_isec.ps1 -ResetDatabase` to start from a clean evidence database, or
`-SkipNpmInstall` to skip the dependency check.

**macOS / Linux:** install the UI dependencies and start Electron from the `ui/`
directory:

```bash
cd ui
npm install
npm start
```

On first launch, complete the setup wizard (load `license.json`, then copy and
save the generated admin token — you need it to switch roles).

## 3. Collect real evidence

With the **Collector** role active, run a collection from the dashboard (or the
quick-collect buttons). ISEC will read real data from the host:

- System logs (Windows event log / Unix syslog)
- Network connections (`netstat` / `ss`)
- File metadata (size, timestamps, permissions, owner)
- Browser history (only if you grant browser-data consent)

Each record is HMAC-signed and linked into a SHA-256 hash chain in an encrypted
SQLite database under `evidence_output/`.

## 4. Export and verify

1. Switch to the **Exporter** role (admin token required) and generate a report
   / evidence export. This produces a ZIP containing the evidence database, a
   signed report, the signing public key, and a `checksum_manifest.json`.
2. Verify that export independently with the bundled verifier:

```bash
python verify_export.py path/to/evidence_export_YYYYMMDD_HHMMSS.zip
```

Add `--json` for full machine-readable output. The verifier checks the manifest
schema, every file hash, the evidence-database hash, the full chain of custody
(hash chain + per-record HMAC signatures), and the PDF report signature. All
checks must report `PASS`.

## 5. (Optional) Confirm tamper detection

To see the integrity guarantees fail safely: make a copy of an exported ZIP,
modify any byte of the contained `evidence.db`, re-zip it, and run
`verify_export.py` against the tampered archive. It must report `FAIL` with an
explicit reason. This demonstrates that altered evidence cannot pass
verification.

---

If steps 1–4 pass on your machine, you have an independently verified,
end-to-end working build.
