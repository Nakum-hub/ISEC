Offline Update Channel
======================

Place an update manifest and installer package in this folder to enable offline updates.
For packaged builds, use the per-user updates folder in the state directory (e.g. `<state-dir>/updates`).

Required files:
1. `manifest.json`
2. Installer package referenced by the manifest (e.g. `ISEC-1.1.0.exe`, `ISEC-1.1.0.dmg`, `ISEC-1.1.0.AppImage`)

Manifest format:
```
{
  "version": "1.1.0",
  "package": "ISEC-1.1.0.exe",
  "sha256": "<optional sha256 hex>",
  "notes": "Release notes for this update."
}
```

Notes:
- The app compares `version` with the current app version.
- If `sha256` is provided, the app verifies the installer hash before allowing apply.
- Updates are applied by launching the installer; follow its prompts to complete the update.
