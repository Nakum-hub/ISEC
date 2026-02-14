# ISEC Internal Red-Team Report v1.0

## Assessment Date

- February 14, 2026

## Objective

Adversarially test bypass paths for:

- license enforcement
- role authorization throttling
- export verification
- production runtime enforcement
- IPC trust boundaries

Assumption: malicious insider with local machine access.

## Attack Exercises and Results

| Target | Attack Attempt | Result |
|---|---|---|
| License enforcement | Tampered signed license payload (`.phase4/license_tampered.json`) | Blocked: `invalid_signature` |
| Role auth throttling | Repeated invalid role auth token attempts in same session (`ISEC_ROLE_AUTH_SESSION_ID=phase4-redteam-session2`) | Blocked with exponential backoff and session lock after threshold |
| Production bypass | Set `ISEC_ALLOW_UNLICENSED=1` under `--env production` | Startup blocked by runtime config validator |
| Production logging guard | `--no-log-file` under `--env production` | Startup blocked by runtime config validator |
| Export verification | Tampered ZIP artifacts (`database`, `manifest checksum`, `PDF signature`) | All tamper variants detected and rejected |

## Findings

### Fixed During Assessment

1. `High`: Verification key leakage path in export verifier context.
- Issue: `verify_export.py` could read host-local key material from state/env during verification, breaking independent verification reliability.
- Fix: Added isolated verification environment (`_isolated_verification_env`) in `verify_export.py`.
- Outcome: clean export passes; tampered exports fail deterministically.

2. `High`: IPC trust boundary bypass in renderer fallback.
- Issue: `ui/js/evidence-viewer.js` had a `require('electron')` fallback path that could bypass preload channel allow-list in permissive runtime contexts.
- Fix: Removed direct `ipcRenderer` fallback; renderer now requires preload bridge only.

3. `High`: Production trust-root override via inline env key.
- Issue: `ISEC_LICENSE_PUBLIC_KEY` could override verifier trust root in production.
- Fix:
  - Added `ISEC_LICENSE_PUBLIC_KEY` to production-forbidden env vars in `src/utils/runtime_config.py`.
  - Ignore inline key override in production in `src/utils/license_manager.py`.
  - Strip `ISEC_LICENSE_PUBLIC_KEY` in Electron backend launch env in `ui/main.js`.

4. `Medium`: Offline update manifest accepted without checksum.
- Issue: update workflow accepted packages when `sha256` was missing.
- Fix: `ui/main.js` now enforces checksum presence and validation.

## Residual Risks

1. Local admin compromise remains out of application-only scope.
- A fully compromised host can still disrupt availability, exfiltrate local keys, or tamper with runtime files.

2. Role auth state file uses best-effort file writes without explicit OS file locking.
- UI path serializes backend calls (`pythonQueue`), which reduces practical race exposure in normal operation.
- Cross-process manual abuse is still theoretically possible and should be treated as a hardening backlog item.

3. Self-signed certificate used for local release demonstration.
- Sufficient for signed-build workflow validation.
- Production distribution should use enterprise CA-backed signing cert and timestamping policy.

## Conclusion

Core controls resisted direct bypass attempts in this pass. Critical trust-boundary and verifier isolation issues identified during adversarial review were remediated in the same cycle. Current v1.0 posture is release-capable for controlled environments, with remaining risk primarily in host compromise and operational key custody.
