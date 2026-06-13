# ISEC Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.0.x (current) | ✅ Security patches |
| 1.0.x | ❌ End of life |

## Security Architecture

### Cryptographic Chain of Custody
- Every evidence record is signed with **HMAC-SHA256**
- Records are linked in a **SHA-256 hash chain** — any modification breaks the chain
- The hash chain is verified on every application startup
- Tampering immediately locks evidence collection and raises an alert
- The HMAC master key is a random 32-byte secret (`secrets.token_bytes`) stored in an OS-protected key file outside the database, **not** in the database itself

### Role-Based Access Control (RBAC)
- Three roles: **collector**, **reviewer**, **exporter**; reviewer (read-only) is the safe default
- Privileged role changes require an **admin token** (env `ISEC_ROLE_ADMIN_TOKEN` or a `0600` token file), with brute-force lockout and exponential backoff
- The persisted role file is **authenticated with HMAC-SHA256** keyed by the admin token. The at-rest encryption key is derived from public system info and provides confidentiality only — it is **not** trusted for authenticity
- Any privileged role that is unsigned, tampered, or signed with the wrong token is **rejected** and the user falls back to reviewer. Rejections are recorded as `role_integrity_failure` audit events

### License Security
- Licenses are signed with **Ed25519** (asymmetric cryptography)
- Each license is bound to a **machine fingerprint** — non-transferable
- The private signing key is never distributed with the application
- License verification uses only the public key, which is **embedded in the application** as the trusted anchor (and is also shipped as `keys/license_public_key.pem`). In production (`ISEC_ENV=production`) environment overrides of the public key are ignored

### Application Security
- **Context isolation**: Renderer has no access to Node.js APIs
- **Preload whitelist**: Only explicitly allowed IPC channels are exposed
- **Navigation lockdown**: All external navigation is blocked
- **Permission blocker**: Camera, microphone, geolocation all blocked
- **CSP**: `script-src 'self'` — no inline scripts, no CDN, no eval
- **DevTools disabled** in production builds

### Data Security
- Evidence database is stored in the user's OS-protected app data directory
- HMAC signing key is generated per-installation and never leaves the machine
- Admin token is stored with `0600` permissions (owner-read only)
- No telemetry, no analytics, no external network calls

## Reporting a Vulnerability

If you discover a security vulnerability in ISEC:

1. **Do not** open a public GitHub issue
2. Email: `security@[your-domain]` with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Your suggested fix (optional)
3. You will receive a response within **48 hours**
4. Security patches are released within **7 days** of confirmation

We follow responsible disclosure — we will credit researchers in the release notes.

## Known Limitations

- ISEC requires Python to be installed (or use the packaged installer which bundles it)
- Browser history collection requires explicit user consent
- Collection of employee data without written consent may be illegal in your jurisdiction
- Old commits in this repository's git history may still contain previously committed runtime/evidence sample files; clone-based forensic copies should treat history as out of scope or rewrite it before distribution
