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

### License Security
- Licenses are signed with **Ed25519** (asymmetric cryptography)
- Each license is bound to a **machine fingerprint** — non-transferable
- The private signing key is never distributed with the application
- License verification uses only the public key (embedded in the package)

### Application Security
- **Context isolation**: Renderer has no access to Node.js APIs
- **Preload whitelist**: Only 25 explicitly allowed IPC channels are exposed
- **Navigation lockdown**: All external navigation is blocked
- **Permission blocker**: Camera, microphone, geolocation all blocked
- **CSP**: `script-src 'self'` — no inline scripts, no CDN, no eval
- **DevTools disabled** in production builds
- **ASAR encrypted** application bundle

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
