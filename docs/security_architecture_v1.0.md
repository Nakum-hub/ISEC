# ISEC Security Architecture v1.0

## Document Metadata

- Version: `1.0.0`
- Status: `Release Candidate`
- Last Updated (UTC): `2026-02-14`
- Scope: Offline evidence collection, integrity protection, role control, export verification

## 1. Cryptographic Architecture Overview

ISEC uses layered cryptographic controls so no single check is trusted in isolation.

### 1.1 License and Entitlement Validation

- License payloads are signed with `Ed25519`.
- Runtime verifies signatures using an offline public key (`ISEC_LICENSE_PUBLIC_KEY[_FILE]` or packaged key).
- Entitlement constraints:
  - expiration and validity window (`not_before`, `expires_at`)
  - optional host and machine fingerprint binding
  - explicit feature flags (`collect`, `view`, `report`, `export`, `all`)
- License verification executes before module initialization.

### 1.2 Evidence Protection and Integrity

- Evidence payloads are encrypted at rest using `Fernet` (AES128-CBC + HMAC under the Fernet construction).
- Each record stores:
  - `prev_record_hash` and `current_record_hash` (`SHA-256`) for chain linkage
  - `hmac_signature` (`HMAC-SHA256`) for record-level authenticity
- Full-chain verification validates both HMAC integrity and parent-child hash linkage.

### 1.3 Report and Export Authenticity

- Forensic reports are signed with RSA (`PKCS#1 v1.5 + SHA-256`) and a JSON sidecar.
- Export package contains:
  - `checksum_manifest.json` with file digests
  - evidence DB hash
  - chain-of-custody verification counters
  - PDF report signature artifacts
- Independent verifier (`verify_export.py`) re-validates all integrity assertions offline.

## 2. Trust Boundary Diagram

```text
+----------------------------- Host OS / Operator -----------------------------+
|                                                                              |
|  +----------------------- ISEC Runtime Process ---------------------------+   |
|  |                                                                       |   |
|  |  [License Verification Boundary]                                      |   |
|  |    main.py -> runtime guardrails -> verify_license()                  |   |
|  |           |                                                           |   |
|  |           v                                                           |   |
|  |  [Authorized Modules Boundary]                                        |   |
|  |    EvidenceCollector / ReportGenerator loaded by feature flags only   |   |
|  |           |                                                           |   |
|  |           v                                                           |   |
|  |  [Evidence Storage Boundary]                                           |   |
|  |    encrypted SQLite + hash chain + HMAC signatures                    |   |
|  |           |                                                           |   |
|  |           v                                                           |   |
|  |  [Export Boundary]                                                     |   |
|  |    ZIP + manifest + signed PDF                                        |   |
|  +-----------------------------------------------------------------------+   |
|                    |                                                       |
|                    v                                                       |
|       External verifier (verify_export.py / client / legal reviewer)       |
|                                                                              |
+------------------------------------------------------------------------------+
```

## 3. Formal Threat Model

| Threat ID | Threat | Attack Path | Impact | Primary Mitigations | Residual Risk |
|---|---|---|---|---|---|
| T-001 | Unlicensed execution | Missing/forged license file | Unauthorized product use | Ed25519 license verification, startup fail-closed | Private key compromise outside ISEC scope |
| T-002 | Role escalation | Token guessing for role change | Privilege abuse | HMAC-safe token compare, exponential backoff, session lock after 5 failures, audit trail | Token theft from compromised endpoint |
| T-003 | Evidence DB tampering | Direct SQLite mutation | Integrity loss | Hash-chain + HMAC verification, export verifier checks | Full host compromise can still destroy availability |
| T-004 | Export manifest tamper | Hash alteration in ZIP | False integrity claims | Manifest checksum re-validation and DB hash checks | None if verifier is trusted and run offline |
| T-005 | PDF report forgery | Signature sidecar alteration | Legal/report authenticity loss | RSA signature verification + report hash + DB hash binding | Signing private key theft |
| T-006 | Insecure production config | Debug mode / bypass flags | Weakened runtime controls | `ISEC_ENV=production` validation and hard startup failure | Misconfiguration before enforcement code executes |

## 4. Chain-of-Custody Process

1. Collectors ingest evidence and store encrypted payloads.
2. Storage layer computes record hash and HMAC signature.
3. Chain verification computes full-link consistency.
4. Reporting signs forensic PDF and binds evidence DB hash.
5. Export packaging writes deterministic checksums and signature artifacts.
6. Independent verification confirms package integrity and authenticity.

## 5. Cryptographic Primitive Justification

- `Ed25519` for license signatures:
  - deterministic, fast verification, short keys/signatures
  - modern default for offline signature validation
- `SHA-256` for record and file hashing:
  - widely standardized and interoperable
  - sufficient collision resistance for current integrity use
- `HMAC-SHA256` for evidence-record authentication:
  - protects against record modification when key is secret
  - simple verification path with low implementation complexity
- `RSA + SHA-256` for PDF signatures:
  - broad ecosystem compatibility for legal/report workflows
  - explicit detached signature sidecar supports offline verification

## 6. Key Management Policy

### 6.1 Key Separation

- License keypair (`Ed25519`) for entitlement.
- Evidence encryption and HMAC keys for local evidence protection.
- Report signing keypair (`RSA`) for output authenticity.

### 6.2 Key Storage

- Private keys remain outside source control and outside exported evidence.
- Runtime key files are stored in local state directories with restrictive permissions.
- Build/release signing credentials are injected via environment variables.

### 6.3 Rotation and Recovery

- Rotate public verifier keys in release artifacts on policy schedule.
- Rotate report signing keys on incident, personnel change, or scheduled intervals.
- Store backup keys in controlled offline custody with documented retrieval procedures.

## 7. Tamper Resistance and Detection

- Evidence writes are immutable by design at logical layer (append-linked records).
- Role authorization failures are auditable and rate-limited.
- Verification tools are externalizable (client-side independent trust path).
- Tamper simulation script (`scripts/simulate_tamper.py`) provides repeatable proof of detection behavior.

## 8. Residual Risks

- Endpoint compromise with filesystem/admin access can exfiltrate keys or destroy data.
- Availability attacks (process kill, storage deletion) are out of cryptographic scope.
- Offline architecture limits centralized revocation and centralized monitoring.
- Operational controls remain required:
  - hardened endpoints
  - restricted admin access
  - secure key custody
  - disciplined release signing workflow

## 9. Version History

| Version | Date (UTC) | Author | Changes |
|---|---|---|---|
| 0.9.0 | 2026-02-13 | ISEC Engineering | Initial architecture draft |
| 1.0.0 | 2026-02-14 | ISEC Engineering | Added formal threat table, trust boundaries, primitive rationale, residual risk, and release governance artifacts |
