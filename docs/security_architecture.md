# ISEC Security Architecture

> This document is superseded by `docs/security_architecture_v1.0.md`.

## 1. Cryptographic Architecture Overview

ISEC uses an offline, defense-in-depth cryptographic model with independent controls for licensing, evidence integrity, and report authenticity.

### 1.1 License Verification
- License documents are signed with Ed25519.
- The runtime validates signature authenticity with a public key (`keys/license_public_key.pem` or configured override).
- Constraints are enforced during bootstrap:
  - Time validity (`not_before`, `expires_at`)
  - Optional machine fingerprint binding
  - Optional host/fingerprint allow-lists
- Startup is fail-closed: invalid license blocks operational actions before collector modules load.

### 1.2 Evidence Integrity
- Each evidence record includes:
  - `current_record_hash` (SHA-256 over normalized record linkage payload)
  - `prev_record_hash` (link to prior record for chain continuity)
  - `hmac_signature` (HMAC-SHA256 over record integrity payload)
- HMAC key material is sourced from secured state storage (or explicit environment/key file overrides).
- Full-chain verification validates:
  - Link integrity between records
  - Per-record HMAC authenticity

### 1.3 Report Authenticity
- Reports are signed using RSA private keys (`signing_private_key.pem`) with sidecar signature artifacts (`.sig.json`).
- Signature payload binds:
  - PDF file hash
  - Evidence database hash
  - System fingerprint metadata
  - Timestamp and signature format markers
- Verification checks canonical metadata hash, signature validity, report hash, and evidence DB hash.

## 2. Chain-of-Custody Process

Chain-of-custody is enforced as a deterministic sequence:

1. Evidence ingestion writes encrypted payloads to SQLite with hash-chain linkage.
2. Integrity metadata is generated and stored atomically with the evidence record.
3. Verification routines recompute HMAC and chain links over the full dataset.
4. Exports include machine-readable and human-readable manifests with:
   - file hashes
   - DB hash
   - chain-of-custody verification counts
   - report signature artifacts

Independent verification is supported via `verify_export.py`, enabling third-party integrity validation without requiring UI trust.

## 3. Key Management Policy

### 3.1 Separation of Key Roles
- License keypair (Ed25519): entitlement enforcement
- Evidence keys (Fernet + HMAC key): confidentiality and record integrity
- Report signing keypair (RSA): artifact authenticity

### 3.2 Storage and Access
- Keys are persisted in per-user state directories, not in the evidence database.
- File permissions are restricted where supported (`chmod 600` on private keys).
- Environment-variable key injection is supported for controlled deployments.

### 3.3 Rotation and Operational Guidance
- License public keys are rotated by replacing trusted verifier keys in deployment artifacts.
- HMAC/encryption keys should be backed up securely with access controls and recovery procedures.
- RSA report signing keys should be versioned and rotated on policy schedule or incident trigger.

## 4. Tamper Resistance Design

ISEC enforces fail-closed behavior for integrity failures:
- Hash-chain or HMAC verification failure marks data integrity as compromised.
- Collection/report/export operations are blocked on tampering states.
- Role elevation attempts are audited and rate-limited.
- After 5 failed auth attempts in a session, role changes are lock-blocked until restart.

This model raises attacker cost for silent record alteration, replay, and unauthorized privilege escalation.

## 5. Threat Model Summary

### 5.1 In-Scope Threats
- Local evidence tampering (DB row mutation, chain-link rewriting)
- Unauthorized role escalation
- Forged or modified PDF report artifacts
- License spoofing and unlicensed operation
- Bruteforce token guessing for privileged role changes

### 5.2 Mitigations
- Signature-verified offline licensing
- HMAC + hash-chain integrity with recomputation checks
- Signed report sidecar verification
- Startup license gating before module initialization
- Session throttling + lockout for role auth attempts
- Audit evidence events for privileged auth flows

### 5.3 Residual Risks
- Host compromise with privileged filesystem access can still disrupt runtime availability.
- Key theft from an already-compromised endpoint can weaken authenticity guarantees.
- Operational controls (endpoint hardening, secure backups, and key custody discipline) remain mandatory.

## 6. Verification and Assurance Artifacts

- `verify_export.py`: independent ZIP verification tool.
- `checksum_manifest.json`: canonical export verification metadata.
- `checksum_manifest.txt`: human-readable audit summary.
- `tests/`: automated pytest coverage for license, role auth, HMAC, tamper detection, and PDF signatures.
