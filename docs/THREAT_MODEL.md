# ISEC Threat Model

This document describes who ISEC defends against, what it guarantees, and where
those guarantees end. It complements `docs/security_architecture.md` (which
describes *how* the system works) by focusing on *adversaries and assurances*.

It is intended for two audiences: security reviewers evaluating ISEC for
acquisition or deployment, and legal/compliance reviewers assessing whether
ISEC-collected evidence is defensible.

## 1. What ISEC is

ISEC is a local, offline digital-evidence collection tool with a tamper-evident
chain of custody. A trained operator collects artifacts on a machine; ISEC
records each item into an encrypted, hash-chained, HMAC-authenticated evidence
store and can export a signed, independently verifiable evidence package.

## 2. Assets to protect

| Asset | Property required |
|---|---|
| Collected evidence records | Integrity, authenticity, confidentiality at rest |
| Chain-of-custody ordering | Integrity (append-only, non-reorderable) |
| Role / authorization state | Authenticity (cannot be forged) |
| License entitlement | Authenticity (cannot be forged or transferred) |
| Exported evidence package | Integrity + independent verifiability |

## 3. Trust boundaries

1. **Operator vs. application** — the operator is trusted to *operate* but not to
   silently rewrite history. Privileged actions require an admin token.
2. **Application vs. local OS user files** — files on disk (role state, evidence DB)
   are treated as untrusted input and are authenticated before use.
3. **Application vs. renderer (Electron)** — the UI renderer is sandboxed with
   context isolation, an IPC allowlist, and a strict CSP.
4. **Vendor vs. customer** — the license signing private key never leaves the
   vendor; only the public verification key ships with the product.

## 4. Adversaries

- **A1 — Local tamperer:** has read/write access to ISEC's data files and wants to
  alter, delete, or reorder evidence after collection.
- **A2 — Privilege escalator:** an unauthorized local user who wants collector or
  exporter capabilities without the admin token.
- **A3 — License pirate:** wants to run a paid tier without a valid license, or to
  copy one license across many machines.
- **A4 — Export forger:** wants to hand a court or client a doctored evidence
  package that still appears valid.
- **A5 — Supply-chain attacker:** wants to compromise ISEC via a malicious or
  vulnerable dependency.

## 5. STRIDE analysis

| Category | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Forge privileged role state (A2) | Role file authenticated with HMAC-SHA256 keyed by admin token; unsigned/wrong-token privileged roles fall back to read-only reviewer and raise an audit event | Admin token compromise grants the attacker the role; protect the token |
| **T**ampering | Alter/reorder evidence (A1) | SHA-256 hash chain + per-record HMAC; chain verified on startup; break locks collection and alerts | Attacker who controls the HMAC key file *and* rewrites the whole chain consistently; mitigated by off-device key custody |
| **R**epudiation | Operator denies an action | Append-only audit events (`role_auth_attempt`, `role_integrity_failure`, etc.) recorded as evidence | Audit store shares the host; high-assurance deployments should ship audit off-device |
| **I**nfo disclosure | Read evidence at rest | Fernet (AES-128-CBC + HMAC) encryption; key in `0600` key file outside the DB | OS-level compromise / memory scraping while unlocked |
| **D**enial of service | Lock out legitimate operator | Brute-force lockout is bounded with backoff; admin token recoverable via token file | Lost admin token + lost evidence key = unrecoverable by design |
| **E**levation | License override / unlicensed run (A3) | Ed25519 license signature + machine-fingerprint binding; production ignores env public-key override | Vendor private-key compromise (out of scope of the client) |

## 6. Chain-of-custody guarantees

ISEC asserts, for any evidence package it exports:

1. **Authenticity** — each record is HMAC-authenticated with an installation key.
2. **Integrity & ordering** — records form a SHA-256 hash chain; any insertion,
   deletion, edit, or reorder breaks verification.
3. **Independent verifiability** — exports are signed (RSA-2048 sidecar) and can be
   verified by a third party without trusting the original host.
4. **Tamper-evidence on import** — the export verifier reports an explicit reason
   on any failure (clean passes, tampered fails).

ISEC does **not** assert that the operator collected the right artifacts, that the
artifacts were not altered *before* collection, or that collection was legal in
the operator's jurisdiction. Those are operational/legal controls (see
`docs/PILOT_AND_LICENSING.md`).

## 7. Out of scope

- Full-disk or kernel-level compromise of the collecting host.
- Coercion of the operator who holds the admin token and evidence key.
- Rewriting the repository's historical git commits (handled operationally).
- Vendor signing-key custody (vendor responsibility, not the shipped client).

## 8. Recommended hardening for high-assurance deployments

- Store the HMAC/evidence key on a removable device or HSM, not the host disk.
- Ship audit events to an append-only off-device sink (WORM bucket / syslog).
- Add RFC 3161 trusted timestamps to the chain head so ordering is anchored to a
  trusted time source, not just local wall-clock.
- Counter-sign the chain head at export with an organization key held off-device.
