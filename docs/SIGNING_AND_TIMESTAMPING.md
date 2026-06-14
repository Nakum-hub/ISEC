# Signing & Trusted Timestamping (All-Free Strategy)

ISEC produces forensic evidence, so the value of the tool depends on a third
party being able to independently verify **what** was collected, **that** it
was not altered, and **when** it existed. None of that requires paid
certificates today. This document lists the free, reputable options ISEC uses
or supports, how to turn them on, and how an independent reviewer verifies
them.

> Upgrade path: every mechanism here can later be swapped for a premium
> Time-Stamp Authority or a paid code-signing certificate **without any code
> change** -- you only change a URL or a CI secret. Start free; upgrade only
> if/when you host or sell.

---

## 1. Trusted timestamping (RFC 3161) -- free public TSAs

The transparency log (`src/forensics/transparency_log.py`) records signed,
hash-linked checkpoints of the evidence chain. Those checkpoints carry a local
timestamp. An **RFC 3161 token** from an independent Time-Stamp Authority
(TSA) upgrades that to trusted, third-party proof of *when* a checkpoint
existed -- which is exactly what defeats backdating / rollback arguments.

**This service is free.** Reputable public TSAs require no account:

| TSA | URL |
| --- | --- |
| DigiCert (default) | `http://timestamp.digicert.com` |
| Sectigo | `http://timestamp.sectigo.com` |
| freeTSA.org | `https://freetsa.org/tsr` |

### How it works in ISEC

- `src/forensics/rfc3161.py` builds a standard DER `TimeStampReq` over
  `sha256(chain_tip_hash)` and POSTs it to the TSA.
- The TSA's reply (a signed `TimeStampResp` token) is stored **base64, opaque**
  inside the checkpoint entry, so the trusted timestamp is itself protected by
  the entry hash and signature.
- It is **optional, off by default, and offline-safe**: if the TSA is
  unreachable the checkpoint is still written, just without a token. Nothing
  in collection ever fails because of timestamping.

### Enabling it

Timestamping activates only when the transparency log is on **and** a TSA URL
is configured:

```bash
# Enable the transparency log + trusted timestamping (any RFC 3161 TSA URL)
export ISEC_TRANSPARENCY_LOG=1
export ISEC_TSA_URL="http://timestamp.digicert.com"
```

or programmatically:

```python
from src.core.collector import EvidenceCollector

collector = EvidenceCollector(
    output_dir,
    transparency_log_enabled=True,
    timestamp_authority_url="http://timestamp.digicert.com",
)
```

### Verifying a stored token (free, no extra dependency)

The stored token is a standard RFC 3161 `TimeStampResp`. Any reviewer can
verify it with OpenSSL (already present on Linux/macOS and available free on
Windows):

```bash
# 1. Decode the base64 "timestamp_token" field from the ledger entry
python -c "import base64,sys;open('token.tsr','wb').write(base64.b64decode(sys.argv[1]))" <BASE64_TOKEN>

# 2. Reconstruct the timestamped imprint (sha256 of the entry's tip_hash text)
printf '%s' "<TIP_HASH>" | openssl dgst -sha256 -binary > imprint.bin

# 3. Inspect the trusted time and TSA
openssl ts -reply -in token.tsr -text

# 4. (Optional) Cryptographically verify against the TSA chain
openssl ts -verify -digest "$(printf '%s' '<TIP_HASH>' | openssl dgst -sha256 -hex | awk '{print $2}')" \
    -in token.tsr -CAfile <tsa-ca-bundle.pem>
```

---

## 2. Release / binary signing -- free options

When you publish a build (e.g. the Electron app or a Python wheel), users need
to know the artifact genuinely came from this project. Free, trusted options:

### a) Sigstore / cosign (recommended, free, keyless)

[Sigstore](https://www.sigstore.dev/) lets you sign release artifacts with no
long-lived key and no cost. Signatures are recorded in the public **Rekor**
transparency log -- a natural fit for a forensic tool. In GitHub Actions:

```yaml
# (delivered as a CI template; move into .github/workflows/ to enable)
- uses: sigstore/cosign-installer@v3
- run: cosign sign-blob --yes dist/ISEC-Setup.exe > ISEC-Setup.exe.sig
```

Users verify with `cosign verify-blob`. Cost: **$0** for public repos.

### b) GPG / minisign detached signatures (free)

Publish a detached `.asc` (GPG) or `.minisig` (minisign) alongside each
release and publish the public key in the repo. Both tools are free and
offline.

### c) SignPath Foundation -- free OSS Windows code signing

Windows SmartScreen trusts Authenticode-signed binaries. A normal OV/EV
certificate costs money, but the
[SignPath Foundation](https://signpath.org/) provides **free code-signing
certificates to qualifying open-source projects**. This is the recommended
free route to a trusted Windows installer.

### d) Self-signed (development only)

Fine for local/dev builds and documented as such; not trusted by end-user
machines, so not used for public releases.

---

## 3. What stays paid (and is deliberately deferred)

| Capability | Free now | Paid later (only if hosting/selling) |
| --- | --- | --- |
| RFC 3161 timestamping | Public TSAs (DigiCert/Sectigo/freeTSA) | Dedicated/qualified EU TSA |
| Release signing | Sigstore / GPG / minisign | n/a (Sigstore is sufficient) |
| Windows code signing | SignPath Foundation (OSS) | OV/EV Authenticode cert (~$200-400/yr) |
| macOS notarization | not required for source distribution | Apple Developer Program ($99/yr) |

Nothing in the codebase hard-codes a paid provider. Upgrading is a
configuration change (a different `ISEC_TSA_URL`, a CI secret, or a signing
certificate), never a rewrite.

---

## 4. Summary

- **Timestamping is already wired and free** -- enable with
  `ISEC_TRANSPARENCY_LOG=1` + `ISEC_TSA_URL=...`.
- **Release signing is free** via Sigstore/cosign or GPG/minisign.
- **Trusted Windows signing is free** for OSS via SignPath Foundation.
- **Paid certificates are optional** and only worth buying if you later host
  or sell -- with zero code changes required to adopt them.
