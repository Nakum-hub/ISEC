# Interoperability: CASE/UCO Evidence Export

ISEC can export collected evidence as a **CASE/UCO JSON-LD bundle** so that
other forensic and investigation tools can ingest it. CASE
(Cyber-investigation Analysis Standard Expression) is built on UCO (Unified
Cyber Ontology) and is the open interchange format used across the digital
forensics community.

The exporter is pure Python (standard library only), runs fully offline, and
adds no new dependency. It is **free** and requires no certificate or paid
service. If ISEC is later hosted or sold, the same export can be validated
against the official CASE shapes/ontology with no code change.

## Quick start

```bash
# Metadata + chain-of-custody only (recommended, privacy-safe default)
python scripts/export_case.py \
  --db output/evidence.db \
  --output export/evidence.case.json

# Include decrypted payloads and every record (expired + deleted)
python scripts/export_case.py \
  --db output/evidence.db \
  --output export/full.case.json \
  --include-payload --include-expired --include-deleted
```

Exit codes: `0` success, `1` export error, `2` could not open the database.

Programmatic use:

```python
from src.storage.database import EvidenceDatabase
from src.forensics.case_export import build_case_bundle, export_case_bundle

storage = EvidenceDatabase("output/evidence.db")
bundle = build_case_bundle(storage)              # dict (JSON-LD)
export_case_bundle(storage, "export/evidence.case.json")
```

## What the bundle contains

The top level is a `uco-core:Bundle` whose `uco-core:object` array holds:

| Node | Type | Purpose |
| --- | --- | --- |
| Tool | `uco-tool:Tool` | Identifies ISEC and its version. |
| Identity | `uco-identity:Identity` | One per distinct collecting actor. |
| Evidence | `uco-observable:ObservableObject` | One per record, with a `ContentDataFacet` (SHA-256 record hash + size). |
| Collection | `uco-action:Action` | The act of collecting the evidence (performer, instrument, time, workstation, IP). |
| Provenance | `case-investigation:ProvenanceRecord` | Chain-of-custody record linking to the evidence and carrying integrity metadata. |

Object `@id` values are derived from the record id (for example
`kb:evidence-3`, `kb:action-collect-3`, `kb:provenance-3`), so re-exporting the
same database produces a stable, diff-friendly document.

## Chain of custody travels with the export

Each `ProvenanceRecord` includes ISEC extension fields (namespaced under
`isec:` so they never collide with standard CASE/UCO terms):

- `isec:integrityVerified` — result of the live HMAC integrity check at export time.
- `isec:recordHash` — the record's SHA-256 hash (`uco-types:Hash`).
- `isec:previousRecordHash` — the linked previous record hash, preserving the
  hash-chain ordering.
- `isec:hmacSignature` — the HMAC-SHA256 signature over the record.
- `isec:retentionStatus` — active / expired / deleted.

A receiving party can therefore re-verify the chain links and per-record
integrity directly from the exported bundle.

## Privacy posture

- **Payloads are excluded by default.** Only metadata, hashes, and
  chain-of-custody integrity are exported unless `--include-payload` is given.
- Expired and deleted records are excluded unless explicitly requested.
- Because the default export never contains decrypted evidence, it is safe to
  share for verification or intake without disclosing case content.

## Validating against the official ontology (optional, free)

For a deeper conformance check you can validate the output with the open-source
CASE tooling (no license required), e.g. `case_validate` from the
`case-utils` project. This is optional; the bundle is valid JSON-LD on its own.
