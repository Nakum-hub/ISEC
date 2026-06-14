# Forensic Transparency Log

The transparency log is an **append-only, hash-linked, optionally-signed**
ledger of evidence-chain checkpoints, stored **outside** the evidence database
(default: `<output-dir>/transparency_log.jsonl`).

## Why it exists

ISEC already protects every evidence record with an internal, blockchain-style
HMAC hash chain. That chain detects edits, insertions, or deletions *within* a
given database file. It **cannot**, on its own, detect an attacker who:

- rolls the entire database back to an earlier state, or
- substitutes a completely different (but internally-consistent) database.

In both cases the internal chain still validates, because the attacker replaced
the chain too.

The transparency log closes that gap. After each collection or export, ISEC
appends a checkpoint capturing:

- `tip_hash` — the current head of the evidence hash chain,
- `record_count` — the number of evidence rows,
- `db_hash` — a SHA-256 of the evidence database file,
- `seq` + `prev_entry_hash` — append-only linkage to the previous checkpoint,
- `timestamp`, optional `extra` context, and an RSA signature (when keys exist).

Because the ledger is append-only and each entry is chained to the previous
one, **a record count that goes backwards, a broken link, or a missing entry**
is detectable later — revealing rollback, truncation, or substitution.

## Enabling it

The feature is **off by default** and changes nothing about how evidence is
collected. Enable it in either of two ways:

- Environment variable: `ISEC_TRANSPARENCY_LOG=1`
- Programmatically: `EvidenceCollector(output_dir, transparency_log_enabled=True)`

When enabled, a signed checkpoint is appended after each `collect_all_evidence`,
`collect_selected_evidence`, and successful `export_to_zip`. Checkpoint
recording is best-effort: a failure to write a checkpoint is logged and never
aborts or corrupts evidence collection.

## Verifying it

Use the bundled CLI. It replays the ledger and checks entry-hash integrity,
linkage, sequential numbering, monotonic record counts (rollback detection),
and digital signatures (when keys are available):

```bash
# Human-readable
python scripts/verify_transparency_log.py --ledger evidence_output/transparency_log.jsonl

# Machine-readable JSON (for pipelines / audit tooling)
python scripts/verify_transparency_log.py --ledger evidence_output/transparency_log.jsonl --json

# Structural checks only (skip signature verification)
python scripts/verify_transparency_log.py --ledger evidence_output/transparency_log.jsonl --no-verify-signatures
```

Exit codes: `0` valid, `1` present-but-invalid (tampering/inconsistency), `2`
ledger not found.

## Scope and limitations

- The signing key is the same RSA key used for report/PDF signing. To make the
  log defensible against an attacker who also controls the host, store the
  signing key off-device (e.g. an HSM or a separate signing service) and/or
  ship checkpoints to an append-only external store. This is a planned
  hardening step.
- The log proves the *order and monotonicity* of observed states; it does not
  by itself provide trusted wall-clock time. RFC 3161 trusted timestamping of
  each checkpoint is a planned enhancement (it requires a network timestamp
  authority and is intentionally not stubbed).
