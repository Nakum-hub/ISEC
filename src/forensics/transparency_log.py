"""
Transparency Log (append-only checkpoint ledger) for ISEC.

The evidence database already maintains an internal blockchain-style hash
chain. That chain detects tampering *within* a given database file, but it
cannot, on its own, detect wholesale rollback or replacement of the database
(for example swapping in an older copy that has fewer records but its own
internally consistent hash chain).

The transparency log closes that gap. It is an append-only ledger, stored
*outside* the evidence database, that records signed checkpoints of the
evidence chain over time. Each checkpoint captures:

  * a monotonically increasing sequence number,
  * the evidence chain tip hash and record count at checkpoint time,
  * an optional hash of the evidence database file,
  * the hash of the previous ledger entry (linking the ledger itself), and
  * an optional digital signature over the entry.

Because record counts must never decrease, the ledger is hash-linked, and
entries are signed, an analyst can detect rollback, truncation, or
substitution of the evidence database by replaying and verifying the ledger.

This module is dependency-free (standard library plus the existing
DigitalSigner) and is intended to be feature-flagged off by default at the
orchestrator level; constructing or using a TransparencyLog on its own has no
effect on evidence collection.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


LEDGER_SCHEMA = "ISEC_TRANSPARENCY_LOG_v1"


def _canonical(obj: Any) -> str:
    """Deterministic JSON encoding used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _entry_hash(entry_core: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry_core).encode("utf-8")).hexdigest()


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class TransparencyLog:
    """Append-only, hash-linked, optionally-signed checkpoint ledger.

    The ledger is stored as newline-delimited JSON (one record per line) so it
    is append-friendly and human-inspectable. Each record has the shape::

        {"entry": {<signed core fields>}, "entry_hash": "...",
         "signature": "..."}

    ``signature`` is present only when a signer was supplied.
    """

    def __init__(self, ledger_path: str, signer: Any = None):
        self.ledger_path = ledger_path
        self.signer = signer
        parent = os.path.dirname(self.ledger_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    # -- reading ---------------------------------------------------------
    def read_entries(self) -> List[Dict[str, Any]]:
        """Return all ledger records in append order."""
        entries: List[Dict[str, Any]] = []
        if not os.path.exists(self.ledger_path):
            return entries
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entries.append(json.loads(line))
        return entries

    def latest_entry(self) -> Optional[Dict[str, Any]]:
        entries = self.read_entries()
        return entries[-1] if entries else None

    # -- writing ---------------------------------------------------------
    def append_checkpoint(
        self,
        tip_hash: Optional[str],
        record_count: int,
        db_hash: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a new checkpoint to the ledger and return the written record.

        Raises ``ValueError`` if ``record_count`` is negative or if it is lower
        than the previous checkpoint's count (a rollback the ledger refuses to
        record, since checkpoints must be monotonically non-decreasing).
        """
        if record_count is None or int(record_count) < 0:
            raise ValueError("record_count must be a non-negative integer")
        record_count = int(record_count)

        entries = self.read_entries()
        prev = entries[-1] if entries else None
        prev_seq = prev["entry"]["seq"] if prev else -1
        prev_entry_hash = prev["entry_hash"] if prev else None
        if prev is not None:
            prev_count = prev["entry"].get("record_count", 0)
            if record_count < prev_count:
                raise ValueError(
                    f"record_count {record_count} is less than previous "
                    f"checkpoint count {prev_count}; refusing to append a "
                    f"rollback to the transparency log"
                )

        entry_core = {
            "schema": LEDGER_SCHEMA,
            "seq": prev_seq + 1,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tip_hash": tip_hash,
            "record_count": record_count,
            "db_hash": db_hash,
            "prev_entry_hash": prev_entry_hash,
            "extra": extra or {},
        }
        entry_hash = _entry_hash(entry_core)

        record: Dict[str, Any] = {"entry": entry_core, "entry_hash": entry_hash}
        if self.signer is not None:
            signed = self.signer.sign_payload(entry_core)
            record["signature"] = signed["signature"]

        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(_canonical(record) + "\n")

        return record

    # -- verification ----------------------------------------------------
    def verify(self, signer: Any = None) -> Dict[str, Any]:
        """Replay and verify the ledger.

        Checks, for every entry: entry-hash integrity, ledger linkage
        (``prev_entry_hash`` chaining), sequential ``seq`` numbering,
        monotonic non-decreasing ``record_count`` (rollback detection), and --
        when a signer is available -- the digital signature.

        Returns a summary dict ``{schema, valid, entries, issues}`` where
        ``issues`` is a list of human-readable problem descriptions.
        """
        signer = signer or self.signer
        entries = self.read_entries()
        issues: List[str] = []

        prev_hash: Optional[str] = None
        prev_seq = -1
        prev_count = 0
        for idx, record in enumerate(entries):
            core = record.get("entry")
            if not isinstance(core, dict):
                issues.append(f"entry {idx}: missing entry body")
                continue

            seq = core.get("seq")

            expected_hash = _entry_hash(core)
            if record.get("entry_hash") != expected_hash:
                issues.append(f"entry {idx} (seq {seq}): entry_hash mismatch")

            if core.get("prev_entry_hash") != prev_hash:
                issues.append(f"entry {idx} (seq {seq}): broken ledger link")

            if seq != prev_seq + 1:
                issues.append(f"entry {idx} (seq {seq}): non-sequential seq")

            count = core.get("record_count", 0)
            if count < prev_count:
                issues.append(
                    f"entry {idx} (seq {seq}): record_count {count} dropped "
                    f"below {prev_count} (possible rollback)"
                )

            if signer is not None:
                signature = record.get("signature")
                if not signature:
                    issues.append(f"entry {idx} (seq {seq}): missing signature")
                elif not signer.verify_payload(core, signature):
                    issues.append(f"entry {idx} (seq {seq}): invalid signature")

            prev_hash = record.get("entry_hash")
            prev_seq = seq if isinstance(seq, int) else prev_seq + 1
            prev_count = max(prev_count, count)

        return {
            "schema": LEDGER_SCHEMA,
            "valid": not issues,
            "entries": len(entries),
            "issues": issues,
        }


def checkpoint_from_database(
    transparency_log: TransparencyLog,
    storage: Any,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append a checkpoint derived from an EvidenceDatabase-like ``storage``.

    Reads the current chain tip hash and total record count from ``storage``
    and appends a signed checkpoint, including a hash of the database file when
    available. Returns the appended ledger record.
    """
    # Refresh the cached chain tip without rewriting verification results.
    try:
        storage.verify_full_hash_chain(update_results=False)
    except TypeError:
        storage.verify_full_hash_chain()
    tip_hash = getattr(storage, "last_record_hash", None)

    try:
        record_count = len(
            storage.get_all_evidence(include_expired=True, include_deleted=True)
        )
    except TypeError:
        record_count = len(storage.get_all_evidence())

    db_hash = None
    db_path = getattr(storage, "db_path", None)
    if db_path and os.path.exists(db_path):
        db_hash = _file_sha256(db_path)

    return transparency_log.append_checkpoint(
        tip_hash=tip_hash,
        record_count=record_count,
        db_hash=db_hash,
        extra=extra,
    )
