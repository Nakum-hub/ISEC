"""
Tests for the forensic transparency log (src/forensics/transparency_log.py).

These tests use a *real* DigitalSigner keypair (generated into a temporary
keys directory) and a *real* EvidenceDatabase, so the signing and rollback
detection paths are exercised genuinely rather than mocked.
"""
import json

import pytest

from src.forensics.transparency_log import (
    LEDGER_SCHEMA,
    TransparencyLog,
    checkpoint_from_database,
)
from src.utils.digital_signer import DigitalSigner


def _make_signer(tmp_path):
    return DigitalSigner(keys_dir=str(tmp_path / "keys"))


def test_append_read_and_verify_signed(tmp_path):
    signer = _make_signer(tmp_path)
    log = TransparencyLog(str(tmp_path / "ledger.jsonl"), signer=signer)

    r0 = log.append_checkpoint(tip_hash="aaa", record_count=1, db_hash="db0")
    r1 = log.append_checkpoint(tip_hash="bbb", record_count=3, db_hash="db1")

    assert r0["entry"]["seq"] == 0
    assert r1["entry"]["seq"] == 1
    assert r0["entry"]["schema"] == LEDGER_SCHEMA
    # Ledger linkage: each entry references the prior entry hash.
    assert r0["entry"]["prev_entry_hash"] is None
    assert r1["entry"]["prev_entry_hash"] == r0["entry_hash"]
    assert "signature" in r0 and "signature" in r1

    entries = log.read_entries()
    assert len(entries) == 2

    result = log.verify()
    assert result["valid"] is True
    assert result["entries"] == 2
    assert result["issues"] == []


def test_unsigned_ledger_verifies_structurally(tmp_path):
    log = TransparencyLog(str(tmp_path / "ledger.jsonl"))  # no signer
    log.append_checkpoint(tip_hash="aaa", record_count=0)
    log.append_checkpoint(tip_hash="bbb", record_count=2)

    entries = log.read_entries()
    assert all("signature" not in e for e in entries)

    # With no signer the structural checks still pass.
    assert log.verify()["valid"] is True


def test_append_rejects_rollback(tmp_path):
    log = TransparencyLog(str(tmp_path / "ledger.jsonl"))
    log.append_checkpoint(tip_hash="aaa", record_count=5)
    with pytest.raises(ValueError):
        log.append_checkpoint(tip_hash="bbb", record_count=3)


def test_append_rejects_negative_count(tmp_path):
    log = TransparencyLog(str(tmp_path / "ledger.jsonl"))
    with pytest.raises(ValueError):
        log.append_checkpoint(tip_hash="aaa", record_count=-1)


def test_verify_detects_entry_hash_tampering(tmp_path):
    signer = _make_signer(tmp_path)
    ledger_path = tmp_path / "ledger.jsonl"
    log = TransparencyLog(str(ledger_path), signer=signer)
    log.append_checkpoint(tip_hash="aaa", record_count=1)
    log.append_checkpoint(tip_hash="bbb", record_count=2)

    # Tamper with the first entry's tip_hash but leave entry_hash/signature.
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["entry"]["tip_hash"] = "FORGED"
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = log.verify()
    assert result["valid"] is False
    # Both the entry-hash integrity check and the signature check should fail,
    # and the downstream ledger link should break too.
    assert any("entry_hash mismatch" in issue for issue in result["issues"])
    assert any("invalid signature" in issue for issue in result["issues"])


def test_verify_detects_broken_ledger_link(tmp_path):
    signer = _make_signer(tmp_path)
    ledger_path = tmp_path / "ledger.jsonl"
    log = TransparencyLog(str(ledger_path), signer=signer)
    log.append_checkpoint(tip_hash="aaa", record_count=1)
    log.append_checkpoint(tip_hash="bbb", record_count=2)
    log.append_checkpoint(tip_hash="ccc", record_count=3)

    # Delete the middle entry -> the third entry's prev_entry_hash no longer
    # matches the (now) preceding entry.
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = log.verify()
    assert result["valid"] is False
    assert any("broken ledger link" in issue for issue in result["issues"])


def test_verify_detects_rollback_in_existing_ledger(tmp_path):
    # Build a ledger by hand (bypassing append's guard) that contains a
    # record_count rollback, and confirm verify() flags it.
    ledger_path = tmp_path / "ledger.jsonl"
    log = TransparencyLog(str(ledger_path))
    log.append_checkpoint(tip_hash="aaa", record_count=2)
    log.append_checkpoint(tip_hash="bbb", record_count=5)

    entries = log.read_entries()
    # Forge a third entry that rolls back the count, correctly hash-linked so
    # only the rollback check fails.
    from src.forensics.transparency_log import _entry_hash, _canonical

    core = {
        "schema": LEDGER_SCHEMA,
        "seq": 2,
        "timestamp": "2026-01-01T00:00:00Z",
        "tip_hash": "ccc",
        "record_count": 1,
        "db_hash": None,
        "prev_entry_hash": entries[-1]["entry_hash"],
        "extra": {},
    }
    forged = {"entry": core, "entry_hash": _entry_hash(core)}
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(_canonical(forged) + "\n")

    result = log.verify()
    assert result["valid"] is False
    assert any("rollback" in issue for issue in result["issues"])


def test_checkpoint_from_database_end_to_end(tmp_path):
    from src.storage.database import EvidenceDatabase

    signer = _make_signer(tmp_path)
    storage = EvidenceDatabase(str(tmp_path / "evidence.db"))
    storage.store_evidence("system_logs", {"line": "one"}, "actor", "ws-1", "10.0.0.1")
    storage.store_evidence("file_metadata", {"path": "/tmp/x"}, "actor", "ws-1", "10.0.0.1")

    log = TransparencyLog(str(tmp_path / "ledger.jsonl"), signer=signer)
    record = checkpoint_from_database(log, storage, extra={"reason": "unit-test"})

    assert record["entry"]["record_count"] == 2
    assert record["entry"]["tip_hash"] == storage.last_record_hash
    assert record["entry"]["db_hash"]  # database file hash captured
    assert record["entry"]["extra"] == {"reason": "unit-test"}

    assert log.verify()["valid"] is True
