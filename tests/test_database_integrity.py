import sqlite3

from src.storage.database import EvidenceDatabase


def test_hmac_verification_failure(tmp_path):
    db_path = tmp_path / "evidence.db"
    db = EvidenceDatabase(str(db_path))
    record_id = db.store_evidence(
        evidence_type="system_logs",
        data={"message": "baseline"},
        actor="tester",
    )

    assert db.verify_integrity(record_id) is True

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE evidence SET hmac_signature = ? WHERE id = ?", ("bad-signature", record_id))
        conn.commit()

    assert db.verify_integrity(record_id) is False


def test_db_tamper_detection_hash_chain(tmp_path):
    db_path = tmp_path / "evidence.db"
    db = EvidenceDatabase(str(db_path))
    first_id = db.store_evidence("system_logs", {"message": "first"}, actor="tester")
    second_id = db.store_evidence("system_logs", {"message": "second"}, actor="tester")
    assert first_id > 0
    assert second_id > 0
    assert db.verify_full_hash_chain(update_results=False) is True

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE evidence SET prev_record_hash = ? WHERE id = ?", ("tampered-prev-hash", second_id))
        conn.commit()

    assert db.verify_full_hash_chain(update_results=False) is False
