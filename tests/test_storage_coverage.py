import os
import sqlite3

import pytest
from cryptography.fernet import Fernet

import src.storage.database as db_module
from src.storage.database import EvidenceDatabase


def test_storage_key_material_normalization_and_decoding(tmp_path, monkeypatch):
    db_path = tmp_path / "norm.db"
    db = EvidenceDatabase(str(db_path))

    valid_key = Fernet.generate_key()
    assert db._normalize_fernet_key(valid_key) == valid_key
    assert db._normalize_fernet_key(valid_key.decode("utf-8")) == valid_key

    decoded_hex = db._decode_key_material("41424344")
    assert decoded_hex == b"ABCD"

    decoded_b64 = db._decode_key_material("QUJDRA==")
    assert decoded_b64 == b"ABCD"

    decoded_plain = db._decode_key_material("not-base64??")
    assert isinstance(decoded_plain, bytes)

    normalized_from_hex = db._normalize_fernet_key("00" * 32)
    assert normalized_from_hex is not None

    assert db._normalize_fernet_key("") is None
    assert db._normalize_fernet_key(None) is None


def test_storage_invalid_env_key_raises(tmp_path, monkeypatch):
    db_path = tmp_path / "invalid_env_key.db"
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", " ")
    with pytest.raises(ValueError):
        EvidenceDatabase(str(db_path))


def test_storage_existing_db_with_invalid_key_file_raises(tmp_path, monkeypatch):
    db_path = tmp_path / "existing.db"
    key_file = tmp_path / "evidence.key"
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY_FILE", str(key_file))

    db = EvidenceDatabase(str(db_path))
    db.store_evidence("system_logs", {"message": "seed"}, actor="tester")
    assert key_file.exists()

    key_file.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        EvidenceDatabase(str(db_path))


def test_storage_master_salt_from_env_and_file(tmp_path, monkeypatch):
    db_path = tmp_path / "salt.db"
    hmac_key_file = tmp_path / "hmac.key"
    monkeypatch.setenv("ISEC_HMAC_KEY_FILE", str(hmac_key_file))
    monkeypatch.setenv("ISEC_HMAC_KEY", "41424344")

    db = EvidenceDatabase(str(db_path))
    assert db.master_salt == b"ABCD"
    assert hmac_key_file.exists()

    monkeypatch.delenv("ISEC_HMAC_KEY", raising=False)
    db2 = EvidenceDatabase(str(db_path))
    assert isinstance(db2.master_salt, bytes)
    assert len(db2.master_salt) > 0


def test_storage_evidence_filters_and_detail_paths(tmp_path):
    db_path = tmp_path / "filters.db"
    db = EvidenceDatabase(str(db_path))
    id_a = db.store_evidence("system_logs", {"a": 1}, actor="tester")
    id_b = db.store_evidence("network_connections", {"b": 2}, actor="tester")
    id_c = db.store_evidence("file_metadata", {"c": 3}, actor="tester")

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE evidence SET retention_status='expired' WHERE id=?", (id_b,))
        conn.execute("UPDATE evidence SET retention_status='deleted' WHERE id=?", (id_c,))
        conn.commit()

    active_rows = db.get_all_evidence()
    active_ids = {row[0] for row in active_rows}
    assert id_a in active_ids
    assert id_b not in active_ids
    assert id_c not in active_ids

    include_expired = db.get_all_evidence(include_expired=True)
    include_expired_ids = {row[0] for row in include_expired}
    assert id_b in include_expired_ids
    assert id_c not in include_expired_ids

    include_all = db.get_all_evidence(include_expired=True, include_deleted=True)
    include_all_ids = {row[0] for row in include_all}
    assert {id_a, id_b, id_c}.issubset(include_all_ids)

    detail = db.get_evidence_detail(id_a)
    assert detail is not None
    assert detail["id"] == id_a
    assert detail["integrityOk"] is True

    assert db.get_evidence_detail(999999) is None
    assert db.decrypt_evidence_data(999999) is None


def test_storage_decrypt_failure_and_hash_chain_result(tmp_path):
    db_path = tmp_path / "decrypt_fail.db"
    db = EvidenceDatabase(str(db_path))
    rec_id = db.store_evidence("system_logs", {"hello": "world"}, actor="tester")

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE evidence SET data='corrupted-ciphertext' WHERE id=?", (rec_id,))
        conn.execute("UPDATE evidence SET chain_verification_result='pending' WHERE id=?", (rec_id,))
        conn.commit()

    assert db.decrypt_evidence_data(rec_id) is None
    assert db.get_hash_chain_verification_result() is False


def test_storage_database_presence_checks(tmp_path):
    missing_path = tmp_path / "missing.db"
    db = EvidenceDatabase(str(tmp_path / "present.db"))
    assert db._database_has_existing_evidence() is False
    db.store_evidence("system_logs", {"x": 1}, actor="tester")
    assert db._database_has_existing_evidence() is True

    # Touch an empty file and ensure empty-size guard path returns False.
    missing_path.write_bytes(b"")
    db_empty = EvidenceDatabase(str(tmp_path / "empty_guard.db"))
    db_empty.db_path = str(missing_path)
    assert db_empty._database_has_existing_evidence() is False


def test_storage_internal_helpers_and_legacy_key_paths(tmp_path, monkeypatch):
    db_path = tmp_path / "helpers.db"
    db = EvidenceDatabase(str(db_path))

    key_file = tmp_path / "keys" / "sample.key"
    db._write_key_file(str(key_file), b"abc123")
    assert key_file.exists()
    assert db._read_key_file(str(key_file)) == b"abc123"

    # Exercise _get_key_file_path exception branch.
    monkeypatch.setattr(db_module, "get_state_file", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    assert db._get_key_file_path("x.key") is None

    # Exercise _legacy_derived_key both platform branches.
    monkeypatch.setattr(db_module.os, "name", "nt", raising=False)
    nt_key = db._legacy_derived_key()
    assert isinstance(nt_key, bytes)
    monkeypatch.setattr(db_module.os, "name", "posix", raising=False)
    posix_key = db._legacy_derived_key()
    assert isinstance(posix_key, bytes)


def test_storage_master_salt_metadata_paths(tmp_path, monkeypatch):
    db_path = tmp_path / "salt_metadata.db"
    hmac_file = tmp_path / "hmac_runtime.key"
    monkeypatch.setenv("ISEC_HMAC_KEY_FILE", str(hmac_file))
    monkeypatch.delenv("ISEC_HMAC_KEY", raising=False)

    db = EvidenceDatabase(str(db_path))

    # Force metadata row with NULL value branch.
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE metadata SET value = NULL WHERE key='master_salt'")
        conn.commit()
    if hmac_file.exists():
        hmac_file.unlink()
    salt_null = db._get_or_create_master_salt()
    assert isinstance(salt_null, bytes)
    assert len(salt_null) == 32

    # Force metadata row with plain-text value decode fallback branch.
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE metadata SET value = ? WHERE key='master_salt'", ("plain-value",))
        conn.commit()
    if hmac_file.exists():
        hmac_file.unlink()
    salt_plain = db._get_or_create_master_salt()
    assert isinstance(salt_plain, bytes)

    # Force OperationalError branch by dropping metadata table.
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("DROP TABLE metadata")
        conn.commit()
    if hmac_file.exists():
        hmac_file.unlink()
    salt_recreated = db._get_or_create_master_salt()
    assert isinstance(salt_recreated, bytes)


def test_storage_get_hash_chain_valid_status_short_path(tmp_path):
    db_path = tmp_path / "status_short_path.db"
    db = EvidenceDatabase(str(db_path))
    rec_id = db.store_evidence("system_logs", {"ok": True}, actor="tester")
    assert rec_id > 0
    db.verify_full_hash_chain(update_results=True)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE evidence SET chain_verification_result='valid' WHERE id=?", (rec_id,))
        conn.commit()
    assert db.get_hash_chain_verification_result() is True
