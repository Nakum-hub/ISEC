"""Tests for the CASE/UCO JSON-LD evidence exporter (Phase F).

All tests run fully offline against a real :class:`EvidenceDatabase`.
"""
import json

from src.storage.database import EvidenceDatabase
from src.forensics.case_export import (
    build_case_bundle,
    export_case_bundle,
    CASE_CONTEXT,
    BUNDLE_ID,
    TOOL_ID,
)


def _seed_db(tmp_path):
    db = EvidenceDatabase(str(tmp_path / "evidence.db"))
    db.store_evidence(
        "system_logs", {"message": "alpha"}, actor="alice",
        workstation_id="WS-1", ip_address="10.0.0.1",
    )
    db.store_evidence(
        "network_connections", {"conn": "beta"}, actor="bob",
        workstation_id="WS-2",
    )
    db.verify_full_hash_chain(update_results=True)
    return db


def test_build_case_bundle_structure(tmp_path):
    db = _seed_db(tmp_path)
    bundle = build_case_bundle(db)

    assert bundle["@type"] == "uco-core:Bundle"
    assert bundle["@id"] == BUNDLE_ID
    assert bundle["@context"] == CASE_CONTEXT

    objects = bundle["uco-core:object"]
    types = [obj["@type"] for obj in objects]

    assert "uco-tool:Tool" in types
    assert types.count("uco-observable:ObservableObject") == 2
    assert types.count("uco-action:Action") == 2
    assert types.count("case-investigation:ProvenanceRecord") == 2
    # alice and bob -> two distinct identity nodes
    assert types.count("uco-identity:Identity") == 2


def test_provenance_carries_chain_of_custody_integrity(tmp_path):
    db = _seed_db(tmp_path)
    bundle = build_case_bundle(db)

    provenance = [
        obj for obj in bundle["uco-core:object"]
        if obj["@type"] == "case-investigation:ProvenanceRecord"
    ]
    assert len(provenance) == 2

    for record in provenance:
        assert record["isec:integrityVerified"]["@value"] == "true"
        assert record["isec:recordHash"]["@type"] == "uco-types:Hash"
        assert record["isec:hmacSignature"]["uco-types:hashMethod"]["@value"] == "HMAC-SHA256"

    exhibits = [rec["case-investigation:exhibitNumber"] for rec in provenance]
    assert exhibits == sorted(exhibits, key=int)


def test_payload_excluded_by_default_and_included_on_request(tmp_path):
    db = _seed_db(tmp_path)

    default_text = json.dumps(build_case_bundle(db))
    assert "alpha" not in default_text, "decrypted payload must not leak by default"

    payload_text = json.dumps(build_case_bundle(db, include_payload=True))
    assert "alpha" in payload_text


def test_export_writes_valid_jsonld(tmp_path):
    db = _seed_db(tmp_path)
    out_path = tmp_path / "export" / "evidence.case.json"

    written = export_case_bundle(db, str(out_path))
    assert written == str(out_path)
    assert out_path.exists()

    loaded = json.loads(out_path.read_text(encoding="utf-8"))
    assert loaded["@type"] == "uco-core:Bundle"
    assert any(obj["@id"] == TOOL_ID for obj in loaded["uco-core:object"])


def test_export_is_deterministic_for_fixed_creation_time(tmp_path):
    db = _seed_db(tmp_path)
    first = build_case_bundle(db, created_time="2026-01-01T00:00:00Z")
    second = build_case_bundle(db, created_time="2026-01-01T00:00:00Z")
    assert json.dumps(first) == json.dumps(second)


def test_empty_database_exports_tool_only(tmp_path):
    db = EvidenceDatabase(str(tmp_path / "empty.db"))
    bundle = build_case_bundle(db)
    objects = bundle["uco-core:object"]
    assert len(objects) == 1
    assert objects[0]["@type"] == "uco-tool:Tool"
