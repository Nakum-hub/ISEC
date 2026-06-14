"""Tests for the court-ready report sections (chain of custody + transparency).

These exercise the Phase D additions to :class:`ReportGenerator` against a real
:class:`EvidenceDatabase` (no mocks). The consent and retention managers use
module-global singletons that are not reset by conftest, so we reset them here
to make sure each ReportGenerator binds to this test's own fresh storage.
"""
import os
import sqlite3

import src.utils.consent_manager as consent_module
import src.utils.retention_engine as retention_module
from src.storage.database import EvidenceDatabase
from src.reporting.report_generator import ReportGenerator


def _reset_manager_singletons():
    consent_module.consent_manager_instance = None
    retention_module.retention_engine_instance = None


def _make_generator(tmp_path):
    """Build a ReportGenerator backed by a seeded, hash-chained database."""
    _reset_manager_singletons()
    out_dir = tmp_path / "out"
    os.makedirs(out_dir, exist_ok=True)
    db = EvidenceDatabase(str(out_dir / "evidence.db"))
    db.store_evidence("system_logs", {"message": "alpha"}, actor="tester", workstation_id="WS-1")
    db.store_evidence("network_connections", {"conn": "beta"}, actor="tester", workstation_id="WS-1")
    db.verify_full_hash_chain(update_results=True)
    generator = ReportGenerator(db, str(out_dir))
    return db, generator, out_dir


def test_chain_of_custody_rows_in_insertion_order(tmp_path):
    _db, generator, _out_dir = _make_generator(tmp_path)
    rows = generator._get_chain_of_custody_rows()

    assert len(rows) == 2

    ids = [row[0] for row in rows]
    assert ids == sorted(ids), "chain of custody must be in insertion (id) order"

    # Columns: id, type, timestamp, actor, workstation, ip, record_hash, retention
    first = rows[0]
    assert first[1] == "system_logs"
    assert first[3] == "tester"
    assert first[4] == "WS-1"
    assert first[7] == "active"
    assert first[6], "each record should carry a current_record_hash"


def test_append_chain_of_custody_handles_intact_and_tampered(tmp_path):
    from reportlab.lib.styles import getSampleStyleSheet

    db, generator, _out_dir = _make_generator(tmp_path)
    styles = getSampleStyleSheet()

    intact_story = []
    generator._append_chain_of_custody(intact_story, styles)
    assert len(intact_story) > 0

    # Corrupt one record and ensure the section still renders (FAIL row) safely.
    with sqlite3.connect(str(db.db_path)) as conn:
        conn.execute(
            "UPDATE evidence SET current_record_hash = 'tampered' "
            "WHERE id = (SELECT MIN(id) FROM evidence)"
        )
        conn.commit()

    tampered_story = []
    generator._append_chain_of_custody(tampered_story, styles)
    assert len(tampered_story) > 0


def test_append_chain_of_custody_empty_database(tmp_path):
    from reportlab.lib.styles import getSampleStyleSheet

    _reset_manager_singletons()
    out_dir = tmp_path / "empty"
    os.makedirs(out_dir, exist_ok=True)
    db = EvidenceDatabase(str(out_dir / "evidence.db"))
    generator = ReportGenerator(db, str(out_dir))

    story = []
    generator._append_chain_of_custody(story, getSampleStyleSheet())
    # Heading + "no records" note + spacer, and no exception on an empty DB.
    assert len(story) >= 2


def test_generate_signed_report_creates_pdf(tmp_path):
    _db, generator, out_dir = _make_generator(tmp_path)

    report_path = generator.generate_signed_report()

    assert report_path.endswith(".pdf")
    assert os.path.exists(report_path)
    assert os.path.getsize(report_path) > 0
    assert os.path.dirname(report_path) == str(out_dir)


def test_resolve_logo_path_honors_env_override(tmp_path, monkeypatch):
    """ISEC_REPORT_LOGO takes precedence and is returned when it points at a
    real, non-empty file (deterministic regardless of any bundled asset)."""
    from PIL import Image as PILImage

    _db, generator, out_dir = _make_generator(tmp_path)
    logo_path = out_dir / "logo.png"
    PILImage.new("RGB", (32, 32), (10, 20, 30)).save(str(logo_path))
    monkeypatch.setenv("ISEC_REPORT_LOGO", str(logo_path))

    assert generator._resolve_logo_path() == str(logo_path)


def test_resolve_logo_path_ignores_empty_env_file(tmp_path, monkeypatch):
    """A zero-byte override is rejected by the non-empty guard."""
    _db, generator, out_dir = _make_generator(tmp_path)
    empty_logo = out_dir / "empty.png"
    empty_logo.write_bytes(b"")
    monkeypatch.setenv("ISEC_REPORT_LOGO", str(empty_logo))

    # The empty override must not be selected; the env path is never returned.
    assert generator._resolve_logo_path() != str(empty_logo)


def test_generate_signed_report_with_logo(tmp_path, monkeypatch):
    """End-to-end: a valid logo asset is embedded and a PDF is produced."""
    from PIL import Image as PILImage

    _db, generator, out_dir = _make_generator(tmp_path)
    logo_path = out_dir / "logo.png"
    PILImage.new("RGB", (64, 32), (200, 50, 50)).save(str(logo_path))
    monkeypatch.setenv("ISEC_REPORT_LOGO", str(logo_path))

    report_path = generator.generate_signed_report()

    assert report_path.endswith(".pdf")
    assert os.path.exists(report_path)
    assert os.path.getsize(report_path) > 0
