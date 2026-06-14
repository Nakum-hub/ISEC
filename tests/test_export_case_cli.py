"""CLI smoke tests for scripts/export_case.py (Phase F).

The script is a standalone entry point (not an importable package), so it is
loaded from its file path via importlib and its ``main(argv)`` is invoked
directly. All tests run fully offline against a real ``EvidenceDatabase``.
"""
import importlib.util
import json
import os

from src.storage.database import EvidenceDatabase
from src.forensics.case_export import TOOL_ID


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT_PATH = os.path.join(_REPO_ROOT, "scripts", "export_case.py")


def _load_cli():
    """Load scripts/export_case.py as a module under a private name."""
    spec = importlib.util.spec_from_file_location("isec_export_case_cli", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_cli_exports_bundle_payload_excluded_by_default(tmp_path):
    _seed_db(tmp_path)
    cli = _load_cli()
    out_path = tmp_path / "export" / "evidence.case.json"

    rc = cli.main(["--db", str(tmp_path / "evidence.db"), "--output", str(out_path)])

    assert rc == 0
    assert out_path.exists()
    loaded = json.loads(out_path.read_text(encoding="utf-8"))
    assert loaded["@type"] == "uco-core:Bundle"
    assert any(obj["@id"] == TOOL_ID for obj in loaded["uco-core:object"])
    # Decrypted payload must not leak unless explicitly requested.
    assert "alpha" not in out_path.read_text(encoding="utf-8")


def test_cli_include_payload_embeds_data(tmp_path):
    _seed_db(tmp_path)
    cli = _load_cli()
    out_path = tmp_path / "full.case.json"

    rc = cli.main([
        "--db", str(tmp_path / "evidence.db"),
        "--output", str(out_path),
        "--include-payload",
    ])

    assert rc == 0
    assert "alpha" in out_path.read_text(encoding="utf-8")


def test_cli_unopenable_database_returns_2(tmp_path):
    cli = _load_cli()
    # Pointing --db at a directory cannot be opened as a SQLite database,
    # which the CLI must report as exit code 2 rather than crashing.
    bad_db_dir = tmp_path / "not_a_db"
    bad_db_dir.mkdir()
    out_path = tmp_path / "out.json"

    rc = cli.main(["--db", str(bad_db_dir), "--output", str(out_path)])

    assert rc == 2
    assert not out_path.exists()
