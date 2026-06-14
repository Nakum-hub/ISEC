"""
Integration tests for the transparency-log feature wired into
EvidenceCollector, plus the standalone verification CLI.

These use a real EvidenceCollector (tmp output dir), real evidence rows, and a
real signer keypair generated into the test-isolated state dir -- no mocks.
"""
import importlib.util
import os

import pytest

from src.core.collector import EvidenceCollector


def _fresh_signer():
    """Reset the signer singleton so get_signer() regenerates keys in the
    current test-isolated state dir (avoids reusing a torn-down dir)."""
    import src.utils.digital_signer as ds

    if hasattr(ds, "signer_instance"):
        ds.signer_instance = None


def test_transparency_disabled_by_default(tmp_path):
    collector = EvidenceCollector(str(tmp_path / "out"))
    assert collector.transparency_log_enabled is False
    assert collector.transparency_log is None

    # Disabled verify summary is well-formed and does not create a ledger.
    summary = collector.verify_transparency_log()
    assert summary["enabled"] is False
    assert summary["valid"] is True

    # Recording is a no-op and never raises.
    assert collector._record_transparency_checkpoint("noop") is None
    assert not os.path.exists(collector.transparency_log_path)


def test_transparency_enabled_records_and_verifies(tmp_path):
    _fresh_signer()
    out_dir = tmp_path / "out"
    collector = EvidenceCollector(str(out_dir), transparency_log_enabled=True)
    assert collector.transparency_log_enabled is True
    assert collector.transparency_log is not None

    # Store a couple of real evidence rows directly via storage.
    collector.storage.store_evidence("system_logs", {"line": "a"}, "actor", "ws-1", "10.0.0.1")
    collector.storage.store_evidence("file_metadata", {"path": "/tmp/x"}, "actor", "ws-1", "10.0.0.1")

    record = collector._record_transparency_checkpoint("unit-test")
    assert record is not None
    assert record["entry"]["record_count"] == 2
    assert os.path.exists(collector.transparency_log_path)

    summary = collector.verify_transparency_log()
    assert summary["enabled"] is True
    assert summary["valid"] is True
    assert summary["entries"] == 1
    assert summary["issues"] == []


def test_transparency_enabled_via_env(tmp_path, monkeypatch):
    _fresh_signer()
    monkeypatch.setenv("ISEC_TRANSPARENCY_LOG", "1")
    collector = EvidenceCollector(str(tmp_path / "out"))
    assert collector.transparency_log_enabled is True
    assert collector.transparency_log is not None


def _load_verify_script():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script_path = os.path.join(repo_root, "scripts", "verify_transparency_log.py")
    spec = importlib.util.spec_from_file_location("isec_verify_transparency_log", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_cli_reports_valid_ledger(tmp_path):
    from src.forensics.transparency_log import TransparencyLog

    ledger_path = tmp_path / "transparency_log.jsonl"
    log = TransparencyLog(str(ledger_path))  # unsigned for a deterministic check
    log.append_checkpoint(tip_hash="aaa", record_count=1)
    log.append_checkpoint(tip_hash="bbb", record_count=2)

    script = _load_verify_script()
    result = script.verify_ledger(str(ledger_path), verify_signatures=False)
    assert result["valid"] is True
    assert result["entries"] == 2
    assert result["ledger_path"] == str(ledger_path)

    # CLI entry point: 0 == valid, 2 == not found.
    assert script.main(["--ledger", str(ledger_path), "--no-verify-signatures", "--json"]) == 0
    assert script.main(["--ledger", str(tmp_path / "missing.jsonl")]) == 2


def test_verify_cli_detects_tampered_ledger(tmp_path):
    from src.forensics.transparency_log import TransparencyLog

    ledger_path = tmp_path / "transparency_log.jsonl"
    log = TransparencyLog(str(ledger_path))
    log.append_checkpoint(tip_hash="aaa", record_count=1)
    log.append_checkpoint(tip_hash="bbb", record_count=2)
    log.append_checkpoint(tip_hash="ccc", record_count=3)

    # Drop the middle entry -> broken ledger linkage.
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    script = _load_verify_script()
    result = script.verify_ledger(str(ledger_path), verify_signatures=False)
    assert result["valid"] is False
    # CLI returns 1 for an invalid (present) ledger.
    assert script.main(["--ledger", str(ledger_path), "--no-verify-signatures"]) == 1
