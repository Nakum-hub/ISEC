import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from src.core.collector import EvidenceCollector
from src.utils.digital_signer import get_signer
from src.utils.role_manager import UserRole
import verify_export as verify_mod
from verify_export import verify_export_archive


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _make_valid_export(tmp_path):
    output_dir = tmp_path / "output"
    export_dir = tmp_path / "exports"
    output_dir.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)

    collector = EvidenceCollector(str(output_dir), collect_enabled=False)
    collector.storage.store_evidence("system_logs", {"event": "seed"}, actor="tester")
    collector.role_manager.set_role(UserRole.EXPORTER, assigned_by="test")
    collector.storage.verify_full_hash_chain(update_results=True)

    report_path = output_dir / "report.pdf"
    report_path.write_bytes(b"%PDF-1.4\n%ISEC Test\n")

    signer = get_signer()
    signature_data = {
        "report_filename": report_path.name,
        "evidence_db_hash": signer._calculate_file_hash(collector.storage.db_path),
    }
    signer.sign_pdf(str(report_path), signature_data)

    export_zip = collector.export_to_zip(str(export_dir), report_path=str(report_path))
    assert export_zip is not None
    assert os.path.exists(export_zip)
    return Path(export_zip)


def _rewrite_zip_with_mutation(src_zip, mutate_fn):
    with tempfile.TemporaryDirectory(prefix="verify_export_test_") as tmp_dir:
        with zipfile.ZipFile(src_zip, "r") as zf:
            zf.extractall(tmp_dir)

        mutate_fn(Path(tmp_dir))

        with zipfile.ZipFile(src_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(tmp_dir):
                for file_name in files:
                    full_path = Path(root) / file_name
                    arc_name = str(full_path.relative_to(tmp_dir)).replace("\\", "/")
                    zf.write(full_path, arc_name)


def test_verify_export_success(tmp_path):
    export_zip = _make_valid_export(tmp_path)
    result = verify_export_archive(str(export_zip))
    assert result["success"] is True
    assert result["checks"]["manifest_present"] is True
    assert result["checks"]["pdf_signature_valid"] is True


def test_verify_export_missing_zip():
    result = verify_export_archive("does-not-exist.zip")
    assert result["success"] is False
    assert "not found" in result["details"]["error"].lower()


def test_verify_export_missing_manifest(tmp_path):
    zip_path = tmp_path / "no_manifest.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        dummy = tmp_path / "dummy.txt"
        dummy.write_text("x", encoding="utf-8")
        zf.write(dummy, "dummy.txt")
    result = verify_export_archive(str(zip_path))
    assert result["success"] is False
    assert "checksum_manifest.json missing" in result["details"]["error"].lower()


def test_verify_export_schema_failure(tmp_path):
    export_zip = _make_valid_export(tmp_path)

    def mutate(root):
        manifest_path = root / "checksum_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema"] = "BROKEN_SCHEMA"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    _rewrite_zip_with_mutation(export_zip, mutate)
    result = verify_export_archive(str(export_zip))
    assert result["success"] is False
    assert "schema" in result["details"]["error"].lower()


def test_verify_export_checksum_failure(tmp_path):
    export_zip = _make_valid_export(tmp_path)

    def mutate(root):
        db_path = root / "evidence.db"
        db_path.write_bytes(db_path.read_bytes() + b"tamper")

    _rewrite_zip_with_mutation(export_zip, mutate)
    result = verify_export_archive(str(export_zip))
    assert result["success"] is False
    assert result["checks"]["manifest_checksums_valid"] is False


def test_verify_export_db_hash_failure(tmp_path):
    export_zip = _make_valid_export(tmp_path)

    def mutate(root):
        manifest_path = root / "checksum_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["evidence_database"]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    _rewrite_zip_with_mutation(export_zip, mutate)
    result = verify_export_archive(str(export_zip))
    assert result["success"] is False
    assert "database hash mismatch" in result["details"]["error"].lower()


def test_verify_export_chain_of_custody_failure(tmp_path):
    export_zip = _make_valid_export(tmp_path)

    def mutate(root):
        manifest_path = root / "checksum_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["chain_of_custody"]["verified_records"] = 999
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    _rewrite_zip_with_mutation(export_zip, mutate)
    result = verify_export_archive(str(export_zip))
    assert result["success"] is False
    assert "chain-of-custody" in result["details"]["error"].lower()


def test_verify_export_pdf_signature_failure(tmp_path):
    export_zip = _make_valid_export(tmp_path)

    def mutate(root):
        manifest_path = root / "checksum_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature_file = manifest["pdf_signature"]["signature_file"]
        sig_path = root / signature_file
        record = json.loads(sig_path.read_text(encoding="utf-8"))
        record["metadata"]["report_hash"] = "f" * 64
        sig_path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
        manifest["files"][signature_file] = _sha256(sig_path)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    _rewrite_zip_with_mutation(export_zip, mutate)
    result = verify_export_archive(str(export_zip))
    assert result["success"] is False
    assert "signature" in result["details"]["error"].lower() or "report hash mismatch" in result["details"]["error"].lower()


def test_verify_pdf_signature_error_branches(tmp_path):
    report = tmp_path / "report.pdf"
    sig = tmp_path / "report.sig.json"
    pub = tmp_path / "public.pem"
    report.write_bytes(b"%PDF-1.4")
    sig.write_text("[]", encoding="utf-8")
    pub.write_text("not-a-key", encoding="utf-8")

    ok, msg, checks = verify_mod._verify_pdf_signature(str(report), str(sig), str(pub))
    assert ok is False
    assert "invalid signature record format" in msg.lower() or "error" in msg.lower()
    assert checks["signature_record_valid"] is False

    # Missing required fields branch.
    sig.write_text(json.dumps({"signature": "aa"}), encoding="utf-8")
    ok2, msg2, _ = verify_mod._verify_pdf_signature(str(report), str(sig), str(pub))
    assert ok2 is False
    assert "missing required fields" in msg2.lower()


def test_verify_export_main_json_and_text_output(tmp_path, monkeypatch, capsys):
    export_zip = _make_valid_export(tmp_path)

    monkeypatch.setattr("sys.argv", ["verify_export.py", str(export_zip), "--json"])
    verify_mod.main()
    out_json = capsys.readouterr().out
    assert "\"success\"" in out_json

    monkeypatch.setattr("sys.argv", ["verify_export.py", str(export_zip)])
    verify_mod.main()
    out_text = capsys.readouterr().out
    assert "ISEC Export Verification" in out_text
