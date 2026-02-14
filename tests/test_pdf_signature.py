import json

from src.utils.digital_signer import DigitalSigner


def test_pdf_signature_verification_passes(tmp_path):
    keys_dir = tmp_path / "keys"
    report_path = tmp_path / "report.pdf"
    db_path = tmp_path / "evidence.db"
    report_path.write_bytes(b"%PDF-1.4\n%ISEC Test Report\n")
    db_path.write_bytes(b"sqlite-bytes")

    signer = DigitalSigner(keys_dir=str(keys_dir))
    signature_data = {
        "report_filename": report_path.name,
        "evidence_db_hash": signer._calculate_file_hash(str(db_path)),
    }
    sig_path = signer.sign_pdf(str(report_path), signature_data)

    verification = signer.verify_pdf_signature(
        report_path=str(report_path),
        signature_path=sig_path,
        evidence_db_path=str(db_path),
    )
    assert verification["success"] is True


def test_pdf_signature_verification_fails_on_tamper(tmp_path):
    keys_dir = tmp_path / "keys"
    report_path = tmp_path / "report.pdf"
    db_path = tmp_path / "evidence.db"
    report_path.write_bytes(b"%PDF-1.4\n%ISEC Test Report\n")
    db_path.write_bytes(b"sqlite-bytes")

    signer = DigitalSigner(keys_dir=str(keys_dir))
    signature_data = {
        "report_filename": report_path.name,
        "evidence_db_hash": signer._calculate_file_hash(str(db_path)),
    }
    sig_path = signer.sign_pdf(str(report_path), signature_data)

    record = json.loads(open(sig_path, "r", encoding="utf-8").read())
    record["metadata"]["report_hash"] = "tampered"
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, sort_keys=True)

    verification = signer.verify_pdf_signature(
        report_path=str(report_path),
        signature_path=sig_path,
        evidence_db_path=str(db_path),
    )
    assert verification["success"] is False
