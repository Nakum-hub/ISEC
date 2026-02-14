"""
Verify an exported ISEC evidence ZIP archive.

Checks performed:
- checksum manifest presence and schema
- file hash validation against manifest
- evidence database hash validation
- chain-of-custody verification (hash chain + per-record HMAC signatures)
- PDF signature verification (report + signature + signing public key)
"""
import argparse
import hashlib
import json
import os
import tempfile
import zipfile
from contextlib import contextmanager

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from src.storage.database import EvidenceDatabase


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _isolated_verification_env(base_tmp_dir):
    state_dir = os.path.join(base_tmp_dir, "_verify_state")
    os.makedirs(state_dir, exist_ok=True)

    overrides = {
        "ISEC_STATE_DIR": state_dir,
    }
    removals = [
        "EVIDENCE_ENCRYPTION_KEY",
        "EVIDENCE_ENCRYPTION_KEY_FILE",
        "ISEC_HMAC_KEY",
        "ISEC_HMAC_KEY_FILE",
    ]

    original = {}
    for key in set(list(overrides.keys()) + removals):
        if key in os.environ:
            original[key] = os.environ[key]
        else:
            original[key] = None

    try:
        for key in removals:
            os.environ.pop(key, None)
        for key, value in overrides.items():
            os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _verify_pdf_signature(report_path, signature_path, public_key_path, evidence_db_path=None):
    checks = {
        "signature_record_valid": False,
        "metadata_hash_valid": False,
        "signature_valid": False,
        "report_hash_valid": False,
        "evidence_db_hash_valid": True,
    }
    try:
        with open(signature_path, "r", encoding="utf-8") as f:
            record = json.load(f)
        if not isinstance(record, dict):
            return False, "Invalid signature record format.", checks

        signature_hex = record.get("signature")
        payload_hash = record.get("payload_hash")
        metadata = record.get("metadata")
        if not signature_hex or not payload_hash or not isinstance(metadata, dict):
            return False, "Signature record missing required fields.", checks
        checks["signature_record_valid"] = True

        canonical_metadata = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        expected_payload_hash = hashlib.sha256(canonical_metadata.encode("utf-8")).hexdigest()
        checks["metadata_hash_valid"] = (expected_payload_hash == payload_hash)
        if not checks["metadata_hash_valid"]:
            return False, "Signature payload hash mismatch.", checks

        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                payload_hash.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            checks["signature_valid"] = True
        except InvalidSignature:
            return False, "Digital signature verification failed.", checks

        report_hash = _sha256(report_path)
        expected_report_hash = metadata.get("report_hash")
        checks["report_hash_valid"] = bool(expected_report_hash and report_hash == expected_report_hash)
        if not checks["report_hash_valid"]:
            return False, "Report hash mismatch.", checks

        if evidence_db_path:
            expected_db_hash = metadata.get("evidence_db_hash")
            actual_db_hash = _sha256(evidence_db_path)
            checks["evidence_db_hash_valid"] = bool(expected_db_hash and actual_db_hash == expected_db_hash)
            if not checks["evidence_db_hash_valid"]:
                return False, "Evidence DB hash mismatch in signature metadata.", checks

        return True, "PDF signature verification passed.", checks
    except Exception as exc:
        return False, f"PDF signature verification error: {exc}", checks


def verify_export_archive(zip_path):
    result = {
        "success": False,
        "checks": {
            "manifest_present": False,
            "manifest_schema_valid": False,
            "manifest_checksums_valid": False,
            "database_hash_valid": False,
            "chain_of_custody_valid": False,
            "pdf_signature_valid": False,
        },
        "details": {},
    }

    if not os.path.exists(zip_path):
        result["details"]["error"] = "ZIP file not found."
        return result

    with tempfile.TemporaryDirectory(prefix="isek_verify_") as tmp_dir:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmp_dir)
            names = set(zf.namelist())

        manifest_path = os.path.join(tmp_dir, "checksum_manifest.json")
        if "checksum_manifest.json" not in names or not os.path.exists(manifest_path):
            result["details"]["error"] = "checksum_manifest.json missing from archive."
            return result
        result["checks"]["manifest_present"] = True

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        result["details"]["manifest"] = manifest

        schema_ok = manifest.get("schema") == "ISEC_EXPORT_MANIFEST_v1"
        result["checks"]["manifest_schema_valid"] = schema_ok
        if not schema_ok:
            result["details"]["error"] = "Unsupported manifest schema."
            return result

        files = manifest.get("files", {})
        if not isinstance(files, dict) or not files:
            result["details"]["error"] = "Manifest file hash list is invalid."
            return result

        checksum_failures = []
        for archive_name, expected_hash in files.items():
            path = os.path.join(tmp_dir, archive_name)
            if not os.path.exists(path):
                checksum_failures.append(f"missing:{archive_name}")
                continue
            actual_hash = _sha256(path)
            if actual_hash != expected_hash:
                checksum_failures.append(f"hash_mismatch:{archive_name}")
        result["checks"]["manifest_checksums_valid"] = len(checksum_failures) == 0
        result["details"]["checksum_failures"] = checksum_failures
        if checksum_failures:
            return result

        db_info = manifest.get("evidence_database", {})
        db_file = db_info.get("file")
        db_path = os.path.join(tmp_dir, db_file) if db_file else None
        if not db_path or not os.path.exists(db_path):
            result["details"]["error"] = "Evidence database file is missing."
            return result

        db_hash_ok = (_sha256(db_path) == db_info.get("sha256"))
        result["checks"]["database_hash_valid"] = db_hash_ok
        if not db_hash_ok:
            result["details"]["error"] = "Evidence database hash mismatch."
            return result

        with _isolated_verification_env(tmp_dir):
            db = EvidenceDatabase(db_path)
            hash_chain_valid = db.verify_full_hash_chain(update_results=False)
            rows = db.get_all_evidence(include_expired=True, include_deleted=True)
            verified_records = 0
            for row in rows:
                if db.verify_integrity(row[0]):
                    verified_records += 1
        manifest_chain = manifest.get("chain_of_custody", {})
        chain_counts_match = (
            manifest_chain.get("verified_records") == verified_records
            and manifest_chain.get("total_records") == len(rows)
        )
        chain_valid = hash_chain_valid and (verified_records == len(rows)) and chain_counts_match
        result["checks"]["chain_of_custody_valid"] = chain_valid
        result["details"]["chain_of_custody"] = {
            "hash_chain_valid": hash_chain_valid,
            "verified_records": verified_records,
            "total_records": len(rows),
            "matches_manifest": chain_counts_match,
        }
        if not chain_valid:
            result["details"]["error"] = "Chain-of-custody integrity checks failed."
            return result

        pdf_meta = manifest.get("pdf_signature", {})
        report_file = pdf_meta.get("report_file")
        signature_file = pdf_meta.get("signature_file")
        public_key_file = pdf_meta.get("public_key_file")
        if not report_file or not signature_file or not public_key_file:
            result["details"]["error"] = "PDF signature files are missing from manifest."
            return result

        report_path = os.path.join(tmp_dir, report_file)
        signature_path = os.path.join(tmp_dir, signature_file)
        public_key_path = os.path.join(tmp_dir, public_key_file)
        if not os.path.exists(report_path) or not os.path.exists(signature_path) or not os.path.exists(public_key_path):
            result["details"]["error"] = "PDF signature artifacts are missing from archive."
            return result

        sig_ok, sig_message, sig_checks = _verify_pdf_signature(
            report_path=report_path,
            signature_path=signature_path,
            public_key_path=public_key_path,
            evidence_db_path=db_path,
        )
        result["checks"]["pdf_signature_valid"] = sig_ok
        result["details"]["pdf_signature"] = {
            "message": sig_message,
            "checks": sig_checks,
        }
        if not sig_ok:
            result["details"]["error"] = sig_message
            return result

    result["success"] = all(result["checks"].values())
    return result


def main():
    parser = argparse.ArgumentParser(description="Verify an exported ISEC ZIP package.")
    parser.add_argument("zip_path", help="Path to exported evidence ZIP")
    parser.add_argument("--json", action="store_true", help="Print full JSON result")
    args = parser.parse_args()

    result = verify_export_archive(args.zip_path)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    print("ISEC Export Verification")
    print("=" * 32)
    print(f"Archive: {args.zip_path}")
    print(f"Success: {'YES' if result.get('success') else 'NO'}")
    for name, value in result.get("checks", {}).items():
        print(f"- {name}: {'PASS' if value else 'FAIL'}")
    if result.get("details", {}).get("error"):
        print(f"Error: {result['details']['error']}")


if __name__ == "__main__":
    main()
