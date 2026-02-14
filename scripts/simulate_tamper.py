"""
Generate tampered export archives and validate that verify_export.py fails.

Scenarios:
1) database_tamper: modifies a DB record while keeping file checksum entry in manifest in sync
2) manifest_checksum_tamper: corrupts a manifest checksum entry
3) pdf_signature_tamper: corrupts PDF signature payload while keeping manifest checksum in sync
"""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import zipfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from verify_export import verify_export_archive


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rewrite_zip(source_zip, output_zip, mutate_fn):
    with tempfile.TemporaryDirectory(prefix="isek_tamper_") as tmp_dir:
        with zipfile.ZipFile(source_zip, "r") as zf:
            zf.extractall(tmp_dir)

        mutate_fn(tmp_dir)

        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(tmp_dir):
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    arc_name = os.path.relpath(full_path, tmp_dir).replace("\\", "/")
                    zf.write(full_path, arc_name)


def mutate_database_tamper(root):
    manifest_path = os.path.join(root, "checksum_manifest.json")
    manifest = json.loads(open(manifest_path, "r", encoding="utf-8").read())

    db_rel = manifest.get("evidence_database", {}).get("file")
    if not db_rel:
        raise RuntimeError("No evidence database file listed in manifest.")
    db_path = os.path.join(root, db_rel)

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE evidence SET actor = 'tamper_simulation' WHERE id = (SELECT MIN(id) FROM evidence)")
        conn.commit()
    finally:
        conn.close()

    # Keep file-list checksum in sync so verification proceeds to DB hash check.
    if db_rel in manifest.get("files", {}):
        manifest["files"][db_rel] = sha256_file(db_path)

    open(manifest_path, "w", encoding="utf-8").write(json.dumps(manifest, indent=2, sort_keys=True))


def mutate_manifest_checksum(root):
    manifest_path = os.path.join(root, "checksum_manifest.json")
    manifest = json.loads(open(manifest_path, "r", encoding="utf-8").read())
    files = manifest.get("files", {})
    if not files:
        raise RuntimeError("Manifest files list is empty.")
    first_key = sorted(files.keys())[0]
    files[first_key] = "0" * 64
    open(manifest_path, "w", encoding="utf-8").write(json.dumps(manifest, indent=2, sort_keys=True))


def mutate_pdf_signature(root):
    manifest_path = os.path.join(root, "checksum_manifest.json")
    manifest = json.loads(open(manifest_path, "r", encoding="utf-8").read())
    sig_rel = manifest.get("pdf_signature", {}).get("signature_file")
    if not sig_rel:
        raise RuntimeError("Signature file missing from manifest.")

    sig_path = os.path.join(root, sig_rel)
    signature_record = json.loads(open(sig_path, "r", encoding="utf-8").read())
    current_signature = signature_record.get("signature", "")
    if not current_signature:
        raise RuntimeError("Signature payload is empty.")

    # Corrupt signature without changing structure.
    first_char = "0" if current_signature[0] != "0" else "1"
    signature_record["signature"] = first_char + current_signature[1:]
    open(sig_path, "w", encoding="utf-8").write(json.dumps(signature_record, indent=2, sort_keys=True))

    # Keep checksum manifest in sync so signature verification stage is reached.
    manifest["files"][sig_rel] = sha256_file(sig_path)
    open(manifest_path, "w", encoding="utf-8").write(json.dumps(manifest, indent=2, sort_keys=True))


def run_scenario(name, source_zip, output_dir, mutate_fn):
    stem = os.path.splitext(os.path.basename(source_zip))[0]
    tampered_zip = os.path.join(output_dir, f"{stem}.{name}.zip")
    rewrite_zip(source_zip, tampered_zip, mutate_fn)
    result = verify_export_archive(tampered_zip)
    return {
        "scenario": name,
        "zip": tampered_zip,
        "success": result.get("success", False),
        "checks": result.get("checks", {}),
        "error": result.get("details", {}).get("error", ""),
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Simulate tampering against an exported ISEC ZIP.")
    parser.add_argument("zip_path", help="Path to a valid exported ZIP")
    parser.add_argument(
        "--output-dir",
        default=os.path.join("artifacts", "tamper_simulation"),
        help="Directory for tampered archives and results",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    return parser.parse_args()


def main():
    args = parse_args()
    zip_path = os.path.abspath(args.zip_path)
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"Export ZIP not found: {zip_path}")

    os.makedirs(args.output_dir, exist_ok=True)

    scenarios = [
        ("database_tamper", mutate_database_tamper),
        ("manifest_checksum_tamper", mutate_manifest_checksum),
        ("pdf_signature_tamper", mutate_pdf_signature),
    ]

    results = []
    for name, fn in scenarios:
        results.append(run_scenario(name, zip_path, args.output_dir, fn))

    report = {
        "source_zip": zip_path,
        "results": results,
    }
    report_path = os.path.join(args.output_dir, "tamper_results.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    expected_failures = [r for r in results if r["success"] is False]
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("ISEC Tamper Simulation")
        print("=" * 24)
        for result in results:
            status = "DETECTED" if not result["success"] else "MISSED"
            print(f"- {result['scenario']}: {status}")
            if result["error"]:
                print(f"  error: {result['error']}")
        print(f"Results file: {report_path}")

    if len(expected_failures) != len(results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
