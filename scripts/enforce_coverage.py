"""
Enforce per-module coverage gates from a coverage.py JSON report.
"""
import argparse
import json
import os
import sys


DEFAULT_TARGETS = {
    "src/utils/license_manager.py": 85.0,
    "src/utils/role_manager.py": 85.0,
    "src/storage/database.py": 85.0,
    "verify_export.py": 85.0,
}


def parse_args():
    parser = argparse.ArgumentParser(description="Enforce per-module coverage thresholds.")
    parser.add_argument(
        "--coverage-json",
        default=os.path.join("coverage", "coverage.json"),
        help="Path to coverage JSON report (default: coverage/coverage.json)",
    )
    parser.add_argument(
        "--min-percent",
        type=float,
        default=85.0,
        help="Default minimum percentage for all tracked modules (default: 85.0)",
    )
    return parser.parse_args()


def normalize_path(path):
    return str(path).replace("\\", "/").strip()


def main():
    args = parse_args()
    json_path = args.coverage_json

    if not os.path.exists(json_path):
        print(f"[FAIL] Coverage report not found: {json_path}")
        return 2

    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    files = payload.get("files", {})
    if not isinstance(files, dict):
        print("[FAIL] Coverage report format is invalid: missing 'files'.")
        return 2

    failed = False
    for target, default_threshold in DEFAULT_TARGETS.items():
        threshold = max(default_threshold, args.min_percent)
        file_entry = None

        for key, value in files.items():
            normalized_key = normalize_path(key)
            if normalized_key.endswith(normalize_path(target)):
                file_entry = value
                break

        if not file_entry:
            print(f"[FAIL] Module coverage entry missing: {target}")
            failed = True
            continue

        summary = file_entry.get("summary", {})
        covered = float(summary.get("percent_covered", 0.0))
        status = "PASS" if covered >= threshold else "FAIL"
        print(f"[{status}] {target}: {covered:.2f}% (required: {threshold:.2f}%)")
        if covered < threshold:
            failed = True

    if failed:
        print("[FAIL] Coverage gate failed.")
        return 1

    print("[PASS] Coverage gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
