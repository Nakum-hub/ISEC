#!/usr/bin/env python3
"""Export ISEC evidence to a CASE/UCO JSON-LD bundle.

Standalone command-line entry point so evidence can be exported for
interoperability with other forensic tooling without going through main.py.

Examples::

    python scripts/export_case.py --db output/evidence.db --output export/evidence.case.json
    python scripts/export_case.py --db output/evidence.db --output export/full.json \
        --include-payload --include-expired --include-deleted

Exit codes: 0 = success, 1 = export error, 2 = could not open database.
"""
import argparse
import sys

from src.storage.database import EvidenceDatabase
from src.forensics.case_export import export_case_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Export ISEC evidence to a CASE/UCO JSON-LD bundle."
    )
    parser.add_argument(
        "--db", required=True,
        help="Path to the ISEC evidence SQLite database.",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path to write the CASE/UCO JSON-LD bundle.",
    )
    parser.add_argument(
        "--include-payload", action="store_true",
        help="Embed decrypted evidence payloads (off by default for privacy).",
    )
    parser.add_argument(
        "--include-expired", action="store_true",
        help="Include records flagged as expired.",
    )
    parser.add_argument(
        "--include-deleted", action="store_true",
        help="Include records flagged as deleted.",
    )
    parser.add_argument(
        "--tool-version", default="1.0.0",
        help="Tool version string recorded in the bundle (default: 1.0.0).",
    )
    args = parser.parse_args(argv)

    try:
        storage = EvidenceDatabase(args.db)
    except Exception as exc:  # noqa: BLE001 - surface any open failure to the CLI
        print(f"ERROR: could not open evidence database: {exc}", file=sys.stderr)
        return 2

    try:
        path = export_case_bundle(
            storage,
            args.output,
            tool_version=args.tool_version,
            include_payload=args.include_payload,
            include_expired=args.include_expired,
            include_deleted=args.include_deleted,
        )
    except Exception as exc:  # noqa: BLE001 - report and fail cleanly
        print(f"ERROR: export failed: {exc}", file=sys.stderr)
        return 1

    print(f"CASE/UCO bundle written to: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
