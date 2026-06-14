#!/usr/bin/env python3
"""Verify an ISEC forensic transparency-log ledger.

The transparency log is an append-only, hash-linked, optionally-signed record
of evidence-chain checkpoints kept *outside* the evidence database. Replaying
it detects rollback, truncation, or wholesale substitution of the evidence
database -- tampering that the in-database hash chain alone cannot reveal,
because an attacker who replaces the whole database also replaces its internal
chain.

Usage:
    python scripts/verify_transparency_log.py --ledger evidence_output/transparency_log.jsonl
    python scripts/verify_transparency_log.py --ledger <path> --json
    python scripts/verify_transparency_log.py --ledger <path> --no-verify-signatures

Exit codes:
    0  ledger is valid
    1  ledger is present but invalid (tampering / inconsistency detected)
    2  ledger file not found
"""
import argparse
import json
import os
import sys

# Allow running as a plain script (python scripts/verify_transparency_log.py)
# by making the repository root importable.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.forensics.transparency_log import TransparencyLog


def _load_signer():
    """Return the local signer if signing keys are available, else None."""
    try:
        from src.utils.digital_signer import get_signer
        return get_signer()
    except Exception:
        return None


def verify_ledger(ledger_path, verify_signatures=True):
    """Verify a ledger file and return the verification summary dict."""
    signer = _load_signer() if verify_signatures else None
    log = TransparencyLog(ledger_path, signer=signer)
    result = log.verify()
    result["ledger_path"] = ledger_path
    result["signature_verification"] = bool(signer is not None)
    return result


def _print_human(result):
    status = "VALID" if result.get("valid") else "INVALID"
    print(f"Transparency log: {status}")
    print(f"  Ledger: {result.get('ledger_path')}")
    print(f"  Entries: {result.get('entries', 0)}")
    print(f"  Signature verification: {'on' if result.get('signature_verification') else 'off'}")
    issues = result.get("issues") or []
    if issues:
        print("  Issues:")
        for issue in issues:
            print(f"    - {issue}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify an ISEC forensic transparency-log ledger."
    )
    parser.add_argument("--ledger", required=True, help="Path to the transparency log (JSONL).")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--no-verify-signatures",
        action="store_true",
        help="Skip digital-signature verification (structural checks only).",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.ledger):
        message = f"Transparency log not found: {args.ledger}"
        if args.json:
            print(json.dumps(
                {"valid": False, "entries": 0, "issues": [message], "ledger_path": args.ledger},
                indent=2, sort_keys=True,
            ))
        else:
            print(message)
        return 2

    result = verify_ledger(args.ledger, verify_signatures=not args.no_verify_signatures)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(result)

    return 0 if result.get("valid") else 1


if __name__ == "__main__":
    sys.exit(main())
