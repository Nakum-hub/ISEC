"""Generate a signed license file for ISEC."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Generate signed ISEC license")
    parser.add_argument("--private-key", required=True, help="Path to license_private_key.pem")
    parser.add_argument("--output", default="license.json", help="Output license file")
    parser.add_argument("--license-id", required=True, help="Unique license ID")
    parser.add_argument("--customer", required=True, help="Customer name")
    parser.add_argument("--plan", default="standard", help="Plan name")
    parser.add_argument("--features", default="collect,report,export,view", help="Comma-separated feature list")
    parser.add_argument("--expires-at", help="Expiry datetime in ISO-8601 (e.g. 2026-12-31T23:59:59Z)")
    parser.add_argument("--not-before", help="Start datetime in ISO-8601")
    parser.add_argument("--machine-fingerprint", help="Optional machine fingerprint to lock license")
    parser.add_argument("--allowed-hosts", help="Comma-separated hostnames to allow")
    args = parser.parse_args()

    private_key_path = Path(args.private_key)
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519")

    features = [feature.strip() for feature in args.features.split(",") if feature.strip()]
    allowed_hosts = [host.strip() for host in (args.allowed_hosts or "").split(",") if host.strip()]

    payload = {
        "license_id": args.license_id,
        "customer": args.customer,
        "plan": args.plan,
        "features": features,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    if args.expires_at:
        payload["expires_at"] = args.expires_at
    if args.not_before:
        payload["not_before"] = args.not_before
    if args.machine_fingerprint:
        payload["machine_fingerprint"] = args.machine_fingerprint
    if allowed_hosts:
        payload["allowed_hosts"] = allowed_hosts

    signature = private_key.sign(canonical_payload(payload)).hex()
    license_doc = {"payload": payload, "signature": signature}

    Path(args.output).write_text(json.dumps(license_doc, indent=2), encoding="utf-8")
    print(f"License written to: {args.output}")


if __name__ == "__main__":
    main()
