"""Generate an Ed25519 license keypair for ISEC."""
import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser(description="Generate ISEC license keypair")
    parser.add_argument("--output-dir", default="keys", help="Directory to write keypair")
    parser.add_argument("--force", action="store_true", help="Overwrite existing keys")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    private_path = output_dir / "license_private_key.pem"
    public_path = output_dir / "license_public_key.pem"

    if (private_path.exists() or public_path.exists()) and not args.force:
        print("Keypair already exists. Use --force to overwrite.")
        return

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    try:
        os.chmod(private_path, 0o600)
    except Exception:
        pass

    print(f"Private key written to: {private_path}")
    print(f"Public key written to: {public_path}")
    print("Distribute ONLY the public key with the app build.")


if __name__ == "__main__":
    main()
