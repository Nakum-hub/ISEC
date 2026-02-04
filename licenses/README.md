License Files
=============

License files are stored as signed JSON documents in the project root (default `license.json`).

Format:
```
{
  "payload": {
    "license_id": "LIC-001",
    "customer": "Acme Corp",
    "plan": "enterprise",
    "features": ["collect", "report", "export", "view"],
    "issued_at": "2026-02-03T18:00:00Z",
    "expires_at": "2026-12-31T23:59:59Z",
    "machine_fingerprint": "optional"
  },
  "signature": "hex_or_base64_signature"
}
```

Use `scripts/generate_license_keypair.py` and `scripts/generate_license.py` to create keys and signed licenses.
