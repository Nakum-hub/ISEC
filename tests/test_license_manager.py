import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.utils.license_manager import LicenseManager


def _canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _build_signed_license(tmp_path, monkeypatch, payload):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", public_pem)

    signature = private_key.sign(_canonical_payload(payload)).hex()
    license_doc = {"payload": payload, "signature": signature}
    license_path = tmp_path / "license.json"
    license_path.write_text(json.dumps(license_doc), encoding="utf-8")
    return license_path


def test_license_signature_validation_valid(tmp_path, monkeypatch):
    payload = {
        "license_id": "LIC-VALID-001",
        "customer": "Test Customer",
        "plan": "pro",
        "features": ["collect", "view", "report", "export"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    license_path = _build_signed_license(tmp_path, monkeypatch, payload)
    manager = LicenseManager(license_file=str(license_path))
    status = manager.get_status()

    assert status["valid"] is True
    assert status["status"] == "valid"
    assert manager.allows("collect") is True
    assert manager.allows("unknown_feature") is False


def test_license_signature_validation_invalid_signature(tmp_path, monkeypatch):
    payload = {
        "license_id": "LIC-BAD-SIG-001",
        "customer": "Test Customer",
        "plan": "pro",
        "features": ["collect", "view"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    license_path = _build_signed_license(tmp_path, monkeypatch, payload)

    # Tamper payload without re-signing to trigger signature verification failure.
    data = json.loads(license_path.read_text(encoding="utf-8"))
    data["payload"]["plan"] = "enterprise"
    license_path.write_text(json.dumps(data), encoding="utf-8")

    manager = LicenseManager(license_file=str(license_path))
    status = manager.get_status()

    assert status["valid"] is False
    assert status["status"] == "invalid_signature"


def test_expired_license_rejected(tmp_path, monkeypatch):
    payload = {
        "license_id": "LIC-EXPIRED-001",
        "customer": "Test Customer",
        "plan": "starter",
        "features": ["view"],
        "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
    }
    license_path = _build_signed_license(tmp_path, monkeypatch, payload)
    manager = LicenseManager(license_file=str(license_path))
    status = manager.get_status()

    assert status["valid"] is False
    assert status["status"] == "invalid_constraints"
    assert "expired" in status["message"].lower()
