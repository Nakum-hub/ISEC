import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

import src.utils.license_manager as lm
from src.utils.license_manager import LicenseManager


def _sign_payload(private_key, payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return private_key.sign(canonical).hex()


def test_license_helper_parsers_and_feature_normalization():
    assert lm._parse_datetime(None) is None
    assert lm._parse_datetime("invalid") is None
    assert lm._parse_signature("") is None
    assert lm._parse_signature("zz") is None
    assert lm._parse_signature("41424344") == b"ABCD"
    assert lm._parse_signature(base64.b64encode(b"ABCD").decode("utf-8")) == b"ABCD"

    normalized = lm._normalize_features(["collect", "Collect", " report ", "", None, "view"])
    assert normalized == ["collect", "report", "view"]


def test_license_public_key_loading_paths(tmp_path, monkeypatch):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    env_file = tmp_path / "pub.pem"
    env_file.write_text(public_pem, encoding="utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY_FILE", str(env_file))
    monkeypatch.delenv("ISEC_LICENSE_PUBLIC_KEY", raising=False)
    assert "BEGIN PUBLIC KEY" in lm._load_public_key_pem()

    monkeypatch.delenv("ISEC_LICENSE_PUBLIC_KEY_FILE", raising=False)
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", public_pem)
    assert lm._load_public_key_pem() == public_pem

    # Default key path branch.
    monkeypatch.delenv("ISEC_LICENSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("ISEC_LICENSE_PUBLIC_KEY_FILE", raising=False)
    default_root = tmp_path / "default_root"
    (default_root / "keys").mkdir(parents=True, exist_ok=True)
    (default_root / "keys" / "license_public_key.pem").write_text(public_pem, encoding="utf-8")
    monkeypatch.setattr(lm, "_project_root", lambda: str(default_root))
    assert "BEGIN PUBLIC KEY" in lm._load_public_key_pem()

    # State key path branch.
    state_root = tmp_path / "state_root"
    (state_root / "keys").mkdir(parents=True, exist_ok=True)
    (state_root / "keys" / "license_public_key.pem").write_text(public_pem, encoding="utf-8")
    monkeypatch.setattr(lm, "_project_root", lambda: str(tmp_path / "missing_default_root"))
    monkeypatch.setattr(lm, "get_state_dir", lambda: str(state_root))
    assert "BEGIN PUBLIC KEY" in lm._load_public_key_pem()


def test_license_constraints_not_before_host_and_fingerprint(tmp_path, monkeypatch):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", public_pem)

    base_payload = {
        "license_id": "LIC-COVER-1",
        "customer": "Cover Customer",
        "plan": "enterprise",
        "features": ["all"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }

    payload_not_before = dict(base_payload)
    payload_not_before["not_before"] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    path1 = tmp_path / "nb.json"
    path1.write_text(json.dumps({"payload": payload_not_before, "signature": _sign_payload(private_key, payload_not_before)}), encoding="utf-8")
    status1 = LicenseManager(license_file=str(path1)).get_status()
    assert status1["valid"] is False
    assert "not active yet" in status1["message"].lower()

    payload_host = dict(base_payload)
    payload_host["allowed_hosts"] = ["different-host"]
    path2 = tmp_path / "host.json"
    path2.write_text(json.dumps({"payload": payload_host, "signature": _sign_payload(private_key, payload_host)}), encoding="utf-8")
    status2 = LicenseManager(license_file=str(path2)).get_status()
    assert status2["valid"] is False
    assert "host" in status2["message"].lower()

    payload_fingerprint = dict(base_payload)
    payload_fingerprint["allowed_fingerprints"] = ["0000-not-current"]
    path3 = tmp_path / "fp.json"
    path3.write_text(json.dumps({"payload": payload_fingerprint, "signature": _sign_payload(private_key, payload_fingerprint)}), encoding="utf-8")
    status3 = LicenseManager(license_file=str(path3)).get_status()
    assert status3["valid"] is False
    assert "device" in status3["message"].lower()


def test_license_invalid_key_type_and_allows_all(tmp_path, monkeypatch):
    # RSA key should be rejected because license verifier requires Ed25519 public key.
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_pem = rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", rsa_public_pem)

    payload = {
        "license_id": "LIC-RSA-KEY",
        "customer": "Cover Customer",
        "plan": "enterprise",
        "features": ["all"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    # Signature bytes are irrelevant here; key type check fails first.
    bad_sig = "aa" * 64
    license_path = tmp_path / "rsa.json"
    license_path.write_text(json.dumps({"payload": payload, "signature": bad_sig}), encoding="utf-8")

    status = LicenseManager(license_file=str(license_path)).get_status()
    assert status["valid"] is False
    assert "ed25519" in status["message"].lower()

    # Positive all-feature allows check.
    ed_private = ed25519.Ed25519PrivateKey.generate()
    ed_public_pem = ed_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", ed_public_pem)
    payload2 = dict(payload)
    payload2["license_id"] = "LIC-ALL"
    payload2["signature"] = None
    license_path2 = tmp_path / "all.json"
    license_path2.write_text(json.dumps({"payload": payload2, "signature": _sign_payload(ed_private, payload2)}), encoding="utf-8")
    manager = LicenseManager(license_file=str(license_path2))
    assert manager.get_status()["valid"] is True
    assert manager.allows("collect") is True
    assert manager.allows("random-feature") is True


def test_license_missing_and_malformed_payload(tmp_path, monkeypatch):
    monkeypatch.delenv("ISEC_LICENSE_PUBLIC_KEY", raising=False)
    missing = LicenseManager(license_file=str(tmp_path / "missing.json")).get_status()
    assert missing["status"] == "missing"

    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps({"payload": "bad", "signature": "aa"}), encoding="utf-8")
    status = LicenseManager(license_file=str(malformed)).get_status()
    assert status["valid"] is False
    assert status["status"] == "missing"


def test_license_state_file_fallback_and_flat_payload(tmp_path, monkeypatch):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", public_pem)

    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(lm, "get_state_dir", lambda: str(state_dir))
    monkeypatch.setattr(lm, "_project_root", lambda: str(tmp_path / "missing_root"))
    monkeypatch.delenv("ISEC_LICENSE_FILE", raising=False)

    payload = {
        "license_id": "LIC-FLAT-1",
        "customer": "Flat Payload",
        "plan": "pro",
        "features": ["view"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=5)).isoformat(),
    }
    signature = _sign_payload(private_key, payload)
    flat_doc = dict(payload)
    flat_doc["signature"] = signature
    (state_dir / "license.json").write_text(json.dumps(flat_doc), encoding="utf-8")

    manager = LicenseManager()
    status = manager.get_status()
    assert status["valid"] is True
    assert status["license_id"] == "LIC-FLAT-1"


def test_license_signature_error_branches(tmp_path, monkeypatch):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    payload = {
        "license_id": "LIC-SIG-BRANCH",
        "customer": "Branch",
        "plan": "pro",
        "features": ["collect"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
    }
    signature = _sign_payload(private_key, payload)
    license_path = tmp_path / "sig_branch.json"
    license_path.write_text(json.dumps({"payload": payload, "signature": signature}), encoding="utf-8")

    # No public key configured branch.
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", "")
    monkeypatch.setattr(lm, "_load_public_key_pem", lambda: None)
    manager = LicenseManager(license_file=str(license_path))
    status = manager.get_status()
    assert status["valid"] is False
    assert "not configured" in status["message"].lower()

    # Missing signature branch.
    monkeypatch.setattr(lm, "_load_public_key_pem", lambda: public_pem)
    missing_sig_path = tmp_path / "missing_sig.json"
    missing_sig_path.write_text(json.dumps({"payload": payload, "signature": ""}), encoding="utf-8")
    status2 = LicenseManager(license_file=str(missing_sig_path)).get_status()
    assert status2["valid"] is False
    assert "missing or invalid" in status2["message"].lower()


def test_license_manager_ignores_inline_public_key_in_production(monkeypatch, tmp_path):
    monkeypatch.setenv("ISEC_ENV", "production")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", "inline-attacker-key")
    monkeypatch.delenv("ISEC_LICENSE_PUBLIC_KEY_FILE", raising=False)

    missing = tmp_path / "missing_license.json"
    manager = LicenseManager(license_file=str(missing))
    assert manager.public_key_pem is None
