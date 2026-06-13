"""Regression tests for V1: privilege escalation via a forged role file.

These tests prove that a privileged role (COLLECTOR/EXPORTER) is only honored
when the persisted role payload carries a valid HMAC tag keyed by the admin
token. Forged or wrongly-signed privileged roles must fall back to the
least-privileged REVIEWER role.
"""
import hashlib
import hmac
import json
import os

from cryptography.fernet import Fernet

from src.utils.role_manager import RoleManager, UserRole


class DummyStorage:
    def __init__(self):
        self.events = []

    def store_evidence(self, evidence_type, data, actor=None, **kwargs):
        self.events.append({
            "evidence_type": evidence_type,
            "data": data,
            "actor": actor,
        })
        return len(self.events)


def _write_role_file(manager, payload):
    """Encrypt a raw role payload with the (public) system-derived key.

    This simulates an attacker who knows the username/hostname and therefore
    can reproduce the confidentiality key, but does NOT know the admin token.
    """
    key = manager._derive_key_from_system_info()
    blob = Fernet(key).encrypt(json.dumps(payload).encode())
    with open(manager.encrypted_role_file, "wb") as f:
        f.write(blob)


def test_valid_signed_privileged_role_loads(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "secret-token")
    manager = RoleManager(DummyStorage())
    assert manager.set_role(UserRole.EXPORTER, assigned_by="admin_token") is True

    # A fresh manager must re-derive trust from the signed file.
    manager2 = RoleManager(DummyStorage())
    assert manager2.get_current_role() == UserRole.EXPORTER


def test_unsigned_forged_privileged_role_is_rejected(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "secret-token")
    manager = RoleManager(DummyStorage())

    forged = {
        "user": manager.user,
        "host": manager.host,
        "role": "exporter",
        "assigned_at": "2026-01-01T00:00:00",
        "assigned_by": "attacker",
        # no signature
    }
    _write_role_file(manager, forged)

    manager2 = RoleManager(DummyStorage())
    assert manager2.get_current_role() == UserRole.REVIEWER


def test_wrong_token_signature_is_rejected(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "real-token")
    manager = RoleManager(DummyStorage())

    forged = {
        "user": manager.user,
        "host": manager.host,
        "role": "collector",
        "assigned_at": "2026-01-01T00:00:00",
        "assigned_by": "attacker",
    }
    canonical = manager._canonical_role_payload(forged)
    forged["signature"] = hmac.new(b"wrong-token", canonical, hashlib.sha256).hexdigest()
    _write_role_file(manager, forged)

    manager2 = RoleManager(DummyStorage())
    assert manager2.get_current_role() == UserRole.REVIEWER


def test_privileged_role_cannot_persist_without_token(monkeypatch):
    monkeypatch.delenv("ISEC_ROLE_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("ISEC_ROLE_ADMIN_TOKEN_FILE", raising=False)
    manager = RoleManager(DummyStorage())

    # Default safe role is fine without a token...
    assert manager.get_current_role() == UserRole.REVIEWER
    # ...but a privileged role cannot be authenticated, so it must not persist.
    assert manager.set_role(UserRole.EXPORTER, assigned_by="x") is False
    assert manager.get_current_role() == UserRole.REVIEWER


def test_tampered_role_emits_integrity_audit_event(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "secret-token")
    manager = RoleManager(DummyStorage())

    forged = {
        "user": manager.user,
        "host": manager.host,
        "role": "exporter",
        "assigned_at": "2026-01-01T00:00:00",
        "assigned_by": "attacker",
    }
    _write_role_file(manager, forged)

    audit_storage = DummyStorage()
    RoleManager(audit_storage)
    failures = [e for e in audit_storage.events if e["evidence_type"] == "role_integrity_failure"]
    assert len(failures) >= 1
    assert failures[0]["data"]["rejected_role"] == "exporter"
