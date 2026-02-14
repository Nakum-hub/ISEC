import json
from datetime import datetime, timedelta, timezone

import pytest

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


def test_role_manager_permissions_and_descriptions(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "token")
    storage = DummyStorage()
    manager = RoleManager(storage)

    assert manager.get_current_role() == UserRole.REVIEWER
    assert manager.has_permission("view") is True
    assert manager.has_permission("collect") is False

    assert manager.set_role(UserRole.COLLECTOR, assigned_by="admin_token") is True
    assert manager.has_permission("collect") is True
    collector_info = manager.get_role_description()
    assert collector_info["role"] == "collector"
    assert "collect" in collector_info["permissions"]

    assert manager.set_role(UserRole.EXPORTER, assigned_by="admin_token") is True
    assert manager.has_permission("export") is True
    exporter_info = manager.get_role_description()
    assert exporter_info["role"] == "exporter"

    manager.current_role = None
    assert manager.get_role_description()["role"] == "unassigned"
    assert manager.has_permission("view") is False

    with pytest.raises(ValueError):
        manager.set_role("not-a-role")


def test_role_manager_token_file_and_missing_token_paths(tmp_path, monkeypatch):
    token_file = tmp_path / "role_token.txt"
    token_file.write_text("file-token", encoding="utf-8")
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("ISEC_ROLE_ADMIN_TOKEN", raising=False)

    storage = DummyStorage()
    manager = RoleManager(storage)
    status = manager.get_role_auth_status()
    assert status["configured"] is True
    assert status["source"] == "file"

    ok, msg = manager.authorize_role_change("file-token")
    assert ok is True
    assert "authorized" in msg.lower()

    monkeypatch.delenv("ISEC_ROLE_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.delenv("ISEC_ROLE_ADMIN_TOKEN", raising=False)
    manager_no_token = RoleManager(DummyStorage())
    ok, msg = manager_no_token.authorize_role_change("anything")
    assert ok is False
    assert "not configured" in msg.lower()


def test_role_manager_loads_legacy_role_file(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "token")
    storage = DummyStorage()
    manager = RoleManager(storage)
    assert manager.set_role(UserRole.EXPORTER, assigned_by="system") is True

    encrypted_blob = open(manager.encrypted_role_file, "rb").read()
    with open(manager.legacy_encrypted_role_file, "wb") as f:
        f.write(encrypted_blob)
    # Remove modern file so load path uses legacy fallback.
    try:
        import os
        os.remove(manager.encrypted_role_file)
    except OSError:
        pass

    manager2 = RoleManager(DummyStorage())
    assert manager2.get_current_role() == UserRole.EXPORTER


def test_role_manager_auth_state_load_parse_and_temp_lock(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "token")
    monkeypatch.setenv("ISEC_ROLE_AUTH_SESSION_ID", "session-temp-lock")
    storage = DummyStorage()
    manager = RoleManager(storage)

    # Force a temporary lock and verify the temporary-lock violation path.
    manager.failed_attempts = 1
    manager.locked_until = datetime.now(timezone.utc) + timedelta(seconds=30)
    manager._save_auth_state()

    reloaded = RoleManager(DummyStorage())
    assert reloaded.failed_attempts >= 1
    assert reloaded._is_temporarily_locked() is True
    ok, msg = reloaded.authorize_role_change("token")
    assert ok is False
    assert "temporarily locked" in msg.lower()

    # Invalid datetime parsing should return None.
    assert reloaded._parse_datetime("not-a-date") is None


def test_role_manager_invalid_auth_state_file(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "token")
    monkeypatch.setenv("ISEC_ROLE_AUTH_SESSION_ID", "session-invalid-state")
    storage = DummyStorage()
    manager = RoleManager(storage)

    with open(manager.auth_state_file, "w", encoding="utf-8") as f:
        f.write("{this-is-invalid-json")

    manager2 = RoleManager(DummyStorage())
    assert manager2.failed_attempts == 0
    assert manager2.session_locked is False
