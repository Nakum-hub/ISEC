from src.utils.role_manager import RoleManager


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


def _role_auth_events(storage):
    return [e for e in storage.events if e["evidence_type"] == "role_auth_attempt"]


def test_role_authorization_bruteforce_lock(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "super-secret-token")
    monkeypatch.setenv("ISEC_ROLE_AUTH_SESSION_ID", "test-session-lock")
    storage = DummyStorage()
    manager = RoleManager(storage)

    for _ in range(4):
        ok, message = manager.authorize_role_change("wrong-token")
        assert ok is False
        assert "retry in" in message.lower()

    ok, message = manager.authorize_role_change("wrong-token")
    assert ok is False
    assert "locked" in message.lower()

    ok, message = manager.authorize_role_change("super-secret-token")
    assert ok is False
    assert "locked" in message.lower()

    events = _role_auth_events(storage)
    assert len(events) >= 6


def test_role_authorization_success_resets_failures(monkeypatch):
    monkeypatch.setenv("ISEC_ROLE_ADMIN_TOKEN", "super-secret-token")
    monkeypatch.setenv("ISEC_ROLE_AUTH_SESSION_ID", "test-session-reset")
    storage = DummyStorage()
    manager = RoleManager(storage)

    ok, _ = manager.authorize_role_change("wrong-token")
    assert ok is False
    ok, _ = manager.authorize_role_change("wrong-token")
    assert ok is False

    # Clear temporary lock in test to avoid waiting for wall clock.
    manager.locked_until = None
    ok, message = manager.authorize_role_change("super-secret-token")
    assert ok is True
    assert "authorized" in message.lower()
    assert manager.failed_attempts == 0
