import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_state_dir(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ISEC_STATE_DIR", str(state_dir))
    monkeypatch.delenv("ISEC_ROLE_AUTH_BYPASS", raising=False)
    monkeypatch.delenv("ISEC_ALLOW_UNLICENSED", raising=False)
    monkeypatch.delenv("ISEC_DEV_ALLOW_UNLICENSED", raising=False)
    yield


@pytest.fixture(autouse=True)
def reset_role_singleton():
    # Reset module-level singleton between tests to avoid auth state leakage.
    from src.utils import role_manager as role_manager_module

    role_manager_module.role_manager_instance = None
    yield
    role_manager_module.role_manager_instance = None


@pytest.fixture(autouse=True)
def isolate_role_manager_legacy_path(tmp_path, monkeypatch):
    # Prevent tests from reading any real legacy role file from the project root.
    from src.utils import role_manager as role_manager_module

    monkeypatch.setattr(role_manager_module, "get_project_root", lambda: str(tmp_path))
    yield
