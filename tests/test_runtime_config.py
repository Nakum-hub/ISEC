from types import SimpleNamespace

from src.utils.runtime_config import build_runtime_config, validate_runtime_config


def _args(**kwargs):
    defaults = {
        "license_file": None,
        "log_level": "INFO",
        "no_log_file": False,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_runtime_config_production_rejects_bypass_env(monkeypatch, tmp_path):
    license_path = tmp_path / "license.json"
    license_path.write_text('{"payload":{},"signature":"00"}', encoding="utf-8")
    monkeypatch.setenv("ISEC_ALLOW_UNLICENSED", "1")

    cfg = build_runtime_config("production")
    failures = validate_runtime_config(_args(license_file=str(license_path)), cfg)
    assert any("ISEC_ALLOW_UNLICENSED" in msg for msg in failures)


def test_runtime_config_production_rejects_inline_public_key_override(monkeypatch, tmp_path):
    license_path = tmp_path / "license.json"
    license_path.write_text('{"payload":{},"signature":"00"}', encoding="utf-8")
    monkeypatch.setenv("ISEC_LICENSE_PUBLIC_KEY", "attacker-key")

    cfg = build_runtime_config("production")
    failures = validate_runtime_config(_args(license_file=str(license_path)), cfg)
    assert any("ISEC_LICENSE_PUBLIC_KEY" in msg for msg in failures)


def test_runtime_config_production_rejects_debug_and_no_log(monkeypatch, tmp_path):
    license_path = tmp_path / "license.json"
    license_path.write_text('{"payload":{},"signature":"00"}', encoding="utf-8")
    monkeypatch.delenv("ISEC_ALLOW_UNLICENSED", raising=False)
    monkeypatch.delenv("ISEC_DEV_ALLOW_UNLICENSED", raising=False)
    monkeypatch.delenv("ISEC_ROLE_AUTH_BYPASS", raising=False)

    cfg = build_runtime_config("production")
    failures = validate_runtime_config(
        _args(license_file=str(license_path), log_level="DEBUG", no_log_file=True),
        cfg,
    )
    assert any("DEBUG" in msg for msg in failures)
    assert any("--no-log-file" in msg for msg in failures)


def test_runtime_config_production_allows_secure_settings(monkeypatch, tmp_path):
    license_path = tmp_path / "license.json"
    license_path.write_text('{"payload":{},"signature":"00"}', encoding="utf-8")
    monkeypatch.delenv("ISEC_ALLOW_UNLICENSED", raising=False)
    monkeypatch.delenv("ISEC_DEV_ALLOW_UNLICENSED", raising=False)
    monkeypatch.delenv("ISEC_ROLE_AUTH_BYPASS", raising=False)

    cfg = build_runtime_config("production")
    failures = validate_runtime_config(_args(license_file=str(license_path), log_level="INFO"), cfg)
    assert failures == []
