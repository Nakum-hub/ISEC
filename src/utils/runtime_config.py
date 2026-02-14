"""
Runtime environment configuration and production safety validation.
"""
from dataclasses import dataclass
import os

from src.utils.paths import get_state_dir


ALLOWED_ENVS = {"development", "testing", "production"}
PRODUCTION_FORBIDDEN_ENV_VARS = (
    "ISEC_ALLOW_UNLICENSED",
    "ISEC_DEV_ALLOW_UNLICENSED",
    "ISEC_ROLE_AUTH_BYPASS",
    "ISEC_LICENSE_PUBLIC_KEY",
)


@dataclass(frozen=True)
class RuntimeConfig:
    environment: str

    @property
    def is_production(self):
        return self.environment == "production"


def resolve_environment(value=None):
    candidate = str(value or os.environ.get("ISEC_ENV", "development")).strip().lower()
    if candidate not in ALLOWED_ENVS:
        raise ValueError(
            f"Invalid ISEC_ENV '{candidate}'. Allowed values: development, testing, production."
        )
    return candidate


def build_runtime_config(value=None):
    environment = resolve_environment(value=value)
    os.environ["ISEC_ENV"] = environment
    return RuntimeConfig(environment=environment)


def _resolve_license_path(args):
    explicit = getattr(args, "license_file", None)
    if explicit:
        return explicit

    env_license = os.environ.get("ISEC_LICENSE_FILE")
    if env_license:
        return env_license

    state_license = os.path.join(get_state_dir(), "license.json")
    if os.path.exists(state_license):
        return state_license

    return os.path.join(os.getcwd(), "license.json")


def validate_runtime_config(args, config):
    """
    Return a list of production safety failures. Empty list means valid.
    """
    if not config.is_production:
        return []

    failures = []

    for env_name in PRODUCTION_FORBIDDEN_ENV_VARS:
        raw = os.environ.get(env_name)
        if raw and str(raw).strip():
            failures.append(
                f"Insecure setting detected: {env_name} must not be set in production."
            )

    log_level = str(getattr(args, "log_level", "INFO")).strip().upper()
    if log_level in {"DEBUG", "TRACE", "NOTSET"}:
        failures.append("Insecure setting detected: DEBUG/TRACE logging is not allowed in production.")

    if getattr(args, "no_log_file", False):
        failures.append("Insecure setting detected: --no-log-file is not allowed in production.")

    license_path = _resolve_license_path(args)
    if not os.path.exists(license_path):
        failures.append(
            f"Production startup blocked: license file not found at '{license_path}'."
        )

    return failures


def is_production_runtime():
    try:
        return resolve_environment() == "production"
    except ValueError:
        return False
