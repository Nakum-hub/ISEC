"""
License Manager Module
Verifies offline license files using a public key signature and optional node-locked constraints.

Trust anchor:
    The embedded PUBLIC_KEY_PEM below is the authoritative license-verification
    public key. It is a PUBLIC key and is safe to ship in source and in packaged
    builds. Embedding it ensures license verification still works when the loose
    keys/license_public_key.pem file is not bundled (e.g. inside a PyInstaller
    one-file build). For development, ISEC_LICENSE_PUBLIC_KEY /
    ISEC_LICENSE_PUBLIC_KEY_FILE may override it; in production (ISEC_ENV=production)
    the env override is ignored.
"""
import base64
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.utils.paths import get_state_dir

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlPUmRti8uBg7yPyYD9hzhBEI77TaWUUDa3PGg797Jw4=
-----END PUBLIC KEY-----"""


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load_public_key_pem() -> Optional[str]:
    is_production = str(os.environ.get("ISEC_ENV", "development")).strip().lower() == "production"

    env_key = None if is_production else os.environ.get("ISEC_LICENSE_PUBLIC_KEY")
    if env_key:
        return env_key

    env_key_file = os.environ.get("ISEC_LICENSE_PUBLIC_KEY_FILE")
    if env_key_file and os.path.exists(env_key_file):
        try:
            return open(env_key_file, "r", encoding="utf-8").read()
        except Exception:
            return None

    default_key_path = os.path.join(_project_root(), "keys", "license_public_key.pem")
    if os.path.exists(default_key_path):
        try:
            return open(default_key_path, "r", encoding="utf-8").read()
        except Exception:
            return None

    state_key_path = os.path.join(get_state_dir(), "keys", "license_public_key.pem")
    if os.path.exists(state_key_path):
        try:
            return open(state_key_path, "r", encoding="utf-8").read()
        except Exception:
            return None

    if "REPLACE_WITH_YOUR_PUBLIC_KEY" in PUBLIC_KEY_PEM:
        return None

    return PUBLIC_KEY_PEM


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        safe_value = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(safe_value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _canonical_payload(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _parse_signature(signature: str) -> Optional[bytes]:
    if not signature:
        return None
    sig = signature.strip()
    try:
        if all(c in "0123456789abcdefABCDEF" for c in sig) and len(sig) % 2 == 0:
            return bytes.fromhex(sig)
    except Exception:
        pass
    try:
        return base64.b64decode(sig.encode("utf-8"))
    except Exception:
        return None


def get_system_fingerprint() -> Tuple[str, Dict[str, str]]:
    system_info = {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }
    payload = json.dumps(system_info, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return fingerprint, system_info


def _normalize_features(features: Any) -> List[str]:
    if not isinstance(features, (list, tuple, set)):
        return []

    normalized = []
    seen = set()
    for item in features:
        if not isinstance(item, str):
            continue
        feature = item.strip().lower()
        if not feature or feature in seen:
            continue
        seen.add(feature)
        normalized.append(feature)
    return normalized


class LicenseManager:
    def __init__(self, license_file: Optional[str] = None):
        if license_file:
            resolved = license_file
        else:
            resolved = os.environ.get("ISEC_LICENSE_FILE") or os.path.join(_project_root(), "license.json")
            if not os.path.exists(resolved):
                state_license = os.path.join(get_state_dir(), "license.json")
                if os.path.exists(state_license):
                    resolved = state_license
        self.license_file = resolved
        self.public_key_pem = _load_public_key_pem()
        self.fingerprint, self.system_info = get_system_fingerprint()

    def _load_license(self) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
        if not self.license_file or not os.path.exists(self.license_file):
            return None, None, "License file not found."
        try:
            with open(self.license_file, "r", encoding="utf-8") as f:
                license_data = json.load(f)
        except Exception as exc:
            return None, None, f"Unable to read license file: {exc}"

        if "payload" in license_data and "signature" in license_data:
            payload = license_data.get("payload")
            signature = license_data.get("signature")
        else:
            payload = {k: v for k, v in license_data.items() if k != "signature"}
            signature = license_data.get("signature")

        if not isinstance(payload, dict):
            return None, None, "License payload is invalid."

        return payload, signature, None

    def _verify_signature(self, payload: Dict[str, Any], signature: str) -> Tuple[bool, str]:
        if not self.public_key_pem:
            return False, "License public key not configured."
        signature_bytes = _parse_signature(signature)
        if not signature_bytes:
            return False, "License signature is missing or invalid."

        try:
            public_key = serialization.load_pem_public_key(self.public_key_pem.encode("utf-8"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False, "License public key must be Ed25519."
            public_key.verify(signature_bytes, _canonical_payload(payload))
        except Exception:
            return False, "License signature verification failed."

        return True, "Signature verified."

    def _verify_constraints(self, payload: Dict[str, Any]) -> Tuple[bool, str]:
        allowed_hosts = payload.get("allowed_hosts") or []
        allowed_fingerprints = payload.get("allowed_fingerprints") or []
        machine_fingerprint = payload.get("machine_fingerprint")

        if machine_fingerprint and machine_fingerprint != self.fingerprint:
            return False, "License is not valid for this machine."

        if allowed_fingerprints and self.fingerprint not in allowed_fingerprints:
            return False, "License is not valid for this device."

        if allowed_hosts and platform.node() not in allowed_hosts:
            return False, "License is not valid for this host."

        not_before = _parse_datetime(payload.get("not_before"))
        expires_at = _parse_datetime(payload.get("expires_at"))
        now = datetime.now(timezone.utc)

        if not_before and now < not_before:
            return False, "License is not active yet."

        if expires_at and now > expires_at:
            return False, "License has expired."

        return True, "License constraints satisfied."

    def get_status(self) -> Dict[str, Any]:
        payload, signature, error = self._load_license()
        if error:
            return {
                "valid": False,
                "status": "missing",
                "message": error,
                "plan": None,
                "features": [],
                "expires_at": None,
                "license_id": None,
                "customer": None,
                "system_fingerprint": self.fingerprint,
            }

        signature_ok, signature_message = self._verify_signature(payload, signature)
        if not signature_ok:
            features = _normalize_features(payload.get("features", []))
            return {
                "valid": False,
                "status": "invalid_signature",
                "message": signature_message,
                "plan": payload.get("plan"),
                "features": features,
                "expires_at": payload.get("expires_at"),
                "license_id": payload.get("license_id"),
                "customer": payload.get("customer"),
                "system_fingerprint": self.fingerprint,
            }

        constraints_ok, constraints_message = self._verify_constraints(payload)
        if not constraints_ok:
            features = _normalize_features(payload.get("features", []))
            return {
                "valid": False,
                "status": "invalid_constraints",
                "message": constraints_message,
                "plan": payload.get("plan"),
                "features": features,
                "expires_at": payload.get("expires_at"),
                "license_id": payload.get("license_id"),
                "customer": payload.get("customer"),
                "system_fingerprint": self.fingerprint,
            }

        features = _normalize_features(payload.get("features", []))
        return {
            "valid": True,
            "status": "valid",
            "message": "License verified.",
            "plan": payload.get("plan"),
            "features": features,
            "expires_at": payload.get("expires_at"),
            "license_id": payload.get("license_id"),
            "customer": payload.get("customer"),
            "system_fingerprint": self.fingerprint,
        }

    def allows(self, action: str) -> bool:
        status = self.get_status()
        if not status.get("valid"):
            return False
        features = status.get("features") or []
        if "all" in features:
            return True
        if not action:
            return False
        return str(action).strip().lower() in features
