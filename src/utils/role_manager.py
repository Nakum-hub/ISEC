"""
Role Manager Module
Implements role-based access control for the ISEC application

Security note (V1 hardening):
    The encrypted role file is encrypted with a key derived from PUBLIC system
    information (username, hostname, platform). That provides confidentiality of
    convenience only -- it does NOT provide authenticity, because anyone who
    knows the username/hostname can reproduce the key and forge a role file that
    grants themselves a privileged role (privilege escalation).

    To close that hole, any role above the safe default (REVIEWER) must now be
    authenticated with an HMAC-SHA256 tag computed over the role payload using
    the role admin token as the key -- the same secret already required to
    authorize a role change. On load, a privileged role is only honored if its
    HMAC verifies against the configured admin token. Unsigned, tampered, or
    unverifiable privileged roles are rejected and the user falls back to the
    least-privileged REVIEWER role.
"""
import json
import os
import getpass
import platform
import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from enum import Enum
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.utils.paths import get_project_root, get_state_file

class UserRole(Enum):
    COLLECTOR = "collector"
    REVIEWER = "reviewer"
    EXPORTER = "exporter"


# Roles that carry privileges beyond the safe read-only default. Persisting or
# loading any of these requires an authentic HMAC signature (see module docstring).
PRIVILEGED_ROLES = frozenset({UserRole.COLLECTOR, UserRole.EXPORTER})


class RoleManager:
    MAX_FAILED_ATTEMPTS = 5
    BASE_BACKOFF_SECONDS = 1

    def __init__(self, storage):
        self.storage = storage
        self.user = getpass.getuser()
        self.host = platform.node()
        self.role_file = get_state_file("user_roles.json")
        self.encrypted_role_file = get_state_file("user_roles.encrypted")
        self.legacy_encrypted_role_file = os.path.join(get_project_root(), "user_roles.encrypted")
        self.auth_state_file = get_state_file("role_auth_state.json", subdir="security")
        self.auth_session_id = os.environ.get("ISEC_ROLE_AUTH_SESSION_ID") or f"cli-{os.getpid()}"
        self.auth_lock = threading.Lock()
        self.failed_attempts = 0
        self.locked_until = None
        self.session_locked = False
        self._load_auth_state()

        # Initialize with default role if no role is set
        self.current_role = self._load_user_role()
        if not self.current_role:
            self.current_role = UserRole.REVIEWER
            self.set_role(self.current_role)
    
    def _derive_key_from_system_info(self):
        """Derive encryption key from system-specific information.

        NOTE: This key is for confidentiality-at-rest convenience only. It is
        derived from public system info and therefore must NOT be relied on for
        authenticity. Authenticity of privileged roles is enforced separately via
        an HMAC tag keyed by the role admin token (see _sign_role_payload).
        """
        # Create a password based on system information
        system_info = f"{self.user}@{self.host}-{platform.system()}-{platform.machine()}"
        password = system_info.encode()
        
        # Use a fixed salt (this is acceptable for local-only encryption)
        salt = b'isek_rol_salt_2023'  # Fixed salt for consistency on same machine
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _get_role_admin_token(self):
        """Load the admin token used to authorize role changes."""
        env_token = os.environ.get("ISEC_ROLE_ADMIN_TOKEN")
        if env_token:
            token = env_token.strip()
            if token:
                return token, "env"

        token_file = os.environ.get("ISEC_ROLE_ADMIN_TOKEN_FILE") or get_state_file("role_admin_token.txt", subdir="keys")
        if token_file and os.path.exists(token_file):
            try:
                with open(token_file, "r", encoding="utf-8") as f:
                    token = f.read().strip()
                    if token:
                        return token, "file"
            except Exception:
                return None, "invalid_file"

        return None, "missing"

    def _role_signing_secret(self):
        """Return the secret (bytes) used to HMAC-authenticate role state, or None."""
        token, _ = self._get_role_admin_token()
        if not token:
            return None
        return token.encode("utf-8")

    def _canonical_role_payload(self, role_data):
        """Deterministic byte serialization of the authenticated role fields.

        The signature field itself is intentionally excluded so signing and
        verification operate over identical bytes.
        """
        payload = {
            key: role_data.get(key)
            for key in ("user", "host", "role", "assigned_at", "assigned_by")
            if key in role_data
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _sign_role_payload(self, role_data):
        """Compute an HMAC-SHA256 tag over the role payload, or None if no secret."""
        secret = self._role_signing_secret()
        if not secret:
            return None
        return hmac.new(secret, self._canonical_role_payload(role_data), hashlib.sha256).hexdigest()

    def _verify_role_payload(self, role_data, signature):
        """Constant-time verification of a role payload's HMAC tag."""
        if not signature or not isinstance(signature, str):
            return False
        secret = self._role_signing_secret()
        if not secret:
            return False
        expected = hmac.new(secret, self._canonical_role_payload(role_data), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _audit_role_integrity_failure(self, reason, role_value):
        """Best-effort audit record when a stored role fails integrity checks."""
        try:
            self.storage.store_evidence(
                evidence_type="role_integrity_failure",
                data={
                    "reason": reason,
                    "rejected_role": role_value,
                    "user": self.user,
                    "host": self.host,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                },
                actor=self.user
            )
        except Exception:
            pass

    def _parse_datetime(self, value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed
        except Exception:
            return None

    def _load_auth_state(self):
        try:
            if not os.path.exists(self.auth_state_file):
                return
            with open(self.auth_state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
            if not isinstance(state, dict):
                return
            sessions = state.get("sessions", {})
            if not isinstance(sessions, dict):
                return
            session_state = sessions.get(self.auth_session_id, {})
            if not isinstance(session_state, dict):
                return

            self.failed_attempts = max(0, int(session_state.get("failed_attempts", 0)))
            self.session_locked = bool(session_state.get("session_locked", False))
            self.locked_until = self._parse_datetime(session_state.get("locked_until"))
        except Exception:
            self.failed_attempts = 0
            self.session_locked = False
            self.locked_until = None

    def _save_auth_state(self):
        os.makedirs(os.path.dirname(self.auth_state_file), exist_ok=True)
        state = {}
        try:
            if os.path.exists(self.auth_state_file):
                with open(self.auth_state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)
                    if not isinstance(state, dict):
                        state = {}
        except Exception:
            state = {}

        sessions = state.get("sessions")
        if not isinstance(sessions, dict):
            sessions = {}

        sessions[self.auth_session_id] = {
            "failed_attempts": self.failed_attempts,
            "session_locked": self.session_locked,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        state["sessions"] = sessions

        try:
            with open(self.auth_state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    def _seconds_until_unlock(self):
        if not self.locked_until:
            return 0
        remaining = (self.locked_until - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))

    def _is_temporarily_locked(self):
        return self._seconds_until_unlock() > 0

    def _audit_role_auth_attempt(self, outcome, reason, provided_token=None):
        payload = {
            "outcome": outcome,
            "reason": reason,
            "session_id": self.auth_session_id,
            "failed_attempts": self.failed_attempts,
            "max_failed_attempts": self.MAX_FAILED_ATTEMPTS,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "session_locked": self.session_locked,
            "provided_token": bool((provided_token or "").strip()),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self.storage.store_evidence(
                evidence_type="role_auth_attempt",
                data=payload,
                actor=self.user
            )
        except Exception:
            pass

    def _register_failure(self, reason, provided_token=None, public_message=None):
        self.failed_attempts += 1
        self.locked_until = None
        self.session_locked = False

        if self.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
            self.session_locked = True
            self._save_auth_state()
            self._audit_role_auth_attempt("denied", "locked_after_failures", provided_token=provided_token)
            return False, "Role change locked after repeated failed authentication attempts. Restart the application to retry."

        backoff_seconds = self.BASE_BACKOFF_SECONDS * (2 ** (self.failed_attempts - 1))
        self.locked_until = datetime.now(timezone.utc) + timedelta(seconds=backoff_seconds)
        self._save_auth_state()
        self._audit_role_auth_attempt("denied", reason, provided_token=provided_token)
        message = public_message or "Role change blocked: invalid admin token."
        return False, f"{message} Retry in {backoff_seconds} second(s)."

    def _register_success(self, provided_token=None):
        self.failed_attempts = 0
        self.locked_until = None
        self.session_locked = False
        self._save_auth_state()
        self._audit_role_auth_attempt("authorized", "token_valid", provided_token=provided_token)

    def get_role_auth_status(self):
        """Return role-change authentication status for UI/API consumers."""
        token, source = self._get_role_admin_token()
        return {
            "required": True,
            "configured": bool(token),
            "source": source,
            "failedAttempts": self.failed_attempts,
            "maxFailedAttempts": self.MAX_FAILED_ATTEMPTS,
            "temporarilyLocked": self._is_temporarily_locked(),
            "lockRemainingSeconds": self._seconds_until_unlock(),
            "sessionLocked": self.session_locked
        }

    def authorize_role_change(self, provided_token):
        """Validate token-based authorization for privileged role changes."""
        with self.auth_lock:
            if self.session_locked:
                self._audit_role_auth_attempt("denied", "session_locked", provided_token=provided_token)
                return False, "Role change locked for this application session after repeated failed attempts. Restart to retry."

            if self._is_temporarily_locked():
                return self._register_failure(
                    "temporary_lock_violation",
                    provided_token=provided_token,
                    public_message="Role change temporarily locked."
                )

            configured_token, _ = self._get_role_admin_token()
            if not configured_token:
                self._audit_role_auth_attempt("denied", "token_not_configured", provided_token=provided_token)
                return False, "Role change blocked: admin token not configured. Set ISEC_ROLE_ADMIN_TOKEN or ISEC_ROLE_ADMIN_TOKEN_FILE."

            candidate = (provided_token or "").strip()
            if not candidate:
                return self._register_failure(
                    "missing_token",
                    provided_token=provided_token,
                    public_message="Role change blocked: admin token is required."
                )

            if not hmac.compare_digest(configured_token, candidate):
                return self._register_failure("invalid_token", provided_token=provided_token)

            self._register_success(provided_token=provided_token)
            return True, "Role change authorized."

    def set_role(self, role, assigned_by='system'):
        """Set the current user's role"""
        if not isinstance(role, UserRole):
            raise ValueError("Role must be a valid UserRole enum value")
        
        role_data = {
            'user': self.user,
            'host': self.host,
            'role': role.value,
            'assigned_at': datetime.now().isoformat(),
            'assigned_by': assigned_by
        }

        # Authenticate the role payload so it cannot be forged offline. A
        # privileged role with no signing secret available cannot be persisted
        # authentically and must not be written.
        signature = self._sign_role_payload(role_data)
        if signature:
            role_data['signature'] = signature
        elif role in PRIVILEGED_ROLES:
            print("Error setting role: cannot persist a privileged role without an admin token configured.")
            return False
        
        try:
            # Encrypt the role data
            key = self._derive_key_from_system_info()
            fernet = Fernet(key)
            
            encrypted_data = fernet.encrypt(json.dumps(role_data).encode())
            
            # Save encrypted role data
            wrote = False
            try:
                with open(self.encrypted_role_file, 'wb') as f:
                    f.write(encrypted_data)
                wrote = True
            except Exception:
                wrote = False

            if not wrote:
                with open(self.legacy_encrypted_role_file, 'wb') as f:
                    f.write(encrypted_data)
            
            # Also save to database for audit trail - fix: remove 'notes' parameter
            self.storage.store_evidence(
                evidence_type="role_assignment",
                data=role_data,
                actor=self.user
            )
            
            self.current_role = role
            return True
            
        except Exception as e:
            print(f"Error setting role: {e}")
            return False
    
    def _load_user_role(self):
        """Load the current user's role from encrypted storage.

        Privileged roles are only honored when accompanied by a valid HMAC tag
        keyed by the configured admin token. Any privileged role that is
        unsigned, tampered, or unverifiable is rejected (return None) so the
        caller falls back to the least-privileged REVIEWER role.
        """
        try:
            target_file = None
            if os.path.exists(self.encrypted_role_file):
                target_file = self.encrypted_role_file
            elif os.path.exists(self.legacy_encrypted_role_file):
                target_file = self.legacy_encrypted_role_file

            if not target_file:
                return None

            # Read encrypted role data
            with open(target_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt using system-derived key
            key = self._derive_key_from_system_info()
            fernet = Fernet(key)
            
            decrypted_data = fernet.decrypt(encrypted_data)
            role_data = json.loads(decrypted_data.decode())
            
            # Verify this role belongs to current user and host
            if not (role_data.get('user') == self.user and role_data.get('host') == self.host):
                return None

            loaded_role = UserRole(role_data.get('role'))

            # The safe default role grants no privileges, so it never needs a
            # signature and can always be honored.
            if loaded_role not in PRIVILEGED_ROLES:
                return loaded_role

            # Privileged roles must be authenticated. Reject anything we cannot
            # cryptographically verify and deny the escalation.
            if self._verify_role_payload(role_data, role_data.get('signature')):
                return loaded_role

            print("Warning: stored role failed integrity verification; defaulting to REVIEWER.")
            self._audit_role_integrity_failure("hmac_verification_failed", role_data.get('role'))
            return None
                
        except Exception as e:
            print(f"Error loading role: {e}")
            return None
    
    def has_permission(self, action):
        """Check if current role has permission for the specified action"""
        if not self.current_role:
            return False  # No role means no permissions
        
        permissions = {
            UserRole.COLLECTOR: {
                'collect': True,
                'view': True,
                'export': False,
                'modify': True
            },
            UserRole.REVIEWER: {
                'collect': False,
                'view': True,
                'export': False,
                'modify': False
            },
            UserRole.EXPORTER: {
                'collect': False,
                'view': True,  # Exporter needs to view data to export it
                'export': True,
                'modify': False
            }
        }
        
        role_permissions = permissions.get(self.current_role, {})
        return role_permissions.get(action, False)
    
    def get_current_role(self):
        """Get the current user's role"""
        return self.current_role
    
    def get_role_description(self):
        """Get a description of the current role"""
        descriptions = {
            UserRole.COLLECTOR: {
                'name': 'Collector',
                'description': 'Can collect evidence, view data, and modify evidence',
                'permissions': ['collect', 'view', 'modify']
            },
            UserRole.REVIEWER: {
                'name': 'Reviewer',
                'description': 'Can only view evidence data',
                'permissions': ['view']
            },
            UserRole.EXPORTER: {
                'name': 'Exporter', 
                'description': 'Can view and export evidence data',
                'permissions': ['view', 'export']
            }
        }
        
        role_info = descriptions.get(self.current_role, {})
        return {
            'role': self.current_role.value if self.current_role else 'unassigned',
            'name': role_info.get('name', 'Unassigned'),
            'description': role_info.get('description', 'No role assigned'),
            'permissions': role_info.get('permissions', [])
        }


# Global instance for convenience
role_manager_instance = None


def get_role_manager(storage):
    """Get the role manager instance"""
    global role_manager_instance
    if role_manager_instance is None:
        role_manager_instance = RoleManager(storage)
    return role_manager_instance
