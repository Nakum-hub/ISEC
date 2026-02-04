"""
Role Manager Module
Implements role-based access control for the ISEC application
"""
import json
import os
import getpass
import platform
import base64
from datetime import datetime
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class UserRole(Enum):
    COLLECTOR = "collector"
    REVIEWER = "reviewer"
    EXPORTER = "exporter"


class RoleManager:
    def __init__(self, storage, default_role=None):
        self.storage = storage
        self.user = getpass.getuser()
        self.host = platform.node()
        self.role_file = os.path.join(os.path.dirname(__file__), "..", "..", "user_roles.json")
        self.encrypted_role_file = os.path.join(os.path.dirname(__file__), "..", "..", "user_roles.encrypted")
        
        # Initialize with default role if no role is set
        self.current_role = self._load_user_role()
        if not self.current_role:
            # Use provided default role if valid, otherwise fall back to Reviewer
            if default_role is not None and isinstance(default_role, UserRole):
                self.current_role = default_role
            else:
                self.current_role = UserRole.REVIEWER  # Default role
            self.set_role(self.current_role)
    
    def _derive_key_from_system_info(self):
        """Derive encryption key from system-specific information"""
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
    
    def set_role(self, role):
        """Set the current user's role"""
        if not isinstance(role, UserRole):
            raise ValueError("Role must be a valid UserRole enum value")
        
        role_data = {
            'user': self.user,
            'host': self.host,
            'role': role.value,
            'assigned_at': datetime.now().isoformat(),
            'assigned_by': 'system'  # In a real system, this could be admin user
        }
        
        try:
            # Encrypt the role data
            key = self._derive_key_from_system_info()
            fernet = Fernet(key)
            
            encrypted_data = fernet.encrypt(json.dumps(role_data).encode())
            
            # Save encrypted role data
            with open(self.encrypted_role_file, 'wb') as f:
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
        """Load the current user's role from encrypted storage"""
        try:
            if not os.path.exists(self.encrypted_role_file):
                return None
            
            # Read encrypted role data
            with open(self.encrypted_role_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt using system-derived key
            key = self._derive_key_from_system_info()
            fernet = Fernet(key)
            
            decrypted_data = fernet.decrypt(encrypted_data)
            role_data = json.loads(decrypted_data.decode())
            
            # Verify this role belongs to current user and host
            if role_data.get('user') == self.user and role_data.get('host') == self.host:
                return UserRole(role_data.get('role'))
            else:
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


def get_role_manager(storage, default_role=None):
    """Get the role manager instance"""
    global role_manager_instance
    if role_manager_instance is None:
        role_manager_instance = RoleManager(storage, default_role=default_role)
    return role_manager_instance