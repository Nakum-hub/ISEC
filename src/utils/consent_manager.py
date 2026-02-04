"""
Consent Manager Module
Implements consent management with status tracking for the ISEC application
"""
import json
import os
import hashlib
from datetime import datetime, timedelta
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass
import platform


class ConsentStatus(Enum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ConsentManager:
    def __init__(self, storage):
        self.storage = storage  # Pass the database storage object
        self.user = getpass.getuser()
        self.host = platform.node()
        self.consent_file = os.path.join(os.path.dirname(__file__), "..", "..", "consents.json")
        self.encrypted_consent_file = os.path.join(os.path.dirname(__file__), "..", "..", "consents.encrypted")
        
        # Encryption key derived from system info
        self.fernet = Fernet(self._derive_encryption_key())

        # Initialize with default consent data if no consent is set
        self.consents = self._load_consents()
        
    def _derive_encryption_key(self):
        """Derive encryption key from system-specific information"""
        # Create a password based on system information
        system_info = f"{self.user}@{self.host}-{platform.system()}-{platform.machine()}"
        password = system_info.encode()
        
        # Use a fixed salt
        salt = b'isek_con_sal_2023'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _load_consents(self):
        """Load consents from encrypted storage"""
        try:
            if not os.path.exists(self.encrypted_consent_file):
                return {}
            
            # Read encrypted consent data
            with open(self.encrypted_consent_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt using system-derived key
            decrypted_data = self.fernet.decrypt(encrypted_data)
            consent_data = json.loads(decrypted_data.decode())
            
            return consent_data
            
        except Exception as e:
            print(f"Error loading consents: {e}")
            return {}
    
    def _save_consents(self):
        """Save consents to encrypted storage"""
        try:
            # Encrypt the consent data
            encrypted_data = self.fernet.encrypt(json.dumps(self.consents).encode())
            
            # Save encrypted consent data
            with open(self.encrypted_consent_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Also save to database for audit trail
            self.storage.store_evidence(
                evidence_type="consent_record",
                data=self.consents,
                actor=self.user
            )
            
            return True
            
        except Exception as e:
            print(f"Error saving consents: {e}")
            return False
    
    def request_consent(self, collection_type, details=None):
        """Request consent for a specific type of data collection"""
        consent_record = {
            'type': collection_type,
            'status': ConsentStatus.PENDING.value,
            'requested_at': datetime.now().isoformat(),
            'requested_by': self.user,
            'details': details or {},
            'expires_at': (datetime.now() + timedelta(days=30)).isoformat()  # Consent expires in 30 days
        }
        
        self.consents[collection_type] = consent_record
        self._save_consents()
        
        return consent_record
    
    def grant_consent(self, collection_type, details=None):
        """Grant consent for a specific type of data collection"""
        if collection_type in self.consents:
            # Update existing record
            self.consents[collection_type].update({
                'status': ConsentStatus.GRANTED.value,
                'granted_at': datetime.now().isoformat(),
                'granted_by': self.user,
                'details': details or self.consents[collection_type]['details']
            })
        else:
            # Create new record
            self.consents[collection_type] = {
                'type': collection_type,
                'status': ConsentStatus.GRANTED.value,
                'granted_at': datetime.now().isoformat(),
                'granted_by': self.user,
                'details': details or {},
                'expires_at': (datetime.now() + timedelta(days=30)).isoformat()
            }
        
        self._save_consents()
        return True
    
    def deny_consent(self, collection_type, reason=None):
        """Deny consent for a specific type of data collection"""
        if collection_type in self.consents:
            # Update existing record
            self.consents[collection_type].update({
                'status': ConsentStatus.DENIED.value,
                'denied_at': datetime.now().isoformat(),
                'denied_by': self.user,
                'reason': reason or 'No reason provided'
            })
        else:
            # Create new record
            self.consents[collection_type] = {
                'type': collection_type,
                'status': ConsentStatus.DENIED.value,
                'denied_at': datetime.now().isoformat(),
                'denied_by': self.user,
                'reason': reason or 'No reason provided',
                'details': {}
            }
        
        self._save_consents()
        return True
    
    def check_consent_status(self, collection_type):
        """Check the consent status for a specific type of data collection"""
        if collection_type not in self.consents:
            return {
                'status': 'PENDING',
                'message': 'Consent not yet requested',
                'details': {}
            }
        
        consent_record = self.consents[collection_type]
        status = consent_record['status']
        
        # Check if consent has expired
        if status == ConsentStatus.GRANTED.value:
            expires_at = datetime.fromisoformat(consent_record['expires_at'])
            if datetime.now() > expires_at:
                self.consents[collection_type]['status'] = ConsentStatus.EXPIRED.value
                self._save_consents()
                return {
                    'status': 'EXPIRED',
                    'message': 'Consent has expired',
                    'details': consent_record.get('details', {})
                }
        
        return {
            'status': status,
            'message': self._get_status_message(status, consent_record),
            'details': consent_record.get('details', {})
        }
    
    def _get_status_message(self, status, consent_record):
        """Get a human-readable message for the consent status"""
        messages = {
            ConsentStatus.GRANTED.value: 'Consent granted',
            ConsentStatus.DENIED.value: 'Consent denied',
            ConsentStatus.PENDING.value: 'Consent pending',
            ConsentStatus.EXPIRED.value: 'Consent expired'
        }
        
        return messages.get(status, 'Unknown status')
    
    def get_consent_summary(self):
        """Get a summary of all consent statuses"""
        summary = {}
        for collection_type, consent_record in self.consents.items():
            status = consent_record['status']
            
            # Check expiration for granted consents
            if status == ConsentStatus.GRANTED.value:
                expires_at = datetime.fromisoformat(consent_record['expires_at'])
                if datetime.now() > expires_at:
                    self.consents[collection_type]['status'] = ConsentStatus.EXPIRED.value
                    status = ConsentStatus.EXPIRED.value
                    self._save_consents()
            
            summary[collection_type] = {
                'status': status,
                'message': self._get_status_message(status, consent_record),
                'timestamp': consent_record.get('granted_at') or consent_record.get('requested_at') or consent_record.get('denied_at', 'Unknown')
            }
        
        return summary


# Global instance for convenience
consent_manager_instance = None


def get_consent_manager(storage):
    """Get the consent manager instance"""
    global consent_manager_instance
    if consent_manager_instance is None:
        consent_manager_instance = ConsentManager(storage)
    return consent_manager_instance