"""
Retention Engine Module
Implements evidence retention policies and automated expiry management for the ISEC application
"""
import os
import json
import sqlite3
from datetime import datetime, timedelta
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass
import platform


class RetentionPolicy(Enum):
    TEMPORARY = "temporary"      # 7 days
    SHORT_TERM = "short_term"    # 30 days
    MEDIUM_TERM = "medium_term"  # 90 days
    LONG_TERM = "long_term"      # 1 year
    PERMANENT = "permanent"      # No expiry


class RetentionEngine:
    def __init__(self, storage, policy=RetentionPolicy.MEDIUM_TERM):
        self.storage = storage  # EvidenceDatabase instance
        self.policy = policy
        self.user = getpass.getuser()
        self.host = platform.node()
        
        # Initialize retention settings
        self.retention_days = self._get_retention_days(policy)
        self.encryption_key = self._derive_encryption_key()
        self.fernet = Fernet(self.encryption_key)
        
        # Load retention settings from database
        self._load_settings()
    
    def _derive_encryption_key(self):
        """Derive encryption key from system-specific information"""
        system_info = f"{self.user}@{self.host}-{platform.system()}-{platform.machine()}"
        password = system_info.encode()
        
        # Use a fixed salt
        salt = b'isek_ret_sal_2023'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _get_retention_days(self, policy):
        """Get retention days based on policy"""
        policy_map = {
            RetentionPolicy.TEMPORARY: 7,
            RetentionPolicy.SHORT_TERM: 30,
            RetentionPolicy.MEDIUM_TERM: 90,
            RetentionPolicy.LONG_TERM: 365,
            RetentionPolicy.PERMANENT: None  # No expiry
        }
        return policy_map.get(policy, 90)  # Default to 90 days
    
    def _load_settings(self):
        """Load retention settings from database"""
        try:
            # Try to get retention days from database
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT value FROM metadata WHERE key = 'retention_policy'")
            row = cursor.fetchone()
            if row:
                try:
                    settings = json.loads(row[0])
                    self.policy = RetentionPolicy(settings.get('policy', 'medium_term'))
                    self.retention_days = settings.get('days', 90)
                except (TypeError, ValueError, json.JSONDecodeError):
                    # If parsing fails, use defaults
                    pass
            
            conn.close()
        except Exception as e:
            print(f"Error loading retention settings: {e}")
    
    def _save_settings(self):
        """Save retention settings to database"""
        try:
            settings = {
                'policy': self.policy.value,
                'days': self.retention_days,
                'updated_by': self.user,
                'updated_at': datetime.now().isoformat()
            }
            
            # Store in database metadata
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO metadata (key, value) 
                VALUES (?, ?)
            """, ('retention_policy', json.dumps(settings)))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving retention settings: {e}")
    
    def set_retention_policy(self, policy, custom_days=None):
        """Set the retention policy"""
        if isinstance(policy, str):
            try:
                policy = RetentionPolicy(policy)
            except ValueError:
                raise ValueError(f"Invalid retention policy: {policy}")

        # Capture the previous policy value for accurate audit logging
        previous_policy_value = self.policy.value

        self.policy = policy
        if custom_days:
            self.retention_days = custom_days
        else:
            self.retention_days = self._get_retention_days(policy)
        
        self._save_settings()
        
        # Log policy change
        self.storage.store_evidence(
            evidence_type="retention_policy_change",
            data={
                'previous_policy': previous_policy_value,
                'new_policy': policy.value,
                'retention_days': self.retention_days,
                'changed_by': self.user
            },
            actor=self.user
        )
        
        return True
    
    def get_retention_policy(self):
        """Get the current retention policy"""
        return {
            'policy': self.policy.value,
            'days': self.retention_days,
            'expires_after': self._get_expiry_date()
        }
    
    def _get_expiry_date(self):
        """Get the expiry date based on retention days"""
        if self.retention_days is None:
            return None  # Permanent retention
        return (datetime.now() + timedelta(days=self.retention_days)).isoformat()
    
    def check_expired_evidence(self):
        """Check for expired evidence records"""
        if self.retention_days is None:
            return []  # No expiry for permanent retention
        
        expiry_threshold = datetime.now() - timedelta(days=self.retention_days)
        expired_ids = []
        
        try:
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, evidence_type 
                FROM evidence 
                WHERE timestamp < ?
                  AND COALESCE(retention_status, 'active') = 'active'
            """, (expiry_threshold.strftime('%Y-%m-%d %H:%M:%S'),))
            
            expired_records = cursor.fetchall()
            expired_ids = [record[0] for record in expired_records]
            
            conn.close()
        except Exception as e:
            print(f"Error checking for expired evidence: {e}")
        
        return expired_ids
    
    def flag_expired_evidence(self):
        """Flag expired evidence in the database"""
        expired_ids = self.check_expired_evidence()
        
        if not expired_ids:
            return {'flagged': 0, 'ids': []}
        
        try:
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()

            cursor.executemany(
                """
                UPDATE evidence
                SET retention_status = 'expired'
                WHERE id = ?
                """,
                [(expired_id,) for expired_id in expired_ids]
            )
            
            conn.commit()
            conn.close()
            
            # Log the expiry event
            self.storage.store_evidence(
                evidence_type="retention_expiry_flag",
                data={
                    'expired_count': len(expired_ids),
                    'expired_ids': expired_ids,
                    'flagged_by': self.user,
                    'flagged_at': datetime.now().isoformat()
                },
                actor=self.user
            )
            
            return {
                'flagged': len(expired_ids),
                'ids': expired_ids
            }
        except Exception as e:
            print(f"Error flagging expired evidence: {e}")
            return {'flagged': 0, 'ids': []}
    
    def prepare_for_deletion(self, evidence_ids):
        """Prepare evidence for deletion with dual confirmation"""
        normalized_ids = self._normalize_evidence_ids(evidence_ids)
        if not normalized_ids:
            return {'success': False, 'message': 'No evidence IDs provided'}
        
        try:
            # Verify the evidence exists and is flagged as expired
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()

            found_records = []
            for evidence_id in normalized_ids:
                cursor.execute(
                    """
                    SELECT id, evidence_type, timestamp, COALESCE(retention_status, 'active') as retention_status
                    FROM evidence
                    WHERE id = ?
                    """,
                    (evidence_id,)
                )
                row = cursor.fetchone()
                if row:
                    found_records.append(row)

            conn.close()
            
            # Check if all requested IDs exist
            found_ids = [record[0] for record in found_records]
            missing_ids = set(normalized_ids) - set(found_ids)
            
            if missing_ids:
                return {
                    'success': False, 
                    'message': f'Evidence IDs not found: {list(missing_ids)}',
                    'found_ids': found_ids
                }

            not_expired = [record[0] for record in found_records if record[3] != 'expired']
            if not_expired:
                return {
                    'success': False,
                    'message': f'Evidence IDs not expired or already deleted: {not_expired}',
                    'found_ids': found_ids
                }
            
            # Mark for deletion with dual confirmation requirement
            for evidence_id in normalized_ids:
                deletion_request = {
                    'evidence_id': evidence_id,
                    'requested_by': self.user,
                    'requested_at': datetime.now().isoformat(),
                    'status': 'pending_confirmation'
                }
                
                self.storage.store_evidence(
                    evidence_type="deletion_request",
                    data=deletion_request,
                    actor=self.user
                )
            
            return {
                'success': True,
                'message': f'Deletion request prepared for {len(normalized_ids)} items. Dual confirmation required.',
                'evidence_ids': normalized_ids
            }
        except Exception as e:
            print(f"Error preparing for deletion: {e}")
            return {'success': False, 'message': str(e)}
    
    def _load_pending_deletion_requests(self):
        """Load pending deletion requests from encrypted evidence records."""
        pending = {}
        try:
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM evidence WHERE evidence_type = 'deletion_request'")
            request_rows = cursor.fetchall()
            conn.close()
        except Exception:
            return pending

        for (record_id,) in request_rows:
            payload = self.storage.decrypt_evidence_data(record_id) or {}
            data = payload.get('data', {}) if isinstance(payload, dict) else {}
            evidence_id = data.get('evidence_id')
            status = data.get('status')
            try:
                evidence_id = int(evidence_id)
            except (TypeError, ValueError):
                continue
            if status == 'pending_confirmation':
                pending[evidence_id] = record_id

        return pending

    def confirm_deletion(self, evidence_ids, confirm_token=None):
        """Confirm deletion with dual confirmation (soft delete)"""
        normalized_ids = self._normalize_evidence_ids(evidence_ids)
        if not normalized_ids:
            return {'success': False, 'message': 'No evidence IDs provided'}
        
        try:
            pending_requests = self._load_pending_deletion_requests()
            pending_ids = [eid for eid in normalized_ids if eid in pending_requests]
            missing_pending = [eid for eid in normalized_ids if eid not in pending_requests]

            if missing_pending:
                return {
                    'success': False,
                    'message': f'No pending deletion requests found for IDs: {missing_pending}'
                }

            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()

            rows = []
            for pending_id in pending_ids:
                cursor.execute(
                    """
                    SELECT id, COALESCE(retention_status, 'active') as retention_status
                    FROM evidence
                    WHERE id = ?
                    """,
                    (pending_id,)
                )
                row = cursor.fetchone()
                if row:
                    rows.append(row)

            status_by_id = {row[0]: row[1] for row in rows}
            not_expired = [eid for eid in pending_ids if status_by_id.get(eid) != 'expired']
            if not_expired:
                conn.close()
                return {
                    'success': False,
                    'message': f'Evidence IDs not expired or already deleted: {not_expired}'
                }

            cursor.executemany(
                """
                UPDATE evidence
                SET retention_status = 'deleted'
                WHERE id = ?
                """,
                [(pending_id,) for pending_id in pending_ids]
            )
            
            conn.commit()
            conn.close()
            
            deleted_count = len(pending_ids)
            
            # Log deletion event
            deletion_log = {
                'deleted_count': deleted_count,
                'deleted_ids': pending_ids,
                'deleted_by': self.user,
                'deleted_at': datetime.now().isoformat(),
                'confirmation_required': 'dual',
                'confirmed_by': self.user,
                'delete_mode': 'soft'
            }
            
            # Store deletion as immutable event in the database
            self.storage.store_evidence(
                evidence_type="evidence_deletion",
                data=deletion_log,
                actor=self.user
            )
            
            return {
                'success': True,
                'message': f'Successfully soft-deleted {deleted_count} evidence items',
                'deleted_count': deleted_count,
                'deleted_ids': pending_ids
            }
        except Exception as e:
            print(f"Error confirming deletion: {e}")
            return {'success': False, 'message': str(e)}

    def _normalize_evidence_ids(self, evidence_ids):
        """Normalize list-like IDs to unique positive integers."""
        normalized = []
        seen = set()
        if not isinstance(evidence_ids, (list, tuple, set)):
            return normalized

        for raw_id in evidence_ids:
            try:
                evidence_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if evidence_id <= 0 or evidence_id in seen:
                continue
            seen.add(evidence_id)
            normalized.append(evidence_id)

        return normalized
    
    def get_retention_status(self):
        """Get the current retention status"""
        try:
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN COALESCE(retention_status, 'active') = 'active' THEN 1 ELSE 0 END) AS active_count,
                    SUM(CASE WHEN COALESCE(retention_status, 'active') = 'expired' THEN 1 ELSE 0 END) AS expired_count,
                    SUM(CASE WHEN COALESCE(retention_status, 'active') = 'deleted' THEN 1 ELSE 0 END) AS deleted_count,
                    COUNT(*) AS total_count
                FROM evidence
            """)
            row = cursor.fetchone()
            conn.close()

            active_count = row[0] or 0
            expired_count = row[1] or 0
            deleted_count = row[2] or 0
            total_count = row[3] or 0
        except Exception:
            active_count = 0
            expired_count = 0
            deleted_count = 0
            total_count = 0

        total_visible = total_count - deleted_count

        return {
            'policy': self.policy.value,
            'retention_days': self.retention_days,
            'total_evidence': total_visible,
            'expired_evidence': expired_count,
            'active_evidence': active_count,
            'next_expiry_check': self._get_expiry_date()
        }


# Global instance for convenience
retention_engine_instance = None


def get_retention_engine(storage, policy=RetentionPolicy.MEDIUM_TERM):
    """Get the retention engine instance"""
    global retention_engine_instance
    if retention_engine_instance is None:
        retention_engine_instance = RetentionEngine(storage, policy)
    return retention_engine_instance
