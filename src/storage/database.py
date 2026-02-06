"""
Secure Evidence Storage Module
Implements encrypted SQLite storage with blockchain-style hash chaining for evidence integrity
"""
import sqlite3
import hashlib
import hmac
import os
import json
from datetime import datetime
from cryptography.fernet import Fernet
import threading
from contextlib import contextmanager


class EvidenceDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()  # Thread safety for database operations
        self.encryption_key = self._setup_encryption()
        self.fernet = Fernet(self.encryption_key)
        
        # Initialize the database schema
        self._initialize_schema()
        
        # Track the last record hash for blockchain-style chaining
        self.last_record_hash = self._get_latest_record_hash()
        
        # Master salt for HMAC signatures
        self.master_salt = self._get_or_create_master_salt()
    
    def _setup_encryption(self):
        """Setup encryption key from environment or create a new one"""
        key_env = os.environ.get('EVIDENCE_ENCRYPTION_KEY')
        if key_env:
            return key_env.encode()
        else:
            # In a real application, you'd want to securely store this key
            # For demo purposes, we'll derive it from a system-specific value
            # and ensure it's properly formatted for Fernet
            import base64
            import secrets
            
            # Generate a proper 32-byte key for Fernet
            system_specific_value = f"isek_db_{os.getuid() if hasattr(os, 'getuid') else os.getcwd()}" if os.name != 'nt' else f"isek_db_{os.environ.get('USERNAME', 'user')}"
            key_bytes = hashlib.sha256(system_specific_value.encode()).digest()
            # Encode to URL-safe base64 as required by Fernet
            return base64.urlsafe_b64encode(key_bytes[:32])  # Take exactly 32 bytes
            
    def _get_or_create_master_salt(self):
        """Get existing master salt or create a new one.

        The salt is stored base64-encoded in the metadata table so that it can be
        round-tripped reliably across processes. Older databases may contain a
        legacy, non-base64 value; in that case we fall back to using the raw
        UTF-8 bytes which will typically cause integrity verification to fail,
        correctly flagging the chain as compromised.
        """
        import base64
        import secrets

        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT value FROM metadata WHERE key = 'master_salt'")
                row = cursor.fetchone()
                if row:
                    stored_value = row[0]
                    if stored_value is None:
                        # Unlikely, but treat as needing a fresh salt
                        new_salt = secrets.token_bytes(32)
                        encoded = base64.b64encode(new_salt).decode('ascii')
                        cursor.execute(
                            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                            ('master_salt', encoded),
                        )
                        conn.commit()
                        return new_salt

                    # Try new base64 format first
                    try:
                        return base64.b64decode(stored_value.encode('ascii'))
                    except Exception:
                        # Legacy format – fall back to UTF-8 bytes
                        return stored_value.encode('utf-8')
                else:
                    # Create a new master salt and persist in base64 format
                    new_salt = secrets.token_bytes(32)  # 32 bytes for strong salt
                    encoded = base64.b64encode(new_salt).decode('ascii')
                    cursor.execute(
                        "INSERT INTO metadata (key, value) VALUES (?, ?)",
                        ('master_salt', encoded),
                    )
                    conn.commit()
                    return new_salt
            except sqlite3.OperationalError:
                # Metadata table doesn't exist, create it
                cursor.execute('''CREATE TABLE IF NOT EXISTS metadata (
                                    key TEXT PRIMARY KEY,
                                    value TEXT
                                )''')
                new_salt = secrets.token_bytes(32)
                encoded = base64.b64encode(new_salt).decode('ascii')
                cursor.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ('master_salt', encoded),
                )
                conn.commit()
                return new_salt
    
    def _initialize_schema(self):
        """Initialize the database schema with evidence table and blockchain-style features"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create evidence table with blockchain-style linking
            cursor.execute('''CREATE TABLE IF NOT EXISTS evidence (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                evidence_type TEXT NOT NULL,
                                data TEXT NOT NULL,  -- Encrypted data
                                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                                actor TEXT,
                                workstation_id TEXT,
                                ip_address TEXT,
                                prev_record_hash TEXT,  -- Hash of previous record
                                current_record_hash TEXT,  -- Hash of current record
                                hmac_signature TEXT,  -- For integrity verification
                                chain_verification_result TEXT DEFAULT 'pending',  -- Result of chain verification
                                retention_status TEXT DEFAULT 'active'  -- active, expired, deleted
                            )''')
            
            # Create index for faster queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON evidence(timestamp)")
            cursor.execute('''CREATE TABLE IF NOT EXISTS metadata (
                                key TEXT PRIMARY KEY,
                                value TEXT
                              )''')
            
            conn.commit()
        
        self._migrate_schema()
    
    def _migrate_schema(self):
        """Ensure the database schema is up-to-date and migrate legacy fields."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(evidence)")
            columns = {row[1] for row in cursor.fetchall()}
            if 'retention_status' not in columns:
                cursor.execute("ALTER TABLE evidence ADD COLUMN retention_status TEXT DEFAULT 'active'")
            if 'chain_verification_result' not in columns:
                cursor.execute("ALTER TABLE evidence ADD COLUMN chain_verification_result TEXT DEFAULT 'pending'")

            cursor.execute('''CREATE TABLE IF NOT EXISTS metadata (
                                key TEXT PRIMARY KEY,
                                value TEXT
                              )''')

            # Normalize legacy rows
            cursor.execute("UPDATE evidence SET retention_status='active' WHERE retention_status IS NULL")
            cursor.execute("UPDATE evidence SET retention_status='expired' WHERE chain_verification_result='expired'")
            cursor.execute("UPDATE evidence SET chain_verification_result='pending' WHERE chain_verification_result='expired'")

            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Thread-safe database connection context manager"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=2)
        try:
            conn.execute('PRAGMA busy_timeout = 2000')
        except Exception:
            pass
        try:
            yield conn
        finally:
            conn.close()
    
    def store_evidence(self, evidence_type, data, actor=None, workstation_id=None, ip_address=None, additional_fields=None):
        """Store encrypted evidence with blockchain-style hash chaining and HMAC signature"""
        with self.lock:  # Ensure thread safety
            # Prepare data for storage
            data_dict = {
                'data': data,
                'additional_fields': additional_fields or {}
            }
            serialized_data = json.dumps(data_dict)
            encrypted_data = self.fernet.encrypt(serialized_data.encode()).decode('utf-8')
            
            # Calculate current record hash (before insertion, using potential future ID)
            next_id = self._get_next_record_id()
            current_record_content = f"{next_id}|{evidence_type}|{encrypted_data}|{actor}|{workstation_id}|{ip_address}|{self.last_record_hash}"
            current_record_hash = hashlib.sha256(current_record_content.encode()).hexdigest()
            
            # Calculate HMAC signature for integrity
            signature_content = f"{current_record_hash}|{evidence_type}|{encrypted_data}"
            hmac_signature = hmac.new(
                self.master_salt,
                signature_content.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Insert evidence record
                cursor.execute('''
                    INSERT INTO evidence 
                    (evidence_type, data, timestamp, actor, workstation_id, ip_address, 
                     prev_record_hash, current_record_hash, hmac_signature)
                    VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)
                ''', (
                    evidence_type, encrypted_data, actor, workstation_id, 
                    ip_address, self.last_record_hash, current_record_hash, hmac_signature
                ))
                
                conn.commit()
                
                # Update the last record hash to the one we just calculated
                self.last_record_hash = current_record_hash
                
                return cursor.lastrowid
    
    def _get_next_record_id(self):
        """Get the next record ID that will be assigned"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM evidence")
            max_id = cursor.fetchone()[0]
            return (max_id or 0) + 1
    
    def _get_latest_record_hash(self):
        """Get the hash of the latest record in the database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT current_record_hash FROM evidence ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else None  # Return None if no records exist
    
    def verify_integrity(self, record_id):
        """Verify the integrity of a specific evidence record using HMAC"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT current_record_hash, evidence_type, data, hmac_signature 
                FROM evidence WHERE id = ?
            ''', (record_id,))
            
            row = cursor.fetchone()
            if not row:
                return False
            
            stored_hash, evidence_type, encrypted_data, stored_signature = row
            
            # Recalculate HMAC signature
            signature_content = f"{stored_hash}|{evidence_type}|{encrypted_data}"
            recalculated_signature = hmac.new(
                self.master_salt,
                signature_content.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures
            return hmac.compare_digest(stored_signature, recalculated_signature)
    
    def verify_full_hash_chain(self, update_results=True):
        """Verify the complete blockchain-style hash chain for all records"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, prev_record_hash, current_record_hash, evidence_type, data, hmac_signature
                FROM evidence
                ORDER BY id
            ''')
            
            records = cursor.fetchall()
            all_valid = True
            
            for i, record in enumerate(records):
                record_id, prev_hash, curr_hash, evidence_type, encrypted_data, hmac_sig = record
                
                # Verify HMAC signature for this record
                signature_content = f"{curr_hash}|{evidence_type}|{encrypted_data}"
                recalculated_signature = hmac.new(
                    self.master_salt,
                    signature_content.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()
                
                hmac_valid = hmac.compare_digest(hmac_sig, recalculated_signature)
                
                # Verify that the stored previous hash matches the actual previous record's hash
                chain_link_valid = True
                if i > 0:  # Not the first record
                    expected_prev_hash = records[i-1][2]  # Previous record's current hash
                    chain_link_valid = (prev_hash == expected_prev_hash)
                else:
                    # First record should have NULL or empty prev_record_hash
                    chain_link_valid = (prev_hash is None or prev_hash == "")
                
                # Overall validity for this record
                record_valid = hmac_valid and chain_link_valid

                if update_results:
                    try:
                        with self._get_connection() as update_conn:
                            update_cursor = update_conn.cursor()
                            verification_result = 'valid' if record_valid else 'invalid'
                            update_cursor.execute('''
                                UPDATE evidence 
                                SET chain_verification_result = ?
                                WHERE id = ?
                            ''', (verification_result, record_id))
                            update_conn.commit()
                    except Exception:
                        pass
                
                if not record_valid:
                    all_valid = False
            
            # Update the last record hash cache
            if records:
                self.last_record_hash = records[-1][2]  # Last record's current hash
            
            return all_valid
    
    def get_hash_chain_verification_result(self):
        """Get the overall result of the hash chain verification"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT chain_verification_result FROM evidence ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return True
            status = row[0]

        if status in ('valid', 'invalid'):
            return status == 'valid'

        # Pending/legacy state: recompute and persist results
        return self.verify_full_hash_chain(update_results=True)
    
    def get_all_evidence(self, include_expired=False, include_deleted=False):
        """Retrieve evidence records, optionally including expired/deleted items"""
        filters = []
        if not include_deleted:
            filters.append("COALESCE(retention_status, 'active') != 'deleted'")
        if not include_expired:
            filters.append("COALESCE(retention_status, 'active') != 'expired'")
        where_clause = f" WHERE {' AND '.join(filters)}" if filters else ""
        query = f"SELECT id, evidence_type, timestamp, actor, workstation_id, ip_address FROM evidence{where_clause} ORDER BY timestamp DESC"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return cursor.fetchall()
    
    def decrypt_evidence_data(self, record_id):
        """Decrypt and return the data for a specific evidence record"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT data FROM evidence WHERE id = ?', (record_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            encrypted_data = row[0]
            try:
                decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode('utf-8')
                return json.loads(decrypted_data)
            except Exception:
                return None  # Return None if decryption fails

    def get_evidence_detail(self, record_id):
        """Return a detailed evidence record for UI display."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, evidence_type, timestamp, actor, workstation_id, ip_address,
                       retention_status, chain_verification_result, prev_record_hash,
                       current_record_hash, hmac_signature, data
                FROM evidence
                WHERE id = ?
            ''', (record_id,))
            row = cursor.fetchone()
            if not row:
                return None

        (rec_id, evidence_type, timestamp, actor, workstation_id, ip_address,
         retention_status, chain_verification_result, prev_record_hash,
         current_record_hash, hmac_signature, encrypted_data) = row

        payload = None
        size_bytes = None
        try:
            payload = self.decrypt_evidence_data(rec_id)
            if payload is not None:
                size_bytes = len(json.dumps(payload).encode('utf-8'))
        except Exception:
            payload = None
            size_bytes = None

        integrity_ok = self.verify_integrity(rec_id)

        return {
            'id': rec_id,
            'type': evidence_type,
            'timestamp': timestamp,
            'actor': actor,
            'workstationId': workstation_id,
            'ipAddress': ip_address,
            'retentionStatus': retention_status,
            'chainVerificationResult': chain_verification_result,
            'prevRecordHash': prev_record_hash,
            'currentRecordHash': current_record_hash,
            'hmacSignature': hmac_signature,
            'data': payload.get('data') if isinstance(payload, dict) else None,
            'additionalFields': payload.get('additional_fields') if isinstance(payload, dict) else None,
            'sizeBytes': size_bytes,
            'integrityOk': integrity_ok
        }
