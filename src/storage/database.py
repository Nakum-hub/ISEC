"""
Secure Evidence Storage Module
Implements encrypted SQLite storage with blockchain-style hash chaining for evidence integrity
"""
import sqlite3
import hashlib
import hmac
import os
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
import threading
from contextlib import contextmanager

from src.utils.paths import get_state_file


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
            normalized_env_key = self._normalize_fernet_key(key_env)
            if not normalized_env_key:
                raise ValueError("EVIDENCE_ENCRYPTION_KEY is invalid. Expected a Fernet-compatible key.")
            return normalized_env_key

        key_file = os.environ.get('EVIDENCE_ENCRYPTION_KEY_FILE') or self._get_key_file_path("evidence_encryption.key")
        if key_file and os.path.exists(key_file):
            try:
                file_key = self._normalize_fernet_key(self._read_key_file(key_file))
                if file_key:
                    return file_key
                if self._database_has_existing_evidence():
                    raise ValueError("Stored encryption key is invalid for an existing evidence database.")
            except ValueError:
                raise
            except Exception:
                pass

        # Preserve compatibility with legacy databases that were encrypted with
        # deterministic key derivation before key files existed.
        if self._database_has_existing_evidence():
            legacy_key = self._legacy_derived_key()
            if key_file:
                try:
                    self._write_key_file(key_file, legacy_key)
                except Exception:
                    pass
            return legacy_key

        # New deployments get a random key persisted outside the DB.
        new_key = Fernet.generate_key()
        if key_file:
            try:
                self._write_key_file(key_file, new_key)
            except Exception:
                pass
        return new_key

    def _legacy_derived_key(self):
        """Legacy key derivation (kept for backwards compatibility)."""
        system_specific_value = (
            f"isek_db_{os.getuid() if hasattr(os, 'getuid') else os.getcwd()}"
            if os.name != 'nt'
            else f"isek_db_{os.environ.get('USERNAME', 'user')}"
        )
        key_bytes = hashlib.sha256(system_specific_value.encode()).digest()
        return base64.urlsafe_b64encode(key_bytes[:32])

    def _get_key_file_path(self, filename):
        try:
            return get_state_file(filename, subdir="keys")
        except Exception:
            return None

    def _read_key_file(self, path):
        with open(path, "rb") as f:
            raw = f.read().strip()
        return raw

    def _write_key_file(self, path, key_bytes):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(key_bytes)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

    def _normalize_fernet_key(self, raw_value):
        """Normalize raw key input to a valid Fernet key format."""
        if raw_value is None:
            return None

        if isinstance(raw_value, bytes):
            data = raw_value.strip()
        else:
            data = str(raw_value).strip().encode("utf-8")

        if not data:
            return None

        # Already a valid Fernet key
        try:
            Fernet(data)
            return data
        except Exception:
            pass

        # Attempt to decode key material and convert to Fernet key.
        decoded = None
        try:
            decoded = self._decode_key_material(data.decode("utf-8"))
        except Exception:
            decoded = None

        if not decoded:
            return None

        if len(decoded) != 32:
            decoded = hashlib.sha256(decoded).digest()

        normalized = base64.urlsafe_b64encode(decoded[:32])
        try:
            Fernet(normalized)
            return normalized
        except Exception:
            return None

    def _database_has_existing_evidence(self):
        """Return True when an evidence table exists and contains records."""
        if not os.path.exists(self.db_path):
            return False

        try:
            if os.path.getsize(self.db_path) <= 0:
                return False
        except Exception:
            return False

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='evidence'")
                if (cursor.fetchone() or [0])[0] == 0:
                    return False
                cursor.execute("SELECT COUNT(*) FROM evidence")
                evidence_count = (cursor.fetchone() or [0])[0]
                return evidence_count > 0
        except Exception:
            return False
            
    def _get_or_create_master_salt(self):
        """Get existing master salt or create a new one.

        Prefer a dedicated key file outside the database. For legacy databases,
        we fall back to the stored metadata value to preserve the existing
        hash chain, then persist it to the key file for future runs.
        """
        import base64
        import secrets

        key_env = os.environ.get("ISEC_HMAC_KEY")
        key_file = os.environ.get("ISEC_HMAC_KEY_FILE") or self._get_key_file_path("evidence_hmac.key")

        if key_env:
            decoded = self._decode_key_material(key_env)
            if decoded:
                if key_file:
                    try:
                        self._write_key_file(key_file, base64.b64encode(decoded))
                    except Exception:
                        pass
                return decoded

        if key_file and os.path.exists(key_file):
            try:
                raw = self._read_key_file(key_file)
                try:
                    return base64.b64decode(raw)
                except Exception:
                    return raw
            except Exception:
                pass

        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT value FROM metadata WHERE key = 'master_salt'")
                row = cursor.fetchone()
                if row:
                    stored_value = row[0]
                    if stored_value is None:
                        new_salt = secrets.token_bytes(32)
                        encoded = base64.b64encode(new_salt).decode('ascii')
                        cursor.execute(
                            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                            ('master_salt', encoded),
                        )
                        conn.commit()
                        return new_salt

                    try:
                        decoded = base64.b64decode(stored_value.encode('ascii'))
                    except Exception:
                        decoded = stored_value.encode('utf-8')

                    if key_file:
                        try:
                            self._write_key_file(key_file, base64.b64encode(decoded))
                        except Exception:
                            pass

                    return decoded
                else:
                    new_salt = secrets.token_bytes(32)
                    encoded = base64.b64encode(new_salt).decode('ascii')
                    cursor.execute(
                        "INSERT INTO metadata (key, value) VALUES (?, ?)",
                        ('master_salt', encoded),
                    )
                    conn.commit()
                    if key_file:
                        try:
                            self._write_key_file(key_file, encoded.encode('ascii'))
                        except Exception:
                            pass
                    return new_salt
            except sqlite3.OperationalError:
                cursor.execute("""CREATE TABLE IF NOT EXISTS metadata (
                                    key TEXT PRIMARY KEY,
                                    value TEXT
                                )""")
                new_salt = secrets.token_bytes(32)
                encoded = base64.b64encode(new_salt).decode('ascii')
                cursor.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ('master_salt', encoded),
                )
                conn.commit()
                if key_file:
                    try:
                        self._write_key_file(key_file, encoded.encode('ascii'))
                    except Exception:
                        pass
                return new_salt

    def _decode_key_material(self, value):
        """Decode key material from hex/base64/plain string."""
        if value is None:
            return None
        data = value.strip()
        try:
            if all(c in "0123456789abcdefABCDEF" for c in data) and len(data) % 2 == 0:
                return bytes.fromhex(data)
        except Exception:
            pass
        try:
            return base64.b64decode(data.encode("utf-8"))
        except Exception:
            return data.encode("utf-8")

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
