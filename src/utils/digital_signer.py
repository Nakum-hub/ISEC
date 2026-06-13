"""
Digital Signer Module
Implements offline digital signing of forensic reports using local keypair
"""
import os
import hashlib
import hmac
import platform
import socket
import getpass
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from src.utils.paths import get_state_dir, ensure_dir

class DigitalSigner:
    def __init__(self, keys_dir=None):
        default_dir = os.path.join(get_state_dir(), "keys")
        override_dir = os.environ.get("ISEC_SIGNING_KEYS_DIR")
        self.keys_dir = keys_dir or override_dir or default_dir
        ensure_dir(self.keys_dir)
        self.private_key_path = os.path.join(self.keys_dir, "signing_private_key.pem")
        self.public_key_path = os.path.join(self.keys_dir, "signing_public_key.pem")
        
        # Generate keys if they don't exist
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            self._generate_keypair()
    
    def _generate_keypair(self):
        """Generate RSA keypair for digital signing"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Serialize private key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize public key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write keys to files with restricted permissions
        with open(self.private_key_path, 'wb') as f:
            f.write(pem_private)
        os.chmod(self.private_key_path, 0o600)  # Read/write for owner only
        
        with open(self.public_key_path, 'wb') as f:
            f.write(pem_public)
        
        print(f"Digital signing keypair generated in {self.keys_dir}")
    
    def _load_private_key(self):
        """Load the private key from file"""
        with open(self.private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        return private_key
    
    def _load_public_key(self):
        """Load the public key from file"""
        with open(self.public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        return public_key
    
    def _generate_system_fingerprint(self):
        """Generate a system fingerprint for the signature"""
        system_info = {
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': socket.gethostname(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'user': getpass.getuser(),
            'platform': platform.platform(),
        }
        
        # Create a hash of the system information
        system_json = json.dumps(system_info, sort_keys=True, separators=(',', ':'))
        fingerprint = hashlib.sha256(system_json.encode()).hexdigest()
        
        return {
            'fingerprint': fingerprint,
            'system_info': system_info
        }
    
    def sign_document(self, document_content, evidence_db_path):
        """
        Sign a document with embedded metadata
        """
        # Generate system fingerprint
        system_data = self._generate_system_fingerprint()
        
        # Get evidence database hash
        evidence_db_hash = self._calculate_file_hash(evidence_db_path)
        
        # Create signature metadata
        signature_metadata = {
            'evidence_db_hash': evidence_db_hash,
            'system_fingerprint': system_data['fingerprint'],
            'system_info': system_data['system_info'],
            'generation_timestamp': datetime.utcnow().isoformat() + 'Z',  # UTC timestamp
            'signature_format': 'ISEC_v1'
        }
        
        # Create the signature payload (JSON representation of metadata)
        payload_json = json.dumps(signature_metadata, sort_keys=True, separators=(',', ':'))
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
        
        # Sign the payload hash with the private key
        private_key = self._load_private_key()
        signature = private_key.sign(
            payload_hash.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Return signature data
        return {
            'signature': signature.hex(),
            'metadata': signature_metadata,
            'payload_hash': payload_hash
        }

    def sign_payload(self, payload):
        """Sign an arbitrary JSON-serializable payload with the local private key.

        Returns a dict with the hex ``signature``, the SHA-256 ``payload_hash``
        that was signed, and the ``canonical_payload`` JSON string used to
        compute it. This is a generic signing primitive used by
        forensic-soundness features (e.g. the transparency log) that need to
        sign structured records rather than PDFs.
        """
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        payload_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        private_key = self._load_private_key()
        signature = private_key.sign(
            payload_hash.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return {
            'signature': signature.hex(),
            'payload_hash': payload_hash,
            'canonical_payload': canonical,
        }

    def verify_payload(self, payload, signature_hex):
        """Verify a signature produced by :meth:`sign_payload` over a payload."""
        try:
            if not signature_hex:
                return False
            canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            payload_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            public_key = self._load_public_key()
            public_key.verify(
                bytes.fromhex(signature_hex),
                payload_hash.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def sign_pdf(self, report_path, signature_data):
        """
        Create an external signature file for a PDF report.
        Stores signature metadata and signature in a sidecar JSON file.
        """
        if not report_path or not os.path.exists(report_path):
            raise FileNotFoundError(f"Report not found: {report_path}")

        report_hash = self._calculate_file_hash(report_path)
        if not report_hash:
            raise ValueError("Unable to calculate report hash")

        system_data = self._generate_system_fingerprint()
        metadata = {
            'signature_format': 'ISEC_PDF_v1',
            'report_filename': signature_data.get('report_filename') or os.path.basename(report_path),
            'report_hash': report_hash,
            'evidence_db_hash': signature_data.get('evidence_db_hash'),
            'system_fingerprint': system_data['fingerprint'],
            'system_info': system_data['system_info'],
            'generation_timestamp': signature_data.get('generation_timestamp') or datetime.utcnow().isoformat() + 'Z'
        }

        payload_json = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

        private_key = self._load_private_key()
        signature = private_key.sign(
            payload_hash.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        signature_record = {
            'signature': signature.hex(),
            'payload_hash': payload_hash,
            'metadata': metadata
        }

        sig_path = report_path + ".sig.json"
        with open(sig_path, 'w', encoding='utf-8') as f:
            json.dump(signature_record, f, indent=2, sort_keys=True)

        return sig_path

    def verify_pdf_signature(self, report_path, signature_path=None, evidence_db_path=None, require_same_host=False):
        """
        Verify a PDF sidecar signature file produced by sign_pdf().
        """
        checks = {
            'signatureRecordValid': False,
            'metadataHashValid': False,
            'signatureValid': False,
            'reportHashValid': False,
            'evidenceDbHashValid': True,
            'systemFingerprintValid': True
        }

        try:
            if not report_path or not os.path.exists(report_path):
                return {'success': False, 'message': 'Report file not found.', 'checks': checks}

            sig_path = signature_path or (report_path + ".sig.json")
            if not os.path.exists(sig_path):
                return {'success': False, 'message': 'Signature file not found.', 'checks': checks}

            with open(sig_path, 'r', encoding='utf-8') as f:
                record = json.load(f)

            if not isinstance(record, dict):
                return {'success': False, 'message': 'Signature record is invalid.', 'checks': checks}

            signature_hex = record.get('signature')
            payload_hash = record.get('payload_hash')
            metadata = record.get('metadata')

            if not signature_hex or not payload_hash or not isinstance(metadata, dict):
                return {'success': False, 'message': 'Signature record missing required fields.', 'checks': checks}
            checks['signatureRecordValid'] = True

            canonical_metadata = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
            expected_payload_hash = hashlib.sha256(canonical_metadata.encode()).hexdigest()
            checks['metadataHashValid'] = hmac.compare_digest(expected_payload_hash, payload_hash)
            if not checks['metadataHashValid']:
                return {'success': False, 'message': 'Signature payload hash mismatch.', 'checks': checks}

            public_key = self._load_public_key()
            signature_bytes = bytes.fromhex(signature_hex)
            try:
                public_key.verify(
                    signature_bytes,
                    payload_hash.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                checks['signatureValid'] = True
            except InvalidSignature:
                return {'success': False, 'message': 'Digital signature verification failed.', 'checks': checks}

            report_hash = self._calculate_file_hash(report_path)
            expected_report_hash = metadata.get('report_hash')
            checks['reportHashValid'] = bool(report_hash and expected_report_hash and hmac.compare_digest(report_hash, expected_report_hash))
            if not checks['reportHashValid']:
                return {'success': False, 'message': 'Report hash mismatch.', 'checks': checks}

            if evidence_db_path:
                expected_db_hash = metadata.get('evidence_db_hash')
                actual_db_hash = self._calculate_file_hash(evidence_db_path)
                checks['evidenceDbHashValid'] = bool(expected_db_hash and actual_db_hash and hmac.compare_digest(expected_db_hash, actual_db_hash))
                if not checks['evidenceDbHashValid']:
                    return {'success': False, 'message': 'Evidence database hash mismatch.', 'checks': checks}

            if require_same_host:
                expected_fingerprint = metadata.get('system_fingerprint')
                current_fingerprint = self._generate_system_fingerprint().get('fingerprint')
                checks['systemFingerprintValid'] = bool(expected_fingerprint and current_fingerprint and hmac.compare_digest(expected_fingerprint, current_fingerprint))
                if not checks['systemFingerprintValid']:
                    return {'success': False, 'message': 'System fingerprint mismatch.', 'checks': checks}

            return {'success': True, 'message': 'Signature verification passed.', 'checks': checks}

        except Exception as e:
            return {'success': False, 'message': f'Signature verification error: {e}', 'checks': checks}
    
    def verify_signature(self, signature_hex, evidence_db_path, system_fingerprint=None, payload_hash=None):
        """
        Verify a raw signature against payload hash, or verify PDF sidecar signature.
        """
        try:
            if signature_hex and os.path.exists(signature_hex):
                result = self.verify_pdf_signature(
                    report_path=evidence_db_path,
                    signature_path=signature_hex,
                    require_same_host=bool(system_fingerprint)
                )
                return bool(result.get('success'))

            if not payload_hash:
                return False

            public_key = self._load_public_key()
            signature_bytes = bytes.fromhex(signature_hex)
            public_key.verify(
                signature_bytes,
                payload_hash.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        if not os.path.exists(file_path):
            return None
            
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()


# Global instance for convenience
signer_instance = None


def get_signer():
    """Get the global signer instance"""
    global signer_instance
    if signer_instance is None:
        signer_instance = DigitalSigner()
    return signer_instance
