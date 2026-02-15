"""
Core Evidence Collector Module
Manages the collection of various types of evidence from the system with consent enforcement and role-based access control
"""
import os
import zipfile
import hashlib
import shutil
import tempfile
import json
from datetime import datetime
from src.storage.database import EvidenceDatabase
from src.collectors.system_logs import SystemLogsCollector
from src.collectors.browser_history import BrowserHistoryCollector
from src.collectors.network_connections import NetworkConnectionsCollector
from src.collectors.file_metadata import FileMetadataCollector
from src.utils.consent_manager import get_consent_manager, ConsentStatus
from src.utils.role_manager import get_role_manager, UserRole
from src.utils.retention_engine import get_retention_engine, RetentionPolicy
from src.utils.digital_signer import get_signer
import getpass
import platform
import socket


class EvidenceCollector:
    def __init__(self, output_dir, update_chain_results=True, collect_enabled=True):
        self.output_dir = output_dir
        self.collect_enabled = bool(collect_enabled)
        # Initialize secure database with encryption
        self.storage = EvidenceDatabase(os.path.join(output_dir, "evidence.db"))
        
        # Get system info for chain of custody
        self.actor = getpass.getuser()
        self.workstation_id = platform.node()
        self.ip_address = self._get_local_ip()
        
        # Initialize role manager for access control
        self.role_manager = get_role_manager(self.storage)
        self.current_role = self.role_manager.get_role_description()
        
        # Initialize retention engine
        self.retention_engine = get_retention_engine(self.storage)
        
        # Check for tampering on startup
        self.tampering_detected = not self.storage.verify_full_hash_chain(update_results=update_chain_results)
        if self.tampering_detected:
            print("CRITICAL: TAMPERING DETECTED - Hash chain integrity compromised!")
            print("Evidence collection locked due to integrity violation.")
            # Optionally, we could disable collectors here
        else:
            print("Hash chain verification passed - Evidence collection proceeding...")
        
        # Initialize consent manager
        self.consent_manager = get_consent_manager(self.storage)
        
        # Check browser consent status
        self.browser_consent_status = self.consent_manager.check_consent_status('browser_data')
        self.browser_consent_granted = self.browser_consent_status['status'] == ConsentStatus.GRANTED.value
        
        # Initialize collectors only when collection is licensed and role permits it.
        if self.collect_enabled and self.role_manager.has_permission('collect'):
            self.system_logs_collector = SystemLogsCollector(self.storage, self.actor, self.workstation_id, self.ip_address)
            self.network_connections_collector = NetworkConnectionsCollector(self.storage, self.actor, self.workstation_id, self.ip_address)
            self.file_metadata_collector = FileMetadataCollector(self.storage, self.actor, self.workstation_id, self.ip_address)
            
            # Only initialize browser collector if consent is granted
            if self.browser_consent_granted:
                self.browser_history_collector = BrowserHistoryCollector(self.storage, self.actor, self.workstation_id, self.ip_address)
            else:
                # Create a browser collector that will enforce consent
                self.browser_history_collector = BrowserHistoryCollector(self.storage, self.actor, self.workstation_id, self.ip_address)
        else:
            # Role doesn't have collection permissions
            self.system_logs_collector = None
            self.network_connections_collector = None
            self.file_metadata_collector = None
            self.browser_history_collector = None
        
        # Flag to indicate if evidence collection should proceed
        self.collection_allowed = self.collect_enabled and not self.tampering_detected and self.role_manager.has_permission('collect')
    
    def _get_local_ip(self):
        """Get the local IP address for chain of custody (offline-safe)."""
        try:
            hostname = socket.gethostname()
            candidates = []
            for info in socket.getaddrinfo(hostname, None):
                family, _, _, _, sockaddr = info
                if family == socket.AF_INET:
                    ip = sockaddr[0]
                    if not ip.startswith("127."):
                        return ip
                    candidates.append(ip)
            if candidates:
                return candidates[0]
        except Exception:
            pass
        return "unknown"
    
    def collect_all_evidence(self):
        """Collect all types of evidence with consent enforcement and role-based access control"""
        if not self.collect_enabled:
            print("Evidence collection disabled: collect feature is not enabled in the active license.")
            return

        if self.tampering_detected:
            print("Evidence collection disabled due to tampering detection.")
            return
            
        if not self.role_manager.has_permission('collect'):
            print(f"Access denied: Role '{self.current_role['name']}' does not have permission to collect evidence.")
            return
        
        print("Collecting system logs...")
        if self.system_logs_collector:
            self.system_logs_collector.collect()
        
        print("Checking browser data collection consent...")
        # The browser collector handles consent internally
        if self.browser_history_collector:
            self.browser_history_collector.collect()
        
        print("Collecting network connections...")
        if self.network_connections_collector:
            self.network_connections_collector.collect()
        
        print("Collecting file metadata...")
        if self.file_metadata_collector:
            self.file_metadata_collector.collect()
        
        # Verify hash chain after collection
        chain_valid = self.storage.verify_full_hash_chain()
        if not chain_valid:
            print("CRITICAL: TAMPERING DETECTED AFTER COLLECTION!")
            self.tampering_detected = True
        
        # Check for expired evidence and flag them
        expired_result = self.retention_engine.flag_expired_evidence()
        if expired_result['flagged'] > 0:
            print(f"Flagged {expired_result['flagged']} expired evidence items")

    def collect_selected_evidence(self, evidence_types):
        """Collect only selected evidence types."""
        if not self.collect_enabled:
            print("Evidence collection disabled: collect feature is not enabled in the active license.")
            return

        if self.tampering_detected:
            print("Evidence collection disabled due to tampering detection.")
            return

        if not self.role_manager.has_permission('collect'):
            print(f"Access denied: Role '{self.current_role['name']}' does not have permission to collect evidence.")
            return

        type_map = {
            'system_logs': self.system_logs_collector,
            'browser_history': self.browser_history_collector,
            'network_connections': self.network_connections_collector,
            'file_metadata': self.file_metadata_collector
        }

        selected = [t for t in (evidence_types or []) if t in type_map]
        if not selected:
            print("No valid evidence types selected. Skipping collection.")
            return

        for evidence_type in selected:
            collector = type_map.get(evidence_type)
            if not collector:
                continue
            if evidence_type == 'system_logs':
                print("Collecting system logs...")
            elif evidence_type == 'browser_history':
                print("Checking browser data collection consent...")
            elif evidence_type == 'network_connections':
                print("Collecting network connections...")
            elif evidence_type == 'file_metadata':
                print("Collecting file metadata...")
            collector.collect()

        chain_valid = self.storage.verify_full_hash_chain()
        if not chain_valid:
            print("CRITICAL: TAMPERING DETECTED AFTER COLLECTION!")
            self.tampering_detected = True

        expired_result = self.retention_engine.flag_expired_evidence()
        if expired_result['flagged'] > 0:
            print(f"Flagged {expired_result['flagged']} expired evidence items")
    
    def export_to_zip(self, export_dir, report_path=None):
        """Export all evidence to a ZIP file with checksum manifest - requires exporter role"""
        if not self.role_manager.has_permission('export'):
            print(f"Access denied: Role '{self.current_role['name']}' does not have permission to export evidence.")
            return None

        zip_filename = f"evidence_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        final_zip_path = os.path.join(export_dir, zip_filename)

        tmp_dir = None
        try:
            tmp_dir = tempfile.mkdtemp(prefix='isek_export_', dir=export_dir)

            files_to_package = {
                os.path.basename(self.storage.db_path): self.storage.db_path
            }

            signer_public_key_path = None
            try:
                signer = get_signer()
                if signer and os.path.exists(signer.public_key_path):
                    signer_public_key_path = signer.public_key_path
                    files_to_package[os.path.basename(signer.public_key_path)] = signer.public_key_path
            except Exception:
                signer_public_key_path = None

            report_sig_path = None
            if report_path and os.path.exists(report_path):
                report_name = os.path.basename(report_path)
                files_to_package[report_name] = report_path
                candidate_sig = report_path + ".sig.json"
                if os.path.exists(candidate_sig):
                    report_sig_path = candidate_sig
                    files_to_package[os.path.basename(candidate_sig)] = candidate_sig

            manifest_data = self._build_export_manifest(
                files_to_package,
                report_path=report_path,
                report_signature_path=report_sig_path,
                signer_public_key_path=signer_public_key_path,
            )

            manifest_json_path = os.path.join(tmp_dir, "checksum_manifest.json")
            with open(manifest_json_path, 'w', encoding='utf-8') as f:
                json.dump(manifest_data, f, indent=2, sort_keys=True)
            files_to_package["checksum_manifest.json"] = manifest_json_path

            manifest_text_path = os.path.join(tmp_dir, "checksum_manifest.txt")
            with open(manifest_text_path, 'w', encoding='utf-8') as f:
                f.write(self._generate_checksum_manifest(manifest_data))
            files_to_package["checksum_manifest.txt"] = manifest_text_path

            tmp_zip_path = os.path.join(tmp_dir, zip_filename)
            with zipfile.ZipFile(tmp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for archive_name, source_path in files_to_package.items():
                    zipf.write(source_path, archive_name)

            if not os.path.exists(tmp_zip_path) or os.path.getsize(tmp_zip_path) <= 0:
                print("Export failed: ZIP was not created correctly.")
                return None

            os.replace(tmp_zip_path, final_zip_path)
            return final_zip_path
        except Exception as exc:
            print(f"Export failed: {exc}")
            return None
        finally:
            if tmp_dir and os.path.isdir(tmp_dir):
                try:
                    shutil.rmtree(tmp_dir)
                except Exception:
                    pass

    def _build_export_manifest(self, files_to_package, report_path=None, report_signature_path=None, signer_public_key_path=None):
        evidence_rows = self.storage.get_all_evidence()
        total_records = len(evidence_rows)
        verified_records = 0
        for row in evidence_rows:
            evidence_id = row[0]
            if self.storage.verify_integrity(evidence_id):
                verified_records += 1

        hash_chain_valid = self.storage.verify_full_hash_chain(update_results=True)
        db_name = os.path.basename(self.storage.db_path)

        file_hashes = {}
        for archive_name, source_path in files_to_package.items():
            file_hashes[archive_name] = self._calculate_file_hash(source_path)

        return {
            "schema": "ISEC_EXPORT_MANIFEST_v1",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "files": file_hashes,
            "evidence_database": {
                "file": db_name,
                "sha256": file_hashes.get(db_name),
                "hash_chain_valid": hash_chain_valid,
                "total_records": total_records,
            },
            "chain_of_custody": {
                "verified_records": verified_records,
                "total_records": total_records,
                "all_signatures_valid": verified_records == total_records,
            },
            "pdf_signature": {
                "report_file": os.path.basename(report_path) if report_path and os.path.exists(report_path) else None,
                "signature_file": os.path.basename(report_signature_path) if report_signature_path and os.path.exists(report_signature_path) else None,
                "present": bool(report_path and report_signature_path and os.path.exists(report_path) and os.path.exists(report_signature_path)),
                "public_key_file": os.path.basename(signer_public_key_path) if signer_public_key_path and os.path.exists(signer_public_key_path) else None,
            },
            "consent_summary": self.consent_manager.get_consent_summary(),
            "role": self.role_manager.get_role_description(),
            "retention": self.retention_engine.get_retention_status(),
        }

    def _generate_checksum_manifest(self, manifest_data):
        """Generate a human-readable checksum manifest from structured export metadata."""
        manifest = f"Checksum Manifest - Generated: {manifest_data.get('generated_at')}\n"
        manifest += "=" * 60 + "\n\n"

        files = manifest_data.get("files", {})
        for archive_name in sorted(files.keys()):
            manifest += f"{files[archive_name]}  {archive_name}\n"

        db_info = manifest_data.get("evidence_database", {})
        chain_info = manifest_data.get("chain_of_custody", {})
        pdf_info = manifest_data.get("pdf_signature", {})
        manifest += "\nHash Chain Integrity: "
        manifest += "PASS\n" if db_info.get("hash_chain_valid") else "FAIL - TAMPERING DETECTED!\n"
        manifest += f"Chain-of-Custody Signatures: {chain_info.get('verified_records', 0)}/{chain_info.get('total_records', 0)} verified\n"
        manifest += f"PDF Signature Present: {'YES' if pdf_info.get('present') else 'NO'}\n"
        if pdf_info.get("report_file"):
            manifest += f"Report File: {pdf_info.get('report_file')}\n"
        if pdf_info.get("signature_file"):
            manifest += f"Report Signature File: {pdf_info.get('signature_file')}\n"
        if pdf_info.get("public_key_file"):
            manifest += f"Signature Public Key File: {pdf_info.get('public_key_file')}\n"

        return manifest
        
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def set_retention_policy(self, policy, custom_days=None):
        """Set the retention policy for evidence"""
        return self.retention_engine.set_retention_policy(policy, custom_days)
    
    def get_retention_status(self):
        """Get the current retention status"""
        return self.retention_engine.get_retention_status()
