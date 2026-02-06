"""
Core Evidence Collector Module
Manages the collection of various types of evidence from the system with consent enforcement and role-based access control
"""
import os
import zipfile
import hashlib
import shutil
import tempfile
from datetime import datetime
from src.storage.database import EvidenceDatabase
from src.collectors.system_logs import SystemLogsCollector
from src.collectors.browser_history import BrowserHistoryCollector
from src.collectors.network_connections import NetworkConnectionsCollector
from src.collectors.file_metadata import FileMetadataCollector
from src.utils.consent_manager import get_consent_manager, ConsentStatus
from src.utils.role_manager import get_role_manager, UserRole
from src.utils.retention_engine import get_retention_engine, RetentionPolicy
import getpass
import platform
import socket


class EvidenceCollector:
    def __init__(self, output_dir, default_role=None, update_chain_results=True):
        self.output_dir = output_dir
        # Initialize secure database with encryption
        self.storage = EvidenceDatabase(os.path.join(output_dir, "evidence.db"))
        
        # Get system info for chain of custody
        self.actor = getpass.getuser()
        self.workstation_id = platform.node()
        self.ip_address = self._get_local_ip()
        
        # Initialize role manager for access control
        self.role_manager = get_role_manager(self.storage, default_role=default_role)
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
        
        # Initialize collectors conditionally based on role permissions
        if self.role_manager.has_permission('collect'):
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
        self.collection_allowed = not self.tampering_detected and self.role_manager.has_permission('collect')
    
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
    
    def export_to_zip(self, export_dir):
        """Export all evidence to a ZIP file with checksum manifest - requires exporter role"""
        if not self.role_manager.has_permission('export'):
            print(f"Access denied: Role '{self.current_role['name']}' does not have permission to export evidence.")
            return None

        zip_filename = f"evidence_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        final_zip_path = os.path.join(export_dir, zip_filename)

        tmp_dir = None
        try:
            tmp_dir = tempfile.mkdtemp(prefix='isek_export_', dir=export_dir)

            manifest_content = self._generate_checksum_manifest()
            manifest_path = os.path.join(tmp_dir, "checksum_manifest.txt")
            with open(manifest_path, 'w') as f:
                f.write(manifest_content)

            tmp_zip_path = os.path.join(tmp_dir, zip_filename)
            with zipfile.ZipFile(tmp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(self.storage.db_path, os.path.basename(self.storage.db_path))
                zipf.write(manifest_path, os.path.basename(manifest_path))

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
    
    def _generate_checksum_manifest(self):
        """Generate a manifest with SHA-256 checksums for all evidence files"""
        manifest = f"Checksum Manifest - Generated: {datetime.now().isoformat()}\n"
        manifest += "="*60 + "\n\n"
        
        # Add database checksum
        db_hash = self._calculate_file_hash(self.storage.db_path)
        manifest += f"{db_hash}  {os.path.basename(self.storage.db_path)}\n"
        
        # Add hash chain verification result
        hash_chain_valid = self.storage.get_hash_chain_verification_result()
        tamper_status = "PASS" if hash_chain_valid else "FAIL - TAMPERING DETECTED!"
        manifest += f"\nHash Chain Integrity: {tamper_status}\n"
        
        # Add consent status information
        consent_summary = self.consent_manager.get_consent_summary()
        manifest += f"\nConsent Status:\n"
        for collection_type, status_info in consent_summary.items():
            manifest += f"  {collection_type}: {status_info['status']} - {status_info['message']}\n"
        
        # Add role information
        role_info = self.role_manager.get_role_description()
        manifest += f"\nUser Role: {role_info['name']} ({role_info['role']})\n"
        manifest += f"Permissions: {', '.join(role_info['permissions'])}\n"
        
        # Add retention status information
        retention_status = self.retention_engine.get_retention_status()
        manifest += f"\nRetention Policy: {retention_status['policy']}\n"
        manifest += f"Retention Days: {retention_status['retention_days']}\n"
        manifest += f"Total Evidence: {retention_status['total_evidence']}\n"
        manifest += f"Active Evidence: {retention_status['active_evidence']}\n"
        manifest += f"Expired Evidence: {retention_status['expired_evidence']}\n"
        
        # Add integrity verification for evidence
        all_evidence = self.storage.get_all_evidence()
        manifest += f"\nIntegrity Verification:\n"
        manifest += f"Total Evidence Items: {len(all_evidence)}\n"
        
        verified_count = 0
        for evidence_row in all_evidence[:10]:  # Show first 10 for brevity
            evidence_id = evidence_row[0]
            integrity_ok = self.storage.verify_integrity(evidence_id)
            if integrity_ok:
                verified_count += 1
            manifest += f"Evidence ID {evidence_id}: {'PASS' if integrity_ok else 'FAIL'}\n"
        
        if len(all_evidence) > 10:
            manifest += f"... and {len(all_evidence) - 10} more items\n"
        
        manifest += f"\nOverall Integrity: {verified_count}/{len(all_evidence)} items verified as authentic\n"
        
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
