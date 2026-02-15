"""
Forensic Report Generator Module
Generates comprehensive PDF reports of collected evidence with digital signatures
"""
import os
import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import Image
import hashlib
import platform
import getpass
import socket
from src.utils.digital_signer import DigitalSigner
from src.utils.consent_manager import get_consent_manager
from src.utils.role_manager import get_role_manager
from src.utils.retention_engine import get_retention_engine


class ReportGenerator:
    def __init__(self, storage, output_dir):
        self.storage = storage
        self.output_dir = output_dir
        self.db_path = storage.db_path
        self.digital_signer = DigitalSigner()
        self.consent_manager = get_consent_manager(storage)
        self.role_manager = get_role_manager(storage)  # Add role manager
        self.retention_engine = get_retention_engine(storage)  # Add retention engine
    
    def _get_evidence_summary(self):
        """Get summary statistics of collected evidence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count evidence by type
        cursor.execute("SELECT evidence_type, COUNT(*) FROM evidence WHERE COALESCE(retention_status, 'active') = 'active' GROUP BY evidence_type")
        evidence_counts = cursor.fetchall()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM evidence WHERE COALESCE(retention_status, 'active') = 'active'")
        total_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_evidence': total_count,
            'by_type': dict(evidence_counts)
        }
    
    def _get_system_info(self):
        """Get system information for the report"""
        return {
            'hostname': platform.node(),
            'os': platform.platform(),
            'user': getpass.getuser(),
            'ip_address': self._get_local_ip(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_local_ip(self):
        """Get the local IP address (offline-safe)."""
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
    
    def _get_consent_summary(self):
        """Get consent status summary for the report"""
        return self.consent_manager.get_consent_summary()
    
    def _get_role_info(self):
        """Get role information for the report"""
        return self.role_manager.get_role_description()
    
    def _get_retention_info(self):
        """Get retention information for the report"""
        return self.retention_engine.get_retention_status()
    
    def _get_hash_chain_verification_result(self):
        """Get hash chain verification result"""
        # We'll call the storage method to get the verification result
        return self.storage.get_hash_chain_verification_result()
    
    def _create_signed_pdf_report(self, filename):
        """Create a signed PDF report with all evidence information"""
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        
        styles = getSampleStyleSheet()
        
        # Custom title style
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        # Report title
        story.append(Paragraph("Internal Security Evidence Collector Report", title_style))
        story.append(Spacer(1, 20))
        
        # System information
        system_info = self._get_system_info()
        story.append(Paragraph("System Information", styles['Heading2']))
        
        system_data = [
            ["Hostname:", system_info['hostname']],
            ["Operating System:", system_info['os']],
            ["User:", system_info['user']],
            ["IP Address:", system_info['ip_address']],
            ["Report Generated:", system_info['timestamp']]
        ]
        
        system_table = Table(system_data, colWidths=[2*inch, 4*inch])
        system_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(system_table)
        story.append(Spacer(1, 20))
        
        # Role information
        role_info = self._get_role_info()
        story.append(Paragraph("User Role Information", styles['Heading2']))
        
        role_data = [
            ["Role:", role_info['name']],
            ["Role ID:", role_info['role']],
            ["Permissions:", ", ".join(role_info['permissions'])]
        ]
        
        role_table = Table(role_data, colWidths=[2*inch, 4*inch])
        role_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(role_table)
        story.append(Spacer(1, 20))
        
        # Retention information
        retention_info = self._get_retention_info()
        story.append(Paragraph("Evidence Retention Information", styles['Heading2']))
        
        retention_data = [
            ["Retention Policy:", retention_info['policy']],
            ["Retention Days:", str(retention_info['retention_days']) if retention_info['retention_days'] is not None else "Permanent"],
            ["Total Evidence Items:", str(retention_info['total_evidence'])],
            ["Active Evidence Items:", str(retention_info['active_evidence'])],
            ["Expired Evidence Items:", str(retention_info['expired_evidence'])]
        ]
        
        retention_table = Table(retention_data, colWidths=[2*inch, 4*inch])
        retention_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(retention_table)
        story.append(Spacer(1, 20))
        
        # Evidence summary
        evidence_summary = self._get_evidence_summary()
        story.append(Paragraph("Evidence Summary", styles['Heading2']))
        
        summary_data = [
            ["Total Evidence Items:", str(evidence_summary['total_evidence'])]
        ]
        
        # Add breakdown by type
        for evidence_type, count in evidence_summary['by_type'].items():
            summary_data.append([f"{evidence_type.title()}:", str(count)])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Consent status
        consent_summary = self._get_consent_summary()
        if consent_summary:
            story.append(Paragraph("Consent Status", styles['Heading2']))
            
            consent_data = []
            for collection_type, status_info in consent_summary.items():
                consent_data.append([collection_type.title(), f"{status_info['status']} - {status_info['message']}"])
            
            if consent_data:  # Only create table if there's consent data
                consent_table = Table(consent_data, colWidths=[2*inch, 4*inch])
                consent_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(consent_table)
                story.append(Spacer(1, 20))
        
        # Integrity verification
        story.append(Paragraph("Integrity Verification", styles['Heading2']))
        
        # Database hash
        db_hash = self._calculate_file_hash(self.db_path)
        hash_chain_valid = self._get_hash_chain_verification_result()
        
        integrity_data = [
            ["Database Hash (SHA-256):", db_hash],
            ["Hash Chain Integrity:", "PASS" if hash_chain_valid else "FAIL - TAMPERING DETECTED!"]
        ]
        
        integrity_table = Table(integrity_data, colWidths=[2*inch, 4*inch])
        integrity_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(integrity_table)
        story.append(Spacer(1, 20))
        
        # Digital signature information
        story.append(Paragraph("Digital Signature Information", styles['Heading2']))
        
        # Generate signature data
        signature_data = {
            'evidence_db_hash': db_hash,
            'system_fingerprint': f"{system_info['hostname']}@{system_info['ip_address']}",
            'generation_timestamp': system_info['timestamp'],
            'report_filename': os.path.basename(filename)
        }
        
        signature_filename = f"{os.path.basename(filename)}.sig.json"
        signature_info_data = [
            ["Signature Status:", "External signature file expected"],
            ["Signature File:", signature_filename],
            ["Evidence DB Hash:", db_hash[:32] + "..."],  # Truncate for readability
            ["System Fingerprint:", f"{system_info['hostname']}@{system_info['ip_address']}"],
            ["Generation Time (UTC):", system_info['timestamp']]
        ]
        
        signature_info_table = Table(signature_info_data, colWidths=[2*inch, 4*inch])
        signature_info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(signature_info_table)
        story.append(Spacer(1, 20))
        
        # Signature verification instructions
        story.append(Paragraph("Verification Instructions", styles['Heading3']))
        verification_text = f"""
        To verify this report's authenticity:<br/>
        1. Verify the signature in <b>{signature_filename}</b> using the organization's public key<br/>
        2. Confirm the database hash matches the original evidence database<br/>
        3. Validate the system fingerprint matches the collection environment<br/>
        4. Check that the timestamp aligns with expected collection time<br/>
        <br/>
        If the signature file is missing, the report should be treated as unsigned.
        """
        story.append(Paragraph(verification_text, styles['Normal']))
        
        # Build document
        doc.build(story)
        
        # Apply digital signature to the PDF if the method exists
        if hasattr(self.digital_signer, 'sign_pdf'):
            try:
                sig_path = self.digital_signer.sign_pdf(filename, signature_data)
                if sig_path:
                    print(f"Digital signature file created: {sig_path}")
                    verification = self.digital_signer.verify_pdf_signature(
                        report_path=filename,
                        signature_path=sig_path,
                        evidence_db_path=self.db_path
                    )
                    if verification.get('success'):
                        print("Digital signature verification passed.")
                    else:
                        print(f"WARNING: Signature verification failed: {verification.get('message')}")
            except Exception as exc:
                print(f"Digital signature failed: {exc}")
        else:
            print("Digital signature method not available, skipping...")
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def generate_signed_report(self):
        """Generate a signed PDF report of the collected evidence"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"forensic_report_{timestamp}.pdf")
        
        self._create_signed_pdf_report(report_filename)
        
        return report_filename
