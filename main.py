"""
Main entry point for the Internal Security Evidence Collector (ISEC)
Handles command-line arguments, initializes the evidence collection process, and manages exports
"""
import argparse
import json
import os
import sys
from src.core.collector import EvidenceCollector
from src.reporting.report_generator import ReportGenerator
from src.utils.consent_manager import get_consent_manager
from src.utils.role_manager import get_role_manager, UserRole
from src.utils.retention_engine import RetentionPolicy
from src.utils.startup_validator import validate_environment
from src.utils.license_manager import LicenseManager
from src.utils.logging_setup import setup_logging

ACTION_STDOUT = None
EVIDENCE_TYPES = {
    'system_logs',
    'browser_history',
    'network_connections',
    'file_metadata'
}

def request_browser_consent(collector):
    """Request consent for browser data collection"""
    consent_manager = get_consent_manager(collector.storage)
    
    print("\nBrowser Data Collection Consent")
    print("=" * 40)
    print("The application needs your consent to collect browser history and related data.")
    print("\nData to be collected:")
    print("- Browser history URLs and timestamps")
    print("- Cookie information")
    print("- Download history")
    print("- Bookmark data")
    print("- Cache entries")
    print("\nThis data will be stored locally and used solely for security monitoring purposes.")
    
    while True:
        response = input("\nDo you consent to browser data collection? (y/n): ").lower().strip()
        if response in ['y', 'yes']:
            # Get available browsers
            available_browsers = collector.browser_history_collector._get_available_browsers()
            if not available_browsers:
                print("No browsers detected on this system.")
                consent_manager.grant_consent('browser_data', {
                    'browsers': [],
                    'time_range': 'N/A',
                    'reason': 'No browsers available'
                })
                return True
            
            print(f"\nAvailable browsers: {', '.join(available_browsers)}")
            selected_browsers_input = input("Enter browsers to scan (comma-separated) or press Enter for all: ").strip()
            
            if selected_browsers_input:
                selected_browsers = [b.strip() for b in selected_browsers_input.split(',')]
                # Validate selected browsers
                valid_browsers = [b for b in selected_browsers if b in available_browsers]
            else:
                valid_browsers = available_browsers
            
            print("\nTime range options:")
            print("1. Last 24 hours")
            print("2. Last 7 days")
            print("3. Last 30 days")
            print("4. All time")
            
            while True:
                try:
                    time_choice = input("Select time range (1-4): ").strip()
                    time_map = {
                        '1': 'last_24h',
                        '2': 'last_7d',
                        '3': 'last_30d',
                        '4': 'all_time'
                    }
                    if time_choice in time_map:
                        selected_time_range = time_map[time_choice]
                        break
                    else:
                        print("Invalid choice. Please select 1-4.")
                except KeyboardInterrupt:
                    print("\nConsent request cancelled.")
                    return False
            
            consent_data = {
                'browsers': valid_browsers,
                'time_range': selected_time_range,
                'timestamp': 'collected_during_collection'
            }
            
            consent_manager.grant_consent('browser_data', consent_data)
            print("Browser data collection consent granted.")
            return True
        elif response in ['n', 'no']:
            consent_manager.deny_consent('browser_data', 'User declined consent')
            print("Browser data collection consent denied. Browser data will not be collected.")
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")


def assign_role(collector):
    """Assign a role to the current user"""
    role_manager = get_role_manager(collector.storage)
    
    print("\nRole Assignment")
    print("=" * 40)
    print("Available roles:")
    print("1. Collector - Can collect evidence, view data, and modify evidence")
    print("2. Reviewer - Can only view evidence data")
    print("3. Exporter - Can view and export evidence data")
    
    while True:
        try:
            role_choice = input("\nSelect role (1-3) or press Enter for default (Reviewer): ").strip()
            if role_choice == '':
                role = UserRole.REVIEWER
                break
            elif role_choice == '1':
                role = UserRole.COLLECTOR
                break
            elif role_choice == '2':
                role = UserRole.REVIEWER
                break
            elif role_choice == '3':
                role = UserRole.EXPORTER
                break
            else:
                print("Invalid choice. Please select 1-3.")
        except KeyboardInterrupt:
            print("\nRole assignment cancelled.")
            return
    
    success = role_manager.set_role(role)
    if success:
        print(f"Role '{role.value}' assigned successfully.")
        current_role = role_manager.get_role_description()
        print(f"Current role: {current_role['name']}")
        print(f"Permissions: {', '.join(current_role['permissions'])}")
    else:
        print("Failed to assign role.")


def set_retention_policy(collector):
    """Set the retention policy for evidence"""
    print("\nEvidence Retention Policy")
    print("=" * 40)
    print("Available retention policies:")
    print("1. Temporary (7 days)")
    print("2. Short Term (30 days)")
    print("3. Medium Term (90 days) - DEFAULT")
    print("4. Long Term (365 days)")
    print("5. Permanent (no expiry)")
    print("6. Custom days")
    
    while True:
        try:
            policy_choice = input("\nSelect retention policy (1-6) or press Enter for default (Medium Term): ").strip()
            if policy_choice == '':
                policy = RetentionPolicy.MEDIUM_TERM
                custom_days = None
                break
            elif policy_choice == '1':
                policy = RetentionPolicy.TEMPORARY
                custom_days = None
                break
            elif policy_choice == '2':
                policy = RetentionPolicy.SHORT_TERM
                custom_days = None
                break
            elif policy_choice == '3':
                policy = RetentionPolicy.MEDIUM_TERM
                custom_days = None
                break
            elif policy_choice == '4':
                policy = RetentionPolicy.LONG_TERM
                custom_days = None
                break
            elif policy_choice == '5':
                policy = RetentionPolicy.PERMANENT
                custom_days = None
                break
            elif policy_choice == '6':
                policy = RetentionPolicy.MEDIUM_TERM  # Default for custom
                while True:
                    try:
                        custom_days = int(input("Enter number of days to retain evidence: "))
                        if custom_days < 0:
                            print("Days cannot be negative.")
                            continue
                        break
                    except ValueError:
                        print("Please enter a valid number.")
                break
            else:
                print("Invalid choice. Please select 1-6.")
        except KeyboardInterrupt:
            print("\nRetention policy setting cancelled.")
            return
    
    success = collector.set_retention_policy(policy, custom_days)
    if success:
        retention_status = collector.get_retention_status()
        print(f"\nRetention policy set successfully.")
        print(f"Policy: {retention_status['policy']}")
        print(f"Retention period: {retention_status['retention_days']} days")
        print(f"Total evidence: {retention_status['total_evidence']}")
        print(f"Active evidence: {retention_status['active_evidence']}")
        print(f"Expired evidence: {retention_status['expired_evidence']}")
    else:
        print("Failed to set retention policy.")


def emit_json(payload):
    out = ACTION_STDOUT if ACTION_STDOUT is not None else sys.stdout
    out.write("ISEC_JSON:" + json.dumps(payload) + "\n")
    out.flush()


def build_status_payload(collector, license_status=None, license_allowed_collect=True):
    current_role = collector.role_manager.get_role_description()
    retention_status = collector.get_retention_status()
    evidence_count = 0
    evidence_type_counts = {}
    evidence_items_count = 0
    try:
        rows = collector.storage.get_all_evidence()
        evidence_count = len(rows)
        for row in rows:
            evidence_type = row[1]
            evidence_type_counts[evidence_type] = evidence_type_counts.get(evidence_type, 0) + 1
            if evidence_type in EVIDENCE_TYPES:
                evidence_items_count += 1
    except Exception:
        pass

    return {
        "success": True,
        "role": current_role.get('role'),
        "roleName": current_role.get('name'),
        "permissions": current_role.get('permissions', []),
        "tamperingDetected": collector.tampering_detected,
        "collectionAllowed": collector.role_manager.has_permission('collect') and not collector.tampering_detected and license_allowed_collect,
        "browserConsent": collector.browser_consent_status,
        "retention": retention_status,
        "evidenceCount": evidence_count,
        "evidenceItemsCount": evidence_items_count,
        "evidenceTypeCounts": evidence_type_counts,
        "hashChainValid": not collector.tampering_detected,
        "license": license_status or {}
    }


def build_timeline_payload(collector):
    try:
        items = []
        rows = collector.storage.get_all_evidence()
        for row in rows:
            record_id, evidence_type, timestamp, actor, workstation_id, ip_address = row

            if evidence_type not in EVIDENCE_TYPES:
                continue

            evidence_payload = collector.storage.decrypt_evidence_data(record_id) or {}
            evidence_data = evidence_payload.get('data', {}) if isinstance(evidence_payload, dict) else {}

            timeline_data = {}
            if evidence_type == 'system_logs':
                timeline_data['entries'] = evidence_data.get('log_count')
            elif evidence_type == 'browser_history':
                timeline_data['entries'] = evidence_data.get('history_count')
            elif evidence_type == 'network_connections':
                timeline_data['connections'] = evidence_data.get('connection_count')
            elif evidence_type == 'file_metadata':
                timeline_data['files'] = evidence_data.get('metadata_count')

            items.append({
                "id": record_id,
                "type": evidence_type,
                "timestamp": timestamp,
                "description": f"{evidence_type.replace('_', ' ').title()} collected",
                "severity": "high" if collector.tampering_detected else "info",
                "data": timeline_data
            })
        return {"success": True, "items": items}
    except Exception as exc:
        return {"success": False, "items": [], "message": str(exc)}


def main():
    parser = argparse.ArgumentParser(description='Internal Security Evidence Collector')
    parser.add_argument('--output-dir', default='evidence_output', help='Directory to store evidence database')
    parser.add_argument('--log-file', help='Path to log file (default: <output-dir>/isec.log)')
    parser.add_argument('--log-level', default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--no-log-file', action='store_true', help='Disable file logging')
    parser.add_argument('--license-file', help='Path to license file (default: license.json)')
    parser.add_argument('--allow-unlicensed', action='store_true', help='Allow running without a valid license (development only)')
    parser.add_argument('--no-report', action='store_true', help='Skip PDF report generation')
    parser.add_argument('--export-dir', help='Directory to export evidence as ZIP')
    parser.add_argument('--assign-role', action='store_true', help='Assign user role interactively')
    parser.add_argument('--set-retention', action='store_true', help='Set evidence retention policy interactively')
    parser.add_argument('--electron-mode', action='store_true', help='Run in non-interactive mode for Electron UI')
    parser.add_argument('--default-role', choices=['collector', 'reviewer', 'exporter'], help='Default user role when initializing role manager')
    parser.add_argument('--action', choices=['run', 'status', 'timeline', 'collect', 'report', 'export', 'set_browser_consent', 'set_role'], default='run', help='Internal action for Electron IPC')
    parser.add_argument('--consent-time-range', choices=['last_24h', 'last_7d', 'last_30d', 'all_time'], help='Time range for browser history consent (Electron action)')
    parser.add_argument('--consent-browsers', help='Comma-separated list of browsers to scan (Electron action)')
    parser.add_argument('--role', choices=['collector', 'reviewer', 'exporter'], help='Role to set (set_role action)')
    
    args = parser.parse_args()

    global ACTION_STDOUT
    if args.action != 'run':
        ACTION_STDOUT = sys.stdout
        sys.stdout = sys.stderr

    log_path = None
    if not args.no_log_file:
        log_path = args.log_file or os.path.join(args.output_dir, 'isec.log')
    setup_logging(log_path, args.log_level)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    validation_result = validate_environment(args.output_dir)
    for check in validation_result["checks"]:
        status = "OK" if check["success"] else "FAILED"
        if check["message"]:
            print(f"Startup check - {check['name']}: {status} - {check['message']}")
        else:
            print(f"Startup check - {check['name']}: {status}")
    if not validation_result["success"]:
        print("Warning: One or more startup checks failed. The application will attempt to continue, but behavior may be degraded.")

    if args.action != 'run':
        critical_failures = [c for c in validation_result.get('checks', []) if c.get('name') in ('output_dir_writable', 'database_accessible') and not c.get('success')]
        if critical_failures:
            emit_json({
                'success': False,
                'message': 'Startup validation failed. Backend action blocked.',
                'checks': critical_failures
            })
            return

    # License enforcement (offline)
    license_manager = LicenseManager(license_file=args.license_file, allow_unlicensed=args.allow_unlicensed)
    license_status = license_manager.get_status()

    def license_allows(action_name):
        return license_manager.allows(action_name)

    # Map default role CLI argument to UserRole enum if provided
    default_role_enum = None
    if args.default_role:
        role_map = {
            'collector': UserRole.COLLECTOR,
            'reviewer': UserRole.REVIEWER,
            'exporter': UserRole.EXPORTER
        }
        default_role_enum = role_map.get(args.default_role)

    # Initialize collector
    update_chain_results = (args.action == 'run')
    collector = EvidenceCollector(args.output_dir, default_role=default_role_enum, update_chain_results=update_chain_results)
    
    if args.action == 'status':
        emit_json(build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect')))
        return
    if args.action == 'timeline':
        if not license_allows('view'):
            emit_json({
                "success": False,
                "message": "Timeline blocked: valid license required.",
                "items": [],
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        emit_json(build_timeline_payload(collector))
        return
    if args.action == 'set_browser_consent':
        if not license_allows('collect'):
            emit_json({
                "success": False,
                "message": "Consent update blocked: valid license required.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        if collector.tampering_detected:
            emit_json({
                "success": False,
                "message": "Consent update blocked due to tampering detection.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        if not collector.role_manager.has_permission('collect'):
            emit_json({
                "success": False,
                "message": "Consent update blocked: collector role required.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        if not args.consent_time_range:
            emit_json({
                "success": False,
                "message": "Consent update blocked: consent time range missing.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return

        available_browsers = []
        try:
            available_browsers = collector.browser_history_collector._get_available_browsers() if collector.browser_history_collector else []
        except Exception:
            available_browsers = []

        consent_details = {
            'time_range': args.consent_time_range,
            'timestamp': 'collected_during_collection'
        }

        if args.consent_browsers:
            requested = [b.strip() for b in args.consent_browsers.split(',') if b.strip()]
            valid = [b for b in requested if b in available_browsers]
            if not valid and available_browsers:
                emit_json({
                    "success": False,
                    "message": "Consent update blocked: no valid browsers selected.",
                    "availableBrowsers": available_browsers,
                    "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
                })
                return
            if valid:
                consent_details['browsers'] = valid

        consent_manager = get_consent_manager(collector.storage)
        consent_manager.grant_consent('browser_data', consent_details)
        collector.browser_consent_status = consent_manager.check_consent_status('browser_data')

        emit_json({
            "success": True,
            "message": "Browser data collection consent granted.",
            "availableBrowsers": available_browsers,
            "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
        })
        return
    if args.action == 'set_role':
        if collector.tampering_detected:
            emit_json({
                "success": False,
                "message": "Role change blocked due to tampering detection.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        if not args.role:
            emit_json({
                "success": False,
                "message": "Role change failed: role is required.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return

        role_map = {
            'collector': UserRole.COLLECTOR,
            'reviewer': UserRole.REVIEWER,
            'exporter': UserRole.EXPORTER
        }
        new_role = role_map.get(args.role)
        if not new_role:
            emit_json({
                "success": False,
                "message": "Role change failed: invalid role.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return

        if collector.role_manager.set_role(new_role):
            emit_json({
                "success": True,
                "message": f"Role set to {args.role}.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return

        emit_json({
            "success": False,
            "message": "Role change failed: unable to persist role.",
            "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
        })
        return
    if args.action == 'collect':
        if not license_allows('collect'):
            emit_json({
                "success": False,
                "message": "Evidence collection blocked: valid license required.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        if not collector.role_manager.has_permission('collect') or collector.tampering_detected:
            emit_json({
                "success": False,
                "message": "Evidence collection not permitted due to role restrictions or tampering detection.",
                "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
            })
            return
        collector.collect_all_evidence()
        emit_json({
            "success": True,
            "message": "Evidence collection completed.",
            "status": build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
        })
        return
    if args.action == 'report':
        status_payload = build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
        if not license_allows('report'):
            emit_json({"success": False, "message": "Report generation blocked: valid license required.", "filePath": None, "status": status_payload})
            return
        if collector.tampering_detected:
            emit_json({"success": False, "message": "Report generation blocked due to tampering detection.", "filePath": None, "status": status_payload})
            return
        if not collector.role_manager.has_permission('view'):
            emit_json({"success": False, "message": "Report generation blocked: insufficient permissions.", "filePath": None, "status": status_payload})
            return
        if status_payload.get('evidenceItemsCount', 0) <= 0:
            emit_json({"success": False, "message": "Report generation blocked: no evidence available.", "filePath": None, "status": status_payload})
            return
        if not status_payload.get('hashChainValid', True):
            emit_json({"success": False, "message": "Report generation blocked: integrity verification failed.", "filePath": None, "status": status_payload})
            return
        report_gen = ReportGenerator(collector.storage, collector.output_dir)
        report_path = report_gen.generate_signed_report()
        emit_json({"success": True, "filePath": report_path, "status": build_status_payload(collector)})
        return
    if args.action == 'export':
        status_payload = build_status_payload(collector, license_status=license_status, license_allowed_collect=license_allows('collect'))
        if not license_allows('export'):
            emit_json({"success": False, "message": "Export blocked: valid license required.", "filePath": None, "status": status_payload})
            return
        if collector.tampering_detected:
            emit_json({"success": False, "message": "Export blocked due to tampering detection.", "filePath": None, "status": status_payload})
            return
        if not collector.role_manager.has_permission('export'):
            emit_json({"success": False, "message": "Export blocked: exporter role required.", "filePath": None, "status": status_payload})
            return
        if not status_payload.get('hashChainValid', True):
            emit_json({"success": False, "message": "Export blocked: integrity verification failed.", "filePath": None, "status": status_payload})
            return
        if status_payload.get('evidenceItemsCount', 0) <= 0:
            emit_json({"success": False, "message": "Export blocked: no evidence available.", "filePath": None, "status": status_payload})
            return
        if not args.export_dir:
            emit_json({"success": False, "message": "Export blocked: export directory not provided.", "filePath": None, "status": status_payload})
            return
        os.makedirs(args.export_dir, exist_ok=True)
        zip_path = collector.export_to_zip(args.export_dir)
        if zip_path:
            emit_json({"success": True, "filePath": zip_path, "status": build_status_payload(collector)})
        else:
            emit_json({"success": False, "message": "Export failed.", "filePath": None, "status": status_payload})
        return
    
    # Handle role assignment if requested
    if args.assign_role:
        assign_role(collector)
        return  # Exit after role assignment
    
    # Handle retention policy setting if requested
    if args.set_retention:
        set_retention_policy(collector)
        return  # Exit after setting retention policy
    
    # Check current role
    current_role = collector.role_manager.get_role_description()
    # Match format expected by Electron main process
    print(f"Current role: {current_role['name']} ({current_role['role']})")
    print(f"Permissions: {', '.join(current_role['permissions'])}")
    
    # Print current retention status
    retention_status = collector.get_retention_status()
    print(f"\nRetention Policy: {retention_status['policy']}")
    print(f"Retention Period: {retention_status['retention_days']} days")
    print(f"Total Evidence: {retention_status['total_evidence']}")
    print(f"Active Evidence: {retention_status['active_evidence']}")
    print(f"Expired Evidence: {retention_status['expired_evidence']}")
    
    # Check for tampering
    if collector.tampering_detected:
        print("\nCRITICAL: TAMPERING DETECTED!")
        print("Evidence collection has been locked due to integrity violation.")
        print("Contact your security administrator immediately.")
        # Do not terminate the process here; the Electron UI and collector flags
        # will enforce lockout for evidence collection and indicate compromised state.
    
    # Check consent for browser data collection
    if collector.browser_consent_status['status'] != 'GRANTED':
        print(f"\nBrowser data collection consent status: {collector.browser_consent_status['status']}")
        if collector.browser_consent_status['status'] == 'DENIED':
            print("Browser data collection is permanently denied by user consent.")
        elif collector.browser_consent_status['status'] == 'PENDING':
            print("Browser data collection requires consent.")
            if args.electron_mode:
                print("Running in Electron mode; skipping interactive browser consent prompt.")
            elif collector.role_manager.has_permission('collect'):
                request_browser_consent(collector)
            else:
                print("Current role does not have permission to collect evidence, so consent request is skipped.")
        else:
            print(f"Browser data collection consent issue: {collector.browser_consent_status.get('message', 'Unknown issue')}")
    
    # Perform evidence collection if permitted
    if not license_allows('collect'):
        print("\nEvidence collection blocked: valid license required.")
    elif collector.role_manager.has_permission('collect') and not collector.tampering_detected:
        print("\nStarting evidence collection...")
        collector.collect_all_evidence()
        print("Evidence collection completed.")
    else:
        print("\nEvidence collection not permitted due to role restrictions or tampering detection.")
    
    # Generate report if not skipped and user has view permission
    if not args.no_report and collector.role_manager.has_permission('view') and license_allows('report'):
        print("\nGenerating forensic report...")
        report_gen = ReportGenerator(collector.storage, collector.output_dir)
        report_path = report_gen.generate_signed_report()
        print(f"Report generated: {report_path}")
    elif not license_allows('report') and not args.no_report:
        print("\nReport generation blocked: valid license required.")
    elif not collector.role_manager.has_permission('view'):
        print("\nReport generation skipped - insufficient permissions.")
    else:
        print("\nReport generation skipped as requested.")
    
    # Export to ZIP if export directory is specified and user has export permission
    if args.export_dir and collector.role_manager.has_permission('export') and license_allows('export'):
        print("\nExporting evidence to ZIP...")
        os.makedirs(args.export_dir, exist_ok=True)
        zip_path = collector.export_to_zip(args.export_dir)
        if zip_path:
            print(f"Evidence exported: {zip_path}")
        else:
            print("Export failed - insufficient permissions or other error.")
    elif args.export_dir and not license_allows('export'):
        print("\nExport blocked: valid license required.")
    elif args.export_dir and not collector.role_manager.has_permission('export'):
        print("\nExport skipped - insufficient permissions.")
    
    print("\nProcess completed.")


if __name__ == "__main__":
    main()
