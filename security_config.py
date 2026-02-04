"""
Security Configuration for ISEC Application
Defines security defaults and hardening settings
"""

# Security defaults
SECURITY_CONFIG = {
    # Encryption settings
    "encryption_enabled": True,
    "default_key_rotation_days": 30,
    
    # File handling limits
    "max_scan_depth": 3,
    "max_files_per_directory": 50,
    "max_file_size_mb": 50,
    "collection_timeout_seconds": 300,
    
    # Database security
    "enable_database_encryption": True,
    "use_multiple_hashes": True,  # SHA-256 and SHA-512
    "enable_hmac_verification": True,
    "secure_temp_storage": True,
    
    # Access controls
    "require_authentication": True,
    "log_all_access": True,
    "enable_audit_logging": True,
    "tamper_detection": True,
    
    # Allowed paths for scanning (whitelist approach)
    "allowed_scan_paths": {
        "windows": [
            "%USERPROFILE%",
            "%PROGRAMDATA%",
            "%WINDIR%\\System32\\winevt\\Logs"  # Windows event logs
        ],
        "linux": [
            "~/",
            "/var/log",
            "/etc"
        ]
    },
    
    # Browser collection limits
    "browser_collection_limits": {
        "max_history_items": 100,
        "max_days_back": 30,
        "max_database_size_mb": 100
    },
    
    # Integrity verification
    "integrity_check_frequency": "on_save",  # Options: on_save, periodic, manual
    "backup_verification_enabled": True,
    
    # Network security (for future expansion)
    "disable_network_access": True,
    "block_dns_requests": True,
    "prevent_external_connections": True
}

# Hardening checklist - implemented settings
HARDENING_CHECKLIST = {
    # Pre-deployment
    "database_encryption_implemented": True,
    "sql_injection_protection": True,
    "input_validation_enabled": True,
    "secure_temp_handling": True,
    "certificate_auth_ready": False,  # Future enhancement
    
    # Runtime security
    "file_path_validation": True,
    "subprocess_timeout": True,
    "parameterized_queries": True,
    "recursion_limits": True,
    "data_encryption": True,
    "multi_hash_algorithms": True,
    
    # Post-collection
    "integrity_verification": True,
    "digital_signatures": True,
    "backup_verification": True,
    "access_logging": True,
    "tamper_detection": True,
    
    # Access controls
    "mfa_support": False,  # Future enhancement
    "rbac_implemented": False,  # Future enhancement
    "action_logging": True,
    "integrity_audits": True,
    "secure_deletion": False  # Future enhancement
}

def get_security_config():
    """Return the security configuration"""
    return SECURITY_CONFIG

def get_hardening_status():
    """Return the current hardening implementation status"""
    return HARDENING_CHECKLIST