"""
Utility Helper Functions
Common utilities for the ISEC application
"""
import os
import platform
import hashlib
from datetime import datetime


def get_system_info():
    """Get basic system information"""
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "node": platform.node(),
        "timestamp": datetime.now().isoformat()
    }


def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate hash of a file using specified algorithm"""
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None


def sanitize_path(path):
    """Sanitize file path for security"""
    # Normalize the path
    normalized = os.path.normpath(path)
    
    # Resolve to absolute path
    absolute = os.path.abspath(normalized)
    
    # Prevent directory traversal
    if ".." in absolute.replace(os.sep, '/').split('/'):
        raise ValueError("Path contains directory traversal")
    
    return absolute


def is_safe_path(base_path, target_path):
    """Check if target path is within base path (prevent directory traversal)"""
    base_abs = os.path.abspath(base_path)
    target_abs = os.path.abspath(target_path)
    
    return os.path.commonpath([base_abs]) == os.path.commonpath([base_abs, target_abs])


def format_bytes(bytes_value):
    """Format bytes value to human readable form"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def get_file_extension(file_path):
    """Get file extension in lowercase"""
    _, ext = os.path.splitext(file_path)
    return ext.lower() if ext else ""