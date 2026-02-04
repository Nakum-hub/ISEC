"""
File Metadata Collector Module
Collects metadata from selected files and directories
"""
import os
import stat
import platform
from datetime import datetime


class FileMetadataCollector:
    def __init__(self, storage, actor, workstation_id, ip_address):
        self.storage = storage
        self.actor = actor
        self.workstation_id = workstation_id
        self.ip_address = ip_address
    
    def collect(self):
        """Collect file metadata from common system directories"""
        print("Collecting file metadata...")
        
        # Define directories to scan based on OS
        if platform.system() == "Windows":
            directories_to_scan = [
                os.path.expandvars(r'%SYSTEMDRIVE%\Users'),
                os.path.expandvars(r'%SYSTEMROOT%\System32'),
                os.path.expandvars(r'%PROGRAMFILES%'),
                os.path.expandvars(r'%PROGRAMFILES(X86)%')
            ]
        else:  # Linux, macOS
            directories_to_scan = [
                '/home',
                '/etc',
                '/var/log',
                '/tmp'
            ]
        
        all_metadata = []
        
        for directory in directories_to_scan:
            if os.path.exists(directory):
                metadata = self._scan_directory(directory)
                all_metadata.extend(metadata)
        
        if all_metadata:
            # Store the collected metadata as evidence
            self.storage.store_evidence(
                evidence_type="file_metadata",
                data={
                    'metadata_count': len(all_metadata),
                    'metadata_sample': all_metadata[:10],  # Store only first 10 as sample
                    'directories_scanned': directories_to_scan,
                    'timestamp': datetime.now().isoformat()
                },
                actor=self.actor,
                workstation_id=self.workstation_id,
                ip_address=self.ip_address
            )
            print(f"Collected metadata from {len(all_metadata)} files/directories")
        else:
            print("No file metadata collected")
    
    def _scan_directory(self, directory, max_depth=2, max_files_per_dir=20):
        """Scan a directory and collect metadata for files"""
        metadata_list = []
        current_depth = 0
        
        # Extract the directory name to check if it's a user directory
        base_dir_name = os.path.basename(directory.rstrip('\\/'))
        
        # Skip scanning if it's a user profile directory (to respect privacy unless specifically allowed)
        if base_dir_name.lower() in ['users', 'home'] and current_depth == 0:
            # Scan only subdirectories but limit to system ones
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isdir(item_path):
                    # Skip personal user directories, just scan system ones
                    if not self._is_personal_directory(item):
                        subdir_metadata = self._scan_directory_level(item_path, current_depth + 1, max_depth, max_files_per_dir)
                        metadata_list.extend(subdir_metadata)
        else:
            metadata_list = self._scan_directory_level(directory, current_depth, max_depth, max_files_per_dir)
        
        return metadata_list
    
    def _scan_directory_level(self, directory, current_depth, max_depth, max_files_per_dir):
        """Scan a directory level and collect metadata"""
        metadata_list = []
        
        if current_depth > max_depth:
            return metadata_list
        
        try:
            items_scanned = 0
            for item in os.listdir(directory):
                if items_scanned >= max_files_per_dir:
                    break
                    
                item_path = os.path.join(directory, item)
                
                try:
                    # Get file/directory stats
                    stat_info = os.stat(item_path)
                    
                    # Determine if it's a file or directory
                    is_dir = stat.S_ISDIR(stat_info.st_mode)
                    
                    metadata = {
                        'path': item_path,
                        'is_directory': is_dir,
                        'size_bytes': stat_info.st_size,
                        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat() if hasattr(stat_info, 'st_ctime') else 'unknown',
                        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                        'permissions': oct(stat_info.st_mode)[-3:],  # Last 3 digits of permission
                        'owner': self._get_owner(item_path),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    metadata_list.append(metadata)
                    items_scanned += 1
                    
                    # If it's a directory and we haven't reached max depth, recurse
                    if is_dir and current_depth < max_depth:
                        subdir_metadata = self._scan_directory_level(item_path, current_depth + 1, max_depth, max_files_per_dir // 2)
                        metadata_list.extend(subdir_metadata)
                        
                except (OSError, IOError) as e:
                    # Skip files that can't be accessed
                    print(f"Could not access {item_path}: {str(e)}")
                    continue
        except PermissionError:
            print(f"Permission denied accessing directory: {directory}")
        except Exception as e:
            print(f"Error scanning directory {directory}: {str(e)}")
        
        return metadata_list
    
    def _is_personal_directory(self, dirname):
        """Check if a directory name suggests it's a personal user directory"""
        # Common names for personal user directories
        personal_names = {
            'public', 'desktop', 'documents', 'downloads', 'music', 'pictures', 
            'videos', 'favorites', 'contacts', 'links', 'saved games',
            # Common username patterns (simplified)
        }
        return dirname.lower() in personal_names or dirname.startswith('.')
    
    def _get_owner(self, filepath):
        """Get the owner of a file/directory"""
        try:
            if platform.system() != "Windows":
                import pwd
                stat_info = os.stat(filepath)
                return pwd.getpwuid(stat_info.st_uid).pw_name
            else:
                # On Windows, return a placeholder since getting owner requires additional libraries
                return "SYSTEM"  # Simplified for Windows
        except:
            return "unknown"