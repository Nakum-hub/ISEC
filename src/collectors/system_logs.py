"""
System Logs Collector Module
Collects system logs from the host operating system
"""
import os
import platform
import subprocess
import tempfile
from datetime import datetime


class SystemLogsCollector:
    def __init__(self, storage, actor, workstation_id, ip_address):
        self.storage = storage
        self.actor = actor
        self.workstation_id = workstation_id
        self.ip_address = ip_address
    
    def collect(self):
        """Collect system logs based on the operating system"""
        print("Collecting system logs...")
        
        try:
            if platform.system() == "Windows":
                logs = self._collect_windows_logs()
            else:  # Linux, macOS, etc.
                logs = self._collect_unix_logs()
            
            if logs:
                # Store the collected logs as evidence
                self.storage.store_evidence(
                    evidence_type="system_logs",
                    data={
                        'log_count': len(logs),
                        'logs_sample': logs[:5],  # Store only first 5 logs as sample
                        'collection_method': platform.system(),
                        'timestamp': datetime.now().isoformat()
                    },
                    actor=self.actor,
                    workstation_id=self.workstation_id,
                    ip_address=self.ip_address
                )
                print(f"Collected {len(logs)} system log entries")
            else:
                print("No system logs collected")
                
        except Exception as e:
            print(f"Error collecting system logs: {str(e)}")
            # Store error as evidence
            self.storage.store_evidence(
                evidence_type="system_log_collection_error",
                data={
                    'error': str(e),
                    'collection_method': platform.system(),
                    'timestamp': datetime.now().isoformat()
                },
                actor=self.actor,
                workstation_id=self.workstation_id,
                ip_address=self.ip_address
            )
    
    def _collect_windows_logs(self):
        """Collect Windows event logs"""
        logs = []
        
        try:
            # Try to use PowerShell to get recent events
            cmd = [
                "powershell", 
                "-Command", 
                "Get-WinEvent -LogName System -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                import json
                log_data = result.stdout.strip()
                if log_data:
                    # Parse the JSON output
                    parsed_logs = json.loads(log_data)
                    # Ensure it's a list even if only one item
                    if not isinstance(parsed_logs, list):
                        parsed_logs = [parsed_logs]
                    
                    for log_entry in parsed_logs:
                        logs.append({
                            'timestamp': log_entry.get('TimeCreated', ''),
                            'id': log_entry.get('Id', ''),
                            'level': log_entry.get('LevelDisplayName', ''),
                            'message': log_entry.get('Message', '')[:500]  # Limit message length
                        })
            else:
                # If PowerShell fails, we'll try alternative methods
                # For now, we'll just return an empty list as a fallback
                print("Windows event log collection failed, using fallback method")
                
        except subprocess.TimeoutExpired:
            print("Windows event log collection timed out")
        except Exception as e:
            print(f"Error collecting Windows logs: {str(e)}")
        
        return logs
    
    def _collect_unix_logs(self):
        """Collect Unix/Linux system logs"""
        logs = []
        
        try:
            # Try to read system logs from common locations
            log_paths = [
                "/var/log/syslog",  # Debian/Ubuntu
                "/var/log/messages",  # RHEL/CentOS
                "/var/log/system.log"  # macOS
            ]
            
            for log_path in log_paths:
                if os.path.exists(log_path):
                    # Read the last 50 lines of the log file
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        recent_lines = lines[-50:]  # Get last 50 lines
                        
                        for line in recent_lines:
                            line = line.strip()
                            if line:
                                # Parse timestamp from log line (simplified)
                                timestamp = ""
                                if len(line) > 20:
                                    timestamp_part = line[:20]
                                    # Look for common timestamp formats
                                    import re
                                    timestamp_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                                    if timestamp_match:
                                        timestamp = timestamp_match.group()
                                
                                logs.append({
                                    'timestamp': timestamp,
                                    'message': line[:500]  # Limit message length
                                })
                    break  # Stop after finding the first available log file
            
        except Exception as e:
            print(f"Error collecting Unix logs: {str(e)}")
        
        return logs