"""
Network Connections Collector Module
Captures network connection snapshots from the host system
"""
import subprocess
import platform
import re
from datetime import datetime


class NetworkConnectionsCollector:
    def __init__(self, storage, actor, workstation_id, ip_address):
        self.storage = storage
        self.actor = actor
        self.workstation_id = workstation_id
        self.ip_address = ip_address
    
    def collect(self):
        """Collect network connection information"""
        print("Collecting network connections...")
        
        try:
            if platform.system() == "Windows":
                connections = self._get_windows_connections()
            else:  # Linux, macOS, etc.
                connections = self._get_unix_connections()
            
            if connections:
                # Store the collected connections as evidence
                self.storage.store_evidence(
                    evidence_type="network_connections",
                    data={
                        'connection_count': len(connections),
                        'connections_sample': connections[:10],  # Store only first 10 as sample
                        'collection_method': platform.system(),
                        'timestamp': datetime.now().isoformat()
                    },
                    actor=self.actor,
                    workstation_id=self.workstation_id,
                    ip_address=self.ip_address
                )
                print(f"Collected {len(connections)} network connections")
            else:
                print("No network connections collected")
                
        except Exception as e:
            print(f"Error collecting network connections: {str(e)}")
            # Store error as evidence
            self.storage.store_evidence(
                evidence_type="network_connection_collection_error",
                data={
                    'error': str(e),
                    'collection_method': platform.system(),
                    'timestamp': datetime.now().isoformat()
                },
                actor=self.actor,
                workstation_id=self.workstation_id,
                ip_address=self.ip_address
            )
    
    def _get_windows_connections(self):
        """Get network connections on Windows using netstat"""
        connections = []
        
        try:
            # Run netstat command to get active connections
            result = subprocess.run(
                ["netstat", "-an", "-p", "TCP"], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for line in lines[4:]:  # Skip header lines
                    parts = line.split()
                    if len(parts) >= 4:
                        protocol = parts[0]
                        local_addr = parts[1]
                        foreign_addr = parts[2]
                        state = parts[3] if len(parts) > 3 else "UNKNOWN"
                        
                        # Parse local address
                        local_match = re.match(r'(.+):(\d+)', local_addr)
                        if local_match:
                            local_ip, local_port = local_match.groups()
                        else:
                            local_ip, local_port = "unknown", "unknown"
                        
                        # Parse foreign address
                        foreign_match = re.match(r'(.+):(\d+)', foreign_addr)
                        if foreign_match:
                            foreign_ip, foreign_port = foreign_match.groups()
                        else:
                            foreign_ip, foreign_port = "unknown", "unknown"
                        
                        connections.append({
                            'protocol': protocol,
                            'local_ip': local_ip,
                            'local_port': local_port,
                            'foreign_ip': foreign_ip,
                            'foreign_port': foreign_port,
                            'state': state,
                            'timestamp': datetime.now().isoformat()
                        })
            
        except subprocess.TimeoutExpired:
            print("Network connection collection timed out")
        except Exception as e:
            print(f"Error getting Windows network connections: {str(e)}")
        
        return connections
    
    def _get_unix_connections(self):
        """Get network connections on Unix-like systems using netstat or ss"""
        connections = []
        
        def split_host_port(address):
            if address.startswith('[') and ']' in address:
                host = address[1:address.rfind(']')]
                port = address[address.rfind(':') + 1:]
                return host, port
            if ':' in address:
                host, port = address.rsplit(':', 1)
                return host, port
            return address, "unknown"
        
        try:
            # Try to use netstat first, fall back to ss if not available
            cmd = ["netstat", "-tuln"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            used_ss = False
            
            # If netstat fails, try ss command
            if result.returncode != 0:
                cmd = ["ss", "-tuln"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                used_ss = True
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                is_ss_output = used_ss or any(line.strip().startswith("Netid") for line in lines)
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("Active Internet connections") or line.startswith("Proto") or line.startswith("Netid"):
                        continue
                    
                    parts = line.split()
                    if is_ss_output:
                        # ss: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
                        if len(parts) < 6:
                            continue
                        protocol = parts[0]
                        state = parts[1]
                        local_addr = parts[4]
                        foreign_addr = parts[5]
                    else:
                        # netstat: Proto Recv-Q Send-Q Local Address Foreign Address State
                        if len(parts) < 6:
                            continue
                        protocol = parts[0]
                        local_addr = parts[3]
                        foreign_addr = parts[4]
                        state = parts[5]
                    
                    local_ip, local_port = split_host_port(local_addr)
                    foreign_ip, foreign_port = split_host_port(foreign_addr)
                    
                    connections.append({
                        'protocol': protocol,
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'foreign_ip': foreign_ip,
                        'foreign_port': foreign_port,
                        'state': state,
                        'timestamp': datetime.now().isoformat()
                    })
            
        except subprocess.TimeoutExpired:
            print("Network connection collection timed out")
        except Exception as e:
            print(f"Error getting Unix network connections: {str(e)}")
        
        return connections
