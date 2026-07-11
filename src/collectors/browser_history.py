"""
Browser History Collector Module
Collects browser history metadata from installed browsers with consent enforcement
"""
import os
import sqlite3
import shutil
import json
from datetime import datetime, timedelta
from pathlib import Path
import getpass
import platform
import socket

from src.collectors.base import BaseCollector, register_collector


@register_collector
class BrowserHistoryCollector(BaseCollector):
    evidence_type = "browser_history"
    display_label = "Collecting browser history metadata..."
    requires_consent = True

    def __init__(self, storage, actor, workstation_id, ip_address):
        super().__init__(storage, actor, workstation_id, ip_address)
        
        # Initialize consent manager to check consent status
        from src.utils.consent_manager import get_consent_manager
        self.consent_manager = get_consent_manager(self.storage)
        
        # Check browser consent status
        self.browser_consent_status = self.consent_manager.check_consent_status('browser_data')
        self.browser_consent_granted = self.browser_consent_status['status'] == 'GRANTED'
        
        if not self.browser_consent_granted:
            print("Browser history collection requires explicit consent. Collection will be skipped.")
    
    def _get_available_browsers(self):
        """Get list of available browsers on the system"""
        browsers = []
        
        # Check for Chrome
        if os.name == 'nt':  # Windows
            chrome_paths = [
                os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data'),
                os.path.expandvars(r'%PROGRAMFILES%\Google\Chrome\Application\chrome.exe'),
                os.path.expandvars(r'%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe')
            ]
        else:  # Linux/Mac
            chrome_paths = [
                os.path.expanduser('~/.config/google-chrome'),
                os.path.expanduser('~/Library/Application Support/Google/Chrome'),
                '/usr/bin/google-chrome',
                '/Applications/Google Chrome.app'
            ]
        
        if any(os.path.exists(path) for path in chrome_paths if path):
            browsers.append('Chrome')
        
        # Check for Firefox
        if os.name == 'nt':  # Windows
            firefox_paths = [
                os.path.expandvars(r'%APPDATA%\Mozilla\Firefox'),
                os.path.expandvars(r'%PROGRAMFILES%\Mozilla Firefox\firefox.exe'),
                os.path.expandvars(r'%PROGRAMFILES(X86)%\Mozilla Firefox\firefox.exe')
            ]
        else:  # Linux/Mac
            firefox_paths = [
                os.path.expanduser('~/.mozilla/firefox'),
                os.path.expanduser('~/Library/Application Support/Firefox'),
                '/usr/bin/firefox',
                '/Applications/Firefox.app'
            ]
        
        if any(os.path.exists(path) for path in firefox_paths if path):
            browsers.append('Firefox')
        
        # Check for Microsoft Edge
        if os.name == 'nt':  # Windows
            edge_paths = [
                os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data'),
                os.path.expandvars(r'%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe'),
                os.path.expandvars(r'%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe')
            ]
            
            if any(os.path.exists(path) for path in edge_paths if path):
                browsers.append('Microsoft Edge')
        
        return browsers
    
    def collect(self):
        """Collect browser history with consent enforcement"""
        # Re-evaluate consent status on each collection attempt
        self.browser_consent_status = self.consent_manager.check_consent_status('browser_data')
        self.browser_consent_granted = self.browser_consent_status['status'] == 'GRANTED'
        
        if not self.browser_consent_granted:
            print("Browser history collection skipped due to lack of consent.")
            # Still store a record that collection was attempted but skipped due to consent
            consent_details = self.browser_consent_status.get('details', {})
            self.storage.store_evidence(
                evidence_type="browser_history_skipped",
                data={
                    'reason': 'consent_denied',
                    'consent_status': self.browser_consent_status['status'],
                    'browsers_available': self._get_available_browsers(),
                    'timestamp': datetime.now().isoformat()
                },
                actor=self.actor,
                workstation_id=self.workstation_id,
                ip_address=self.ip_address
            )
            return
        
        print("Collecting browser history metadata...")
        
        # Get the browsers and time range from consent details
        consent_details = self.browser_consent_status.get('details', {})
        selected_browsers = consent_details.get('browsers', self._get_available_browsers())
        time_range = consent_details.get('time_range', 'all_time')
        
        # Map time ranges to datetime thresholds
        time_thresholds = {
            'last_24h': datetime.now() - timedelta(hours=24),
            'last_7d': datetime.now() - timedelta(days=7),
            'last_30d': datetime.now() - timedelta(days=30),
            'all_time': datetime.min
        }
        cutoff_date = time_thresholds.get(time_range, datetime.min)
        
        for browser in selected_browsers:
            try:
                history_data = self._collect_browser_history(browser, cutoff_date)
                
                if history_data:
                    # Store browser history metadata
                    self.storage.store_evidence(
                        evidence_type="browser_history",
                        data={
                            'browser': browser,
                            'history_count': len(history_data),
                            'history_entries': history_data[:10],  # Limit to first 10 entries for storage efficiency
                            'collection_params': {
                                'time_range': time_range,
                                'cutoff_date': cutoff_date.isoformat()
                            },
                            'timestamp': datetime.now().isoformat()
                        },
                        actor=self.actor,
                        workstation_id=self.workstation_id,
                        ip_address=self.ip_address
                    )
                    
                    print(f"Collected {len(history_data)} history entries from {browser}")
                else:
                    print(f"No history found for {browser}")
                    
            except Exception as e:
                print(f"Error collecting history from {browser}: {str(e)}")
                # Log the error as evidence
                self.storage.store_evidence(
                    evidence_type="browser_collection_error",
                    data={
                        'browser': browser,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    },
                    actor=self.actor,
                    workstation_id=self.workstation_id,
                    ip_address=self.ip_address
                )
    
    def _collect_browser_history(self, browser, cutoff_date):
        """Collect history from a specific browser"""
        history_data = []
        
        # Define profile paths for different browsers
        if browser.lower() == 'chrome':
            if os.name == 'nt':  # Windows
                profile_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History')
            else:  # Linux/Mac
                profile_path = os.path.expanduser('~/.config/google-chrome/Default/History')
                
        elif browser.lower() == 'firefox':
            # Firefox uses JSON files, but for simplicity we'll look for places.sqlite
            if os.name == 'nt':  # Windows
                profiles_dir = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
            else:  # Linux/Mac
                profiles_dir = os.path.expanduser('~/.mozilla/firefox')
            
            # Find the default profile
            if os.path.exists(profiles_dir):
                for profile in os.listdir(profiles_dir):
                    if profile.endswith('.default') or profile.endswith('.default-release'):
                        profile_path = os.path.join(profiles_dir, profile, 'places.sqlite')
                        break
                else:
                    return []  # No suitable profile found
            else:
                return []
                
        elif browser.lower() == 'microsoft edge':
            if os.name == 'nt':  # Windows
                profile_path = os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History')
            else:
                return []  # Edge is primarily Windows
        else:
            return []
        
        # Check if the history database exists
        if not os.path.exists(profile_path):
            return []
        
        # Create a temporary copy of the database to avoid locking issues
        temp_path = f"{profile_path}_temp_copy"
        conn = None
        try:
            shutil.copy2(profile_path, temp_path)
            
            # Connect to the copied database
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            # Query browser history based on browser type
            if 'firefox' in browser.lower():
                # Firefox uses places.sqlite
                cursor.execute("""
                    SELECT 
                        moz_places.url,
                        moz_places.title,
                        datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') as visit_time,
                        moz_historyvisits.visit_type
                    FROM moz_places
                    JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                    WHERE moz_historyvisits.visit_date/1000000 > ?
                    ORDER BY moz_historyvisits.visit_date DESC
                    LIMIT 100
                """, (int(cutoff_date.timestamp()),))
            else:
                # Chrome and Edge use similar schema
                cursor.execute("""
                    SELECT 
                        url,
                        title,
                        datetime(last_visit_time/1000000-11644473600, 'unixepoch') as visit_time,
                        visit_count
                    FROM urls
                    WHERE last_visit_time/1000000-11644473600 > ?
                    ORDER BY last_visit_time DESC
                    LIMIT 100
                """, (int(cutoff_date.timestamp()),))
            
            rows = cursor.fetchall()
            
            for row in rows:
                url = row[0]
                title = row[1] if row[1] else "No Title"
                visit_time = row[2]
                
                # Only add if the visit time is after our cutoff date
                try:
                    visit_datetime = datetime.strptime(visit_time, '%Y-%m-%d %H:%M:%S')
                    if visit_datetime >= cutoff_date:
                        history_data.append({
                            'url': url,
                            'title': title,
                            'visit_time': visit_time,
                            'timestamp': visit_datetime.isoformat()
                        })
                except ValueError:
                    # Skip if we can't parse the date
                    continue
            
        except Exception as e:
            print(f"Error reading {browser} history database: {str(e)}")
        finally:
            # Always close before removing the temp copy: an open SQLite
            # handle keeps the file locked on Windows and os.remove would
            # fail with WinError 32.
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
        return history_data
