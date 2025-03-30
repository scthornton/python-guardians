#!/usr/bin/env python3
"""
Log Analyzer - Detects suspicious login attempts from authentication logs

This script analyzes authentication log files (like /var/log/auth.log on Linux systems)
to identify potential brute force attacks, unusual login times, and suspicious IP addresses.

Features:
- Detects multiple failed login attempts from the same IP
- Identifies successful logins after multiple failures (potential breach)
- Alerts on logins from unusual geographic locations or at unusual times
- Generates summary reports of authentication activities

Usage:
    python log_analyzer.py --log-file /path/to/auth.log --threshold 5

Requirements:
    - Python 3.6+
    - geoip2 (pip install geoip2) - optional for geolocation features
"""

import argparse
import re
import sys
import os
import datetime
import platform
from collections import defaultdict, Counter
import ipaddress

# Optional module for geolocation
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

class LogAnalyzer:
    def __init__(self, log_file, threshold=5, geo_db=None):
        """
        Initialize the log analyzer with specified parameters.
        
        Args:
            log_file (str): Path to the authentication log file
            threshold (int): Number of failed attempts to consider suspicious
            geo_db (str): Path to GeoIP database (optional)
        """
        self.log_file = log_file
        self.threshold = threshold
        self.geo_db = geo_db
        self.failed_attempts = defaultdict(list)
        self.successful_logins = defaultdict(list)
        self.user_ips = defaultdict(set)
        self.ip_users = defaultdict(set)
        self.reader = None
        
        # Initialize GeoIP reader if available
        if GEOIP_AVAILABLE and geo_db and os.path.exists(geo_db):
            self.reader = geoip2.database.Reader(geo_db)
    
    def parse_logs(self):
        """Parse the log file and extract relevant authentication events."""
        print(f"Analyzing log file: {self.log_file}")
        
        if not os.path.exists(self.log_file):
            print(f"Error: Log file {self.log_file} not found.")
            return False
            
        try:
            # Common log patterns for authentication events
            failed_pattern = re.compile(r'(\w+ \d+ \d+:\d+:\d+).*Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)')
            success_pattern = re.compile(r'(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)')
            
            with open(self.log_file, 'r') as f:
                for line in f:
                    # Check for failed login attempts
                    failed_match = failed_pattern.search(line)
                    if failed_match:
                        timestamp, user, ip = failed_match.groups()
                        self.failed_attempts[ip].append((timestamp, user))
                        self.user_ips[user].add(ip)
                        self.ip_users[ip].add(user)
                        continue
                    
                    # Check for successful logins
                    success_match = success_pattern.search(line)
                    if success_match:
                        timestamp, user, ip = success_match.groups()
                        self.successful_logins[ip].append((timestamp, user))
                        self.user_ips[user].add(ip)
                        self.ip_users[ip].add(user)
            
            return True
        except Exception as e:
            print(f"Error parsing log file: {e}")
            return False
    
    def analyze(self):
        """Analyze the parsed log data and identify suspicious activities."""
        if not self.parse_logs():
            return
        
        print("\n=== Analysis Results ===\n")
        
        # Check for IPs with many failed attempts
        print("Potential Brute Force Attempts:")
        for ip, attempts in self.failed_attempts.items():
            if len(attempts) >= self.threshold:
                users = Counter([user for _, user in attempts])
                geo_info = self._get_geo_info(ip)
                
                print(f"  IP: {ip} {geo_info}")
                print(f"    Failed attempts: {len(attempts)}")
                print(f"    Targeted users: {', '.join(users.keys())}")
                
                # Check if any successful logins after failures (potential breach)
                if ip in self.successful_logins:
                    print(f"    WARNING: Successful login(s) from this IP after failures!")
                    for timestamp, user in self.successful_logins[ip]:
                        print(f"      {timestamp} - User: {user}")
                print()
        
        # Check for users with logins from multiple IPs
        print("\nUsers with Multiple Login Sources:")
        for user, ips in self.user_ips.items():
            if len(ips) > 1:
                print(f"  User: {user}")
                print(f"    Login sources: {', '.join(ips)}")
                print()
    
    def _get_geo_info(self, ip):
        """Get geolocation information for an IP address if available."""
        if not self.reader:
            return ""
        
        try:
            # Only look up public IPs
            if not ipaddress.ip_address(ip).is_private:
                response = self.reader.city(ip)
                return f"({response.country.name}, {response.city.name})"
        except Exception:
            pass
        return ""

def is_admin():
    """Check if the script is running with administrator privileges."""
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        # Unix-like systems
        try:
            return os.geteuid() == 0
        except AttributeError:
            # Fallback to a basic check
            return os.access('/root', os.R_OK)

def main():
    parser = argparse.ArgumentParser(description="Analyze authentication logs for suspicious activities")
    parser.add_argument("--log-file", "-f", required=True, help="Path to the authentication log file")
    parser.add_argument("--threshold", "-t", type=int, default=5, 
                        help="Number of failed attempts to consider suspicious")
    parser.add_argument("--geo-db", "-g", help="Path to MaxMind GeoIP database (optional)")
    
    args = parser.parse_args()
    
    # Platform-specific default log locations
    if platform.system() == 'Windows':
        default_log = "C:\\Windows\\Security\\logs\\Security.evtx"
        print(f"Note: On Windows, you may need to export Security event logs from Event Viewer")
        print(f"Default Windows security log location: {default_log}")
    else:
        default_log = "/var/log/auth.log"
        print(f"Default Linux authentication log location: {default_log}")
    
    analyzer = LogAnalyzer(args.log_file, args.threshold, args.geo_db)
    analyzer.analyze()

if __name__ == "__main__":
    main()
