
#!/usr/bin/env python3
"""
File Integrity Monitor - Detect changes in critical files

This script monitors files and directories for changes by calculating and comparing
hash values at regular intervals. It can detect file modifications, additions, and
deletions, making it useful for security monitoring and compliance.

Features:
- Monitor multiple files and directories
- Detect file modifications, additions, and deletions
- Configurable scan intervals
- Multiple hash algorithms (MD5, SHA-1, SHA-256)
- Email notifications for detected changes
- Baseline creation and comparison
- Detailed logging of all events

Usage:
    python file_integrity_monitor.py --config config.json
    python file_integrity_monitor.py --path /etc/passwd --interval 300

Requirements:
    - Python 3.6+
    - (Optional) smtplib for email notifications
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('file_monitor.log')
    ]
)
logger = logging.getLogger(__name__)

class FileIntegrityMonitor:
    def __init__(self, paths=None, exclude=None, interval=3600, hash_type='sha256',
                 baseline_file='baseline.json', email_config=None, recursive=False):
        """
        Initialize the file integrity monitor.
        
        Args:
            paths (list): List of files and directories to monitor
            exclude (list): List of patterns to exclude from monitoring
            interval (int): Scan interval in seconds
            hash_type (str): Hash algorithm to use (md5, sha1, sha256)
            baseline_file (str): Path to baseline file
            email_config (dict): Email notification configuration
            recursive (bool): Whether to scan directories recursively
        """
        self.paths = paths or []
        self.exclude = exclude or []
        self.interval = interval
        self.hash_type = hash_type.lower()
        self.baseline_file = baseline_file
        self.email_config = email_config
        self.recursive = recursive
        self.baseline = {}
        self.running = True
        
        # Validate hash type
        if self.hash_type not in ['md5', 'sha1', 'sha256']:
            logger.error(f"Invalid hash type: {self.hash_type}. Using sha256.")
            self.hash_type = 'sha256'
    
    def calculate_file_hash(self, file_path):
        """
        Calculate the hash of a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: Hexadecimal hash value or None on error
        """
        try:
            hasher = self._get_hasher()
            
            with open(file_path, 'rb') as f:
                # Read and update hash in chunks for memory efficiency
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
                    
            return hasher.hexdigest()
            
        except PermissionError:
            logger.warning(f"Permission denied: {file_path}")
            return None
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def _get_hasher(self):
        """Get the appropriate hasher object based on the hash type."""
        if self.hash_type == 'md5':
            return hashlib.md5()
        elif self.hash_type == 'sha1':
            return hashlib.sha1()
        else:  # sha256
            return hashlib.sha256()
    
    def scan_paths(self):
        """
        Scan all monitored paths and build a dictionary of file hashes.
        
        Returns:
            dict: Dictionary mapping file paths to their hash values
        """
        scan_result = {}
        file_count = 0
        
        for path in self.paths:
            path = os.path.abspath(path)
            
            if os.path.isfile(path):
                # Single file
                file_hash = self.calculate_file_hash(path)
                if file_hash:
                    scan_result[path] = {
                        'hash': file_hash,
                        'size': os.path.getsize(path),
                        'modified': os.path.getmtime(path)
                    }
                    file_count += 1
                    
            elif os.path.isdir(path):
                # Directory
                for root, dirs, files in os.walk(path):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
                    if not self.recursive:
                        dirs[:] = []  # Clear dirs list to prevent recursion
                        
                    for file in files:
                        file_path = os.path.join(root, file)
                        if not self._is_excluded(file_path):
                            file_hash = self.calculate_file_hash(file_path)
                            if file_hash:
                                scan_result[file_path] = {
                                    'hash': file_hash,
                                    'size': os.path.getsize(file_path),
                                    'modified': os.path.getmtime(file_path)
                                }
                                file_count += 1
            else:
                logger.warning(f"Path does not exist: {path}")
        
        logger.info(f"Scanned {file_count} files")
        return scan_result
    
    def _is_excluded(self, path):
        """Check if a path matches any exclusion pattern."""
        for pattern in self.exclude:
            if pattern in path:
                return True
        return False
    
    def create_baseline(self):
        """Create a new baseline of file hashes."""
        logger.info("Creating new baseline...")
        self.baseline = self.scan_paths()
        
        # Save to file
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'hash_type': self.hash_type,
                    'files': self.baseline
                }, f, indent=2)
            logger.info(f"Baseline saved to {self.baseline_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
            return False
    
    def load_baseline(self):
        """Load baseline from file."""
        if not os.path.exists(self.baseline_file):
            logger.warning(f"Baseline file not found: {self.baseline_file}")
            return False
            
        try:
            with open(self.baseline_file, 'r') as f:
                data = json.load(f)
                self.baseline = data.get('files', {})
                hash_type = data.get('hash_type')
                timestamp = data.get('timestamp')
                
                if hash_type != self.hash_type:
                    logger.warning(
                        f"Baseline uses different hash type ({hash_type}) than currently configured ({self.hash_type})"
                    )
                    
                logger.info(f"Baseline loaded from {self.baseline_file} (created: {timestamp})")
                logger.info(f"Loaded {len(self.baseline)} files in baseline")
                return True
                
        except json.JSONDecodeError:
            logger.error(f"Error parsing baseline file: {self.baseline_file}")
            return False
        except Exception as e:
            logger.error(f"Error loading baseline: {e}")
            return False
    
    def compare_with_baseline(self):
        """
        Compare current state with baseline and detect changes.
        
        Returns:
            tuple: Lists of (modified, added, deleted) files
        """
        if not self.baseline:
            logger.warning("No baseline loaded, cannot compare")
            return [], [], []
            
        current = self.scan_paths()
        
        modified = []
        added = []
        deleted = []
        
        # Check for modified and deleted files
        for path, info in self.baseline.items():
            if path in current:
                if current[path]['hash'] != info['hash']:
                    modified.append(path)
            else:
                deleted.append(path)
        
        # Check for added files
        for path in current:
            if path not in self.baseline:
                added.append(path)
        
        return modified, added, deleted
    
    def send_notification(self, modified, added, deleted):
        """Send email notification about changes."""
        if not self.email_config or not (modified or added or deleted):
            return
            
        try:
            sender = self.email_config.get('sender')
            recipient = self.email_config.get('recipient')
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)
            username = self.email_config.get('username')
            password = self.email_config.get('password')
            
            if not all([sender, recipient, smtp_server]):
                logger.warning("Incomplete email configuration, skipping notification")
                return
                
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = f"File Integrity Alert - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Build message body
            body = "The following file changes were detected:\n\n"
            
            if modified:
                body += "Modified files:\n"
                for path in modified:
                    body += f"  - {path}\n"
                body += "\n"
                
            if added:
                body += "Added files:\n"
                for path in added:
                    body += f"  - {path}\n"
                body += "\n"
                
            if deleted:
                body += "Deleted files:\n"
                for path in deleted:
                    body += f"  - {path}\n"
                body += "\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
                
            logger.info(f"Notification email sent to {recipient}")
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
    
    def monitor_files(self):
        """
        Start the monitoring process.
        
        This function runs in a loop, performing scans at the specified interval.
        """
        logger.info(f"Starting file integrity monitoring")
        logger.info(f"Monitoring {len(self.paths)} paths with {self.hash_type} hashing")
        logger.info(f"Scan interval: {self.interval} seconds")
        
        # Load or create baseline
        if os.path.exists(self.baseline_file):
            self.load_baseline()
        else:
            logger.info("No baseline found, creating new baseline")
            self.create_baseline()
            # Return since we just created a baseline and have nothing to compare against
            return
        
        try:
            while self.running:
                logger.info("Running integrity check...")
                modified, added, deleted = self.compare_with_baseline()
                
                if modified or added or deleted:
                    logger.warning(
                        f"Changes detected: {len(modified)} modified, "
                        f"{len(added)} added, {len(deleted)} deleted"
                    )
                    
                    # Log details of changes
                    for path in modified:
                        logger.warning(f"Modified: {path}")
                    for path in added:
                        logger.warning(f"Added: {path}")
                    for path in deleted:
                        logger.warning(f"Deleted: {path}")
                        
                    # Send notification
                    self.send_notification(modified, added, deleted)
                else:
                    logger.info("No changes detected")
                
                # Wait for next scan
                logger.info(f"Next scan in {self.interval} seconds")
                for _ in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
    
    def start_monitor_thread(self):
        """Start monitoring in a separate thread."""
        thread = threading.Thread(target=self.monitor_files)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self):
        """Stop the monitoring process."""
        self.running = False

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--path", "-p", action="append", help="Path to monitor (can be specified multiple times)")
    parser.add_argument("--exclude", "-e", action="append", help="Pattern to exclude (can be specified multiple times)")
    parser.add_argument("--interval", "-i", type=int, default=3600, help="Scan interval in seconds")
    parser.add_argument("--hash", type=str, choices=["md5", "sha1", "sha256"], default="sha256", help="Hash algorithm")
    parser.add_argument("--baseline", "-b", help="Path to baseline file")
    parser.add_argument("--create-baseline", action="store_true", help="Create a new baseline and exit")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directories recursively")
    
    args = parser.parse_args()
    
    # Load configuration from file or command line arguments
    if args.config:
        config = load_config(args.config)
        if not config:
            sys.exit(1)
            
        monitor = FileIntegrityMonitor(
            paths=config.get('paths', []),
            exclude=config.get('exclude', []),
            interval=config.get('interval', 3600),
            hash_type=config.get('hash_type', 'sha256'),
            baseline_file=config.get('baseline_file', 'baseline.json'),
            email_config=config.get('email', None),
            recursive=config.get('recursive', False)
        )
    else:
        if not args.path:
            logger.error("No paths specified for monitoring")
            parser.print_help()
            sys.exit(1)
            
        monitor = FileIntegrityMonitor(
            paths=args.path,
            exclude=args.exclude or [],
            interval=args.interval,
            hash_type=args.hash,
            baseline_file=args.baseline or 'baseline.json',
            recursive=args.recursive
        )
    
    # Create baseline if requested
    if args.create_baseline:
        if monitor.create_baseline():
            logger.info("Baseline created successfully")
            sys.exit(0)
        else:
            logger.error("Failed to create baseline")
            sys.exit(1)
    
    # Start monitoring
    try:
        monitor.monitor_files()
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    
if __name__ == "__main__":
    main()
