#!/usr/bin/env python3
"""
Port Scanner - Multi-threaded network port scanner

This script performs TCP port scanning on target hosts to identify open ports and
running services. It supports scanning individual IP addresses, CIDR notation, and
hostname targets.

Features:
- Multi-threaded scanning for improved performance
- Service version detection (banner grabbing)
- Common port scanning or full range scans
- Timeout controls to handle unresponsive hosts

Usage:
    python port_scanner.py --target 192.168.1.0/24 --ports 22,80,443-445 --threads 50

Requirements:
    - Python 3.6+
"""

import argparse
import socket
import ipaddress
import threading
import time
import sys
import concurrent.futures
import platform
from datetime import datetime

# Common ports to scan if none specified
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Dictionary of common services for port identification
PORT_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy"
}

class PortScanner:
    def __init__(self, timeout=1.0):
        """
        Initialize the port scanner.
        
        Args:
            timeout (float): Timeout in seconds for socket connections
        """
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()
    
    def scan_port(self, ip, port):
        """
        Scan a single port on the specified IP address.
        
        Args:
            ip (str): IP address to scan
            port (int): Port number to scan
            
        Returns:
            tuple: (ip, port, is_open, banner)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        banner = ""
        
        try:
            start_time = time.time()
            result = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            
            if result == 0:
                # Port is open, try to get banner
                try:
                    sock.send(b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
                    banner = sock.recv(1024).strip().decode('utf-8', errors='ignore')[:100]
                except:
                    # If HTTP request fails, try a basic connection banner
                    try:
                        banner = sock.recv(1024).strip().decode('utf-8', errors='ignore')[:100]
                    except:
                        pass
                
                service = PORT_MAP.get(port, "Unknown")
                with self.lock:
                    self.results.append((ip, port, True, service, banner, response_time))
                return ip, port, True, service, banner, response_time
        except socket.error:
            pass
        finally:
            sock.close()
        
        return ip, port, False, "", "", 0
        
    def scan(self, targets, ports, threads=50):
        """
        Scan the specified targets and ports.
        
        Args:
            targets (list): List of IP addresses to scan
            ports (list): List of ports to scan
            threads (int): Number of threads to use
            
        Returns:
            list: Results of the scan
        """
        start_time = time.time()
        total_ports = len(targets) * len(ports)
        completed = 0
        results = []
        
        print(f"Starting scan of {len(targets)} host(s) on {len(ports)} port(s) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Using {threads} threads with {self.timeout}s timeout")
        
        # Use a thread pool for scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_scan = {
                executor.submit(self.scan_port, ip, port): (ip, port) 
                for ip in targets for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_scan):
                ip, port = future_to_scan[future]
                completed += 1
                
                # Print progress every 10 ports or when scan completes
                if completed % 10 == 0 or completed == total_ports:
                    percent_done = (completed / total_ports) * 100
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    remaining = (total_ports - completed) / rate if rate > 0 else 0
                    
                    sys.stdout.write(f"\rProgress: {completed}/{total_ports} ({percent_done:.1f}%) "
                                    f"- {rate:.1f} ports/sec - ETA: {remaining:.0f}s")
                    sys.stdout.flush()
        
        print("\nScan completed in {:.2f} seconds".format(time.time() - start_time))
        return self.results
    
    def print_results(self):
        """Print the scan results in a formatted table."""
        if not self.results:
            print("No open ports found.")
            return
            
        # Sort results by IP and port
        sorted_results = sorted(self.results, key=lambda x: (socket.inet_aton(x[0]), x[1]))
        
        print("\nOpen Ports:")
        print("-" * 90)
        print(f"{'IP Address':<15} {'Port':<6} {'Service':<10} {'Response Time':<14} {'Banner'}")
        print("-" * 90)
        
        for ip, port, is_open, service, banner, response_time in sorted_results:
            if is_open:
                banner_display = banner[:40] + "..." if len(banner) > 40 else banner
                banner_display = banner_display.replace('\n', ' ').replace('\r', '')
                print(f"{ip:<15} {port:<6} {service:<10} {response_time*1000:>8.1f} ms    {banner_display}")

def parse_port_range(port_string):
    """
    Parse port specification string into a list of ports.
    
    Formats:
    - Individual ports: "80,443,8080"
    - Port ranges: "1-1000"
    - Mixed: "80,443,1000-2000"
    
    Args:
        port_string (str): String specifying ports to scan
        
    Returns:
        list: List of port numbers
    """
    ports = []
    if not port_string:
        return COMMON_PORTS
        
    for item in port_string.split(','):
        item = item.strip()
        if '-' in item:
            start, end = map(int, item.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return ports

def parse_targets(target_string):
    """
    Parse target specification into a list of IP addresses.
    
    Formats:
    - Individual IP: "192.168.1.1"
    - CIDR notation: "192.168.1.0/24"
    - Hostname: "example.com"
    
    Args:
        target_string (str): String specifying targets to scan
        
    Returns:
        list: List of IP addresses
    """
    targets = []
    
    for target in target_string.split(','):
        target = target.strip()
        
        try:
            # Check if target is CIDR notation
            if '/' in target:
                for ip in ipaddress.IPv4Network(target, strict=False):
                    targets.append(str(ip))
            # Check if target is an IP address
            elif target.replace('.', '').isdigit() and len(target.split('.')) == 4:
                targets.append(target)
            # Assume target is a hostname
            else:
                ip = socket.gethostbyname(target)
                targets.append(ip)
        except (socket.gaierror, ValueError) as e:
            print(f"Error resolving target {target}: {e}")
    
    return targets

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
    parser = argparse.ArgumentParser(description="Multi-threaded TCP port scanner")
    parser.add_argument("--target", "-t", required=True, 
                        help="Target(s) to scan (IP, CIDR, or hostname, comma-separated)")
    parser.add_argument("--ports", "-p", default="",
                        help="Port(s) to scan (e.g., 80,443,8080 or 1-1000)")
    parser.add_argument("--threads", "-n", type=int, default=50,
                        help="Number of threads to use (default: 50)")
    parser.add_argument("--timeout", "-w", type=float, default=1.0,
                        help="Timeout in seconds for each connection attempt (default: 1.0)")
    
    args = parser.parse_args()
    
    # Check for administrator privileges and warn if needed
    if not is_admin() and platform.system() == 'Windows':
        print("Warning: Some network operations may require administrator privileges.")
        print("Consider running this script as administrator for full functionality.")
    
    try:
        targets = parse_targets(args.target)
        if not targets:
            print("No valid targets specified.")
            return
            
        ports = parse_port_range(args.ports)
        if not ports:
            print("No valid ports specified.")
            return
            
        scanner = PortScanner(timeout=args.timeout)
        scanner.scan(targets, ports, threads=args.threads)
        scanner.print_results()
        
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
