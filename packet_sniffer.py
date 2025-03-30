
#!/usr/bin/env python3
"""
Network Packet Sniffer - Capture and analyze network traffic

This script captures and analyzes network packets, allowing for monitoring of network
traffic, protocol analysis, and basic network forensics. It can filter traffic by
protocol, port, or IP address and save captures to PCAP files.

Features:
- Live packet capture from network interfaces
- Protocol identification and parsing (Ethernet, IP, TCP, UDP, ICMP, HTTP, etc.)
- Filtering by protocol, port, IP address, or custom BPF filters
- Save captured traffic to PCAP files for later analysis
- Traffic statistics and summary reporting

Usage:
    sudo python packet_sniffer.py --interface eth0 --filter "port 80" --count 100
    sudo python packet_sniffer.py --interface eth0 --pcap capture.pcap

Requirements:
    - Python 3.6+
    - Scapy library
    - Root/Administrator privileges for packet capture
"""

import argparse
import datetime
import os
import signal
import sys
import time
import platform
from collections import Counter, defaultdict

try:
    from scapy.all import (
        sniff, wrpcap, IP, TCP, UDP, ICMP, DNS, Ether, 
        Raw, conf, rdpcap, get_if_list
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("Error: This script requires the Scapy library.")
    print("Install it using: pip install scapy")
    sys.exit(1)

# Global variables
running = True
packets_captured = 0
start_time = None
protocol_counter = Counter()
ip_counter = defaultdict(int)
port_counter = defaultdict(int)
http_methods = Counter()

# Check if running with sufficient privileges - cross-platform approach
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

if not is_admin():
    print("Warning: This script should be run with administrator privileges for full functionality.")
    print("Some packet capture features may be limited.")

class PacketSniffer:
    def __init__(self, interface=None, packet_filter=None, count=0, 
                 output_pcap=None, read_pcap=None, verbose=1):
        """
        Initialize the packet sniffer.
        
        Args:
            interface (str): Network interface to listen on
            packet_filter (str): BPF filter string
            count (int): Number of packets to capture (0 for unlimited)
            output_pcap (str): Path to save captured packets
            read_pcap (str): Path to read packets from PCAP file
            verbose (int): Verbosity level (0-3)
        """
        self.interface = interface
        self.packet_filter = packet_filter
        self.count = count
        self.output_pcap = output_pcap
        self.read_pcap = read_pcap
        self.verbose = verbose
        self.packets = []
        
        # Set Scapy verbosity
        conf.verb = 0
    
    def packet_callback(self, packet):
        """Callback function for each captured packet."""
        global packets_captured, protocol_counter, ip_counter, port_counter, http_methods
        
        packets_captured += 1
        self.packets.append(packet)
        
        # Extract timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Basic packet info
        if self.verbose >= 1:
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
            else:
                src_mac = "??"
                dst_mac = "??"
            
            protocol = "???"
            src_ip = "???"
            dst_ip = "???"
            src_port = "??"
            dst_port = "??"
            length = len(packet)
            
            # Protocol identification and parsing
            if IP in packet:
                protocol = "IP"
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_counter[src_ip] += 1
                ip_counter[dst_ip] += 1
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    port_counter[src_port] += 1
                    port_counter[dst_port] += 1
                    
                    # Check for HTTP
                    if dst_port == 80 or src_port == 80:
                        if Raw in packet:
                            try:
                                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                                if payload.startswith(('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS')):
                                    protocol = "HTTP"
                                    method = payload.split(' ')[0]
                                    http_methods[method] += 1
                            except:
                                pass
                                
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    port_counter[src_port] += 1
                    port_counter[dst_port] += 1
                    
                    # Check for DNS
                    if dst_port == 53 or src_port == 53:
                        if DNS in packet:
                            protocol = "DNS"
                            
                elif ICMP in packet:
                    protocol = "ICMP"
            
            protocol_counter[protocol] += 1
            
            # Print packet info based on verbosity
            if self.verbose == 1:
                print(f"{timestamp} {protocol:<5} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({length} bytes)")
            elif self.verbose == 2:
                print(f"{timestamp} {protocol:<5} {src_mac} -> {dst_mac} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({length} bytes)")
            elif self.verbose >= 3:
                print(f"\n{'='*80}")
                print(f"{timestamp} - Packet #{packets_captured}")
                print(f"{'='*80}")
                packet.show()
        
        # Check if we've reached the packet count limit
        if self.count > 0 and packets_captured >= self.count:
            return True
    
    def start_capture(self):
        """Start the packet capture process."""
        global running, start_time, packets_captured
        packets_captured = 0
        start_time = time.time()
        
        print(f"Starting packet capture on {self.interface or 'default interface'}")
        if self.packet_filter:
            print(f"Filter: {self.packet_filter}")
        
        if self.count > 0:
            print(f"Capturing {self.count} packets...")
        else:
            print("Capturing packets until interrupted (Ctrl+C to stop)...")
        
        try:
            # Register signal handler for graceful exit
            signal.signal(signal.SIGINT, self._signal_handler)
            
            # Start sniffing
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self.packet_callback,
                store=False,
                count=self.count if self.count > 0 else None
            )
            
        except Exception as e:
            print(f"Error during packet capture: {e}")
        finally:
            # Save captured packets if requested
            if self.output_pcap and self.packets:
                self._save_pcap()
                
            self._print_statistics()
    
    def analyze_pcap(self):
        """Analyze an existing PCAP file."""
        global running, start_time, packets_captured
        packets_captured = 0
        start_time = time.time()
        
        print(f"Analyzing PCAP file: {self.read_pcap}")
        
        try:
            # Load and process PCAP file
            pcap_packets = rdpcap(self.read_pcap)
            for packet in pcap_packets:
                self.packet_callback(packet)
            
            self._print_statistics()
            
        except Exception as e:
            print(f"Error analyzing PCAP file: {e}")
    
    def _save_pcap(self):
        """Save captured packets to a PCAP file."""
        if not self.packets:
            return
            
        try:
            wrpcap(self.output_pcap, self.packets)
            print(f"Saved {len(self.packets)} packets to {self.output_pcap}")
        except Exception as e:
            print(f"Error saving PCAP file: {e}")
    
    def _print_statistics(self):
        """Print capture statistics."""
        global protocol_counter, ip_counter, port_counter, http_methods, start_time
        
        duration = time.time() - start_time
        
        print("\n" + "=" * 50)
        print(f"Capture Statistics")
        print("=" * 50)
        print(f"Total packets captured: {packets_captured}")
        print(f"Capture duration: {duration:.2f} seconds")
        print(f"Packets per second: {packets_captured/duration:.2f}" if duration > 0 else "Packets per second: N/A")
        
        # Protocol distribution
        print("\nProtocol Distribution:")
        for protocol, count in protocol_counter.most_common():
            percentage = (count / packets_captured) * 100 if packets_captured > 0 else 0
            print(f"  {protocol:<6}: {count:>5} ({percentage:.1f}%)")
        
        # Top talkers (IP addresses)
        if ip_counter:
            print("\nTop IP Addresses:")
            for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / sum(ip_counter.values())) * 100
                print(f"  {ip:<15}: {count:>5} ({percentage:.1f}%)")
        
        # Top ports
        if port_counter:
            print("\nTop Ports:")
            for port, count in sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / sum(port_counter.values())) * 100
                print(f"  {port:<6}: {count:>5} ({percentage:.1f}%)")
        
        # HTTP methods (if any)
        if http_methods:
            print("\nHTTP Methods:")
            for method, count in http_methods.most_common():
                print(f"  {method:<7}: {count}")
    
    def _signal_handler(self, sig, frame):
        """Handle interrupt signal for graceful exit."""
        global running
        print("\nCapture interrupted by user.")
        running = False
        
        # Save captured packets if requested
        if self.output_pcap and self.packets:
            self._save_pcap()
            
        self._print_statistics()
        sys.exit(0)

def get_available_interfaces():
    """Get a list of available network interfaces."""
    try:
        return get_if_list()
    except:
        return []

def main():
    # Get available interfaces
    interfaces = get_available_interfaces()
    
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("--interface", "-i", help="Network interface to listen on")
    parser.add_argument("--filter", "-f", help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("--verbose", "-v", action="count", default=1, help="Increase output verbosity")
    parser.add_argument("--pcap", "-w", help="Save captured packets to PCAP file")
    parser.add_argument("--read", "-r", help="Read and analyze packets from PCAP file")
    parser.add_argument("--list-interfaces", "-l", action="store_true", help="List available network interfaces")
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        return
    
    # Create the packet sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        packet_filter=args.filter,
        count=args.count,
        output_pcap=args.pcap,
        read_pcap=args.read,
        verbose=args.verbose
    )
    
    # Either analyze a PCAP file or start a live capture
    if args.read:
        sniffer.analyze_pcap()
    else:
        sniffer.start_capture()

if __name__ == "__main__":
    main()
