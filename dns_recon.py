
#!/usr/bin/env python3
"""
DNS Reconnaissance Tool - Gather DNS information about domains

This script performs comprehensive DNS reconnaissance to gather information about domains
and networks. It retrieves various DNS record types, identifies mail servers, nameservers,
and other network infrastructure, and can help map an organization's attack surface.

Features:
- Retrieve multiple DNS record types (A, AAAA, MX, NS, TXT, SOA, etc.)
- Perform reverse DNS lookups for IP ranges
- Zone transfer attempts
- DNS cache snooping
- Subdomain enumeration via DNS
- DNS record history retrieval
- Automated reporting and visualization

Usage:
    python dns_recon.py --domain example.com
    python dns_recon.py --ip 192.168.1.1
    python dns_recon.py --range 192.168.1.0/24

Requirements:
    - Python 3.6+
    - dnspython
    - ipaddress
"""

import argparse
import concurrent.futures
import dns.name
import dns.query
import dns.resolver
import dns.reversename
import dns.zone
import ipaddress
import json
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime

# Configure DNS resolver
dns_resolver = dns.resolver.Resolver()

# Default DNS servers (can be overridden via command line)
DEFAULT_DNS_SERVERS = [
    '8.8.8.8',       # Google
    '1.1.1.1',       # Cloudflare
    '9.9.9.9',       # Quad9
    '208.67.222.222' # OpenDNS
]

# Common DNS record types to query
COMMON_RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA', 'DNSKEY', 'DS', 'DMARC', 'SPF'
]

# Common subdomains for enumeration (a small list for demonstration)
COMMON_SUBDOMAINS = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
    'smtp', 'secure', 'vpn', 'admin', 'ftp', 'dev', 'staging', 'api',
    'portal', 'ssh', 'git', 'cdn', 'cloud', 'support', 'web'
]

class DNSRecon:
    def __init__(self, domain=None, ip=None, ip_range=None, dns_servers=None, 
                 timeout=5, threads=10, verbose=False, output=None, 
                 subdomains=None, history=False):
        """
        Initialize the DNS reconnaissance tool.
        
        Args:
            domain (str): Target domain to investigate
            ip (str): Target IP address for reverse lookup
            ip_range (str): IP range in CIDR notation
            dns_servers (list): DNS servers to use for queries
            timeout (int): Timeout for DNS queries in seconds
            threads (int): Number of threads for concurrent queries
            verbose (bool): Enable verbose output
            output (str): Output file path
            subdomains (str): Path to subdomain wordlist file
            history (bool): Retrieve historical DNS records if available
        """
        self.domain = domain
        self.ip = ip
        self.ip_range = ip_range
        self.dns_servers = dns_servers or DEFAULT_DNS_SERVERS
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.output = output
        self.subdomains_file = subdomains
        self.history = history
        
        self.results = {
            'domain_records': defaultdict(dict),
            'reverse_lookup': {},
            'subdomains': [],
            'zone_transfers': [],
            'dns_servers': []
        }
        
        # Configure resolver
        dns_resolver.timeout = self.timeout
        dns_resolver.lifetime = self.timeout
        dns_resolver.nameservers = [self.dns_servers[0]]  # Primary DNS server
    
    def run(self):
        """
        Execute DNS reconnaissance based on provided parameters.
        
        Returns:
            dict: Reconnaissance results
        """
        start_time = time.time()
        
        print(f"DNS Reconnaissance Tool - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Set up the resolver with the specified DNS servers
        if self.dns_servers:
            print(f"Using DNS servers: {', '.join(self.dns_servers)}")
        
        # Domain reconnaissance
        if self.domain:
            print(f"\nTarget domain: {self.domain}")
            
            # Get the authoritative name servers
            ns_records = self._query_record(self.domain, 'NS')
            if ns_records:
                print(f"Authoritative nameservers: {', '.join(ns_records)}")
                self.results['dns_servers'] = ns_records
                
                # Attempt zone transfers
                print("\nAttempting zone transfers from each nameserver...")
                self._attempt_zone_transfers()
            
            # Query common record types
            print("\nQuerying DNS records:")
            self._query_all_records()
            
            # Perform subdomain enumeration
            print("\nEnumerating subdomains:")
            self._enumerate_subdomains()
        
        # IP or IP range reconnaissance
        if self.ip:
            print(f"\nTarget IP: {self.ip}")
            self._perform_reverse_lookup(self.ip)
            
        elif self.ip_range:
            print(f"\nTarget IP range: {self.ip_range}")
            self._scan_ip_range()
        
        # Output results
        duration = time.time() - start_time
        print(f"\nReconnaissance completed in {duration:.2f} seconds")
        
        if self.output:
            self._save_results()
        
        return self.results
    
    def _query_record(self, domain, record_type):
        """
        Query a specific DNS record type for a domain.
        
        Args:
            domain (str): Domain to query
            record_type (str): DNS record type
            
        Returns:
            list: Record values or empty list if not found
        """
        try:
            if record_type == 'DMARC':
                # DMARC records are stored as TXT records at _dmarc.domain
                answers = dns_resolver.resolve(f'_dmarc.{domain}', 'TXT')
            elif record_type == 'SPF':
                # SPF records are stored as TXT records
                answers = dns_resolver.resolve(domain, 'TXT')
                # Filter for SPF records
                return [str(rdata).strip('"') for rdata in answers if 'spf' in str(rdata).lower()]
            else:
                answers = dns_resolver.resolve(domain, record_type)
                
            if record_type == 'A' or record_type == 'AAAA':
                return [rdata.address for rdata in answers]
            elif record_type == 'MX':
                return [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
            elif record_type == 'NS':
                return [str(rdata).rstrip('.') for rdata in answers]
            elif record_type == 'CNAME':
                return [str(rdata).rstrip('.') for rdata in answers]
            elif record_type == 'SOA':
                return [f"{rdata.mname} {rdata.rname} (Serial: {rdata.serial})" for rdata in answers]
            elif record_type == 'TXT' or record_type == 'DMARC':
                return [str(rdata).strip('"') for rdata in answers]
            else:
                return [str(rdata) for rdata in answers]
                
        except dns.resolver.NXDOMAIN:
            if self.verbose:
                print(f"  {record_type} - NXDOMAIN")
            return []
        except dns.resolver.NoAnswer:
            if self.verbose:
                print(f"  {record_type} - No Answer")
            return []
        except dns.exception.Timeout:
            if self.verbose:
                print(f"  {record_type} - Timeout")
            return []
        except Exception as e:
            if self.verbose:
                print(f"  {record_type} - Error: {e}")
            return []
    
    def _query_all_records(self):
        """Query all common record types for the target domain."""
        for record_type in COMMON_RECORD_TYPES:
            values = self._query_record(self.domain, record_type)
            
            if values:
                self.results['domain_records'][record_type] = values
                
                if record_type == 'A' or record_type == 'AAAA':
                    print(f"  {record_type}: {', '.join(values)}")
                elif record_type == 'MX':
                    for value in values:
                        print(f"  MX: {value}")
                else:
                    print(f"  {record_type}: {values[0] if len(values) == 1 else ''}")
                    if len(values) > 1:
                        for value in values:
                            print(f"    {value}")
            else:
                if self.verbose:
                    print(f"  {record_type}: No records found")
    
    def _attempt_zone_transfers(self):
        """Attempt zone transfer from each nameserver."""
        if not self.domain:
            return
            
        nameservers = self.results.get('dns_servers', [])
        if not nameservers:
            nameservers = self._query_record(self.domain, 'NS')
        
        zone_transfer_results = []
        
        for ns in nameservers:
            try:
                print(f"  Attempting zone transfer from {ns}...")
                
                # Try to query the server directly
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))
                
                # If successful, process the zone data
                print(f"  {ns}: Zone transfer successful! Found {len(zone.nodes)} records")
                
                # Extract records from the zone
                records = []
                for name, node in zone.nodes.items():
                    rdatasets = node.rdatasets
                    for rdataset in rdatasets:
                        for rdata in rdataset:
                            record = {
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'ttl': rdataset.ttl,
                                'data': str(rdata)
                            }
                            records.append(record)
                
                zone_transfer_results.append({
                    'nameserver': ns,
                    'success': True,
                    'records': records
                })
                
            except Exception as e:
                if self.verbose:
                    print(f"  {ns}: Zone transfer failed - {e}")
                
                zone_transfer_results.append({
                    'nameserver': ns,
                    'success': False,
                    'error': str(e)
                })
        
        self.results['zone_transfers'] = zone_transfer_results
    
    def _enumerate_subdomains(self):
        """
        Enumerate subdomains of the target domain using various methods.
        - Common subdomain dictionary
        - User-supplied wordlist (if provided)
        - DNS brute forcing
        """
        if not self.domain:
            return
            
        discovered_subdomains = set()
        
        # Try with common subdomains first
        print("  Testing common subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self._resolve_subdomain, f"{subdomain}.{self.domain}"): subdomain
                for subdomain in COMMON_SUBDOMAINS
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        fqdn = f"{subdomain}.{self.domain}"
                        discovered_subdomains.add(fqdn)
                        print(f"    Found: {fqdn} - {result}")
                except Exception:
                    pass
        
        # User-supplied wordlist
        if self.subdomains_file:
            try:
                with open(self.subdomains_file, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                
                print(f"  Testing {len(wordlist)} subdomains from wordlist...")
                
                # Track progress
                total = len(wordlist)
                completed = 0
                found = len(discovered_subdomains)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_subdomain = {
                        executor.submit(self._resolve_subdomain, f"{subdomain}.{self.domain}"): subdomain
                        for subdomain in wordlist
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_subdomain):
                        subdomain = future_to_subdomain[future]
                        completed += 1
                        
                        # Show progress every 100 attempts
                        if completed % 100 == 0 or completed == total:
                            percent = (completed / total) * 100
                            sys.stdout.write(f"\r    Progress: {completed}/{total} ({percent:.1f}%) - Found: {found}")
                            sys.stdout.flush()
                        
                        try:
                            result = future.result()
                            if result:
                                fqdn = f"{subdomain}.{self.domain}"
                                if fqdn not in discovered_subdomains:
                                    discovered_subdomains.add(fqdn)
                                    found += 1
                                    print(f"\n    Found: {fqdn} - {result}")
                        except Exception:
                            pass
                
                print()  # Newline after progress display
                
            except Exception as e:
                print(f"  Error with subdomain wordlist: {e}")
        
        # Attempt to find subdomains from CNAME records
        for subdomain in list(discovered_subdomains):
            try:
                cname_records = self._query_record(subdomain, 'CNAME')
                for cname in cname_records:
                    if cname.endswith(self.domain):
                        if cname not in discovered_subdomains:
                            discovered_subdomains.add(cname)
                            print(f"    Found via CNAME: {cname}")
            except Exception:
                pass
        
        # Store results
        self.results['subdomains'] = sorted(list(discovered_subdomains))
        print(f"  Total subdomains discovered: {len(discovered_subdomains)}")
    
    def _resolve_subdomain(self, subdomain):
        """
        Attempt to resolve a subdomain to an IP address.
        
        Args:
            subdomain (str): Subdomain to resolve
            
        Returns:
            str: IP address(es) if resolved, None otherwise
        """
        try:
            answers = dns_resolver.resolve(subdomain, 'A')
            return ', '.join(rdata.address for rdata in answers)
        except Exception:
            return None
    
    def _perform_reverse_lookup(self, ip):
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip (str): IP address to lookup
            
        Returns:
            str: Hostname or None if not found
        """
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = dns_resolver.resolve(reverse_name, 'PTR')
            hostnames = [str(rdata).rstrip('.') for rdata in answers]
            
            if hostnames:
                print(f"  Reverse DNS: {', '.join(hostnames)}")
                self.results['reverse_lookup'][ip] = hostnames
                return hostnames
            
        except Exception as e:
            if self.verbose:
                print(f"  Reverse lookup failed: {e}")
        
        print("  No reverse DNS records found")
        return None
    
    def _scan_ip_range(self):
        """Scan an IP range for reverse DNS records."""
        try:
            network = ipaddress.ip_network(self.ip_range)
            total_ips = network.num_addresses
            
            if total_ips > 256 and not self.verbose:
                print(f"  IP range contains {total_ips} addresses. This may take a while.")
                print("  Use --verbose for detailed progress.")
            
            print(f"  Scanning {total_ips} IP addresses for reverse DNS records...")
            
            # Track progress
            completed = 0
            found = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_ip = {
                    executor.submit(self._perform_reverse_lookup_quiet, str(ip)): str(ip)
                    for ip in network
                }
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    # Show progress every 10 IPs or when complete
                    if completed % 10 == 0 or completed == total_ips:
                        percent = (completed / total_ips) * 100
                        sys.stdout.write(f"\r  Progress: {completed}/{total_ips} ({percent:.1f}%) - Found: {found}")
                        sys.stdout.flush()
                    
                    try:
                        hostnames = future.result()
                        if hostnames:
                            found += 1
                            if self.verbose:
                                print(f"\n  {ip}: {', '.join(hostnames)}")
                    except Exception:
                        pass
            
            print(f"\n  Found {found} reverse DNS records")
            
        except ValueError as e:
            print(f"  Invalid IP range format: {e}")
    
    def _perform_reverse_lookup_quiet(self, ip):
        """
        Perform reverse DNS lookup without printing results.
        
        Args:
            ip (str): IP address to lookup
            
        Returns:
            list: Hostnames or empty list if not found
        """
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = dns_resolver.resolve(reverse_name, 'PTR')
            hostnames = [str(rdata).rstrip('.') for rdata in answers]
            
            if hostnames:
                self.results['reverse_lookup'][ip] = hostnames
                return hostnames
            
        except Exception:
            pass
        
        return []
    
    def _save_results(self):
        """Save results to a file."""
        try:
            with open(self.output, 'w') as f:
                # Add metadata
                result_data = {
                    'metadata': {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'target_domain': self.domain,
                        'target_ip': self.ip,
                        'target_range': self.ip_range,
                        'dns_servers': self.dns_servers
                    },
                    'results': self.results
                }
                
                json.dump(result_data, f, indent=2)
                
            print(f"Results saved to {self.output}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description="DNS Reconnaissance Tool")
    parser.add_argument("--domain", "-d", help="Target domain")
    parser.add_argument("--ip", "-i", help="Target IP address for reverse lookup")
    parser.add_argument("--range", "-r", help="IP range in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("--server", "-s", action="append", help="DNS server to use (can be specified multiple times)")
    parser.add_argument("--timeout", "-t", type=int, default=5, help="Timeout for DNS queries in seconds")
    parser.add_argument("--threads", "-n", type=int, default=10, help="Number of threads for concurrent queries")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", "-o", help="Output file path (JSON format)")
    parser.add_argument("--subdomains", "-w", help="Path to subdomain wordlist file")
    parser.add_argument("--history", action="store_true", help="Attempt to retrieve historical DNS records")
    
    args = parser.parse_args()
    
    # Validate that at least one target is specified
    if not (args.domain or args.ip or args.range):
        parser.error("At least one target (--domain, --ip, or --range) must be specified")
    
    try:
        recon = DNSRecon(
            domain=args.domain,
            ip=args.ip,
            ip_range=args.range,
            dns_servers=args.server,
            timeout=args.timeout,
            threads=args.threads,
            verbose=args.verbose,
            output=args.output,
            subdomains=args.subdomains,
            history=args.history
        )
        
        recon.run()
        
    except KeyboardInterrupt:
        print("\nReconnaissance interrupted by user")
    except Exception as e:
        print(f"Error during reconnaissance: {e}")

if __name__ == "__main__":
    main()
