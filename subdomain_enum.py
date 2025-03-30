
#!/usr/bin/env python3
"""
Subdomain Enumeration Tool - Discover subdomains of a target domain

This script performs subdomain enumeration using multiple techniques, including DNS
queries, certificate transparency logs, search engine results, and brute force attacks.
It can help identify the attack surface of a target organization.

Features:
- Certificate transparency log search
- DNS zone transfers
- Brute force subdomain discovery
- Search engine results scraping
- Public dataset querying
- Active DNS resolution and validation
- Export results to various formats

Usage:
    python subdomain_enum.py --domain example.com
    python subdomain_enum.py --domain example.com --wordlist subdomains.txt --output results.txt

Requirements:
    - Python 3.6+
    - dns.resolver (dnspython)
    - requests
"""

import argparse
import concurrent.futures
import csv
import dns.resolver
import dns.zone
import dns.query
import json
import os
import random
import re
import sys
import time
from collections import defaultdict
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: This script requires the 'requests' library.")
    print("Install it using: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    import dns.zone
except ImportError:
    print("Error: This script requires the 'dnspython' library.")
    print("Install it using: pip install dnspython")
    sys.exit(1)

# Default DNS servers
DEFAULT_DNS_SERVERS = [
    '8.8.8.8',       # Google
    '1.1.1.1',       # Cloudflare
    '9.9.9.9',       # Quad9
    '208.67.222.222' # OpenDNS
]

# User agents for HTTP requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

class SubdomainEnumerator:
    def __init__(self, domain, wordlist=None, dns_servers=None, max_threads=20, 
                 timeout=10, verify=True, output=None, output_format="txt"):
        """
        Initialize the subdomain enumerator.
        
        Args:
            domain (str): Target domain to enumerate
            wordlist (str): Path to wordlist file for brute force
            dns_servers (list): List of DNS servers to use for resolution
            max_threads (int): Maximum number of threads for concurrent operations
            timeout (int): Timeout for network requests in seconds
            verify (bool): Whether to verify discovered subdomains
            output (str): Path to output file
            output_format (str): Output format (txt, csv, json)
        """
        self.domain = domain.lower()
        self.wordlist_path = wordlist
        self.dns_servers = dns_servers or DEFAULT_DNS_SERVERS
        self.max_threads = max_threads
        self.timeout = timeout
        self.verify = verify
        self.output = output
        self.output_format = output_format
        
        self.subdomains = set()
        self.verified_subdomains = set()
        self.dns_records = defaultdict(dict)
        
        # Initialize DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [self.dns_servers[0]] if self.dns_servers else DEFAULT_DNS_SERVERS
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
    
    def enumerate(self):
        """
        Perform subdomain enumeration using all available methods.
        
        Returns:
            set: Discovered subdomains
        """
        print(f"\nStarting subdomain enumeration for: {self.domain}")
        
        # Get nameservers for the domain
        nameservers = self._get_domain_nameservers()
        if nameservers:
            print(f"Nameservers: {', '.join(nameservers)}")
        
        # Try zone transfer first (rarely works but good to check)
        if nameservers:
            print("\nAttempting DNS zone transfers...")
            zone_subdomains = self._try_zone_transfer(nameservers)
            if zone_subdomains:
                print(f"Found {len(zone_subdomains)} subdomains via zone transfer")
                self.subdomains.update(zone_subdomains)
        
        # Query certificate transparency logs
        print("\nQuerying certificate transparency logs...")
        ct_subdomains = self._query_certificate_transparency()
        if ct_subdomains:
            print(f"Found {len(ct_subdomains)} subdomains in certificate logs")
            self.subdomains.update(ct_subdomains)
        
        # Query common DNS records
        print("\nQuerying common DNS records...")
        dns_subdomains = self._query_common_dns_records()
        if dns_subdomains:
            print(f"Found {len(dns_subdomains)} subdomains via DNS queries")
            self.subdomains.update(dns_subdomains)
        
        # Search online services (limited results for API-free usage)
        print("\nSearching online services for subdomains...")
        online_subdomains = self._search_online_services()
        if online_subdomains:
            print(f"Found {len(online_subdomains)} subdomains from online services")
            self.subdomains.update(online_subdomains)
        
        # Brute force subdomains if wordlist provided
        if self.wordlist_path:
            print(f"\nPerforming brute force enumeration using {self.wordlist_path}...")
            brute_force_subdomains = self._brute_force_subdomains()
            if brute_force_subdomains:
                print(f"Found {len(brute_force_subdomains)} subdomains via brute force")
                self.subdomains.update(brute_force_subdomains)
        
        # Verify discovered subdomains
        if self.verify and self.subdomains:
            print(f"\nVerifying {len(self.subdomains)} discovered subdomains...")
            self._verify_subdomains()
            print(f"Verified {len(self.verified_subdomains)} active subdomains")
        
        # Save results
        if self.output:
            self._save_results()
        
        return self.verified_subdomains if self.verify else self.subdomains
    
    def _get_domain_nameservers(self):
        """Get authoritative nameservers for the domain."""
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception as e:
            print(f"Error getting nameservers: {e}")
            return []
    
    def _try_zone_transfer(self, nameservers):
        """Attempt DNS zone transfer from each nameserver."""
        subdomains = set()
        
        for ns in nameservers:
            try:
                print(f"  Attempting zone transfer from {ns}...")
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))
                for name, node in zone.nodes.items():
                    subdomain = str(name) + '.' + self.domain
                    if subdomain.startswith('@'):
                        subdomain = self.domain
                    subdomains.add(subdomain)
                print(f"  Successful zone transfer from {ns}!")
                # Usually if one works, there's no need to try others
                break
            except Exception as e:
                # This is expected to fail most of the time
                continue
        
        return subdomains
    
    def _query_certificate_transparency(self):
        """Query certificate transparency logs for subdomains."""
        subdomains = set()
        
        # APIs for certificate transparency (no authentication required)
        ct_apis = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for api_url in ct_apis:
            try:
                response = self._make_request(api_url)
                if not response:
                    continue
                
                if "crt.sh" in api_url:
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            for entry in data:
                                name_value = entry.get('name_value', '')
                                # Handle wildcard certs and multiple domains
                                if '\n' in name_value:
                                    names = name_value.split('\n')
                                else:
                                    names = [name_value]
                                    
                                for name in names:
                                    # Skip wildcard entries and non-matching domains
                                    if name.endswith(f".{self.domain}") and '*' not in name:
                                        subdomains.add(name.lower())
                        except json.JSONDecodeError:
                            pass
                
                elif "certspotter" in api_url:
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            for entry in data:
                                dns_names = entry.get('dns_names', [])
                                for name in dns_names:
                                    if name.endswith(f".{self.domain}") and '*' not in name:
                                        subdomains.add(name.lower())
                        except json.JSONDecodeError:
                            pass
            
            except Exception as e:
                print(f"  Error querying {api_url}: {e}")
                continue
        
        return subdomains
    
    def _query_common_dns_records(self):
        """Query common DNS records that might reveal subdomains."""
        subdomains = set()
        common_prefixes = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
                         'smtp', 'secure', 'vpn', 'admin', 'mx', 'ftp', 'dev', 'staging']
        
        # Try direct lookups for common prefixes
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_prefix = {
                executor.submit(self._resolve_domain, f"{prefix}.{self.domain}"): prefix
                for prefix in common_prefixes
            }
            
            for future in concurrent.futures.as_completed(future_to_prefix):
                prefix = future_to_prefix[future]
                try:
                    result = future.result()
                    if result:
                        subdomains.add(f"{prefix}.{self.domain}")
                except Exception:
                    pass
        
        # Try to get subdomains from MX records
        try:
            for record_type in ['MX', 'NS', 'CNAME', 'SOA', 'TXT']:
                try:
                    answers = self.resolver.resolve(self.domain, record_type)
                    for rdata in answers:
                        if record_type == 'MX':
                            mx_host = str(rdata.exchange).rstrip('.')
                            if self.domain in mx_host:
                                subdomains.add(mx_host.lower())
                        elif record_type == 'NS':
                            ns_host = str(rdata).rstrip('.')
                            if self.domain in ns_host:
                                subdomains.add(ns_host.lower())
                        elif record_type == 'CNAME':
                            cname = str(rdata).rstrip('.')
                            if self.domain in cname:
                                subdomains.add(cname.lower())
                except Exception:
                    continue
        except Exception as e:
            print(f"  Error querying DNS records: {e}")
        
        return subdomains
    
    def _search_online_services(self):
        """Search online services for subdomains (limited without API keys)."""
        subdomains = set()
        
        # Limited version since many services now require API keys
        # For a real tool, you would integrate APIs from services like:
        # - VirusTotal
        # - SecurityTrails
        # - AlienVault OTX
        # - Shodan
        # etc.
        
        # Simple search engine scraping (might be blocked/limited)
        search_urls = [
            f"https://www.google.com/search?q=site%3A*.{self.domain}&num=100",
            f"https://search.yahoo.com/search?p=site%3A*.{self.domain}&n=100"
        ]
        
        subdomain_pattern = re.compile(f'([a-zA-Z0-9_-]+\.{re.escape(self.domain)})')
        
        for url in search_urls:
            try:
                response = self._make_request(url)
                if response and response.status_code == 200:
                    matches = subdomain_pattern.findall(response.text)
                    for match in matches:
                        subdomains.add(match.lower())
            except Exception as e:
                print(f"  Error searching {url}: {e}")
        
        return subdomains
    
    def _brute_force_subdomains(self):
        """Perform brute force subdomain enumeration using a wordlist."""
        subdomains = set()
        
        if not self.wordlist_path or not os.path.exists(self.wordlist_path):
            print(f"  Error: Wordlist file not found: {self.wordlist_path}")
            return subdomains
            
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
                
            print(f"  Loaded {len(words)} words for brute force")
            
            # Track progress
            total_words = len(words)
            completed = 0
            found = 0
            start_time = time.time()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_subdomain = {
                    executor.submit(self._resolve_domain, f"{word}.{self.domain}"): word
                    for word in words
                }
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    word = future_to_subdomain[future]
                    completed += 1
                    
                    # Show progress every 100 attempts or when complete
                    if completed % 100 == 0 or completed == total_words:
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        remaining = (total_words - completed) / rate if rate > 0 else 0
                        percent = (completed / total_words) * 100
                        
                        sys.stdout.write(
                            f"\r  Progress: {completed}/{total_words} ({percent:.1f}%) "
                            f"- Found: {found} - {rate:.1f} req/sec - ETA: {remaining:.0f}s"
                        )
                        sys.stdout.flush()
                    
                    try:
                        result = future.result()
                        if result:
                            subdomain = f"{word}.{self.domain}"
                            subdomains.add(subdomain)
                            found += 1
                            
                            # Show new findings immediately
                            print(f"\n  Found: {subdomain} {result}")
                    except Exception:
                        pass
            
            print()  # New line after progress display
            
        except Exception as e:
            print(f"  Error during brute force: {e}")
        
        return subdomains
    
    def _resolve_domain(self, domain):
        """
        Attempt to resolve a domain name.
        
        Args:
            domain (str): Domain name to resolve
            
        Returns:
            str: IP address(es) if resolved, None otherwise
        """
        try:
            answers = self.resolver.resolve(domain, 'A')
            return ', '.join(rdata.address for rdata in answers)
        except Exception:
            return None
    
    def _verify_subdomains(self):
        """Verify discovered subdomains are active by resolving them."""
        print(f"  Resolving {len(self.subdomains)} subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_subdomain = {
                executor.submit(self._get_dns_info, subdomain): subdomain
                for subdomain in self.subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        self.verified_subdomains.add(subdomain)
                except Exception:
                    pass
    
    def _get_dns_info(self, domain):
        """
        Get DNS information for a domain.
        
        Args:
            domain (str): Domain to query
            
        Returns:
            bool: True if any records were found
        """
        found_records = False
        
        # Try different record types
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
            try:
                answers = self.resolver.resolve(domain, record_type)
                self.dns_records[domain][record_type] = []
                
                for rdata in answers:
                    if record_type == 'A' or record_type == 'AAAA':
                        self.dns_records[domain][record_type].append(rdata.address)
                    elif record_type == 'CNAME':
                        self.dns_records[domain][record_type].append(str(rdata.target))
                    elif record_type == 'MX':
                        self.dns_records[domain][record_type].append(str(rdata.exchange))
                    else:
                        self.dns_records[domain][record_type].append(str(rdata))
                
                found_records = True
            except Exception:
                continue
        
        return found_records
    
    def _make_request(self, url):
        """Make an HTTP request with random user agent and error handling."""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        try:
            return requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=True  # SSL verification
            )
        except RequestException:
            return None
    
    def _save_results(self):
        """Save the results to a file in the specified format."""
        subdomains_to_save = self.verified_subdomains if self.verify else self.subdomains
        
        if not subdomains_to_save:
            print("No results to save.")
            return
            
        try:
            if self.output_format == 'json':
                with open(self.output, 'w') as f:
                    results = {
                        'domain': self.domain,
                        'subdomains': sorted(list(subdomains_to_save)),
                        'total': len(subdomains_to_save),
                        'dns_records': self.dns_records
                    }
                    json.dump(results, f, indent=4)
            elif self.output_format == 'csv':
                with open(self.output, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Subdomain', 'IP Addresses'])
                    
                    for subdomain in sorted(subdomains_to_save):
                        ip_addresses = self.dns_records.get(subdomain, {}).get('A', [''])
                        writer.writerow([subdomain, ', '.join(ip_addresses)])
            else:
                # Default to text format
                with open(self.output, 'w') as f:
                    f.write(f"# Subdomains of {self.domain}\n")
                    f.write(f"# Total: {len(subdomains_to_save)}\n\n")
                    
                    for subdomain in sorted(subdomains_to_save):
                        f.write(f"{subdomain}\n")
            
            print(f"Results saved to {self.output}")
            
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("--domain", "-d", required=True, help="Target domain to enumerate")
    parser.add_argument("--wordlist", "-w", help="Path to wordlist file for brute force")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", "-f", choices=["txt", "json", "csv"], default="txt",
                        help="Output format (default: txt)")
    parser.add_argument("--threads", "-t", type=int, default=20,
                        help="Number of threads for concurrent operations (default: 20)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout for network requests in seconds (default: 10)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verification of discovered subdomains")
    parser.add_argument("--dns-server", action="append",
                        help="DNS server to use (can be specified multiple times)")
    
    args = parser.parse_args()
    
    dns_servers = args.dns_server or DEFAULT_DNS_SERVERS
    
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        wordlist=args.wordlist,
        dns_servers=dns_servers,
        max_threads=args.threads,
        timeout=args.timeout,
        verify=not args.no_verify,
        output=args.output,
        output_format=args.format
    )
    
    try:
        subdomains = enumerator.enumerate()
        
        # Print summary
        print("\nEnumeration Summary:")
        print(f"Target domain: {args.domain}")
        print(f"Total subdomains discovered: {len(subdomains)}")
        
        # Print top 20 subdomains
        if subdomains:
            print("\nSubdomains (first 20):")
            for subdomain in sorted(list(subdomains))[:20]:
                ip_addresses = enumerator.dns_records.get(subdomain, {}).get('A', ['N/A'])
                print(f"  {subdomain:<40} {', '.join(ip_addresses)}")
            
            if len(subdomains) > 20:
                print(f"  ... and {len(subdomains) - 20} more")
        
    except KeyboardInterrupt:
        print("\nEnumeration interrupted by user.")
    except Exception as e:
        print(f"Error during enumeration: {e}")

if __name__ == "__main__":
    main()
