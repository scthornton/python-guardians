#!/usr/bin/env python3
"""
Directory Brute Force Scanner - Find hidden web directories and files

This script performs brute force scanning of web servers to identify hidden directories
and files. It uses wordlists to generate paths to test and can follow redirects and
spider additional directories.

Features:
- Customizable wordlists for directory and file discovery
- Multi-threaded scanning for faster execution
- Response code, size, and content analysis
- Follow redirect options for deeper discovery
- Custom headers and user agent support
- Export results to various formats (JSON, CSV)

Usage:
    python directory_bruteforce.py --url https://example.com --wordlist common.txt
    python directory_bruteforce.py --url https://example.com --wordlist common.txt --extensions php,txt,html

Requirements:
    - Python 3.6+
    - requests library
"""

import argparse
import concurrent.futures
import csv
import json
import os
import random
import sys
import time
import platform
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.exceptions import RequestException, ConnectionError, Timeout
except ImportError:
    print("Error: This script requires the 'requests' library.")
    print("Install it using: pip install requests")
    sys.exit(1)

# Disable SSL warnings
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

# Default user agents for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

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

class DirectoryScanner:
    def __init__(self, url, wordlist, extensions=None, threads=10, timeout=10, 
                 follow_redirects=False, user_agent=None, delay=0, 
                 ignore_codes=None, output_file=None, output_format="txt"):
        """
        Initialize the directory scanner.
        
        Args:
            url (str): Target URL to scan
            wordlist (str): Path to wordlist file
            extensions (list): File extensions to check
            threads (int): Number of concurrent threads
            timeout (int): Request timeout in seconds
            follow_redirects (bool): Whether to follow redirects
            user_agent (str): Custom user agent or 'random'
            delay (float): Delay between requests in seconds
            ignore_codes (list): HTTP status codes to ignore
            output_file (str): Path to output file
            output_format (str): Output format (txt, csv, json)
        """
        self.base_url = url if url.endswith('/') else url + '/'
        self.wordlist_path = wordlist
        self.extensions = extensions if extensions else []
        self.threads = threads
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent
        self.delay = delay
        self.ignore_codes = ignore_codes if ignore_codes else [404]
        self.output_file = output_file
        self.output_format = output_format
        
        self.paths = []
        self.results = []
        self.session = requests.Session()
        self.load_wordlist()
    
    def load_wordlist(self):
        """Load and process the wordlist."""
        if not os.path.exists(self.wordlist_path):
            print(f"Error: Wordlist file not found: {self.wordlist_path}")
            sys.exit(1)
            
        with open(self.wordlist_path, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Process words with extensions
        for word in wordlist:
            # Add the base word (directory)
            self.paths.append(word)
            
            # Add extensions if specified
            for ext in self.extensions:
                if ext.startswith('.'):
                    self.paths.append(f"{word}{ext}")
                else:
                    self.paths.append(f"{word}.{ext}")
        
        print(f"Loaded {len(self.paths)} paths to scan")
    
    def get_random_agent(self):
        """Get a random user agent string."""
        return random.choice(USER_AGENTS)
    
    def scan_url(self, path):
        """
        Scan a single URL path.
        
        Args:
            path (str): Path to scan
            
        Returns:
            dict: Scan result or None if error/ignore
        """
        url = urljoin(self.base_url, path)
        
        # Prepare headers
        headers = {}
        if self.user_agent == 'random':
            headers['User-Agent'] = self.get_random_agent()
        elif self.user_agent:
            headers['User-Agent'] = self.user_agent
        
        try:
            # Optional delay to avoid overwhelming the server
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Make the request
            start_time = time.time()
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                headers=headers,
                verify=False  # Ignore SSL certificate verification
            )
            response_time = time.time() - start_time
            
            # Skip ignored status codes
            if response.status_code in self.ignore_codes:
                return None
                
            # Process the response
            content_type = response.headers.get('Content-Type', '')
            content_length = len(response.content)
            redirect_url = response.headers.get('Location') if response.is_redirect else None
            
            result = {
                'url': url,
                'path': path,
                'status': response.status_code,
                'content_length': content_length,
                'content_type': content_type,
                'redirect': redirect_url,
                'response_time': response_time
            }
            
            return result
            
        except ConnectionError:
            # Silently fail for connection issues
            return None
        except Timeout:
            # Silently fail for timeouts
            return None
        except RequestException as e:
            # Print other request exceptions but continue
            print(f"Error scanning {url}: {e}")
            return None
        except Exception as e:
            # Print unexpected errors but continue
            print(f"Unexpected error scanning {url}: {e}")
            return None
    
    def scan(self):
        """Perform the directory scan using multiple threads."""
        print(f"\nStarting scan of {self.base_url}")
        print(f"Using {self.threads} threads with {self.timeout}s timeout")
        print(f"Press Ctrl+C to abort the scan\n")
        
        # Display initial status information
        parsed_url = urlparse(self.base_url)
        print(f"Target: {parsed_url.netloc} ({parsed_url.scheme})")
        start_time = time.time()
        
        try:
            # Print table header
            print(f"\n{'Path':<50} {'Status':<7} {'Length':<10} {'Time':<10}")
            print('-' * 80)
            
            # Use a thread pool for scanning
            completed = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all tasks
                future_to_path = {executor.submit(self.scan_url, path): path for path in self.paths}
                
                # Process as they complete
                for future in concurrent.futures.as_completed(future_to_path):
                    path = future_to_path[future]
                    completed += 1
                    
                    # Print progress every 10 paths
                    if completed % 10 == 0:
                        progress = (completed / len(self.paths)) * 100
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        eta = (len(self.paths) - completed) / rate if rate > 0 else 0
                        
                        sys.stdout.write(f"\rProgress: {completed}/{len(self.paths)} ({progress:.1f}%) "
                                        f"- {rate:.1f} req/sec - ETA: {eta:.0f}s")
                        sys.stdout.flush()
                    
                    # Process the result
                    try:
                        result = future.result()
                        if result:
                            self.results.append(result)
                            # Print interesting findings immediately
                            status = result['status']
                            path_display = f"/{result['path']}"[:49]
                            content_length = result['content_length']
                            response_time = result['response_time'] * 1000  # ms
                            
                            # Skip printing if it's just a redirect to the root
                            if status in [301, 302] and result.get('redirect') == '/':
                                continue
                                
                            # Color code based on status
                            if 200 <= status < 300:
                                status_color = '\033[92m'  # Green
                            elif 300 <= status < 400:
                                status_color = '\033[94m'  # Blue
                            elif 400 <= status < 500:
                                status_color = '\033[93m'  # Yellow
                            elif 500 <= status < 600:
                                status_color = '\033[91m'  # Red
                            else:
                                status_color = '\033[0m'   # Reset
                                
                            reset_color = '\033[0m'
                            print(f"{path_display:<50} {status_color}{status}{reset_color:<7} {content_length:<10} {response_time:.2f}ms")
                            
                    except Exception as e:
                        print(f"Error processing result for {path}: {e}")
            
            # Calculate and print summary
            scan_time = time.time() - start_time
            print(f"\nScan completed in {scan_time:.2f} seconds")
            print(f"Found {len(self.results)} interesting paths")
            
            # Write output file if specified
            if self.output_file:
                self.write_output()
                
            return self.results
                
        except KeyboardInterrupt:
            print("\nScan aborted by user")
            # Still write partial results if output file specified
            if self.output_file and self.results:
                self.write_output()
                
            return self.results
    
    def write_output(self):
        """Write scan results to the specified output file."""
        if not self.results:
            print("No results to write")
            return
            
        try:
            if self.output_format == 'json':
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
            elif self.output_format == 'csv':
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                    writer.writeheader()
                    writer.writerows(self.results)
            else:
                # Default txt format
                with open(self.output_file, 'w') as f:
                    f.write(f"# Directory scan results for {self.base_url}\n")
                    f.write(f"# Scan completed at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    f.write(f"{'URL':<70} {'Status':<7} {'Length':<10} {'Type':<30}\n")
                    f.write('-' * 120 + '\n')
                    
                    for result in sorted(self.results, key=lambda x: x['url']):
                        url = result['url']
                        status = result['status']
                        length = result['content_length']
                        content_type = result['content_type'].split(';')[0]
                        
                        f.write(f"{url:<70} {status:<7} {length:<10} {content_type:<30}\n")
            
            print(f"Results written to {self.output_file}")
            
        except Exception as e:
            print(f"Error writing output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Directory Brute Force Scanner")
    parser.add_argument("--url", "-u", required=True, help="Target URL to scan")
    parser.add_argument("--wordlist", "-w", required=True, help="Path to wordlist file")
    parser.add_argument("--extensions", "-x", help="File extensions to check (e.g., php,html,txt)")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--follow-redirects", "-r", action="store_true", help="Follow redirects")
    parser.add_argument("--user-agent", "-a", default="random", help="User agent string (default: random)")
    parser.add_argument("--delay", "-d", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--ignore-codes", "-i", help="HTTP status codes to ignore (e.g., 404,403)")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", "-f", choices=["txt", "json", "csv"], default="txt",
                        help="Output format (default: txt)")
    
    args = parser.parse_args()
    
    # Process arguments
    extensions = args.extensions.split(',') if args.extensions else []
    ignore_codes = [int(code) for code in args.ignore_codes.split(',')] if args.ignore_codes else [404]
    
    # Platform-specific wordlist suggestions
    if not os.path.exists(args.wordlist):
        if platform.system() == 'Windows':
            print(f"Error: Wordlist '{args.wordlist}' not found.")
            print("Suggested locations for wordlists on Windows:")
            print("  - C:\\tools\\wordlists\\dirb\\common.txt")
            print("  - C:\\tools\\wordlists\\dirbuster\\directory-list-2.3-medium.txt")
        else:
            print(f"Error: Wordlist '{args.wordlist}' not found.")
            print("Suggested locations for wordlists on Linux:")
            print("  - /usr/share/wordlists/dirb/common.txt")
            print("  - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        return
        
    # Create and run the scanner
    scanner = DirectoryScanner(
        url=args.url,
        wordlist=args.wordlist,
        extensions=extensions,
        threads=args.threads,
        timeout=args.timeout,
        follow_redirects=args.follow_redirects,
        user_agent=args.user_agent,
        delay=args.delay,
        ignore_codes=ignore_codes,
        output_file=args.output,
        output_format=args.format
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()
