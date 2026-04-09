#!/usr/bin/env python3
"""
HTTP Response Analyzer - Make HTTP requests and analyze response headers
"""

import requests
import argparse
import sys
from urllib.parse import urlparse
import json
from typing import Dict, List
import ssl
import socket
from datetime import datetime

class HTTPAnalyzer:
    """Analyze HTTP responses and headers"""
    
    # Common security headers to check
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    # Headers that reveal server info
    INFO_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-Runtime'
    ]
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

    def _make_request(self, url: str, method: str, verify_ssl: bool):
        if method.upper() == 'HEAD':
            return self.session.head(
                url,
                timeout=self.timeout,
                verify=verify_ssl,
                allow_redirects=True
            )
        return self.session.get(
            url,
            timeout=self.timeout,
            verify=verify_ssl,
            allow_redirects=True
        )
    
    def format_url(self, target: str) -> str:
        """Ensure URL has proper scheme"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target
    
    def analyze_headers(self, url: str, method: str = 'GET') -> Dict:
        """Make HTTP request and analyze headers"""
        results = {
            'url': url,
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'status_code': None,
            'headers': {},
            'security_headers': {},
            'server_info': {},
            'missing_security_headers': [],
            'analysis': []
        }
        
        try:
            print(f"Requesting {url}...")

            try:
                response = self._make_request(url, method, self.verify_ssl)
            except requests.exceptions.SSLError as ssl_error:
                if url.startswith('https://') and self.verify_ssl:
                    results['analysis'].append(
                        "⚠ HTTPS handshake failed with certificate verification enabled; retrying with --insecure behavior"
                    )
                    try:
                        response = self._make_request(url, method, False)
                        results['analysis'].append("✓ HTTPS request succeeded after disabling SSL verification")
                    except requests.exceptions.SSLError:
                        http_url = 'http://' + urlparse(url).netloc
                        results['analysis'].append("⚠ HTTPS still failing; retrying over HTTP")
                        response = self._make_request(http_url, method, False)
                        results['analysis'].append("⚠ Fallback to HTTP was used")
                elif url.startswith('https://') and not self.verify_ssl:
                    http_url = 'http://' + urlparse(url).netloc
                    results['analysis'].append("⚠ HTTPS failed even with --insecure; retrying over HTTP")
                    response = self._make_request(http_url, method, False)
                    results['analysis'].append("⚠ Fallback to HTTP was used")
                else:
                    raise ssl_error

            results['url'] = response.url
            
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)
            
            # Analyze security headers
            for header in self.SECURITY_HEADERS:
                if header in response.headers:
                    results['security_headers'][header] = response.headers[header]
                    results['analysis'].append(
                        f"✓ {header}: {response.headers[header][:80]}..."
                    )
                else:
                    results['missing_security_headers'].append(header)
                    results['analysis'].append(f"✗ Missing: {header}")
            
            # Extract server information
            for header in self.INFO_HEADERS:
                if header in response.headers:
                    results['server_info'][header] = response.headers[header]
            
            # Additional analysis
            results['analysis'].extend(self._analyze_response(response))
            
            return results
            
        except requests.exceptions.SSLError as e:
            results['error'] = f"SSL Error: {e}"
            results['analysis'].append("⚠ SSL certificate verification failed")
            return results
        except requests.exceptions.Timeout:
            results['error'] = "Request timeout"
            results['analysis'].append(f"⚠ Request timed out after {self.timeout}s")
            return results
        except requests.exceptions.ConnectionError as e:
            results['error'] = f"Connection error: {e}"
            results['analysis'].append("⚠ Could not connect to target")
            return results
        except Exception as e:
            results['error'] = str(e)
            results['analysis'].append(f"⚠ Error: {e}")
            return results
    
    def _analyze_response(self, response) -> List[str]:
        """Perform additional response analysis"""
        analysis = []
        
        # Status code analysis
        if 200 <= response.status_code < 300:
            analysis.append(f"✓ Status {response.status_code}: Success")
        elif 300 <= response.status_code < 400:
            analysis.append(f"→ Status {response.status_code}: Redirect")
        elif 400 <= response.status_code < 500:
            analysis.append(f"⚠ Status {response.status_code}: Client Error")
        elif response.status_code >= 500:
            analysis.append(f"✗ Status {response.status_code}: Server Error")
        
        # Content-Type analysis
        content_type = response.headers.get('Content-Type', 'Not specified')
        analysis.append(f"Content-Type: {content_type}")
        
        # HTTPS/TLS analysis
        if response.url.startswith('https://'):
            analysis.append("✓ Using HTTPS")
        else:
            analysis.append("⚠ Not using HTTPS")
        
        # Cache headers
        cache_control = response.headers.get('Cache-Control')
        if cache_control:
            analysis.append(f"Cache-Control: {cache_control}")
        
        # Check for common info disclosure
        dangerous_headers = ['X-Powered-By', 'X-AspNet-Version', 'Server']
        for header in dangerous_headers:
            if header in response.headers:
                analysis.append(f"⚠ Information disclosure: {header}")
        
        return analysis
    
    def print_results(self, results: Dict) -> None:
        """Pretty print analysis results"""
        print("\n" + "="*70)
        print(f"HTTP Analysis Results")
        print("="*70)
        
        print(f"\nTarget: {results['url']}")
        print(f"Method: {results['method']}")
        
        if 'error' in results:
            print(f"\n✗ Error: {results['error']}")
            return
        
        print(f"Status Code: {results['status_code']}")
        
        # Security headers
        print("\n--- Security Headers ---")
        if results['security_headers']:
            for header, value in results['security_headers'].items():
                truncated = value[:60] + "..." if len(value) > 60 else value
                print(f"  ✓ {header}")
                print(f"    {truncated}")
        else:
            print("  (none found)")
        
        if results['missing_security_headers']:
            print("\n--- Missing Security Headers ---")
            for header in results['missing_security_headers']:
                print(f"  ✗ {header}")
        
        # Server Information
        if results['server_info']:
            print("\n--- Server Information ---")
            for header, value in results['server_info'].items():
                print(f"  {header}: {value}")
        
        # Analysis summary
        print("\n--- Analysis ---")
        for line in results['analysis']:
            print(f"  {line}")
        
        print("\n" + "="*70)
    
    def export_json(self, results: Dict, filename: str) -> None:
        """Export results as JSON"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults exported to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='HTTP Response Analyzer - Analyze HTTP headers and response'
    )
    parser.add_argument(
        'target',
        help='Target URL or hostname (e.g., example.com or https://example.com)'
    )
    parser.add_argument(
        '--method',
        choices=['GET', 'HEAD'],
        default='GET',
        help='HTTP method to use [default: GET]'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds [default: 10]'
    )
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Export results to JSON file'
    )
    parser.add_argument(
        '--headers',
        action='store_true',
        help='Display all response headers'
    )
    
    args = parser.parse_args()
    
    try:
        url = HTTPAnalyzer().format_url(args.target)
        
        analyzer = HTTPAnalyzer(
            timeout=args.timeout,
            verify_ssl=not args.insecure
        )
        
        results = analyzer.analyze_headers(url, method=args.method)
        analyzer.print_results(results)
        
        # Display all headers if requested
        if args.headers and 'headers' in results:
            print("\n--- All Response Headers ---")
            for header, value in results['headers'].items():
                print(f"  {header}: {value}")
        
        # Export to JSON if requested
        if args.json:
            analyzer.export_json(results, args.json)
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()

