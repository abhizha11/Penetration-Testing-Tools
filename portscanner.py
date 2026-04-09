#!/usr/bin/env python3
"""
Port Scanner - Check if ports are open on a target host
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import time

class PortScanner:
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.results = []
    
    def check_port(self, host: str, port: int) -> Tuple[int, bool]:
        """Check if a single port is open on the target host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port, result == 0
        except socket.gaierror:
            print(f"Error: Cannot resolve hostname {host}", file=sys.stderr)
            return port, False
        except socket.error as e:
            print(f"Error scanning port {port}: {e}", file=sys.stderr)
            return port, False
    
    def scan_ports(self, host: str, ports: List[int], threads: int = 10) -> None:
        """Scan multiple ports concurrently"""
        print(f"Scanning {len(ports)} ports on {host}...")
        print("-" * 50)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.check_port, host, port): port 
                      for port in sorted(ports)}
            
            for future in as_completed(futures):
                port, is_open = future.result()
                status = "OPEN" if is_open else "CLOSED"
                print(f"Port {port:5d}: {status}")
                if is_open:
                    self.results.append(port)
        
        print("-" * 50)
        print(f"Scan complete. Open ports: {len(self.results)}")
        if self.results:
            print(f"Open ports: {', '.join(map(str, sorted(self.results)))}")

def parse_port_range(port_string: str) -> List[int]:
    """Parse port string like '80,443,8000-8003' into list of ports"""
    ports = []
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def main():
    parser = argparse.ArgumentParser(
        description='Port Scanner - Check if ports are open on target host'
    )
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument(
        '-p', '--ports',
        default='20-25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443',
        help='Ports to scan (e.g., "80,443,8000-8003") [default: common ports]'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=3,
        help='Connection timeout in seconds [default: 3]'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads [default: 10]'
    )
    
    args = parser.parse_args()
    
    try:
        ports = parse_port_range(args.ports)
        if not ports:
            print("Error: No valid ports specified", file=sys.stderr)
            sys.exit(1)
        
        scanner = PortScanner(timeout=args.timeout)
        start_time = time.time()
        scanner.scan_ports(args.host, ports, threads=args.threads)
        elapsed = time.time() - start_time
        print(f"Scan took {elapsed:.2f} seconds")
        
    except ValueError as e:
        print(f"Error parsing ports: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(130)

if __name__ == '__main__':
    main()

