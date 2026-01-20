#!/usr/bin/env python3
"""
Fast Port Scanner - Async multi-threaded port scanning
Usage: portscanner <host> [--ports 1-1000] [--threads 100] [--timeout 1]
"""

import socket
import argparse
import concurrent.futures
from typing import List, Tuple
import time

# Common ports with service names
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB'
}


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, 'unknown')
            return (port, True, service)
    except:
        pass
    return (port, False, '')


def parse_ports(port_str: str) -> List[int]:
    """Parse port specification like '22,80,443' or '1-1000'"""
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(description='Fast Port Scanner')
    parser.add_argument('host', help='Target host/IP')
    parser.add_argument('--ports', '-p', default='1-1024', help='Ports to scan (e.g., 22,80,443 or 1-1000)')
    parser.add_argument('--threads', '-t', type=int, default=100, help='Number of threads')
    parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout')
    parser.add_argument('--common', '-c', action='store_true', help='Scan only common ports')
    args = parser.parse_args()

    if args.common:
        ports = list(COMMON_PORTS.keys())
    else:
        ports = parse_ports(args.ports)

    print(f"🔍 Scanning {args.host}")
    print(f"   Ports: {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s")
    print("-" * 50)

    start_time = time.time()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, args.host, port, args.timeout): port for port in ports}

        for future in concurrent.futures.as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
                print(f"   ✓ {port:5d}/tcp  open  {service}")

    elapsed = time.time() - start_time
    print("-" * 50)
    print(f"✓ Scan complete: {len(open_ports)} open ports found in {elapsed:.2f}s")

    if open_ports:
        print("\nOpen ports summary:")
        for port, service in sorted(open_ports):
            print(f"  {port}/tcp - {service}")


if __name__ == '__main__':
    main()
