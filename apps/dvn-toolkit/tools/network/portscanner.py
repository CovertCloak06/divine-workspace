#!/usr/bin/env python3
"""
Port Scanner - Scan for open ports on a host
Usage: portscanner.py <host> [--ports 1-1000] [--fast]
"""

import socket
import argparse
import concurrent.futures
import sys
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common ports and their services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}

# Well-known port ranges
COMMON_RANGE = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]


def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            # Try to get banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return port, True, banner[:100]
            except:
                return port, True, None
        return port, False, None
    except:
        return port, False, None


def parse_ports(port_string):
    """Parse port specification like '1-100,443,8080'"""
    ports = set()

    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        elif part.lower() == 'common':
            ports.update(COMMON_RANGE)
        elif part:
            ports.add(int(part))

    return sorted(ports)


def resolve_host(host):
    """Resolve hostname to IP"""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None


def main():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('host', nargs='?', help='Host to scan')
    parser.add_argument('--ports', '-p', default='common',
                        help='Ports to scan (e.g., 1-1000, 80,443, common)')
    parser.add_argument('--timeout', '-t', type=float, default=1,
                        help='Timeout per port (seconds)')
    parser.add_argument('--threads', '-T', type=int, default=100,
                        help='Number of threads')
    parser.add_argument('--fast', '-f', action='store_true',
                        help='Fast scan (common ports only)')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Scan all ports (1-65535)')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔍 Port Scanner                               ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.host:
        args.host = input(f"  {CYAN}Target host:{RESET} ").strip()

    if not args.host:
        print(f"  {RED}Host required{RESET}\n")
        return

    # Resolve host
    ip = resolve_host(args.host)
    if not ip:
        print(f"  {RED}Could not resolve host: {args.host}{RESET}\n")
        return

    print(f"  {BOLD}Target:{RESET} {args.host}", end='')
    if ip != args.host:
        print(f" ({ip})")
    else:
        print()

    # Determine ports to scan
    if args.all:
        ports = list(range(1, 65536))
        print(f"  {BOLD}Ports:{RESET} All (1-65535)")
    elif args.fast:
        ports = COMMON_RANGE
        print(f"  {BOLD}Ports:{RESET} Common ({len(ports)} ports)")
    else:
        ports = parse_ports(args.ports)
        print(f"  {BOLD}Ports:{RESET} {len(ports)} ports")

    print(f"  {BOLD}Threads:{RESET} {args.threads}")
    print(f"  {BOLD}Timeout:{RESET} {args.timeout}s")

    print(f"\n  {DIM}Scanning started at {datetime.now().strftime('%H:%M:%S')}{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    start_time = datetime.now()
    open_ports = []
    scanned = 0

    # Scan ports
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, port, args.timeout): port for port in ports}

        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            scanned += 1

            # Progress
            if scanned % 100 == 0 or scanned == len(ports):
                percent = (scanned / len(ports)) * 100
                sys.stdout.write(f"\r  {DIM}Progress: {scanned}/{len(ports)} ({percent:.0f}%){RESET}")
                sys.stdout.flush()

            if is_open:
                open_ports.append((port, banner))

    print()  # New line after progress

    elapsed = (datetime.now() - start_time).total_seconds()

    # Results
    print(f"\n  {BOLD}Results:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    if open_ports:
        open_ports.sort(key=lambda x: x[0])

        print(f"\n  {GREEN}Found {len(open_ports)} open port(s):{RESET}\n")
        print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<15} BANNER")
        print(f"  {'-' * 60}")

        for port, banner in open_ports:
            service = COMMON_PORTS.get(port, 'unknown')
            banner_str = banner[:30] + '...' if banner and len(banner) > 30 else (banner or '')

            print(f"  {GREEN}{port:<8}{RESET} {'open':<8} {CYAN}{service:<15}{RESET} {DIM}{banner_str}{RESET}")
    else:
        print(f"\n  {YELLOW}No open ports found{RESET}")

    # Summary
    print(f"\n  {DIM}{'─' * 50}{RESET}")
    print(f"  Scanned {len(ports)} ports in {elapsed:.1f}s ({len(ports)/elapsed:.0f} ports/sec)")
    print(f"  Finished at {datetime.now().strftime('%H:%M:%S')}")

    # Suggest next steps
    if open_ports:
        print(f"\n  {BOLD}Suggested next steps:{RESET}")
        for port, _ in open_ports[:3]:
            if port == 22:
                print(f"  {DIM}• SSH: ssh user@{args.host}{RESET}")
            elif port == 80:
                print(f"  {DIM}• HTTP: curl http://{args.host}{RESET}")
            elif port == 443:
                print(f"  {DIM}• HTTPS: curl https://{args.host}{RESET}")
            elif port == 3306:
                print(f"  {DIM}• MySQL: mysql -h {args.host}{RESET}")

    print()


if __name__ == '__main__':
    main()
