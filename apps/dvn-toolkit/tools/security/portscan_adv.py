#!/usr/bin/env python3
"""
Advanced Port Scanner - Service detection, banner grabbing, and vuln hints
Usage: portscan_adv <host> [--ports 1-1000] [--service-detect] [--banner]
"""

import argparse
import socket
import concurrent.futures
import ssl
import re
from typing import Dict, List, Tuple, Optional

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Service signatures for detection
SERVICE_SIGNATURES = {
    'SSH': [rb'^SSH-[\d.]+-'],
    'FTP': [rb'^220.*FTP', rb'^220.*FileZilla', rb'^220.*vsftpd', rb'^220.*ProFTPD'],
    'SMTP': [rb'^220.*SMTP', rb'^220.*Postfix', rb'^220.*Sendmail', rb'^220.*ESMTP'],
    'HTTP': [rb'^HTTP/1\.[01]', rb'^<!DOCTYPE', rb'^<html'],
    'MySQL': [rb'^.\x00\x00\x00\x0a[\d.]+'],
    'PostgreSQL': [rb'^E.*FATAL'],
    'Redis': [rb'^-ERR', rb'^\+PONG', rb'^\$'],
    'MongoDB': [rb'.*ismaster'],
    'Telnet': [rb'^\xff[\xfb-\xfe]'],
    'POP3': [rb'^\+OK'],
    'IMAP': [rb'^\* OK'],
    'RDP': [rb'^\x03\x00'],
    'VNC': [rb'^RFB \d'],
    'SMB': [rb'^\x00\x00\x00'],
}

# Known vulnerable versions (simplified examples)
VULN_PATTERNS = {
    'OpenSSH': [
        (r'OpenSSH_([0-6]\.|7\.[0-6])', 'Potentially outdated OpenSSH version'),
    ],
    'Apache': [
        (r'Apache/2\.2\.', 'Apache 2.2.x - End of Life'),
        (r'Apache/2\.4\.([0-9]|[12][0-9]|3[0-9]|4[0-8])([^0-9]|$)', 'Apache < 2.4.49 - Check for CVEs'),
    ],
    'nginx': [
        (r'nginx/1\.([0-9]|1[0-7])\.', 'nginx < 1.18 - Check for CVEs'),
    ],
    'MySQL': [
        (r'5\.[0-5]\.', 'MySQL 5.0-5.5 - End of Life'),
    ],
    'ProFTPD': [
        (r'ProFTPD 1\.3\.[0-5]', 'ProFTPD < 1.3.6 - Multiple CVEs'),
    ],
    'vsftpd': [
        (r'vsftpd 2\.3\.4', 'vsftpd 2.3.4 - Backdoor vulnerability'),
    ],
}

# Common port services
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB', 9200: 'Elasticsearch',
}

def grab_banner(host: str, port: int, timeout: float = 3) -> Optional[str]:
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send probe for certain services
        if port in [80, 8080, 8000, 8888]:
            sock.send(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
        elif port == 6379:  # Redis
            sock.send(b'PING\r\n')
        elif port == 27017:  # MongoDB
            sock.send(b'\x3a\x00\x00\x00\xa7\x41\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00')

        banner = sock.recv(1024)
        sock.close()
        return banner.decode('utf-8', errors='replace').strip()[:200]
    except:
        return None

def grab_ssl_banner(host: str, port: int, timeout: float = 3) -> Optional[Dict]:
    """Grab SSL certificate info"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            cert = s.getpeercert(binary_form=False)

            # Get raw for banner
            s.send(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
            banner = s.recv(1024).decode('utf-8', errors='replace')[:200]

            return {
                'cert': cert,
                'banner': banner
            }
    except:
        return None

def identify_service(banner: str) -> str:
    """Identify service from banner"""
    if not banner:
        return 'unknown'

    banner_bytes = banner.encode()
    for service, patterns in SERVICE_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, banner_bytes, re.IGNORECASE):
                return service

    return 'unknown'

def check_vulnerabilities(banner: str) -> List[str]:
    """Check for known vulnerable versions"""
    vulns = []
    if not banner:
        return vulns

    for service, patterns in VULN_PATTERNS.items():
        for pattern, desc in patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                vulns.append(f"{service}: {desc}")

    return vulns

def scan_port(host: str, port: int, timeout: float, grab_banners: bool) -> Dict:
    """Scan a single port with optional banner grab"""
    result = {
        'port': port,
        'state': 'closed',
        'service': COMMON_PORTS.get(port, 'unknown'),
        'banner': None,
        'vulns': []
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if sock.connect_ex((host, port)) == 0:
            result['state'] = 'open'
            sock.close()

            if grab_banners:
                # Try SSL first for HTTPS ports
                if port in [443, 8443, 993, 995, 465, 636]:
                    ssl_info = grab_ssl_banner(host, port, timeout)
                    if ssl_info:
                        result['banner'] = ssl_info['banner']
                        result['ssl'] = True
                else:
                    banner = grab_banner(host, port, timeout)
                    if banner:
                        result['banner'] = banner
                        result['service'] = identify_service(banner)
                        result['vulns'] = check_vulnerabilities(banner)
        else:
            sock.close()
    except:
        pass

    return result

def parse_ports(port_str: str) -> List[int]:
    """Parse port specification"""
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def main():
    parser = argparse.ArgumentParser(description='Advanced Port Scanner')
    parser.add_argument('host', help='Target host/IP')
    parser.add_argument('--ports', '-p', default='1-1024', help='Ports to scan')
    parser.add_argument('--threads', '-t', type=int, default=50, help='Threads')
    parser.add_argument('--timeout', type=float, default=2.0, help='Timeout')
    parser.add_argument('--banner', '-b', action='store_true', help='Grab banners')
    parser.add_argument('--common', '-c', action='store_true', help='Scan common ports only')
    args = parser.parse_args()

    # Resolve host
    try:
        ip = socket.gethostbyname(args.host)
    except:
        print(f"{RED}Could not resolve host: {args.host}{RESET}")
        return

    if args.common:
        ports = list(COMMON_PORTS.keys())
    else:
        ports = parse_ports(args.ports)

    print(f"\n{BOLD}{CYAN}Advanced Port Scanner{RESET}")
    print(f"Target: {args.host} ({ip})")
    print(f"Ports: {len(ports)} | Threads: {args.threads}")
    print(f"Banner grabbing: {'ON' if args.banner else 'OFF'}")
    print(f"\n{'='*60}\n")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, args.timeout, args.banner): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['state'] == 'open':
                open_ports.append(result)

                # Print immediately
                port = result['port']
                service = result['service']
                print(f"{GREEN}[OPEN]{RESET} {port}/tcp - {CYAN}{service}{RESET}")

                if result['banner']:
                    # Truncate and clean banner
                    banner = result['banner'].replace('\n', ' ').replace('\r', '')[:60]
                    print(f"       {DIM}Banner: {banner}{RESET}")

                if result['vulns']:
                    for vuln in result['vulns']:
                        print(f"       {RED}[!] {vuln}{RESET}")

    # Summary
    print(f"\n{'='*60}")
    print(f"{BOLD}Scan Complete{RESET}")
    print(f"Open ports: {len(open_ports)}")

    if open_ports:
        print(f"\n{BOLD}Port Summary:{RESET}")
        for r in sorted(open_ports, key=lambda x: x['port']):
            ssl_marker = f" {YELLOW}[SSL]{RESET}" if r.get('ssl') else ""
            print(f"  {r['port']:5}/tcp  {r['service']:15}{ssl_marker}")

    # Vulnerability summary
    all_vulns = [v for r in open_ports for v in r.get('vulns', [])]
    if all_vulns:
        print(f"\n{BOLD}{RED}Potential Vulnerabilities:{RESET}")
        for v in set(all_vulns):
            print(f"  {RED}[!]{RESET} {v}")

    print()

if __name__ == '__main__':
    main()
