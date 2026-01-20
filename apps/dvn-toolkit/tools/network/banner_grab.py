#!/usr/bin/env python3
"""
Banner Grabber - Grab service banners from ports (Shodan-lite)
Usage: banner_grab.py [host] [--ports PORTS] [--json]
Connects to services and retrieves version/banner information
"""

import sys
import json
import argparse
import socket
import ssl
import re
import concurrent.futures

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common ports and their services
COMMON_PORTS = {
    21: {'name': 'FTP', 'probe': b'', 'ssl': False},
    22: {'name': 'SSH', 'probe': b'', 'ssl': False},
    23: {'name': 'Telnet', 'probe': b'', 'ssl': False},
    25: {'name': 'SMTP', 'probe': b'EHLO probe\r\n', 'ssl': False},
    80: {'name': 'HTTP', 'probe': b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n', 'ssl': False},
    110: {'name': 'POP3', 'probe': b'', 'ssl': False},
    143: {'name': 'IMAP', 'probe': b'', 'ssl': False},
    443: {'name': 'HTTPS', 'probe': b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n', 'ssl': True},
    465: {'name': 'SMTPS', 'probe': b'EHLO probe\r\n', 'ssl': True},
    587: {'name': 'SMTP-SUB', 'probe': b'EHLO probe\r\n', 'ssl': False},
    993: {'name': 'IMAPS', 'probe': b'', 'ssl': True},
    995: {'name': 'POP3S', 'probe': b'', 'ssl': True},
    1433: {'name': 'MSSQL', 'probe': b'', 'ssl': False},
    3306: {'name': 'MySQL', 'probe': b'', 'ssl': False},
    3389: {'name': 'RDP', 'probe': b'', 'ssl': False},
    5432: {'name': 'PostgreSQL', 'probe': b'', 'ssl': False},
    5900: {'name': 'VNC', 'probe': b'', 'ssl': False},
    6379: {'name': 'Redis', 'probe': b'INFO\r\n', 'ssl': False},
    8080: {'name': 'HTTP-ALT', 'probe': b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n', 'ssl': False},
    8443: {'name': 'HTTPS-ALT', 'probe': b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n', 'ssl': True},
    9200: {'name': 'Elasticsearch', 'probe': b'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n', 'ssl': False},
    27017: {'name': 'MongoDB', 'probe': b'', 'ssl': False},
}


def grab_banner(host, port, timeout=5, use_ssl=False, probe=b''):
    """Grab banner from a single port"""
    result = {
        'port': port,
        'state': 'closed',
        'service': COMMON_PORTS.get(port, {}).get('name', 'unknown'),
        'banner': None,
        'ssl': use_ssl,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        result['state'] = 'open'

        # Send probe if specified
        if probe:
            probe_data = probe.replace(b'{host}', host.encode())
            sock.send(probe_data)

        # Receive banner
        try:
            sock.settimeout(3)
            banner = sock.recv(4096)
            if banner:
                # Clean banner
                banner_text = banner.decode('utf-8', errors='replace').strip()
                # Limit length
                result['banner'] = banner_text[:500]
        except socket.timeout:
            pass

        # Try to get SSL certificate info
        if use_ssl and hasattr(sock, 'getpeercert'):
            try:
                cert = sock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result['ssl_subject'] = subject.get('commonName', '')
            except:
                pass

        sock.close()

    except socket.timeout:
        result['state'] = 'filtered'
    except ConnectionRefusedError:
        result['state'] = 'closed'
    except ssl.SSLError as e:
        result['state'] = 'open'
        result['ssl_error'] = str(e)[:50]
    except Exception as e:
        result['error'] = str(e)[:50]

    return result


def scan_ports(host, ports, timeout=5, threads=10):
    """Scan multiple ports and grab banners"""
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}

        for port in ports:
            port_info = COMMON_PORTS.get(port, {})
            use_ssl = port_info.get('ssl', port in [443, 465, 993, 995, 8443])
            probe = port_info.get('probe', b'')

            future = executor.submit(grab_banner, host, port, timeout, use_ssl, probe)
            futures[future] = port

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)

    # Sort by port number
    results.sort(key=lambda x: x['port'])
    return results


def parse_ports(port_string):
    """Parse port specification"""
    ports = set()

    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            except:
                pass
        else:
            try:
                ports.add(int(part))
            except:
                pass

    return sorted(ports)


def extract_version(banner):
    """Try to extract version info from banner"""
    if not banner:
        return None

    # Common version patterns
    patterns = [
        r'Server:\s*([^\r\n]+)',  # HTTP Server header
        r'SSH-[\d\.]+-([\w\d\.\-_]+)',  # SSH version
        r'(\d+\.\d+[\.\d]*)',  # Generic version numbers
        r'([A-Za-z]+/[\d\.]+)',  # Product/version format
    ]

    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)[:50]

    return None


def display_results(host, results):
    """Display banner grab results"""
    print(f"\n  {BOLD}Banner Grab Results{RESET}")
    print(f"  {DIM}{'═' * 60}{RESET}\n")

    print(f"  {CYAN}Host:{RESET}  {host}")
    print()

    open_ports = [r for r in results if r['state'] == 'open']
    filtered_ports = [r for r in results if r['state'] == 'filtered']

    if not open_ports:
        print(f"  {YELLOW}No open ports found{RESET}\n")
        return

    print(f"  {BOLD}Open Ports ({len(open_ports)}){RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}\n")

    for r in open_ports:
        port = r['port']
        service = r['service']
        banner = r.get('banner', '')

        # Status indicator
        ssl_indicator = f" {CYAN}[SSL]{RESET}" if r.get('ssl') else ""

        print(f"  {GREEN}{port:5}{RESET} {service:12}{ssl_indicator}")

        # Extract and show version
        version = extract_version(banner)
        if version:
            print(f"       {CYAN}Version:{RESET} {version}")

        # Show banner preview
        if banner:
            # Clean up banner for display
            banner_preview = banner.replace('\r\n', ' ').replace('\n', ' ')[:80]
            print(f"       {DIM}{banner_preview}{'...' if len(banner) > 80 else ''}{RESET}")

        if r.get('ssl_subject'):
            print(f"       {CYAN}SSL CN:{RESET} {r['ssl_subject']}")

        print()

    if filtered_ports:
        print(f"  {DIM}Filtered ports: {len(filtered_ports)}{RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(description='Banner Grabber')
    parser.add_argument('host', nargs='?', help='Target host')
    parser.add_argument('--ports', '-p', default='21,22,23,25,80,110,143,443,3306,3389,5432,8080,8443',
                       help='Ports to scan (e.g., 80,443 or 1-1000)')
    parser.add_argument('--common', '-c', action='store_true', help='Scan all common ports')
    parser.add_argument('--timeout', '-t', type=int, default=5, help='Timeout per port')
    parser.add_argument('--threads', type=int, default=10, help='Concurrent threads')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Banner Grabber (Shodan-lite){RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    host = args.host
    if not host:
        host = input(f"\n  {CYAN}Target host:{RESET} ").strip()

    if not host:
        print(f"  {RED}Host required{RESET}")
        sys.exit(1)

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
        if not args.json:
            print(f"\n  {DIM}Resolved {host} to {ip}{RESET}")
    except:
        if not args.json:
            print(f"  {YELLOW}Could not resolve {host}, using as-is{RESET}")
        ip = host

    # Parse ports
    if args.common:
        ports = list(COMMON_PORTS.keys())
    else:
        ports = parse_ports(args.ports)

    if not args.json:
        print(f"  {DIM}Scanning {len(ports)} ports...{RESET}\n")

    results = scan_ports(ip, ports, args.timeout, args.threads)

    if args.json:
        output = {
            'host': host,
            'ip': ip,
            'results': results
        }
        print(json.dumps(output, indent=2))
    else:
        display_results(host, results)


if __name__ == '__main__':
    main()
