#!/usr/bin/env python3
"""
Reverse DNS Lookup - Get hostnames from IP addresses
Usage: reverse_dns.py [ip] [--range] [--json]
Performs reverse DNS lookups and discovers associated domains
"""

import sys
import json
import argparse
import socket
import subprocess
import ipaddress
import concurrent.futures

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def reverse_lookup(ip):
    """Perform reverse DNS lookup"""
    try:
        # Use socket for basic reverse lookup
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {'ip': ip, 'hostname': hostname, 'success': True}
    except socket.herror:
        return {'ip': ip, 'hostname': None, 'success': False, 'error': 'No PTR record'}
    except socket.gaierror as e:
        return {'ip': ip, 'hostname': None, 'success': False, 'error': str(e)}
    except Exception as e:
        return {'ip': ip, 'hostname': None, 'success': False, 'error': str(e)}


def reverse_lookup_dig(ip):
    """Use dig for more detailed reverse lookup"""
    try:
        # Create PTR record name
        if ':' in ip:  # IPv6
            return reverse_lookup(ip)

        octets = ip.split('.')
        ptr_name = '.'.join(reversed(octets)) + '.in-addr.arpa'

        result = subprocess.run(
            ['dig', '+short', '-x', ip],
            capture_output=True, text=True, timeout=10
        )

        hostname = result.stdout.strip()
        if hostname:
            # Remove trailing dot
            hostname = hostname.rstrip('.')
            return {'ip': ip, 'hostname': hostname, 'success': True, 'ptr': ptr_name}
        else:
            return {'ip': ip, 'hostname': None, 'success': False, 'error': 'No PTR record', 'ptr': ptr_name}
    except subprocess.TimeoutExpired:
        return {'ip': ip, 'hostname': None, 'success': False, 'error': 'Timeout'}
    except Exception as e:
        # Fall back to socket
        return reverse_lookup(ip)


def expand_cidr(cidr):
    """Expand CIDR notation to list of IPs"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Limit to /24 or smaller
        if network.num_addresses > 256:
            raise ValueError("Network too large (max /24)")
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        return []


def expand_range(ip_range):
    """Expand IP range to list of IPs"""
    # Format: 192.168.1.1-50 or 192.168.1.1-192.168.1.50
    try:
        if '-' not in ip_range:
            return [ip_range]

        parts = ip_range.split('-')
        if len(parts) != 2:
            return []

        base = parts[0].strip()
        end = parts[1].strip()

        # Check if end is just a number (e.g., 192.168.1.1-50)
        if '.' not in end:
            base_parts = base.split('.')
            start_num = int(base_parts[3])
            end_num = int(end)

            if end_num < start_num or end_num > 255:
                return []

            ips = []
            for i in range(start_num, end_num + 1):
                ips.append(f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}")
            return ips
        else:
            # Full range: 192.168.1.1-192.168.1.50
            start_ip = ipaddress.ip_address(base)
            end_ip = ipaddress.ip_address(end)

            if end_ip < start_ip:
                return []

            count = int(end_ip) - int(start_ip) + 1
            if count > 256:
                return []

            return [str(ipaddress.ip_address(int(start_ip) + i)) for i in range(count)]
    except Exception as e:
        return []


def bulk_reverse_lookup(ips, threads=20, show_progress=True):
    """Perform reverse lookups on multiple IPs"""
    results = []
    total = len(ips)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(reverse_lookup_dig, ip): ip for ip in ips}

        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            results.append(result)

            if show_progress:
                done = i + 1
                pct = int((done / total) * 100)
                bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
                print(f"\r  [{bar}] {pct}% ({done}/{total})", end='', flush=True)

    if show_progress:
        print()

    return results


def display_results(results, show_all=False):
    """Display reverse lookup results"""
    print(f"\n  {BOLD}Reverse DNS Results{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}\n")

    # Group by success
    found = [r for r in results if r['success']]
    not_found = [r for r in results if not r['success']]

    print(f"  {GREEN}Found:{RESET} {len(found)} | {YELLOW}No PTR:{RESET} {len(not_found)}")
    print()

    if found:
        print(f"  {BOLD}Resolved Hostnames{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for r in found:
            print(f"  {CYAN}{r['ip']:15}{RESET} -> {GREEN}{r['hostname']}{RESET}")

        print()

    if show_all and not_found:
        print(f"  {BOLD}No PTR Record{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for r in not_found[:20]:
            print(f"  {DIM}{r['ip']:15} -> No PTR{RESET}")

        if len(not_found) > 20:
            print(f"  {DIM}... and {len(not_found) - 20} more{RESET}")

        print()


def main():
    parser = argparse.ArgumentParser(description='Reverse DNS Lookup')
    parser.add_argument('target', nargs='?', help='IP, CIDR, or range (e.g., 192.168.1.1-50)')
    parser.add_argument('--range', '-r', action='store_true', help='Treat input as range')
    parser.add_argument('--cidr', '-c', action='store_true', help='Treat input as CIDR')
    parser.add_argument('--threads', '-t', type=int, default=20, help='Concurrent threads')
    parser.add_argument('--all', '-a', action='store_true', help='Show all results including failures')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Reverse DNS Lookup{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    target = args.target
    if not target:
        target = input(f"\n  {CYAN}Target IP/CIDR/Range:{RESET} ").strip()

    if not target:
        print(f"  {RED}Target required{RESET}")
        sys.exit(1)

    # Determine what kind of target this is
    ips = []

    if '/' in target:
        # CIDR notation
        ips = expand_cidr(target)
        if not ips:
            print(f"  {RED}Invalid or too large CIDR (max /24){RESET}")
            sys.exit(1)
    elif '-' in target:
        # Range
        ips = expand_range(target)
        if not ips:
            print(f"  {RED}Invalid range format{RESET}")
            sys.exit(1)
    else:
        # Single IP
        ips = [target]

    if not args.json:
        print(f"\n  {DIM}Looking up {len(ips)} IP(s)...{RESET}\n")

    if len(ips) == 1:
        # Single lookup
        result = reverse_lookup_dig(ips[0])

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"  {BOLD}Result{RESET}")
            print(f"  {DIM}{'─' * 50}{RESET}\n")

            print(f"  {CYAN}IP:{RESET}       {result['ip']}")
            if result['success']:
                print(f"  {CYAN}Hostname:{RESET} {GREEN}{result['hostname']}{RESET}")
            else:
                print(f"  {CYAN}Hostname:{RESET} {YELLOW}Not found ({result.get('error', 'Unknown')}){RESET}")

            if result.get('ptr'):
                print(f"  {CYAN}PTR Name:{RESET} {DIM}{result['ptr']}{RESET}")
            print()

    else:
        # Bulk lookup
        results = bulk_reverse_lookup(ips, args.threads, not args.json)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            display_results(results, args.all)


if __name__ == '__main__':
    main()
