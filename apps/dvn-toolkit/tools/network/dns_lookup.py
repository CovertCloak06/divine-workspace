#!/usr/bin/env python3
"""
DNS Lookup Tool - Query DNS records for any domain
Usage: dns_lookup.py <domain> [--type A]
"""

import socket
import subprocess
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']


def query_dns_dig(domain, record_type='A'):
    """Query DNS using dig command"""
    try:
        result = subprocess.run(
            ['dig', '+short', record_type, domain],
            capture_output=True, text=True, timeout=10
        )
        records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
        return records
    except:
        return []


def query_dns_nslookup(domain, record_type='A'):
    """Query DNS using nslookup as fallback"""
    try:
        result = subprocess.run(
            ['nslookup', f'-type={record_type}', domain],
            capture_output=True, text=True, timeout=10
        )
        # Parse nslookup output
        records = []
        for line in result.stdout.split('\n'):
            if 'Address:' in line and '#' not in line:
                records.append(line.split('Address:')[1].strip())
            elif '=' in line:
                records.append(line.split('=')[1].strip())
        return records
    except:
        return []


def query_dns_socket(domain):
    """Query A record using socket (basic fallback)"""
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        return ips
    except:
        return []


def reverse_dns(ip):
    """Perform reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return None


def get_all_records(domain):
    """Get all DNS record types"""
    results = {}
    for rtype in RECORD_TYPES:
        records = query_dns_dig(domain, rtype)
        if not records:
            records = query_dns_nslookup(domain, rtype)
        if records:
            results[rtype] = records
    return results


def main():
    parser = argparse.ArgumentParser(description='DNS Lookup Tool')
    parser.add_argument('domain', help='Domain to query')
    parser.add_argument('--type', '-t', default='ALL', help='Record type (A, AAAA, MX, NS, TXT, CNAME, SOA, ALL)')
    parser.add_argument('--reverse', '-r', action='store_true', help='Reverse DNS lookup (for IP)')
    parser.add_argument('--trace', action='store_true', help='Trace DNS resolution path')
    args = parser.parse_args()

    domain = args.domain.replace('https://', '').replace('http://', '').split('/')[0]

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🌐 DNS Lookup Tool                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Domain: {domain}{RESET}\n")

    # Reverse lookup
    if args.reverse:
        print(f"  {BOLD}Reverse DNS Lookup:{RESET}")
        hostname = reverse_dns(domain)
        if hostname:
            print(f"  {GREEN}{domain} → {hostname}{RESET}")
        else:
            print(f"  {RED}No PTR record found{RESET}")
        print()
        return

    # Trace
    if args.trace:
        print(f"  {BOLD}DNS Resolution Trace:{RESET}")
        try:
            result = subprocess.run(
                ['dig', '+trace', domain],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n')[:30]:
                if line.strip() and not line.startswith(';'):
                    print(f"  {DIM}{line}{RESET}")
        except:
            print(f"  {RED}Trace requires dig command{RESET}")
        print()
        return

    # Query specific or all record types
    if args.type.upper() == 'ALL':
        results = get_all_records(domain)

        if not results:
            print(f"  {RED}No DNS records found{RESET}\n")
            return

        for rtype, records in results.items():
            color = {
                'A': GREEN, 'AAAA': GREEN, 'MX': YELLOW,
                'NS': CYAN, 'TXT': DIM, 'CNAME': YELLOW
            }.get(rtype, RESET)

            print(f"  {BOLD}{rtype} Records:{RESET}")
            for record in records:
                # For A records, try reverse lookup
                extra = ''
                if rtype == 'A':
                    rev = reverse_dns(record)
                    if rev:
                        extra = f" {DIM}({rev}){RESET}"

                print(f"    {color}•{RESET} {record}{extra}")
            print()

    else:
        rtype = args.type.upper()
        records = query_dns_dig(domain, rtype)
        if not records:
            records = query_dns_nslookup(domain, rtype)

        print(f"  {BOLD}{rtype} Records:{RESET}")
        if records:
            for record in records:
                print(f"    {GREEN}•{RESET} {record}")
        else:
            print(f"    {DIM}No {rtype} records found{RESET}")
        print()

    # Additional info
    print(f"  {BOLD}Quick Info:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")

    # Get nameservers
    ns_records = query_dns_dig(domain, 'NS')
    if ns_records:
        print(f"  {CYAN}Nameservers:{RESET} {', '.join(ns_records[:3])}")

    # Check if domain uses common services
    txt_records = query_dns_dig(domain, 'TXT')
    services = []
    for txt in txt_records:
        if 'google-site' in txt.lower():
            services.append('Google Verified')
        if 'v=spf1' in txt:
            services.append('SPF')
        if 'v=DMARC' in txt.upper():
            services.append('DMARC')
        if 'MS=' in txt:
            services.append('Microsoft 365')

    if services:
        print(f"  {CYAN}Detected:{RESET} {', '.join(services)}")

    print()


if __name__ == '__main__':
    main()
