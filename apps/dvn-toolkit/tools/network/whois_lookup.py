#!/usr/bin/env python3
"""
WHOIS Lookup - Query domain registration information
Usage: whois_lookup.py <domain>
"""

import socket
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# WHOIS servers for different TLDs
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'ai': 'whois.nic.ai',
    'dev': 'whois.nic.google',
    'app': 'whois.nic.google',
    'me': 'whois.nic.me',
    'us': 'whois.nic.us',
    'uk': 'whois.nic.uk',
    'de': 'whois.denic.de',
    'fr': 'whois.nic.fr',
    'eu': 'whois.eu',
    'ru': 'whois.tcinet.ru',
    'cn': 'whois.cnnic.cn',
    'jp': 'whois.jprs.jp',
    'au': 'whois.auda.org.au',
    'ca': 'whois.cira.ca',
    'nl': 'whois.domain-registry.nl',
    'be': 'whois.dns.be',
    'ch': 'whois.nic.ch',
    'se': 'whois.iis.se',
    'no': 'whois.norid.no',
    'pl': 'whois.dns.pl',
    'br': 'whois.registro.br',
    'in': 'whois.registry.in',
    'xyz': 'whois.nic.xyz',
    'online': 'whois.nic.online',
    'site': 'whois.nic.site',
    'tech': 'whois.nic.tech',
}


def get_whois_server(domain):
    """Determine WHOIS server for domain"""
    parts = domain.lower().split('.')
    tld = parts[-1] if parts else None

    # Try TLD-specific server
    if tld in WHOIS_SERVERS:
        return WHOIS_SERVERS[tld]

    # Default to IANA
    return 'whois.iana.org'


def query_whois(domain, server, port=43):
    """Query WHOIS server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, port))

        # Send query
        query = f"{domain}\r\n"
        sock.send(query.encode())

        # Receive response
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        return response.decode('utf-8', errors='ignore')

    except socket.timeout:
        return None
    except Exception as e:
        return None


def parse_whois(response):
    """Parse WHOIS response into structured data"""
    data = {}

    patterns = {
        'registrar': r'Registrar:\s*(.+)',
        'registrar_url': r'Registrar URL:\s*(.+)',
        'creation_date': r'Creat(?:ion|ed).*?:\s*(.+)',
        'expiration_date': r'(?:Expir(?:y|ation)|Registry Expiry).*?:\s*(.+)',
        'updated_date': r'Updated.*?:\s*(.+)',
        'status': r'(?:Domain )?Status:\s*(.+)',
        'name_servers': r'Name Server:\s*(.+)',
        'registrant_name': r'Registrant Name:\s*(.+)',
        'registrant_org': r'Registrant Organi[sz]ation:\s*(.+)',
        'registrant_country': r'Registrant Country:\s*(.+)',
        'admin_email': r'(?:Admin|Registrant) Email:\s*(.+)',
        'dnssec': r'DNSSEC:\s*(.+)',
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            if key in ['status', 'name_servers']:
                data[key] = [m.strip() for m in matches]
            else:
                data[key] = matches[0].strip()

    return data


def main():
    parser = argparse.ArgumentParser(description='WHOIS Lookup')
    parser.add_argument('domain', nargs='?', help='Domain to lookup')
    parser.add_argument('--server', '-s', help='WHOIS server to use')
    parser.add_argument('--raw', '-r', action='store_true', help='Show raw response')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🌐 WHOIS Lookup                               ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.domain:
        args.domain = input(f"  {CYAN}Domain:{RESET} ").strip()

    if not args.domain:
        print(f"  {RED}Domain required{RESET}\n")
        return

    # Clean domain
    domain = args.domain.lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.strip('.')

    print(f"  {BOLD}Domain:{RESET} {domain}")

    # Determine WHOIS server
    server = args.server or get_whois_server(domain)
    print(f"  {DIM}Server: {server}{RESET}")

    print(f"\n  {DIM}Querying...{RESET}")

    # First query
    response = query_whois(domain, server)

    if not response:
        print(f"\n  {RED}No response from WHOIS server{RESET}\n")
        return

    # Check for referral to another server
    referral_match = re.search(r'Registrar WHOIS Server:\s*(\S+)', response)
    if referral_match and referral_match.group(1) != server:
        referral_server = referral_match.group(1)
        print(f"  {DIM}Following referral to {referral_server}...{RESET}")
        referral_response = query_whois(domain, referral_server)
        if referral_response:
            response = referral_response

    # Raw output
    if args.raw:
        print(f"\n{response}")
        return

    # Parse and display
    data = parse_whois(response)

    print(f"\n  {BOLD}Registration Info:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    if data.get('registrar'):
        print(f"  {CYAN}Registrar:{RESET}     {data['registrar']}")

    if data.get('registrar_url'):
        print(f"  {CYAN}Registrar URL:{RESET} {data['registrar_url']}")

    if data.get('creation_date'):
        print(f"  {CYAN}Created:{RESET}       {data['creation_date']}")

    if data.get('expiration_date'):
        exp = data['expiration_date']
        # Check if expiring soon
        print(f"  {CYAN}Expires:{RESET}       {exp}")

    if data.get('updated_date'):
        print(f"  {CYAN}Updated:{RESET}       {data['updated_date']}")

    # Status
    if data.get('status'):
        print(f"\n  {BOLD}Status:{RESET}")
        for status in data['status'][:5]:
            # Parse status code
            status_code = status.split()[0] if status else status
            if 'clientTransferProhibited' in status:
                color = GREEN
            elif 'pendingDelete' in status or 'redemption' in status.lower():
                color = RED
            else:
                color = RESET
            print(f"    {color}• {status_code}{RESET}")

    # Name servers
    if data.get('name_servers'):
        print(f"\n  {BOLD}Name Servers:{RESET}")
        for ns in data['name_servers'][:6]:
            print(f"    {CYAN}•{RESET} {ns.lower()}")

    # Registrant info (if available)
    if any(data.get(k) for k in ['registrant_name', 'registrant_org', 'registrant_country']):
        print(f"\n  {BOLD}Registrant:{RESET}")
        if data.get('registrant_name'):
            print(f"  {CYAN}Name:{RESET}    {data['registrant_name']}")
        if data.get('registrant_org'):
            print(f"  {CYAN}Org:{RESET}     {data['registrant_org']}")
        if data.get('registrant_country'):
            print(f"  {CYAN}Country:{RESET} {data['registrant_country']}")

    # DNSSEC
    if data.get('dnssec'):
        dnssec = data['dnssec']
        if 'signed' in dnssec.lower() or 'yes' in dnssec.lower():
            print(f"\n  {GREEN}✓ DNSSEC enabled{RESET}")
        else:
            print(f"\n  {DIM}DNSSEC: {dnssec}{RESET}")

    # If no structured data found
    if not data:
        print(f"\n  {YELLOW}Could not parse structured data{RESET}")
        print(f"  {DIM}Use --raw to see full response{RESET}")

    print()


if __name__ == '__main__':
    main()
