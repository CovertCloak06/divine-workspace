#!/usr/bin/env python3
"""
Domain Reconnaissance - Full domain investigation
Usage: domain_recon.py [domain] [--deep] [--json]
Comprehensive domain analysis including DNS, WHOIS, subdomains, and more
"""

import sys
import json
import argparse
import socket
import ssl
import urllib.request
import urllib.error
import subprocess
import re
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common subdomains to check
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'imap', 'blog', 'admin',
    'portal', 'api', 'dev', 'staging', 'test', 'beta', 'app', 'mobile', 'm',
    'secure', 'shop', 'store', 'login', 'auth', 'vpn', 'remote', 'cdn', 'static',
    'assets', 'media', 'img', 'images', 'video', 'docs', 'help', 'support',
    'forum', 'wiki', 'git', 'gitlab', 'jenkins', 'ci', 'status', 'monitor',
    'ns1', 'ns2', 'dns', 'mx', 'email', 'cloud', 'server', 'db', 'database',
    'backup', 'old', 'new', 'demo', 'sandbox', 'internal', 'corp', 'intranet',
]


def resolve_domain(domain):
    """Resolve domain to IP addresses"""
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        return ips
    except:
        return []


def get_dns_records(domain, record_type):
    """Get DNS records using dig"""
    try:
        result = subprocess.run(
            ['dig', '+short', record_type, domain],
            capture_output=True, text=True, timeout=10
        )
        records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
        return records
    except:
        return []


def get_all_dns_records(domain):
    """Get all DNS record types"""
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    records = {}

    for rtype in record_types:
        result = get_dns_records(domain, rtype)
        if result:
            records[rtype] = result

    return records


def check_ssl_cert(domain, port=443):
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Parse certificate
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                # Get validity dates
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')

                # Get SANs
                san = []
                for type_name, value in cert.get('subjectAltName', []):
                    if type_name == 'DNS':
                        san.append(value)

                return {
                    'valid': True,
                    'subject': subject.get('commonName', ''),
                    'issuer': issuer.get('organizationName', ''),
                    'not_before': not_before,
                    'not_after': not_after,
                    'san': san[:10],  # Limit SANs
                    'serial': cert.get('serialNumber', ''),
                }
    except ssl.SSLCertVerificationError as e:
        return {'valid': False, 'error': 'Certificate verification failed'}
    except Exception as e:
        return {'valid': False, 'error': str(e)[:50]}


def get_whois_info(domain):
    """Get WHOIS information"""
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=15
        )

        output = result.stdout

        # Parse key fields
        info = {}

        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiry_date': r'(?:Registry Expiry Date|Expiration Date):\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'registrant_country': r'Registrant Country:\s*(.+)',
            'registrant_org': r'Registrant Organization:\s*(.+)',
            'dnssec': r'DNSSEC:\s*(.+)',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == 'name_servers':
                    if 'name_servers' not in info:
                        info['name_servers'] = []
                    info['name_servers'].append(value.lower())
                else:
                    info[key] = value

        # Get all name servers
        ns_matches = re.findall(r'Name Server:\s*(.+)', output, re.IGNORECASE)
        if ns_matches:
            info['name_servers'] = list(set(ns.strip().lower() for ns in ns_matches))[:5]

        return info
    except:
        return {}


def enumerate_subdomains(domain, quick=False):
    """Find subdomains"""
    found = []
    subs_to_check = COMMON_SUBDOMAINS[:20] if quick else COMMON_SUBDOMAINS

    for sub in subs_to_check:
        subdomain = f"{sub}.{domain}"
        ips = resolve_domain(subdomain)
        if ips:
            found.append({'subdomain': subdomain, 'ips': ips})

    return found


def check_web_technologies(domain):
    """Detect web technologies from headers"""
    techs = []

    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})

            with urllib.request.urlopen(req, timeout=10) as response:
                headers = dict(response.headers)

                # Server
                if headers.get('Server'):
                    techs.append(f"Server: {headers['Server']}")

                # X-Powered-By
                if headers.get('X-Powered-By'):
                    techs.append(f"Powered by: {headers['X-Powered-By']}")

                # Framework detection
                for header, tech in [
                    ('X-AspNet-Version', 'ASP.NET'),
                    ('X-Drupal-Cache', 'Drupal'),
                    ('X-Shopify-Stage', 'Shopify'),
                    ('X-Wix-Request-Id', 'Wix'),
                ]:
                    if headers.get(header):
                        techs.append(tech)

                # Cookies
                cookies = headers.get('Set-Cookie', '')
                if 'PHPSESSID' in cookies:
                    techs.append('PHP')
                if 'JSESSIONID' in cookies:
                    techs.append('Java')
                if 'ASP.NET' in cookies:
                    techs.append('ASP.NET')
                if 'laravel' in cookies.lower():
                    techs.append('Laravel')
                if 'wordpress' in cookies.lower():
                    techs.append('WordPress')

                break
        except:
            continue

    return list(set(techs))


def check_security_txt(domain):
    """Check for security.txt"""
    for path in ['/.well-known/security.txt', '/security.txt']:
        try:
            url = f"https://{domain}{path}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Security-Scanner/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                content = response.read().decode()[:500]
                return {'found': True, 'path': path, 'content': content}
        except:
            continue
    return {'found': False}


def check_robots_txt(domain):
    """Get robots.txt"""
    try:
        url = f"https://{domain}/robots.txt"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode()
            lines = content.strip().split('\n')[:20]

            # Extract disallowed paths
            disallowed = []
            for line in lines:
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        disallowed.append(path)

            return {'found': True, 'disallowed': disallowed[:10]}
    except:
        return {'found': False}


def display_results(domain, data):
    """Display reconnaissance results"""
    print(f"\n  {BOLD}Domain Reconnaissance Report{RESET}")
    print(f"  {DIM}{'═' * 55}{RESET}\n")

    print(f"  {CYAN}Target:{RESET}  {BOLD}{domain}{RESET}")
    print(f"  {CYAN}Date:{RESET}    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # DNS Records
    dns = data.get('dns', {})
    if dns:
        print(f"  {BOLD}DNS Records{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")

        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            records = dns.get(rtype, [])
            if records:
                print(f"  {CYAN}{rtype:6}{RESET}", end='')
                for i, rec in enumerate(records[:3]):
                    if i == 0:
                        print(f"  {rec[:50]}")
                    else:
                        print(f"  {' ' * 8}  {rec[:50]}")
                if len(records) > 3:
                    print(f"  {' ' * 8}  {DIM}... and {len(records) - 3} more{RESET}")
        print()

    # WHOIS
    whois = data.get('whois', {})
    if whois:
        print(f"  {BOLD}WHOIS Information{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")

        if whois.get('registrar'):
            print(f"  {CYAN}Registrar:{RESET}    {whois['registrar'][:40]}")
        if whois.get('creation_date'):
            print(f"  {CYAN}Created:{RESET}      {whois['creation_date'][:30]}")
        if whois.get('expiry_date'):
            print(f"  {CYAN}Expires:{RESET}      {whois['expiry_date'][:30]}")
        if whois.get('registrant_org'):
            print(f"  {CYAN}Organization:{RESET} {whois['registrant_org'][:40]}")
        if whois.get('name_servers'):
            print(f"  {CYAN}Nameservers:{RESET}  {', '.join(whois['name_servers'][:3])}")
        print()

    # SSL Certificate
    ssl_info = data.get('ssl', {})
    if ssl_info:
        print(f"  {BOLD}SSL Certificate{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")

        if ssl_info.get('valid'):
            print(f"  {CYAN}Status:{RESET}       {GREEN}Valid{RESET}")
            print(f"  {CYAN}Subject:{RESET}      {ssl_info.get('subject', 'N/A')}")
            print(f"  {CYAN}Issuer:{RESET}       {ssl_info.get('issuer', 'N/A')}")
            print(f"  {CYAN}Expires:{RESET}      {ssl_info.get('not_after', 'N/A')}")
            if ssl_info.get('san'):
                print(f"  {CYAN}SANs:{RESET}         {', '.join(ssl_info['san'][:3])}")
        else:
            print(f"  {CYAN}Status:{RESET}       {RED}Invalid - {ssl_info.get('error', 'Unknown')}{RESET}")
        print()

    # Subdomains
    subdomains = data.get('subdomains', [])
    if subdomains:
        print(f"  {BOLD}Subdomains Found ({len(subdomains)}){RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")

        for sub in subdomains[:10]:
            ips = ', '.join(sub['ips'][:2])
            print(f"  {GREEN}  {sub['subdomain']}{RESET}")
            print(f"     {DIM}{ips}{RESET}")

        if len(subdomains) > 10:
            print(f"  {DIM}  ... and {len(subdomains) - 10} more{RESET}")
        print()

    # Technologies
    techs = data.get('technologies', [])
    if techs:
        print(f"  {BOLD}Technologies Detected{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")
        for tech in techs:
            print(f"  {YELLOW}  {tech}{RESET}")
        print()

    # Security
    print(f"  {BOLD}Security Files{RESET}")
    print(f"  {DIM}{'─' * 45}{RESET}")

    security_txt = data.get('security_txt', {})
    if security_txt.get('found'):
        print(f"  {GREEN}  security.txt found at {security_txt['path']}{RESET}")
    else:
        print(f"  {DIM}  security.txt not found{RESET}")

    robots = data.get('robots_txt', {})
    if robots.get('found'):
        print(f"  {GREEN}  robots.txt found{RESET}")
        if robots.get('disallowed'):
            print(f"     {DIM}Disallowed: {', '.join(robots['disallowed'][:3])}{RESET}")
    else:
        print(f"  {DIM}  robots.txt not found{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Domain Reconnaissance')
    parser.add_argument('domain', nargs='?', help='Domain to investigate')
    parser.add_argument('--deep', '-d', action='store_true', help='Deep scan (more subdomains)')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick scan')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Domain Reconnaissance Tool{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    domain = args.domain
    if not domain:
        domain = input(f"\n  {CYAN}Domain to investigate:{RESET} ").strip()

    if not domain:
        print(f"  {RED}Domain required{RESET}")
        sys.exit(1)

    # Clean domain
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

    data = {'domain': domain}

    # Run scans
    steps = [
        ('Getting DNS records', lambda: get_all_dns_records(domain)),
        ('Checking WHOIS', lambda: get_whois_info(domain)),
        ('Checking SSL certificate', lambda: check_ssl_cert(domain)),
        ('Detecting technologies', lambda: check_web_technologies(domain)),
        ('Checking security.txt', lambda: check_security_txt(domain)),
        ('Checking robots.txt', lambda: check_robots_txt(domain)),
    ]

    if not args.quick:
        steps.append(('Enumerating subdomains', lambda: enumerate_subdomains(domain, not args.deep)))

    for desc, func in steps:
        if not args.json:
            print(f"  {DIM}{desc}...{RESET}", end=' ', flush=True)
        try:
            key = desc.split()[-1].lower().replace('.', '_')
            if key == 'records':
                key = 'dns'
            elif key == 'certificate':
                key = 'ssl'
            result = func()
            data[key] = result
            if not args.json:
                print(f"{GREEN}OK{RESET}")
        except Exception as e:
            if not args.json:
                print(f"{RED}Failed{RESET}")
            data[key] = {'error': str(e)}

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        display_results(domain, data)


if __name__ == '__main__':
    main()
