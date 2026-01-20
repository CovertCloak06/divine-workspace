#!/usr/bin/env python3
"""
Recon Tool - WHOIS, DNS, IP info, headers, and more
Usage: recon <target> [--whois] [--dns] [--headers] [--all]
"""

import argparse
import socket
import ssl
import json
import re
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlparse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

def get_dns_records(domain):
    """Get DNS records for a domain"""
    records = {}

    # A records
    try:
        records['A'] = socket.gethostbyname_ex(domain)[2]
    except:
        records['A'] = []

    # Try to get MX, NS via DNS query (basic)
    try:
        import subprocess

        # MX records
        result = subprocess.run(['dig', '+short', 'MX', domain], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            records['MX'] = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

        # NS records
        result = subprocess.run(['dig', '+short', 'NS', domain], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            records['NS'] = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

        # TXT records
        result = subprocess.run(['dig', '+short', 'TXT', domain], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            records['TXT'] = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
    except:
        pass

    return records

def get_whois(target):
    """Get WHOIS info via web API"""
    try:
        url = f"https://api.hackertarget.com/whois/?q={target}"
        req = Request(url, headers={'User-Agent': 'ReconTool/1.0'})
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode()
    except Exception as e:
        return f"Error: {e}"

def get_http_headers(url):
    """Get HTTP headers from a URL"""
    if not url.startswith('http'):
        url = f'https://{url}'

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
        })

        with urlopen(req, timeout=10, context=ctx) as resp:
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'url': resp.url
            }
    except Exception as e:
        return {'error': str(e)}

def get_ssl_info(domain, port=443):
    """Get SSL certificate info"""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, port))
            cert = s.getpeercert()
            return {
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'serial': cert.get('serialNumber'),
                'notBefore': cert.get('notBefore'),
                'notAfter': cert.get('notAfter'),
                'san': [x[1] for x in cert.get('subjectAltName', [])]
            }
    except Exception as e:
        return {'error': str(e)}

def get_ip_info(ip):
    """Get IP geolocation info"""
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = Request(url, headers={'User-Agent': 'ReconTool/1.0'})
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {'error': str(e)}

def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def analyze_headers(headers):
    """Analyze security headers"""
    security_headers = {
        'Strict-Transport-Security': 'HSTS - Forces HTTPS',
        'X-Frame-Options': 'Clickjacking protection',
        'X-Content-Type-Options': 'MIME sniffing protection',
        'Content-Security-Policy': 'CSP - Script injection protection',
        'X-XSS-Protection': 'XSS filter (deprecated)',
        'Referrer-Policy': 'Referrer info control',
        'Permissions-Policy': 'Feature permissions',
    }

    findings = []
    for header, desc in security_headers.items():
        if header in headers or header.lower() in [h.lower() for h in headers]:
            findings.append((header, GREEN, 'Present'))
        else:
            findings.append((header, RED, 'Missing'))

    return findings

def main():
    parser = argparse.ArgumentParser(description='Recon Tool')
    parser.add_argument('target', help='Target domain, URL, or IP')
    parser.add_argument('--whois', '-w', action='store_true', help='WHOIS lookup')
    parser.add_argument('--dns', '-d', action='store_true', help='DNS records')
    parser.add_argument('--headers', '-H', action='store_true', help='HTTP headers')
    parser.add_argument('--ssl', '-s', action='store_true', help='SSL certificate info')
    parser.add_argument('--ip', '-i', action='store_true', help='IP geolocation')
    parser.add_argument('--all', '-a', action='store_true', help='All checks')
    args = parser.parse_args()

    target = args.target.strip()

    # Parse target
    if target.startswith('http'):
        parsed = urlparse(target)
        domain = parsed.netloc
        url = target
    else:
        domain = target
        url = f'https://{target}'

    # Check if IP
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)

    print(f"\n{BOLD}{CYAN}Reconnaissance: {target}{RESET}\n")

    # Resolve to IP if domain
    if not is_ip:
        try:
            ip = socket.gethostbyname(domain)
            print(f"{BOLD}IP Address:{RESET} {ip}")
            rdns = reverse_dns(ip)
            if rdns:
                print(f"{BOLD}Reverse DNS:{RESET} {rdns}")
        except:
            ip = None
            print(f"{RED}Could not resolve domain{RESET}")
    else:
        ip = domain
        rdns = reverse_dns(ip)
        if rdns:
            print(f"{BOLD}Reverse DNS:{RESET} {rdns}")

    # DNS Records
    if (args.dns or args.all) and not is_ip:
        print(f"\n{BOLD}DNS Records{RESET}")
        records = get_dns_records(domain)
        for rtype, values in records.items():
            if values:
                print(f"  {CYAN}{rtype:5}{RESET} {', '.join(values)}")

    # WHOIS
    if args.whois or args.all:
        print(f"\n{BOLD}WHOIS{RESET}")
        whois = get_whois(domain if not is_ip else ip)
        # Show relevant lines
        for line in whois.split('\n')[:20]:
            if line.strip() and not line.startswith('%') and not line.startswith('#'):
                print(f"  {line}")
        if whois.count('\n') > 20:
            print(f"  {DIM}... (truncated){RESET}")

    # HTTP Headers
    if args.headers or args.all:
        print(f"\n{BOLD}HTTP Headers{RESET}")
        result = get_http_headers(url)
        if 'error' in result:
            print(f"  {RED}{result['error']}{RESET}")
        else:
            print(f"  Status: {result['status']}")
            print(f"  Final URL: {result['url']}")
            print(f"\n  {BOLD}Headers:{RESET}")
            for k, v in result['headers'].items():
                print(f"    {CYAN}{k}:{RESET} {v[:60]}{'...' if len(v) > 60 else ''}")

            print(f"\n  {BOLD}Security Headers Analysis:{RESET}")
            for header, color, status in analyze_headers(result['headers']):
                print(f"    {color}[{status:7}]{RESET} {header}")

    # SSL Info
    if (args.ssl or args.all) and not is_ip:
        print(f"\n{BOLD}SSL Certificate{RESET}")
        ssl_info = get_ssl_info(domain)
        if 'error' in ssl_info:
            print(f"  {RED}{ssl_info['error']}{RESET}")
        else:
            print(f"  Subject: {ssl_info['subject'].get('commonName', 'N/A')}")
            print(f"  Issuer: {ssl_info['issuer'].get('organizationName', 'N/A')}")
            print(f"  Valid: {ssl_info['notBefore']} to {ssl_info['notAfter']}")
            if ssl_info['san']:
                print(f"  SANs: {', '.join(ssl_info['san'][:5])}")
                if len(ssl_info['san']) > 5:
                    print(f"        {DIM}... and {len(ssl_info['san']) - 5} more{RESET}")

    # IP Info
    if args.ip or args.all:
        print(f"\n{BOLD}IP Geolocation{RESET}")
        if ip:
            info = get_ip_info(ip)
            if 'error' not in info and info.get('status') == 'success':
                print(f"  Country: {info.get('country')} ({info.get('countryCode')})")
                print(f"  Region: {info.get('regionName')}")
                print(f"  City: {info.get('city')}")
                print(f"  ISP: {info.get('isp')}")
                print(f"  Org: {info.get('org')}")
                print(f"  AS: {info.get('as')}")
            else:
                print(f"  {RED}Could not get IP info{RESET}")

    print()

if __name__ == '__main__':
    main()
