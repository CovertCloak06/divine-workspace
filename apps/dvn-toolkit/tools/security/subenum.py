#!/usr/bin/env python3
"""
Subdomain Enumerator - Find subdomains via DNS bruteforce and public sources
Usage: subenum <domain> [--wordlist subdomains.txt] [--threads 20]
"""

import argparse
import socket
import concurrent.futures
import ssl
import json
from urllib.request import urlopen, Request
from urllib.error import URLError

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common subdomains for bruteforce
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'dns', 'dns1', 'dns2', 'vpn', 'gateway', 'router', 'api', 'dev', 'staging',
    'test', 'portal', 'admin', 'blog', 'shop', 'store', 'secure', 'login',
    'app', 'apps', 'mobile', 'm', 'cdn', 'static', 'assets', 'img', 'images',
    'video', 'videos', 'media', 'download', 'downloads', 'files', 'docs',
    'support', 'help', 'kb', 'wiki', 'forum', 'forums', 'community', 'board',
    'cpanel', 'panel', 'whm', 'plesk', 'webmin', 'phpmyadmin', 'mysql', 'sql',
    'db', 'database', 'backup', 'backups', 'git', 'svn', 'jenkins', 'ci',
    'jira', 'confluence', 'bitbucket', 'gitlab', 'github', 'slack', 'mail2',
    'mx', 'mx1', 'mx2', 'email', 'remote', 'server', 'server1', 'server2',
    'web', 'web1', 'web2', 'cloud', 'aws', 'azure', 'gcp', 'api1', 'api2',
    'v1', 'v2', 'beta', 'alpha', 'demo', 'preview', 'stage', 'staging2',
    'uat', 'qa', 'prod', 'production', 'internal', 'intranet', 'extranet',
    'partners', 'partner', 'client', 'clients', 'customer', 'customers',
    'billing', 'payment', 'payments', 'checkout', 'cart', 'account', 'accounts',
    'dashboard', 'console', 'status', 'health', 'monitor', 'monitoring',
    'logs', 'log', 'analytics', 'stats', 'metrics', 'grafana', 'kibana',
    'elastic', 'elasticsearch', 'redis', 'memcached', 'cache', 'proxy',
    'ns', 'ns3', 'ns4', 'autodiscover', 'autoconfig', 'imap', 'pop3',
    'exchange', 'owa', 'calendar', 'meet', 'meetings', 'webex', 'zoom',
    'sso', 'auth', 'oauth', 'identity', 'idp', 'ldap', 'ad', 'directory'
]

def resolve_subdomain(subdomain, domain):
    """Try to resolve a subdomain"""
    fqdn = f"{subdomain}.{domain}"
    try:
        ips = socket.gethostbyname_ex(fqdn)[2]
        return (fqdn, ips)
    except socket.gaierror:
        return None
    except Exception:
        return None

def query_crtsh(domain):
    """Query crt.sh for certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, headers={'User-Agent': 'SubdomainEnumerator/1.0'})
        with urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and '*' not in sub:
                        subdomains.add(sub)
            return subdomains
    except Exception as e:
        return set()

def query_hackertarget(domain):
    """Query HackerTarget API for subdomains"""
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = Request(url, headers={'User-Agent': 'SubdomainEnumerator/1.0'})
        with urlopen(req, timeout=10) as resp:
            data = resp.read().decode()
            subdomains = set()
            for line in data.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
            return subdomains
    except:
        return set()

def bruteforce_subdomains(domain, wordlist, threads=20):
    """Bruteforce subdomains using wordlist"""
    found = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, sub, domain): sub
            for sub in wordlist
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                fqdn, ips = result
                found[fqdn] = ips
                print(f"  {GREEN}+{RESET} {fqdn} -> {', '.join(ips)}")

    return found

def main():
    parser = argparse.ArgumentParser(description='Subdomain Enumerator')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--wordlist', '-w', help='Custom wordlist file')
    parser.add_argument('--threads', '-t', type=int, default=20, help='Number of threads')
    parser.add_argument('--no-passive', '-np', action='store_true', help='Skip passive enumeration')
    parser.add_argument('--output', '-o', help='Output file')
    args = parser.parse_args()

    domain = args.domain.lower().strip()
    if domain.startswith('http'):
        domain = domain.split('//')[1].split('/')[0]

    all_subdomains = set()
    resolved = {}

    print(f"\n{BOLD}{CYAN}Subdomain Enumeration: {domain}{RESET}\n")

    # Passive enumeration
    if not args.no_passive:
        print(f"{BOLD}[*] Passive Enumeration{RESET}")

        print(f"  {DIM}Querying crt.sh...{RESET}")
        crtsh_subs = query_crtsh(domain)
        print(f"  Found {len(crtsh_subs)} from crt.sh")
        all_subdomains.update(crtsh_subs)

        print(f"  {DIM}Querying HackerTarget...{RESET}")
        ht_subs = query_hackertarget(domain)
        print(f"  Found {len(ht_subs)} from HackerTarget")
        all_subdomains.update(ht_subs)

        print(f"  {GREEN}Total passive: {len(all_subdomains)}{RESET}\n")

    # Load wordlist
    wordlist = COMMON_SUBDOMAINS.copy()
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                custom = [line.strip() for line in f if line.strip()]
                wordlist = list(set(wordlist + custom))
                print(f"{BOLD}[*] Loaded {len(wordlist)} words from wordlist{RESET}\n")
        except Exception as e:
            print(f"{RED}Error loading wordlist: {e}{RESET}")

    # Bruteforce
    print(f"{BOLD}[*] DNS Bruteforce ({len(wordlist)} words, {args.threads} threads){RESET}")
    resolved = bruteforce_subdomains(domain, wordlist, args.threads)

    # Resolve passive findings
    if all_subdomains:
        print(f"\n{BOLD}[*] Resolving passive findings...{RESET}")
        passive_only = [s.replace(f'.{domain}', '').split('.')[0] for s in all_subdomains]
        passive_resolved = bruteforce_subdomains(domain, passive_only, args.threads)
        resolved.update(passive_resolved)

    # Summary
    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"{GREEN}{BOLD}Found {len(resolved)} live subdomains{RESET}\n")

    for fqdn in sorted(resolved.keys()):
        ips = resolved[fqdn]
        print(f"  {CYAN}{fqdn}{RESET} -> {', '.join(ips)}")

    # Output to file
    if args.output:
        with open(args.output, 'w') as f:
            for fqdn in sorted(resolved.keys()):
                f.write(f"{fqdn}\n")
        print(f"\n{DIM}Results saved to: {args.output}{RESET}")

    print()

if __name__ == '__main__':
    main()
