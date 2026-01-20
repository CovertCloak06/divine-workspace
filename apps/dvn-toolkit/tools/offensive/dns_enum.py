#!/usr/bin/env python3
"""
DNS Enumeration Tool
Discover subdomains, DNS records, and zone information
For authorized security testing only

QUICK START:
    ./dns_enum.py example.com                  # Basic enumeration
    ./dns_enum.py example.com --subdomains     # Find subdomains
    ./dns_enum.py example.com --all            # Full enumeration
"""

import socket
import argparse
import sys
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    E = '\033[0m'
    BOLD = '\033[1m'

# Common subdomains wordlist (built-in)
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'email', 'cloud',
    'api', 'dev', 'staging', 'test', 'admin', 'portal', 'blog', 'shop', 'store',
    'secure', 'vpn', 'remote', 'server', 'web', 'app', 'apps', 'mobile', 'm',
    'cdn', 'static', 'assets', 'img', 'images', 'media', 'video', 'files',
    'download', 'downloads', 'upload', 'uploads', 'backup', 'db', 'database',
    'sql', 'mysql', 'postgres', 'mongo', 'redis', 'cache', 'proxy', 'gateway',
    'auth', 'login', 'sso', 'id', 'identity', 'oauth', 'dashboard', 'panel',
    'cpanel', 'whm', 'plesk', 'webmin', 'phpmyadmin', 'pma', 'jenkins', 'git',
    'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'jira', 'confluence',
    'wiki', 'docs', 'doc', 'help', 'support', 'ticket', 'helpdesk', 'status',
    'monitor', 'nagios', 'zabbix', 'grafana', 'kibana', 'elastic', 'log',
    'logs', 'analytics', 'stats', 'metrics', 'search', 'solr', 'elasticsearch',
    'internal', 'intranet', 'extranet', 'corp', 'corporate', 'office', 'hr',
    'crm', 'erp', 'sap', 'exchange', 'owa', 'autodiscover', 'lyncdiscover',
    'meet', 'meeting', 'conference', 'chat', 'slack', 'teams', 'zoom',
    'stage', 'staging2', 'dev2', 'test2', 'uat', 'qa', 'demo', 'sandbox',
    'beta', 'alpha', 'preview', 'canary', 'prod', 'production', 'live',
    'primary', 'secondary', 'backup2', 'dr', 'failover', 'lb', 'loadbalancer',
    'node1', 'node2', 'node3', 'worker1', 'worker2', 'master', 'slave',
    'www1', 'www2', 'www3', 'web1', 'web2', 'app1', 'app2', 'api1', 'api2',
    'ns', 'nameserver', 'time', 'ntp', 'ldap', 'ad', 'dc', 'dc1', 'dc2',
    'ftp2', 'sftp', 'ssh', 'shell', 'terminal', 'console', 'manage',
    'management', 'adm', 'administrator', 'root', 'system', 'sys', 'info',
    'about', 'contact', 'home', 'old', 'new', 'v1', 'v2', 'v3', 'api-v1',
    'api-v2', 'rest', 'graphql', 'ws', 'websocket', 'socket', 'wss',
    'payment', 'pay', 'checkout', 'cart', 'order', 'orders', 'invoice',
    'billing', 'account', 'accounts', 'user', 'users', 'member', 'members',
    'customer', 'clients', 'partner', 'partners', 'vendor', 'vendors',
    'affiliate', 'affiliates', 'reseller', 'agent', 'agents', 'dealer'
]

HELP_TEXT = """
================================================================================
                    DNS ENUMERATION - COMPREHENSIVE GUIDE
                    Subdomain Discovery and DNS Intelligence
================================================================================

WHAT IS DNS ENUMERATION?
------------------------
DNS (Domain Name System) is the internet's phone book - it translates domain
names like "example.com" into IP addresses like "93.184.216.34". DNS enumeration
is the process of gathering all DNS-related information about a target domain.

The most valuable aspect is SUBDOMAIN DISCOVERY. Organizations register one
domain (company.com) but create many subdomains (dev.company.com, staging.company.com,
admin.company.com). These subdomains often have weaker security than the main site.

WHY THIS MATTERS: Subdomains are a massive blind spot for many organizations.
The main website might be hardened, but dev.company.com might be running outdated
software, or internal.company.com might be exposed to the internet accidentally.


UNDERSTANDING DNS RECORD TYPES
------------------------------

A RECORD (Address)
  Maps domain name to IPv4 address
  WHAT IT TELLS YOU: Where the server physically is
  EXAMPLE: example.com → 93.184.216.34
  USE: Primary target for port scanning

AAAA RECORD (IPv6 Address)
  Maps domain name to IPv6 address
  WHAT IT TELLS YOU: IPv6-enabled infrastructure
  NOTE: Sometimes reveals different servers than IPv4

MX RECORD (Mail Exchange)
  Specifies mail servers for the domain
  WHAT IT TELLS YOU: Email infrastructure, often reveals internal naming
  EXAMPLE: mail.internal.company.com - note "internal" hostname!
  USE: Mail servers are often good targets, may reveal internal hostnames

NS RECORD (Name Server)
  Identifies authoritative DNS servers
  WHAT IT TELLS YOU: Who manages their DNS
  USE: Zone transfer attempts, DNS infrastructure mapping

TXT RECORD (Text)
  Stores arbitrary text data
  WHAT IT TELLS YOU: SPF records, domain verification, sometimes sensitive config
  LOOK FOR: Internal IPs, cloud provider info, API keys (rarely but happens)

CNAME RECORD (Canonical Name)
  Alias that points to another domain
  WHAT IT TELLS YOU: Service relationships, cloud services being used
  EXAMPLE: www.company.com CNAME company.netlify.app
  USE: Subdomain takeover vulnerabilities if target service is abandoned

SOA RECORD (Start of Authority)
  Contains zone administration info
  WHAT IT TELLS YOU: Primary nameserver, admin email, zone serial numbers


THE SUBDOMAIN GOLDMINE
----------------------
Subdomains are where the treasure often lies. Here's why:

COMMON VULNERABLE SUBDOMAINS:
  dev.company.com      Development server, often outdated, debug enabled
  staging.company.com  Staging environment, may have test accounts
  test.company.com     Test server, possibly world-accessible
  admin.company.com    Admin panel, prime bruteforce target
  old.company.com      Legacy system, likely unpatched
  beta.company.com     Beta features, less security review
  api.company.com      API endpoint, potential IDOR/auth issues
  internal.company.com Accidentally exposed internal resources
  vpn.company.com      VPN portal, credential bruteforce target
  jira.company.com     Project management, information disclosure
  git.company.com      Source code repository, massive information leak
  jenkins.company.com  CI/CD server, often misconfigured

LESS OBVIOUS BUT VALUABLE:
  m.company.com        Mobile site, often different codebase
  cdn.company.com      Content delivery, may have path traversal
  img.company.com      Image hosting, possible unrestricted upload
  status.company.com   Status page, reveals infrastructure
  docs.company.com     Documentation, may leak internal info


SUBDOMAIN DISCOVERY METHODS
---------------------------

1. PASSIVE ENUMERATION (No direct contact with target)
   - Certificate Transparency logs (crt.sh)
   - Search engine dorking (site:*.company.com)
   - Wayback Machine historical records
   - Public DNS datasets (DNSDumpster, SecurityTrails)
   THIS TOOL: Doesn't do passive (use online tools first)

2. ACTIVE BRUTEFORCING (This tool's main function)
   - Try wordlist of common subdomain names
   - Check if each one resolves to an IP
   - Fast with threading, but generates DNS traffic

3. ZONE TRANSFER (If misconfigured - jackpot!)
   - Ask nameserver for ALL records at once
   - Usually blocked, but check anyway
   - Command: dig axfr @ns1.company.com company.com


WHAT TO DO WITH FOUND SUBDOMAINS
--------------------------------

1. DOCUMENT EVERYTHING
   - List all subdomains with their IPs
   - Note which IPs are shared vs unique
   - Identify cloud vs self-hosted

2. PORT SCAN EACH ONE
   ./nmap_lite.py subdomain1.company.com
   Different subdomains may have different services exposed

3. CHECK FOR WEB CONTENT
   Visit each one in browser
   Run web_fuzzer.py on interesting ones

4. LOOK FOR SUBDOMAIN TAKEOVER
   If a CNAME points to a service that's unclaimed:
   - company.com CNAME company.heroku.com (but heroku account deleted)
   - You could claim that heroku app and take over the subdomain
   - Major vulnerability!

5. CHECK FOR SENSITIVE EXPOSURE
   Git repositories, admin panels, internal tools
   Things that shouldn't be public


SCENARIO-BASED USAGE
--------------------

SCENARIO: Starting reconnaissance on a new target
COMMAND:  ./dns_enum.py target.com
WHY:      Get baseline DNS information
          See A records, MX records, basic structure
NEXT:     Run subdomain enumeration
          Note any interesting hostnames in MX/NS records


SCENARIO: Full subdomain discovery
COMMAND:  ./dns_enum.py target.com -s -t 100
WHY:      Built-in wordlist covers common subdomains
          100 threads makes it fast
NEXT:     Port scan each discovered subdomain
          Check each for web content


SCENARIO: Thorough enumeration with custom wordlist
COMMAND:  ./dns_enum.py target.com -s \\
              -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \\
              -o target_subdomains.txt
WHY:      Larger wordlist catches more subdomains
          Save results for later reference
NEXT:     Review results, prioritize interesting ones
          Cross-reference with certificate transparency


SCENARIO: Looking for specific patterns
COMMAND:  Create custom wordlist with: dev, staging, admin, test, uat, qa,
          preprod, api, api-v1, api-v2, internal, corp, vpn
WHY:      Targeted list for high-value subdomains
          Faster than huge wordlist
NEXT:     If found, these are priority targets


INTERPRETING RESULTS
--------------------

MANY SUBDOMAINS POINT TO SAME IP:
  Likely using virtual hosting (multiple sites on one server)
  → Web fuzzer each subdomain separately, different content

SUBDOMAIN DOESN'T RESOLVE BUT DID BEFORE:
  Server was taken down but DNS not cleaned up
  → Check for subdomain takeover opportunity

INTERNAL-SOUNDING NAMES RESOLVE:
  dev, staging, internal, corp
  → Priority targets, often less hardened

CLOUD PROVIDER IPS:
  AWS, Azure, GCP ranges
  → Check for S3 buckets, blob storage misconfigs

WILDCARD RESPONSE:
  Every subdomain you try resolves to same IP
  → Domain has wildcard DNS (*.company.com)
  → Compare response sizes to filter real vs wildcard


SUBDOMAIN WORDLISTS
-------------------

BUILT-IN: ~200 common subdomains (quick scan)

RECOMMENDED EXTERNAL:
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt   (quick)
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt  (thorough)
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt (extensive)

CUSTOM GENERATION:
  Use ./wordlist_gen.py to create target-specific lists
  Include company name, products, known patterns


COMMON MISTAKES TO AVOID
------------------------
1. Only checking www - subdomains are where vulnerabilities hide
2. Not saving results - you'll want to reference this later
3. Using huge wordlist first - start small, expand if needed
4. Ignoring MX/NS records - they reveal internal naming conventions
5. Not port scanning found subdomains - each could be different


COMMAND REFERENCE
-----------------
BASIC:
  ./dns_enum.py DOMAIN          Basic DNS record lookup

OPTIONS:
  -s, --subdomains              Enable subdomain bruteforcing
  -w, --wordlist FILE           Use custom subdomain wordlist
  --all                         Run all enumeration techniques
  -t, --threads NUM             Thread count (default: 50)
  -o, --output FILE             Save results to file


NEXT STEPS AFTER DNS ENUM
-------------------------
1. Port scan interesting subdomains: ./nmap_lite.py subdomain.target.com
2. Check web content: ./web_fuzzer.py -u http://subdomain.target.com
3. Look up IP geolocation and ownership
4. Check certificate transparency: crt.sh, censys.io
5. Check Wayback Machine for historical content
================================================================================
"""

def banner():
    print(f"""{C.C}
    ____  _   _______   ______
   / __ \/ | / / ___/  / ____/___  __  ______ ___
  / / / /  |/ /\__ \  / __/ / __ \/ / / / __ `__ \\
 / /_/ / /|  /___/ / / /___/ / / / /_/ / / / / / /
/_____/_/ |_//____/ /_____/_/ /_/\__,_/_/ /_/ /_/
{C.E}{C.Y}DNS Enumeration Tool{C.E}
""")

def resolve_host(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except:
        return None

def get_all_ips(hostname: str) -> List[str]:
    """Get all IP addresses for hostname"""
    try:
        return list(set(socket.gethostbyname_ex(hostname)[2]))
    except:
        return []

def reverse_dns(ip: str) -> Optional[str]:
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def check_subdomain(domain: str, subdomain: str) -> Optional[Dict]:
    """Check if subdomain exists"""
    full_domain = f"{subdomain}.{domain}"
    ip = resolve_host(full_domain)

    if ip:
        return {
            'subdomain': subdomain,
            'domain': full_domain,
            'ip': ip
        }
    return None

def enumerate_subdomains(domain: str, wordlist: List[str], threads: int = 50) -> List[Dict]:
    """Brute-force subdomain enumeration"""
    found = []
    checked = 0
    total = len(wordlist)

    print(f"{C.B}[*]{C.E} Checking {total} potential subdomains...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, domain, sub): sub for sub in wordlist}

        for future in as_completed(futures):
            checked += 1
            result = future.result()

            if result:
                found.append(result)
                print(f"{C.G}[+]{C.E} Found: {C.Y}{result['domain']}{C.E} → {result['ip']}")

            # Progress indicator
            if checked % 100 == 0:
                print(f"{C.B}[*]{C.E} Progress: {checked}/{total}", end='\r')

    print(f"{C.B}[*]{C.E} Checked {total} subdomains" + " " * 20)
    return found

def get_dns_records(domain: str) -> Dict:
    """Get basic DNS information using socket"""
    records = {
        'A': [],
        'reverse': [],
        'aliases': []
    }

    # Get A records
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)
        records['A'] = ips
        records['aliases'] = aliases

        # Reverse DNS for each IP
        for ip in ips:
            rev = reverse_dns(ip)
            if rev:
                records['reverse'].append({'ip': ip, 'hostname': rev})
    except Exception as e:
        pass

    return records

def zone_transfer_check(domain: str) -> bool:
    """
    Check if zone transfer might be possible
    Note: This just checks if we can connect to NS on port 53
    """
    # Get nameserver IPs
    ns_domain = domain

    try:
        ns_ip = socket.gethostbyname(f"ns1.{domain}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ns_ip, 53))
        sock.close()
        return result == 0
    except:
        return False

def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{C.R}[!]{C.E} Error loading wordlist: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description='DNS Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For authorized security testing only.'
    )

    parser.add_argument('domain', nargs='?', help='Target domain')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Enumerate subdomains')
    parser.add_argument('-w', '--wordlist', help='Custom subdomain wordlist')
    parser.add_argument('--all', action='store_true', help='Full enumeration')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-o', '--output', help='Save output to file')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    if not args.domain:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    banner()

    domain = args.domain.lower().strip()
    results = {'domain': domain, 'records': {}, 'subdomains': []}

    print(f"{C.B}[*]{C.E} Target: {C.Y}{domain}{C.E}")
    print(f"{C.B}[*]{C.E} " + "=" * 50)

    # Basic DNS records
    print(f"\n{C.M}[DNS Records]{C.E}")
    records = get_dns_records(domain)
    results['records'] = records

    if records['A']:
        print(f"{C.G}[+]{C.E} A Records:")
        for ip in records['A']:
            print(f"    {C.Y}{ip}{C.E}")

    if records['aliases']:
        print(f"{C.G}[+]{C.E} Aliases:")
        for alias in records['aliases']:
            print(f"    {C.C}{alias}{C.E}")

    if records['reverse']:
        print(f"{C.G}[+]{C.E} Reverse DNS:")
        for rev in records['reverse']:
            print(f"    {rev['ip']} → {C.C}{rev['hostname']}{C.E}")

    # Common subdomains quick check
    print(f"\n{C.M}[Common Subdomains]{C.E}")
    quick_subs = ['www', 'mail', 'ftp', 'admin', 'webmail', 'vpn', 'remote']
    for sub in quick_subs:
        ip = resolve_host(f"{sub}.{domain}")
        if ip:
            print(f"{C.G}[+]{C.E} {sub}.{domain} → {C.Y}{ip}{C.E}")

    # Full subdomain enumeration
    if args.subdomains or args.all:
        print(f"\n{C.M}[Subdomain Enumeration]{C.E}")

        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
        else:
            wordlist = COMMON_SUBDOMAINS

        if wordlist:
            found_subs = enumerate_subdomains(domain, wordlist, args.threads)
            results['subdomains'] = found_subs
            print(f"\n{C.G}[+]{C.E} Found {C.Y}{len(found_subs)}{C.E} subdomains")

    # Zone transfer check
    if args.all:
        print(f"\n{C.M}[Zone Transfer Check]{C.E}")
        if zone_transfer_check(domain):
            print(f"{C.Y}[!]{C.E} Port 53/tcp open on nameserver - zone transfer might be possible")
            print(f"    Try: dig axfr @ns1.{domain} {domain}")
        else:
            print(f"{C.B}[*]{C.E} Zone transfer check inconclusive")

    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"DNS Enumeration Results - {domain}\n")
            f.write("=" * 50 + "\n\n")

            f.write("A Records:\n")
            for ip in results['records'].get('A', []):
                f.write(f"  {ip}\n")

            f.write("\nSubdomains Found:\n")
            for sub in results['subdomains']:
                f.write(f"  {sub['domain']} -> {sub['ip']}\n")

        print(f"\n{C.B}[*]{C.E} Results saved to {args.output}")

    print(f"\n{C.B}[*]{C.E} Enumeration complete")

if __name__ == '__main__':
    main()
