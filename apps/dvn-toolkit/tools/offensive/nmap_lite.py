#!/usr/bin/env python3
"""
Nmap Lite - Network Scanner
A lightweight port scanner with service detection
For authorized security testing only

QUICK START:
    ./nmap_lite.py 192.168.1.1              # Scan common ports
    ./nmap_lite.py 192.168.1.1 -p 1-1000    # Scan port range
    ./nmap_lite.py 192.168.1.1 -sV          # Detect services
    ./nmap_lite.py 192.168.1.0/24 --ping    # Ping sweep network
"""

import socket
import argparse
import sys
import os
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

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

# Common ports with service names
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

# Service banners for detection
SERVICE_PROBES = {
    'HTTP': b'GET / HTTP/1.0\r\n\r\n',
    'SSH': b'',
    'FTP': b'',
    'SMTP': b'EHLO test\r\n',
}

HELP_TEXT = """
================================================================================
                         NMAP LITE - COMPLETE GUIDE
================================================================================

WHAT IS PORT SCANNING AND WHY DO IT?
------------------------------------
Every networked computer has 65,535 "ports" - think of them as numbered doors.
When a service runs (like a web server or database), it "listens" on a specific
port, waiting for connections.

Port scanning answers the question: "What services are running on this machine?"

This is almost ALWAYS your first step in a pentest because:
  • You can't attack what you can't see
  • Each open port is a potential entry point
  • The services running tell you what vulnerabilities to look for

UNDERSTANDING THE METHODOLOGY
-----------------------------
Port scanning fits into the pentest workflow like this:

  1. RECONNAISSANCE (you are here)
     └─> Port scan to find open services

  2. ENUMERATION
     └─> Dig deeper into each service you found

  3. VULNERABILITY SCANNING
     └─> Look for known weaknesses in those services

  4. EXPLOITATION
     └─> Use vulnerabilities to gain access

WHAT EACH RESULT MEANS (AND WHAT TO DO ABOUT IT)
-------------------------------------------------

[OPEN] - Port is accepting connections

   WHAT THIS MEANS: A service is running and listening. This is what you want
   to find. Each open port is something you can interact with.

   WHAT TO DO NEXT:
   • Note the service name (SSH, HTTP, MySQL, etc.)
   • Research that service for default credentials
   • Look up known vulnerabilities for that service version
   • Try connecting to it manually to learn more

   EXAMPLE: You find port 22 (SSH) open
   → Try: ssh user@target (test for weak passwords)
   → Try: searchsploit openssh (look for exploits)
   → Check if it allows password auth or only keys

[CLOSED] - Port refused connection

   WHAT THIS MEANS: The port responded but said "nothing is listening here."
   This actually confirms the host is alive and reachable.

   WHAT TO DO NEXT:
   • Usually nothing - closed ports aren't useful
   • But this tells you the host IS up and responding

[FILTERED] - No response received

   WHAT THIS MEANS: A firewall is likely blocking your scan. The packets
   went out but nothing came back - they were silently dropped.

   WHAT TO DO NEXT:
   • Try a different scan technique (SYN scan, etc.)
   • The service MIGHT still be there, just protected
   • Note this for your report - firewall is present

WHEN TO USE EACH SCAN TYPE
--------------------------

SCENARIO: "I know nothing about this target"
COMMAND:  ./nmap_lite.py target.com
WHY:      Scans the 25 most common ports quickly. Good starting point to see
          what's obviously running. Takes seconds.
NEXT:     If you find web ports (80/443), run web scanners. If you find
          SSH (22), try password attacks. Expand scan if nothing found.

SCENARIO: "Quick scan found nothing, but I suspect more services exist"
COMMAND:  ./nmap_lite.py target.com -p 1-10000
WHY:      Admins often hide services on non-standard ports. A web app might
          run on port 8080, 8443, or 9000 instead of 80/443. This wider scan
          finds those hidden services.
NEXT:     Any new ports found? Research what typically runs on those ports.

SCENARIO: "I found open ports, now I need to know WHAT is running"
COMMAND:  ./nmap_lite.py target.com -p 22,80,443 -sV
WHY:      The -sV flag grabs "banners" - text the service sends when you
          connect. This reveals software names and VERSION NUMBERS. Version
          numbers are CRITICAL because old versions have known exploits.
NEXT:     Google "[software] [version] exploit" or use searchsploit.
          Example: "Apache 2.4.29 exploit" might find CVE-2017-15710.

SCENARIO: "I need to find all live hosts on a network"
COMMAND:  ./nmap_lite.py 192.168.1.0/24 --ping
WHY:      Before scanning ports, you need to know what's actually online.
          The /24 means "scan all 256 addresses in this subnet." Ping sweep
          quickly identifies which IPs respond.
NEXT:     Take the list of live IPs and scan each one individually for
          open ports.

SCENARIO: "I'm doing a CTF and need results fast"
COMMAND:  ./nmap_lite.py target -p 1-65535 -T5 -t 500
WHY:      -T5 is fastest timing, -t 500 uses 500 threads. This is LOUD and
          would be detected in real life, but CTFs don't care about stealth.
          Scans all possible ports as fast as possible.
NEXT:     Focus on unusual ports - CTF flags are often on weird port numbers.

SCENARIO: "Real pentest - I need to avoid detection"
COMMAND:  ./nmap_lite.py target -T1 -t 10
WHY:      -T1 is slowest timing with delays between probes. -t 10 limits
          parallelism. This looks more like normal traffic and is less likely
          to trigger IDS/IPS alerts. Takes much longer but stays quiet.
NEXT:     Same workflow, just slower. Document your stealth approach.

COMMON PORT CHEAT SHEET
-----------------------
When you see these ports open, here's what to investigate:

PORT 21 (FTP):
  • Try anonymous login: ftp target → login: anonymous
  • Check for upload ability (can you plant files?)
  • Old FTP servers have many exploits

PORT 22 (SSH):
  • Try common usernames: root, admin, user, guest
  • Check SSH version for known vulnerabilities
  • If you get creds later, this is your access point

PORT 23 (Telnet):
  • UNENCRYPTED! Credentials sent in plain text
  • Often has default passwords
  • Extremely dangerous if open to internet

PORT 80/443 (HTTP/HTTPS):
  • Web application - huge attack surface
  • Run web vulnerability scanners next
  • Check for admin panels, login pages, APIs

PORT 445 (SMB):
  • Windows file sharing - VERY common in corporate networks
  • Check for null sessions (anonymous access)
  • EternalBlue and other major exploits target this

PORT 3306 (MySQL):
  • Database - if accessible, try default creds
  • root with blank password is common
  • Contains all the data you want

PORT 3389 (RDP):
  • Remote Desktop - Windows GUI access
  • Try credential attacks (bruteforce)
  • BlueKeep vulnerability if old version

SAVING AND USING RESULTS
------------------------
Always save scan results for documentation:
  ./nmap_lite.py target -sV -o scan_results.txt

Your results file becomes:
  • Evidence for your pentest report
  • Reference when you move to exploitation phase
  • Checklist of services to investigate

COMMON MISTAKES TO AVOID
------------------------
❌ Scanning without authorization - ILLEGAL without permission
❌ Scanning too fast on real networks - gets you detected/blocked
❌ Stopping at common ports - services hide on high ports
❌ Ignoring version numbers - that's where the vulns are
❌ Not saving output - you'll forget what you found

QUICK REFERENCE
---------------
./nmap_lite.py TARGET                    # Quick scan of common ports
./nmap_lite.py TARGET -p 1-1000          # Scan first 1000 ports
./nmap_lite.py TARGET -p 1-65535         # Scan ALL ports (slow)
./nmap_lite.py TARGET -sV                # Get service versions
./nmap_lite.py TARGET --ping             # Find live hosts
./nmap_lite.py TARGET -T1 -t 10          # Stealth mode
./nmap_lite.py TARGET -T5 -t 500         # Speed mode (CTF)
./nmap_lite.py TARGET -o results.txt     # Save to file

================================================================================
"""

def banner():
    print(f"""{C.C}
    _   ____  ______    ____     __    _ __
   / | / /  |/  /   |  / __ \   / /   (_) /____
  /  |/ / /|_/ / /| | / /_/ /  / /   / / __/ _ \
 / /|  / /  / / ___ |/ ____/  / /___/ / /_/  __/
/_/ |_/_/  /_/_/  |_/_/      /_____/_/\__/\___/
{C.E}{C.Y}Lightweight Network Scanner{C.E}
""")

def parse_ports(port_arg: str) -> List[int]:
    """Parse port argument into list of ports"""
    ports = []

    for part in port_arg.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))

def get_top_ports(n: int) -> List[int]:
    """Get top N common ports"""
    all_common = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                  993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379,
                  8080, 8443, 27017, 8000, 8888, 9000, 9090, 10000, 1080,
                  1443, 2049, 2121, 4443, 5000, 5001, 6000, 6001, 7001,
                  8001, 8081, 8082, 8181, 8888, 9001, 9080, 9443]
    return all_common[:n]

def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            service = COMMON_PORTS.get(port, 'unknown')
            sock.close()
            return (port, True, service)

        sock.close()
        return (port, False, '')
    except socket.timeout:
        return (port, False, 'filtered')
    except Exception as e:
        return (port, False, str(e))

def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send probe based on port
        if port in [80, 8080, 8000, 8888]:
            sock.send(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
        elif port == 25:
            sock.send(b'EHLO test\r\n')
        else:
            sock.send(b'\r\n')

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        # Clean up banner
        if banner:
            return banner.split('\n')[0][:60]
        return ''
    except:
        return ''

def ping_host(host: str, timeout: float = 1.0) -> bool:
    """Check if host is alive using TCP ping"""
    common_ports = [80, 443, 22, 445, 139]

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except:
            pass

    return False

def resolve_host(host: str) -> str:
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(host)
    except:
        return host

def scan_network(network: str, threads: int = 50) -> List[str]:
    """Ping sweep a network"""
    live_hosts = []

    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except:
        return []

    print(f"{C.B}[*]{C.E} Scanning {len(hosts)} hosts...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, host): host for host in hosts}

        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    live_hosts.append(host)
                    print(f"{C.G}[+]{C.E} Host up: {host}")
            except:
                pass

    return live_hosts

def scan_host(host: str, ports: List[int], threads: int = 100,
              service_detection: bool = False, timeout: float = 1.0) -> List[Dict]:
    """Scan a host for open ports"""
    results = []
    open_count = 0

    # Resolve hostname
    ip = resolve_host(host)
    if ip != host:
        print(f"{C.B}[*]{C.E} Resolved {host} → {ip}")

    print(f"{C.B}[*]{C.E} Scanning {len(ports)} ports on {ip}...")
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in as_completed(futures):
            port, is_open, service = future.result()

            if is_open:
                open_count += 1
                banner = ''

                if service_detection:
                    banner = grab_banner(ip, port)

                result = {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                results.append(result)

                # Print as we find them
                if banner:
                    print(f"{C.G}[+]{C.E} {port}/tcp {C.Y}{service:12}{C.E} {C.C}{banner}{C.E}")
                else:
                    print(f"{C.G}[+]{C.E} {port}/tcp {C.Y}{service}{C.E}")

    elapsed = time.time() - start_time
    print(f"\n{C.B}[*]{C.E} Scan completed in {elapsed:.2f}s")
    print(f"{C.B}[*]{C.E} Found {C.G}{open_count}{C.E} open ports")

    return sorted(results, key=lambda x: x['port'])

def main():
    parser = argparse.ArgumentParser(
        description='Nmap Lite - Lightweight Network Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For authorized security testing only.'
    )

    parser.add_argument('target', nargs='?', help='Target IP, hostname, or CIDR range')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 22,80,443 or 1-1000)')
    parser.add_argument('--top-ports', type=int, help='Scan top N common ports')
    parser.add_argument('--all', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('-sV', '--service', action='store_true', help='Service version detection')
    parser.add_argument('--ping', action='store_true', help='Ping sweep (host discovery)')
    parser.add_argument('-T', '--timing', type=int, choices=[1,2,3,4,5], default=3,
                       help='Timing template (1=slow, 5=fast)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads')
    parser.add_argument('-o', '--output', help='Save output to file')
    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    # Show full help
    if args.help_full:
        print(HELP_TEXT)
        return

    # Need target
    if not args.target:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    banner()

    # Timing adjustments
    timing_threads = {1: 10, 2: 25, 3: 100, 4: 200, 5: 500}
    timing_timeout = {1: 3.0, 2: 2.0, 3: 1.0, 4: 0.5, 5: 0.3}

    threads = args.threads or timing_threads.get(args.timing, 100)
    timeout = args.timeout or timing_timeout.get(args.timing, 1.0)

    # Ping sweep mode
    if args.ping:
        if '/' in args.target:
            live_hosts = scan_network(args.target, threads)
            print(f"\n{C.B}[*]{C.E} Found {C.G}{len(live_hosts)}{C.E} live hosts")

            if args.output:
                with open(args.output, 'w') as f:
                    for host in live_hosts:
                        f.write(host + '\n')
                print(f"{C.B}[*]{C.E} Saved to {args.output}")
        else:
            if ping_host(args.target):
                print(f"{C.G}[+]{C.E} Host {args.target} is up")
            else:
                print(f"{C.R}[-]{C.E} Host {args.target} appears down")
        return

    # Determine ports to scan
    if args.all:
        ports = list(range(1, 65536))
    elif args.ports:
        ports = parse_ports(args.ports)
    elif args.top_ports:
        ports = get_top_ports(args.top_ports)
    else:
        ports = list(COMMON_PORTS.keys())

    # Scan
    results = scan_host(
        args.target,
        ports,
        threads=threads,
        service_detection=args.service,
        timeout=timeout
    )

    # Save output
    if args.output and results:
        with open(args.output, 'w') as f:
            f.write(f"Nmap Lite Scan Results - {args.target}\n")
            f.write("=" * 50 + "\n\n")
            for r in results:
                line = f"{r['port']}/tcp\t{r['state']}\t{r['service']}"
                if r.get('banner'):
                    line += f"\t{r['banner']}"
                f.write(line + '\n')
        print(f"{C.B}[*]{C.E} Results saved to {args.output}")

if __name__ == '__main__':
    main()
