#!/usr/bin/env python3
"""
Ping Sweep - Find live hosts in an IP range
Usage: ping_sweep.py 192.168.1.0/24 [--threads 100]
"""

import subprocess
import argparse
import concurrent.futures
import ipaddress
import time
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def ping_host(ip):
    """Ping a single host, return (ip, alive, latency)"""
    try:
        start = time.time()
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', str(ip)],
            capture_output=True, timeout=2
        )
        latency = round((time.time() - start) * 1000, 1)

        if result.returncode == 0:
            return (str(ip), True, latency)
    except:
        pass
    return (str(ip), False, 0)


def expand_range(target):
    """Expand target into list of IPs"""
    ips = []

    # CIDR notation (192.168.1.0/24)
    if '/' in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            ips = list(network.hosts())
        except:
            pass

    # Range notation (192.168.1.1-50)
    elif '-' in target:
        try:
            base, end_part = target.rsplit('.', 1)
            start, end = end_part.split('-')
            for i in range(int(start), int(end) + 1):
                ips.append(ipaddress.ip_address(f"{base}.{i}"))
        except:
            pass

    # Single IP
    else:
        try:
            ips = [ipaddress.ip_address(target)]
        except:
            pass

    return ips


def main():
    parser = argparse.ArgumentParser(description='Ping Sweep - Find live hosts')
    parser.add_argument('target', help='Target (192.168.1.0/24 or 192.168.1.1-50)')
    parser.add_argument('--threads', '-t', type=int, default=100, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=1, help='Ping timeout in seconds')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only show live hosts')
    args = parser.parse_args()

    ips = expand_range(args.target)

    if not ips:
        print(f"{RED}Invalid target: {args.target}{RESET}")
        print(f"{DIM}Examples: 192.168.1.0/24, 10.0.0.1-100, 192.168.1.1{RESET}")
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║          🏓 Ping Sweep Scanner             ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Target: {args.target}{RESET}")
    print(f"  {DIM}Hosts to scan: {len(ips)}{RESET}")
    print(f"  {DIM}Threads: {args.threads}{RESET}")
    print()

    live_hosts = []
    dead_hosts = []
    scanned = 0
    total = len(ips)

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}

        for future in concurrent.futures.as_completed(futures):
            ip, alive, latency = future.result()
            scanned += 1

            if alive:
                live_hosts.append((ip, latency))
                print(f"  {GREEN}[+]{RESET} {ip:<16} {GREEN}alive{RESET} ({latency}ms)")
            elif not args.quiet:
                dead_hosts.append(ip)
                # Progress indicator
                sys.stdout.write(f"\r  {DIM}Scanning... {scanned}/{total} ({len(live_hosts)} alive){RESET}")
                sys.stdout.flush()

    elapsed = round(time.time() - start_time, 2)

    print(f"\n\n  {DIM}{'─' * 40}{RESET}")
    print(f"\n  {BOLD}Summary:{RESET}")
    print(f"  {GREEN}● Live hosts: {len(live_hosts)}{RESET}")
    print(f"  {RED}● Dead hosts: {len(dead_hosts)}{RESET}")
    print(f"  {DIM}● Scan time: {elapsed}s{RESET}")

    if live_hosts:
        print(f"\n  {BOLD}Live Hosts:{RESET}")
        live_hosts.sort(key=lambda x: [int(p) for p in x[0].split('.')])
        for ip, latency in live_hosts:
            bar = '█' * min(int(latency / 10), 20)
            color = GREEN if latency < 50 else YELLOW if latency < 100 else RED
            print(f"    {ip:<16} {color}{latency:>6}ms {bar}{RESET}")

    print()


if __name__ == '__main__':
    main()
