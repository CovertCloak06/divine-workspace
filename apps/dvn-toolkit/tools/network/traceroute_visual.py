#!/usr/bin/env python3
"""
Visual Traceroute - Trace packet route with geolocation
Usage: traceroute_visual.py [host] [--hops N] [--json]
Shows the path packets take with location data
"""

import sys
import json
import argparse
import subprocess
import socket
import urllib.request
import re
import time

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Simple geolocation cache
GEO_CACHE = {}


def geolocate_ip(ip):
    """Get geolocation for an IP"""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    # Skip private IPs
    if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
        result = {'city': 'Private', 'country': 'LAN', 'lat': None, 'lon': None}
        GEO_CACHE[ip] = result
        return result

    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp'
        req = urllib.request.Request(url, headers={'User-Agent': 'Traceroute/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                result = {
                    'city': data.get('city', 'Unknown'),
                    'country': data.get('countryCode', 'Unknown'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'isp': data.get('isp', ''),
                }
                GEO_CACHE[ip] = result
                return result
    except:
        pass

    result = {'city': 'Unknown', 'country': '??', 'lat': None, 'lon': None}
    GEO_CACHE[ip] = result
    return result


def parse_traceroute_line(line):
    """Parse a single traceroute output line"""
    # Match hop number
    match = re.match(r'\s*(\d+)\s+(.+)', line)
    if not match:
        return None

    hop_num = int(match.group(1))
    rest = match.group(2)

    # Check for timeout
    if rest.strip() == '* * *':
        return {
            'hop': hop_num,
            'host': None,
            'ip': None,
            'times': [],
            'timeout': True
        }

    # Extract hostname and IP
    host_match = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)', rest)
    if host_match:
        host = host_match.group(1)
        ip = host_match.group(2)
    else:
        # Try just IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', rest)
        if ip_match:
            ip = ip_match.group(1)
            host = ip
        else:
            return None

    # Extract times
    times = re.findall(r'(\d+\.?\d*)\s*ms', rest)
    times = [float(t) for t in times]

    return {
        'hop': hop_num,
        'host': host,
        'ip': ip,
        'times': times,
        'timeout': False
    }


def run_traceroute(target, max_hops=30, timeout=5):
    """Run traceroute and yield hops"""
    # Try traceroute first
    cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', str(timeout), target]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Skip first line (header)
        first_line = True

        for line in process.stdout:
            if first_line:
                first_line = False
                continue

            hop = parse_traceroute_line(line)
            if hop:
                yield hop

        process.wait()
    except FileNotFoundError:
        print(f"  {YELLOW}traceroute not found, trying tracepath...{RESET}")
        # Try tracepath as fallback
        try:
            result = subprocess.run(
                ['tracepath', '-n', target],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split('\n'):
                hop = parse_traceroute_line(line)
                if hop:
                    yield hop
        except:
            raise Exception("Neither traceroute nor tracepath available")


def resolve_target(target):
    """Resolve target to IP"""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        return None


def display_hop(hop, show_geo=True):
    """Display a single hop"""
    hop_num = hop['hop']

    if hop['timeout']:
        print(f"  {DIM}{hop_num:2}.{RESET} {'*' * 3} {DIM}Request timed out{RESET}")
        return

    ip = hop['ip']
    host = hop['host']
    times = hop['times']

    # Calculate average time
    avg_time = sum(times) / len(times) if times else 0

    # Color based on latency
    if avg_time < 20:
        time_color = GREEN
    elif avg_time < 100:
        time_color = YELLOW
    else:
        time_color = RED

    # Format times
    time_str = ' '.join(f'{t:.1f}ms' for t in times[:3])

    # Get geolocation
    if show_geo:
        geo = geolocate_ip(ip)
        location = f"{geo['city']}, {geo['country']}"
    else:
        location = ''

    # Display
    print(f"  {CYAN}{hop_num:2}.{RESET} {ip:15} {time_color}{time_str:25}{RESET}", end='')
    if show_geo:
        print(f" {DIM}{location}{RESET}", end='')
    print()

    if host != ip:
        print(f"      {DIM}({host}){RESET}")


def draw_ascii_map(hops):
    """Draw a simple ASCII route visualization"""
    print(f"\n  {BOLD}Route Visualization{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    # Get unique countries
    countries = []
    for hop in hops:
        if hop.get('geo') and hop['geo'].get('country'):
            country = hop['geo']['country']
            if country not in ['??', 'LAN'] and (not countries or countries[-1] != country):
                countries.append(country)

    if countries:
        # Draw simple path
        print(f"  {GREEN}[START]{RESET}", end='')
        for country in countries:
            print(f" ──> {CYAN}{country}{RESET}", end='')
        print(f" ──> {GREEN}[END]{RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(description='Visual Traceroute')
    parser.add_argument('target', nargs='?', help='Target host or IP')
    parser.add_argument('--hops', '-m', type=int, default=30, help='Max hops')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--no-geo', '-n', action='store_true', help='Skip geolocation')
    parser.add_argument('--map', action='store_true', help='Show route map')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Visual Traceroute{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    target = args.target
    if not target:
        target = input(f"\n  {CYAN}Target host:{RESET} ").strip()

    if not target:
        print(f"  {RED}Target required{RESET}")
        sys.exit(1)

    # Resolve target
    target_ip = resolve_target(target)
    if not target_ip:
        print(f"  {RED}Could not resolve {target}{RESET}")
        sys.exit(1)

    if not args.json:
        print(f"\n  {CYAN}Target:{RESET}  {target} ({target_ip})")
        print(f"  {CYAN}Max hops:{RESET} {args.hops}")
        print()
        print(f"  {BOLD}Tracing route...{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

    hops = []

    try:
        for hop in run_traceroute(target, args.hops):
            # Add geolocation
            if hop['ip'] and not args.no_geo:
                hop['geo'] = geolocate_ip(hop['ip'])
            else:
                hop['geo'] = None

            hops.append(hop)

            if not args.json:
                display_hop(hop, not args.no_geo)

            # Rate limit for geolocation API
            if not args.no_geo:
                time.sleep(0.15)

    except Exception as e:
        if not args.json:
            print(f"\n  {RED}Error: {e}{RESET}")
        else:
            print(json.dumps({'error': str(e)}))
        sys.exit(1)

    # Summary
    if not args.json:
        print(f"\n  {DIM}{'─' * 50}{RESET}")

        total_hops = len(hops)
        timeout_hops = len([h for h in hops if h['timeout']])
        successful_hops = total_hops - timeout_hops

        all_times = [t for h in hops for t in h.get('times', [])]
        if all_times:
            avg_latency = sum(all_times) / len(all_times)
            max_latency = max(all_times)
            print(f"\n  {CYAN}Hops:{RESET} {successful_hops}/{total_hops} | {CYAN}Avg:{RESET} {avg_latency:.1f}ms | {CYAN}Max:{RESET} {max_latency:.1f}ms")

        # Show map
        if args.map:
            draw_ascii_map(hops)

        print()

    if args.json:
        print(json.dumps(hops, indent=2))


if __name__ == '__main__':
    main()
