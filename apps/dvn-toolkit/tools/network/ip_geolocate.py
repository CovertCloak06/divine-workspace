#!/usr/bin/env python3
"""
IP Geolocation - Get location info for IP addresses
Usage: ip_geolocate.py [ip] [--json] [--map]
Uses free APIs (no key required)
"""

import sys
import json
import argparse
import socket
import urllib.request
import urllib.error

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Free IP geolocation APIs
APIS = [
    {
        'name': 'ip-api.com',
        'url': 'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query',
        'parser': lambda d: {
            'ip': d.get('query'),
            'country': d.get('country'),
            'country_code': d.get('countryCode'),
            'region': d.get('regionName'),
            'city': d.get('city'),
            'zip': d.get('zip'),
            'lat': d.get('lat'),
            'lon': d.get('lon'),
            'timezone': d.get('timezone'),
            'isp': d.get('isp'),
            'org': d.get('org'),
            'asn': d.get('as'),
            'mobile': d.get('mobile'),
            'proxy': d.get('proxy'),
            'hosting': d.get('hosting'),
        }
    },
    {
        'name': 'ipwho.is',
        'url': 'https://ipwho.is/{ip}',
        'parser': lambda d: {
            'ip': d.get('ip'),
            'country': d.get('country'),
            'country_code': d.get('country_code'),
            'region': d.get('region'),
            'city': d.get('city'),
            'zip': d.get('postal'),
            'lat': d.get('latitude'),
            'lon': d.get('longitude'),
            'timezone': d.get('timezone', {}).get('id') if isinstance(d.get('timezone'), dict) else None,
            'isp': d.get('connection', {}).get('isp') if isinstance(d.get('connection'), dict) else None,
            'org': d.get('connection', {}).get('org') if isinstance(d.get('connection'), dict) else None,
            'asn': d.get('connection', {}).get('asn') if isinstance(d.get('connection'), dict) else None,
        }
    },
]


def get_public_ip():
    """Get your public IP address"""
    try:
        with urllib.request.urlopen('https://api.ipify.org', timeout=5) as r:
            return r.read().decode().strip()
    except:
        try:
            with urllib.request.urlopen('https://ifconfig.me/ip', timeout=5) as r:
                return r.read().decode().strip()
        except:
            return None


def resolve_hostname(host):
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def geolocate_ip(ip):
    """Get geolocation data for an IP"""
    for api in APIS:
        try:
            url = api['url'].format(ip=ip)
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())

                # Check for errors
                if data.get('status') == 'fail':
                    continue
                if data.get('success') == False:
                    continue

                return api['parser'](data)
        except Exception as e:
            continue

    return None


def format_coordinates(lat, lon):
    """Format coordinates with direction"""
    if lat is None or lon is None:
        return "Unknown"

    lat_dir = 'N' if lat >= 0 else 'S'
    lon_dir = 'E' if lon >= 0 else 'W'
    return f"{abs(lat):.4f}° {lat_dir}, {abs(lon):.4f}° {lon_dir}"


def generate_map_url(lat, lon):
    """Generate map URLs"""
    if lat is None or lon is None:
        return None
    return {
        'google': f"https://www.google.com/maps?q={lat},{lon}",
        'osm': f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=12",
    }


def display_results(data, show_map=False):
    """Display geolocation results"""
    print(f"\n  {BOLD}IP Geolocation Results{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    print(f"  {CYAN}IP Address:{RESET}    {data.get('ip', 'Unknown')}")
    print()

    # Location
    print(f"  {BOLD}Location{RESET}")
    print(f"  {CYAN}Country:{RESET}       {data.get('country', 'Unknown')} ({data.get('country_code', '?')})")
    print(f"  {CYAN}Region:{RESET}        {data.get('region', 'Unknown')}")
    print(f"  {CYAN}City:{RESET}          {data.get('city', 'Unknown')}")
    if data.get('zip'):
        print(f"  {CYAN}ZIP/Postal:{RESET}    {data.get('zip')}")
    print(f"  {CYAN}Coordinates:{RESET}   {format_coordinates(data.get('lat'), data.get('lon'))}")
    if data.get('timezone'):
        print(f"  {CYAN}Timezone:{RESET}      {data.get('timezone')}")
    print()

    # Network
    print(f"  {BOLD}Network{RESET}")
    if data.get('isp'):
        print(f"  {CYAN}ISP:{RESET}           {data.get('isp')}")
    if data.get('org'):
        print(f"  {CYAN}Organization:{RESET} {data.get('org')}")
    if data.get('asn'):
        print(f"  {CYAN}ASN:{RESET}           {data.get('asn')}")
    print()

    # Flags
    flags = []
    if data.get('mobile'):
        flags.append(f"{YELLOW}Mobile{RESET}")
    if data.get('proxy'):
        flags.append(f"{RED}Proxy/VPN{RESET}")
    if data.get('hosting'):
        flags.append(f"{CYAN}Hosting/DC{RESET}")

    if flags:
        print(f"  {BOLD}Flags:{RESET}         {', '.join(flags)}")
        print()

    # Map links
    if show_map:
        maps = generate_map_url(data.get('lat'), data.get('lon'))
        if maps:
            print(f"  {BOLD}Map Links{RESET}")
            print(f"  {CYAN}Google:{RESET}  {maps['google']}")
            print(f"  {CYAN}OSM:{RESET}     {maps['osm']}")
            print()


def bulk_lookup(ips):
    """Lookup multiple IPs"""
    results = []
    for ip in ips:
        print(f"  Looking up {ip}...", end=' ', flush=True)
        data = geolocate_ip(ip)
        if data:
            print(f"{GREEN}OK{RESET}")
            results.append(data)
        else:
            print(f"{RED}Failed{RESET}")
            results.append({'ip': ip, 'error': 'Lookup failed'})
    return results


def main():
    parser = argparse.ArgumentParser(description='IP Geolocation')
    parser.add_argument('target', nargs='?', help='IP address or hostname (default: your IP)')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--map', '-m', action='store_true', help='Show map links')
    parser.add_argument('--bulk', '-b', nargs='+', help='Lookup multiple IPs')
    parser.add_argument('--resolve', '-r', action='store_true', help='Resolve hostname first')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  IP Geolocation Tool{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    # Bulk mode
    if args.bulk:
        results = bulk_lookup(args.bulk)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for data in results:
                if 'error' not in data:
                    display_results(data, args.map)
        return

    # Single target
    target = args.target

    if not target:
        if not args.json:
            print(f"\n  {DIM}Getting your public IP...{RESET}")
        target = get_public_ip()
        if not target:
            print(f"  {RED}Could not determine your public IP{RESET}")
            sys.exit(1)

    # Resolve hostname if needed
    if args.resolve or not target[0].isdigit():
        if not args.json:
            print(f"  {DIM}Resolving {target}...{RESET}")
        resolved = resolve_hostname(target)
        if resolved:
            if not args.json:
                print(f"  {DIM}Resolved to {resolved}{RESET}")
            target = resolved
        else:
            print(f"  {RED}Could not resolve {target}{RESET}")
            sys.exit(1)

    # Lookup
    if not args.json:
        print(f"  {DIM}Looking up {target}...{RESET}")

    data = geolocate_ip(target)

    if not data:
        if args.json:
            print(json.dumps({'error': 'Lookup failed', 'ip': target}))
        else:
            print(f"  {RED}Geolocation lookup failed{RESET}")
        sys.exit(1)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        display_results(data, args.map)


if __name__ == '__main__':
    main()
