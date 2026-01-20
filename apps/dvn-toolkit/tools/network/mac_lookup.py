#!/usr/bin/env python3
"""
MAC Lookup - Identify device vendors from MAC address
Usage: mac_lookup.py <mac_address>
"""

import urllib.request
import json
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common OUI (Organizationally Unique Identifier) database
# First 3 bytes of MAC address identify the vendor
OUI_DATABASE = {
    '00:00:0C': 'Cisco Systems',
    '00:1A:2B': 'Ayecom Technology',
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    '00:15:5D': 'Microsoft Hyper-V',
    '08:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM',
    '00:1C:42': 'Parallels',
    'AC:DE:48': 'Private',
    '00:03:93': 'Apple',
    '00:05:02': 'Apple',
    '00:0A:27': 'Apple',
    '00:0A:95': 'Apple',
    '00:0D:93': 'Apple',
    '00:11:24': 'Apple',
    '00:14:51': 'Apple',
    '00:16:CB': 'Apple',
    '00:17:F2': 'Apple',
    '00:19:E3': 'Apple',
    '00:1B:63': 'Apple',
    '00:1C:B3': 'Apple',
    '00:1D:4F': 'Apple',
    '00:1E:52': 'Apple',
    '00:1E:C2': 'Apple',
    '00:1F:5B': 'Apple',
    '00:1F:F3': 'Apple',
    '00:21:E9': 'Apple',
    '00:22:41': 'Apple',
    '00:23:12': 'Apple',
    '00:23:32': 'Apple',
    '00:23:6C': 'Apple',
    '00:23:DF': 'Apple',
    '00:24:36': 'Apple',
    '00:25:00': 'Apple',
    '00:25:4B': 'Apple',
    '00:25:BC': 'Apple',
    '00:26:08': 'Apple',
    '00:26:4A': 'Apple',
    '00:26:B0': 'Apple',
    '00:26:BB': 'Apple',
    'F8:1E:DF': 'Apple',
    '18:AF:61': 'Apple',
    '28:CF:DA': 'Apple',
    '34:C0:59': 'Apple',
    '40:6C:8F': 'Apple',
    '54:26:96': 'Apple',
    '60:03:08': 'Apple',
    '78:31:C1': 'Apple',
    '7C:6D:62': 'Apple',
    '88:53:95': 'Apple',
    'A4:5E:60': 'Apple',
    'B8:17:C2': 'Apple',
    'D8:00:4D': 'Apple',
    'E4:CE:8F': 'Apple',
    'F0:18:98': 'Apple',
    '00:24:E8': 'Dell',
    '14:FE:B5': 'Dell',
    '18:03:73': 'Dell',
    '18:A9:9B': 'Dell',
    '24:B6:FD': 'Dell',
    '34:17:EB': 'Dell',
    '44:A8:42': 'Dell',
    '5C:26:0A': 'Dell',
    '74:86:7A': 'Dell',
    '78:45:C4': 'Dell',
    '84:7B:EB': 'Dell',
    '98:90:96': 'Dell',
    'B0:83:FE': 'Dell',
    'B8:2A:72': 'Dell',
    'D4:BE:D9': 'Dell',
    'EC:F4:BB': 'Dell',
    'F8:B1:56': 'Dell',
    '00:04:5A': 'Linksys',
    '00:06:25': 'Linksys',
    '00:0C:41': 'Linksys',
    '00:0F:66': 'Linksys',
    '00:12:17': 'Linksys',
    '00:13:10': 'Linksys',
    '00:14:BF': 'Linksys',
    '00:16:B6': 'Linksys',
    '00:18:39': 'Linksys',
    '00:18:F8': 'Linksys',
    '00:1A:70': 'Linksys',
    '00:1C:10': 'Linksys',
    '00:1D:7E': 'Linksys',
    '00:1E:E5': 'Linksys',
    '00:21:29': 'Linksys',
    '00:22:6B': 'Linksys',
    '00:23:69': 'Linksys',
    '00:25:9C': 'Linksys',
    '20:AA:4B': 'Linksys',
    'C0:C1:C0': 'Linksys',
    '00:18:0A': 'Intel',
    '00:19:D1': 'Intel',
    '00:1B:21': 'Intel',
    '00:1C:C0': 'Intel',
    '00:1D:E0': 'Intel',
    '00:1E:64': 'Intel',
    '00:1E:65': 'Intel',
    '00:1E:67': 'Intel',
    '00:1F:3B': 'Intel',
    '00:1F:3C': 'Intel',
    '00:20:E0': 'Intel',
    '00:21:5C': 'Intel',
    '00:21:5D': 'Intel',
    '00:21:6A': 'Intel',
    '00:21:6B': 'Intel',
    '00:22:FA': 'Intel',
    '00:22:FB': 'Intel',
    '00:24:D6': 'Intel',
    '00:24:D7': 'Intel',
    '00:26:C6': 'Intel',
    '00:26:C7': 'Intel',
    '00:27:10': 'Intel',
    'B4:B5:2F': 'Hewlett-Packard',
    '00:0B:CD': 'Hewlett-Packard',
    '00:0D:9D': 'Hewlett-Packard',
    '00:0E:7F': 'Hewlett-Packard',
    '00:0F:20': 'Hewlett-Packard',
    '00:10:83': 'Hewlett-Packard',
    '00:11:0A': 'Hewlett-Packard',
    '00:11:85': 'Hewlett-Packard',
    '00:12:79': 'Hewlett-Packard',
    '00:13:21': 'Hewlett-Packard',
    '00:14:38': 'Hewlett-Packard',
    '00:14:C2': 'Hewlett-Packard',
    '00:15:60': 'Hewlett-Packard',
    '00:16:35': 'Hewlett-Packard',
    '00:17:08': 'Hewlett-Packard',
    '00:17:A4': 'Hewlett-Packard',
    '00:18:71': 'Hewlett-Packard',
    '00:18:FE': 'Hewlett-Packard',
    '00:19:BB': 'Hewlett-Packard',
    '00:1A:4B': 'Hewlett-Packard',
    '00:1B:78': 'Hewlett-Packard',
    '00:1C:2E': 'Hewlett-Packard',
    '00:1E:0B': 'Hewlett-Packard',
    '00:1F:29': 'Hewlett-Packard',
    '00:21:5A': 'Hewlett-Packard',
    '00:22:64': 'Hewlett-Packard',
    '00:23:7D': 'Hewlett-Packard',
    '00:24:81': 'Hewlett-Packard',
    '00:25:B3': 'Hewlett-Packard',
    '00:26:55': 'Hewlett-Packard',
    '2C:41:38': 'Hewlett-Packard',
    '30:8D:99': 'Hewlett-Packard',
    '44:1E:A1': 'Hewlett-Packard',
    '48:0F:CF': 'Hewlett-Packard',
    '50:65:F3': 'Hewlett-Packard',
    '58:20:B1': 'Hewlett-Packard',
    '6C:C2:17': 'Hewlett-Packard',
    '80:C1:6E': 'Hewlett-Packard',
    '94:57:A5': 'Hewlett-Packard',
    '98:4B:E1': 'Hewlett-Packard',
    'A0:D3:C1': 'Hewlett-Packard',
    'B4:99:BA': 'Hewlett-Packard',
    'B8:AF:67': 'Hewlett-Packard',
    'C8:CB:B8': 'Hewlett-Packard',
    'D4:85:64': 'Hewlett-Packard',
    'D8:D3:85': 'Hewlett-Packard',
    'EC:B1:D7': 'Hewlett-Packard',
    'FC:15:B4': 'Hewlett-Packard',
    '00:1E:68': 'Quanta',
    'D4:3D:7E': 'Raspberry Pi',
    'B8:27:EB': 'Raspberry Pi',
    'DC:A6:32': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi',
    '28:CD:C1': 'Raspberry Pi',
    '2C:CF:67': 'NVIDIA',
    '04:4B:ED': 'NVIDIA',
}


def normalize_mac(mac):
    """Normalize MAC address to XX:XX:XX format"""
    mac = mac.upper().replace('-', ':').replace('.', ':')
    # Remove any extra characters
    mac = re.sub(r'[^0-9A-F:]', '', mac)

    # If no colons, add them
    if ':' not in mac and len(mac) == 12:
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    return mac


def lookup_vendor(mac):
    """Look up vendor from MAC address"""
    mac = normalize_mac(mac)

    # Get OUI (first 3 octets)
    parts = mac.split(':')
    if len(parts) < 3:
        return None

    oui = ':'.join(parts[:3])

    # Check local database first
    if oui in OUI_DATABASE:
        return OUI_DATABASE[oui]

    # Try online lookup
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.read().decode('utf-8').strip()
    except:
        pass

    return None


def main():
    parser = argparse.ArgumentParser(description='MAC Address Lookup')
    parser.add_argument('mac', nargs='*', help='MAC address(es) to lookup')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔍 MAC Address Lookup                         ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.mac:
        mac_input = input(f"  {CYAN}MAC Address:{RESET} ").strip()
        args.mac = [mac_input] if mac_input else []

    if not args.mac:
        print(f"  {RED}MAC address required{RESET}")
        print(f"  {DIM}Format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF{RESET}\n")
        return

    print(f"  {BOLD}Results:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    for mac in args.mac:
        normalized = normalize_mac(mac)
        vendor = lookup_vendor(mac)

        print(f"  {CYAN}MAC:{RESET}    {GREEN}{normalized}{RESET}")

        if vendor:
            print(f"  {CYAN}Vendor:{RESET} {vendor}")
        else:
            print(f"  {CYAN}Vendor:{RESET} {YELLOW}Unknown{RESET}")

        # Additional info
        parts = normalized.split(':')
        if len(parts) >= 1:
            first_byte = int(parts[0], 16)

            # Check if locally administered
            if first_byte & 0x02:
                print(f"  {CYAN}Type:{RESET}   {YELLOW}Locally Administered{RESET}")
            else:
                print(f"  {CYAN}Type:{RESET}   Universally Administered (UAA)")

            # Check if multicast
            if first_byte & 0x01:
                print(f"  {CYAN}Cast:{RESET}   Multicast")
            else:
                print(f"  {CYAN}Cast:{RESET}   Unicast")

        print()

    print(f"  {DIM}Note: Online lookup used if not in local database{RESET}\n")


if __name__ == '__main__':
    main()
