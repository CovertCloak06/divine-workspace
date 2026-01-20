#!/usr/bin/env python3
"""
Subnet Calculator - IP/CIDR calculations
Usage: subnet_calc.py 192.168.1.0/24
"""

import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def ip_to_int(ip):
    """Convert IP address to integer"""
    parts = [int(p) for p in ip.split('.')]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def int_to_ip(num):
    """Convert integer to IP address"""
    return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"


def cidr_to_netmask(cidr):
    """Convert CIDR to netmask"""
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return int_to_ip(mask)


def netmask_to_cidr(netmask):
    """Convert netmask to CIDR"""
    binary = bin(ip_to_int(netmask)).count('1')
    return binary


def calculate_subnet(ip, cidr):
    """Calculate subnet details"""
    ip_int = ip_to_int(ip)
    mask_int = (0xffffffff >> (32 - cidr)) << (32 - cidr)

    network = ip_int & mask_int
    broadcast = network | (~mask_int & 0xffffffff)

    first_host = network + 1 if cidr < 31 else network
    last_host = broadcast - 1 if cidr < 31 else broadcast

    num_hosts = (2 ** (32 - cidr)) - 2 if cidr < 31 else 2 ** (32 - cidr)
    if cidr == 32:
        num_hosts = 1

    return {
        'network': int_to_ip(network),
        'broadcast': int_to_ip(broadcast),
        'netmask': cidr_to_netmask(cidr),
        'wildcard': int_to_ip(~mask_int & 0xffffffff),
        'first_host': int_to_ip(first_host),
        'last_host': int_to_ip(last_host),
        'num_hosts': max(0, num_hosts),
        'cidr': cidr,
    }


def ip_in_subnet(ip, network, cidr):
    """Check if IP is in subnet"""
    ip_int = ip_to_int(ip)
    net_int = ip_to_int(network)
    mask_int = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return (ip_int & mask_int) == (net_int & mask_int)


def parse_input(text):
    """Parse IP/CIDR or IP netmask input"""
    # CIDR notation: 192.168.1.0/24
    cidr_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)/(\d+)$', text)
    if cidr_match:
        return cidr_match.group(1), int(cidr_match.group(2))

    # IP + netmask: 192.168.1.0 255.255.255.0
    mask_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$', text)
    if mask_match:
        ip = mask_match.group(1)
        netmask = mask_match.group(2)
        cidr = netmask_to_cidr(netmask)
        return ip, cidr

    # Just IP, assume /24
    ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)$', text)
    if ip_match:
        return ip_match.group(1), 24

    return None, None


def print_binary(ip):
    """Print IP in binary format"""
    parts = [int(p) for p in ip.split('.')]
    binary = '.'.join(f'{p:08b}' for p in parts)
    return binary


def main():
    parser = argparse.ArgumentParser(description='Subnet Calculator')
    parser.add_argument('address', nargs='?', help='IP/CIDR (e.g., 192.168.1.0/24)')
    parser.add_argument('--check', '-c', help='Check if IP is in subnet')
    parser.add_argument('--split', '-s', type=int, help='Split into N subnets')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔢 Subnet Calculator                          ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.address:
        args.address = input(f"  {CYAN}IP/CIDR (e.g., 192.168.1.0/24):{RESET} ").strip()

    ip, cidr = parse_input(args.address)

    if not ip or cidr is None:
        print(f"  {RED}Invalid format. Use: 192.168.1.0/24 or 192.168.1.0 255.255.255.0{RESET}\n")
        return

    if not (0 <= cidr <= 32):
        print(f"  {RED}CIDR must be 0-32{RESET}\n")
        return

    result = calculate_subnet(ip, cidr)

    print(f"  {BOLD}Subnet Information:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    print(f"\n  {CYAN}Network:{RESET}      {GREEN}{result['network']}/{cidr}{RESET}")
    print(f"  {CYAN}Netmask:{RESET}      {result['netmask']}")
    print(f"  {CYAN}Wildcard:{RESET}     {result['wildcard']}")
    print(f"  {CYAN}Broadcast:{RESET}    {result['broadcast']}")

    print(f"\n  {CYAN}First Host:{RESET}   {result['first_host']}")
    print(f"  {CYAN}Last Host:{RESET}    {result['last_host']}")
    print(f"  {CYAN}Total Hosts:{RESET}  {YELLOW}{result['num_hosts']:,}{RESET}")

    # Binary representation
    print(f"\n  {BOLD}Binary:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}IP:{RESET}       {print_binary(ip)}")
    print(f"  {CYAN}Netmask:{RESET}  {print_binary(result['netmask'])}")
    print(f"  {CYAN}Network:{RESET}  {print_binary(result['network'])}")

    # Class info
    first_octet = int(ip.split('.')[0])
    if first_octet < 128:
        ip_class = 'A'
        default_cidr = 8
    elif first_octet < 192:
        ip_class = 'B'
        default_cidr = 16
    elif first_octet < 224:
        ip_class = 'C'
        default_cidr = 24
    else:
        ip_class = 'D/E (Multicast/Reserved)'
        default_cidr = None

    print(f"\n  {BOLD}Classification:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}Class:{RESET}        {ip_class}")
    if default_cidr:
        print(f"  {CYAN}Default CIDR:{RESET} /{default_cidr}")

    # Private/Public
    private_ranges = [
        ('10.0.0.0', 8),
        ('172.16.0.0', 12),
        ('192.168.0.0', 16),
    ]
    is_private = False
    for net, mask in private_ranges:
        if ip_in_subnet(ip, net, mask):
            is_private = True
            break

    print(f"  {CYAN}Type:{RESET}         {'Private (RFC1918)' if is_private else 'Public'}")

    # Check IP
    if args.check:
        print(f"\n  {BOLD}IP Check:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        if ip_in_subnet(args.check, result['network'], cidr):
            print(f"  {GREEN}✓ {args.check} is IN this subnet{RESET}")
        else:
            print(f"  {RED}✗ {args.check} is NOT in this subnet{RESET}")

    # Split subnets
    if args.split and args.split > 1:
        import math
        bits_needed = math.ceil(math.log2(args.split))
        new_cidr = cidr + bits_needed

        if new_cidr > 32:
            print(f"\n  {RED}Cannot split into {args.split} subnets (need /{new_cidr}){RESET}")
        else:
            print(f"\n  {BOLD}Split into {2**bits_needed} subnets (/{new_cidr}):{RESET}")
            print(f"  {DIM}{'─' * 50}{RESET}")

            net_int = ip_to_int(result['network'])
            subnet_size = 2 ** (32 - new_cidr)

            for i in range(min(2**bits_needed, 16)):
                subnet_net = net_int + (i * subnet_size)
                sub = calculate_subnet(int_to_ip(subnet_net), new_cidr)
                print(f"  {CYAN}{i+1}.{RESET} {sub['network']}/{new_cidr} ({sub['num_hosts']} hosts)")

            if 2**bits_needed > 16:
                print(f"  {DIM}... and {2**bits_needed - 16} more{RESET}")

    # Quick reference
    print(f"\n  {BOLD}CIDR Quick Reference:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    refs = [(32, 1), (30, 2), (29, 6), (28, 14), (27, 30), (26, 62), (25, 126), (24, 254), (23, 510), (22, 1022), (16, 65534), (8, 16777214)]
    for c, hosts in refs[:6]:
        marker = f"{YELLOW}◄{RESET}" if c == cidr else " "
        print(f"  /{c:<3} = {hosts:>10,} hosts  {marker}")

    print()


if __name__ == '__main__':
    main()
