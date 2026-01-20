#!/usr/bin/env python3
"""
ARP Scanner - Find all devices on your local network
Usage: arp_scan.py [network] [--interface eth0]
"""

import subprocess
import socket
import struct
import re
import argparse
import concurrent.futures
import os

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common MAC vendor prefixes (first 3 bytes)
VENDORS = {
    '00:50:56': 'VMware',
    '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',
    '52:54:00': 'QEMU/KVM',
    'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi',
    '00:1a:79': 'Apple',
    '00:03:93': 'Apple',
    'a4:83:e7': 'Apple',
    '3c:22:fb': 'Apple',
    '00:17:88': 'Philips Hue',
    '94:10:3e': 'Samsung',
    'cc:2d:e0': 'Samsung',
    'ac:bc:32': 'Samsung',
    '00:1e:c2': 'Apple',
    '18:31:bf': 'Xiaomi',
    '64:cc:2e': 'Xiaomi',
    '50:ec:50': 'Xiaomi',
    'b4:2e:99': 'TP-Link',
    '50:c7:bf': 'TP-Link',
    'c0:25:e9': 'TP-Link',
    '00:18:0a': 'Cisco',
    '00:1b:0d': 'Cisco',
    '00:50:f1': 'Intel',
    '3c:97:0e': 'Intel',
    '00:15:5d': 'Microsoft Hyper-V',
    '00:1c:42': 'Parallels',
    '00:16:3e': 'Xen',
    '7c:2e:bd': 'Google',
    'f4:f5:d8': 'Google',
    '94:eb:2c': 'Google',
    '00:04:4b': 'Nvidia Shield',
    '48:b0:2d': 'Nvidia',
    'b0:fc:36': 'Amazon',
    '74:c2:46': 'Amazon Echo',
    '40:b4:cd': 'Amazon',
    'f0:27:2d': 'Amazon',
}


def get_local_network():
    """Get the local network CIDR"""
    try:
        # Get default gateway and interface
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                parts = line.split()
                gateway_idx = parts.index('via') + 1
                gateway = parts[gateway_idx]
                # Assume /24 network
                network = '.'.join(gateway.split('.')[:3]) + '.0/24'
                return network
    except:
        pass
    return '192.168.1.0/24'


def get_vendor(mac):
    """Look up vendor from MAC address"""
    prefix = mac[:8].lower()
    for vendor_prefix, name in VENDORS.items():
        if prefix == vendor_prefix.lower():
            return name
    return 'Unknown'


def get_hostname(ip):
    """Try to get hostname for IP"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname[:30]
    except:
        return ''


def ping_host(ip):
    """Ping a single host"""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            capture_output=True, timeout=2
        )
        return result.returncode == 0
    except:
        return False


def get_arp_table():
    """Get current ARP table"""
    devices = {}
    try:
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                ip = parts[0]
                mac = parts[2] if len(parts) > 2 else ''
                if mac and mac != '(incomplete)':
                    devices[ip] = mac
    except:
        pass
    return devices


def scan_network_arp(network):
    """Scan network using ARP"""
    devices = []

    # Try using arp-scan if available (most accurate)
    try:
        result = subprocess.run(
            ['sudo', 'arp-scan', '--localnet', '-q'],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.split('\n'):
            parts = line.split('\t')
            if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                devices.append({
                    'ip': parts[0],
                    'mac': parts[1],
                    'vendor': parts[2] if len(parts) > 2 else get_vendor(parts[1])
                })
        if devices:
            return devices
    except:
        pass

    # Fall back to ping + ARP table
    base = '.'.join(network.split('.')[:3])
    ips = [f"{base}.{i}" for i in range(1, 255)]

    print(f"  {DIM}Scanning {len(ips)} addresses...{RESET}")

    # Parallel ping
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(ping_host, ips)

    # Read ARP table
    arp_table = get_arp_table()

    for ip, mac in arp_table.items():
        devices.append({
            'ip': ip,
            'mac': mac,
            'vendor': get_vendor(mac)
        })

    return devices


def display_devices(devices):
    """Display discovered devices"""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                     🔍 Network Device Scanner                        ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════╝{RESET}\n")

    if not devices:
        print(f"  {RED}No devices found. Try running with sudo.{RESET}")
        return

    # Sort by IP
    devices.sort(key=lambda x: [int(p) for p in x['ip'].split('.')])

    print(f"  {BOLD}{'IP Address':<16} {'MAC Address':<18} {'Vendor':<20} {'Hostname':<25}{RESET}")
    print(f"  {DIM}{'─' * 80}{RESET}")

    for dev in devices:
        ip = dev['ip']
        mac = dev['mac']
        vendor = dev.get('vendor', 'Unknown')[:18]
        hostname = get_hostname(ip)

        # Color by vendor type
        if 'Raspberry' in vendor:
            color = GREEN
        elif 'Apple' in vendor or 'Samsung' in vendor or 'Google' in vendor:
            color = CYAN
        elif 'VMware' in vendor or 'Virtual' in vendor or 'QEMU' in vendor:
            color = YELLOW
        else:
            color = RESET

        print(f"  {CYAN}{ip:<16}{RESET} {DIM}{mac:<18}{RESET} {color}{vendor:<20}{RESET} {hostname:<25}")

    print(f"\n  {GREEN}Found {len(devices)} devices on the network{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description='ARP Network Scanner')
    parser.add_argument('network', nargs='?', help='Network to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--interface', '-i', help='Network interface')
    args = parser.parse_args()

    network = args.network or get_local_network()

    print(f"\n{BOLD}{CYAN}ARP Scanner{RESET}")
    print(f"{DIM}Network: {network}{RESET}")
    print(f"{DIM}Scanning for devices...{RESET}\n")

    devices = scan_network_arp(network)
    display_devices(devices)


if __name__ == '__main__':
    main()
