#!/usr/bin/env python3
"""
Wake-on-LAN - Wake devices remotely
Usage: wol.py <mac_address> [--ip broadcast]
"""

import socket
import struct
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def create_magic_packet(mac_address):
    """Create Wake-on-LAN magic packet"""
    # Remove separators and validate
    mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()

    if len(mac) != 12:
        raise ValueError("Invalid MAC address length")

    if not all(c in '0123456789ABCDEF' for c in mac):
        raise ValueError("Invalid MAC address characters")

    # Convert to bytes
    mac_bytes = bytes.fromhex(mac)

    # Magic packet: 6 bytes of 0xFF followed by MAC address repeated 16 times
    magic = b'\xff' * 6 + mac_bytes * 16

    return magic


def send_magic_packet(mac_address, broadcast='255.255.255.255', port=9):
    """Send Wake-on-LAN magic packet"""
    try:
        packet = create_magic_packet(mac_address)
    except ValueError as e:
        return False, str(e)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast, port))
        sock.close()
        return True, None
    except Exception as e:
        return False, str(e)


def format_mac(mac):
    """Format MAC address nicely"""
    mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


def main():
    parser = argparse.ArgumentParser(description='Wake-on-LAN')
    parser.add_argument('mac', nargs='?', help='MAC address (e.g., AA:BB:CC:DD:EE:FF)')
    parser.add_argument('--broadcast', '-b', default='255.255.255.255',
                        help='Broadcast address')
    parser.add_argument('--port', '-p', type=int, default=9, help='Port (default: 9)')
    parser.add_argument('--count', '-c', type=int, default=3, help='Number of packets to send')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📡 Wake-on-LAN                                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.mac:
        print(f"  {BOLD}Enter MAC address of device to wake:{RESET}")
        print(f"  {DIM}Format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF{RESET}\n")
        args.mac = input(f"  {CYAN}MAC Address:{RESET} ").strip()

    if not args.mac:
        print(f"  {RED}MAC address required{RESET}\n")
        return

    # Validate MAC format
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]?){5}[0-9A-Fa-f]{2}$'
    mac_clean = args.mac.replace(':', '').replace('-', '').replace('.', '')

    if len(mac_clean) != 12 or not all(c in '0123456789ABCDEFabcdef' for c in mac_clean):
        print(f"  {RED}Invalid MAC address format{RESET}")
        print(f"  {DIM}Use format like: AA:BB:CC:DD:EE:FF{RESET}\n")
        return

    formatted_mac = format_mac(args.mac)

    print(f"  {BOLD}Target:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"  {CYAN}MAC Address:{RESET}  {GREEN}{formatted_mac}{RESET}")
    print(f"  {CYAN}Broadcast:{RESET}    {args.broadcast}")
    print(f"  {CYAN}Port:{RESET}         {args.port}")
    print()

    # Send magic packets
    print(f"  {YELLOW}Sending magic packets...{RESET}")

    success_count = 0
    for i in range(args.count):
        success, error = send_magic_packet(args.mac, args.broadcast, args.port)
        if success:
            success_count += 1
            print(f"    {GREEN}✓{RESET} Packet {i+1} sent")
        else:
            print(f"    {RED}✗{RESET} Packet {i+1} failed: {error}")

    print()
    if success_count == args.count:
        print(f"  {GREEN}✓ All {args.count} magic packets sent successfully{RESET}")
        print(f"\n  {DIM}The device should wake up in a few seconds if:{RESET}")
        print(f"  {DIM}  • Wake-on-LAN is enabled in BIOS{RESET}")
        print(f"  {DIM}  • Network adapter supports WoL{RESET}")
        print(f"  {DIM}  • Device is connected via Ethernet{RESET}")
    else:
        print(f"  {YELLOW}Sent {success_count}/{args.count} packets{RESET}")

    print()


if __name__ == '__main__':
    main()
