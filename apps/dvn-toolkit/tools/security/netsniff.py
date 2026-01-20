#!/usr/bin/env python3
"""
Network Sniffer - Capture and analyze network packets (requires root)
Usage: sudo netsniff [--interface eth0] [--filter "tcp port 80"] [--output capture.pcap]
"""

import argparse
import socket
import struct
import sys
import os
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Ethernet header: 14 bytes
# IP header: 20+ bytes
# TCP header: 20+ bytes
# UDP header: 8 bytes

PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    89: 'OSPF',
}

TCP_FLAGS = {
    0x01: 'FIN',
    0x02: 'SYN',
    0x04: 'RST',
    0x08: 'PSH',
    0x10: 'ACK',
    0x20: 'URG',
    0x40: 'ECE',
    0x80: 'CWR',
}

def parse_ethernet(raw_data):
    """Parse Ethernet header"""
    dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = ':'.join(f'{b:02x}' for b in dest)
    src_mac = ':'.join(f'{b:02x}' for b in src)
    return dest_mac, src_mac, socket.htons(proto), raw_data[14:]

def parse_ip(raw_data):
    """Parse IP header"""
    version_ihl = raw_data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl, protocol, src, dest = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip = '.'.join(map(str, src))
    dest_ip = '.'.join(map(str, dest))
    return version, ihl, ttl, protocol, src_ip, dest_ip, raw_data[ihl:]

def parse_tcp(raw_data):
    """Parse TCP header"""
    src_port, dest_port, seq, ack, offset_flags = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x1FF

    flag_str = []
    for mask, name in TCP_FLAGS.items():
        if flags & mask:
            flag_str.append(name)

    return src_port, dest_port, seq, ack, flag_str, raw_data[offset:]

def parse_udp(raw_data):
    """Parse UDP header"""
    src_port, dest_port, length = struct.unpack('! H H H 2x', raw_data[:8])
    return src_port, dest_port, length, raw_data[8:]

def parse_icmp(raw_data):
    """Parse ICMP header"""
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return icmp_type, code, raw_data[4:]

def format_data(data, max_len=64):
    """Format packet data for display"""
    if not data:
        return ""

    # Try to decode as ASCII
    try:
        text = data[:max_len].decode('utf-8', errors='replace')
        printable = ''.join(c if c.isprintable() else '.' for c in text)
        return printable
    except:
        return data[:max_len].hex()

def get_color_for_protocol(proto):
    """Get color for protocol"""
    if proto == 'TCP':
        return CYAN
    elif proto == 'UDP':
        return GREEN
    elif proto == 'ICMP':
        return YELLOW
    return RESET

def sniff(interface=None, packet_filter=None, output_file=None, count=0, verbose=False):
    """Main packet capture loop"""
    # Create raw socket
    try:
        if os.name == 'nt':
            # Windows
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if interface:
                sock.bind((interface, 0))
    except PermissionError:
        print(f"{RED}Error: This tool requires root/admin privileges{RESET}")
        print(f"{DIM}Run with: sudo python netsniff.py{RESET}")
        return
    except Exception as e:
        print(f"{RED}Error creating socket: {e}{RESET}")
        return

    print(f"{BOLD}{CYAN}Network Sniffer{RESET}")
    print(f"Interface: {interface or 'all'}")
    if packet_filter:
        print(f"Filter: {packet_filter}")
    print(f"\n{BOLD}Capturing packets... (Ctrl+C to stop){RESET}\n")

    packets_captured = 0
    pcap_data = []

    try:
        while count == 0 or packets_captured < count:
            raw_data, addr = sock.recvfrom(65535)
            timestamp = datetime.now()

            # Parse Ethernet (Linux only, Windows starts at IP)
            if os.name != 'nt':
                dest_mac, src_mac, eth_proto, data = parse_ethernet(raw_data)
                if eth_proto != 8:  # Not IPv4
                    continue
            else:
                data = raw_data

            # Parse IP
            try:
                version, ihl, ttl, protocol, src_ip, dest_ip, data = parse_ip(data)
            except:
                continue

            proto_name = PROTOCOLS.get(protocol, f'Unknown({protocol})')
            color = get_color_for_protocol(proto_name)

            # Apply filter
            if packet_filter:
                filter_match = False
                if proto_name.lower() in packet_filter.lower():
                    filter_match = True
                elif src_ip in packet_filter or dest_ip in packet_filter:
                    filter_match = True
                if 'port' in packet_filter.lower():
                    # Will check port below
                    pass
                elif not filter_match:
                    continue

            # Parse transport layer
            src_port = dest_port = 0
            flags_str = ""
            payload = b""

            if protocol == 6:  # TCP
                src_port, dest_port, seq, ack, flags, payload = parse_tcp(data)
                flags_str = ','.join(flags)
            elif protocol == 17:  # UDP
                src_port, dest_port, length, payload = parse_udp(data)
            elif protocol == 1:  # ICMP
                icmp_type, code, payload = parse_icmp(data)
                flags_str = f"type={icmp_type} code={code}"

            # Port filter
            if packet_filter and 'port' in packet_filter.lower():
                import re
                port_match = re.search(r'port\s*(\d+)', packet_filter.lower())
                if port_match:
                    port = int(port_match.group(1))
                    if src_port != port and dest_port != port:
                        continue

            packets_captured += 1

            # Format output
            time_str = timestamp.strftime('%H:%M:%S.%f')[:-3]

            if src_port and dest_port:
                print(f"{DIM}{time_str}{RESET} {color}{proto_name:4}{RESET} {src_ip}:{src_port} → {dest_ip}:{dest_port}", end='')
            else:
                print(f"{DIM}{time_str}{RESET} {color}{proto_name:4}{RESET} {src_ip} → {dest_ip}", end='')

            if flags_str:
                print(f" [{flags_str}]", end='')

            print(f" len={len(payload)}")

            if verbose and payload:
                data_preview = format_data(payload)
                if data_preview:
                    print(f"  {DIM}{data_preview}{RESET}")

            # Store for pcap
            if output_file:
                pcap_data.append((timestamp, raw_data))

    except KeyboardInterrupt:
        print(f"\n\n{BOLD}Capture stopped{RESET}")
        print(f"Packets captured: {packets_captured}")

    finally:
        sock.close()

        # Save to simple format (not true pcap, but readable)
        if output_file and pcap_data:
            with open(output_file, 'wb') as f:
                for ts, data in pcap_data:
                    f.write(f"--- {ts.isoformat()} ---\n".encode())
                    f.write(data)
                    f.write(b'\n')
            print(f"Saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Network Sniffer')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--filter', '-f', help='Packet filter (e.g., "tcp port 80")')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--count', '-c', type=int, default=0, help='Number of packets to capture')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show packet data')
    args = parser.parse_args()

    if os.geteuid() != 0 and os.name != 'nt':
        print(f"{RED}This tool requires root privileges{RESET}")
        print(f"Run with: sudo {' '.join(sys.argv)}")
        return

    sniff(args.interface, args.filter, args.output, args.count, args.verbose)

if __name__ == '__main__':
    main()
