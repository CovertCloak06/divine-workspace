#!/usr/bin/env python3
"""
Bandwidth Monitor - Real-time network traffic monitor
Usage: bandwidth.py [--interface eth0] [--interval 1]
"""

import os
import time
import argparse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_interfaces():
    """Get list of network interfaces"""
    interfaces = []
    try:
        for iface in os.listdir('/sys/class/net'):
            if iface != 'lo':
                interfaces.append(iface)
    except:
        pass
    return interfaces


def get_bytes(interface):
    """Get TX/RX bytes for interface"""
    try:
        with open(f'/sys/class/net/{interface}/statistics/rx_bytes') as f:
            rx = int(f.read().strip())
        with open(f'/sys/class/net/{interface}/statistics/tx_bytes') as f:
            tx = int(f.read().strip())
        return rx, tx
    except:
        return 0, 0


def format_bytes(bytes_val):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"


def format_speed(bytes_per_sec):
    """Format speed to human readable"""
    for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.1f} {unit}"
        bytes_per_sec /= 1024
    return f"{bytes_per_sec:.1f} TB/s"


def draw_bar(value, max_val, width=30):
    """Draw a progress bar"""
    if max_val == 0:
        return '░' * width
    filled = int((value / max_val) * width)
    return '█' * filled + '░' * (width - filled)


def main():
    parser = argparse.ArgumentParser(description='Bandwidth Monitor')
    parser.add_argument('--interface', '-i', help='Network interface to monitor')
    parser.add_argument('--interval', '-n', type=float, default=1, help='Update interval in seconds')
    parser.add_argument('--max-speed', '-m', type=float, default=100, help='Max speed in MB/s for bar scaling')
    args = parser.parse_args()

    interfaces = get_interfaces()

    if not interfaces:
        print(f"{RED}No network interfaces found{RESET}")
        return

    # Select interface
    if args.interface:
        if args.interface not in interfaces:
            print(f"{RED}Interface {args.interface} not found{RESET}")
            print(f"{DIM}Available: {', '.join(interfaces)}{RESET}")
            return
        selected = [args.interface]
    else:
        selected = interfaces

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📊 Bandwidth Monitor                          ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}")
    print(f"{DIM}Monitoring: {', '.join(selected)} | Interval: {args.interval}s | Ctrl+C to stop{RESET}\n")

    # Initialize previous values
    prev_stats = {iface: get_bytes(iface) for iface in selected}
    max_speed_bytes = args.max_speed * 1024 * 1024  # MB/s to B/s

    # Track totals
    session_start = time.time()
    session_rx = {iface: 0 for iface in selected}
    session_tx = {iface: 0 for iface in selected}

    # Peak speeds
    peak_rx = {iface: 0 for iface in selected}
    peak_tx = {iface: 0 for iface in selected}

    try:
        while True:
            time.sleep(args.interval)

            os.system('clear')
            print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
            print(f"{BOLD}{CYAN}║              📊 Bandwidth Monitor                          ║{RESET}")
            print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}")

            elapsed = time.time() - session_start
            print(f"{DIM}Session: {int(elapsed)}s | Ctrl+C to stop{RESET}\n")

            for iface in selected:
                rx, tx = get_bytes(iface)
                prev_rx, prev_tx = prev_stats[iface]

                # Calculate speed
                rx_speed = (rx - prev_rx) / args.interval
                tx_speed = (tx - prev_tx) / args.interval

                # Update session totals
                session_rx[iface] += (rx - prev_rx)
                session_tx[iface] += (tx - prev_tx)

                # Update peaks
                peak_rx[iface] = max(peak_rx[iface], rx_speed)
                peak_tx[iface] = max(peak_tx[iface], tx_speed)

                # Store for next iteration
                prev_stats[iface] = (rx, tx)

                # Color based on speed
                rx_color = GREEN if rx_speed < max_speed_bytes * 0.5 else YELLOW if rx_speed < max_speed_bytes * 0.8 else RED
                tx_color = GREEN if tx_speed < max_speed_bytes * 0.5 else YELLOW if tx_speed < max_speed_bytes * 0.8 else RED

                print(f"  {BOLD}{CYAN}{iface}{RESET}")
                print(f"  {'─' * 56}")

                # Download
                rx_bar = draw_bar(rx_speed, max_speed_bytes)
                print(f"  {GREEN}↓ RX:{RESET} {rx_color}{format_speed(rx_speed):>12}{RESET}  {rx_color}{rx_bar}{RESET}")

                # Upload
                tx_bar = draw_bar(tx_speed, max_speed_bytes)
                print(f"  {RED}↑ TX:{RESET} {tx_color}{format_speed(tx_speed):>12}{RESET}  {tx_color}{tx_bar}{RESET}")

                print()
                print(f"  {DIM}Total RX: {format_bytes(rx):<12} Session: {format_bytes(session_rx[iface]):<10} Peak: {format_speed(peak_rx[iface])}{RESET}")
                print(f"  {DIM}Total TX: {format_bytes(tx):<12} Session: {format_bytes(session_tx[iface]):<10} Peak: {format_speed(peak_tx[iface])}{RESET}")
                print()

    except KeyboardInterrupt:
        print(f"\n{CYAN}Monitor stopped.{RESET}")

        # Final summary
        print(f"\n{BOLD}Session Summary:{RESET}")
        for iface in selected:
            print(f"\n  {CYAN}{iface}:{RESET}")
            print(f"    Downloaded: {GREEN}{format_bytes(session_rx[iface])}{RESET}")
            print(f"    Uploaded:   {RED}{format_bytes(session_tx[iface])}{RESET}")
            print(f"    Peak DL:    {format_speed(peak_rx[iface])}")
            print(f"    Peak UL:    {format_speed(peak_tx[iface])}")
        print()


if __name__ == '__main__':
    main()
