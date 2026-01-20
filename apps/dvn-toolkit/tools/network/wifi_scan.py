#!/usr/bin/env python3
"""
WiFi Network Scanner - Find nearby wireless networks
Usage: wifi_scan.py [--interface wlan0] [--watch]
"""

import subprocess
import re
import argparse
import time
import os

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_wifi_interface():
    """Find the wireless interface"""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.STDOUT)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line or 'ESSID' in line:
                return line.split()[0]
    except:
        pass

    # Try common names
    for iface in ['wlan0', 'wlp2s0', 'wlp3s0', 'wifi0']:
        if os.path.exists(f'/sys/class/net/{iface}'):
            return iface
    return None


def scan_networks_nmcli():
    """Scan using NetworkManager CLI"""
    networks = []
    try:
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY', 'dev', 'wifi', 'list', '--rescan', 'yes'],
            capture_output=True, text=True, timeout=30
        )

        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split(':')
            if len(parts) >= 7:
                networks.append({
                    'ssid': parts[0] or '<Hidden>',
                    'bssid': ':'.join(parts[1:7]),
                    'channel': parts[7] if len(parts) > 7 else '',
                    'signal': parts[10] if len(parts) > 10 else '',
                    'bars': parts[11] if len(parts) > 11 else '',
                    'security': parts[12] if len(parts) > 12 else 'Open'
                })
    except Exception as e:
        pass

    return networks


def scan_networks_iwlist(interface):
    """Scan using iwlist (requires sudo)"""
    networks = []
    try:
        result = subprocess.run(
            ['sudo', 'iwlist', interface, 'scan'],
            capture_output=True, text=True, timeout=30
        )

        current = {}
        for line in result.stdout.split('\n'):
            line = line.strip()

            if 'Cell' in line and 'Address:' in line:
                if current:
                    networks.append(current)
                current = {'bssid': line.split('Address:')[1].strip()}
            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip('"')
                current['ssid'] = ssid or '<Hidden>'
            elif 'Channel:' in line:
                current['channel'] = re.search(r'Channel:(\d+)', line).group(1)
            elif 'Signal level=' in line:
                match = re.search(r'Signal level[=:](-?\d+)', line)
                if match:
                    current['signal'] = match.group(1)
            elif 'Encryption key:' in line:
                current['encrypted'] = 'on' in line.lower()
            elif 'WPA' in line or 'WPA2' in line:
                current['security'] = current.get('security', '') + ' WPA'

        if current:
            networks.append(current)

    except Exception as e:
        pass

    return networks


def signal_to_bars(signal):
    """Convert signal strength to visual bars"""
    try:
        sig = int(signal)
        if sig >= 80 or sig >= -50:
            return '████', GREEN
        elif sig >= 60 or sig >= -60:
            return '███░', GREEN
        elif sig >= 40 or sig >= -70:
            return '██░░', YELLOW
        elif sig >= 20 or sig >= -80:
            return '█░░░', YELLOW
        else:
            return '░░░░', RED
    except:
        return '????', DIM


def display_networks(networks):
    """Display networks in a nice table"""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                     📡 WiFi Network Scanner                          ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════╝{RESET}\n")

    if not networks:
        print(f"  {RED}No networks found. Try running with sudo or check your WiFi adapter.{RESET}")
        return

    # Sort by signal strength
    networks.sort(key=lambda x: int(x.get('signal', 0) or 0), reverse=True)

    print(f"  {BOLD}{'SSID':<30} {'BSSID':<18} {'CH':>3} {'Signal':>8} {'Security':<15}{RESET}")
    print(f"  {DIM}{'─' * 80}{RESET}")

    for net in networks:
        ssid = net.get('ssid', '<Unknown>')[:28]
        bssid = net.get('bssid', '')[:17]
        channel = net.get('channel', '?')
        signal = net.get('signal', '')
        security = net.get('security', 'Open')[:14]

        bars, color = signal_to_bars(signal)

        # Color security
        if 'WPA3' in security:
            sec_color = GREEN
        elif 'WPA2' in security or 'WPA' in security:
            sec_color = YELLOW
        elif 'WEP' in security:
            sec_color = RED
        else:
            sec_color = RED  # Open network

        print(f"  {CYAN}{ssid:<30}{RESET} {DIM}{bssid:<18}{RESET} {channel:>3} {color}{bars}{RESET} {signal:>3}  {sec_color}{security:<15}{RESET}")

    print(f"\n  {DIM}Found {len(networks)} networks{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description='WiFi Network Scanner')
    parser.add_argument('--interface', '-i', help='Wireless interface to use')
    parser.add_argument('--watch', '-w', action='store_true', help='Continuously scan')
    parser.add_argument('--interval', type=int, default=5, help='Scan interval in seconds')
    args = parser.parse_args()

    interface = args.interface or get_wifi_interface()

    print(f"\n{BOLD}{CYAN}WiFi Scanner{RESET}")
    print(f"{DIM}Interface: {interface or 'auto-detect'}{RESET}")
    print(f"{DIM}Scanning...{RESET}")

    try:
        while True:
            # Try nmcli first (doesn't need sudo)
            networks = scan_networks_nmcli()

            # Fall back to iwlist if nmcli fails
            if not networks and interface:
                networks = scan_networks_iwlist(interface)

            os.system('clear' if os.name != 'nt' else 'cls')
            display_networks(networks)

            if not args.watch:
                break

            print(f"  {DIM}Refreshing in {args.interval}s... (Ctrl+C to stop){RESET}")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{CYAN}Scan stopped.{RESET}\n")


if __name__ == '__main__':
    main()
