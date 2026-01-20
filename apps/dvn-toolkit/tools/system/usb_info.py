#!/usr/bin/env python3
"""
USB Info - Display USB device information
Usage: usb_info.py
"""

import subprocess
import os
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_usb_devices():
    """Get list of USB devices using lsusb"""
    devices = []

    try:
        result = subprocess.run(['lsusb'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.strip():
                # Parse: Bus 001 Device 002: ID 1234:5678 Device Name
                match = re.match(r'Bus (\d+) Device (\d+): ID ([0-9a-f:]+) (.+)', line)
                if match:
                    devices.append({
                        'bus': match.group(1),
                        'device': match.group(2),
                        'id': match.group(3),
                        'name': match.group(4),
                    })
    except FileNotFoundError:
        pass

    return devices


def get_usb_details(bus, device):
    """Get detailed USB device info"""
    try:
        result = subprocess.run(
            ['lsusb', '-v', '-s', f'{bus}:{device}'],
            capture_output=True, text=True
        )
        return result.stdout
    except:
        return ""


def get_block_devices():
    """Get USB block devices (storage)"""
    devices = []

    try:
        result = subprocess.run(['lsblk', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL', '-J'],
                               capture_output=True, text=True)
        import json
        data = json.loads(result.stdout)

        for device in data.get('blockdevices', []):
            if device.get('type') == 'disk':
                # Check if USB by looking at /sys
                dev_name = device.get('name', '')
                if os.path.exists(f'/sys/block/{dev_name}/device'):
                    removable_path = f'/sys/block/{dev_name}/removable'
                    if os.path.exists(removable_path):
                        with open(removable_path) as f:
                            if f.read().strip() == '1':
                                devices.append(device)
    except:
        pass

    return devices


def get_usb_ports():
    """Get USB port information"""
    ports = []

    try:
        # Walk /sys/bus/usb/devices
        usb_path = '/sys/bus/usb/devices'
        if os.path.exists(usb_path):
            for entry in os.listdir(usb_path):
                entry_path = os.path.join(usb_path, entry)
                if os.path.isdir(entry_path):
                    info = {'port': entry}

                    # Read device info
                    for prop in ['manufacturer', 'product', 'idVendor', 'idProduct', 'speed']:
                        prop_path = os.path.join(entry_path, prop)
                        if os.path.exists(prop_path):
                            try:
                                with open(prop_path) as f:
                                    info[prop] = f.read().strip()
                            except:
                                pass

                    if 'idVendor' in info:
                        ports.append(info)
    except:
        pass

    return ports


def format_speed(speed):
    """Format USB speed"""
    speed_map = {
        '1.5': 'Low Speed (1.5 Mbps)',
        '12': 'Full Speed (12 Mbps)',
        '480': 'High Speed USB 2.0 (480 Mbps)',
        '5000': 'SuperSpeed USB 3.0 (5 Gbps)',
        '10000': 'SuperSpeed+ USB 3.1 (10 Gbps)',
        '20000': 'SuperSpeed+ USB 3.2 (20 Gbps)',
    }
    return speed_map.get(speed, f'{speed} Mbps')


def main():
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔌 USB Device Info                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # List USB devices
    devices = get_usb_devices()

    if devices:
        print(f"  {BOLD}USB Devices ({len(devices)}):{RESET}")
        print(f"  {DIM}{'─' * 55}{RESET}\n")

        for dev in devices:
            # Determine device type by name/id
            name_lower = dev['name'].lower()
            if 'hub' in name_lower:
                icon = '🔀'
                color = DIM
            elif 'keyboard' in name_lower:
                icon = '⌨️ '
                color = GREEN
            elif 'mouse' in name_lower:
                icon = '🖱️ '
                color = GREEN
            elif 'storage' in name_lower or 'flash' in name_lower or 'disk' in name_lower:
                icon = '💾'
                color = YELLOW
            elif 'camera' in name_lower or 'webcam' in name_lower:
                icon = '📷'
                color = GREEN
            elif 'audio' in name_lower or 'sound' in name_lower:
                icon = '🔊'
                color = GREEN
            elif 'bluetooth' in name_lower:
                icon = '📶'
                color = CYAN
            elif 'wireless' in name_lower or 'wifi' in name_lower:
                icon = '📡'
                color = CYAN
            else:
                icon = '📟'
                color = RESET

            print(f"  {icon} {color}{dev['name'][:45]}{RESET}")
            print(f"     {DIM}ID: {dev['id']} | Bus {dev['bus']} Device {dev['device']}{RESET}")
            print()
    else:
        print(f"  {DIM}No USB devices found (lsusb not available?){RESET}\n")

    # USB Storage devices
    storage = get_block_devices()

    if storage:
        print(f"  {BOLD}USB Storage:{RESET}")
        print(f"  {DIM}{'─' * 55}{RESET}\n")

        for dev in storage:
            name = dev.get('name', 'unknown')
            size = dev.get('size', 'N/A')
            vendor = dev.get('vendor', '').strip() or 'Unknown'
            model = dev.get('model', '').strip() or 'USB Device'
            mount = dev.get('mountpoint', '')

            print(f"  💾 {GREEN}/dev/{name}{RESET} - {size}")
            print(f"     {CYAN}Vendor:{RESET} {vendor}")
            print(f"     {CYAN}Model:{RESET}  {model}")
            if mount:
                print(f"     {CYAN}Mount:{RESET}  {mount}")

            # List partitions
            for child in dev.get('children', []):
                child_name = child.get('name', '')
                child_size = child.get('size', '')
                child_mount = child.get('mountpoint', '')
                mount_str = f" → {child_mount}" if child_mount else ""
                print(f"     {DIM}├── {child_name} ({child_size}){mount_str}{RESET}")

            print()

    # USB port details
    ports = get_usb_ports()

    if ports:
        connected = [p for p in ports if p.get('product') or p.get('manufacturer')]

        if connected:
            print(f"  {BOLD}Device Details:{RESET}")
            print(f"  {DIM}{'─' * 55}{RESET}\n")

            for port in connected[:10]:
                product = port.get('product', 'Unknown Device')
                manufacturer = port.get('manufacturer', '')
                speed = port.get('speed', '')

                print(f"  {GREEN}{product}{RESET}")
                if manufacturer:
                    print(f"     {CYAN}Manufacturer:{RESET} {manufacturer}")
                print(f"     {CYAN}ID:{RESET} {port.get('idVendor', '????')}:{port.get('idProduct', '????')}")
                if speed:
                    print(f"     {CYAN}Speed:{RESET} {format_speed(speed)}")
                print()

    # USB version info
    print(f"  {BOLD}USB Speed Reference:{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}")
    print(f"  {CYAN}USB 1.1:{RESET}  12 Mbps (Full Speed)")
    print(f"  {CYAN}USB 2.0:{RESET}  480 Mbps (High Speed)")
    print(f"  {CYAN}USB 3.0:{RESET}  5 Gbps (SuperSpeed)")
    print(f"  {CYAN}USB 3.1:{RESET}  10 Gbps (SuperSpeed+)")
    print(f"  {CYAN}USB 3.2:{RESET}  20 Gbps (SuperSpeed+)")
    print(f"  {CYAN}USB4:{RESET}    40 Gbps")
    print()


if __name__ == '__main__':
    main()
