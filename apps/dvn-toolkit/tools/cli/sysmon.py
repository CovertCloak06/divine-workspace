#!/usr/bin/env python3
"""
System Monitor - Live CPU/RAM/Disk/Network dashboard
Usage: sysmon [--interval 1] [--no-color]
"""

import os
import time
import argparse
from pathlib import Path

# ANSI colors
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

def read_file(path):
    try:
        return Path(path).read_text().strip()
    except:
        return None

def get_cpu_usage():
    """Get CPU usage from /proc/stat"""
    try:
        with open('/proc/stat') as f:
            line = f.readline()
        parts = line.split()[1:]
        idle = int(parts[3])
        total = sum(int(p) for p in parts[:8])
        return idle, total
    except:
        return 0, 1

def get_memory():
    """Get memory stats from /proc/meminfo"""
    mem = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(':')] = int(parts[1]) * 1024
    except:
        pass

    total = mem.get('MemTotal', 0)
    available = mem.get('MemAvailable', mem.get('MemFree', 0))
    used = total - available
    swap_total = mem.get('SwapTotal', 0)
    swap_free = mem.get('SwapFree', 0)

    return {
        'total': total,
        'used': used,
        'available': available,
        'percent': (used / total * 100) if total else 0,
        'swap_total': swap_total,
        'swap_used': swap_total - swap_free
    }

def get_disk():
    """Get disk usage"""
    try:
        st = os.statvfs('/')
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        return {
            'total': total,
            'used': used,
            'free': free,
            'percent': (used / total * 100) if total else 0
        }
    except:
        return {'total': 0, 'used': 0, 'free': 0, 'percent': 0}

def get_network():
    """Get network stats from /proc/net/dev"""
    stats = {'rx': 0, 'tx': 0}
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if ':' in line and 'lo:' not in line:
                    parts = line.split(':')[1].split()
                    stats['rx'] += int(parts[0])
                    stats['tx'] += int(parts[8])
    except:
        pass
    return stats

def get_load():
    """Get system load average"""
    try:
        return [float(x) for x in read_file('/proc/loadavg').split()[:3]]
    except:
        return [0, 0, 0]

def get_uptime():
    """Get system uptime"""
    try:
        secs = float(read_file('/proc/uptime').split()[0])
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        mins = int((secs % 3600) // 60)
        return f"{days}d {hours}h {mins}m"
    except:
        return "unknown"

def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}PB"

def bar(percent, width=30, color=GREEN):
    filled = int(width * percent / 100)
    empty = width - filled
    if percent > 90:
        color = RED
    elif percent > 70:
        color = YELLOW
    return f"{color}{'█' * filled}{DIM}{'░' * empty}{RESET}"

def main():
    parser = argparse.ArgumentParser(description='System Monitor')
    parser.add_argument('--interval', '-i', type=float, default=1.0, help='Update interval')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    args = parser.parse_args()

    if args.no_color:
        globals().update({k: '' for k in ['CYAN', 'GREEN', 'YELLOW', 'RED', 'RESET', 'BOLD', 'DIM']})

    prev_cpu = get_cpu_usage()
    prev_net = get_network()
    prev_time = time.time()

    try:
        while True:
            time.sleep(args.interval)

            # Calculate CPU usage
            curr_cpu = get_cpu_usage()
            idle_diff = curr_cpu[0] - prev_cpu[0]
            total_diff = curr_cpu[1] - prev_cpu[1]
            cpu_percent = 100 * (1 - idle_diff / total_diff) if total_diff else 0
            prev_cpu = curr_cpu

            # Calculate network speed
            curr_net = get_network()
            curr_time = time.time()
            time_diff = curr_time - prev_time
            rx_speed = (curr_net['rx'] - prev_net['rx']) / time_diff
            tx_speed = (curr_net['tx'] - prev_net['tx']) / time_diff
            prev_net = curr_net
            prev_time = curr_time

            mem = get_memory()
            disk = get_disk()
            load = get_load()

            # Clear screen and print
            os.system('clear' if os.name != 'nt' else 'cls')

            print(f"{BOLD}{CYAN}System Monitor{RESET}")
            print(f"{DIM}Uptime: {get_uptime()} | Load: {load[0]:.2f} {load[1]:.2f} {load[2]:.2f}{RESET}\n")

            print(f"{BOLD}CPU{RESET}  {bar(cpu_percent)} {cpu_percent:5.1f}%")
            print(f"{BOLD}RAM{RESET}  {bar(mem['percent'])} {mem['percent']:5.1f}%  {human_size(mem['used'])}/{human_size(mem['total'])}")
            print(f"{BOLD}Disk{RESET} {bar(disk['percent'])} {disk['percent']:5.1f}%  {human_size(disk['used'])}/{human_size(disk['total'])}")

            if mem['swap_total']:
                swap_pct = mem['swap_used'] / mem['swap_total'] * 100
                print(f"{BOLD}Swap{RESET} {bar(swap_pct)} {swap_pct:5.1f}%  {human_size(mem['swap_used'])}/{human_size(mem['swap_total'])}")

            print(f"\n{BOLD}Network{RESET}")
            print(f"  {GREEN}↓{RESET} {human_size(rx_speed)}/s   {CYAN}↑{RESET} {human_size(tx_speed)}/s")
            print(f"  Total: {human_size(curr_net['rx'])} received, {human_size(curr_net['tx'])} sent")

            print(f"\n{DIM}Press Ctrl+C to exit{RESET}")

    except KeyboardInterrupt:
        print("\n")

if __name__ == '__main__':
    main()
