#!/usr/bin/env python3
"""
System Info - Display comprehensive system information
Usage: sysinfo.py [--json]
"""

import os
import subprocess
import platform
import argparse
import json

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
MAGENTA = '\033[95m'


def run_cmd(cmd):
    """Run command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except:
        return None


def get_cpu_info():
    """Get CPU information"""
    info = {
        'model': 'Unknown',
        'cores': 0,
        'threads': 0,
        'freq': 'Unknown'
    }

    try:
        with open('/proc/cpuinfo', 'r') as f:
            content = f.read()

        for line in content.split('\n'):
            if 'model name' in line:
                info['model'] = line.split(':')[1].strip()
                break

        info['cores'] = os.cpu_count() or 0

        # Get thread count
        threads = run_cmd("grep -c processor /proc/cpuinfo")
        if threads:
            info['threads'] = int(threads)

        # Get frequency
        freq = run_cmd("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null")
        if freq:
            info['freq'] = f"{int(freq) / 1000:.0f} MHz"
    except:
        pass

    return info


def get_memory_info():
    """Get memory information"""
    info = {
        'total': 0,
        'used': 0,
        'free': 0,
        'percent': 0
    }

    try:
        with open('/proc/meminfo', 'r') as f:
            content = f.read()

        for line in content.split('\n'):
            if line.startswith('MemTotal:'):
                info['total'] = int(line.split()[1]) * 1024
            elif line.startswith('MemAvailable:'):
                info['free'] = int(line.split()[1]) * 1024

        info['used'] = info['total'] - info['free']
        info['percent'] = (info['used'] / info['total'] * 100) if info['total'] > 0 else 0
    except:
        pass

    return info


def get_disk_info():
    """Get disk information"""
    disks = []
    try:
        result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            parts = lines[1].split()
            disks.append({
                'mount': parts[5],
                'total': parts[1],
                'used': parts[2],
                'free': parts[3],
                'percent': int(parts[4].replace('%', ''))
            })
    except:
        pass
    return disks


def get_gpu_info():
    """Get GPU information"""
    gpu = run_cmd("lspci 2>/dev/null | grep -i 'vga\\|3d\\|display' | head -1 | cut -d: -f3")
    if gpu:
        return gpu.strip()
    return None


def get_network_info():
    """Get network interface information"""
    interfaces = []
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        current_iface = None

        for line in result.stdout.split('\n'):
            if ': ' in line and not line.startswith(' '):
                parts = line.split(': ')
                if len(parts) >= 2:
                    current_iface = {'name': parts[1].split('@')[0], 'ip': None, 'mac': None}
            elif 'inet ' in line and current_iface:
                current_iface['ip'] = line.split()[1].split('/')[0]
            elif 'link/ether' in line and current_iface:
                current_iface['mac'] = line.split()[1]
                if current_iface['name'] not in ['lo']:
                    interfaces.append(current_iface)
                current_iface = None
    except:
        pass
    return interfaces


def get_uptime():
    """Get system uptime"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])

        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m")

        return ' '.join(parts)
    except:
        return None


def format_bytes(b):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def usage_bar(percent, width=20):
    """Create usage bar"""
    filled = int((percent / 100) * width)
    bar = '█' * filled + '░' * (width - filled)

    if percent > 90:
        return f"{RED}{bar}{RESET}"
    elif percent > 70:
        return f"{YELLOW}{bar}{RESET}"
    return f"{GREEN}{bar}{RESET}"


def main():
    parser = argparse.ArgumentParser(description='System Information')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    # Gather all info
    cpu = get_cpu_info()
    memory = get_memory_info()
    disks = get_disk_info()
    gpu = get_gpu_info()
    network = get_network_info()
    uptime = get_uptime()

    if args.json:
        data = {
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'hostname': platform.node()
            },
            'cpu': cpu,
            'memory': memory,
            'disks': disks,
            'gpu': gpu,
            'network': network,
            'uptime': uptime
        }
        print(json.dumps(data, indent=2, default=str))
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🖥️  System Information                         ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # System
    print(f"  {BOLD}System:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}Hostname:{RESET}    {platform.node()}")
    print(f"  {CYAN}OS:{RESET}          {platform.system()} {platform.release()}")
    print(f"  {CYAN}Kernel:{RESET}      {platform.version().split()[0] if platform.version() else 'Unknown'}")
    print(f"  {CYAN}Arch:{RESET}        {platform.machine()}")
    if uptime:
        print(f"  {CYAN}Uptime:{RESET}      {GREEN}{uptime}{RESET}")
    print()

    # CPU
    print(f"  {BOLD}CPU:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}Model:{RESET}       {cpu['model'][:45]}")
    print(f"  {CYAN}Cores:{RESET}       {cpu['cores']} cores, {cpu['threads']} threads")
    print(f"  {CYAN}Frequency:{RESET}   {cpu['freq']}")

    # Load average
    try:
        load = os.getloadavg()
        print(f"  {CYAN}Load Avg:{RESET}    {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}")
    except:
        pass
    print()

    # Memory
    print(f"  {BOLD}Memory:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    bar = usage_bar(memory['percent'])
    print(f"  {CYAN}RAM:{RESET}         {bar} {memory['percent']:.1f}%")
    print(f"  {CYAN}Used:{RESET}        {format_bytes(memory['used'])} / {format_bytes(memory['total'])}")
    print(f"  {CYAN}Available:{RESET}   {format_bytes(memory['free'])}")
    print()

    # Disk
    if disks:
        print(f"  {BOLD}Storage:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        for disk in disks:
            bar = usage_bar(disk['percent'])
            print(f"  {CYAN}{disk['mount']:<12}{RESET} {bar} {disk['percent']}%")
            print(f"               {disk['used']} / {disk['total']} ({disk['free']} free)")
        print()

    # GPU
    if gpu:
        print(f"  {BOLD}GPU:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        print(f"  {CYAN}Graphics:{RESET}    {gpu[:50]}")
        print()

    # Network
    if network:
        print(f"  {BOLD}Network:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        for iface in network[:4]:
            ip_str = iface['ip'] if iface['ip'] else 'No IP'
            print(f"  {CYAN}{iface['name']:<12}{RESET} {ip_str}")
            if iface['mac']:
                print(f"  {DIM}{'':12} {iface['mac']}{RESET}")
        print()

    # Shell
    print(f"  {BOLD}Environment:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}Shell:{RESET}       {os.environ.get('SHELL', 'Unknown')}")
    print(f"  {CYAN}Terminal:{RESET}    {os.environ.get('TERM', 'Unknown')}")
    print(f"  {CYAN}User:{RESET}        {os.environ.get('USER', 'Unknown')}")
    print(f"  {CYAN}Home:{RESET}        {os.environ.get('HOME', 'Unknown')}")
    print()


if __name__ == '__main__':
    main()
