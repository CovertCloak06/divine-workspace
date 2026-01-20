#!/usr/bin/env python3
"""
Process Manager - View and manage system processes
Usage: processes.py [--sort cpu|mem|pid] [--filter name]
"""

import subprocess
import argparse
import os
import signal

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_processes():
    """Get list of running processes"""
    try:
        result = subprocess.run(
            ['ps', 'aux', '--sort=-%cpu'],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split('\n')

        processes = []
        for line in lines[1:]:  # Skip header
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    'user': parts[0],
                    'pid': int(parts[1]),
                    'cpu': float(parts[2]),
                    'mem': float(parts[3]),
                    'vsz': int(parts[4]),
                    'rss': int(parts[5]),
                    'tty': parts[6],
                    'stat': parts[7],
                    'start': parts[8],
                    'time': parts[9],
                    'command': parts[10] if len(parts) > 10 else ''
                })
        return processes
    except Exception as e:
        print(f"{RED}Error getting processes: {e}{RESET}")
        return []


def format_memory(kb):
    """Format memory in human readable"""
    if kb > 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb > 1024:
        return f"{kb / 1024:.1f} MB"
    return f"{kb} KB"


def get_cpu_bar(cpu, width=10):
    """Create CPU usage bar"""
    filled = int((cpu / 100) * width)
    filled = min(filled, width)
    bar = '█' * filled + '░' * (width - filled)

    if cpu > 80:
        return f"{RED}{bar}{RESET}"
    elif cpu > 50:
        return f"{YELLOW}{bar}{RESET}"
    return f"{GREEN}{bar}{RESET}"


def get_mem_bar(mem, width=10):
    """Create memory usage bar"""
    filled = int((mem / 100) * width)
    filled = min(filled, width)
    bar = '█' * filled + '░' * (width - filled)

    if mem > 80:
        return f"{RED}{bar}{RESET}"
    elif mem > 50:
        return f"{YELLOW}{bar}{RESET}"
    return f"{GREEN}{bar}{RESET}"


def kill_process(pid, force=False):
    """Kill a process by PID"""
    try:
        sig = signal.SIGKILL if force else signal.SIGTERM
        os.kill(pid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return None


def interactive_mode(processes):
    """Interactive process management"""
    while True:
        print(f"\n  {BOLD}Actions:{RESET}")
        print(f"  {CYAN}[k]{RESET} Kill process  {CYAN}[r]{RESET} Refresh  {CYAN}[q]{RESET} Quit")

        action = input(f"\n  {CYAN}Action:{RESET} ").strip().lower()

        if action == 'q':
            break
        elif action == 'r':
            return True  # Signal to refresh
        elif action == 'k':
            try:
                pid = int(input(f"  {CYAN}PID to kill:{RESET} "))
                force = input(f"  {CYAN}Force kill? (y/N):{RESET} ").strip().lower() == 'y'

                result = kill_process(pid, force)
                if result is True:
                    print(f"  {GREEN}Process {pid} terminated{RESET}")
                elif result is False:
                    print(f"  {YELLOW}Process {pid} not found{RESET}")
                else:
                    print(f"  {RED}Permission denied - try with sudo{RESET}")
            except ValueError:
                print(f"  {RED}Invalid PID{RESET}")

    return False


def main():
    parser = argparse.ArgumentParser(description='Process Manager')
    parser.add_argument('--sort', '-s', default='cpu', choices=['cpu', 'mem', 'pid', 'user'],
                        help='Sort by field')
    parser.add_argument('--filter', '-f', help='Filter by process name')
    parser.add_argument('--count', '-n', type=int, default=20, help='Number of processes to show')
    parser.add_argument('--all', '-a', action='store_true', help='Show all processes')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    args = parser.parse_args()

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')

        print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║              📊 Process Manager                            ║{RESET}")
        print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

        processes = get_processes()

        if not processes:
            print(f"  {RED}No processes found{RESET}\n")
            return

        # Filter
        if args.filter:
            processes = [p for p in processes if args.filter.lower() in p['command'].lower()]
            print(f"  {DIM}Filtered by: {args.filter}{RESET}\n")

        # Sort
        if args.sort == 'cpu':
            processes.sort(key=lambda x: x['cpu'], reverse=True)
        elif args.sort == 'mem':
            processes.sort(key=lambda x: x['mem'], reverse=True)
        elif args.sort == 'pid':
            processes.sort(key=lambda x: x['pid'])
        elif args.sort == 'user':
            processes.sort(key=lambda x: x['user'])

        # Limit
        count = len(processes) if args.all else min(args.count, len(processes))

        # System summary
        total_cpu = sum(p['cpu'] for p in processes)
        total_mem = sum(p['mem'] for p in processes)

        print(f"  {BOLD}System Summary:{RESET}")
        print(f"  {DIM}{'─' * 56}{RESET}")
        print(f"  Total Processes: {CYAN}{len(processes)}{RESET}  |  CPU Load: {YELLOW}{total_cpu:.1f}%{RESET}  |  Memory: {YELLOW}{total_mem:.1f}%{RESET}")
        print()

        # Header
        print(f"  {BOLD}{'PID':>7}  {'USER':<10} {'CPU':>6} {'MEM':>6} {'RSS':>10}  COMMAND{RESET}")
        print(f"  {DIM}{'─' * 70}{RESET}")

        for p in processes[:count]:
            # Truncate command
            cmd = p['command'][:35] + '...' if len(p['command']) > 38 else p['command']

            # Color based on resource usage
            if p['cpu'] > 50 or p['mem'] > 50:
                color = RED
            elif p['cpu'] > 20 or p['mem'] > 20:
                color = YELLOW
            else:
                color = RESET

            cpu_bar = get_cpu_bar(p['cpu'], 6)

            print(f"  {CYAN}{p['pid']:>7}{RESET}  {p['user']:<10} {color}{p['cpu']:>5.1f}%{RESET} {p['mem']:>5.1f}% {format_memory(p['rss']):>10}  {cmd}")

        print(f"\n  {DIM}Showing {count} of {len(processes)} processes (sorted by {args.sort}){RESET}")

        if args.interactive:
            if not interactive_mode(processes):
                break
        else:
            break

    print()


if __name__ == '__main__':
    main()
