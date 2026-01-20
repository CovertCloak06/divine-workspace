#!/usr/bin/env python3
"""
Disk Usage Analyzer - Visualize disk space usage
Usage: diskusage.py [path] [--depth 2]
"""

import os
import argparse
import subprocess

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
MAGENTA = '\033[95m'


def get_dir_size(path):
    """Get total size of directory"""
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file(follow_symlinks=False):
                total += entry.stat().st_size
            elif entry.is_dir(follow_symlinks=False):
                total += get_dir_size(entry.path)
    except PermissionError:
        pass
    return total


def format_size(size):
    """Format size in human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def get_disk_info():
    """Get disk partition info"""
    partitions = []
    try:
        result = subprocess.run(['df', '-h'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:]

        for line in lines:
            parts = line.split()
            if len(parts) >= 6 and not parts[0].startswith('tmpfs'):
                partitions.append({
                    'filesystem': parts[0],
                    'size': parts[1],
                    'used': parts[2],
                    'avail': parts[3],
                    'percent': int(parts[4].replace('%', '')),
                    'mount': parts[5]
                })
    except:
        pass
    return partitions


def usage_bar(percent, width=30):
    """Create usage bar"""
    filled = int((percent / 100) * width)
    bar = '█' * filled + '░' * (width - filled)

    if percent > 90:
        return f"{RED}{bar}{RESET}"
    elif percent > 70:
        return f"{YELLOW}{bar}{RESET}"
    return f"{GREEN}{bar}{RESET}"


def scan_directory(path, depth=2, current_depth=0, parent_size=None):
    """Scan directory and return size info"""
    items = []

    try:
        entries = list(os.scandir(path))
    except PermissionError:
        return items

    for entry in entries:
        try:
            if entry.is_file(follow_symlinks=False):
                size = entry.stat().st_size
                items.append({
                    'name': entry.name,
                    'path': entry.path,
                    'size': size,
                    'type': 'file',
                    'children': []
                })
            elif entry.is_dir(follow_symlinks=False):
                size = get_dir_size(entry.path)
                children = []
                if current_depth < depth - 1:
                    children = scan_directory(entry.path, depth, current_depth + 1, size)
                items.append({
                    'name': entry.name,
                    'path': entry.path,
                    'size': size,
                    'type': 'dir',
                    'children': children
                })
        except (PermissionError, OSError):
            continue

    # Sort by size descending
    items.sort(key=lambda x: x['size'], reverse=True)
    return items


def print_tree(items, total_size, indent=0, max_items=15):
    """Print directory tree with sizes"""
    shown = 0

    for item in items[:max_items]:
        prefix = '  ' * indent
        percent = (item['size'] / total_size * 100) if total_size > 0 else 0

        # Color based on size percentage
        if percent > 30:
            color = RED
        elif percent > 10:
            color = YELLOW
        else:
            color = RESET

        # Icon
        icon = '📁' if item['type'] == 'dir' else '📄'

        # Size bar (mini)
        bar_width = 10
        filled = int((percent / 100) * bar_width)
        bar = '█' * filled + '░' * (bar_width - filled)

        name = item['name'][:30] + '...' if len(item['name']) > 33 else item['name']

        print(f"{prefix}{icon} {color}{name:<35}{RESET} {format_size(item['size']):>10}  {DIM}{bar}{RESET} {percent:>5.1f}%")

        # Print children
        if item['children']:
            print_tree(item['children'], item['size'], indent + 1, max_items=5)

        shown += 1

    if len(items) > max_items:
        prefix = '  ' * indent
        print(f"{prefix}{DIM}... and {len(items) - max_items} more items{RESET}")


def main():
    parser = argparse.ArgumentParser(description='Disk Usage Analyzer')
    parser.add_argument('path', nargs='?', default='.', help='Path to analyze')
    parser.add_argument('--depth', '-d', type=int, default=2, help='Depth of analysis')
    parser.add_argument('--top', '-t', type=int, default=15, help='Top N items to show')
    parser.add_argument('--all', '-a', action='store_true', help='Show all partitions')
    args = parser.parse_args()

    path = os.path.abspath(args.path)

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              💾 Disk Usage Analyzer                        ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Show disk partitions
    partitions = get_disk_info()
    if partitions:
        print(f"  {BOLD}Disk Partitions:{RESET}")
        print(f"  {DIM}{'─' * 60}{RESET}")

        for p in partitions:
            bar = usage_bar(p['percent'], 20)
            print(f"  {CYAN}{p['mount']:<15}{RESET} {bar} {p['percent']:>3}%  {p['used']}/{p['size']}")
        print()

    # Analyze directory
    if not os.path.exists(path):
        print(f"  {RED}Path not found: {path}{RESET}\n")
        return

    print(f"  {BOLD}Analyzing:{RESET} {path}")
    print(f"  {DIM}Scanning... (depth={args.depth}){RESET}\n")

    # Get total size first
    total_size = get_dir_size(path)

    print(f"  {BOLD}Total Size:{RESET} {GREEN}{format_size(total_size)}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}\n")

    # Scan and display
    items = scan_directory(path, args.depth)

    if items:
        print_tree(items, total_size, max_items=args.top)
    else:
        print(f"  {DIM}Empty directory or no accessible files{RESET}")

    # Summary
    print(f"\n  {DIM}{'─' * 60}{RESET}")

    # Count files and dirs
    file_count = sum(1 for item in items if item['type'] == 'file')
    dir_count = sum(1 for item in items if item['type'] == 'dir')

    print(f"  {CYAN}Items:{RESET} {dir_count} directories, {file_count} files")

    # Largest item
    if items:
        largest = items[0]
        print(f"  {CYAN}Largest:{RESET} {largest['name']} ({format_size(largest['size'])})")

    print()


if __name__ == '__main__':
    main()
