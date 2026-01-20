#!/usr/bin/env python3
"""
Duplicate Finder - Find duplicate files by content hash
Usage: duplicate.py [path] [--delete] [--min-size 1024]
"""

import os
import hashlib
import argparse
from collections import defaultdict

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_file_hash(filepath, quick=False):
    """Calculate MD5 hash of file"""
    hasher = hashlib.md5()

    try:
        with open(filepath, 'rb') as f:
            if quick:
                # Just hash first and last 64KB for speed
                hasher.update(f.read(65536))
                f.seek(-65536, 2)
                hasher.update(f.read())
            else:
                # Full file hash
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None


def format_size(size):
    """Format size in human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def scan_files(path, min_size=1, extensions=None):
    """Scan directory for files"""
    files = []

    for root, dirs, filenames in os.walk(path):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for filename in filenames:
            if filename.startswith('.'):
                continue

            filepath = os.path.join(root, filename)

            try:
                size = os.path.getsize(filepath)
                if size < min_size:
                    continue

                if extensions:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in extensions:
                        continue

                files.append({
                    'path': filepath,
                    'name': filename,
                    'size': size
                })
            except:
                continue

    return files


def find_duplicates(files, progress_callback=None):
    """Find duplicate files by hash"""
    # Group by size first (quick filter)
    by_size = defaultdict(list)
    for f in files:
        by_size[f['size']].append(f)

    # Only check files with same size
    potential = []
    for size, group in by_size.items():
        if len(group) > 1:
            potential.extend(group)

    # Hash files
    by_hash = defaultdict(list)
    total = len(potential)

    for i, f in enumerate(potential):
        if progress_callback:
            progress_callback(i + 1, total)

        file_hash = get_file_hash(f['path'])
        if file_hash:
            f['hash'] = file_hash
            by_hash[file_hash].append(f)

    # Find duplicates
    duplicates = []
    for hash_val, group in by_hash.items():
        if len(group) > 1:
            duplicates.append({
                'hash': hash_val,
                'size': group[0]['size'],
                'files': group
            })

    # Sort by total wasted space
    duplicates.sort(key=lambda x: x['size'] * (len(x['files']) - 1), reverse=True)

    return duplicates


def main():
    parser = argparse.ArgumentParser(description='Duplicate Finder')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--min-size', '-m', type=int, default=1024, help='Minimum file size (bytes)')
    parser.add_argument('--extensions', '-e', help='Filter by extensions (comma-separated)')
    parser.add_argument('--delete', '-d', action='store_true', help='Interactive deletion mode')
    parser.add_argument('--auto-delete', action='store_true', help='Auto-delete duplicates (keep oldest)')
    args = parser.parse_args()

    path = os.path.abspath(args.path)
    extensions = None
    if args.extensions:
        extensions = set('.' + e.strip().lstrip('.') for e in args.extensions.split(','))

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔍 Duplicate File Finder                      ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Scanning: {path}{RESET}")
    print(f"  {DIM}Min size: {format_size(args.min_size)}{RESET}")
    if extensions:
        print(f"  {DIM}Extensions: {', '.join(extensions)}{RESET}")
    print()

    # Scan files
    print(f"  {CYAN}Scanning files...{RESET}", end=' ')
    files = scan_files(path, args.min_size, extensions)
    print(f"{GREEN}{len(files)} files found{RESET}")

    if not files:
        print(f"\n  {DIM}No files to analyze{RESET}\n")
        return

    # Find duplicates
    print(f"  {CYAN}Calculating hashes...{RESET}")

    def progress(current, total):
        percent = (current / total) * 100
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = '█' * filled + '░' * (bar_len - filled)
        print(f"\r  {DIM}{bar} {percent:.0f}% ({current}/{total}){RESET}", end='')

    duplicates = find_duplicates(files, progress)
    print()  # New line after progress

    if not duplicates:
        print(f"\n  {GREEN}No duplicates found!{RESET}\n")
        return

    # Calculate stats
    total_wasted = sum(d['size'] * (len(d['files']) - 1) for d in duplicates)
    total_dup_files = sum(len(d['files']) - 1 for d in duplicates)

    print(f"\n  {BOLD}Results:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {YELLOW}Found {len(duplicates)} sets of duplicates{RESET}")
    print(f"  {YELLOW}{total_dup_files} duplicate files wasting {format_size(total_wasted)}{RESET}")
    print()

    # Show duplicates
    for i, dup in enumerate(duplicates[:20]):
        wasted = dup['size'] * (len(dup['files']) - 1)
        print(f"  {BOLD}Set {i+1}:{RESET} {len(dup['files'])} files, {format_size(dup['size'])} each ({RED}-{format_size(wasted)}{RESET})")

        for j, f in enumerate(dup['files']):
            marker = f"{GREEN}[keep]{RESET}" if j == 0 else f"{RED}[dup]{RESET}"
            rel_path = os.path.relpath(f['path'], path)
            print(f"    {marker} {rel_path}")
        print()

    if len(duplicates) > 20:
        print(f"  {DIM}... and {len(duplicates) - 20} more duplicate sets{RESET}\n")

    # Interactive deletion
    if args.delete:
        print(f"\n  {BOLD}Interactive Deletion:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        deleted_count = 0
        deleted_size = 0

        for i, dup in enumerate(duplicates):
            print(f"\n  {BOLD}Set {i+1}/{len(duplicates)}:{RESET} {format_size(dup['size'])} x {len(dup['files'])}")

            for j, f in enumerate(dup['files']):
                print(f"    [{j+1}] {f['name']}")
                print(f"        {DIM}{os.path.dirname(f['path'])}{RESET}")

            choice = input(f"\n  {CYAN}Keep which? (1-{len(dup['files'])}, s=skip, q=quit):{RESET} ").strip().lower()

            if choice == 'q':
                break
            elif choice == 's':
                continue
            elif choice.isdigit():
                keep_idx = int(choice) - 1
                if 0 <= keep_idx < len(dup['files']):
                    for j, f in enumerate(dup['files']):
                        if j != keep_idx:
                            try:
                                os.remove(f['path'])
                                deleted_count += 1
                                deleted_size += f['size']
                                print(f"    {RED}Deleted: {f['name']}{RESET}")
                            except Exception as e:
                                print(f"    {RED}Error: {e}{RESET}")

        print(f"\n  {GREEN}Deleted {deleted_count} files, freed {format_size(deleted_size)}{RESET}")

    elif args.auto_delete:
        print(f"\n  {BOLD}Auto-deleting duplicates (keeping oldest)...{RESET}")

        deleted_count = 0
        deleted_size = 0

        for dup in duplicates:
            # Sort by modification time (keep oldest)
            sorted_files = sorted(dup['files'], key=lambda x: os.path.getmtime(x['path']))

            for f in sorted_files[1:]:  # Skip first (oldest)
                try:
                    os.remove(f['path'])
                    deleted_count += 1
                    deleted_size += f['size']
                except:
                    pass

        print(f"  {GREEN}Deleted {deleted_count} files, freed {format_size(deleted_size)}{RESET}")

    print()


if __name__ == '__main__':
    main()
