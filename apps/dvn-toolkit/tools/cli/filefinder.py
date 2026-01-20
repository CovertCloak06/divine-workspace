#!/usr/bin/env python3
"""
Duplicate File Finder - Find duplicate files by content hash
Usage: filefinder <path> [--delete] [--size-only] [--min-size 1MB]
"""

import argparse
import hashlib
import os
from collections import defaultdict
from pathlib import Path

def human_size(size):
    """Convert bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"

def parse_size(size_str):
    """Parse size string like '1MB' to bytes"""
    units = {'B': 1, 'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
    size_str = size_str.upper().strip()
    for unit, mult in units.items():
        if size_str.endswith(unit):
            return int(float(size_str[:-len(unit)]) * mult)
    return int(size_str)

def file_hash(filepath, quick=False):
    """Get file hash (MD5 for speed)"""
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            if quick:
                # Only hash first/last 8KB for speed
                hasher.update(f.read(8192))
                f.seek(-8192, 2)
                hasher.update(f.read(8192))
            else:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def find_duplicates(path, min_size=0, size_only=False):
    """Find duplicate files"""
    # Group by size first
    size_groups = defaultdict(list)

    print(f"Scanning {path}...")
    file_count = 0

    for root, _, files in os.walk(path):
        for name in files:
            filepath = Path(root) / name
            try:
                size = filepath.stat().st_size
                if size >= min_size:
                    size_groups[size].append(filepath)
                    file_count += 1
            except:
                pass

    print(f"Scanned {file_count} files")

    # Find groups with potential duplicates
    potential = {s: files for s, files in size_groups.items() if len(files) > 1}
    print(f"Found {len(potential)} size groups with potential duplicates")

    if size_only:
        return {s: [(f, None) for f in files] for s, files in potential.items()}

    # Hash files in same-size groups
    duplicates = {}
    for size, files in potential.items():
        hash_groups = defaultdict(list)
        for f in files:
            h = file_hash(f)
            if h:
                hash_groups[h].append(f)

        for h, flist in hash_groups.items():
            if len(flist) > 1:
                duplicates[h] = (size, flist)

    return duplicates

def main():
    parser = argparse.ArgumentParser(description='Find duplicate files')
    parser.add_argument('path', default='.', nargs='?', help='Directory to scan')
    parser.add_argument('--delete', '-d', action='store_true', help='Interactively delete duplicates')
    parser.add_argument('--size-only', '-s', action='store_true', help='Match by size only (faster)')
    parser.add_argument('--min-size', '-m', default='0', help='Minimum file size (e.g., 1MB)')
    args = parser.parse_args()

    min_size = parse_size(args.min_size)
    duplicates = find_duplicates(args.path, min_size, args.size_only)

    if not duplicates:
        print("\nNo duplicates found!")
        return

    total_waste = 0
    dup_count = 0

    print(f"\n{'='*60}")
    print("DUPLICATE FILES FOUND")
    print(f"{'='*60}\n")

    for key, data in duplicates.items():
        if args.size_only:
            size = key
            files = [f for f, _ in data]
        else:
            size, files = data

        waste = size * (len(files) - 1)
        total_waste += waste
        dup_count += len(files) - 1

        print(f"Size: {human_size(size)} | Copies: {len(files)} | Wasted: {human_size(waste)}")
        for i, f in enumerate(files):
            marker = "[KEEP]" if i == 0 else "[DUP] "
            print(f"  {marker} {f}")

        if args.delete and len(files) > 1:
            resp = input("  Delete duplicates? [y/N/q]: ").lower()
            if resp == 'q':
                break
            if resp == 'y':
                for f in files[1:]:
                    try:
                        f.unlink()
                        print(f"    Deleted: {f}")
                    except Exception as e:
                        print(f"    Error: {e}")
        print()

    print(f"{'='*60}")
    print(f"Total: {dup_count} duplicate files | Wasted space: {human_size(total_waste)}")

if __name__ == '__main__':
    main()
