#!/usr/bin/env python3
"""
File Organizer - Sort files into folders by type, date, or name pattern
Usage: fileorg <path> [--by type|date|ext] [--dry-run] [--recursive]
"""

import argparse
import os
import shutil
from datetime import datetime
from pathlib import Path
from collections import defaultdict

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

# File type categories
FILE_TYPES = {
    'Images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', '.tiff', '.raw', '.heic'},
    'Videos': {'.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpeg'},
    'Audio': {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus'},
    'Documents': {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx', '.csv'},
    'Archives': {'.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz', '.tar.gz', '.tgz'},
    'Code': {'.py', '.js', '.ts', '.html', '.css', '.java', '.c', '.cpp', '.h', '.go', '.rs', '.rb', '.php', '.sh', '.json', '.xml', '.yaml', '.yml', '.sql', '.md'},
    'Executables': {'.exe', '.msi', '.dmg', '.app', '.deb', '.rpm', '.apk', '.bin'},
    'Fonts': {'.ttf', '.otf', '.woff', '.woff2', '.eot'},
    'Data': {'.db', '.sqlite', '.json', '.xml', '.csv', '.parquet', '.pkl'},
}

def get_file_type(ext):
    """Get category for file extension"""
    ext = ext.lower()
    for category, extensions in FILE_TYPES.items():
        if ext in extensions:
            return category
    return 'Other'

def get_date_folder(filepath, granularity='month'):
    """Get date-based folder name"""
    try:
        mtime = os.path.getmtime(filepath)
        dt = datetime.fromtimestamp(mtime)
        if granularity == 'year':
            return dt.strftime('%Y')
        elif granularity == 'month':
            return dt.strftime('%Y-%m')
        else:
            return dt.strftime('%Y-%m-%d')
    except:
        return 'Unknown-Date'

def organize_files(source, organize_by='type', dry_run=False, recursive=False, date_granularity='month'):
    """Organize files into folders"""
    source = Path(source)
    if not source.exists():
        print(f"{RED}Error: Path does not exist{RESET}")
        return

    # Collect files
    if recursive:
        files = [f for f in source.rglob('*') if f.is_file()]
    else:
        files = [f for f in source.iterdir() if f.is_file()]

    if not files:
        print("No files found to organize.")
        return

    # Plan moves
    moves = defaultdict(list)

    for filepath in files:
        ext = filepath.suffix.lower()

        if organize_by == 'type':
            folder = get_file_type(ext)
        elif organize_by == 'ext':
            folder = ext[1:].upper() if ext else 'No-Extension'
        elif organize_by == 'date':
            folder = get_date_folder(filepath, date_granularity)
        else:
            folder = 'Other'

        moves[folder].append(filepath)

    # Summary
    print(f"\n{BOLD}{CYAN}File Organization Plan{RESET}")
    print(f"Source: {source}")
    print(f"Organize by: {organize_by}")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"\n{BOLD}Files to organize: {len(files)}{RESET}\n")

    total_moved = 0

    for folder, file_list in sorted(moves.items()):
        dest_dir = source / folder

        print(f"{CYAN}{folder}/{RESET} ({len(file_list)} files)")

        if not dry_run and not dest_dir.exists():
            dest_dir.mkdir(parents=True)

        for filepath in file_list:
            dest_path = dest_dir / filepath.name

            # Handle name conflicts
            if dest_path.exists() and dest_path != filepath:
                base = dest_path.stem
                suffix = dest_path.suffix
                counter = 1
                while dest_path.exists():
                    dest_path = dest_dir / f"{base}_{counter}{suffix}"
                    counter += 1

            if filepath.parent == dest_dir:
                # Already in correct folder
                continue

            rel_path = filepath.relative_to(source) if recursive else filepath.name
            print(f"  {GREEN}→{RESET} {rel_path}")

            if not dry_run:
                try:
                    shutil.move(str(filepath), str(dest_path))
                    total_moved += 1
                except Exception as e:
                    print(f"    {RED}Error: {e}{RESET}")
            else:
                total_moved += 1

    print(f"\n{BOLD}{'Would move' if dry_run else 'Moved'}: {total_moved} files{RESET}")

    if dry_run:
        print(f"\n{YELLOW}This was a dry run. Use without --dry-run to actually move files.{RESET}")

def main():
    parser = argparse.ArgumentParser(description='File Organizer')
    parser.add_argument('path', default='.', nargs='?', help='Directory to organize')
    parser.add_argument('--by', '-b', choices=['type', 'ext', 'date'], default='type', help='Organize by')
    parser.add_argument('--dry-run', '-n', action='store_true', help='Show what would be done')
    parser.add_argument('--recursive', '-r', action='store_true', help='Include subdirectories')
    parser.add_argument('--date-format', '-d', choices=['year', 'month', 'day'], default='month', help='Date folder granularity')
    args = parser.parse_args()

    organize_files(
        args.path,
        organize_by=args.by,
        dry_run=args.dry_run,
        recursive=args.recursive,
        date_granularity=args.date_format
    )

if __name__ == '__main__':
    main()
