#!/usr/bin/env python3
"""
Bulk Renamer - Rename multiple files with patterns
Usage: bulk_rename.py <pattern> [--replace new] [--prefix str] [--suffix str]
"""

import os
import re
import argparse
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_files(directory, pattern=None, recursive=False):
    """Get files matching pattern"""
    files = []

    if recursive:
        for root, _, filenames in os.walk(directory):
            for f in filenames:
                filepath = os.path.join(root, f)
                if pattern is None or re.search(pattern, f):
                    files.append(filepath)
    else:
        for f in os.listdir(directory):
            filepath = os.path.join(directory, f)
            if os.path.isfile(filepath):
                if pattern is None or re.search(pattern, f):
                    files.append(filepath)

    return sorted(files)


def generate_new_name(filepath, args, index):
    """Generate new filename based on options"""
    directory = os.path.dirname(filepath)
    filename = os.path.basename(filepath)
    name, ext = os.path.splitext(filename)

    new_name = name

    # Search and replace
    if args.find and args.replace is not None:
        if args.regex:
            new_name = re.sub(args.find, args.replace, new_name)
        else:
            new_name = new_name.replace(args.find, args.replace)

    # Case changes
    if args.lower:
        new_name = new_name.lower()
    elif args.upper:
        new_name = new_name.upper()
    elif args.title:
        new_name = new_name.title()

    # Remove characters
    if args.remove:
        for char in args.remove:
            new_name = new_name.replace(char, '')

    # Replace spaces
    if args.spaces:
        new_name = new_name.replace(' ', args.spaces)

    # Add prefix/suffix
    if args.prefix:
        new_name = args.prefix + new_name
    if args.suffix:
        new_name = new_name + args.suffix

    # Numbering
    if args.number:
        new_name = f"{index:0{args.number_pad}d}_{new_name}"
    if args.number_only:
        new_name = f"{index:0{args.number_pad}d}"

    # Date prefix
    if args.date:
        date_str = datetime.now().strftime(args.date_format)
        new_name = f"{date_str}_{new_name}"

    # Extension changes
    new_ext = ext
    if args.ext:
        new_ext = '.' + args.ext.lstrip('.')
    if args.lower_ext:
        new_ext = new_ext.lower()

    return os.path.join(directory, new_name + new_ext)


def main():
    parser = argparse.ArgumentParser(description='Bulk File Renamer')
    parser.add_argument('files', nargs='*', help='Files to rename (or use --dir)')
    parser.add_argument('--dir', '-d', default='.', help='Directory to process')
    parser.add_argument('--pattern', '-p', help='Filter files by regex pattern')
    parser.add_argument('--recursive', '-r', action='store_true', help='Process subdirectories')

    # Rename operations
    parser.add_argument('--find', '-f', help='Text to find')
    parser.add_argument('--replace', help='Text to replace with')
    parser.add_argument('--regex', action='store_true', help='Use regex for find/replace')

    parser.add_argument('--prefix', help='Add prefix to filename')
    parser.add_argument('--suffix', help='Add suffix to filename')

    parser.add_argument('--lower', action='store_true', help='Convert to lowercase')
    parser.add_argument('--upper', action='store_true', help='Convert to uppercase')
    parser.add_argument('--title', action='store_true', help='Convert to title case')

    parser.add_argument('--remove', help='Characters to remove')
    parser.add_argument('--spaces', help='Replace spaces with character')

    parser.add_argument('--number', '-n', action='store_true', help='Add number prefix')
    parser.add_argument('--number-only', action='store_true', help='Replace name with number')
    parser.add_argument('--number-pad', type=int, default=3, help='Number padding (default: 3)')

    parser.add_argument('--date', action='store_true', help='Add date prefix')
    parser.add_argument('--date-format', default='%Y%m%d', help='Date format (default: %%Y%%m%%d)')

    parser.add_argument('--ext', '-e', help='Change extension')
    parser.add_argument('--lower-ext', action='store_true', help='Lowercase extension')

    parser.add_argument('--dry-run', action='store_true', help='Preview without renaming')
    parser.add_argument('--yes', '-y', action='store_true', help='Skip confirmation')

    args = parser.parse_args()

    # Get files to process
    if args.files:
        files = [f for f in args.files if os.path.isfile(f)]
    else:
        files = get_files(args.dir, args.pattern, args.recursive)

    if not files:
        print(f"\n{RED}No files found to rename{RESET}")
        print(f"{DIM}Use --pattern to filter, or specify files directly{RESET}\n")
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📁 Bulk File Renamer                          ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Found {len(files)} files{RESET}\n")

    # Generate new names
    renames = []
    for i, filepath in enumerate(files, 1):
        new_path = generate_new_name(filepath, args, i)
        if filepath != new_path:
            renames.append((filepath, new_path))

    if not renames:
        print(f"  {YELLOW}No changes needed{RESET}\n")
        return

    # Preview changes
    print(f"  {BOLD}Planned renames:{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")

    for old, new in renames:
        old_name = os.path.basename(old)
        new_name = os.path.basename(new)
        print(f"  {DIM}{old_name}{RESET}")
        print(f"  {GREEN}  → {new_name}{RESET}")
        print()

    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {BOLD}Total: {len(renames)} files to rename{RESET}")

    if args.dry_run:
        print(f"\n  {YELLOW}Dry run - no changes made{RESET}\n")
        return

    # Confirm
    if not args.yes:
        confirm = input(f"\n  {CYAN}Proceed with rename? (y/n):{RESET} ").strip().lower()
        if confirm != 'y':
            print(f"  {YELLOW}Cancelled{RESET}\n")
            return

    # Execute renames
    print(f"\n  {BOLD}Renaming...{RESET}")
    success = 0
    errors = []

    for old, new in renames:
        try:
            # Check if target exists
            if os.path.exists(new):
                errors.append((old, "Target already exists"))
                continue

            os.rename(old, new)
            success += 1
            print(f"  {GREEN}✓{RESET} {os.path.basename(old)} → {os.path.basename(new)}")

        except Exception as e:
            errors.append((old, str(e)))
            print(f"  {RED}✗{RESET} {os.path.basename(old)}: {e}")

    print(f"\n  {GREEN}Renamed: {success}{RESET}")
    if errors:
        print(f"  {RED}Errors: {len(errors)}{RESET}")

    print()


if __name__ == '__main__':
    main()
