#!/usr/bin/env python3
"""
Secure File Shredder - Permanently delete files beyond recovery
Usage: shred.py <file> [--passes 3]
"""

import os
import sys
import argparse
import secrets

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def shred_file(filepath, passes=3, verbose=True):
    """Securely overwrite and delete a file"""
    if not os.path.exists(filepath):
        return False, "File not found"

    if not os.path.isfile(filepath):
        return False, "Not a regular file"

    try:
        file_size = os.path.getsize(filepath)

        if verbose:
            print(f"  {DIM}File size: {file_size:,} bytes{RESET}")

        # Open file for overwriting
        with open(filepath, 'r+b') as f:
            for pass_num in range(passes):
                if verbose:
                    pattern_type = ['zeros', 'ones', 'random'][pass_num % 3]
                    print(f"  Pass {pass_num + 1}/{passes}: Writing {pattern_type}...", end=' ')
                    sys.stdout.flush()

                f.seek(0)

                # Different patterns for each pass
                if pass_num % 3 == 0:
                    # Write zeros
                    chunk_size = 65536
                    written = 0
                    while written < file_size:
                        to_write = min(chunk_size, file_size - written)
                        f.write(b'\x00' * to_write)
                        written += to_write
                elif pass_num % 3 == 1:
                    # Write ones (0xFF)
                    chunk_size = 65536
                    written = 0
                    while written < file_size:
                        to_write = min(chunk_size, file_size - written)
                        f.write(b'\xff' * to_write)
                        written += to_write
                else:
                    # Write random data
                    chunk_size = 65536
                    written = 0
                    while written < file_size:
                        to_write = min(chunk_size, file_size - written)
                        f.write(secrets.token_bytes(to_write))
                        written += to_write

                # Ensure data is written to disk
                f.flush()
                os.fsync(f.fileno())

                if verbose:
                    print(f"{GREEN}done{RESET}")

        # Truncate to zero size
        with open(filepath, 'w') as f:
            pass

        # Rename file multiple times to obscure original name
        directory = os.path.dirname(filepath) or '.'
        current_path = filepath

        for i in range(3):
            new_name = secrets.token_hex(16)
            new_path = os.path.join(directory, new_name)
            os.rename(current_path, new_path)
            current_path = new_path

        # Finally delete
        os.remove(current_path)

        return True, None

    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, str(e)


def shred_directory(dirpath, passes=3, verbose=True):
    """Recursively shred all files in directory"""
    if not os.path.isdir(dirpath):
        return False, "Not a directory"

    files_shredded = 0
    errors = []

    for root, dirs, files in os.walk(dirpath, topdown=False):
        for name in files:
            filepath = os.path.join(root, name)
            if verbose:
                print(f"\n  {CYAN}Shredding:{RESET} {name}")

            success, error = shred_file(filepath, passes, verbose)
            if success:
                files_shredded += 1
            else:
                errors.append((filepath, error))

        # Remove empty directories
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except:
                pass

    # Remove the top directory
    try:
        os.rmdir(dirpath)
    except:
        pass

    return files_shredded, errors


def main():
    parser = argparse.ArgumentParser(description='Secure File Shredder')
    parser.add_argument('files', nargs='+', help='Files or directories to shred')
    parser.add_argument('--passes', '-p', type=int, default=3, help='Number of overwrite passes (default: 3)')
    parser.add_argument('--recursive', '-r', action='store_true', help='Recursively shred directories')
    parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔥 Secure File Shredder                       ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Confirm
    if not args.force:
        print(f"  {RED}WARNING: This will PERMANENTLY destroy:{RESET}")
        for f in args.files:
            print(f"    • {f}")
        print(f"\n  {YELLOW}Files cannot be recovered after shredding!{RESET}")

        confirm = input(f"\n  {CYAN}Type 'yes' to confirm:{RESET} ").strip().lower()
        if confirm != 'yes':
            print(f"\n  {DIM}Aborted{RESET}\n")
            return

    print(f"\n  {DIM}Overwrite passes: {args.passes}{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")

    total_shredded = 0
    total_errors = []

    for target in args.files:
        if not os.path.exists(target):
            print(f"\n  {RED}Not found: {target}{RESET}")
            continue

        if os.path.isdir(target):
            if not args.recursive:
                print(f"\n  {YELLOW}Skipping directory: {target} (use -r for recursive){RESET}")
                continue

            print(f"\n  {BOLD}Shredding directory:{RESET} {target}")
            count, errors = shred_directory(target, args.passes, not args.quiet)
            total_shredded += count
            total_errors.extend(errors)

            if not args.quiet:
                print(f"  {GREEN}Shredded {count} files{RESET}")
        else:
            if not args.quiet:
                print(f"\n  {BOLD}Shredding:{RESET} {target}")

            success, error = shred_file(target, args.passes, not args.quiet)

            if success:
                total_shredded += 1
                if not args.quiet:
                    print(f"  {GREEN}✓ File securely destroyed{RESET}")
            else:
                total_errors.append((target, error))
                print(f"  {RED}✗ Failed: {error}{RESET}")

    # Summary
    print(f"\n  {DIM}{'─' * 40}{RESET}")
    print(f"  {BOLD}Summary:{RESET}")
    print(f"  {GREEN}✓ {total_shredded} file(s) securely destroyed{RESET}")

    if total_errors:
        print(f"  {RED}✗ {len(total_errors)} error(s):{RESET}")
        for path, error in total_errors[:5]:
            print(f"    • {path}: {error}")

    print()


if __name__ == '__main__':
    main()
