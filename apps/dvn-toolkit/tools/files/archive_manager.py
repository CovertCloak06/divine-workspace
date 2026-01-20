#!/usr/bin/env python3
"""
Archive Manager - Create and extract archives
Usage: archive_manager.py [create|extract|list] <file>
"""

import os
import sys
import tarfile
import zipfile
import argparse
import subprocess
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def format_size(size):
    """Format size in human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_archive_type(filepath):
    """Detect archive type"""
    lower = filepath.lower()

    if lower.endswith('.tar.gz') or lower.endswith('.tgz'):
        return 'tar.gz'
    elif lower.endswith('.tar.bz2') or lower.endswith('.tbz2'):
        return 'tar.bz2'
    elif lower.endswith('.tar.xz') or lower.endswith('.txz'):
        return 'tar.xz'
    elif lower.endswith('.tar'):
        return 'tar'
    elif lower.endswith('.zip'):
        return 'zip'
    elif lower.endswith('.7z'):
        return '7z'
    elif lower.endswith('.rar'):
        return 'rar'
    elif lower.endswith('.gz'):
        return 'gz'
    elif lower.endswith('.bz2'):
        return 'bz2'

    return None


def list_tar(filepath, archive_type):
    """List contents of tar archive"""
    mode_map = {
        'tar': 'r',
        'tar.gz': 'r:gz',
        'tar.bz2': 'r:bz2',
        'tar.xz': 'r:xz',
    }

    mode = mode_map.get(archive_type, 'r')
    files = []

    try:
        with tarfile.open(filepath, mode) as tar:
            for member in tar.getmembers():
                files.append({
                    'name': member.name,
                    'size': member.size,
                    'mtime': datetime.fromtimestamp(member.mtime),
                    'isdir': member.isdir(),
                })
    except Exception as e:
        return None, str(e)

    return files, None


def list_zip(filepath):
    """List contents of zip archive"""
    files = []

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for info in zf.infolist():
                files.append({
                    'name': info.filename,
                    'size': info.file_size,
                    'compressed': info.compress_size,
                    'mtime': datetime(*info.date_time),
                    'isdir': info.is_dir(),
                })
    except Exception as e:
        return None, str(e)

    return files, None


def extract_tar(filepath, dest, archive_type):
    """Extract tar archive"""
    mode_map = {
        'tar': 'r',
        'tar.gz': 'r:gz',
        'tar.bz2': 'r:bz2',
        'tar.xz': 'r:xz',
    }

    mode = mode_map.get(archive_type, 'r')

    try:
        with tarfile.open(filepath, mode) as tar:
            tar.extractall(dest)
        return True, None
    except Exception as e:
        return False, str(e)


def extract_zip(filepath, dest):
    """Extract zip archive"""
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            zf.extractall(dest)
        return True, None
    except Exception as e:
        return False, str(e)


def extract_7z(filepath, dest):
    """Extract 7z archive"""
    try:
        result = subprocess.run(['7z', 'x', filepath, f'-o{dest}', '-y'],
                               capture_output=True, text=True)
        return result.returncode == 0, result.stderr
    except FileNotFoundError:
        return False, "7z not installed"


def extract_rar(filepath, dest):
    """Extract rar archive"""
    try:
        result = subprocess.run(['unrar', 'x', filepath, dest],
                               capture_output=True, text=True)
        return result.returncode == 0, result.stderr
    except FileNotFoundError:
        return False, "unrar not installed"


def create_tar(files, output, compression='gz'):
    """Create tar archive"""
    mode_map = {
        'none': 'w',
        'gz': 'w:gz',
        'bz2': 'w:bz2',
        'xz': 'w:xz',
    }

    mode = mode_map.get(compression, 'w:gz')

    try:
        with tarfile.open(output, mode) as tar:
            for f in files:
                tar.add(f, arcname=os.path.basename(f))
        return True, None
    except Exception as e:
        return False, str(e)


def create_zip(files, output):
    """Create zip archive"""
    try:
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                if os.path.isdir(f):
                    for root, dirs, filenames in os.walk(f):
                        for filename in filenames:
                            filepath = os.path.join(root, filename)
                            arcname = os.path.relpath(filepath, os.path.dirname(f))
                            zf.write(filepath, arcname)
                else:
                    zf.write(f, os.path.basename(f))
        return True, None
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description='Archive Manager')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['list', 'extract', 'create', 'info'])
    parser.add_argument('files', nargs='*', help='Archive file or files to archive')
    parser.add_argument('--output', '-o', help='Output file/directory')
    parser.add_argument('--format', '-f', choices=['tar', 'tar.gz', 'tar.bz2', 'tar.xz', 'zip'],
                       default='tar.gz', help='Archive format for create')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📦 Archive Manager                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list' or args.action == 'info':
        if not args.files:
            args.files = [input(f"  {CYAN}Archive file:{RESET} ").strip()]

        filepath = args.files[0]
        if not filepath or not os.path.exists(filepath):
            print(f"  {RED}File not found: {filepath}{RESET}\n")
            return

        archive_type = get_archive_type(filepath)
        if not archive_type:
            print(f"  {RED}Unknown archive type{RESET}\n")
            return

        print(f"  {BOLD}Archive: {GREEN}{os.path.basename(filepath)}{RESET}")
        print(f"  {CYAN}Type:{RESET}   {archive_type}")
        print(f"  {CYAN}Size:{RESET}   {format_size(os.path.getsize(filepath))}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        # List contents
        if archive_type.startswith('tar'):
            files, error = list_tar(filepath, archive_type)
        elif archive_type == 'zip':
            files, error = list_zip(filepath)
        else:
            print(f"  {YELLOW}Cannot list contents of {archive_type} files{RESET}")
            print(f"  {DIM}Use extract to view contents{RESET}\n")
            return

        if error:
            print(f"  {RED}Error: {error}{RESET}\n")
            return

        print(f"  {BOLD}Contents ({len(files)} items):{RESET}\n")

        total_size = 0
        for f in files[:50]:
            if f['isdir']:
                print(f"  {CYAN}📁 {f['name']}/{RESET}")
            else:
                size = format_size(f['size'])
                print(f"  📄 {f['name']:<40} {DIM}{size:>10}{RESET}")
                total_size += f['size']

        if len(files) > 50:
            print(f"\n  {DIM}... and {len(files) - 50} more files{RESET}")

        print(f"\n  {DIM}Total uncompressed: {format_size(total_size)}{RESET}\n")

    elif args.action == 'extract':
        if not args.files:
            args.files = [input(f"  {CYAN}Archive file:{RESET} ").strip()]

        filepath = args.files[0]
        if not filepath or not os.path.exists(filepath):
            print(f"  {RED}File not found: {filepath}{RESET}\n")
            return

        archive_type = get_archive_type(filepath)
        if not archive_type:
            print(f"  {RED}Unknown archive type{RESET}\n")
            return

        dest = args.output or '.'
        os.makedirs(dest, exist_ok=True)

        print(f"  {YELLOW}Extracting {os.path.basename(filepath)}...{RESET}")

        if archive_type.startswith('tar'):
            success, error = extract_tar(filepath, dest, archive_type)
        elif archive_type == 'zip':
            success, error = extract_zip(filepath, dest)
        elif archive_type == '7z':
            success, error = extract_7z(filepath, dest)
        elif archive_type == 'rar':
            success, error = extract_rar(filepath, dest)
        else:
            print(f"  {RED}Cannot extract {archive_type} files{RESET}\n")
            return

        if success:
            print(f"  {GREEN}✓ Extracted to: {dest}{RESET}\n")
        else:
            print(f"  {RED}✗ Failed: {error}{RESET}\n")

    elif args.action == 'create':
        if not args.files:
            print(f"  {BOLD}Create Archive:{RESET}")
            print(f"  {DIM}Enter files/directories to archive (empty line to finish){RESET}\n")

            while True:
                path = input(f"  {CYAN}Path:{RESET} ").strip()
                if not path:
                    break
                if os.path.exists(path):
                    args.files.append(path)
                else:
                    print(f"  {RED}Not found: {path}{RESET}")

        if not args.files:
            print(f"  {RED}No files to archive{RESET}\n")
            return

        # Determine output name
        if not args.output:
            base = os.path.basename(args.files[0])
            if len(args.files) > 1:
                base = 'archive'
            ext_map = {
                'tar': '.tar',
                'tar.gz': '.tar.gz',
                'tar.bz2': '.tar.bz2',
                'tar.xz': '.tar.xz',
                'zip': '.zip',
            }
            args.output = base + ext_map.get(args.format, '.tar.gz')

        print(f"  {BOLD}Creating archive:{RESET}")
        print(f"  {CYAN}Output:{RESET} {args.output}")
        print(f"  {CYAN}Format:{RESET} {args.format}")
        print(f"  {CYAN}Files:{RESET}  {len(args.files)}")
        print()

        print(f"  {YELLOW}Compressing...{RESET}")

        if args.format.startswith('tar'):
            compression = args.format.replace('tar.', '') if '.' in args.format else 'none'
            success, error = create_tar(args.files, args.output, compression)
        elif args.format == 'zip':
            success, error = create_zip(args.files, args.output)
        else:
            print(f"  {RED}Unsupported format{RESET}\n")
            return

        if success:
            size = format_size(os.path.getsize(args.output))
            print(f"  {GREEN}✓ Created: {args.output} ({size}){RESET}\n")
        else:
            print(f"  {RED}✗ Failed: {error}{RESET}\n")


if __name__ == '__main__':
    main()
