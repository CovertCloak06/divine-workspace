#!/usr/bin/env python3
"""
Backup Tool - Simple backup and restore utility
Usage: backup_tool.py [backup|restore|list] <path>
"""

import os
import sys
import json
import shutil
import tarfile
import hashlib
import argparse
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

BACKUP_DIR = os.path.expanduser('~/.dvn_backups')
MANIFEST_FILE = os.path.join(BACKUP_DIR, 'manifest.json')


def ensure_backup_dir():
    """Ensure backup directory exists"""
    os.makedirs(BACKUP_DIR, exist_ok=True)


def load_manifest():
    """Load backup manifest"""
    if os.path.exists(MANIFEST_FILE):
        try:
            with open(MANIFEST_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'backups': []}


def save_manifest(manifest):
    """Save backup manifest"""
    with open(MANIFEST_FILE, 'w') as f:
        json.dump(manifest, f, indent=2)


def calculate_hash(filepath):
    """Calculate file hash"""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hasher.update(chunk)
    return hasher.hexdigest()[:12]


def get_dir_size(path):
    """Get directory size"""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total += os.path.getsize(fp)
    return total


def format_size(size):
    """Format size in human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def create_backup(source_path, name=None, compress=True):
    """Create a backup of file or directory"""
    ensure_backup_dir()

    if not os.path.exists(source_path):
        return False, f"Path not found: {source_path}"

    source_path = os.path.abspath(source_path)
    basename = os.path.basename(source_path.rstrip('/'))
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = name or f"{basename}_{timestamp}"

    ext = '.tar.gz' if compress else '.tar'
    backup_file = os.path.join(BACKUP_DIR, f"{backup_name}{ext}")

    # Create tarball
    mode = 'w:gz' if compress else 'w'
    try:
        with tarfile.open(backup_file, mode) as tar:
            tar.add(source_path, arcname=basename)
    except Exception as e:
        return False, str(e)

    # Update manifest
    manifest = load_manifest()
    backup_info = {
        'id': timestamp,
        'name': backup_name,
        'source': source_path,
        'file': backup_file,
        'created': datetime.now().isoformat(),
        'size': os.path.getsize(backup_file),
        'hash': calculate_hash(backup_file),
        'compressed': compress,
    }
    manifest['backups'].append(backup_info)
    save_manifest(manifest)

    return True, backup_info


def restore_backup(backup_id, dest_path=None):
    """Restore a backup"""
    manifest = load_manifest()

    # Find backup
    backup = None
    for b in manifest['backups']:
        if b['id'] == backup_id or b['name'] == backup_id:
            backup = b
            break

    if not backup:
        return False, f"Backup not found: {backup_id}"

    if not os.path.exists(backup['file']):
        return False, f"Backup file missing: {backup['file']}"

    # Determine destination
    if not dest_path:
        dest_path = os.path.dirname(backup['source'])

    try:
        mode = 'r:gz' if backup.get('compressed', True) else 'r'
        with tarfile.open(backup['file'], mode) as tar:
            tar.extractall(dest_path)
    except Exception as e:
        return False, str(e)

    return True, dest_path


def list_backups():
    """List all backups"""
    manifest = load_manifest()
    return manifest.get('backups', [])


def delete_backup(backup_id):
    """Delete a backup"""
    manifest = load_manifest()

    for i, b in enumerate(manifest['backups']):
        if b['id'] == backup_id or b['name'] == backup_id:
            # Delete file
            if os.path.exists(b['file']):
                os.remove(b['file'])

            # Remove from manifest
            manifest['backups'].pop(i)
            save_manifest(manifest)
            return True

    return False


def main():
    parser = argparse.ArgumentParser(description='Backup Tool')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['backup', 'restore', 'list', 'delete', 'info'])
    parser.add_argument('path', nargs='?', help='Path to backup/restore or backup ID')
    parser.add_argument('--name', '-n', help='Backup name')
    parser.add_argument('--dest', '-d', help='Restore destination')
    parser.add_argument('--no-compress', action='store_true', help='Disable compression')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              💾 Backup Tool                                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list':
        backups = list_backups()

        if not backups:
            print(f"  {DIM}No backups found{RESET}")
            print(f"  {DIM}Backup directory: {BACKUP_DIR}{RESET}\n")
            return

        print(f"  {BOLD}Backups ({len(backups)}):{RESET}")
        print(f"  {DIM}{'─' * 55}{RESET}\n")

        total_size = 0
        for b in backups:
            created = datetime.fromisoformat(b['created']).strftime('%Y-%m-%d %H:%M')
            size = format_size(b['size'])
            total_size += b['size']

            print(f"  {GREEN}{b['name']}{RESET}")
            print(f"     {CYAN}ID:{RESET}      {b['id']}")
            print(f"     {CYAN}Source:{RESET}  {b['source']}")
            print(f"     {CYAN}Created:{RESET} {created}")
            print(f"     {CYAN}Size:{RESET}    {size}")
            print()

        print(f"  {DIM}Total: {format_size(total_size)}{RESET}")
        print(f"  {DIM}Location: {BACKUP_DIR}{RESET}\n")

    elif args.action == 'backup':
        if not args.path:
            args.path = input(f"  {CYAN}Path to backup:{RESET} ").strip()

        if not args.path:
            print(f"  {RED}Path required{RESET}\n")
            return

        # Show what will be backed up
        path = os.path.abspath(args.path)
        if os.path.isdir(path):
            size = get_dir_size(path)
            print(f"  {BOLD}Creating backup:{RESET}")
            print(f"  {DIM}{'─' * 40}{RESET}")
            print(f"  {CYAN}Source:{RESET} {path}")
            print(f"  {CYAN}Size:{RESET}   {format_size(size)}")
            print()
        elif os.path.isfile(path):
            size = os.path.getsize(path)
            print(f"  {BOLD}Creating backup:{RESET}")
            print(f"  {DIM}{'─' * 40}{RESET}")
            print(f"  {CYAN}File:{RESET} {path}")
            print(f"  {CYAN}Size:{RESET} {format_size(size)}")
            print()

        print(f"  {YELLOW}Backing up...{RESET}")
        success, result = create_backup(args.path, args.name, not args.no_compress)

        if success:
            print(f"  {GREEN}✓ Backup created successfully{RESET}")
            print(f"\n  {CYAN}Name:{RESET} {result['name']}")
            print(f"  {CYAN}ID:{RESET}   {result['id']}")
            print(f"  {CYAN}Size:{RESET} {format_size(result['size'])}")
            print(f"  {CYAN}File:{RESET} {result['file']}")
        else:
            print(f"  {RED}✗ Backup failed: {result}{RESET}")

        print()

    elif args.action == 'restore':
        if not args.path:
            backups = list_backups()
            if not backups:
                print(f"  {DIM}No backups available{RESET}\n")
                return

            print(f"  {BOLD}Select backup to restore:{RESET}\n")
            for i, b in enumerate(backups, 1):
                print(f"  {CYAN}{i}.{RESET} {b['name']}")

            choice = input(f"\n  {CYAN}Number or ID:{RESET} ").strip()

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(backups):
                    args.path = backups[idx]['id']
                else:
                    print(f"  {RED}Invalid selection{RESET}\n")
                    return
            except ValueError:
                args.path = choice

        if not args.path:
            print(f"  {RED}Backup ID required{RESET}\n")
            return

        print(f"  {YELLOW}Restoring...{RESET}")
        success, result = restore_backup(args.path, args.dest)

        if success:
            print(f"  {GREEN}✓ Restored to: {result}{RESET}\n")
        else:
            print(f"  {RED}✗ Restore failed: {result}{RESET}\n")

    elif args.action == 'delete':
        if not args.path:
            args.path = input(f"  {CYAN}Backup ID to delete:{RESET} ").strip()

        if not args.path:
            print(f"  {RED}Backup ID required{RESET}\n")
            return

        if delete_backup(args.path):
            print(f"  {GREEN}✓ Backup deleted{RESET}\n")
        else:
            print(f"  {RED}Backup not found: {args.path}{RESET}\n")

    elif args.action == 'info':
        backups = list_backups()
        total_size = sum(b['size'] for b in backups)

        print(f"  {BOLD}Backup Info:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")
        print(f"  {CYAN}Total backups:{RESET}  {len(backups)}")
        print(f"  {CYAN}Total size:{RESET}     {format_size(total_size)}")
        print(f"  {CYAN}Backup dir:{RESET}     {BACKUP_DIR}")
        print()


if __name__ == '__main__':
    main()
