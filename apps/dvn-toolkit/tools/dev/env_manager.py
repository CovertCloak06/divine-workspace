#!/usr/bin/env python3
"""
Environment Manager - Manage .env files and environment variables
Usage: env_manager.py [show|set|get|export]
"""

import os
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def parse_env_file(filepath):
    """Parse .env file"""
    env_vars = {}

    if not os.path.exists(filepath):
        return env_vars

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse KEY=value
            match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
            if match:
                key = match.group(1)
                value = match.group(2)

                # Remove quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]

                env_vars[key] = value

    return env_vars


def write_env_file(filepath, env_vars, comments=None):
    """Write .env file"""
    with open(filepath, 'w') as f:
        if comments:
            for comment in comments:
                f.write(f"# {comment}\n")
            f.write("\n")

        for key, value in sorted(env_vars.items()):
            # Quote if contains spaces or special chars
            if ' ' in value or '\n' in value or '"' in value:
                value = f'"{value}"'
            f.write(f"{key}={value}\n")


def mask_value(value, show_length=4):
    """Mask sensitive value"""
    if len(value) <= show_length:
        return '*' * len(value)
    return value[:show_length] + '*' * (len(value) - show_length)


def is_sensitive(key):
    """Check if key is likely sensitive"""
    sensitive_patterns = [
        'password', 'secret', 'key', 'token', 'api', 'auth',
        'credential', 'private', 'access', 'jwt', 'bearer'
    ]
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in sensitive_patterns)


def find_env_files(directory='.'):
    """Find all .env files"""
    files = []
    for item in os.listdir(directory):
        if item == '.env' or item.startswith('.env.'):
            filepath = os.path.join(directory, item)
            if os.path.isfile(filepath):
                files.append(filepath)
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description='Environment Manager')
    parser.add_argument('action', nargs='?', default='show',
                        choices=['show', 'set', 'get', 'delete', 'export', 'diff', 'create'],
                        help='Action to perform')
    parser.add_argument('args', nargs='*', help='Arguments (KEY=value for set, KEY for get)')
    parser.add_argument('--file', '-f', default='.env', help='Environment file')
    parser.add_argument('--reveal', '-r', action='store_true', help='Show sensitive values')
    parser.add_argument('--all', '-a', action='store_true', help='Show all env files')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔐 Environment Manager                        ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'show':
        if args.all:
            # Show all env files
            files = find_env_files()
            if not files:
                print(f"  {DIM}No .env files found{RESET}\n")
                return

            for filepath in files:
                env_vars = parse_env_file(filepath)
                print(f"  {BOLD}{filepath}{RESET} ({len(env_vars)} vars)")

                for key, value in sorted(env_vars.items()):
                    if is_sensitive(key) and not args.reveal:
                        value = mask_value(value)
                    print(f"    {CYAN}{key}{RESET}={value}")
                print()
        else:
            # Show single file
            env_vars = parse_env_file(args.file)

            if not os.path.exists(args.file):
                print(f"  {YELLOW}File not found: {args.file}{RESET}")
                print(f"  {DIM}Use 'create' to create a new .env file{RESET}\n")
                return

            print(f"  {BOLD}File:{RESET} {args.file}")
            print(f"  {BOLD}Variables:{RESET} {len(env_vars)}")
            print(f"  {DIM}{'─' * 50}{RESET}\n")

            for key, value in sorted(env_vars.items()):
                sensitive = is_sensitive(key)
                if sensitive and not args.reveal:
                    display_value = mask_value(value)
                    print(f"  {CYAN}{key}{RESET}={display_value} {YELLOW}(sensitive){RESET}")
                else:
                    print(f"  {CYAN}{key}{RESET}={value}")

            if not args.reveal:
                sensitive_count = sum(1 for k in env_vars if is_sensitive(k))
                if sensitive_count > 0:
                    print(f"\n  {DIM}Use --reveal to show {sensitive_count} sensitive value(s){RESET}")

    elif args.action == 'set':
        if not args.args:
            print(f"  {RED}Usage: env_manager.py set KEY=value{RESET}\n")
            return

        env_vars = parse_env_file(args.file)

        for arg in args.args:
            if '=' in arg:
                key, value = arg.split('=', 1)
                env_vars[key] = value
                print(f"  {GREEN}Set {key}{RESET}")
            else:
                print(f"  {RED}Invalid format: {arg} (use KEY=value){RESET}")

        write_env_file(args.file, env_vars)
        print(f"\n  {GREEN}Saved to {args.file}{RESET}")

    elif args.action == 'get':
        if not args.args:
            print(f"  {RED}Usage: env_manager.py get KEY{RESET}\n")
            return

        env_vars = parse_env_file(args.file)

        for key in args.args:
            if key in env_vars:
                value = env_vars[key]
                if is_sensitive(key) and not args.reveal:
                    print(f"  {CYAN}{key}{RESET}={mask_value(value)}")
                else:
                    print(f"  {CYAN}{key}{RESET}={value}")
            else:
                print(f"  {YELLOW}{key} not found{RESET}")

    elif args.action == 'delete':
        if not args.args:
            print(f"  {RED}Usage: env_manager.py delete KEY{RESET}\n")
            return

        env_vars = parse_env_file(args.file)

        for key in args.args:
            if key in env_vars:
                del env_vars[key]
                print(f"  {RED}Deleted {key}{RESET}")
            else:
                print(f"  {YELLOW}{key} not found{RESET}")

        write_env_file(args.file, env_vars)

    elif args.action == 'export':
        env_vars = parse_env_file(args.file)

        print(f"  {BOLD}Export commands:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for key, value in sorted(env_vars.items()):
            # Escape for shell
            escaped = value.replace("'", "'\"'\"'")
            print(f"export {key}='{escaped}'")

    elif args.action == 'diff':
        if len(args.args) < 1:
            print(f"  {RED}Usage: env_manager.py diff .env.example{RESET}\n")
            return

        file1 = args.file
        file2 = args.args[0]

        vars1 = parse_env_file(file1)
        vars2 = parse_env_file(file2)

        all_keys = set(vars1.keys()) | set(vars2.keys())

        print(f"  {BOLD}Comparing:{RESET} {file1} vs {file2}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for key in sorted(all_keys):
            if key not in vars1:
                print(f"  {RED}- {key}{RESET} (missing in {file1})")
            elif key not in vars2:
                print(f"  {GREEN}+ {key}{RESET} (missing in {file2})")
            elif vars1[key] != vars2[key]:
                print(f"  {YELLOW}~ {key}{RESET} (different values)")

    elif args.action == 'create':
        if os.path.exists(args.file):
            print(f"  {YELLOW}File already exists: {args.file}{RESET}\n")
            return

        # Create template
        template = {
            'APP_NAME': 'myapp',
            'APP_ENV': 'development',
            'DEBUG': 'true',
            'LOG_LEVEL': 'info',
            'DATABASE_URL': '',
            'API_KEY': '',
            'SECRET_KEY': '',
        }

        comments = [
            'Environment Configuration',
            f'Created: {__import__("datetime").datetime.now().strftime("%Y-%m-%d")}',
        ]

        write_env_file(args.file, template, comments)
        print(f"  {GREEN}Created {args.file} with template{RESET}")

    print()


if __name__ == '__main__':
    main()
