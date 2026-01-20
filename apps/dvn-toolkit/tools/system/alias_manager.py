#!/usr/bin/env python3
"""
Alias Manager - Manage shell aliases
Usage: alias_manager.py [list|add|delete|export]
"""

import os
import re
import argparse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_shell_config():
    """Get the shell config file path"""
    shell = os.environ.get('SHELL', '/bin/bash')

    if 'zsh' in shell:
        return os.path.expanduser('~/.zshrc')
    elif 'fish' in shell:
        return os.path.expanduser('~/.config/fish/config.fish')
    else:
        return os.path.expanduser('~/.bashrc')


def get_aliases():
    """Get current aliases from shell config"""
    config_file = get_shell_config()
    aliases = {}

    if not os.path.exists(config_file):
        return aliases

    with open(config_file, 'r') as f:
        content = f.read()

    # Match alias definitions
    # alias name='command'
    # alias name="command"
    pattern = r"^alias\s+([a-zA-Z0-9_-]+)\s*=\s*['\"](.+?)['\"]"

    for line in content.split('\n'):
        line = line.strip()
        match = re.match(pattern, line)
        if match:
            aliases[match.group(1)] = match.group(2)

    return aliases


def add_alias(name, command):
    """Add an alias to shell config"""
    config_file = get_shell_config()

    # Validate name
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]*$', name):
        return False, "Invalid alias name"

    # Read current content
    content = ""
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            content = f.read()

    # Check if alias exists
    existing = get_aliases()
    if name in existing:
        # Update existing alias
        pattern = rf"^alias\s+{re.escape(name)}\s*=\s*['\"].+?['\"]"
        new_line = f"alias {name}='{command}'"
        content = re.sub(pattern, new_line, content, flags=re.MULTILINE)
    else:
        # Add new alias
        alias_line = f"\nalias {name}='{command}'\n"
        content += alias_line

    # Write back
    with open(config_file, 'w') as f:
        f.write(content)

    return True, config_file


def delete_alias(name):
    """Remove an alias from shell config"""
    config_file = get_shell_config()

    if not os.path.exists(config_file):
        return False

    with open(config_file, 'r') as f:
        content = f.read()

    # Remove alias line
    pattern = rf"^alias\s+{re.escape(name)}\s*=\s*['\"].+?['\"].*\n?"
    new_content = re.sub(pattern, '', content, flags=re.MULTILINE)

    if new_content == content:
        return False

    with open(config_file, 'w') as f:
        f.write(new_content)

    return True


def export_aliases():
    """Export aliases as shell commands"""
    aliases = get_aliases()
    lines = []
    for name, cmd in sorted(aliases.items()):
        lines.append(f"alias {name}='{cmd}'")
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Alias Manager')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['list', 'add', 'delete', 'export', 'search'])
    parser.add_argument('name', nargs='?', help='Alias name')
    parser.add_argument('command', nargs='?', help='Command for alias')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔗 Alias Manager                              ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    config_file = get_shell_config()
    shell_name = os.path.basename(os.environ.get('SHELL', 'bash'))
    print(f"  {DIM}Shell: {shell_name} | Config: {config_file}{RESET}\n")

    if args.action == 'list':
        aliases = get_aliases()

        if not aliases:
            print(f"  {DIM}No aliases defined{RESET}\n")
            return

        print(f"  {BOLD}Aliases ({len(aliases)}):{RESET}")
        print(f"  {DIM}{'─' * 55}{RESET}\n")

        # Group by prefix
        for name in sorted(aliases.keys()):
            cmd = aliases[name]
            # Truncate long commands
            display_cmd = cmd[:50] + '...' if len(cmd) > 50 else cmd
            print(f"  {GREEN}{name:<15}{RESET} {DIM}→{RESET} {display_cmd}")

        print()

    elif args.action == 'add':
        if not args.name:
            args.name = input(f"  {CYAN}Alias name:{RESET} ").strip()
        if not args.command:
            args.command = input(f"  {CYAN}Command:{RESET} ").strip()

        if not args.name or not args.command:
            print(f"  {RED}Name and command required{RESET}\n")
            return

        success, result = add_alias(args.name, args.command)

        if success:
            print(f"  {GREEN}✓ Alias added: {args.name}{RESET}")
            print(f"\n  {YELLOW}Run this to apply:{RESET}")
            print(f"  {DIM}source {result}{RESET}")
            print(f"\n  {DIM}Or restart your terminal{RESET}")
        else:
            print(f"  {RED}✗ {result}{RESET}")

        print()

    elif args.action == 'delete':
        if not args.name:
            aliases = get_aliases()
            if not aliases:
                print(f"  {DIM}No aliases to delete{RESET}\n")
                return

            print(f"  {BOLD}Select alias to delete:{RESET}\n")
            alias_list = sorted(aliases.keys())
            for i, name in enumerate(alias_list, 1):
                print(f"  {CYAN}{i}.{RESET} {name}")

            choice = input(f"\n  {CYAN}Number or name:{RESET} ").strip()

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(alias_list):
                    args.name = alias_list[idx]
            except ValueError:
                args.name = choice

        if not args.name:
            print(f"  {RED}Alias name required{RESET}\n")
            return

        if delete_alias(args.name):
            print(f"  {GREEN}✓ Alias deleted: {args.name}{RESET}")
            print(f"\n  {YELLOW}Restart terminal or source config to apply{RESET}")
        else:
            print(f"  {RED}Alias not found: {args.name}{RESET}")

        print()

    elif args.action == 'export':
        exported = export_aliases()
        if exported:
            print(f"  {BOLD}Exported Aliases:{RESET}")
            print(f"  {DIM}{'─' * 55}{RESET}\n")
            print(exported)
            print()
        else:
            print(f"  {DIM}No aliases to export{RESET}\n")

    elif args.action == 'search':
        query = args.name or input(f"  {CYAN}Search:{RESET} ").strip()
        if not query:
            print(f"  {RED}Search term required{RESET}\n")
            return

        aliases = get_aliases()
        matches = {k: v for k, v in aliases.items()
                  if query.lower() in k.lower() or query.lower() in v.lower()}

        if matches:
            print(f"  {BOLD}Matches ({len(matches)}):{RESET}\n")
            for name, cmd in sorted(matches.items()):
                print(f"  {GREEN}{name}{RESET} → {cmd}")
        else:
            print(f"  {DIM}No matches found{RESET}")

        print()

    # Suggested aliases
    print(f"  {BOLD}Suggested Aliases:{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}")
    suggestions = [
        ("ll", "ls -la"),
        ("la", "ls -A"),
        ("...", "cd ../.."),
        ("gs", "git status"),
        ("gp", "git pull"),
        ("gc", "git commit -m"),
        ("gd", "git diff"),
        ("cls", "clear"),
        ("py", "python3"),
        ("ports", "netstat -tuln"),
    ]

    existing = get_aliases()
    for name, cmd in suggestions[:5]:
        if name not in existing:
            print(f"  {CYAN}{name}{RESET} → {DIM}{cmd}{RESET}")

    print()


if __name__ == '__main__':
    main()
