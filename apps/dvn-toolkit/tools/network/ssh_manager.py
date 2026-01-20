#!/usr/bin/env python3
"""
SSH Manager - Save and manage SSH connections
Usage: ssh_manager.py [list|add|connect|delete]
"""

import os
import json
import argparse
import subprocess

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

CONFIG_FILE = os.path.expanduser('~/.dvn_ssh_hosts.json')


def load_hosts():
    """Load saved hosts"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}


def save_hosts(hosts):
    """Save hosts to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(hosts, f, indent=2)


def add_host(name, host, user, port=22, key=None, description=''):
    """Add a new host"""
    hosts = load_hosts()
    hosts[name] = {
        'host': host,
        'user': user,
        'port': port,
        'key': key,
        'description': description
    }
    save_hosts(hosts)
    return True


def delete_host(name):
    """Delete a host"""
    hosts = load_hosts()
    if name in hosts:
        del hosts[name]
        save_hosts(hosts)
        return True
    return False


def connect_host(name):
    """Connect to a host"""
    hosts = load_hosts()
    if name not in hosts:
        return False, "Host not found"

    h = hosts[name]
    cmd = ['ssh']

    if h.get('port') and h['port'] != 22:
        cmd.extend(['-p', str(h['port'])])

    if h.get('key'):
        cmd.extend(['-i', os.path.expanduser(h['key'])])

    cmd.append(f"{h['user']}@{h['host']}")

    print(f"  {DIM}Connecting: {' '.join(cmd)}{RESET}\n")

    try:
        subprocess.run(cmd)
        return True, None
    except Exception as e:
        return False, str(e)


def list_hosts():
    """List all hosts"""
    hosts = load_hosts()
    return hosts


def interactive_add():
    """Interactive host addition"""
    print(f"\n  {BOLD}Add New Host:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}\n")

    name = input(f"  {CYAN}Name (alias):{RESET} ").strip()
    if not name:
        return None

    host = input(f"  {CYAN}Hostname/IP:{RESET} ").strip()
    if not host:
        return None

    user = input(f"  {CYAN}Username:{RESET} ").strip()
    if not user:
        user = os.environ.get('USER', 'root')

    port = input(f"  {CYAN}Port [22]:{RESET} ").strip()
    port = int(port) if port else 22

    key = input(f"  {CYAN}SSH Key path (optional):{RESET} ").strip()
    key = key if key else None

    desc = input(f"  {CYAN}Description (optional):{RESET} ").strip()

    add_host(name, host, user, port, key, desc)
    return name


def main():
    parser = argparse.ArgumentParser(description='SSH Manager')
    parser.add_argument('action', nargs='?', default='interactive',
                        choices=['list', 'add', 'connect', 'delete', 'interactive'],
                        help='Action to perform')
    parser.add_argument('name', nargs='?', help='Host name')
    parser.add_argument('--host', '-H', help='Hostname/IP')
    parser.add_argument('--user', '-u', help='Username')
    parser.add_argument('--port', '-p', type=int, default=22, help='Port')
    parser.add_argument('--key', '-k', help='SSH key path')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔐 SSH Manager                                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list':
        hosts = list_hosts()
        if not hosts:
            print(f"  {DIM}No saved hosts{RESET}\n")
            return

        print(f"  {BOLD}Saved Hosts:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for name, h in hosts.items():
            print(f"  {GREEN}{name}{RESET}")
            print(f"    {h['user']}@{h['host']}:{h.get('port', 22)}")
            if h.get('description'):
                print(f"    {DIM}{h['description']}{RESET}")
            if h.get('key'):
                print(f"    {DIM}Key: {h['key']}{RESET}")
            print()

    elif args.action == 'add':
        if args.name and args.host and args.user:
            add_host(args.name, args.host, args.user, args.port, args.key)
            print(f"  {GREEN}Added: {args.name}{RESET}\n")
        else:
            name = interactive_add()
            if name:
                print(f"\n  {GREEN}Added: {name}{RESET}\n")

    elif args.action == 'connect':
        if not args.name:
            hosts = list_hosts()
            if not hosts:
                print(f"  {DIM}No saved hosts{RESET}\n")
                return

            print(f"  {BOLD}Select host:{RESET}\n")
            host_list = list(hosts.keys())
            for i, name in enumerate(host_list, 1):
                h = hosts[name]
                print(f"  {CYAN}{i}.{RESET} {name} ({h['user']}@{h['host']})")

            choice = input(f"\n  {CYAN}Number:{RESET} ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(host_list):
                    args.name = host_list[idx]
            except:
                pass

        if args.name:
            success, error = connect_host(args.name)
            if not success:
                print(f"  {RED}Error: {error}{RESET}\n")

    elif args.action == 'delete':
        if not args.name:
            args.name = input(f"  {CYAN}Host name to delete:{RESET} ").strip()

        if args.name:
            if delete_host(args.name):
                print(f"  {GREEN}Deleted: {args.name}{RESET}\n")
            else:
                print(f"  {RED}Host not found: {args.name}{RESET}\n")

    else:
        # Interactive mode
        hosts = list_hosts()

        while True:
            print(f"  {BOLD}Options:{RESET}")
            print(f"  {CYAN}1.{RESET} List hosts")
            print(f"  {CYAN}2.{RESET} Connect to host")
            print(f"  {CYAN}3.{RESET} Add new host")
            print(f"  {CYAN}4.{RESET} Delete host")
            print(f"  {CYAN}5.{RESET} Quick connect (user@host)")
            print(f"  {CYAN}6.{RESET} Exit")

            choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

            if choice == '1':
                hosts = list_hosts()
                if hosts:
                    print(f"\n  {BOLD}Saved Hosts:{RESET}")
                    for name, h in hosts.items():
                        print(f"    {GREEN}{name}{RESET}: {h['user']}@{h['host']}")
                else:
                    print(f"\n  {DIM}No saved hosts{RESET}")
                print()

            elif choice == '2':
                hosts = list_hosts()
                if not hosts:
                    print(f"\n  {DIM}No saved hosts{RESET}\n")
                    continue

                host_list = list(hosts.keys())
                print()
                for i, name in enumerate(host_list, 1):
                    print(f"  {CYAN}{i}.{RESET} {name}")

                num = input(f"\n  {CYAN}Number:{RESET} ").strip()
                try:
                    idx = int(num) - 1
                    if 0 <= idx < len(host_list):
                        connect_host(host_list[idx])
                except:
                    pass
                print()

            elif choice == '3':
                name = interactive_add()
                if name:
                    print(f"\n  {GREEN}Added: {name}{RESET}\n")

            elif choice == '4':
                name = input(f"\n  {CYAN}Host name:{RESET} ").strip()
                if name and delete_host(name):
                    print(f"  {GREEN}Deleted{RESET}\n")
                else:
                    print(f"  {RED}Not found{RESET}\n")

            elif choice == '5':
                target = input(f"\n  {CYAN}user@host:{RESET} ").strip()
                if target:
                    print()
                    subprocess.run(['ssh', target])
                print()

            elif choice == '6':
                break

            else:
                print()

    print()


if __name__ == '__main__':
    main()
