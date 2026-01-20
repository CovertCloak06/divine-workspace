#!/usr/bin/env python3
"""
UUID Generator - Generate various UUID formats
Usage: uuid_gen.py [--count N] [--version 1|4]
"""

import uuid
import argparse
import hashlib
import time
import random

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def generate_uuid1():
    """Generate UUID v1 (time-based)"""
    return str(uuid.uuid1())


def generate_uuid4():
    """Generate UUID v4 (random)"""
    return str(uuid.uuid4())


def generate_uuid3(namespace, name):
    """Generate UUID v3 (MD5 hash)"""
    ns_uuid = getattr(uuid, f'NAMESPACE_{namespace.upper()}', uuid.NAMESPACE_DNS)
    return str(uuid.uuid3(ns_uuid, name))


def generate_uuid5(namespace, name):
    """Generate UUID v5 (SHA-1 hash)"""
    ns_uuid = getattr(uuid, f'NAMESPACE_{namespace.upper()}', uuid.NAMESPACE_DNS)
    return str(uuid.uuid5(ns_uuid, name))


def generate_short_id(length=8):
    """Generate short alphanumeric ID"""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))


def generate_nano_id(length=21):
    """Generate NanoID-style ID"""
    chars = '_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(chars) for _ in range(length))


def uuid_to_formats(u):
    """Convert UUID to various formats"""
    u = u.replace('-', '').lower()

    # Standard
    standard = f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}"

    # No dashes
    nodash = u

    # Braces
    braces = "{" + standard + "}"

    # URN
    urn = "urn:uuid:" + standard

    # Base64
    import base64
    b64 = base64.b64encode(bytes.fromhex(u)).decode('ascii').rstrip('=')

    return {
        'standard': standard,
        'nodash': nodash,
        'braces': braces,
        'urn': urn,
        'base64': b64,
    }


def main():
    parser = argparse.ArgumentParser(description='UUID Generator')
    parser.add_argument('--count', '-n', type=int, default=1, help='Number of UUIDs')
    parser.add_argument('--version', '-v', type=int, choices=[1, 3, 4, 5], default=4,
                        help='UUID version')
    parser.add_argument('--name', help='Name for v3/v5 UUID')
    parser.add_argument('--namespace', default='dns', help='Namespace for v3/v5')
    parser.add_argument('--short', '-s', type=int, metavar='LEN', help='Generate short ID')
    parser.add_argument('--nano', action='store_true', help='Generate NanoID')
    parser.add_argument('--format', '-f', action='store_true', help='Show all formats')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔑 UUID Generator                             ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Short ID mode
    if args.short:
        print(f"  {BOLD}Short IDs ({args.short} chars):{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")
        for _ in range(args.count):
            print(f"  {GREEN}{generate_short_id(args.short)}{RESET}")
        print()
        return

    # NanoID mode
    if args.nano:
        print(f"  {BOLD}NanoIDs:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")
        for _ in range(args.count):
            print(f"  {GREEN}{generate_nano_id()}{RESET}")
        print()
        return

    # UUID generation
    print(f"  {BOLD}UUID v{args.version}:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    for i in range(args.count):
        if args.version == 1:
            u = generate_uuid1()
        elif args.version == 3:
            name = args.name or f"example{i}"
            u = generate_uuid3(args.namespace, name)
        elif args.version == 5:
            name = args.name or f"example{i}"
            u = generate_uuid5(args.namespace, name)
        else:
            u = generate_uuid4()

        if args.format and args.count == 1:
            formats = uuid_to_formats(u)
            print(f"  {CYAN}Standard:{RESET}  {GREEN}{formats['standard']}{RESET}")
            print(f"  {CYAN}No Dash:{RESET}   {formats['nodash']}")
            print(f"  {CYAN}Braces:{RESET}    {formats['braces']}")
            print(f"  {CYAN}URN:{RESET}       {formats['urn']}")
            print(f"  {CYAN}Base64:{RESET}    {formats['base64']}")
        else:
            print(f"  {GREEN}{u}{RESET}")

    # Info
    print(f"\n  {BOLD}UUID Version Info:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}v1:{RESET} Time-based (MAC + timestamp)")
    print(f"  {CYAN}v3:{RESET} MD5 hash of namespace + name")
    print(f"  {CYAN}v4:{RESET} Random (most common)")
    print(f"  {CYAN}v5:{RESET} SHA-1 hash of namespace + name")

    print()


if __name__ == '__main__':
    main()
