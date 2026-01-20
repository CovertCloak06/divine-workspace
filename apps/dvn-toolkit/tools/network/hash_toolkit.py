#!/usr/bin/env python3
"""
Hash Toolkit - Generate, identify, and crack hashes
Usage: hash_toolkit.py [action] [input] [--type TYPE]
Actions: generate, identify, crack, compare
"""

import sys
import json
import argparse
import hashlib
import binascii
import os
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Hash type signatures
HASH_SIGNATURES = {
    'MD5': {'length': 32, 'pattern': r'^[a-f0-9]{32}$'},
    'SHA1': {'length': 40, 'pattern': r'^[a-f0-9]{40}$'},
    'SHA224': {'length': 56, 'pattern': r'^[a-f0-9]{56}$'},
    'SHA256': {'length': 64, 'pattern': r'^[a-f0-9]{64}$'},
    'SHA384': {'length': 96, 'pattern': r'^[a-f0-9]{96}$'},
    'SHA512': {'length': 128, 'pattern': r'^[a-f0-9]{128}$'},
    'SHA3-256': {'length': 64, 'pattern': r'^[a-f0-9]{64}$'},
    'SHA3-512': {'length': 128, 'pattern': r'^[a-f0-9]{128}$'},
    'BLAKE2b': {'length': 128, 'pattern': r'^[a-f0-9]{128}$'},
    'BLAKE2s': {'length': 64, 'pattern': r'^[a-f0-9]{64}$'},
    'NTLM': {'length': 32, 'pattern': r'^[a-f0-9]{32}$'},
    'MySQL323': {'length': 16, 'pattern': r'^[a-f0-9]{16}$'},
    'MySQL5': {'length': 40, 'pattern': r'^[a-f0-9]{40}$'},
    'bcrypt': {'length': 60, 'pattern': r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$'},
    'PBKDF2': {'length': None, 'pattern': r'^pbkdf2'},
}

# Common passwords for quick crack attempts
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'master', 'michael', 'football',
    'shadow', 'ashley', 'fuckme', 'jennifer', 'superman', 'admin', 'welcome',
    'password1', 'password123', '123456789', '12345', '1234567890', 'iloveyou',
    'sunshine', 'princess', '123123', 'admin123', 'root', 'toor', 'pass',
    'test', 'guest', 'master', 'changeme', 'passwd', 'hello', 'love',
]


def generate_hash(data, hash_type='sha256'):
    """Generate hash of data"""
    data_bytes = data.encode() if isinstance(data, str) else data

    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
    }

    func = hash_funcs.get(hash_type.lower().replace('-', '_'))
    if not func:
        return None

    return func(data_bytes).hexdigest()


def generate_all_hashes(data):
    """Generate all supported hashes"""
    results = {}
    hash_types = ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'sha3_256', 'blake2b', 'blake2s']

    for ht in hash_types:
        results[ht.upper()] = generate_hash(data, ht)

    return results


def identify_hash(hash_string):
    """Identify hash type based on format"""
    hash_string = hash_string.strip().lower()
    possible = []

    for hash_type, sig in HASH_SIGNATURES.items():
        pattern = sig['pattern']
        if re.match(pattern, hash_string, re.IGNORECASE):
            possible.append(hash_type)

    # More specific identification
    length = len(hash_string)

    # Remove duplicates based on length
    if length == 32:
        possible = ['MD5', 'NTLM']
    elif length == 40:
        possible = ['SHA1', 'MySQL5']
    elif length == 64:
        possible = ['SHA256', 'SHA3-256', 'BLAKE2s']
    elif length == 128:
        possible = ['SHA512', 'SHA3-512', 'BLAKE2b']
    elif hash_string.startswith('$2'):
        possible = ['bcrypt']
    elif hash_string.startswith('pbkdf2'):
        possible = ['PBKDF2']

    return possible


def crack_hash(hash_string, wordlist=None, hash_type=None):
    """Attempt to crack hash using wordlist"""
    hash_string = hash_string.strip().lower()

    # Auto-detect hash type if not specified
    if not hash_type:
        possible_types = identify_hash(hash_string)
        if not possible_types:
            return None
        # Try MD5/SHA1/SHA256 first
        if 'MD5' in possible_types:
            hash_type = 'md5'
        elif 'SHA1' in possible_types:
            hash_type = 'sha1'
        elif 'SHA256' in possible_types:
            hash_type = 'sha256'
        else:
            hash_type = possible_types[0].lower()

    # Prepare wordlist
    words = COMMON_PASSWORDS.copy()

    if wordlist:
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        words.append(word)
        except:
            pass

    # Try each word
    for word in words:
        test_hash = generate_hash(word, hash_type)
        if test_hash and test_hash.lower() == hash_string:
            return word

    return None


def hash_file(filepath, hash_type='sha256'):
    """Calculate hash of a file"""
    hash_func = getattr(hashlib, hash_type.lower().replace('-', '_'), None)
    if not hash_func:
        return None

    hasher = hash_func()

    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None


def compare_hashes(hash1, hash2):
    """Securely compare two hashes"""
    # Normalize
    hash1 = hash1.strip().lower()
    hash2 = hash2.strip().lower()

    # Length check
    if len(hash1) != len(hash2):
        return False

    # Constant-time comparison
    result = 0
    for a, b in zip(hash1, hash2):
        result |= ord(a) ^ ord(b)
    return result == 0


def display_hash_results(hashes):
    """Display generated hashes"""
    print(f"\n  {BOLD}Generated Hashes{RESET}")
    print(f"  {DIM}{'─' * 70}{RESET}\n")

    for hash_type, hash_value in hashes.items():
        print(f"  {CYAN}{hash_type:10}{RESET} {hash_value}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Hash Toolkit')
    parser.add_argument('action', nargs='?', default='generate',
                       choices=['generate', 'identify', 'crack', 'file', 'compare'],
                       help='Action to perform')
    parser.add_argument('input', nargs='?', help='Input data or hash')
    parser.add_argument('--type', '-t', default='sha256', help='Hash type')
    parser.add_argument('--wordlist', '-w', help='Wordlist for cracking')
    parser.add_argument('--all', '-a', action='store_true', help='Generate all hash types')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--compare-to', '-c', help='Hash to compare against')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Hash Toolkit{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    # Generate action
    if args.action == 'generate':
        data = args.input
        if not data:
            data = input(f"\n  {CYAN}Data to hash:{RESET} ").strip()

        if not data:
            print(f"  {RED}Data required{RESET}")
            sys.exit(1)

        if args.all:
            hashes = generate_all_hashes(data)
            if args.json:
                print(json.dumps(hashes, indent=2))
            else:
                display_hash_results(hashes)
        else:
            result = generate_hash(data, args.type)
            if result:
                if args.json:
                    print(json.dumps({'type': args.type.upper(), 'hash': result}))
                else:
                    print(f"\n  {CYAN}{args.type.upper()}:{RESET} {result}\n")
            else:
                print(f"  {RED}Unsupported hash type: {args.type}{RESET}")

    # Identify action
    elif args.action == 'identify':
        hash_str = args.input
        if not hash_str:
            hash_str = input(f"\n  {CYAN}Hash to identify:{RESET} ").strip()

        if not hash_str:
            print(f"  {RED}Hash required{RESET}")
            sys.exit(1)

        possible = identify_hash(hash_str)

        if args.json:
            print(json.dumps({'hash': hash_str, 'possible_types': possible}))
        else:
            print(f"\n  {BOLD}Hash Identification{RESET}")
            print(f"  {DIM}{'─' * 50}{RESET}\n")
            print(f"  {CYAN}Hash:{RESET}    {hash_str[:64]}{'...' if len(hash_str) > 64 else ''}")
            print(f"  {CYAN}Length:{RESET}  {len(hash_str)} characters")
            print()

            if possible:
                print(f"  {GREEN}Possible types:{RESET}")
                for t in possible:
                    print(f"    {YELLOW}  {t}{RESET}")
            else:
                print(f"  {RED}Unknown hash format{RESET}")
            print()

    # Crack action
    elif args.action == 'crack':
        hash_str = args.input
        if not hash_str:
            hash_str = input(f"\n  {CYAN}Hash to crack:{RESET} ").strip()

        if not hash_str:
            print(f"  {RED}Hash required{RESET}")
            sys.exit(1)

        if not args.json:
            print(f"\n  {DIM}Attempting to crack hash...{RESET}")
            print(f"  {DIM}Using {len(COMMON_PASSWORDS)} common passwords{RESET}")
            if args.wordlist:
                print(f"  {DIM}+ custom wordlist: {args.wordlist}{RESET}")
            print()

        result = crack_hash(hash_str, args.wordlist, args.type if args.type != 'sha256' else None)

        if args.json:
            print(json.dumps({'hash': hash_str, 'cracked': result is not None, 'plaintext': result}))
        else:
            if result:
                print(f"  {GREEN}CRACKED!{RESET}")
                print(f"  {CYAN}Plaintext:{RESET} {BOLD}{result}{RESET}")
            else:
                print(f"  {YELLOW}Could not crack hash{RESET}")
                print(f"  {DIM}Try a larger wordlist with --wordlist{RESET}")
            print()

    # File hash action
    elif args.action == 'file':
        filepath = args.input
        if not filepath:
            filepath = input(f"\n  {CYAN}File path:{RESET} ").strip()

        if not filepath or not os.path.exists(filepath):
            print(f"  {RED}File not found{RESET}")
            sys.exit(1)

        if args.all:
            results = {}
            for ht in ['md5', 'sha1', 'sha256', 'sha512']:
                results[ht.upper()] = hash_file(filepath, ht)
            if args.json:
                print(json.dumps({'file': filepath, 'hashes': results}))
            else:
                print(f"\n  {BOLD}File Hashes{RESET}")
                print(f"  {DIM}{'─' * 70}{RESET}")
                print(f"  {CYAN}File:{RESET} {filepath}\n")
                for ht, hv in results.items():
                    print(f"  {CYAN}{ht:10}{RESET} {hv}")
                print()
        else:
            result = hash_file(filepath, args.type)
            if args.json:
                print(json.dumps({'file': filepath, 'type': args.type.upper(), 'hash': result}))
            else:
                print(f"\n  {CYAN}File:{RESET} {filepath}")
                print(f"  {CYAN}{args.type.upper()}:{RESET} {result}\n")

    # Compare action
    elif args.action == 'compare':
        hash1 = args.input
        hash2 = args.compare_to

        if not hash1:
            hash1 = input(f"\n  {CYAN}First hash:{RESET} ").strip()
        if not hash2:
            hash2 = input(f"  {CYAN}Second hash:{RESET} ").strip()

        if not hash1 or not hash2:
            print(f"  {RED}Two hashes required{RESET}")
            sys.exit(1)

        match = compare_hashes(hash1, hash2)

        if args.json:
            print(json.dumps({'hash1': hash1, 'hash2': hash2, 'match': match}))
        else:
            print()
            if match:
                print(f"  {GREEN}  MATCH - Hashes are identical{RESET}")
            else:
                print(f"  {RED}  NO MATCH - Hashes differ{RESET}")
            print()


if __name__ == '__main__':
    main()
