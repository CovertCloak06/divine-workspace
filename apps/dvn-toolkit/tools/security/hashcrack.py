#!/usr/bin/env python3
"""
Hash Analyzer - Identify and analyze hash types
Usage: hashcrack.py <hash> [--wordlist file]
"""

import hashlib
import argparse
import re
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Hash patterns
HASH_PATTERNS = [
    (r'^[a-f0-9]{32}$', ['MD5', 'MD4', 'NTLM', 'Domain Cached Credentials']),
    (r'^[a-f0-9]{40}$', ['SHA-1', 'MySQL5', 'RIPEMD-160']),
    (r'^[a-f0-9]{56}$', ['SHA-224']),
    (r'^[a-f0-9]{64}$', ['SHA-256', 'SHA3-256', 'BLAKE2s']),
    (r'^[a-f0-9]{96}$', ['SHA-384', 'SHA3-384']),
    (r'^[a-f0-9]{128}$', ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool']),
    (r'^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$', ['MD5crypt (Unix)']),
    (r'^\$5\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{43}$', ['SHA-256crypt (Unix)']),
    (r'^\$6\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{86}$', ['SHA-512crypt (Unix)']),
    (r'^\$2[ayb]\$\d{2}\$[a-zA-Z0-9./]{53}$', ['bcrypt']),
    (r'^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$', ['Apache MD5']),
    (r'^[a-f0-9]{32}:[a-f0-9]+$', ['MD5 (salted)', 'WordPress']),
    (r'^[a-f0-9]{40}:[a-f0-9]+$', ['SHA-1 (salted)']),
]


def identify_hash(hash_string):
    """Identify possible hash types"""
    hash_lower = hash_string.lower().strip()

    matches = []
    for pattern, types in HASH_PATTERNS:
        if re.match(pattern, hash_lower, re.IGNORECASE):
            matches.extend(types)

    # Also check by length
    length = len(hash_lower)
    length_hints = {
        32: 'Likely MD5/NTLM',
        40: 'Likely SHA-1',
        64: 'Likely SHA-256',
        128: 'Likely SHA-512',
    }

    hint = length_hints.get(length)

    return matches, hint


def hash_string(text, algorithm):
    """Hash a string with given algorithm"""
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
    }

    if algorithm.lower() in algorithms:
        return algorithms[algorithm.lower()](text.encode()).hexdigest()
    return None


def dictionary_attack(target_hash, wordlist_path, algorithms=None):
    """Attempt to crack hash using wordlist"""
    if algorithms is None:
        # Guess based on hash length
        length = len(target_hash)
        if length == 32:
            algorithms = ['md5']
        elif length == 40:
            algorithms = ['sha1']
        elif length == 64:
            algorithms = ['sha256']
        else:
            algorithms = ['md5', 'sha1', 'sha256']

    target_lower = target_hash.lower()

    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            line_count = 0
            for line in f:
                word = line.strip()
                line_count += 1

                # Progress
                if line_count % 10000 == 0:
                    sys.stdout.write(f"\r  {DIM}Tried {line_count:,} words...{RESET}")
                    sys.stdout.flush()

                for algo in algorithms:
                    hashed = hash_string(word, algo)
                    if hashed and hashed == target_lower:
                        print()  # New line
                        return word, algo

        print()  # New line
        return None, None

    except FileNotFoundError:
        return None, None


def generate_hashes(text):
    """Generate all common hashes for a string"""
    algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

    results = {}
    for algo in algorithms:
        results[algo.upper()] = hash_string(text, algo)

    return results


def main():
    parser = argparse.ArgumentParser(description='Hash Analyzer')
    parser.add_argument('hash', nargs='?', help='Hash to analyze/crack')
    parser.add_argument('--wordlist', '-w', help='Wordlist for cracking')
    parser.add_argument('--generate', '-g', help='Generate hashes for text')
    parser.add_argument('--algorithm', '-a', help='Specific algorithm to use')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔓 Hash Analyzer                              ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Generate mode
    if args.generate:
        print(f"  {BOLD}Input:{RESET} {args.generate}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        hashes = generate_hashes(args.generate)
        for algo, hash_val in hashes.items():
            print(f"  {CYAN}{algo:10}{RESET} {hash_val}")
        print()
        return

    # Get hash
    if not args.hash:
        args.hash = input(f"  {CYAN}Hash:{RESET} ").strip()

    if not args.hash:
        print(f"  {RED}Hash required{RESET}\n")
        return

    hash_val = args.hash.strip()

    # Identify hash type
    print(f"  {BOLD}Hash:{RESET} {hash_val[:50]}{'...' if len(hash_val) > 50 else ''}")
    print(f"  {BOLD}Length:{RESET} {len(hash_val)} characters")

    types, hint = identify_hash(hash_val)

    print(f"\n  {BOLD}Possible Types:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    if types:
        for t in types[:6]:
            print(f"    {CYAN}•{RESET} {t}")
    elif hint:
        print(f"    {YELLOW}{hint}{RESET}")
    else:
        print(f"    {DIM}Unknown hash format{RESET}")

    # Wordlist attack
    if args.wordlist:
        print(f"\n  {BOLD}Dictionary Attack:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        print(f"  Wordlist: {args.wordlist}")

        algorithms = [args.algorithm.lower()] if args.algorithm else None

        print(f"  {YELLOW}Attempting to crack...{RESET}")

        result, algo = dictionary_attack(hash_val, args.wordlist, algorithms)

        if result:
            print(f"\n  {GREEN}✓ CRACKED!{RESET}")
            print(f"  {BOLD}Password:{RESET} {GREEN}{result}{RESET}")
            print(f"  {BOLD}Algorithm:{RESET} {algo.upper()}")
        else:
            print(f"\n  {RED}✗ Not found in wordlist{RESET}")

    # Interactive options
    else:
        print(f"\n  {BOLD}Options:{RESET}")
        print(f"  {CYAN}1.{RESET} Verify a password against this hash")
        print(f"  {CYAN}2.{RESET} Quick wordlist attack (common passwords)")
        print(f"  {CYAN}3.{RESET} Exit")

        choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

        if choice == '1':
            password = input(f"  {CYAN}Password to verify:{RESET} ").strip()

            if password:
                print(f"\n  {BOLD}Verification:{RESET}")
                algorithms = ['md5', 'sha1', 'sha256', 'sha512']

                found = False
                for algo in algorithms:
                    hashed = hash_string(password, algo)
                    if hashed and hashed.lower() == hash_val.lower():
                        print(f"  {GREEN}✓ Match found ({algo.upper()}){RESET}")
                        found = True
                        break

                if not found:
                    print(f"  {RED}✗ No match{RESET}")

        elif choice == '2':
            # Common passwords
            common = [
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
                'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
                'bailey', 'shadow', '123123', '654321', 'superman',
                'qazwsx', 'michael', 'football', 'password1', 'password123',
                'admin', 'root', 'toor', 'test', 'guest', 'welcome',
            ]

            print(f"\n  {YELLOW}Testing common passwords...{RESET}")

            found = False
            for pwd in common:
                for algo in ['md5', 'sha1', 'sha256']:
                    hashed = hash_string(pwd, algo)
                    if hashed and hashed.lower() == hash_val.lower():
                        print(f"\n  {GREEN}✓ FOUND: {pwd} ({algo.upper()}){RESET}")
                        found = True
                        break
                if found:
                    break

            if not found:
                print(f"  {RED}Not found in common passwords{RESET}")
                print(f"  {DIM}Try with a wordlist: --wordlist rockyou.txt{RESET}")

    print()


if __name__ == '__main__':
    main()
