#!/usr/bin/env python3
"""
Hash Tool - Hash cracking, generation, and identification
Usage: hasher <input> [--crack wordlist.txt] [--type md5] [--identify]
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Hash type patterns for identification
HASH_PATTERNS = [
    ('MD5', r'^[a-fA-F0-9]{32}$'),
    ('SHA1', r'^[a-fA-F0-9]{40}$'),
    ('SHA256', r'^[a-fA-F0-9]{64}$'),
    ('SHA512', r'^[a-fA-F0-9]{128}$'),
    ('NTLM', r'^[a-fA-F0-9]{32}$'),
    ('MySQL323', r'^[a-fA-F0-9]{16}$'),
    ('MySQL5', r'^\*[a-fA-F0-9]{40}$'),
    ('bcrypt', r'^\$2[ayb]\$.{56}$'),
    ('MD5-crypt', r'^\$1\$.{8}\$.{22}$'),
    ('SHA256-crypt', r'^\$5\$.{0,16}\$.{43}$'),
    ('SHA512-crypt', r'^\$6\$.{0,16}\$.{86}$'),
]

ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'sha384': hashlib.sha384,
    'sha224': hashlib.sha224,
}

def identify_hash(hash_str):
    """Identify possible hash types"""
    matches = []
    hash_str = hash_str.strip()

    for name, pattern in HASH_PATTERNS:
        if re.match(pattern, hash_str):
            matches.append(name)

    # Distinguish MD5 from NTLM by context
    if len(hash_str) == 32 and hash_str.isalnum():
        return ['MD5', 'NTLM', 'MD4', 'LM']

    return matches if matches else ['Unknown']

def generate_hash(text, algorithm='md5'):
    """Generate hash of text"""
    if algorithm not in ALGORITHMS:
        print(f"{RED}Unknown algorithm: {algorithm}{RESET}")
        return None

    hasher = ALGORITHMS[algorithm]()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def generate_all_hashes(text):
    """Generate all common hashes"""
    results = {}
    for algo in ALGORITHMS:
        results[algo] = generate_hash(text, algo)
    return results

def crack_hash(target_hash, wordlist_path, algorithm=None):
    """Attempt to crack hash using wordlist"""
    target_hash = target_hash.lower().strip()

    # Auto-detect algorithm if not specified
    if not algorithm:
        hash_len = len(target_hash)
        if hash_len == 32:
            algorithm = 'md5'
        elif hash_len == 40:
            algorithm = 'sha1'
        elif hash_len == 64:
            algorithm = 'sha256'
        else:
            print(f"{YELLOW}Could not auto-detect hash type. Use --type{RESET}")
            return None

    if algorithm not in ALGORITHMS:
        print(f"{RED}Unknown algorithm: {algorithm}{RESET}")
        return None

    wordlist = Path(wordlist_path)
    if not wordlist.exists():
        print(f"{RED}Wordlist not found: {wordlist_path}{RESET}")
        return None

    print(f"\n{BOLD}Cracking {algorithm.upper()} hash...{RESET}")
    print(f"Target: {CYAN}{target_hash}{RESET}")
    print(f"Wordlist: {wordlist_path}\n")

    hasher_func = ALGORITHMS[algorithm]
    attempts = 0

    try:
        with open(wordlist, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue

                attempts += 1
                test_hash = hasher_func(word.encode('utf-8')).hexdigest()

                if test_hash == target_hash:
                    return word, attempts

                # Progress indicator
                if attempts % 100000 == 0:
                    print(f"\r  Tried {attempts:,} passwords...", end='', flush=True)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted after {attempts:,} attempts{RESET}")
        return None

    return None, attempts

def main():
    parser = argparse.ArgumentParser(description='Hash Tool - Crack, Generate, Identify')
    parser.add_argument('input', help='Hash to crack/identify OR text to hash')
    parser.add_argument('--crack', '-c', metavar='WORDLIST', help='Wordlist file for cracking')
    parser.add_argument('--type', '-t', choices=list(ALGORITHMS.keys()), help='Hash algorithm')
    parser.add_argument('--identify', '-i', action='store_true', help='Identify hash type')
    parser.add_argument('--all', '-a', action='store_true', help='Generate all hash types')
    args = parser.parse_args()

    # Identify hash type
    if args.identify:
        print(f"\n{BOLD}Hash Identification{RESET}")
        print(f"Input: {CYAN}{args.input}{RESET}")
        possible = identify_hash(args.input)
        print(f"Possible types: {GREEN}{', '.join(possible)}{RESET}\n")
        return

    # Crack hash
    if args.crack:
        result = crack_hash(args.input, args.crack, args.type)
        if result:
            password, attempts = result
            if password:
                print(f"\n\n{GREEN}{BOLD}CRACKED!{RESET}")
                print(f"  Hash: {args.input}")
                print(f"  Password: {GREEN}{password}{RESET}")
                print(f"  Attempts: {attempts:,}\n")
            else:
                print(f"\n{RED}Not found after {attempts:,} attempts{RESET}\n")
        return

    # Generate hashes
    if args.all:
        print(f"\n{BOLD}Hash Generation{RESET}")
        print(f"Input: {CYAN}{args.input}{RESET}\n")
        for algo, hash_val in generate_all_hashes(args.input).items():
            print(f"  {algo.upper():8} {hash_val}")
        print()
    else:
        algo = args.type or 'md5'
        hash_val = generate_hash(args.input, algo)
        if hash_val:
            print(f"\n{algo.upper()}: {GREEN}{hash_val}{RESET}\n")

if __name__ == '__main__':
    main()
