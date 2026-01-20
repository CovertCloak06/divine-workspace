#!/usr/bin/env python3
"""
Hash Toolkit - Hash Identification, Generation, and Cracking
For authorized security testing only

QUICK START:
    ./hash_toolkit.py identify "5f4dcc3b5aa765d61d8327deb882cf99"
    ./hash_toolkit.py generate "password" --all
    ./hash_toolkit.py crack "hash" -w wordlist.txt
"""

import argparse
import sys
import os
import hashlib
import re
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    E = '\033[0m'
    BOLD = '\033[1m'

# Hash patterns for identification
HASH_PATTERNS = {
    'MD5': {
        'regex': r'^[a-fA-F0-9]{32}$',
        'length': 32,
        'hashcat': 0,
        'john': 'raw-md5'
    },
    'SHA1': {
        'regex': r'^[a-fA-F0-9]{40}$',
        'length': 40,
        'hashcat': 100,
        'john': 'raw-sha1'
    },
    'SHA256': {
        'regex': r'^[a-fA-F0-9]{64}$',
        'length': 64,
        'hashcat': 1400,
        'john': 'raw-sha256'
    },
    'SHA512': {
        'regex': r'^[a-fA-F0-9]{128}$',
        'length': 128,
        'hashcat': 1700,
        'john': 'raw-sha512'
    },
    'SHA384': {
        'regex': r'^[a-fA-F0-9]{96}$',
        'length': 96,
        'hashcat': 10800,
        'john': 'raw-sha384'
    },
    'MD4': {
        'regex': r'^[a-fA-F0-9]{32}$',
        'length': 32,
        'hashcat': 900,
        'john': 'raw-md4'
    },
    'NTLM': {
        'regex': r'^[a-fA-F0-9]{32}$',
        'length': 32,
        'hashcat': 1000,
        'john': 'nt'
    },
    'MySQL323': {
        'regex': r'^[a-fA-F0-9]{16}$',
        'length': 16,
        'hashcat': 200,
        'john': 'mysql'
    },
    'MySQL5': {
        'regex': r'^\*[A-F0-9]{40}$',
        'length': 41,
        'hashcat': 300,
        'john': 'mysql-sha1'
    },
    'bcrypt': {
        'regex': r'^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$',
        'length': 60,
        'hashcat': 3200,
        'john': 'bcrypt'
    },
    'SHA512crypt': {
        'regex': r'^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$',
        'length': None,
        'hashcat': 1800,
        'john': 'sha512crypt'
    },
    'SHA256crypt': {
        'regex': r'^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$',
        'length': None,
        'hashcat': 7400,
        'john': 'sha256crypt'
    },
    'MD5crypt': {
        'regex': r'^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$',
        'length': None,
        'hashcat': 500,
        'john': 'md5crypt'
    },
    'APR1': {
        'regex': r'^\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$',
        'length': None,
        'hashcat': 1600,
        'john': 'md5crypt'
    },
    'DES': {
        'regex': r'^[./A-Za-z0-9]{13}$',
        'length': 13,
        'hashcat': 1500,
        'john': 'descrypt'
    },
    'LM': {
        'regex': r'^[A-Fa-f0-9]{32}$',
        'length': 32,
        'hashcat': 3000,
        'john': 'lm'
    },
    'RIPEMD160': {
        'regex': r'^[a-fA-F0-9]{40}$',
        'length': 40,
        'hashcat': 6000,
        'john': 'ripemd-160'
    },
    'Whirlpool': {
        'regex': r'^[a-fA-F0-9]{128}$',
        'length': 128,
        'hashcat': 6100,
        'john': 'whirlpool'
    },
    'Base64': {
        'regex': r'^[A-Za-z0-9+/]+={0,2}$',
        'length': None,
        'hashcat': None,
        'john': None
    },
}

HELP_TEXT = """
================================================================================
                    HASH TOOLKIT - COMPREHENSIVE GUIDE
                    Hash Identification, Generation, and Cracking
================================================================================

WHAT ARE HASHES?
----------------
A hash is a one-way mathematical function that converts any input into a
fixed-length string of characters. The key properties:

  1. ONE-WAY: You cannot reverse a hash to get the original input
  2. DETERMINISTIC: Same input always produces same hash
  3. FIXED LENGTH: Output is always same size regardless of input size
  4. AVALANCHE: Tiny input change = completely different hash

EXAMPLE:
  "password"  ->  5f4dcc3b5aa765d61d8327deb882cf99 (MD5)
  "password1" ->  7c6a180b36896a65c3ceea3e3c14d5e7 (MD5)
  Notice how adding "1" completely changed the hash

WHY THIS MATTERS: Passwords are never stored in plain text - they're hashed.
When you find password hashes (from databases, config files, /etc/shadow),
you need to crack them to get the actual passwords.


UNDERSTANDING HASH TYPES
------------------------

MD5 (Message Digest 5)
  LENGTH: 32 hexadecimal characters
  EXAMPLE: 5f4dcc3b5aa765d61d8327deb882cf99
  SECURITY: BROKEN - fast to compute, vulnerable to collisions
  COMMON IN: Legacy systems, MySQL (old), MD5 file checksums
  CRACK SPEED: Very fast (~10 billion/sec on GPU)
  HASHCAT MODE: 0

SHA1 (Secure Hash Algorithm 1)
  LENGTH: 40 hexadecimal characters
  EXAMPLE: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
  SECURITY: DEPRECATED - collision attacks demonstrated
  COMMON IN: Git commits, older certificates
  CRACK SPEED: Fast (~3 billion/sec on GPU)
  HASHCAT MODE: 100

SHA256 (SHA-2 Family)
  LENGTH: 64 hexadecimal characters
  EXAMPLE: 5e884898da28047d9169e1...c4afb8c11a268f417ddb7
  SECURITY: Currently secure for most uses
  COMMON IN: Modern applications, blockchain, file integrity
  CRACK SPEED: Medium (~1 billion/sec on GPU)
  HASHCAT MODE: 1400

SHA512
  LENGTH: 128 hexadecimal characters
  SECURITY: Very secure
  COMMON IN: High-security applications
  CRACK SPEED: Slower than SHA256
  HASHCAT MODE: 1700

NTLM (Windows)
  LENGTH: 32 hexadecimal characters (same as MD5!)
  EXAMPLE: a4f49c406510bdcab6824ee7c30fd852
  SECURITY: Weak - no salting, fast to crack
  COMMON IN: Windows password storage, Active Directory
  CRACK SPEED: Very fast (~25 billion/sec on GPU)
  HASHCAT MODE: 1000
  NOTE: Looks like MD5 but different algorithm

bcrypt
  LENGTH: 60 characters, starts with $2a$, $2b$, or $2y$
  EXAMPLE: $2a$10$N9qo8uLOickgx2ZMRZoMy...
  SECURITY: EXCELLENT - slow by design, includes salt
  COMMON IN: Modern web apps, Django, Rails
  CRACK SPEED: Very slow (~50k/sec on GPU) - INTENTIONAL
  HASHCAT MODE: 3200

MD5crypt ($1$)
  FORMAT: $1$<salt>$<hash>
  EXAMPLE: $1$xyz$hashhashhashhashhashhash
  SECURITY: Outdated but stronger than plain MD5
  COMMON IN: Old Linux /etc/shadow
  HASHCAT MODE: 500

SHA512crypt ($6$)
  FORMAT: $6$<salt>$<hash>
  EXAMPLE: $6$rounds=5000$saltsalt$hashhash...
  SECURITY: Good - slow and salted
  COMMON IN: Modern Linux /etc/shadow
  HASHCAT MODE: 1800


HOW HASH CRACKING WORKS
-----------------------
Since hashes can't be reversed, we crack them by GUESSING:

1. DICTIONARY ATTACK
   - Try every word in a wordlist
   - Hash each word, compare to target
   - Fast if password is in wordlist
   - rockyou.txt has 14 million passwords

2. BRUTE FORCE
   - Try every possible combination
   - a, b, c... aa, ab, ac... aaa, aab...
   - Guaranteed to find password eventually
   - Gets exponentially slower with length

3. RULE-BASED
   - Take dictionary words, apply transformations
   - password -> Password, password1, P@ssw0rd!, etc.
   - Catches common password patterns

4. RAINBOW TABLES
   - Pre-computed hash->password lookup tables
   - Very fast but only works without salts
   - Defeated by salting


THE IMPORTANCE OF SALTING
-------------------------
A SALT is random data added before hashing:

WITHOUT SALT:
  hash("password") = 5f4dcc3b...
  Every "password" produces same hash
  Attackers can pre-compute or use rainbow tables

WITH SALT:
  hash("xyz" + "password") = different_hash
  hash("abc" + "password") = another_hash
  Same password, different salts = different hashes
  Must crack each hash individually

This is why bcrypt and SHA512crypt are strong - they include salts
and are intentionally slow to compute.


SCENARIO-BASED USAGE
--------------------

SCENARIO: Found a hash, don't know what type
COMMAND:  ./hash_toolkit.py identify "5f4dcc3b5aa765d61d8327deb882cf99"
WHY:      First step is always identification
          Tool shows possible types and hashcat/john modes
NEXT:     If MD5/NTLM (same length), try both when cracking
          Check context for clues (Windows = NTLM, web = MD5)


SCENARIO: Dump of hashes from database
COMMAND:  ./hash_toolkit.py identify -f hashes.txt
WHY:      Batch identification saves time
          Shows which cracking approach to use
NEXT:     For serious cracking, use hashcat/john (much faster)
          This tool shows the correct modes to use


SCENARIO: Need to verify a suspected password
COMMAND:  ./hash_toolkit.py compare "password123" "hash_here" -t md5
WHY:      Quick check without full cracking
          Useful when you have a guess
NEXT:     If match, you've found the password
          If not, proceed to wordlist cracking


SCENARIO: Quick crack attempt with wordlist
COMMAND:  ./hash_toolkit.py crack "5f4dcc3b..." -w /path/to/rockyou.txt
WHY:      Dictionary attack against common passwords
          This tool is slower than hashcat but convenient
NEXT:     If not found, use hashcat/john with rules
          Try specialized wordlists


SCENARIO: Generate hashes for testing
COMMAND:  ./hash_toolkit.py generate "MyTestPassword" --all
WHY:      See what different hash types look like
          Useful for understanding and verification
NEXT:     Use these to test your cracking setup
          Compare against hashes you're analyzing


WHERE TO FIND HASHES
--------------------

LINUX SYSTEMS:
  /etc/shadow - User password hashes (requires root)
  Format: username:$type$salt$hash:...
  Types: $1$ = MD5crypt, $5$ = SHA256crypt, $6$ = SHA512crypt

WINDOWS SYSTEMS:
  SAM database - Local account hashes
  NTDS.dit - Active Directory hashes
  Tools: mimikatz, secretsdump, hashdump

DATABASES:
  User tables often have password columns
  Check for columns named: password, pass, pwd, hash
  May be plain MD5/SHA or application-specific

WEB APPLICATIONS:
  Config files, database dumps
  WordPress: wp_users table, phpass hashes
  Drupal, Joomla: Similar user tables

NETWORK CAPTURES:
  NTLM hashes in SMB traffic
  HTTP Basic auth (if using hashes)


SERIOUS CRACKING: HASHCAT & JOHN
--------------------------------
This tool is for quick work. For serious cracking, use:

HASHCAT (GPU-accelerated):
  hashcat -m 0 hash.txt wordlist.txt         # MD5
  hashcat -m 1000 hash.txt wordlist.txt      # NTLM
  hashcat -m 1800 hash.txt wordlist.txt      # SHA512crypt
  hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule  # With rules

JOHN THE RIPPER:
  john --format=raw-md5 hash.txt
  john --format=nt hash.txt
  john --wordlist=rockyou.txt hash.txt

The tool shows hashcat modes and john formats in identification results.


COMMON MISTAKES TO AVOID
------------------------
1. Not identifying hash type first
2. Using wrong hash type when cracking
3. Expecting to crack bcrypt quickly (it's designed to be slow)
4. Not using rules with dictionary attacks
5. Confusing MD5 and NTLM (same length, different algorithms)
6. Forgetting about salts when building rainbow tables


WORDLIST LOCATIONS
------------------
Common wordlists on Kali/security distros:
  /usr/share/wordlists/rockyou.txt           (14M passwords)
  /usr/share/seclists/Passwords/             (many specialized lists)
  /usr/share/wordlists/fasttrack.txt         (smaller, common passwords)

Generate custom wordlists:
  ./wordlist_gen.py --target "target info"


COMMAND REFERENCE
-----------------
IDENTIFY:
  ./hash_toolkit.py identify "HASH"          Identify single hash
  ./hash_toolkit.py identify -f FILE         Identify from file

GENERATE:
  ./hash_toolkit.py generate "TEXT"          Generate default hashes
  ./hash_toolkit.py generate "TEXT" --all    Generate all types
  ./hash_toolkit.py generate "TEXT" --md5    Generate specific type

CRACK:
  ./hash_toolkit.py crack "HASH" -w FILE     Crack with wordlist
  ./hash_toolkit.py crack "HASH" -w FILE -t TYPE   Specify hash type

COMPARE:
  ./hash_toolkit.py compare "TEXT" "HASH"    Check if text matches hash
  ./hash_toolkit.py compare "TEXT" "HASH" -t TYPE   Specify type
================================================================================
"""

def banner():
    print(f"""{C.C}
    __  __           __    ______            ____   _ __
   / / / /___ ______/ /_  /_  __/___  ____  / / /__(_) /_
  / /_/ / __ `/ ___/ __ \  / / / __ \/ __ \/ / //_/ / __/
 / __  / /_/ (__  ) / / / / / / /_/ / /_/ / / ,< / / /_
/_/ /_/\__,_/____/_/ /_/ /_/  \____/\____/_/_/|_/_/\__/
{C.E}{C.Y}Hash Identification, Generation & Cracking{C.E}
""")

def identify_hash(hash_string: str) -> List[Dict]:
    """Identify possible hash types"""
    matches = []
    hash_string = hash_string.strip()

    for name, info in HASH_PATTERNS.items():
        if re.match(info['regex'], hash_string):
            # For same-length hashes, we need context to distinguish
            matches.append({
                'type': name,
                'length': len(hash_string),
                'hashcat_mode': info['hashcat'],
                'john_format': info['john']
            })

    return matches

def generate_hash(plaintext: str, hash_type: str) -> Optional[str]:
    """Generate a hash from plaintext"""
    text_bytes = plaintext.encode('utf-8')

    if hash_type == 'md5':
        return hashlib.md5(text_bytes).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(text_bytes).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(text_bytes).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(text_bytes).hexdigest()
    elif hash_type == 'sha384':
        return hashlib.sha384(text_bytes).hexdigest()
    elif hash_type == 'md4':
        try:
            return hashlib.new('md4', text_bytes).hexdigest()
        except:
            return None
    elif hash_type == 'ntlm':
        # NTLM is MD4 of UTF-16LE encoded password
        try:
            return hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
        except:
            return None
    elif hash_type == 'ripemd160':
        try:
            return hashlib.new('ripemd160', text_bytes).hexdigest()
        except:
            return None

    return None

def generate_all_hashes(plaintext: str) -> Dict[str, str]:
    """Generate all supported hashes"""
    hashes = {}

    for hash_type in ['md5', 'sha1', 'sha256', 'sha512', 'sha384', 'ntlm', 'md4']:
        h = generate_hash(plaintext, hash_type)
        if h:
            hashes[hash_type.upper()] = h

    return hashes

def crack_hash(target_hash: str, wordlist_path: str, hash_type: str = None,
               threads: int = 4) -> Optional[str]:
    """Attempt to crack hash using wordlist"""

    # Auto-detect hash type if not specified
    if not hash_type:
        matches = identify_hash(target_hash)
        if matches:
            hash_type = matches[0]['type'].lower()
        else:
            print(f"{C.R}[!]{C.E} Could not identify hash type. Use -t to specify.")
            return None

    # Map hash type names
    type_map = {
        'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256',
        'sha512': 'sha512', 'ntlm': 'ntlm', 'sha384': 'sha384'
    }

    if hash_type.lower() not in type_map:
        print(f"{C.R}[!]{C.E} Unsupported hash type for cracking: {hash_type}")
        return None

    hash_func = hash_type.lower()
    target_hash = target_hash.lower()

    print(f"{C.B}[*]{C.E} Hash type: {hash_type}")
    print(f"{C.B}[*]{C.E} Loading wordlist...")

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f]
    except Exception as e:
        print(f"{C.R}[!]{C.E} Error loading wordlist: {e}")
        return None

    print(f"{C.B}[*]{C.E} Loaded {len(words)} words")
    print(f"{C.B}[*]{C.E} Cracking...")

    checked = 0
    for word in words:
        checked += 1

        h = generate_hash(word, hash_func)
        if h and h.lower() == target_hash:
            print(f"\n{C.G}[+]{C.E} CRACKED!")
            print(f"{C.G}[+]{C.E} Hash: {target_hash}")
            print(f"{C.G}[+]{C.E} Plaintext: {C.Y}{word}{C.E}")
            return word

        if checked % 100000 == 0:
            print(f"{C.B}[*]{C.E} Checked {checked}/{len(words)}...", end='\r')

    print(f"\n{C.R}[-]{C.E} Hash not cracked. Tried {len(words)} words.")
    return None

def compare_hash(plaintext: str, target_hash: str, hash_type: str = None) -> bool:
    """Compare plaintext against hash"""

    # Auto-detect if not specified
    if not hash_type:
        matches = identify_hash(target_hash)
        if matches:
            hash_type = matches[0]['type'].lower()

    if not hash_type:
        print(f"{C.R}[!]{C.E} Could not determine hash type")
        return False

    generated = generate_hash(plaintext, hash_type.lower())

    if generated and generated.lower() == target_hash.lower():
        print(f"{C.G}[+]{C.E} MATCH! '{plaintext}' produces this {hash_type.upper()} hash")
        return True
    else:
        print(f"{C.R}[-]{C.E} NO MATCH")
        if generated:
            print(f"{C.B}[*]{C.E} '{plaintext}' produces: {generated}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Hash Toolkit - Identify, Generate, and Crack Hashes',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')

    # Identify subcommand
    id_parser = subparsers.add_parser('identify', help='Identify hash type')
    id_parser.add_argument('hash', nargs='?', help='Hash to identify')
    id_parser.add_argument('-f', '--file', help='File containing hashes')

    # Generate subcommand
    gen_parser = subparsers.add_parser('generate', help='Generate hashes')
    gen_parser.add_argument('plaintext', help='Text to hash')
    gen_parser.add_argument('-a', '--all', action='store_true', help='Generate all hash types')
    gen_parser.add_argument('--md5', action='store_true', help='Generate MD5')
    gen_parser.add_argument('--sha1', action='store_true', help='Generate SHA1')
    gen_parser.add_argument('--sha256', action='store_true', help='Generate SHA256')
    gen_parser.add_argument('--sha512', action='store_true', help='Generate SHA512')
    gen_parser.add_argument('--ntlm', action='store_true', help='Generate NTLM')

    # Crack subcommand
    crack_parser = subparsers.add_parser('crack', help='Crack hash')
    crack_parser.add_argument('hash', help='Hash to crack')
    crack_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file')
    crack_parser.add_argument('-t', '--type', help='Hash type')
    crack_parser.add_argument('--threads', type=int, default=4, help='Threads')

    # Compare subcommand
    cmp_parser = subparsers.add_parser('compare', help='Compare plaintext to hash')
    cmp_parser.add_argument('plaintext', help='Plaintext to check')
    cmp_parser.add_argument('hash', help='Hash to compare against')
    cmp_parser.add_argument('-t', '--type', help='Hash type')

    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    banner()

    if not args.mode:
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    # Identify mode
    if args.mode == 'identify':
        hashes = []
        if args.hash:
            hashes = [args.hash]
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    hashes = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"{C.R}[!]{C.E} Error reading file: {e}")
                return

        for h in hashes:
            print(f"\n{C.B}[*]{C.E} Analyzing: {C.Y}{h[:50]}{'...' if len(h) > 50 else ''}{C.E}")
            matches = identify_hash(h)

            if matches:
                print(f"{C.G}[+]{C.E} Possible types:")
                for m in matches:
                    print(f"    {C.Y}{m['type']:15}{C.E} "
                          f"len={m['length']} "
                          f"hashcat={m['hashcat_mode']} "
                          f"john={m['john_format']}")
            else:
                print(f"{C.R}[-]{C.E} Unknown hash type")

    # Generate mode
    elif args.mode == 'generate':
        print(f"{C.B}[*]{C.E} Plaintext: {C.Y}{args.plaintext}{C.E}\n")

        if args.all:
            hashes = generate_all_hashes(args.plaintext)
            for name, h in hashes.items():
                print(f"{C.G}{name:10}{C.E} {h}")
        else:
            types_to_gen = []
            if args.md5: types_to_gen.append('md5')
            if args.sha1: types_to_gen.append('sha1')
            if args.sha256: types_to_gen.append('sha256')
            if args.sha512: types_to_gen.append('sha512')
            if args.ntlm: types_to_gen.append('ntlm')

            if not types_to_gen:
                types_to_gen = ['md5', 'sha256']  # Default

            for t in types_to_gen:
                h = generate_hash(args.plaintext, t)
                if h:
                    print(f"{C.G}{t.upper():10}{C.E} {h}")

    # Crack mode
    elif args.mode == 'crack':
        crack_hash(args.hash, args.wordlist, args.type, args.threads)

    # Compare mode
    elif args.mode == 'compare':
        compare_hash(args.plaintext, args.hash, args.type)

if __name__ == '__main__':
    main()
