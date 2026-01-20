#!/usr/bin/env python3
"""
Wordlist Generator - Create Custom Wordlists for Password Cracking
For authorized security testing only

QUICK START:
    ./wordlist_gen.py --target "John Smith 1990" -o wordlist.txt
    ./wordlist_gen.py --combine words.txt --rules
    ./wordlist_gen.py --profile -o custom.txt
"""

import argparse
import sys
import os
import itertools
from typing import List, Set, Generator
from datetime import datetime

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

# Common password patterns
LEET_MAP = {
    'a': ['a', '@', '4'],
    'b': ['b', '8'],
    'e': ['e', '3'],
    'g': ['g', '9'],
    'i': ['i', '1', '!'],
    'l': ['l', '1', '|'],
    'o': ['o', '0'],
    's': ['s', '$', '5'],
    't': ['t', '7', '+'],
    'z': ['z', '2'],
}

COMMON_SUFFIXES = [
    '', '!', '!!', '!!!', '.', '?',
    '1', '12', '123', '1234', '12345', '123456',
    '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12',
    '69', '99', '00', '01', '21', '22', '23', '24', '25',
    '1!', '123!', '@1', '@123', '#1', '*',
    '2020', '2021', '2022', '2023', '2024', '2025', '2026',
]

COMMON_PREFIXES = [
    '', '1', '12', '123', '@', '!', '*', '#',
]

COMMON_WORDS = [
    'password', 'pass', 'qwerty', 'abc', 'letmein', 'welcome',
    'admin', 'user', 'login', 'test', 'guest', 'master',
    'love', 'baby', 'angel', 'princess', 'dragon', 'monkey',
    'summer', 'winter', 'spring', 'football', 'baseball', 'soccer',
    'iloveyou', 'sunshine', 'shadow', 'superman', 'batman',
]

HELP_TEXT = """
================================================================================
                    WORDLIST GENERATOR - COMPREHENSIVE GUIDE
                    Custom Password Lists for Targeted Cracking
================================================================================

WHY CUSTOM WORDLISTS?
---------------------
Generic wordlists like rockyou.txt contain millions of leaked passwords,
but they're... generic. A TARGETED wordlist based on what you know about
the target is often far more effective.

THE PSYCHOLOGY OF PASSWORDS:
  - People use personal information they can remember
  - Names of family, pets, significant others
  - Birthdays, anniversaries, important years
  - Favorite sports teams, bands, movies
  - Company names (especially for work accounts)
  - Keyboard patterns and simple modifications

EXAMPLE: If target is "John Smith, born 1985, likes baseball, works at Acme"
  Custom list might include:
    john, John, JOHN, john85, John1985, johnsmith, smithjohn
    baseball, Baseball!, baseball123, Acme2024, AcmeJohn
    John@Acme, smith85!, BaseballJohn, etc.

WHY THIS MATTERS: A focused 10,000-word custom list often cracks passwords
that a generic 14-million-word list misses.


GATHERING INTEL FOR WORDLISTS
-----------------------------
Before generating, OSINT (Open Source Intelligence) is your friend:

SOCIAL MEDIA:
  - Facebook: Names, relationships, birthdays, interests, pets
  - LinkedIn: Job history, company names, professional interests
  - Twitter/X: Interests, opinions, events they care about
  - Instagram: Pet names, locations, hobbies, partner names

PUBLIC RECORDS:
  - Address (street names become passwords)
  - Property records
  - Marriage/divorce records (spouse names, anniversary dates)

COMPANY INFO:
  - Company name and variations
  - Product names
  - Office locations
  - Company slogan or values

THE TARGET'S WORLD:
  - Local sports teams
  - Local landmarks
  - School names
  - Car model (people love their cars)


UNDERSTANDING MUTATIONS
-----------------------
Raw words are rarely used as-is. People apply MUTATIONS:

CASE VARIATIONS:
  john -> John, JOHN, jOHN, JoHn

COMMON SUFFIXES (most important):
  john -> john1, john123, john!, john2024, john@123

COMMON PREFIXES:
  john -> 123john, @john, 1john

LEET SPEAK (character substitution):
  password -> p@ssw0rd, p4ssword, pa$$word
  a->@ or 4, e->3, i->1 or !, o->0, s->$ or 5

YEAR PATTERNS:
  john -> john2024, john2023, john24, john23

KEYBOARD PATTERNS ADDED:
  john -> john123, johnqwerty, john!!!


COMMON PASSWORD PATTERNS
------------------------
Understanding patterns helps you generate effective lists:

PATTERN 1: Word + Numbers
  Password123, Summer2024, John1985
  → Use --suffix to add number combinations

PATTERN 2: Capitalized + Special + Numbers
  Password1!, Summer2024$, Admin123!
  → Use --case --suffix together

PATTERN 3: Leet + Numbers
  P@ssw0rd123, $umm3r2024
  → Use --leet --suffix together

PATTERN 4: Concatenation
  JohnSmith, BaseballFan, AcmeAdmin
  → Tool automatically combines base words

PATTERN 5: Keyboard Shifts
  qwerty, 123456, qwerty123
  → Include keyboard patterns in base words

PATTERN 6: Seasonal + Year
  Summer2024!, Winter2023, Fall2024
  → Common for passwords that require periodic changes


SCENARIO-BASED USAGE
--------------------

SCENARIO: Know target's name and birth year
COMMAND:  ./wordlist_gen.py --target "john smith 1985" -o john.txt
WHY:      Creates combinations of john, smith, 1985
          Applies common mutations automatically
NEXT:     Use with bruteforce.py or hash_toolkit.py crack
          Add more keywords if these don't work


SCENARIO: Comprehensive target profiling
COMMAND:  ./wordlist_gen.py --profile -o target_full.txt
WHY:      Interactive mode asks about all relevant info
          Most thorough approach for important targets
NEXT:     Review generated list, remove unlikely entries
          May need to split into smaller focused lists


SCENARIO: Company/organization passwords
COMMAND:  ./wordlist_gen.py --target "acme corp 2024" \\
              --keywords "product1,product2,NYC" -o company.txt
WHY:      Corporate passwords often include company info
          Products, locations, founding year
NEXT:     Great for testing default/initial passwords
          Works accounts often follow patterns


SCENARIO: Have base words, need mutations
COMMAND:  ./wordlist_gen.py --combine seeds.txt --rules --leet -o mutated.txt
WHY:      Takes your curated base words
          Applies all common password transformations
NEXT:     Can create large lists from small seeds
          Balance size vs. time to crack


SCENARIO: Testing password complexity requirements
COMMAND:  ./wordlist_gen.py --pattern "?u?l?l?l?l?d?d?s" --limit 100000
WHY:      Generates passwords matching specific pattern
          Uppercase, 4 lowercase, 2 digits, 1 special
          Matches common complexity requirements
NEXT:     Useful when you know the password policy
          Much faster than random brute force


SCENARIO: Quick common password variations
COMMAND:  ./wordlist_gen.py --target "password admin welcome" \\
              --rules -o common_variations.txt
WHY:      Takes common base passwords
          Generates all likely variations
NEXT:     Fast first attempt before deeper cracking
          Often catches lazy password choices


PATTERN SYNTAX
--------------
For --pattern option, use these placeholders:

  ?l = lowercase letter (a-z)
  ?u = uppercase letter (A-Z)
  ?d = digit (0-9)
  ?s = special character (!@#$%^&*...)
  ?a = any alphanumeric + common special

EXAMPLES:
  "?u?l?l?l?l?d?d"        Abcde12     (caps + lower + digits)
  "Password?d?d?d"        Password123 (literal + digits)
  "?u?l?l?l?l?l?d?s"      Summer2!    (common corporate pattern)
  "?d?d?d?d?d?d"          123456      (6-digit PIN)

WARNING: Patterns can generate HUGE lists. Always use --limit.
  "?a?a?a?a?a?a" = billions of combinations


WORDLIST SIZE STRATEGY
----------------------

SMALL FOCUSED (100-1000 words):
  - Use when: Quick first attempt, specific target intel
  - Method: --target with known info, minimal mutations
  - Crack time: Seconds

MEDIUM TARGETED (1000-50000 words):
  - Use when: Standard targeted attack
  - Method: --profile or --target with --rules
  - Crack time: Minutes to hours (depending on hash)

LARGE COMPREHENSIVE (50000-500000 words):
  - Use when: Important target, have time
  - Method: --profile with --leet --suffix --prefix
  - Crack time: Hours to days

REMEMBER: For bcrypt or SHA512crypt hashes, even "small" lists take
significant time because the hash algorithm is intentionally slow.


COMBINING WITH OTHER TOOLS
--------------------------

WORKFLOW:
  1. Gather OSINT about target
  2. Generate wordlist: ./wordlist_gen.py --profile -o target.txt
  3. Crack hashes: ./hash_toolkit.py crack HASH -w target.txt
  4. Or bruteforce: ./bruteforce.py -u URL -U admin -P target.txt

FOR GPU CRACKING (hashcat):
  1. Generate base list here
  2. Use hashcat with rules: hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule
  3. Hashcat rules add even more mutations efficiently


COMMON MISTAKES TO AVOID
------------------------
1. Making wordlist too large (quality > quantity)
2. Not researching target before generating
3. Forgetting common suffixes (most passwords end with numbers/!)
4. Ignoring years (2024, 24, 2023 are everywhere)
5. Not considering keyboard layout (qwerty adjacent to password)
6. Creating duplicates (wastes cracking time)


COMMAND REFERENCE
-----------------
INPUT:
  --target "words"       Space-separated target info
  --profile              Interactive profiling mode
  --combine FILE         Base words from file
  --pattern "?l?d..."    Pattern-based generation

TARGET INFO:
  --name "name"          Target's name
  --birth "year"         Birth year
  --company "name"       Company/employer
  --keywords "x,y,z"     Additional keywords

MUTATIONS:
  --rules                Apply standard password rules
  --leet                 Apply l33t speak substitutions
  --case                 Apply case variations
  --suffix               Add common suffixes
  --prefix               Add common prefixes
  --years                Add recent years

OUTPUT:
  -o, --output FILE      Save wordlist to file
  --min NUM              Minimum password length (default: 6)
  --max NUM              Maximum password length (default: 16)
  --limit NUM            Maximum passwords to generate
================================================================================
"""

def banner():
    print(f"""{C.C}
 _    __              ____    _      __
| |  / /___  _________/ / /   (_)____/ /_
| | /| / / __ \\/ ___/ __  / /   / / ___/ __/
| |/ |/ / /_/ / /  / /_/ / /___/ (__  ) /_
|__/|__/\\____/_/   \\__,_/_____/_/____/\\__/
{C.E}{C.Y}Custom Wordlist Generator{C.E}
""")

def apply_case_variations(word: str) -> Set[str]:
    """Generate case variations"""
    variations = {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.title(),
        word.swapcase(),
    }

    # First letter upper, rest lower
    if len(word) > 0:
        variations.add(word[0].upper() + word[1:].lower())

    return variations

def apply_leet_speak(word: str, max_variations: int = 100) -> Set[str]:
    """Apply l33t speak substitutions"""
    variations = set()
    word_lower = word.lower()

    # Find replaceable characters
    replaceable = [(i, c) for i, c in enumerate(word_lower) if c in LEET_MAP]

    if not replaceable:
        return {word}

    # Limit combinations
    num_to_replace = min(len(replaceable), 3)

    for r in range(1, num_to_replace + 1):
        for positions in itertools.combinations(range(len(replaceable)), r):
            chars_at_positions = [replaceable[p] for p in positions]

            replacements = [LEET_MAP[c] for _, c in chars_at_positions]
            for combo in itertools.product(*replacements):
                new_word = list(word_lower)
                for idx, (pos, _) in enumerate(chars_at_positions):
                    new_word[pos] = combo[idx]
                variations.add(''.join(new_word))

                if len(variations) >= max_variations:
                    return variations

    return variations

def apply_suffix(word: str, suffixes: List[str] = None) -> Set[str]:
    """Add common suffixes"""
    if suffixes is None:
        suffixes = COMMON_SUFFIXES
    return {word + s for s in suffixes}

def apply_prefix(word: str, prefixes: List[str] = None) -> Set[str]:
    """Add common prefixes"""
    if prefixes is None:
        prefixes = COMMON_PREFIXES
    return {p + word for p in prefixes}

def mutate_word(word: str, rules: bool = True, leet: bool = False,
                case: bool = True, suffix: bool = True, prefix: bool = False) -> Set[str]:
    """Apply all selected mutations to a word"""
    results = {word}

    if case:
        new_results = set()
        for w in results:
            new_results.update(apply_case_variations(w))
        results = new_results

    if leet:
        new_results = set()
        for w in results:
            new_results.update(apply_leet_speak(w))
        results = new_results

    if prefix:
        new_results = set()
        for w in results:
            new_results.update(apply_prefix(w))
        results = new_results

    if suffix:
        new_results = set()
        for w in results:
            new_results.update(apply_suffix(w))
        results = new_results

    return results

def generate_from_pattern(pattern: str, limit: int = 100000) -> Generator[str, None, None]:
    """Generate passwords from pattern"""
    import string

    charset = {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?',
        '?a': string.ascii_letters + string.digits + '!@#$%^&*',
    }

    # Parse pattern
    parts = []
    i = 0
    while i < len(pattern):
        if i + 1 < len(pattern) and pattern[i:i+2] in charset:
            parts.append(charset[pattern[i:i+2]])
            i += 2
        else:
            parts.append(pattern[i])
            i += 1

    # Generate combinations
    count = 0
    for combo in itertools.product(*parts):
        yield ''.join(combo)
        count += 1
        if count >= limit:
            break

def profile_target() -> List[str]:
    """Interactive profiling mode"""
    print(f"\n{C.M}=== Target Profiling ==={C.E}")
    print(f"{C.B}Enter information about the target. Press Enter to skip.{C.E}\n")

    words = []

    # Collect info
    questions = [
        ("First name", "name"),
        ("Last name", "name"),
        ("Nickname/Username", "name"),
        ("Birth year (YYYY)", "year"),
        ("Birth month (MM)", "month"),
        ("Birth day (DD)", "day"),
        ("Partner/Spouse name", "name"),
        ("Child's name", "name"),
        ("Pet's name", "name"),
        ("Company/Employer", "name"),
        ("Favorite sports team", "name"),
        ("Favorite band/artist", "name"),
        ("City/Town", "name"),
        ("Street name", "name"),
        ("Other keywords (comma-separated)", "keywords"),
    ]

    for question, q_type in questions:
        answer = input(f"{C.Y}{question}:{C.E} ").strip()
        if answer:
            if q_type == 'keywords':
                words.extend([w.strip() for w in answer.split(',')])
            else:
                words.append(answer)

    return words

def generate_wordlist(base_words: List[str], rules: bool = True,
                      leet: bool = False, case: bool = True,
                      suffix: bool = True, prefix: bool = False,
                      min_len: int = 6, max_len: int = 16,
                      limit: int = None) -> Set[str]:
    """Generate full wordlist from base words"""
    wordlist = set()

    # Add base words
    wordlist.update(base_words)

    # Add common words
    wordlist.update(COMMON_WORDS)

    # Create combinations of base words
    for w1, w2 in itertools.combinations(base_words, 2):
        wordlist.add(w1 + w2)
        wordlist.add(w2 + w1)
        wordlist.add(w1.capitalize() + w2.capitalize())

    # Apply mutations
    mutated = set()
    for word in wordlist:
        mutations = mutate_word(word, rules, leet, case, suffix, prefix)
        mutated.update(mutations)

    # Filter by length
    filtered = {w for w in mutated if min_len <= len(w) <= max_len}

    # Apply limit
    if limit and len(filtered) > limit:
        filtered = set(list(filtered)[:limit])

    return filtered

def main():
    parser = argparse.ArgumentParser(
        description='Wordlist Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Input modes
    parser.add_argument('--target', help='Target info (space-separated)')
    parser.add_argument('--profile', action='store_true', help='Interactive profiling')
    parser.add_argument('--combine', help='File with base words to mutate')
    parser.add_argument('--pattern', help='Pattern to generate from')

    # Individual fields
    parser.add_argument('--name', help='Target name')
    parser.add_argument('--birth', help='Birth year')
    parser.add_argument('--company', help='Company name')
    parser.add_argument('--keywords', help='Comma-separated keywords')

    # Mutation options
    parser.add_argument('--rules', action='store_true', help='Apply password rules')
    parser.add_argument('--leet', action='store_true', help='Apply l33t speak')
    parser.add_argument('--case', action='store_true', help='Apply case variations')
    parser.add_argument('--suffix', action='store_true', help='Add common suffixes')
    parser.add_argument('--prefix', action='store_true', help='Add common prefixes')
    parser.add_argument('--years', action='store_true', help='Add recent years')

    # Output options
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--min', type=int, default=6, help='Min password length')
    parser.add_argument('--max', type=int, default=16, help='Max password length')
    parser.add_argument('--limit', type=int, help='Max passwords to generate')

    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    banner()

    base_words = []

    # Collect base words from various sources
    if args.profile:
        base_words = profile_target()
    elif args.target:
        base_words = args.target.split()
    elif args.combine:
        try:
            with open(args.combine, 'r') as f:
                base_words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{C.R}[!]{C.E} Error reading file: {e}")
            return
    elif args.pattern:
        print(f"{C.B}[*]{C.E} Generating from pattern: {C.Y}{args.pattern}{C.E}")
        limit = args.limit or 100000
        passwords = list(generate_from_pattern(args.pattern, limit))
        print(f"{C.G}[+]{C.E} Generated {len(passwords)} passwords")

        if args.output:
            with open(args.output, 'w') as f:
                for p in passwords:
                    f.write(p + '\n')
            print(f"{C.B}[*]{C.E} Saved to {args.output}")
        else:
            for p in passwords[:20]:
                print(p)
            if len(passwords) > 20:
                print(f"... and {len(passwords) - 20} more")
        return

    # Add individual fields
    if args.name:
        base_words.extend(args.name.split())
    if args.birth:
        base_words.append(args.birth)
    if args.company:
        base_words.append(args.company)
    if args.keywords:
        base_words.extend(args.keywords.split(','))

    if not base_words:
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    print(f"{C.B}[*]{C.E} Base words: {C.Y}{', '.join(base_words)}{C.E}")

    # Determine mutations
    use_rules = args.rules or (not any([args.leet, args.case, args.suffix, args.prefix]))
    use_suffix = args.suffix or use_rules
    use_case = args.case or use_rules

    # Generate wordlist
    print(f"{C.B}[*]{C.E} Generating wordlist...")
    wordlist = generate_wordlist(
        base_words,
        rules=use_rules,
        leet=args.leet,
        case=use_case,
        suffix=use_suffix,
        prefix=args.prefix,
        min_len=args.min,
        max_len=args.max,
        limit=args.limit
    )

    print(f"{C.G}[+]{C.E} Generated {C.Y}{len(wordlist)}{C.E} passwords")

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            for word in sorted(wordlist):
                f.write(word + '\n')
        print(f"{C.B}[*]{C.E} Saved to {args.output}")
    else:
        # Print sample
        sample = sorted(wordlist)[:30]
        print(f"\n{C.M}Sample passwords:{C.E}")
        for p in sample:
            print(f"  {p}")
        if len(wordlist) > 30:
            print(f"  ... and {len(wordlist) - 30} more")
        print(f"\n{C.Y}Tip:{C.E} Use -o filename.txt to save full wordlist")

if __name__ == '__main__':
    main()
