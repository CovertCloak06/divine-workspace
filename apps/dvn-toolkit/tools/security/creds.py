#!/usr/bin/env python3
"""
Credential Checker - Check for leaked credentials, weak passwords, and common patterns
Usage: creds <password/email> [--check-breach] [--strength] [--generate]
"""

import argparse
import hashlib
import re
import string
import math
import secrets
from urllib.request import urlopen, Request
from urllib.error import URLError

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common password patterns
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
    'princess', 'admin', 'welcome', 'shadow', 'ashley', 'football', 'jesus',
    'michael', 'ninja', 'mustang', 'password1', 'password123', 'letmein',
    'login', 'starwars', 'passw0rd', 'solo', 'access', 'flower', 'hottie',
    'loveme', 'zaq1zaq1', 'lovely', 'secret', 'hello', 'charlie', 'donald'
]

COMMON_PATTERNS = [
    (r'^[a-z]+$', 'lowercase only'),
    (r'^[A-Z]+$', 'uppercase only'),
    (r'^[0-9]+$', 'numbers only'),
    (r'^[a-zA-Z]+$', 'letters only'),
    (r'^(.)\1+$', 'repeated character'),
    (r'^(012|123|234|345|456|567|678|789)+', 'sequential numbers'),
    (r'^(abc|bcd|cde|def|efg|fgh|ghi)+', 'sequential letters'),
    (r'^(qwert|asdf|zxcv)', 'keyboard pattern'),
    (r'\d{4}$', 'ends with year/number'),
    (r'^[a-zA-Z]+\d{1,4}$', 'word + numbers'),
]

def check_hibp(password):
    """Check password against Have I Been Pwned database"""
    # Hash the password with SHA1
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = Request(url, headers={'User-Agent': 'CredChecker/1.0'})
        with urlopen(req, timeout=10) as resp:
            hashes = resp.read().decode()

            for line in hashes.split('\n'):
                if ':' in line:
                    hash_suffix, count = line.strip().split(':')
                    if hash_suffix == suffix:
                        return int(count)
        return 0
    except Exception as e:
        return -1  # Error checking

def check_email_breach(email):
    """Check if email appears in known breaches (using HIBP)"""
    # Note: HIBP requires API key for email lookup
    # This is a placeholder - would need API key for real implementation
    return None

def calculate_entropy(password):
    """Calculate password entropy"""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)

def analyze_password(password):
    """Analyze password strength and patterns"""
    issues = []
    score = 100

    # Length check
    if len(password) < 8:
        issues.append(("Length < 8 characters", -30))
    elif len(password) < 12:
        issues.append(("Length < 12 characters", -10))
    elif len(password) >= 16:
        issues.append(("Good length (16+)", 10))

    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_special])
    if variety < 2:
        issues.append(("Low character variety", -20))
    elif variety >= 4:
        issues.append(("Good character variety", 10))

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        issues.append(("Common password", -50))

    # Pattern checks
    for pattern, desc in COMMON_PATTERNS:
        if re.search(pattern, password, re.I):
            issues.append((f"Pattern: {desc}", -15))
            break

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append(("Repeated characters", -10))

    # Dictionary words (basic check)
    common_words = ['password', 'admin', 'user', 'login', 'welcome', 'test']
    for word in common_words:
        if word in password.lower():
            issues.append((f"Contains common word: {word}", -15))
            break

    # Calculate final score
    for issue, penalty in issues:
        score += penalty

    score = max(0, min(100, score))

    return score, issues

def strength_rating(score):
    """Convert score to rating"""
    if score < 20:
        return "Very Weak", RED
    elif score < 40:
        return "Weak", RED
    elif score < 60:
        return "Fair", YELLOW
    elif score < 80:
        return "Strong", GREEN
    else:
        return "Very Strong", GREEN

def generate_password(length=16, use_special=True):
    """Generate a secure password"""
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += "!@#$%^&*"

    # Ensure at least one of each type
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_special:
        password.append(secrets.choice("!@#$%^&*"))

    # Fill the rest
    password.extend(secrets.choice(chars) for _ in range(length - len(password)))

    # Shuffle
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)

def main():
    parser = argparse.ArgumentParser(description='Credential Checker')
    parser.add_argument('input', nargs='?', help='Password or email to check')
    parser.add_argument('--check-breach', '-b', action='store_true', help='Check against breach database')
    parser.add_argument('--strength', '-s', action='store_true', help='Analyze password strength')
    parser.add_argument('--generate', '-g', action='store_true', help='Generate secure password')
    parser.add_argument('--length', '-l', type=int, default=16, help='Generated password length')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}Credential Checker{RESET}\n")

    # Generate password
    if args.generate:
        print(f"{BOLD}Generated Passwords:{RESET}")
        for i in range(5):
            pwd = generate_password(args.length)
            entropy = calculate_entropy(pwd)
            print(f"  {GREEN}{pwd}{RESET}  ({entropy:.0f} bits)")
        print()
        return

    if not args.input:
        print(f"{RED}No input provided. Use --help for options.{RESET}")
        return

    # Determine if email or password
    is_email = '@' in args.input

    if is_email:
        print(f"{BOLD}Email Analysis:{RESET} {args.input}")
        # Email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, args.input):
            print(f"  {GREEN}Valid format{RESET}")
        else:
            print(f"  {RED}Invalid format{RESET}")

        # Domain check
        domain = args.input.split('@')[1]
        print(f"  Domain: {domain}")

        # Check disposable email domains
        disposable = ['tempmail', 'throwaway', 'mailinator', 'guerrilla', '10minute']
        if any(d in domain.lower() for d in disposable):
            print(f"  {YELLOW}Warning: Possible disposable email{RESET}")
    else:
        password = args.input
        print(f"{BOLD}Password Analysis:{RESET}")
        print(f"  Length: {len(password)}")

        # Entropy
        entropy = calculate_entropy(password)
        print(f"  Entropy: {entropy:.1f} bits")

        # Strength analysis
        if args.strength or True:  # Always show strength
            score, issues = analyze_password(password)
            rating, color = strength_rating(score)

            print(f"  Strength: {color}{rating} ({score}/100){RESET}")

            print(f"\n{BOLD}Analysis:{RESET}")
            for issue, penalty in issues:
                if penalty > 0:
                    print(f"  {GREEN}+{RESET} {issue}")
                else:
                    print(f"  {RED}-{RESET} {issue}")

        # Breach check
        if args.check_breach:
            print(f"\n{BOLD}Breach Database Check:{RESET}")
            count = check_hibp(password)
            if count > 0:
                print(f"  {RED}PWNED! Found {count:,} times in breaches{RESET}")
                print(f"  {YELLOW}This password should NOT be used{RESET}")
            elif count == 0:
                print(f"  {GREEN}Not found in breach database{RESET}")
            else:
                print(f"  {YELLOW}Could not check (API error){RESET}")

    print()

if __name__ == '__main__':
    main()
