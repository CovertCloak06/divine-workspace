#!/usr/bin/env python3
"""
Password Generator - Generate secure passwords and passphrases
Usage: password_gen.py [--length 16] [--count 5]
"""

import secrets
import string
import argparse
import math

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Word list for passphrases (common English words)
WORDLIST = [
    'apple', 'banana', 'cherry', 'dragon', 'eagle', 'forest', 'guitar', 'harbor',
    'island', 'jungle', 'knight', 'lemon', 'mountain', 'nebula', 'ocean', 'planet',
    'quantum', 'river', 'sunset', 'thunder', 'umbrella', 'violet', 'whisper', 'xenon',
    'yellow', 'zenith', 'anchor', 'breeze', 'castle', 'diamond', 'ember', 'falcon',
    'glacier', 'horizon', 'ivory', 'jasmine', 'karma', 'lantern', 'marble', 'nectar',
    'olive', 'phoenix', 'quartz', 'rainbow', 'shadow', 'tornado', 'universe', 'velvet',
    'walnut', 'xerox', 'yogurt', 'zephyr', 'arctic', 'blaze', 'comet', 'dusk',
    'eclipse', 'flame', 'garden', 'haven', 'indigo', 'jade', 'kite', 'lotus',
    'meadow', 'night', 'opal', 'prism', 'quest', 'rapids', 'silver', 'temple',
    'unity', 'voyage', 'willow', 'azure', 'bronze', 'coral', 'dawn', 'echo',
    'frost', 'grove', 'haze', 'iris', 'jewel', 'kelp', 'lunar', 'mist',
    'nova', 'orbit', 'pearl', 'quill', 'reef', 'storm', 'tide', 'vortex',
    'winter', 'alpha', 'beta', 'gamma', 'delta', 'sigma', 'omega', 'cipher',
    'matrix', 'pixel', 'vector', 'binary', 'cosmic', 'cyber', 'digital', 'hyper',
]


def generate_password(length=16, uppercase=True, lowercase=True, digits=True, symbols=True):
    """Generate random password"""
    chars = ''

    if lowercase:
        chars += string.ascii_lowercase
    if uppercase:
        chars += string.ascii_uppercase
    if digits:
        chars += string.digits
    if symbols:
        chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'

    if not chars:
        chars = string.ascii_letters + string.digits

    # Ensure at least one of each type
    password = []
    if lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if digits:
        password.append(secrets.choice(string.digits))
    if symbols:
        password.append(secrets.choice('!@#$%^&*()_+-='))

    # Fill rest
    remaining = length - len(password)
    password.extend(secrets.choice(chars) for _ in range(remaining))

    # Shuffle
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)

    return ''.join(password_list)


def generate_passphrase(words=4, separator='-', capitalize=False, add_number=False):
    """Generate passphrase from words"""
    selected = [secrets.choice(WORDLIST) for _ in range(words)]

    if capitalize:
        selected = [word.capitalize() for word in selected]

    phrase = separator.join(selected)

    if add_number:
        phrase += separator + str(secrets.randbelow(100))

    return phrase


def generate_pin(length=6):
    """Generate numeric PIN"""
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


def calculate_entropy(password, charset_size):
    """Calculate password entropy"""
    return len(password) * math.log2(charset_size)


def check_strength(password):
    """Check password strength"""
    score = 0
    feedback = []

    # Length
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    # Character types
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_symbol:
        score += 1

    # Calculate charset size
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32

    entropy = calculate_entropy(password, charset_size) if charset_size > 0 else 0

    # Rating
    if score >= 6 and entropy >= 60:
        strength = ('Excellent', GREEN)
    elif score >= 5 and entropy >= 50:
        strength = ('Strong', GREEN)
    elif score >= 4 and entropy >= 40:
        strength = ('Good', YELLOW)
    elif score >= 3:
        strength = ('Fair', YELLOW)
    else:
        strength = ('Weak', RED)

    return {
        'score': score,
        'strength': strength,
        'entropy': entropy,
        'has_lower': has_lower,
        'has_upper': has_upper,
        'has_digit': has_digit,
        'has_symbol': has_symbol,
    }


def main():
    parser = argparse.ArgumentParser(description='Password Generator')
    parser.add_argument('--length', '-l', type=int, default=16, help='Password length')
    parser.add_argument('--count', '-c', type=int, default=5, help='Number to generate')
    parser.add_argument('--passphrase', '-p', action='store_true', help='Generate passphrase')
    parser.add_argument('--words', '-w', type=int, default=4, help='Words in passphrase')
    parser.add_argument('--pin', action='store_true', help='Generate PIN')
    parser.add_argument('--no-symbols', action='store_true', help='No special characters')
    parser.add_argument('--no-upper', action='store_true', help='No uppercase')
    parser.add_argument('--check', help='Check password strength')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔑 Password Generator                         ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Check strength mode
    if args.check:
        password = args.check
        result = check_strength(password)

        print(f"  {BOLD}Password Analysis:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")
        print(f"  {DIM}Password: {password[:3]}{'*' * (len(password) - 3)}{RESET}")
        print(f"  {CYAN}Length:{RESET}   {len(password)} characters")

        strength_text, strength_color = result['strength']
        print(f"  {CYAN}Strength:{RESET} {strength_color}{strength_text}{RESET}")
        print(f"  {CYAN}Entropy:{RESET}  {result['entropy']:.1f} bits")

        print(f"\n  {BOLD}Character Types:{RESET}")
        print(f"    {'✓' if result['has_lower'] else '✗'} Lowercase")
        print(f"    {'✓' if result['has_upper'] else '✗'} Uppercase")
        print(f"    {'✓' if result['has_digit'] else '✗'} Digits")
        print(f"    {'✓' if result['has_symbol'] else '✗'} Symbols")

        # Time to crack estimate
        if result['entropy'] > 0:
            combinations = 2 ** result['entropy']
            # Assuming 1 billion guesses/second
            seconds = combinations / 1_000_000_000 / 2  # Average case
            if seconds < 60:
                time_str = f"{seconds:.0f} seconds"
            elif seconds < 3600:
                time_str = f"{seconds / 60:.0f} minutes"
            elif seconds < 86400:
                time_str = f"{seconds / 3600:.0f} hours"
            elif seconds < 31536000:
                time_str = f"{seconds / 86400:.0f} days"
            elif seconds < 31536000 * 1000:
                time_str = f"{seconds / 31536000:.0f} years"
            else:
                time_str = "billions of years"

            print(f"\n  {CYAN}Time to crack:{RESET} ~{time_str}")
            print(f"  {DIM}(at 1 billion guesses/second){RESET}")

        print()
        return

    # Generate passwords
    if args.pin:
        print(f"  {BOLD}Generated PINs:{RESET}\n")
        for i in range(args.count):
            pin = generate_pin(args.length if args.length != 16 else 6)
            print(f"  {GREEN}{pin}{RESET}")

    elif args.passphrase:
        print(f"  {BOLD}Generated Passphrases:{RESET}")
        print(f"  {DIM}({args.words} words each){RESET}\n")

        for i in range(args.count):
            phrase = generate_passphrase(
                words=args.words,
                separator='-',
                capitalize=True,
                add_number=True
            )
            entropy = args.words * math.log2(len(WORDLIST))
            print(f"  {GREEN}{phrase}{RESET}")
            print(f"  {DIM}~{entropy:.0f} bits entropy{RESET}\n")

    else:
        print(f"  {BOLD}Generated Passwords:{RESET}")
        print(f"  {DIM}({args.length} characters each){RESET}\n")

        for i in range(args.count):
            password = generate_password(
                length=args.length,
                uppercase=not args.no_upper,
                symbols=not args.no_symbols
            )
            result = check_strength(password)
            strength_text, strength_color = result['strength']

            print(f"  {GREEN}{password}{RESET}")
            print(f"  {DIM}{strength_text} ({result['entropy']:.0f} bits){RESET}\n")

    # Tips
    print(f"  {BOLD}Tips:{RESET}")
    print(f"  {DIM}• Use a password manager to store passwords securely")
    print(f"  • Never reuse passwords across sites")
    print(f"  • Enable 2FA where available{RESET}")

    print()


if __name__ == '__main__':
    main()
