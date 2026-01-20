#!/usr/bin/env python3
"""
Regex Tester - Test and debug regular expressions
Usage: regex_test.py <pattern> [text] [--flags i,m,s]
"""

import re
import argparse
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
BG_GREEN = '\033[42m'
BG_YELLOW = '\033[43m'


# Common regex patterns for quick reference
COMMON_PATTERNS = {
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'url': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
    'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'ipv6': r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
    'phone': r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}',
    'date': r'\d{4}[-/]\d{2}[-/]\d{2}',
    'time': r'\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp][Mm])?',
    'hex_color': r'#(?:[0-9a-fA-F]{3}){1,2}\b',
    'mac': r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'ssn': r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
    'zip': r'\b\d{5}(?:-\d{4})?\b',
    'username': r'^[a-zA-Z0-9_]{3,16}$',
    'password_strong': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
    'slug': r'^[a-z0-9]+(?:-[a-z0-9]+)*$',
    'html_tag': r'<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>.*?</\1>',
    'word': r'\b\w+\b',
    'sentence': r'[A-Z][^.!?]*[.!?]',
}


def highlight_matches(text, matches):
    """Highlight matches in text"""
    if not matches:
        return text

    # Sort matches by start position
    sorted_matches = sorted(matches, key=lambda m: m.start())

    result = []
    last_end = 0

    colors = [BG_GREEN, BG_YELLOW]

    for i, match in enumerate(sorted_matches):
        # Add text before match
        result.append(text[last_end:match.start()])
        # Add highlighted match
        color = colors[i % len(colors)]
        result.append(f"{color}{BOLD}{match.group()}{RESET}")
        last_end = match.end()

    # Add remaining text
    result.append(text[last_end:])

    return ''.join(result)


def explain_regex(pattern):
    """Provide basic explanation of regex pattern"""
    explanations = []

    tokens = [
        (r'\^', 'Start of string/line'),
        (r'\$', 'End of string/line'),
        (r'\.', 'Any character'),
        (r'\*', 'Zero or more'),
        (r'\+', 'One or more'),
        (r'\?', 'Zero or one (optional)'),
        (r'\[.*?\]', 'Character class'),
        (r'\(.*?\)', 'Capture group'),
        (r'\(\?:.*?\)', 'Non-capturing group'),
        (r'\(\?=.*?\)', 'Positive lookahead'),
        (r'\(\?!.*?\)', 'Negative lookahead'),
        (r'\\d', 'Digit [0-9]'),
        (r'\\D', 'Non-digit'),
        (r'\\w', 'Word char [a-zA-Z0-9_]'),
        (r'\\W', 'Non-word char'),
        (r'\\s', 'Whitespace'),
        (r'\\S', 'Non-whitespace'),
        (r'\\b', 'Word boundary'),
        (r'\{(\d+)\}', 'Exactly N times'),
        (r'\{(\d+),\}', 'N or more times'),
        (r'\{(\d+),(\d+)\}', 'Between N and M times'),
        (r'\|', 'OR (alternation)'),
    ]

    for token_pattern, desc in tokens:
        if re.search(token_pattern, pattern):
            explanations.append(desc)

    return explanations


def interactive_mode():
    """Interactive regex testing"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔤 Regex Tester - Interactive                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Commands: 'list' for common patterns, 'quit' to exit{RESET}\n")

    pattern = None
    flags = 0

    while True:
        if pattern is None:
            user_input = input(f"  {CYAN}Pattern:{RESET} ").strip()

            if user_input.lower() == 'quit':
                break
            elif user_input.lower() == 'list':
                print(f"\n  {BOLD}Common Patterns:{RESET}")
                for name, pat in COMMON_PATTERNS.items():
                    print(f"    {CYAN}{name:15}{RESET} {DIM}{pat[:50]}{'...' if len(pat) > 50 else ''}{RESET}")
                print()
                continue
            elif user_input in COMMON_PATTERNS:
                pattern = COMMON_PATTERNS[user_input]
                print(f"  {DIM}Using: {pattern}{RESET}")
            else:
                pattern = user_input

            # Get flags
            flag_input = input(f"  {CYAN}Flags (i=ignore case, m=multiline, s=dotall):{RESET} ").strip()
            flags = 0
            if 'i' in flag_input:
                flags |= re.IGNORECASE
            if 'm' in flag_input:
                flags |= re.MULTILINE
            if 's' in flag_input:
                flags |= re.DOTALL

        try:
            compiled = re.compile(pattern, flags)
        except re.error as e:
            print(f"  {RED}Invalid regex: {e}{RESET}\n")
            pattern = None
            continue

        print(f"\n  {DIM}Enter test text (empty line to change pattern):{RESET}")
        text = input(f"  {CYAN}Text:{RESET} ").strip()

        if not text:
            pattern = None
            print()
            continue

        # Find all matches
        matches = list(compiled.finditer(text))

        print(f"\n  {BOLD}Results:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        if matches:
            print(f"  {GREEN}Found {len(matches)} match(es){RESET}\n")
            print(f"  {highlight_matches(text, matches)}\n")

            for i, match in enumerate(matches):
                print(f"  {CYAN}Match {i+1}:{RESET} '{match.group()}' at {match.start()}-{match.end()}")
                if match.groups():
                    for j, group in enumerate(match.groups(), 1):
                        print(f"    {DIM}Group {j}: '{group}'{RESET}")
        else:
            print(f"  {RED}No matches found{RESET}")

        print()


def main():
    parser = argparse.ArgumentParser(description='Regex Tester')
    parser.add_argument('pattern', nargs='?', help='Regex pattern (or common pattern name)')
    parser.add_argument('text', nargs='?', help='Text to search')
    parser.add_argument('--flags', '-f', default='', help='Flags: i=ignorecase, m=multiline, s=dotall')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--list', '-l', action='store_true', help='List common patterns')
    parser.add_argument('--explain', '-e', action='store_true', help='Explain pattern')
    parser.add_argument('--findall', action='store_true', help='Use findall instead of finditer')
    args = parser.parse_args()

    if args.list:
        print(f"\n{BOLD}Common Regex Patterns:{RESET}\n")
        for name, pattern in COMMON_PATTERNS.items():
            print(f"  {CYAN}{name:15}{RESET} {pattern}")
        print()
        return

    if args.interactive or (not args.pattern and not args.text):
        interactive_mode()
        return

    # Get pattern
    pattern = COMMON_PATTERNS.get(args.pattern, args.pattern)

    print(f"\n{BOLD}{CYAN}Regex Tester{RESET}\n")
    print(f"  {DIM}Pattern: {pattern}{RESET}")

    # Explain pattern
    if args.explain:
        explanations = explain_regex(pattern)
        if explanations:
            print(f"\n  {BOLD}Pattern contains:{RESET}")
            for exp in explanations:
                print(f"    • {exp}")
        print()

    # Compile with flags
    flags = 0
    if 'i' in args.flags:
        flags |= re.IGNORECASE
    if 'm' in args.flags:
        flags |= re.MULTILINE
    if 's' in args.flags:
        flags |= re.DOTALL

    try:
        compiled = re.compile(pattern, flags)
    except re.error as e:
        print(f"  {RED}Invalid regex: {e}{RESET}\n")
        return

    # Get text
    if args.text:
        text = args.text
    else:
        print(f"  {DIM}Reading from stdin...{RESET}")
        text = sys.stdin.read()

    # Find matches
    matches = list(compiled.finditer(text))

    print(f"\n  {BOLD}Results:{RESET}")
    if matches:
        print(f"  {GREEN}Found {len(matches)} match(es){RESET}\n")

        # Show highlighted text (first 500 chars)
        display_text = text[:500] + ('...' if len(text) > 500 else '')
        print(f"  {highlight_matches(display_text, [m for m in matches if m.end() <= 500])}\n")

        for i, match in enumerate(matches[:20]):
            print(f"  {CYAN}[{i+1}]{RESET} '{match.group()}' @ {match.start()}")

        if len(matches) > 20:
            print(f"  {DIM}... and {len(matches) - 20} more{RESET}")
    else:
        print(f"  {RED}No matches found{RESET}")

    print()


if __name__ == '__main__':
    main()
