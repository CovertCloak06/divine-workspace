#!/usr/bin/env python3
"""
Diff Tool - Compare files side by side
Usage: diff_tool.py file1 file2
"""

import argparse
import os
import difflib

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
BG_GREEN = '\033[42m'
BG_RED = '\033[41m'


def read_file(filepath):
    """Read file contents"""
    try:
        with open(filepath, 'r') as f:
            return f.readlines()
    except Exception as e:
        return None


def unified_diff(file1, file2, lines1, lines2):
    """Generate unified diff"""
    diff = difflib.unified_diff(
        lines1, lines2,
        fromfile=file1,
        tofile=file2,
        lineterm=''
    )
    return list(diff)


def side_by_side(lines1, lines2, width=80):
    """Generate side-by-side diff"""
    half_width = (width - 3) // 2

    result = []
    matcher = difflib.SequenceMatcher(None, lines1, lines2)

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            for i in range(i1, i2):
                left = lines1[i].rstrip()[:half_width]
                right = lines2[j1 + (i - i1)].rstrip()[:half_width]
                result.append(('equal', left, right))
        elif tag == 'replace':
            max_lines = max(i2 - i1, j2 - j1)
            for i in range(max_lines):
                left = lines1[i1 + i].rstrip()[:half_width] if i < (i2 - i1) else ''
                right = lines2[j1 + i].rstrip()[:half_width] if i < (j2 - j1) else ''
                result.append(('replace', left, right))
        elif tag == 'delete':
            for i in range(i1, i2):
                left = lines1[i].rstrip()[:half_width]
                result.append(('delete', left, ''))
        elif tag == 'insert':
            for j in range(j1, j2):
                right = lines2[j].rstrip()[:half_width]
                result.append(('insert', '', right))

    return result


def inline_diff(lines1, lines2):
    """Generate inline diff with context"""
    result = []
    matcher = difflib.SequenceMatcher(None, lines1, lines2)

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            # Show only first and last line of equal blocks if large
            if i2 - i1 > 6:
                for i in range(i1, i1 + 2):
                    result.append(('equal', i + 1, lines1[i].rstrip()))
                result.append(('skip', 0, f'... {i2 - i1 - 4} identical lines ...'))
                for i in range(i2 - 2, i2):
                    result.append(('equal', i + 1, lines1[i].rstrip()))
            else:
                for i in range(i1, i2):
                    result.append(('equal', i + 1, lines1[i].rstrip()))
        elif tag == 'replace':
            for i in range(i1, i2):
                result.append(('delete', i + 1, lines1[i].rstrip()))
            for j in range(j1, j2):
                result.append(('insert', j + 1, lines2[j].rstrip()))
        elif tag == 'delete':
            for i in range(i1, i2):
                result.append(('delete', i + 1, lines1[i].rstrip()))
        elif tag == 'insert':
            for j in range(j1, j2):
                result.append(('insert', j + 1, lines2[j].rstrip()))

    return result


def main():
    parser = argparse.ArgumentParser(description='Diff Tool')
    parser.add_argument('file1', nargs='?', help='First file')
    parser.add_argument('file2', nargs='?', help='Second file')
    parser.add_argument('--side-by-side', '-s', action='store_true', help='Side by side view')
    parser.add_argument('--unified', '-u', action='store_true', help='Unified diff format')
    parser.add_argument('--context', '-c', type=int, default=3, help='Context lines')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📝 Diff Tool                                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.file1:
        args.file1 = input(f"  {CYAN}First file:{RESET} ").strip()
    if not args.file2:
        args.file2 = input(f"  {CYAN}Second file:{RESET} ").strip()

    if not args.file1 or not args.file2:
        print(f"  {RED}Two files required{RESET}\n")
        return

    if not os.path.exists(args.file1):
        print(f"  {RED}File not found: {args.file1}{RESET}\n")
        return
    if not os.path.exists(args.file2):
        print(f"  {RED}File not found: {args.file2}{RESET}\n")
        return

    lines1 = read_file(args.file1)
    lines2 = read_file(args.file2)

    if lines1 is None:
        print(f"  {RED}Could not read: {args.file1}{RESET}\n")
        return
    if lines2 is None:
        print(f"  {RED}Could not read: {args.file2}{RESET}\n")
        return

    print(f"  {BOLD}Comparing:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {RED}- {args.file1}{RESET} ({len(lines1)} lines)")
    print(f"  {GREEN}+ {args.file2}{RESET} ({len(lines2)} lines)")
    print()

    # Check if files are identical
    if lines1 == lines2:
        print(f"  {GREEN}✓ Files are identical{RESET}\n")
        return

    # Unified diff
    if args.unified:
        print(f"  {BOLD}Unified Diff:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        diff = unified_diff(args.file1, args.file2, lines1, lines2)
        for line in diff:
            line = line.rstrip()
            if line.startswith('+++') or line.startswith('---'):
                print(f"  {BOLD}{line}{RESET}")
            elif line.startswith('@@'):
                print(f"  {CYAN}{line}{RESET}")
            elif line.startswith('+'):
                print(f"  {GREEN}{line}{RESET}")
            elif line.startswith('-'):
                print(f"  {RED}{line}{RESET}")
            else:
                print(f"  {line}")
        print()
        return

    # Side by side
    if args.side_by_side:
        print(f"  {BOLD}Side by Side:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        half = 35
        print(f"  {RED}{args.file1[:half]:<{half}}{RESET} │ {GREEN}{args.file2[:half]}{RESET}")
        print(f"  {'─' * half} ┼ {'─' * half}")

        diff = side_by_side(lines1, lines2, 80)
        for tag, left, right in diff[:100]:
            left = left[:half]
            right = right[:half]

            if tag == 'equal':
                print(f"  {left:<{half}} │ {right}")
            elif tag == 'replace':
                print(f"  {RED}{left:<{half}}{RESET} │ {GREEN}{right}{RESET}")
            elif tag == 'delete':
                print(f"  {RED}{left:<{half}}{RESET} │")
            elif tag == 'insert':
                print(f"  {'':<{half}} │ {GREEN}{right}{RESET}")

        if len(diff) > 100:
            print(f"\n  {DIM}... and {len(diff) - 100} more lines{RESET}")
        print()
        return

    # Default: inline diff
    print(f"  {BOLD}Changes:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    diff = inline_diff(lines1, lines2)

    additions = 0
    deletions = 0

    for tag, linenum, content in diff[:150]:
        content = content[:70]

        if tag == 'equal':
            print(f"  {DIM}{linenum:>4} │{RESET} {content}")
        elif tag == 'delete':
            print(f"  {RED}{linenum:>4} │ - {content}{RESET}")
            deletions += 1
        elif tag == 'insert':
            print(f"  {GREEN}{linenum:>4} │ + {content}{RESET}")
            additions += 1
        elif tag == 'skip':
            print(f"  {DIM}     │ {content}{RESET}")

    if len(diff) > 150:
        print(f"\n  {DIM}... output truncated{RESET}")

    # Summary
    print(f"\n  {BOLD}Summary:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {GREEN}+{additions} additions{RESET}  {RED}-{deletions} deletions{RESET}")

    # Similarity
    ratio = difflib.SequenceMatcher(None, lines1, lines2).ratio()
    print(f"  Similarity: {ratio * 100:.1f}%")

    print()


if __name__ == '__main__':
    main()
