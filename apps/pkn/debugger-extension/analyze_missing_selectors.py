#!/usr/bin/env python3
"""
Missing Selector Analyzer
Finds JavaScript references to CSS classes/IDs that don't exist in HTML/CSS.

Example bug this catches:
  - JS does: document.querySelector('.chat-container')
  - But '.chat-container' class doesn't exist in CSS or HTML
  - The selector silently returns null, causing errors later
"""

import re
import sys
from pathlib import Path
from collections import defaultdict
from typing import Set, Dict, List, Tuple

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'


def extract_css_selectors(root_path: Path) -> Tuple[Set[str], Set[str]]:
    """Extract all class and ID selectors from CSS files."""
    classes = set()
    ids = set()

    for css_file in root_path.rglob('*.css'):
        if any(skip in str(css_file) for skip in ['node_modules', '.venv', 'vendor', 'llama.cpp', '/archive/', '/android/', '/www/', '.backup', '.bak', '.old', 'old-code']):
            continue

        try:
            content = css_file.read_text(encoding='utf-8')
        except:
            continue

        # Find class selectors: .className
        class_pattern = r'\.([a-zA-Z_-][a-zA-Z0-9_-]*)'
        for match in re.finditer(class_pattern, content):
            classes.add(match.group(1))

        # Find ID selectors: #idName
        id_pattern = r'#([a-zA-Z_-][a-zA-Z0-9_-]*)'
        for match in re.finditer(id_pattern, content):
            ids.add(match.group(1))

    return classes, ids


def extract_html_selectors(root_path: Path) -> Tuple[Set[str], Set[str]]:
    """Extract all class and ID attributes from HTML files."""
    classes = set()
    ids = set()

    for html_file in root_path.rglob('*.html'):
        if any(skip in str(html_file) for skip in ['node_modules', '.venv', 'vendor', 'llama.cpp', '/archive/', '/android/', '/www/', '.backup', '.bak', '.old', 'old-code']):
            continue

        try:
            content = html_file.read_text(encoding='utf-8')
        except:
            continue

        # Find class attributes: class="name1 name2"
        class_pattern = r'class\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(class_pattern, content):
            for cls in match.group(1).split():
                classes.add(cls)

        # Find ID attributes: id="name"
        id_pattern = r'id\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(id_pattern, content):
            ids.add(match.group(1))

    return classes, ids


def extract_js_selector_refs(root_path: Path) -> Dict[str, List[Tuple[Path, int, str]]]:
    """Extract all selector references from JavaScript files."""
    refs = defaultdict(list)  # selector -> [(file, line, context)]

    patterns = [
        # querySelector/querySelectorAll with class or ID
        r'querySelector(?:All)?\s*\(\s*["\']([.#][^"\']+)["\']',
        # getElementById
        r'getElementById\s*\(\s*["\']([^"\']+)["\']',
        # getElementsByClassName
        r'getElementsByClassName\s*\(\s*["\']([^"\']+)["\']',
        # jQuery-style selectors (if used)
        r'\$\s*\(\s*["\']([.#][^"\']+)["\']',
        # classList.add/remove/toggle/contains
        r'classList\.(?:add|remove|toggle|contains)\s*\(\s*["\']([^"\']+)["\']',
        # className assignments (partial - just for awareness)
        r'\.className\s*=\s*["\']([^"\']+)["\']',
    ]

    for js_file in root_path.rglob('*.js'):
        if any(skip in str(js_file) for skip in ['node_modules', '.venv', 'vendor', 'llama.cpp', '/archive/', '/android/', '/www/', '.backup', '.bak', '.old', 'old-code']):
            continue

        try:
            content = js_file.read_text(encoding='utf-8')
        except:
            continue

        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            for pattern in patterns:
                for match in re.finditer(pattern, line):
                    selector = match.group(1)
                    # Normalize selector
                    if 'getElementById' in pattern:
                        selector = f'#{selector}'
                    elif 'getElementsByClassName' in pattern or 'classList' in pattern:
                        selector = f'.{selector}'

                    refs[selector].append((js_file, line_num, line.strip()[:60]))

    return refs


def analyze_missing(root_path: Path) -> Dict[str, List[Tuple[Path, int, str]]]:
    """Find selectors referenced in JS but not defined in HTML/CSS."""

    # Get all defined selectors
    css_classes, css_ids = extract_css_selectors(root_path)
    html_classes, html_ids = extract_html_selectors(root_path)

    all_classes = css_classes | html_classes
    all_ids = css_ids | html_ids

    # Get all JS references
    js_refs = extract_js_selector_refs(root_path)

    # Find missing
    missing = {}

    for selector, locations in js_refs.items():
        if selector.startswith('.'):
            class_name = selector[1:]
            # Handle compound selectors like .class1.class2
            parts = class_name.split('.')
            if not any(part in all_classes for part in parts if part):
                missing[selector] = locations
        elif selector.startswith('#'):
            id_name = selector[1:]
            if id_name not in all_ids:
                missing[selector] = locations

    return missing


def main():
    if len(sys.argv) < 2:
        root = Path('/home/gh0st/dvn/divine-workspace/apps/pkn/frontend')
    else:
        root = Path(sys.argv[1])

    if not root.exists():
        print(f"{RED}Error: Path does not exist: {root}{RESET}")
        sys.exit(1)

    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}{'Missing Selector Analyzer'.center(70)}{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\nScanning: {root}\n")

    missing = analyze_missing(root)

    # Filter out dynamic selectors (contain variables or template literals)
    static_missing = {
        k: v for k, v in missing.items()
        if not any(c in k for c in ['$', '{', '}', '+'])
    }

    if not static_missing:
        print(f"{GREEN}✓ No missing selectors found{RESET}")
        sys.exit(0)

    print(f"{RED}Found {len(static_missing)} potentially missing selector(s):{RESET}\n")

    for selector, locations in sorted(static_missing.items()):
        print(f"{YELLOW}► {selector}{RESET}")
        for file_path, line_num, context in locations[:3]:  # Show first 3
            rel_path = file_path.relative_to(root) if file_path.is_relative_to(root) else file_path
            print(f"    {rel_path}:{line_num}")
            print(f"      {context}...")
        if len(locations) > 3:
            print(f"    ... and {len(locations) - 3} more")
        print()

    print(f"{RED}✗ {len(static_missing)} potentially missing selector(s){RESET}")
    print(f"\n{YELLOW}Note: Some may be dynamically created. Review each case.{RESET}")
    print(f"{YELLOW}Fix: Add missing classes/IDs to HTML/CSS, or fix the JS reference.{RESET}")

    # Return error only if high confidence issues found
    # (multiple references to same missing selector = likely real bug)
    high_confidence = sum(1 for v in static_missing.values() if len(v) >= 2)
    sys.exit(1 if high_confidence > 0 else 0)


if __name__ == '__main__':
    main()
