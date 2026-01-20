#!/usr/bin/env python3
"""
JSON Tool - Format, validate, query JSON data
Usage: json_tool.py <file.json> [--query path.to.key] [--minify]
"""

import json
import sys
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
MAGENTA = '\033[95m'


def colorize_json(obj, indent=0):
    """Colorize JSON output"""
    spaces = '  ' * indent

    if isinstance(obj, dict):
        if not obj:
            return '{}'

        lines = ['{']
        items = list(obj.items())
        for i, (key, value) in enumerate(items):
            comma = ',' if i < len(items) - 1 else ''
            colored_value = colorize_json(value, indent + 1)
            lines.append(f'{spaces}  {CYAN}"{key}"{RESET}: {colored_value}{comma}')
        lines.append(f'{spaces}}}')
        return '\n'.join(lines)

    elif isinstance(obj, list):
        if not obj:
            return '[]'

        # Check if simple array (all primitives)
        if all(isinstance(x, (str, int, float, bool, type(None))) for x in obj) and len(obj) <= 5:
            items = [colorize_json(x) for x in obj]
            return '[' + ', '.join(items) + ']'

        lines = ['[']
        for i, item in enumerate(obj):
            comma = ',' if i < len(obj) - 1 else ''
            colored_item = colorize_json(item, indent + 1)
            lines.append(f'{spaces}  {colored_item}{comma}')
        lines.append(f'{spaces}]')
        return '\n'.join(lines)

    elif isinstance(obj, str):
        return f'{GREEN}"{obj}"{RESET}'

    elif isinstance(obj, bool):
        return f'{MAGENTA}{str(obj).lower()}{RESET}'

    elif isinstance(obj, (int, float)):
        return f'{YELLOW}{obj}{RESET}'

    elif obj is None:
        return f'{DIM}null{RESET}'

    return str(obj)


def query_json(data, path):
    """Query JSON data using dot notation or bracket notation"""
    if not path:
        return data

    # Parse path like "users[0].name" or "config.database.host"
    parts = re.split(r'\.|\[(\d+)\]', path)
    parts = [p for p in parts if p is not None and p != '']

    result = data
    for part in parts:
        if isinstance(result, dict):
            if part in result:
                result = result[part]
            else:
                return None
        elif isinstance(result, list):
            try:
                idx = int(part)
                result = result[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None

    return result


def get_keys(data, prefix=''):
    """Get all keys in JSON structure"""
    keys = []

    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.append(full_key)
            keys.extend(get_keys(value, full_key))
    elif isinstance(data, list) and data:
        keys.extend(get_keys(data[0], f"{prefix}[0]"))

    return keys


def validate_json(content):
    """Validate JSON and return errors"""
    try:
        json.loads(content)
        return True, None
    except json.JSONDecodeError as e:
        return False, {
            'message': e.msg,
            'line': e.lineno,
            'column': e.colno,
            'position': e.pos
        }


def diff_json(obj1, obj2, path=''):
    """Compare two JSON objects"""
    diffs = []

    if type(obj1) != type(obj2):
        diffs.append({
            'path': path or 'root',
            'type': 'type_change',
            'old': type(obj1).__name__,
            'new': type(obj2).__name__
        })
        return diffs

    if isinstance(obj1, dict):
        all_keys = set(obj1.keys()) | set(obj2.keys())
        for key in all_keys:
            new_path = f"{path}.{key}" if path else key

            if key not in obj1:
                diffs.append({'path': new_path, 'type': 'added', 'value': obj2[key]})
            elif key not in obj2:
                diffs.append({'path': new_path, 'type': 'removed', 'value': obj1[key]})
            else:
                diffs.extend(diff_json(obj1[key], obj2[key], new_path))

    elif isinstance(obj1, list):
        for i in range(max(len(obj1), len(obj2))):
            new_path = f"{path}[{i}]"
            if i >= len(obj1):
                diffs.append({'path': new_path, 'type': 'added', 'value': obj2[i]})
            elif i >= len(obj2):
                diffs.append({'path': new_path, 'type': 'removed', 'value': obj1[i]})
            else:
                diffs.extend(diff_json(obj1[i], obj2[i], new_path))

    elif obj1 != obj2:
        diffs.append({
            'path': path or 'root',
            'type': 'changed',
            'old': obj1,
            'new': obj2
        })

    return diffs


def main():
    parser = argparse.ArgumentParser(description='JSON Tool')
    parser.add_argument('file', nargs='?', help='JSON file to process')
    parser.add_argument('--query', '-q', help='Query path (e.g., users[0].name)')
    parser.add_argument('--minify', '-m', action='store_true', help='Minify output')
    parser.add_argument('--validate', '-v', action='store_true', help='Validate only')
    parser.add_argument('--keys', '-k', action='store_true', help='List all keys')
    parser.add_argument('--diff', '-d', help='Compare with another JSON file')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    args = parser.parse_args()

    # Read input
    if args.file:
        try:
            with open(args.file, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"{RED}File not found: {args.file}{RESET}")
            return
    else:
        print(f"{CYAN}Paste JSON (Ctrl+D when done):{RESET}")
        content = sys.stdin.read()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📋 JSON Tool                                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Validate
    valid, error = validate_json(content)

    if args.validate:
        if valid:
            print(f"  {GREEN}✓ Valid JSON{RESET}")
        else:
            print(f"  {RED}✗ Invalid JSON{RESET}")
            print(f"  {RED}  Line {error['line']}, Column {error['column']}: {error['message']}{RESET}")
        print()
        return

    if not valid:
        print(f"  {RED}Error: {error['message']}{RESET}")
        print(f"  {DIM}Line {error['line']}, Column {error['column']}{RESET}\n")
        return

    data = json.loads(content)

    # Show keys
    if args.keys:
        keys = get_keys(data)
        print(f"  {BOLD}Keys found:{RESET} {len(keys)}\n")
        for key in keys[:50]:
            print(f"  {CYAN}•{RESET} {key}")
        if len(keys) > 50:
            print(f"  {DIM}... and {len(keys) - 50} more{RESET}")
        print()
        return

    # Diff mode
    if args.diff:
        try:
            with open(args.diff, 'r') as f:
                data2 = json.load(f)
        except Exception as e:
            print(f"  {RED}Error loading diff file: {e}{RESET}\n")
            return

        diffs = diff_json(data, data2)

        if not diffs:
            print(f"  {GREEN}✓ Files are identical{RESET}\n")
        else:
            print(f"  {BOLD}Differences:{RESET} {len(diffs)}\n")
            for diff in diffs[:30]:
                if diff['type'] == 'added':
                    print(f"  {GREEN}+ {diff['path']}{RESET}: {diff['value']}")
                elif diff['type'] == 'removed':
                    print(f"  {RED}- {diff['path']}{RESET}: {diff['value']}")
                elif diff['type'] == 'changed':
                    print(f"  {YELLOW}~ {diff['path']}{RESET}: {diff['old']} → {diff['new']}")
                elif diff['type'] == 'type_change':
                    print(f"  {YELLOW}! {diff['path']}{RESET}: type {diff['old']} → {diff['new']}")
            print()
        return

    # Query
    if args.query:
        result = query_json(data, args.query)

        if result is None:
            print(f"  {YELLOW}Path not found: {args.query}{RESET}\n")
        else:
            print(f"  {DIM}Query: {args.query}{RESET}\n")
            if args.no_color:
                print(json.dumps(result, indent=2))
            else:
                print(colorize_json(result))
            print()
        return

    # Output
    if args.minify:
        print(json.dumps(data, separators=(',', ':')))
    elif args.no_color:
        print(json.dumps(data, indent=2))
    else:
        print(colorize_json(data))

    # Stats
    def count_elements(obj):
        if isinstance(obj, dict):
            return 1 + sum(count_elements(v) for v in obj.values())
        elif isinstance(obj, list):
            return 1 + sum(count_elements(v) for v in obj)
        return 1

    element_count = count_elements(data)
    print(f"\n  {DIM}Elements: {element_count} | Size: {len(content):,} bytes{RESET}")
    print()


if __name__ == '__main__':
    main()
