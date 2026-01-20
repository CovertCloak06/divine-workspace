#!/usr/bin/env python3
"""
Data Formatter - Format and convert JSON, YAML, XML, CSV
Usage: jsonfmt <file> [--to json|yaml|csv] [--minify] [--validate]
"""

import argparse
import json
import sys
import csv
import io
from pathlib import Path

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def detect_format(content, filename=''):
    """Detect data format"""
    ext = Path(filename).suffix.lower() if filename else ''

    if ext == '.json' or content.strip().startswith(('{', '[')):
        return 'json'
    elif ext in ['.yaml', '.yml'] or ': ' in content and not content.strip().startswith('<'):
        return 'yaml'
    elif ext == '.xml' or content.strip().startswith('<'):
        return 'xml'
    elif ext == '.csv' or ',' in content.split('\n')[0]:
        return 'csv'
    return 'unknown'


def parse_json(content):
    """Parse JSON"""
    return json.loads(content)


def parse_yaml(content):
    """Parse YAML (simple implementation)"""
    result = {}
    current_dict = result
    indent_stack = [(0, result)]

    for line in content.split('\n'):
        if not line.strip() or line.strip().startswith('#'):
            continue

        indent = len(line) - len(line.lstrip())
        line = line.strip()

        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            # Handle nested structure
            while indent_stack and indent <= indent_stack[-1][0]:
                indent_stack.pop()

            if indent_stack:
                current_dict = indent_stack[-1][1]

            if value:
                # Handle different value types
                if value.lower() == 'true':
                    current_dict[key] = True
                elif value.lower() == 'false':
                    current_dict[key] = False
                elif value.lower() == 'null':
                    current_dict[key] = None
                elif value.isdigit():
                    current_dict[key] = int(value)
                elif value.startswith('[') and value.endswith(']'):
                    # Simple array
                    items = value[1:-1].split(',')
                    current_dict[key] = [i.strip().strip('"\'') for i in items if i.strip()]
                else:
                    current_dict[key] = value.strip('"\'')
            else:
                current_dict[key] = {}
                indent_stack.append((indent, current_dict[key]))

    return result


def parse_csv(content):
    """Parse CSV to list of dicts"""
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def parse_xml(content):
    """Parse XML (simple implementation)"""
    import re

    def parse_element(text):
        result = {}
        # Find all tags
        pattern = r'<(\w+)(?:\s[^>]*)?>([^<]*(?:<(?!/\1>)[^<]*)*)</\1>'
        matches = re.findall(pattern, text, re.DOTALL)

        for tag, inner in matches:
            inner = inner.strip()
            if '<' in inner:
                result[tag] = parse_element(inner)
            else:
                result[tag] = inner

        return result

    # Remove XML declaration
    content = re.sub(r'<\?xml[^>]+\?>', '', content)
    return parse_element(content)


def to_json(data, minify=False):
    """Convert to JSON"""
    if minify:
        return json.dumps(data, separators=(',', ':'))
    return json.dumps(data, indent=2)


def to_yaml(data, indent=0):
    """Convert to YAML (simple implementation)"""
    lines = []

    def format_value(value, ind):
        spaces = '  ' * ind
        if isinstance(value, dict):
            if not value:
                return '{}'
            result = []
            for k, v in value.items():
                formatted = format_value(v, ind + 1)
                if isinstance(v, (dict, list)) and v:
                    result.append(f"{spaces}{k}:")
                    result.append(formatted)
                else:
                    result.append(f"{spaces}{k}: {formatted}")
            return '\n'.join(result)
        elif isinstance(value, list):
            if not value:
                return '[]'
            result = []
            for item in value:
                if isinstance(item, dict):
                    result.append(f"{spaces}-")
                    result.append(format_value(item, ind + 1))
                else:
                    result.append(f"{spaces}- {item}")
            return '\n'.join(result)
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        elif value is None:
            return 'null'
        elif isinstance(value, str) and (':' in value or '\n' in value):
            return f'"{value}"'
        else:
            return str(value)

    return format_value(data, 0)


def to_csv(data):
    """Convert to CSV"""
    if not isinstance(data, list):
        data = [data]

    if not data:
        return ''

    # Get all keys
    keys = set()
    for item in data:
        if isinstance(item, dict):
            keys.update(item.keys())
    keys = sorted(keys)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    writer.writerows(data)

    return output.getvalue()


def colorize_json(text):
    """Add colors to JSON for display"""
    import re

    # Color strings
    text = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"(?=\s*:)', f'{CYAN}"\\1"{RESET}', text)
    text = re.sub(r':\s*"([^"\\]*(?:\\.[^"\\]*)*)"', f': {GREEN}"\\1"{RESET}', text)

    # Color numbers, booleans, null
    text = re.sub(r':\s*(\d+(?:\.\d+)?)', f': {YELLOW}\\1{RESET}', text)
    text = re.sub(r':\s*(true|false|null)', f': {YELLOW}\\1{RESET}', text)

    return text


def main():
    parser = argparse.ArgumentParser(description='Data Formatter')
    parser.add_argument('input', nargs='?', help='Input file (or use stdin)')
    parser.add_argument('--to', '-t', choices=['json', 'yaml', 'csv'], help='Output format')
    parser.add_argument('--minify', '-m', action='store_true', help='Minify output')
    parser.add_argument('--validate', '-v', action='store_true', help='Validate only')
    parser.add_argument('--no-color', action='store_true', help='Disable color output')
    parser.add_argument('--output', '-o', help='Output file')
    args = parser.parse_args()

    # Read input
    if args.input:
        with open(args.input) as f:
            content = f.read()
        filename = args.input
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
        filename = ''
    else:
        print(f"{RED}No input provided{RESET}")
        return

    print(f"\n{BOLD}{CYAN}Data Formatter{RESET}\n")

    # Detect format
    input_format = detect_format(content, filename)
    print(f"Detected format: {CYAN}{input_format.upper()}{RESET}")

    # Parse
    try:
        if input_format == 'json':
            data = parse_json(content)
        elif input_format == 'yaml':
            data = parse_yaml(content)
        elif input_format == 'csv':
            data = parse_csv(content)
        elif input_format == 'xml':
            data = parse_xml(content)
        else:
            print(f"{RED}Unknown format{RESET}")
            return

        print(f"Status: {GREEN}Valid{RESET}")

        if args.validate:
            print(f"\n{GREEN}Input is valid {input_format.upper()}{RESET}")
            return

    except Exception as e:
        print(f"Status: {RED}Invalid{RESET}")
        print(f"Error: {e}")
        return

    # Convert
    output_format = args.to or input_format
    print(f"Output format: {CYAN}{output_format.upper()}{RESET}\n")

    if output_format == 'json':
        output = to_json(data, args.minify)
        if not args.no_color and not args.output:
            output = colorize_json(output)
    elif output_format == 'yaml':
        output = to_yaml(data)
    elif output_format == 'csv':
        output = to_csv(data)
    else:
        output = to_json(data)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Saved to: {args.output}")
    else:
        print(output)

    print()


if __name__ == '__main__':
    main()
