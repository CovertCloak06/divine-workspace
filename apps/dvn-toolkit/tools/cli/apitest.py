#!/usr/bin/env python3
"""
API Tester - Quick endpoint testing with pretty output
Usage: apitest <url> [--method POST] [--data '{"key":"value"}'] [--headers 'Auth: token']
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

# ANSI colors
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'


def colorize_json(obj, indent=2):
    """Pretty print JSON with colors"""
    def format_value(v, depth=0):
        spaces = ' ' * (depth * indent)
        if isinstance(v, dict):
            if not v:
                return '{}'
            lines = ['{']
            for i, (k, val) in enumerate(v.items()):
                comma = ',' if i < len(v) - 1 else ''
                lines.append(f'{spaces}  {CYAN}"{k}"{RESET}: {format_value(val, depth + 1)}{comma}')
            lines.append(f'{spaces}}}')
            return '\n'.join(lines)
        elif isinstance(v, list):
            if not v:
                return '[]'
            lines = ['[']
            for i, item in enumerate(v):
                comma = ',' if i < len(v) - 1 else ''
                lines.append(f'{spaces}  {format_value(item, depth + 1)}{comma}')
            lines.append(f'{spaces}]')
            return '\n'.join(lines)
        elif isinstance(v, str):
            return f'{GREEN}"{v}"{RESET}'
        elif isinstance(v, bool):
            return f'{YELLOW}{str(v).lower()}{RESET}'
        elif v is None:
            return f'{YELLOW}null{RESET}'
        else:
            return f'{YELLOW}{v}{RESET}'

    return format_value(obj)


def make_request(url, method='GET', data=None, headers=None, timeout=30):
    """Make HTTP request and return response details"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    req_headers = {'User-Agent': 'APITest/1.0', 'Accept': 'application/json'}
    if headers:
        for h in headers:
            if ':' in h:
                key, val = h.split(':', 1)
                req_headers[key.strip()] = val.strip()

    body = None
    if data:
        if isinstance(data, str):
            try:
                body = json.dumps(json.loads(data)).encode()
            except:
                body = data.encode()
        req_headers['Content-Type'] = 'application/json'

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - start
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'body': resp.read().decode('utf-8', errors='replace'),
                'time': elapsed,
                'error': None
            }
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        return {
            'status': e.code,
            'headers': dict(e.headers) if e.headers else {},
            'body': e.read().decode('utf-8', errors='replace') if e.fp else '',
            'time': elapsed,
            'error': str(e.reason)
        }
    except Exception as e:
        return {
            'status': 0,
            'headers': {},
            'body': '',
            'time': time.time() - start,
            'error': str(e)
        }


def main():
    parser = argparse.ArgumentParser(description='API Tester')
    parser.add_argument('url', help='API endpoint URL')
    parser.add_argument('--method', '-m', default='GET', help='HTTP method')
    parser.add_argument('--data', '-d', help='Request body (JSON)')
    parser.add_argument('--header', '-H', action='append', dest='headers', help='Headers (Key: Value)')
    parser.add_argument('--timeout', '-t', type=int, default=30, help='Timeout in seconds')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show response headers')
    args = parser.parse_args()

    print(f"\n{BOLD}→ {args.method} {args.url}{RESET}")
    if args.data:
        print(f"  Body: {args.data[:50]}...")

    result = make_request(args.url, args.method, args.data, args.headers, args.timeout)

    # Status line
    status_color = GREEN if 200 <= result['status'] < 300 else YELLOW if result['status'] < 400 else RED
    print(f"\n{status_color}{BOLD}← {result['status']}{RESET} ({result['time']*1000:.0f}ms)")

    if result['error']:
        print(f"  {RED}Error: {result['error']}{RESET}")

    # Headers
    if args.verbose and result['headers']:
        print(f"\n{BOLD}Headers:{RESET}")
        for k, v in result['headers'].items():
            print(f"  {CYAN}{k}{RESET}: {v}")

    # Body
    if result['body']:
        print(f"\n{BOLD}Response:{RESET}")
        try:
            data = json.loads(result['body'])
            print(colorize_json(data))
        except:
            print(result['body'][:2000])
            if len(result['body']) > 2000:
                print(f"\n... ({len(result['body'])} bytes total)")

    print()


if __name__ == '__main__':
    main()
