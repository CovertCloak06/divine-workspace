#!/usr/bin/env python3
"""
cURL Builder - Interactive cURL command builder
Usage: curl_builder.py [url] [--method POST] [--headers]
"""

import argparse
import json
import urllib.parse
import urllib.request
import ssl

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def build_curl_command(url, method='GET', headers=None, data=None, auth=None, options=None):
    """Build a cURL command string"""
    parts = ['curl']

    # Method
    if method != 'GET':
        parts.append(f'-X {method}')

    # Headers
    if headers:
        for key, value in headers.items():
            parts.append(f"-H '{key}: {value}'")

    # Auth
    if auth:
        if auth.get('type') == 'basic':
            parts.append(f"-u '{auth['user']}:{auth['pass']}'")
        elif auth.get('type') == 'bearer':
            parts.append(f"-H 'Authorization: Bearer {auth['token']}'")

    # Data
    if data:
        if isinstance(data, dict):
            json_data = json.dumps(data)
            parts.append(f"-d '{json_data}'")
        else:
            parts.append(f"-d '{data}'")

    # Options
    if options:
        if options.get('verbose'):
            parts.append('-v')
        if options.get('silent'):
            parts.append('-s')
        if options.get('insecure'):
            parts.append('-k')
        if options.get('follow'):
            parts.append('-L')
        if options.get('output'):
            parts.append(f"-o '{options['output']}'")
        if options.get('timeout'):
            parts.append(f"--connect-timeout {options['timeout']}")

    # URL (always last)
    parts.append(f"'{url}'")

    return ' \\\n  '.join(parts)


def execute_request(url, method='GET', headers=None, data=None, timeout=10):
    """Execute the request and return response"""
    try:
        # Prepare request
        req_headers = headers or {}

        if data and isinstance(data, dict):
            data = json.dumps(data).encode()
            req_headers['Content-Type'] = 'application/json'
        elif data:
            data = data.encode()

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        # SSL context (allow self-signed for testing)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            body = response.read().decode('utf-8', errors='replace')

            return {
                'status': response.status,
                'reason': response.reason,
                'headers': dict(response.headers),
                'body': body
            }

    except urllib.error.HTTPError as e:
        return {
            'status': e.code,
            'reason': e.reason,
            'headers': dict(e.headers) if e.headers else {},
            'body': e.read().decode('utf-8', errors='replace') if e.fp else ''
        }
    except Exception as e:
        return {'error': str(e)}


def interactive_mode():
    """Interactive cURL builder"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔗 cURL Builder - Interactive                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # URL
    url = input(f"  {CYAN}URL:{RESET} ").strip()
    if not url:
        print(f"  {RED}URL required{RESET}\n")
        return

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Method
    print(f"\n  {BOLD}Method:{RESET}")
    print(f"  {CYAN}1.{RESET} GET (default)")
    print(f"  {CYAN}2.{RESET} POST")
    print(f"  {CYAN}3.{RESET} PUT")
    print(f"  {CYAN}4.{RESET} DELETE")
    print(f"  {CYAN}5.{RESET} PATCH")

    method_choice = input(f"\n  {CYAN}Choice [1]:{RESET} ").strip() or '1'
    methods = {'1': 'GET', '2': 'POST', '3': 'PUT', '4': 'DELETE', '5': 'PATCH'}
    method = methods.get(method_choice, 'GET')

    # Headers
    headers = {}
    print(f"\n  {BOLD}Headers:{RESET} (empty line when done)")

    # Common headers
    print(f"  {DIM}Quick add: 1=JSON, 2=Form, 3=Auth Bearer{RESET}")

    while True:
        header_input = input(f"  {CYAN}Header:{RESET} ").strip()

        if not header_input:
            break

        if header_input == '1':
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            print(f"    {GREEN}Added JSON headers{RESET}")
        elif header_input == '2':
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            print(f"    {GREEN}Added form header{RESET}")
        elif header_input == '3':
            token = input(f"    {CYAN}Bearer token:{RESET} ").strip()
            if token:
                headers['Authorization'] = f'Bearer {token}'
                print(f"    {GREEN}Added auth header{RESET}")
        elif ':' in header_input:
            key, value = header_input.split(':', 1)
            headers[key.strip()] = value.strip()
            print(f"    {GREEN}Added: {key.strip()}{RESET}")
        else:
            print(f"    {YELLOW}Format: Header-Name: value{RESET}")

    # Body data
    data = None
    if method in ['POST', 'PUT', 'PATCH']:
        print(f"\n  {BOLD}Request Body:{RESET}")
        print(f"  {DIM}Enter JSON or key=value pairs (empty to skip){RESET}")

        body_input = input(f"  {CYAN}Body:{RESET} ").strip()

        if body_input:
            # Try to parse as JSON
            try:
                data = json.loads(body_input)
            except:
                # Try key=value format
                if '=' in body_input:
                    data = dict(pair.split('=', 1) for pair in body_input.split('&'))
                else:
                    data = body_input

    # Options
    print(f"\n  {BOLD}Options:{RESET}")
    follow = input(f"  {CYAN}Follow redirects? (y/N):{RESET} ").strip().lower() == 'y'
    verbose = input(f"  {CYAN}Verbose output? (y/N):{RESET} ").strip().lower() == 'y'

    options = {
        'follow': follow,
        'verbose': verbose
    }

    # Build command
    curl_cmd = build_curl_command(url, method, headers, data, options=options)

    print(f"\n  {BOLD}Generated cURL Command:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"\n{GREEN}{curl_cmd}{RESET}\n")

    # Execute?
    execute = input(f"  {CYAN}Execute request? (Y/n):{RESET} ").strip().lower()

    if execute != 'n':
        print(f"\n  {BOLD}Response:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        result = execute_request(url, method, headers, data)

        if 'error' in result:
            print(f"  {RED}Error: {result['error']}{RESET}")
        else:
            # Status
            status_color = GREEN if result['status'] < 400 else RED
            print(f"\n  {BOLD}Status:{RESET} {status_color}{result['status']} {result['reason']}{RESET}")

            # Headers
            if verbose:
                print(f"\n  {BOLD}Response Headers:{RESET}")
                for key, value in result['headers'].items():
                    print(f"  {CYAN}{key}:{RESET} {value}")

            # Body
            print(f"\n  {BOLD}Body:{RESET}")
            body = result['body']

            # Try to pretty print JSON
            try:
                json_body = json.loads(body)
                body = json.dumps(json_body, indent=2)
            except:
                pass

            # Truncate if too long
            if len(body) > 2000:
                body = body[:2000] + f"\n{DIM}... (truncated){RESET}"

            print(body)

    print()


def main():
    parser = argparse.ArgumentParser(description='cURL Builder')
    parser.add_argument('url', nargs='?', help='URL to request')
    parser.add_argument('--method', '-X', default='GET', help='HTTP method')
    parser.add_argument('--header', '-H', action='append', help='Header (Key: Value)')
    parser.add_argument('--data', '-d', help='Request body')
    parser.add_argument('--json', '-j', help='JSON data')
    parser.add_argument('--execute', '-e', action='store_true', help='Execute request')
    args = parser.parse_args()

    if not args.url:
        interactive_mode()
        return

    print(f"\n{BOLD}{CYAN}cURL Builder{RESET}\n")

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                key, value = h.split(':', 1)
                headers[key.strip()] = value.strip()

    # Parse data
    data = None
    if args.json:
        try:
            data = json.loads(args.json)
            headers['Content-Type'] = 'application/json'
        except:
            print(f"  {RED}Invalid JSON{RESET}\n")
            return
    elif args.data:
        data = args.data

    # Build command
    curl_cmd = build_curl_command(args.url, args.method, headers, data)
    print(f"{GREEN}{curl_cmd}{RESET}\n")

    if args.execute:
        print(f"  {BOLD}Response:{RESET}")
        result = execute_request(args.url, args.method, headers, data)

        if 'error' in result:
            print(f"  {RED}Error: {result['error']}{RESET}")
        else:
            status_color = GREEN if result['status'] < 400 else RED
            print(f"  Status: {status_color}{result['status']}{RESET}")
            print(result['body'][:1000])

    print()


if __name__ == '__main__':
    main()
