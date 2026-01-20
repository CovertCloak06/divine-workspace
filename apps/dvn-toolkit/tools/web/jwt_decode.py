#!/usr/bin/env python3
"""
JWT Decoder - Decode and analyze JSON Web Tokens
Usage: jwt_decode.py <token> [--verify secret]
"""

import base64
import json
import argparse
import hmac
import hashlib
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def base64url_decode(data):
    """Decode base64url (JWT uses URL-safe base64 without padding)"""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding

    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')

    return base64.b64decode(data)


def decode_jwt(token):
    """Decode a JWT token into its parts"""
    parts = token.split('.')

    if len(parts) != 3:
        return None, None, None, "Invalid JWT format (expected 3 parts)"

    try:
        header = json.loads(base64url_decode(parts[0]))
    except Exception as e:
        return None, None, None, f"Failed to decode header: {e}"

    try:
        payload = json.loads(base64url_decode(parts[1]))
    except Exception as e:
        return None, None, None, f"Failed to decode payload: {e}"

    signature = parts[2]

    return header, payload, signature, None


def verify_signature(token, secret, algorithm='HS256'):
    """Verify JWT signature"""
    parts = token.split('.')
    if len(parts) != 3:
        return False

    message = f"{parts[0]}.{parts[1]}".encode()
    signature = base64url_decode(parts[2])

    if algorithm.startswith('HS'):
        if algorithm == 'HS256':
            expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        elif algorithm == 'HS384':
            expected = hmac.new(secret.encode(), message, hashlib.sha384).digest()
        elif algorithm == 'HS512':
            expected = hmac.new(secret.encode(), message, hashlib.sha512).digest()
        else:
            return None

        return hmac.compare_digest(signature, expected)

    return None  # RS/ES algorithms need crypto libraries


def format_timestamp(ts):
    """Format Unix timestamp"""
    try:
        dt = datetime.fromtimestamp(ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)


def analyze_payload(payload):
    """Analyze JWT payload for common claims"""
    analysis = []

    # Standard claims
    if 'exp' in payload:
        exp_time = datetime.fromtimestamp(payload['exp'])
        if exp_time < datetime.now():
            analysis.append(f"{RED}✗ Token EXPIRED at {format_timestamp(payload['exp'])}{RESET}")
        else:
            diff = exp_time - datetime.now()
            analysis.append(f"{GREEN}✓ Expires in {diff.days}d {diff.seconds//3600}h{RESET}")

    if 'iat' in payload:
        analysis.append(f"  Issued: {format_timestamp(payload['iat'])}")

    if 'nbf' in payload:
        nbf_time = datetime.fromtimestamp(payload['nbf'])
        if nbf_time > datetime.now():
            analysis.append(f"{YELLOW}⚠ Token not valid until {format_timestamp(payload['nbf'])}{RESET}")

    if 'iss' in payload:
        analysis.append(f"  Issuer: {payload['iss']}")

    if 'sub' in payload:
        analysis.append(f"  Subject: {payload['sub']}")

    if 'aud' in payload:
        analysis.append(f"  Audience: {payload['aud']}")

    return analysis


def main():
    parser = argparse.ArgumentParser(description='JWT Decoder')
    parser.add_argument('token', nargs='?', help='JWT token to decode')
    parser.add_argument('--verify', '-v', help='Secret key for signature verification')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    # Read token from stdin if not provided
    if not args.token:
        print(f"{CYAN}Paste JWT token (press Enter twice when done):{RESET}")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        token = ''.join(lines).strip()
    else:
        token = args.token.strip()

    # Remove 'Bearer ' prefix if present
    if token.lower().startswith('bearer '):
        token = token[7:]

    header, payload, signature, error = decode_jwt(token)

    if error:
        print(f"\n{RED}Error: {error}{RESET}\n")
        return

    if args.json:
        print(json.dumps({
            'header': header,
            'payload': payload,
            'signature': signature
        }, indent=2, default=str))
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔐 JWT Decoder                                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Header
    print(f"  {BOLD}Header:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    alg = header.get('alg', 'none')
    typ = header.get('typ', 'JWT')

    alg_color = RED if alg == 'none' else GREEN
    print(f"  {CYAN}Algorithm:{RESET} {alg_color}{alg}{RESET}")
    print(f"  {CYAN}Type:{RESET} {typ}")
    for key, value in header.items():
        if key not in ['alg', 'typ']:
            print(f"  {CYAN}{key}:{RESET} {value}")

    # Security warning for 'none' algorithm
    if alg == 'none':
        print(f"\n  {RED}⚠ WARNING: Algorithm is 'none' - signature not verified!{RESET}")

    # Payload
    print(f"\n  {BOLD}Payload:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    for key, value in payload.items():
        # Format known timestamp fields
        if key in ['exp', 'iat', 'nbf', 'auth_time']:
            formatted = format_timestamp(value)
            print(f"  {CYAN}{key}:{RESET} {value} {DIM}({formatted}){RESET}")
        elif isinstance(value, dict):
            print(f"  {CYAN}{key}:{RESET}")
            for k, v in value.items():
                print(f"    {k}: {v}")
        elif isinstance(value, list):
            print(f"  {CYAN}{key}:{RESET} {', '.join(str(v) for v in value)}")
        else:
            print(f"  {CYAN}{key}:{RESET} {value}")

    # Signature
    print(f"\n  {BOLD}Signature:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {DIM}{signature[:50]}{'...' if len(signature) > 50 else ''}{RESET}")

    # Analysis
    analysis = analyze_payload(payload)
    if analysis:
        print(f"\n  {BOLD}Analysis:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        for line in analysis:
            print(f"  {line}")

    # Verify signature if secret provided
    if args.verify:
        print(f"\n  {BOLD}Signature Verification:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        result = verify_signature(token, args.verify, alg)
        if result is True:
            print(f"  {GREEN}✓ Signature is VALID{RESET}")
        elif result is False:
            print(f"  {RED}✗ Signature is INVALID{RESET}")
        else:
            print(f"  {YELLOW}⚠ Cannot verify {alg} algorithm (only HS256/384/512 supported){RESET}")

    print()


if __name__ == '__main__':
    main()
