#!/usr/bin/env python3
"""
Encoder/Decoder - Multi-format encoding tool for CTFs and security work
Usage: encoder <input> [--encode base64] [--decode] [--all]
"""

import argparse
import base64
import binascii
import html
import urllib.parse
import codecs
import hashlib
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

def safe_decode(func, data, name):
    """Safely try a decode operation"""
    try:
        result = func(data)
        return result if result != data else None
    except:
        return None

# Encoding functions
def to_base64(data):
    return base64.b64encode(data.encode()).decode()

def from_base64(data):
    return base64.b64decode(data).decode()

def to_base32(data):
    return base64.b32encode(data.encode()).decode()

def from_base32(data):
    return base64.b32decode(data).decode()

def to_hex(data):
    return binascii.hexlify(data.encode()).decode()

def from_hex(data):
    return binascii.unhexlify(data).decode()

def to_url(data):
    return urllib.parse.quote(data)

def from_url(data):
    return urllib.parse.unquote(data)

def to_html(data):
    return html.escape(data)

def from_html(data):
    return html.unescape(data)

def to_rot13(data):
    return codecs.encode(data, 'rot_13')

def from_rot13(data):
    return codecs.decode(data, 'rot_13')

def to_binary(data):
    return ' '.join(format(ord(c), '08b') for c in data)

def from_binary(data):
    data = data.replace(' ', '')
    return ''.join(chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8))

def to_octal(data):
    return ' '.join(format(ord(c), 'o') for c in data)

def from_octal(data):
    return ''.join(chr(int(o, 8)) for o in data.split())

def to_decimal(data):
    return ' '.join(str(ord(c)) for c in data)

def from_decimal(data):
    return ''.join(chr(int(d)) for d in data.split())

def to_reverse(data):
    return data[::-1]

def to_upper(data):
    return data.upper()

def to_lower(data):
    return data.lower()

def to_morse(data):
    morse = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    return ' '.join(morse.get(c.upper(), c) for c in data)

def from_morse(data):
    morse = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' '
    }
    return ''.join(morse.get(c, c) for c in data.split())

def caesar(data, shift):
    result = []
    for c in data:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

def xor_encode(data, key):
    """XOR encode/decode"""
    result = []
    for i, c in enumerate(data):
        result.append(chr(ord(c) ^ ord(key[i % len(key)])))
    return ''.join(result)

ENCODERS = {
    'base64': (to_base64, from_base64),
    'base32': (to_base32, from_base32),
    'hex': (to_hex, from_hex),
    'url': (to_url, from_url),
    'html': (to_html, from_html),
    'rot13': (to_rot13, from_rot13),
    'binary': (to_binary, from_binary),
    'octal': (to_octal, from_octal),
    'decimal': (to_decimal, from_decimal),
    'morse': (to_morse, from_morse),
    'reverse': (to_reverse, to_reverse),
    'upper': (to_upper, to_lower),
    'lower': (to_lower, to_upper),
}

def auto_decode(data):
    """Try to auto-decode input"""
    results = []

    # Try each decoder
    for name, (enc, dec) in ENCODERS.items():
        try:
            result = dec(data)
            if result and result != data and result.isprintable():
                results.append((name, result))
        except:
            pass

    # Try caesar shifts
    for shift in range(1, 26):
        result = caesar(data, shift)
        if result != data:
            # Simple heuristic: check for common English patterns
            if any(word in result.lower() for word in ['the', 'and', 'flag', 'key', 'password']):
                results.append((f'caesar-{shift}', result))

    return results

def main():
    parser = argparse.ArgumentParser(description='Encoder/Decoder Tool')
    parser.add_argument('input', nargs='?', help='Input string (or use stdin)')
    parser.add_argument('--encode', '-e', choices=list(ENCODERS.keys()), help='Encoding type')
    parser.add_argument('--decode', '-d', choices=list(ENCODERS.keys()), help='Decoding type')
    parser.add_argument('--all', '-a', action='store_true', help='Show all encodings')
    parser.add_argument('--auto', action='store_true', help='Auto-detect and decode')
    parser.add_argument('--caesar', '-c', type=int, metavar='SHIFT', help='Caesar cipher shift')
    parser.add_argument('--xor', '-x', metavar='KEY', help='XOR with key')
    args = parser.parse_args()

    # Get input
    if args.input:
        data = args.input
    elif not sys.stdin.isatty():
        data = sys.stdin.read().strip()
    else:
        print(f"{RED}No input provided{RESET}")
        return

    print(f"\n{BOLD}{CYAN}Encoder/Decoder{RESET}")
    print(f"Input: {data[:50]}{'...' if len(data) > 50 else ''}\n")

    # Auto decode
    if args.auto:
        print(f"{BOLD}Auto-decode results:{RESET}")
        results = auto_decode(data)
        if results:
            for name, result in results:
                display = result[:60] + '...' if len(result) > 60 else result
                print(f"  {GREEN}{name:10}{RESET} {display}")
        else:
            print(f"  {DIM}No decodings found{RESET}")
        print()
        return

    # Show all encodings
    if args.all:
        print(f"{BOLD}All encodings:{RESET}")
        for name, (enc, dec) in ENCODERS.items():
            try:
                result = enc(data)
                display = result[:50] + '...' if len(result) > 50 else result
                print(f"  {CYAN}{name:10}{RESET} {display}")
            except Exception as e:
                print(f"  {name:10} {DIM}(error){RESET}")

        # Hashes
        print(f"\n{BOLD}Hashes:{RESET}")
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            h = hashlib.new(algo, data.encode()).hexdigest()
            print(f"  {CYAN}{algo:10}{RESET} {h}")
        print()
        return

    # Specific encoding/decoding
    if args.encode:
        encoder = ENCODERS[args.encode][0]
        result = encoder(data)
        print(f"{GREEN}{args.encode}:{RESET} {result}\n")
        return

    if args.decode:
        decoder = ENCODERS[args.decode][1]
        try:
            result = decoder(data)
            print(f"{GREEN}Decoded:{RESET} {result}\n")
        except Exception as e:
            print(f"{RED}Decode error: {e}{RESET}\n")
        return

    # Caesar cipher
    if args.caesar is not None:
        result = caesar(data, args.caesar)
        print(f"{GREEN}Caesar ({args.caesar}):{RESET} {result}\n")
        return

    # XOR
    if args.xor:
        result = xor_encode(data, args.xor)
        hex_result = to_hex(result)
        print(f"{GREEN}XOR ({args.xor}):{RESET}")
        print(f"  Hex: {hex_result}")
        print(f"  Raw: {repr(result)}\n")
        return

    # Default: show common encodings
    print(f"{BOLD}Common encodings:{RESET}")
    for name in ['base64', 'hex', 'url', 'rot13', 'binary']:
        try:
            result = ENCODERS[name][0](data)
            print(f"  {CYAN}{name:10}{RESET} {result}")
        except:
            pass
    print()

if __name__ == '__main__':
    main()
