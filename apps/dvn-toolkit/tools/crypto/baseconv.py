#!/usr/bin/env python3
"""
Base Converter - Convert between number bases and encodings
Usage: baseconv.py <input> [--from auto] [--to all]
"""

import argparse
import base64
import binascii
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def detect_base(text):
    """Try to detect the input encoding/base"""
    text = text.strip()

    # Binary (only 0 and 1)
    if re.match(r'^[01\s]+$', text):
        return 'binary'

    # Octal (only 0-7, starts with 0o or just 0-7)
    if re.match(r'^0o[0-7]+$', text) or re.match(r'^[0-7]+$', text):
        if all(c in '01234567' for c in text.replace('0o', '')):
            return 'octal'

    # Hex (only 0-9, a-f)
    if re.match(r'^(0x)?[0-9a-fA-F\s]+$', text):
        return 'hex'

    # Decimal (only digits)
    if re.match(r'^\d+$', text):
        return 'decimal'

    # Base64 (alphanumeric + /+ and = padding)
    if re.match(r'^[A-Za-z0-9+/]+=*$', text):
        try:
            base64.b64decode(text)
            return 'base64'
        except:
            pass

    # ASCII text
    return 'ascii'


def to_int(text, base='auto'):
    """Convert input to integer"""
    text = text.strip()

    if base == 'auto':
        base = detect_base(text)

    if base == 'binary':
        return int(text.replace(' ', ''), 2)
    elif base == 'octal':
        return int(text.replace('0o', ''), 8)
    elif base == 'decimal':
        return int(text)
    elif base == 'hex':
        return int(text.replace('0x', '').replace(' ', ''), 16)
    elif base == 'ascii':
        return int.from_bytes(text.encode(), 'big')
    elif base == 'base64':
        try:
            decoded = base64.b64decode(text)
            return int.from_bytes(decoded, 'big')
        except:
            return 0
    else:
        return int(text)


def from_int(num, to_base):
    """Convert integer to target base"""
    if num == 0:
        if to_base == 'ascii':
            return ''
        return '0'

    if to_base == 'binary':
        return bin(num)[2:]
    elif to_base == 'octal':
        return oct(num)[2:]
    elif to_base == 'decimal':
        return str(num)
    elif to_base == 'hex':
        return hex(num)[2:]
    elif to_base == 'ascii':
        try:
            byte_len = (num.bit_length() + 7) // 8
            return num.to_bytes(byte_len, 'big').decode('utf-8', errors='replace')
        except:
            return f"<cannot decode: {num}>"
    elif to_base == 'base64':
        try:
            byte_len = (num.bit_length() + 7) // 8
            return base64.b64encode(num.to_bytes(byte_len, 'big')).decode()
        except:
            return f"<cannot encode>"
    else:
        return str(num)


def convert_all(text, from_base='auto'):
    """Convert to all bases"""
    results = {}

    if from_base == 'auto':
        from_base = detect_base(text)

    try:
        num = to_int(text, from_base)

        results['detected'] = from_base
        results['decimal'] = str(num)
        results['hex'] = hex(num)[2:].upper()
        results['binary'] = bin(num)[2:]
        results['octal'] = oct(num)[2:]

        # ASCII if printable
        try:
            byte_len = (num.bit_length() + 7) // 8 or 1
            ascii_val = num.to_bytes(byte_len, 'big').decode('utf-8', errors='replace')
            if ascii_val.isprintable() or '\n' in ascii_val:
                results['ascii'] = ascii_val
        except:
            pass

        # Base64
        try:
            byte_len = (num.bit_length() + 7) // 8 or 1
            results['base64'] = base64.b64encode(num.to_bytes(byte_len, 'big')).decode()
        except:
            pass

    except Exception as e:
        results['error'] = str(e)

    return results


def text_to_all(text):
    """Convert text to all representations"""
    results = {}

    text_bytes = text.encode('utf-8')

    results['ascii'] = text
    results['hex'] = text_bytes.hex().upper()
    results['binary'] = ' '.join(format(b, '08b') for b in text_bytes)
    results['decimal'] = ' '.join(str(b) for b in text_bytes)
    results['base64'] = base64.b64encode(text_bytes).decode()
    results['base32'] = base64.b32encode(text_bytes).decode()
    results['url'] = ''.join(f'%{b:02X}' for b in text_bytes)

    # Reverse
    results['reversed'] = text[::-1]

    # ROT13
    rot13 = ''
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            rot13 += chr((ord(c) - base + 13) % 26 + base)
        else:
            rot13 += c
    results['rot13'] = rot13

    return results


def main():
    parser = argparse.ArgumentParser(description='Base Converter')
    parser.add_argument('input', nargs='?', help='Input value')
    parser.add_argument('--from', '-f', dest='from_base', default='auto',
                        choices=['auto', 'binary', 'octal', 'decimal', 'hex', 'ascii', 'base64'],
                        help='Input base')
    parser.add_argument('--to', '-t', dest='to_base', default='all',
                        choices=['all', 'binary', 'octal', 'decimal', 'hex', 'ascii', 'base64'],
                        help='Output base')
    parser.add_argument('--text', action='store_true', help='Treat input as text')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    args = parser.parse_args()

    if args.interactive or not args.input:
        interactive_mode()
        return

    text = args.input

    print(f"\n{BOLD}{CYAN}Base Converter{RESET}\n")
    print(f"  {DIM}Input: {text}{RESET}\n")

    if args.text:
        results = text_to_all(text)
    else:
        results = convert_all(text, args.from_base)

    if 'detected' in results:
        print(f"  {DIM}Detected as: {results['detected']}{RESET}\n")

    for key, value in results.items():
        if key not in ['detected', 'error']:
            print(f"  {CYAN}{key:>10}:{RESET} {GREEN}{value}{RESET}")

    if 'error' in results:
        print(f"  {RED}Error: {results['error']}{RESET}")

    print()


def interactive_mode():
    """Interactive conversion mode"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║           🔢 Base Converter                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════╝{RESET}\n")

    while True:
        print(f"  {BOLD}Options:{RESET}")
        print(f"  [1] Convert number (auto-detect base)")
        print(f"  [2] Convert text to all formats")
        print(f"  [3] Hex to ASCII")
        print(f"  [4] ASCII to Hex")
        print(f"  [5] Binary to ASCII")
        print(f"  [6] Base64 decode")
        print(f"  [7] Base64 encode")
        print(f"  [0] Exit")

        choice = input(f"\n  {GREEN}>{RESET} ").strip()

        if choice == '0':
            break

        text = input(f"  {CYAN}Input:{RESET} ").strip()
        if not text:
            continue

        print()

        if choice == '1':
            results = convert_all(text)
            for key, value in results.items():
                if key not in ['detected', 'error']:
                    print(f"  {CYAN}{key:>10}:{RESET} {GREEN}{value}{RESET}")

        elif choice == '2':
            results = text_to_all(text)
            for key, value in results.items():
                print(f"  {CYAN}{key:>10}:{RESET} {GREEN}{value}{RESET}")

        elif choice == '3':
            try:
                result = bytes.fromhex(text.replace(' ', '')).decode('utf-8', errors='replace')
                print(f"  {GREEN}ASCII: {result}{RESET}")
            except Exception as e:
                print(f"  {RED}Error: {e}{RESET}")

        elif choice == '4':
            result = text.encode().hex().upper()
            print(f"  {GREEN}Hex: {result}{RESET}")

        elif choice == '5':
            try:
                bits = text.replace(' ', '')
                result = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
                print(f"  {GREEN}ASCII: {result}{RESET}")
            except Exception as e:
                print(f"  {RED}Error: {e}{RESET}")

        elif choice == '6':
            try:
                result = base64.b64decode(text).decode('utf-8', errors='replace')
                print(f"  {GREEN}Decoded: {result}{RESET}")
            except Exception as e:
                print(f"  {RED}Error: {e}{RESET}")

        elif choice == '7':
            result = base64.b64encode(text.encode()).decode()
            print(f"  {GREEN}Base64: {result}{RESET}")

        print()


if __name__ == '__main__':
    main()
