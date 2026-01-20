#!/usr/bin/env python3
"""
Cipher Toolkit - Encrypt/decrypt with various classical ciphers
Usage: cipher.py <text> [--cipher caesar] [--key 3]
"""

import argparse
import string

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def caesar_encrypt(text, shift):
    """Caesar cipher encryption"""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(text, shift):
    """Caesar cipher decryption"""
    return caesar_encrypt(text, -shift)


def caesar_bruteforce(text):
    """Try all 26 Caesar shifts"""
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(text, shift)
        results.append((shift, decrypted))
    return results


def rot13(text):
    """ROT13 encoding (Caesar with shift 13)"""
    return caesar_encrypt(text, 13)


def vigenere_encrypt(text, key):
    """Vigenere cipher encryption"""
    result = []
    key = key.upper()
    key_idx = 0

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)


def vigenere_decrypt(text, key):
    """Vigenere cipher decryption"""
    result = []
    key = key.upper()
    key_idx = 0

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)


def atbash(text):
    """Atbash cipher (reverse alphabet)"""
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return ''.join(result)


def xor_encrypt(text, key):
    """XOR encryption"""
    result = []
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        result.append(chr(ord(char) ^ ord(key_char)))
    return result


def xor_to_hex(text, key):
    """XOR encryption with hex output"""
    xored = xor_encrypt(text, key)
    return ''.join(f'{ord(c):02x}' for c in xored)


def hex_xor_decrypt(hex_text, key):
    """XOR decryption from hex"""
    try:
        bytes_data = bytes.fromhex(hex_text)
        result = []
        for i, b in enumerate(bytes_data):
            key_char = key[i % len(key)]
            result.append(chr(b ^ ord(key_char)))
        return ''.join(result)
    except:
        return "Invalid hex input"


def rail_fence_encrypt(text, rails):
    """Rail fence cipher encryption"""
    if rails < 2:
        return text

    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    return ''.join(''.join(rail) for rail in fence)


def rail_fence_decrypt(text, rails):
    """Rail fence cipher decryption"""
    if rails < 2:
        return text

    # Calculate lengths for each rail
    lengths = [0] * rails
    rail = 0
    direction = 1
    for _ in text:
        lengths[rail] += 1
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # Split text into rails
    fence = []
    idx = 0
    for length in lengths:
        fence.append(list(text[idx:idx+length]))
        idx += length

    # Read off in zigzag pattern
    result = []
    rail = 0
    direction = 1
    for _ in text:
        result.append(fence[rail].pop(0))
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    return ''.join(result)


def morse_encode(text):
    """Encode to Morse code"""
    MORSE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    return ' '.join(MORSE.get(c.upper(), c) for c in text)


def morse_decode(text):
    """Decode from Morse code"""
    MORSE_REV = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' '
    }
    return ''.join(MORSE_REV.get(c, c) for c in text.split())


def a1z26_encode(text):
    """A1Z26 cipher (A=1, B=2, etc.)"""
    result = []
    for char in text:
        if char.isalpha():
            result.append(str(ord(char.upper()) - ord('A') + 1))
        elif char == ' ':
            result.append('0')
        else:
            result.append(char)
    return '-'.join(result)


def a1z26_decode(text):
    """A1Z26 cipher decode"""
    result = []
    for num in text.replace(' ', '-').split('-'):
        try:
            n = int(num)
            if n == 0:
                result.append(' ')
            elif 1 <= n <= 26:
                result.append(chr(ord('A') + n - 1))
        except:
            result.append(num)
    return ''.join(result)


def binary_encode(text):
    """Encode to binary"""
    return ' '.join(format(ord(c), '08b') for c in text)


def binary_decode(text):
    """Decode from binary"""
    try:
        return ''.join(chr(int(b, 2)) for b in text.split())
    except:
        return "Invalid binary"


def main():
    parser = argparse.ArgumentParser(description='Cipher Toolkit')
    parser.add_argument('text', nargs='?', help='Text to process')
    parser.add_argument('--cipher', '-c', default='caesar',
                        choices=['caesar', 'vigenere', 'atbash', 'xor', 'rail', 'rot13',
                                'morse', 'a1z26', 'binary', 'all'],
                        help='Cipher to use')
    parser.add_argument('--key', '-k', default='3', help='Key/shift value')
    parser.add_argument('--decrypt', '-d', action='store_true', help='Decrypt mode')
    parser.add_argument('--bruteforce', '-b', action='store_true', help='Bruteforce (Caesar only)')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    args = parser.parse_args()

    if args.interactive or not args.text:
        interactive_menu()
        return

    text = args.text
    cipher = args.cipher
    key = args.key
    decrypt = args.decrypt

    print(f"\n{BOLD}{CYAN}Cipher Toolkit{RESET}\n")
    print(f"  {DIM}Input: {text}{RESET}")
    print(f"  {DIM}Cipher: {cipher}{RESET}")
    print(f"  {DIM}Mode: {'Decrypt' if decrypt else 'Encrypt'}{RESET}\n")

    if cipher == 'all':
        show_all_ciphers(text)
        return

    if cipher == 'caesar':
        shift = int(key)
        if args.bruteforce:
            print(f"  {BOLD}Bruteforce results:{RESET}\n")
            for shift, result in caesar_bruteforce(text):
                print(f"    [{shift:2}] {result}")
        else:
            result = caesar_decrypt(text, shift) if decrypt else caesar_encrypt(text, shift)
            print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'rot13':
        result = rot13(text)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'vigenere':
        if decrypt:
            result = vigenere_decrypt(text, key)
        else:
            result = vigenere_encrypt(text, key)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'atbash':
        result = atbash(text)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'xor':
        if decrypt:
            result = hex_xor_decrypt(text, key)
        else:
            result = xor_to_hex(text, key)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'rail':
        rails = int(key)
        if decrypt:
            result = rail_fence_decrypt(text, rails)
        else:
            result = rail_fence_encrypt(text, rails)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'morse':
        if decrypt:
            result = morse_decode(text)
        else:
            result = morse_encode(text)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'a1z26':
        if decrypt:
            result = a1z26_decode(text)
        else:
            result = a1z26_encode(text)
        print(f"  {GREEN}Result: {result}{RESET}")

    elif cipher == 'binary':
        if decrypt:
            result = binary_decode(text)
        else:
            result = binary_encode(text)
        print(f"  {GREEN}Result: {result}{RESET}")

    print()


def show_all_ciphers(text):
    """Show text encoded with all ciphers"""
    print(f"  {BOLD}All Cipher Outputs:{RESET}\n")

    print(f"  {CYAN}Caesar (shift 3):{RESET} {caesar_encrypt(text, 3)}")
    print(f"  {CYAN}Caesar (shift 13/ROT13):{RESET} {rot13(text)}")
    print(f"  {CYAN}Atbash:{RESET} {atbash(text)}")
    print(f"  {CYAN}Vigenere (key=KEY):{RESET} {vigenere_encrypt(text, 'KEY')}")
    print(f"  {CYAN}Rail Fence (3 rails):{RESET} {rail_fence_encrypt(text, 3)}")
    print(f"  {CYAN}Morse:{RESET} {morse_encode(text)}")
    print(f"  {CYAN}A1Z26:{RESET} {a1z26_encode(text)}")
    print(f"  {CYAN}Binary:{RESET} {binary_encode(text)}")
    print(f"  {CYAN}XOR (key=K) hex:{RESET} {xor_to_hex(text, 'K')}")
    print()


def interactive_menu():
    """Interactive cipher menu"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║           🔐 Cipher Toolkit                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════╝{RESET}\n")

    while True:
        print(f"  {BOLD}Select cipher:{RESET}")
        print(f"  [1] Caesar (shift cipher)")
        print(f"  [2] ROT13")
        print(f"  [3] Vigenere")
        print(f"  [4] Atbash")
        print(f"  [5] XOR")
        print(f"  [6] Rail Fence")
        print(f"  [7] Morse Code")
        print(f"  [8] A1Z26 (A=1, B=2...)")
        print(f"  [9] Binary")
        print(f"  [0] Exit")

        choice = input(f"\n  {GREEN}>{RESET} ").strip()

        if choice == '0':
            break

        text = input(f"  {CYAN}Text:{RESET} ").strip()
        if not text:
            continue

        mode = input(f"  {CYAN}[E]ncrypt or [D]ecrypt?{RESET} ").strip().lower()
        decrypt = mode.startswith('d')

        if choice == '1':
            shift = int(input(f"  {CYAN}Shift (1-25):{RESET} ") or '3')
            brute = input(f"  {CYAN}Bruteforce? (y/n):{RESET} ").strip().lower() == 'y'
            if brute:
                print(f"\n  {BOLD}All shifts:{RESET}")
                for s, r in caesar_bruteforce(text):
                    print(f"    [{s:2}] {r}")
            else:
                result = caesar_decrypt(text, shift) if decrypt else caesar_encrypt(text, shift)
                print(f"\n  {GREEN}Result: {result}{RESET}")
        elif choice == '2':
            print(f"\n  {GREEN}Result: {rot13(text)}{RESET}")
        elif choice == '3':
            key = input(f"  {CYAN}Key:{RESET} ") or 'KEY'
            result = vigenere_decrypt(text, key) if decrypt else vigenere_encrypt(text, key)
            print(f"\n  {GREEN}Result: {result}{RESET}")
        elif choice == '4':
            print(f"\n  {GREEN}Result: {atbash(text)}{RESET}")
        elif choice == '5':
            key = input(f"  {CYAN}Key:{RESET} ") or 'K'
            if decrypt:
                result = hex_xor_decrypt(text, key)
            else:
                result = xor_to_hex(text, key)
            print(f"\n  {GREEN}Result: {result}{RESET}")
        elif choice == '6':
            rails = int(input(f"  {CYAN}Rails (2-10):{RESET} ") or '3')
            result = rail_fence_decrypt(text, rails) if decrypt else rail_fence_encrypt(text, rails)
            print(f"\n  {GREEN}Result: {result}{RESET}")
        elif choice == '7':
            result = morse_decode(text) if decrypt else morse_encode(text)
            print(f"\n  {GREEN}Result: {result}{RESET}")
        elif choice == '8':
            result = a1z26_decode(text) if decrypt else a1z26_encode(text)
            print(f"\n  {GREEN}Result: {result}{RESET}")
        elif choice == '9':
            result = binary_decode(text) if decrypt else binary_encode(text)
            print(f"\n  {GREEN}Result: {result}{RESET}")

        print()


if __name__ == '__main__':
    main()
