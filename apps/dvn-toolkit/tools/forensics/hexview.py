#!/usr/bin/env python3
"""
Hex Viewer - View and analyze files in hexadecimal
Usage: hexview.py <file> [--offset 0] [--length 256]
"""

import argparse
import os
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
MAGENTA = '\033[95m'

# Magic bytes for file type detection
MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'GIF87a': 'GIF Image (87a)',
    b'GIF89a': 'GIF Image (89a)',
    b'%PDF': 'PDF Document',
    b'PK\x03\x04': 'ZIP/Office Archive',
    b'PK\x05\x06': 'ZIP (empty)',
    b'\x1f\x8b': 'GZIP',
    b'BZh': 'BZIP2',
    b'\xfd7zXZ': 'XZ',
    b'Rar!\x1a\x07': 'RAR Archive',
    b'7z\xbc\xaf\x27\x1c': '7-Zip',
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': 'MP4/M4A Video',
    b'\x00\x00\x00\x20\x66\x74\x79\x70': 'MP4 Video',
    b'ID3': 'MP3 Audio (ID3)',
    b'\xff\xfb': 'MP3 Audio',
    b'\xff\xfa': 'MP3 Audio',
    b'OggS': 'OGG Audio/Video',
    b'fLaC': 'FLAC Audio',
    b'RIFF': 'WAV/AVI',
    b'\x1aE\xdf\xa3': 'MKV/WebM Video',
    b'\x7fELF': 'ELF Executable',
    b'MZ': 'Windows Executable',
    b'\xca\xfe\xba\xbe': 'Java Class/Mach-O Fat',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit',
    b'\xce\xfa\xed\xfe': 'Mach-O 32-bit',
    b'SQLite format 3': 'SQLite Database',
    b'<!DOCTYPE': 'HTML Document',
    b'<html': 'HTML Document',
    b'<?xml': 'XML Document',
    b'{\n': 'JSON (likely)',
    b'[': 'JSON Array (likely)',
    b'#!/': 'Script (shebang)',
}


def detect_file_type(data):
    """Detect file type from magic bytes"""
    for magic, file_type in MAGIC_BYTES.items():
        if data.startswith(magic):
            return file_type
    return None


def is_printable(byte):
    """Check if byte is printable ASCII"""
    return 32 <= byte <= 126


def colorize_byte(byte):
    """Colorize byte based on type"""
    if byte == 0:
        return f'{DIM}00{RESET}'
    elif is_printable(byte):
        return f'{GREEN}{byte:02x}{RESET}'
    elif byte == 0xff:
        return f'{RED}ff{RESET}'
    elif byte < 32:
        return f'{YELLOW}{byte:02x}{RESET}'
    else:
        return f'{CYAN}{byte:02x}{RESET}'


def format_ascii(data):
    """Format bytes as ASCII with dots for non-printable"""
    result = []
    for byte in data:
        if is_printable(byte):
            result.append(chr(byte))
        else:
            result.append(f'{DIM}.{RESET}')
    return ''.join(result)


def hexdump(data, offset=0, bytes_per_line=16, colorize=True):
    """Generate hex dump"""
    lines = []

    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        addr = offset + i

        # Address
        addr_str = f'{CYAN}{addr:08x}{RESET}'

        # Hex bytes
        hex_parts = []
        for j, byte in enumerate(chunk):
            if colorize:
                hex_parts.append(colorize_byte(byte))
            else:
                hex_parts.append(f'{byte:02x}')

            # Add extra space in middle
            if j == 7:
                hex_parts.append(' ')

        # Pad if short line
        hex_str = ' '.join(hex_parts)
        padding = (bytes_per_line * 3 + 1) - len(' '.join([f'{b:02x}' for b in chunk])) - (1 if len(chunk) > 8 else 0)

        # ASCII representation
        ascii_str = format_ascii(chunk)

        lines.append(f'{addr_str}  {hex_str}{" " * max(0, padding)}  |{ascii_str}|')

    return '\n'.join(lines)


def find_strings(data, min_length=4):
    """Find ASCII strings in binary data"""
    strings = []
    current = []
    start_offset = 0

    for i, byte in enumerate(data):
        if is_printable(byte):
            if not current:
                start_offset = i
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append((start_offset, ''.join(current)))
            current = []

    if len(current) >= min_length:
        strings.append((start_offset, ''.join(current)))

    return strings


def analyze_entropy(data, block_size=256):
    """Calculate entropy of data blocks"""
    import math

    def calc_entropy(block):
        if not block:
            return 0
        freq = {}
        for byte in block:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0
        for count in freq.values():
            p = count / len(block)
            entropy -= p * math.log2(p)
        return entropy

    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        ent = calc_entropy(block)
        blocks.append((i, ent))

    return blocks


def main():
    parser = argparse.ArgumentParser(description='Hex Viewer')
    parser.add_argument('file', help='File to view')
    parser.add_argument('--offset', '-o', type=int, default=0, help='Start offset')
    parser.add_argument('--length', '-l', type=int, default=512, help='Number of bytes to show')
    parser.add_argument('--all', '-a', action='store_true', help='Show entire file')
    parser.add_argument('--strings', '-s', action='store_true', help='Extract strings')
    parser.add_argument('--entropy', '-e', action='store_true', help='Show entropy analysis')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    parser.add_argument('--width', '-w', type=int, default=16, help='Bytes per line')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"{RED}File not found: {args.file}{RESET}")
        return

    file_size = os.path.getsize(args.file)

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔍 Hex Viewer                                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {BOLD}File:{RESET} {args.file}")
    print(f"  {BOLD}Size:{RESET} {file_size:,} bytes ({file_size / 1024:.1f} KB)")

    # Read file
    with open(args.file, 'rb') as f:
        if args.all:
            data = f.read()
        else:
            f.seek(args.offset)
            data = f.read(args.length)

    # Detect file type
    with open(args.file, 'rb') as f:
        header = f.read(32)
    file_type = detect_file_type(header)
    if file_type:
        print(f"  {BOLD}Type:{RESET} {GREEN}{file_type}{RESET}")

    print()

    # String extraction mode
    if args.strings:
        with open(args.file, 'rb') as f:
            full_data = f.read()
        strings = find_strings(full_data)

        print(f"  {BOLD}Strings Found:{RESET} {len(strings)}\n")
        for offset, string in strings[:100]:
            print(f"  {CYAN}{offset:08x}{RESET}: {string[:80]}")
        if len(strings) > 100:
            print(f"\n  {DIM}... and {len(strings) - 100} more{RESET}")
        print()
        return

    # Entropy analysis mode
    if args.entropy:
        with open(args.file, 'rb') as f:
            full_data = f.read()
        blocks = analyze_entropy(full_data)

        print(f"  {BOLD}Entropy Analysis:{RESET}\n")
        max_entropy = 8.0

        for offset, entropy in blocks[:50]:
            bar_len = int((entropy / max_entropy) * 40)
            bar = '█' * bar_len + '░' * (40 - bar_len)

            if entropy > 7.5:
                color = RED
                note = " (encrypted/compressed?)"
            elif entropy > 6:
                color = YELLOW
                note = ""
            else:
                color = GREEN
                note = ""

            print(f"  {CYAN}{offset:08x}{RESET} {color}{bar} {entropy:.2f}{note}{RESET}")

        avg_entropy = sum(e for _, e in blocks) / len(blocks) if blocks else 0
        print(f"\n  {BOLD}Average Entropy:{RESET} {avg_entropy:.2f}/8.0")
        if avg_entropy > 7.5:
            print(f"  {YELLOW}⚠ High entropy suggests encrypted or compressed data{RESET}")
        print()
        return

    # Hex dump
    print(f"  {BOLD}Hex Dump:{RESET} (offset {args.offset}, {len(data)} bytes)\n")
    print(hexdump(data, args.offset, args.width, not args.no_color))
    print()

    # Show color legend
    print(f"  {BOLD}Legend:{RESET} {DIM}00=null{RESET} {GREEN}XX=printable{RESET} {YELLOW}XX=control{RESET} {RED}ff{RESET} {CYAN}XX=other{RESET}")
    print()


if __name__ == '__main__':
    main()
