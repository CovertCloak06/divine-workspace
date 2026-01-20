#!/usr/bin/env python3
"""
QR Code Tool - Generate and decode QR codes (ASCII art in terminal)
Usage: qrcode generate "Hello World" [--output qr.png]
       qrcode decode image.png
"""

import argparse
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'


def generate_qr_data(text):
    """Generate QR code matrix (simplified version for ASCII display)"""
    # This is a simplified QR code generator for ASCII art
    # For production, use a proper library like qrcode

    # Calculate size needed
    version = 1  # Smallest
    size = 21 + (version - 1) * 4

    # Initialize matrix
    matrix = [[0] * size for _ in range(size)]

    # Add finder patterns (top-left, top-right, bottom-left)
    def add_finder(row, col):
        for r in range(7):
            for c in range(7):
                if (r in [0, 6] or c in [0, 6] or
                    (2 <= r <= 4 and 2 <= c <= 4)):
                    if 0 <= row + r < size and 0 <= col + c < size:
                        matrix[row + r][col + c] = 1

    add_finder(0, 0)
    add_finder(0, size - 7)
    add_finder(size - 7, 0)

    # Add timing patterns
    for i in range(8, size - 8):
        matrix[6][i] = 1 if i % 2 == 0 else 0
        matrix[i][6] = 1 if i % 2 == 0 else 0

    # Encode data (simplified - just visual representation)
    data_bits = ''.join(format(ord(c), '08b') for c in text)

    # Fill data area with pattern based on text
    bit_idx = 0
    for row in range(size):
        for col in range(size):
            if matrix[row][col] == 0:
                # Skip reserved areas
                if row < 9 and (col < 9 or col > size - 9):
                    continue
                if row > size - 9 and col < 9:
                    continue
                if row == 6 or col == 6:
                    continue

                if bit_idx < len(data_bits):
                    matrix[row][col] = int(data_bits[bit_idx])
                    bit_idx += 1
                else:
                    # Pattern fill
                    matrix[row][col] = (row + col) % 2

    return matrix


def matrix_to_ascii(matrix, invert=False):
    """Convert matrix to ASCII art"""
    lines = []

    # Top border
    width = len(matrix[0]) * 2 + 4
    lines.append('█' * width)
    lines.append('█' + ' ' * (width - 2) + '█')

    for row in matrix:
        line = '█ '
        for cell in row:
            if invert:
                cell = 1 - cell
            line += '██' if cell else '  '
        line += ' █'
        lines.append(line)

    lines.append('█' + ' ' * (width - 2) + '█')
    lines.append('█' * width)

    return '\n'.join(lines)


def decode_qr_from_file(filepath):
    """Attempt to decode QR from image file"""
    # This would require pyzbar or similar library
    # For now, provide instructions

    return None, "QR decoding requires additional libraries (pyzbar, PIL)"


def generate_svg(matrix, filepath, cell_size=10):
    """Generate SVG QR code"""
    size = len(matrix)
    svg_size = size * cell_size + 40  # Add quiet zone

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{svg_size}" height="{svg_size}">
<rect width="100%" height="100%" fill="white"/>
'''

    for row in range(size):
        for col in range(size):
            if matrix[row][col]:
                x = 20 + col * cell_size
                y = 20 + row * cell_size
                svg += f'<rect x="{x}" y="{y}" width="{cell_size}" height="{cell_size}" fill="black"/>\n'

    svg += '</svg>'

    with open(filepath, 'w') as f:
        f.write(svg)


def main():
    parser = argparse.ArgumentParser(description='QR Code Tool')
    subparsers = parser.add_subparsers(dest='command')

    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate QR code')
    gen_parser.add_argument('text', help='Text to encode')
    gen_parser.add_argument('--output', '-o', help='Output file (SVG)')
    gen_parser.add_argument('--invert', '-i', action='store_true', help='Invert colors')

    # Decode command
    dec_parser = subparsers.add_parser('decode', help='Decode QR code')
    dec_parser.add_argument('image', help='Image file to decode')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    print(f"\n{BOLD}{CYAN}QR Code Tool{RESET}\n")

    if args.command == 'generate':
        text = args.text

        # Show text info
        print(f"Text: {text[:50]}{'...' if len(text) > 50 else ''}")
        print(f"Length: {len(text)} characters\n")

        # Generate matrix
        matrix = generate_qr_data(text)

        # Display ASCII version
        print(matrix_to_ascii(matrix, args.invert))

        # Save to file if requested
        if args.output:
            if args.output.endswith('.svg'):
                generate_svg(matrix, args.output)
                print(f"\n{GREEN}Saved to: {args.output}{RESET}")
            else:
                print(f"\n{YELLOW}Note: Only SVG output is supported without PIL{RESET}")

        print(f"\n{DIM}Note: This is a simplified QR visualization.{RESET}")
        print(f"{DIM}For scannable QR codes, use a proper library.{RESET}")

    elif args.command == 'decode':
        result, error = decode_qr_from_file(args.image)

        if result:
            print(f"{GREEN}Decoded:{RESET}")
            print(result)
        else:
            print(f"{YELLOW}{error}{RESET}")
            print(f"\nTo decode QR codes, install: pip install pyzbar pillow")

    print()


if __name__ == '__main__':
    main()
