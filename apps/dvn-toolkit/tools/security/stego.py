#!/usr/bin/env python3
"""
Steganography Tool - Hide/extract data in images
Usage: stego hide <image> <message> [--output out.png]
       stego extract <image>
       stego analyze <image>
"""

import argparse
import struct
import zlib
import os
from pathlib import Path

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Magic signature for our hidden data
MAGIC = b'DVNSTEG1'


def read_png_chunks(filepath):
    """Read PNG file and return chunks"""
    chunks = []
    with open(filepath, 'rb') as f:
        signature = f.read(8)
        if signature != b'\x89PNG\r\n\x1a\n':
            raise ValueError("Not a valid PNG file")

        while True:
            length_bytes = f.read(4)
            if not length_bytes:
                break

            length = struct.unpack('>I', length_bytes)[0]
            chunk_type = f.read(4)
            data = f.read(length)
            crc = f.read(4)

            chunks.append({
                'type': chunk_type,
                'data': data,
                'length': length
            })

            if chunk_type == b'IEND':
                break

    return chunks


def write_png_chunks(filepath, chunks):
    """Write PNG file from chunks"""
    with open(filepath, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')

        for chunk in chunks:
            chunk_type = chunk['type']
            data = chunk['data']

            f.write(struct.pack('>I', len(data)))
            f.write(chunk_type)
            f.write(data)

            crc = zlib.crc32(chunk_type + data) & 0xffffffff
            f.write(struct.pack('>I', crc))


def hide_in_png(image_path, message, output_path):
    """Hide message in PNG using tEXt chunk"""
    chunks = read_png_chunks(image_path)

    # Compress and encode message
    compressed = zlib.compress(message.encode())
    hidden_data = MAGIC + struct.pack('>I', len(message)) + compressed

    # Create a tEXt chunk with our data (disguised as a comment)
    keyword = b'Comment'
    text_data = keyword + b'\x00' + hidden_data

    # Create new chunk
    new_chunk = {
        'type': b'tEXt',
        'data': text_data
    }

    # Insert before IEND
    for i, chunk in enumerate(chunks):
        if chunk['type'] == b'IEND':
            chunks.insert(i, new_chunk)
            break

    write_png_chunks(output_path, chunks)
    return len(hidden_data)


def extract_from_png(image_path):
    """Extract hidden message from PNG"""
    chunks = read_png_chunks(image_path)

    for chunk in chunks:
        if chunk['type'] == b'tEXt':
            data = chunk['data']
            if b'\x00' in data:
                keyword, content = data.split(b'\x00', 1)
                if content.startswith(MAGIC):
                    content = content[len(MAGIC):]
                    msg_len = struct.unpack('>I', content[:4])[0]
                    compressed = content[4:]
                    try:
                        message = zlib.decompress(compressed).decode()
                        return message[:msg_len]
                    except:
                        pass

    return None


def lsb_hide(image_path, message, output_path):
    """Hide message in image LSB (works with BMP, simple implementation)"""
    with open(image_path, 'rb') as f:
        data = bytearray(f.read())

    # For BMP files
    if data[:2] == b'BM':
        offset = struct.unpack('<I', data[10:14])[0]
    else:
        offset = 0

    # Prepare message
    message_bytes = MAGIC + struct.pack('>I', len(message)) + message.encode()
    bits = ''.join(format(byte, '08b') for byte in message_bytes)

    if len(bits) > len(data) - offset:
        raise ValueError("Message too large for this image")

    # Embed in LSB
    for i, bit in enumerate(bits):
        data[offset + i] = (data[offset + i] & 0xFE) | int(bit)

    with open(output_path, 'wb') as f:
        f.write(data)

    return len(message_bytes)


def lsb_extract(image_path):
    """Extract message from LSB"""
    with open(image_path, 'rb') as f:
        data = f.read()

    # Find offset
    if data[:2] == b'BM':
        offset = struct.unpack('<I', data[10:14])[0]
    else:
        offset = 0

    # Extract bits
    extracted = []
    for i in range(len(MAGIC) + 4 + 10000):  # Reasonable max
        if offset + i >= len(data):
            break
        extracted.append(str(data[offset + i] & 1))

    # Convert to bytes
    bits = ''.join(extracted)
    bytes_data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

    if not bytes_data.startswith(MAGIC):
        return None

    bytes_data = bytes_data[len(MAGIC):]
    msg_len = struct.unpack('>I', bytes_data[:4])[0]
    message = bytes_data[4:4+msg_len].decode('utf-8', errors='replace')

    return message


def analyze_image(image_path):
    """Analyze image for potential hidden data"""
    findings = []

    with open(image_path, 'rb') as f:
        data = f.read()

    # Check file type
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        file_type = 'PNG'
    elif data[:2] == b'BM':
        file_type = 'BMP'
    elif data[:2] == b'\xff\xd8':
        file_type = 'JPEG'
    elif data[:4] == b'GIF8':
        file_type = 'GIF'
    else:
        file_type = 'Unknown'

    findings.append(('File Type', file_type))
    findings.append(('File Size', f'{len(data):,} bytes'))

    # PNG specific analysis
    if file_type == 'PNG':
        chunks = read_png_chunks(image_path)
        chunk_types = [c['type'].decode() for c in chunks]
        findings.append(('PNG Chunks', ', '.join(chunk_types)))

        # Look for suspicious chunks
        for chunk in chunks:
            if chunk['type'] == b'tEXt':
                keyword = chunk['data'].split(b'\x00')[0].decode()
                content = chunk['data'].split(b'\x00', 1)[1] if b'\x00' in chunk['data'] else b''
                findings.append(('tEXt Chunk', f'{keyword}: {len(content)} bytes'))

                if MAGIC in content:
                    findings.append(('Hidden Data', 'DVN Stego signature detected!'))

            elif chunk['type'] not in [b'IHDR', b'IDAT', b'IEND', b'PLTE', b'tRNS', b'gAMA', b'sRGB']:
                findings.append(('Unusual Chunk', chunk['type'].decode()))

    # Check for appended data after file
    if file_type == 'JPEG':
        # JPEG ends with FFD9
        end_idx = data.rfind(b'\xff\xd9')
        if end_idx != -1 and end_idx < len(data) - 2:
            appended = len(data) - end_idx - 2
            findings.append(('Appended Data', f'{appended} bytes after JPEG end marker'))

    # Check for common steganography signatures
    signatures = [
        (MAGIC, 'DVN Stego'),
        (b'PK\x03\x04', 'ZIP archive'),
        (b'Rar!', 'RAR archive'),
        (b'7z\xbc\xaf', '7-Zip archive'),
        (b'%PDF', 'PDF document'),
    ]

    for sig, name in signatures:
        if sig in data[100:]:  # Skip header
            findings.append(('Embedded', f'{name} signature found'))

    return findings


def main():
    parser = argparse.ArgumentParser(description='Steganography Tool')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Hide command
    hide_parser = subparsers.add_parser('hide', help='Hide message in image')
    hide_parser.add_argument('image', help='Input image')
    hide_parser.add_argument('message', help='Message to hide (or @file to read from file)')
    hide_parser.add_argument('--output', '-o', help='Output image')
    hide_parser.add_argument('--method', '-m', choices=['png', 'lsb'], default='png',
                            help='Hiding method')

    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract hidden message')
    extract_parser.add_argument('image', help='Image to extract from')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze image for hidden data')
    analyze_parser.add_argument('image', help='Image to analyze')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    print(f"\n{BOLD}{CYAN}Steganography Tool{RESET}\n")

    if args.command == 'hide':
        # Read message
        message = args.message
        if message.startswith('@'):
            with open(message[1:]) as f:
                message = f.read()

        # Determine output path
        output = args.output
        if not output:
            p = Path(args.image)
            output = str(p.parent / f"{p.stem}_stego{p.suffix}")

        print(f"Input: {args.image}")
        print(f"Message: {len(message)} characters")
        print(f"Output: {output}")

        try:
            if args.method == 'png' or args.image.lower().endswith('.png'):
                size = hide_in_png(args.image, message, output)
            else:
                size = lsb_hide(args.image, message, output)

            print(f"\n{GREEN}Success!{RESET} Hidden {size} bytes in image")
            print(f"Output saved to: {output}")

        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")

    elif args.command == 'extract':
        print(f"Image: {args.image}")

        message = None

        # Try PNG method first
        if args.image.lower().endswith('.png'):
            message = extract_from_png(args.image)

        # Try LSB method
        if not message:
            message = lsb_extract(args.image)

        if message:
            print(f"\n{GREEN}Hidden message found!{RESET}")
            print(f"\n{BOLD}Message:{RESET}")
            print(message)
        else:
            print(f"\n{YELLOW}No hidden message found (using DVN Stego format){RESET}")

    elif args.command == 'analyze':
        print(f"Image: {args.image}")
        print()

        findings = analyze_image(args.image)

        for key, value in findings:
            color = GREEN if 'Hidden' in key or 'Embedded' in key else CYAN
            print(f"  {color}{key}:{RESET} {value}")

    print()


if __name__ == '__main__':
    main()
