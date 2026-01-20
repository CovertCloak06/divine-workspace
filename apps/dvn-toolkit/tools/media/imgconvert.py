#!/usr/bin/env python3
"""
Image Converter - Convert and resize images
Usage: imgconvert.py <image> [--format png] [--resize 800x600]
"""

import os
import sys
import argparse
import struct
import zlib

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_image_info(filepath):
    """Get image dimensions and format from file"""
    info = {'format': None, 'width': 0, 'height': 0, 'size': 0}

    try:
        info['size'] = os.path.getsize(filepath)

        with open(filepath, 'rb') as f:
            header = f.read(32)

            # PNG
            if header[:8] == b'\x89PNG\r\n\x1a\n':
                info['format'] = 'PNG'
                if header[12:16] == b'IHDR':
                    info['width'] = struct.unpack('>I', header[16:20])[0]
                    info['height'] = struct.unpack('>I', header[20:24])[0]

            # JPEG
            elif header[:2] == b'\xff\xd8':
                info['format'] = 'JPEG'
                f.seek(0)
                data = f.read()

                # Find SOF0 marker for dimensions
                i = 2
                while i < len(data) - 9:
                    if data[i] == 0xff:
                        marker = data[i + 1]
                        if marker in [0xc0, 0xc1, 0xc2]:  # SOF markers
                            info['height'] = struct.unpack('>H', data[i + 5:i + 7])[0]
                            info['width'] = struct.unpack('>H', data[i + 7:i + 9])[0]
                            break
                        elif marker == 0xd9:  # EOI
                            break
                        elif marker not in [0x00, 0xd8, 0xd9]:
                            length = struct.unpack('>H', data[i + 2:i + 4])[0]
                            i += length + 2
                            continue
                    i += 1

            # GIF
            elif header[:6] in [b'GIF87a', b'GIF89a']:
                info['format'] = 'GIF'
                info['width'] = struct.unpack('<H', header[6:8])[0]
                info['height'] = struct.unpack('<H', header[8:10])[0]

            # BMP
            elif header[:2] == b'BM':
                info['format'] = 'BMP'
                info['width'] = struct.unpack('<I', header[18:22])[0]
                info['height'] = abs(struct.unpack('<i', header[22:26])[0])

            # WebP
            elif header[:4] == b'RIFF' and header[8:12] == b'WEBP':
                info['format'] = 'WebP'
                if header[12:16] == b'VP8 ':
                    # Lossy
                    info['width'] = struct.unpack('<H', header[26:28])[0] & 0x3fff
                    info['height'] = struct.unpack('<H', header[28:30])[0] & 0x3fff

    except Exception as e:
        pass

    return info


def format_size(size):
    """Format size in human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def convert_with_tools(input_file, output_file, options=None):
    """Convert image using system tools"""
    import subprocess

    options = options or {}

    # Try ImageMagick convert
    cmd = ['convert', input_file]

    if options.get('resize'):
        cmd.extend(['-resize', options['resize']])

    if options.get('quality'):
        cmd.extend(['-quality', str(options['quality'])])

    if options.get('strip'):
        cmd.append('-strip')

    cmd.append(output_file)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.returncode == 0, result.stderr
    except FileNotFoundError:
        return None, "ImageMagick not installed"
    except Exception as e:
        return False, str(e)


def batch_convert(input_dir, output_format, options=None):
    """Batch convert images"""
    import glob

    patterns = ['*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp', '*.webp']
    files = []

    for pattern in patterns:
        files.extend(glob.glob(os.path.join(input_dir, pattern)))
        files.extend(glob.glob(os.path.join(input_dir, pattern.upper())))

    return files


def main():
    parser = argparse.ArgumentParser(description='Image Converter')
    parser.add_argument('input', nargs='?', help='Input image or directory')
    parser.add_argument('--format', '-f', help='Output format (png, jpg, gif, webp)')
    parser.add_argument('--output', '-o', help='Output file or directory')
    parser.add_argument('--resize', '-r', help='Resize (e.g., 800x600, 50%)')
    parser.add_argument('--quality', '-q', type=int, help='Quality (1-100)')
    parser.add_argument('--strip', '-s', action='store_true', help='Strip metadata')
    parser.add_argument('--info', '-i', action='store_true', help='Show image info only')
    parser.add_argument('--batch', '-b', action='store_true', help='Batch mode')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🖼️  Image Converter                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.input:
        # Interactive mode
        print(f"  {BOLD}Options:{RESET}")
        print(f"  {CYAN}1.{RESET} Convert single image")
        print(f"  {CYAN}2.{RESET} Batch convert")
        print(f"  {CYAN}3.{RESET} Image info")

        choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

        if choice == '3':
            filepath = input(f"  {CYAN}Image path:{RESET} ").strip()
            if filepath:
                args.input = filepath
                args.info = True
        elif choice == '1':
            args.input = input(f"  {CYAN}Input image:{RESET} ").strip()
            args.format = input(f"  {CYAN}Output format (png/jpg/gif/webp):{RESET} ").strip() or 'png'
            resize = input(f"  {CYAN}Resize (e.g., 800x600, empty to skip):{RESET} ").strip()
            if resize:
                args.resize = resize
        elif choice == '2':
            args.input = input(f"  {CYAN}Input directory:{RESET} ").strip()
            args.format = input(f"  {CYAN}Output format:{RESET} ").strip() or 'png'
            args.batch = True

    if not args.input or not os.path.exists(args.input):
        print(f"  {RED}File/directory not found{RESET}\n")
        return

    # Info only
    if args.info:
        info = get_image_info(args.input)
        if info['format']:
            print(f"  {BOLD}Image Information:{RESET}")
            print(f"  {DIM}{'─' * 40}{RESET}")
            print(f"  {CYAN}Format:{RESET}     {info['format']}")
            print(f"  {CYAN}Dimensions:{RESET} {info['width']} x {info['height']} pixels")
            print(f"  {CYAN}File size:{RESET}  {format_size(info['size'])}")

            # Calculate pixel count
            pixels = info['width'] * info['height']
            print(f"  {CYAN}Pixels:{RESET}     {pixels:,}")

            # Megapixels
            mp = pixels / 1_000_000
            print(f"  {CYAN}Megapixels:{RESET} {mp:.1f} MP")
        else:
            print(f"  {RED}Could not read image info{RESET}")
        print()
        return

    # Batch mode
    if args.batch or os.path.isdir(args.input):
        files = batch_convert(args.input, args.format or 'png')

        if not files:
            print(f"  {DIM}No images found{RESET}\n")
            return

        print(f"  {BOLD}Found {len(files)} images{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")

        output_dir = args.output or args.input
        options = {
            'resize': args.resize,
            'quality': args.quality,
            'strip': args.strip
        }

        success_count = 0
        for filepath in files:
            filename = os.path.basename(filepath)
            name, _ = os.path.splitext(filename)
            output_file = os.path.join(output_dir, f"{name}.{args.format or 'png'}")

            print(f"  Converting {filename}...", end=' ')
            success, error = convert_with_tools(filepath, output_file, options)

            if success:
                print(f"{GREEN}OK{RESET}")
                success_count += 1
            elif success is None:
                print(f"{RED}Tool not found{RESET}")
                break
            else:
                print(f"{RED}Failed{RESET}")

        print(f"\n  {GREEN}Converted {success_count}/{len(files)} images{RESET}")
        print()
        return

    # Single file conversion
    info = get_image_info(args.input)
    print(f"  {BOLD}Input:{RESET} {os.path.basename(args.input)}")
    if info['format']:
        print(f"  {DIM}{info['format']} {info['width']}x{info['height']} ({format_size(info['size'])}){RESET}")

    # Determine output
    if args.output:
        output_file = args.output
    elif args.format:
        name, _ = os.path.splitext(args.input)
        output_file = f"{name}.{args.format}"
    else:
        print(f"  {RED}Specify output format with --format{RESET}\n")
        return

    print(f"\n  {BOLD}Output:{RESET} {os.path.basename(output_file)}")

    options = {
        'resize': args.resize,
        'quality': args.quality,
        'strip': args.strip
    }

    if args.resize:
        print(f"  {DIM}Resize: {args.resize}{RESET}")
    if args.quality:
        print(f"  {DIM}Quality: {args.quality}%{RESET}")

    print(f"\n  Converting...", end=' ')
    success, error = convert_with_tools(args.input, output_file, options)

    if success:
        print(f"{GREEN}Done{RESET}")

        # Show result info
        out_info = get_image_info(output_file)
        if out_info['format']:
            print(f"\n  {BOLD}Result:{RESET}")
            print(f"  {CYAN}Format:{RESET}     {out_info['format']}")
            print(f"  {CYAN}Dimensions:{RESET} {out_info['width']} x {out_info['height']}")
            print(f"  {CYAN}Size:{RESET}       {format_size(out_info['size'])}")

            # Size comparison
            if info['size'] and out_info['size']:
                ratio = out_info['size'] / info['size'] * 100
                if ratio < 100:
                    print(f"  {GREEN}↓ {100 - ratio:.1f}% smaller{RESET}")
                else:
                    print(f"  {YELLOW}↑ {ratio - 100:.1f}% larger{RESET}")

    elif success is None:
        print(f"{RED}ImageMagick required{RESET}")
        print(f"\n  {DIM}Install with: sudo apt install imagemagick{RESET}")
    else:
        print(f"{RED}Failed: {error}{RESET}")

    print()


if __name__ == '__main__':
    main()
