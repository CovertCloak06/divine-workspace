#!/usr/bin/env python3
"""
Metadata Tool - View, strip, or modify file metadata (EXIF, etc.)
Usage: metadata.py <file> [--strip] [--view]
"""

import os
import argparse
import subprocess
import struct
import json
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_basic_info(filepath):
    """Get basic file info"""
    stat = os.stat(filepath)
    return {
        'filename': os.path.basename(filepath),
        'path': os.path.abspath(filepath),
        'size': stat.st_size,
        'size_human': format_size(stat.st_size),
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
    }


def format_size(size):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_image_metadata(filepath):
    """Extract EXIF metadata from images using exiftool if available, otherwise basic parsing"""
    metadata = {}

    # Try exiftool first
    try:
        result = subprocess.run(
            ['exiftool', '-json', filepath],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if data:
                return data[0]
    except:
        pass

    # Basic EXIF parsing for JPEG
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        if data[:2] == b'\xff\xd8':  # JPEG
            metadata['format'] = 'JPEG'

            # Find EXIF marker
            idx = 2
            while idx < len(data) - 4:
                marker = data[idx:idx+2]
                if marker == b'\xff\xe1':  # EXIF
                    length = struct.unpack('>H', data[idx+2:idx+4])[0]
                    exif_data = data[idx+4:idx+2+length]

                    if exif_data[:4] == b'Exif':
                        metadata['has_exif'] = True
                        # Basic parsing - look for common strings
                        exif_str = exif_data.decode('utf-8', errors='ignore')
                        for keyword in ['Camera', 'Make', 'Model', 'DateTime', 'GPS', 'Software']:
                            if keyword in exif_str:
                                metadata[f'contains_{keyword}'] = True
                    break
                elif marker[0:1] == b'\xff':
                    length = struct.unpack('>H', data[idx+2:idx+4])[0]
                    idx += 2 + length
                else:
                    break

        elif data[:8] == b'\x89PNG\r\n\x1a\n':  # PNG
            metadata['format'] = 'PNG'
            # PNG chunks can contain metadata
            idx = 8
            while idx < len(data) - 8:
                length = struct.unpack('>I', data[idx:idx+4])[0]
                chunk_type = data[idx+4:idx+8].decode('ascii', errors='ignore')
                if chunk_type in ['tEXt', 'iTXt', 'zTXt']:
                    metadata['has_text_chunks'] = True
                idx += 12 + length

    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def get_pdf_metadata(filepath):
    """Extract PDF metadata"""
    metadata = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4096)  # Read first 4KB

        if data[:4] == b'%PDF':
            metadata['format'] = 'PDF'

            # Look for /Info dictionary
            content = data.decode('latin-1', errors='ignore')

            keywords = ['Author', 'Creator', 'Producer', 'Title', 'Subject', 'Keywords', 'CreationDate', 'ModDate']
            for kw in keywords:
                if f'/{kw}' in content:
                    # Try to extract value
                    start = content.find(f'/{kw}')
                    if start != -1:
                        end = content.find('/', start + 1)
                        if end != -1:
                            value = content[start:end].strip()
                            if '(' in value:
                                value = value.split('(')[1].split(')')[0]
                            metadata[kw] = value[:100]

    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def get_audio_metadata(filepath):
    """Extract audio file metadata (ID3 tags)"""
    metadata = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(128)  # ID3v1 is at end, ID3v2 at start

        # ID3v2
        if data[:3] == b'ID3':
            metadata['format'] = 'MP3 with ID3v2'
            version = f"{data[3]}.{data[4]}"
            metadata['id3_version'] = version
            metadata['has_id3'] = True

        # ID3v1 (at end of file)
        with open(filepath, 'rb') as f:
            f.seek(-128, 2)
            tag = f.read(128)
            if tag[:3] == b'TAG':
                metadata['title'] = tag[3:33].decode('latin-1').strip('\x00')
                metadata['artist'] = tag[33:63].decode('latin-1').strip('\x00')
                metadata['album'] = tag[63:93].decode('latin-1').strip('\x00')
                metadata['year'] = tag[93:97].decode('latin-1').strip('\x00')

    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def strip_metadata_exiftool(filepath, output=None):
    """Strip metadata using exiftool"""
    output = output or filepath
    try:
        result = subprocess.run(
            ['exiftool', '-all=', '-overwrite_original', filepath],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except:
        return False


def strip_jpeg_metadata(filepath, output=None):
    """Strip EXIF from JPEG manually"""
    output = output or filepath
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        if data[:2] != b'\xff\xd8':
            return False

        # Find and remove APP1 (EXIF) markers
        result = b'\xff\xd8'
        idx = 2

        while idx < len(data) - 4:
            marker = data[idx:idx+2]

            if marker == b'\xff\xd9':  # End of image
                result += data[idx:]
                break
            elif marker == b'\xff\xe1':  # APP1 (EXIF) - skip it
                length = struct.unpack('>H', data[idx+2:idx+4])[0]
                idx += 2 + length
            elif marker[0:1] == b'\xff' and marker[1:2] != b'\x00':
                length = struct.unpack('>H', data[idx+2:idx+4])[0]
                result += data[idx:idx+2+length]
                idx += 2 + length
            else:
                result += data[idx:]
                break

        with open(output, 'wb') as f:
            f.write(result)
        return True

    except:
        return False


def display_metadata(filepath):
    """Display all metadata for a file"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📋 Metadata Viewer                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Basic info
    basic = get_basic_info(filepath)
    print(f"  {BOLD}File Information:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    for key, value in basic.items():
        print(f"  {CYAN}{key:>15}:{RESET} {value}")

    # Get extension
    ext = os.path.splitext(filepath)[1].lower()

    # Type-specific metadata
    print(f"\n  {BOLD}Embedded Metadata:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp']:
        metadata = get_image_metadata(filepath)
    elif ext == '.pdf':
        metadata = get_pdf_metadata(filepath)
    elif ext in ['.mp3', '.flac', '.m4a', '.wav']:
        metadata = get_audio_metadata(filepath)
    else:
        metadata = {'note': 'No specific parser for this file type'}

    if metadata:
        for key, value in metadata.items():
            if isinstance(value, str) and len(value) > 60:
                value = value[:60] + '...'
            print(f"  {CYAN}{key:>20}:{RESET} {value}")
    else:
        print(f"  {DIM}No metadata found{RESET}")

    # Privacy warnings
    print(f"\n  {BOLD}Privacy Analysis:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    warnings = []
    if 'GPS' in str(metadata):
        warnings.append(f"{RED}⚠ GPS location data found!{RESET}")
    if 'Author' in metadata or 'Creator' in metadata or 'artist' in metadata:
        warnings.append(f"{YELLOW}⚠ Author/creator information present{RESET}")
    if 'Software' in str(metadata) or 'Producer' in metadata:
        warnings.append(f"{YELLOW}⚠ Software information present{RESET}")
    if 'DateTime' in str(metadata) or 'CreationDate' in metadata:
        warnings.append(f"{YELLOW}⚠ Date/time information present{RESET}")
    if 'Make' in str(metadata) or 'Model' in str(metadata):
        warnings.append(f"{YELLOW}⚠ Camera/device information present{RESET}")

    if warnings:
        for w in warnings:
            print(f"  {w}")
    else:
        print(f"  {GREEN}✓ No obvious privacy concerns found{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Metadata Tool')
    parser.add_argument('file', nargs='?', help='File to analyze')
    parser.add_argument('--strip', '-s', action='store_true', help='Strip all metadata')
    parser.add_argument('--output', '-o', help='Output file (for strip)')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.file:
        print(f"\n{BOLD}{CYAN}Metadata Tool{RESET}")
        print(f"\n  Usage: metadata.py <file> [--strip] [--output newfile]")
        print(f"\n  {DIM}View:  metadata.py photo.jpg")
        print(f"  Strip: metadata.py photo.jpg --strip")
        print(f"  Safe:  metadata.py photo.jpg --strip --output clean.jpg{RESET}\n")
        return

    filepath = args.file

    if not os.path.exists(filepath):
        print(f"{RED}File not found: {filepath}{RESET}")
        return

    if args.strip:
        print(f"\n{BOLD}{CYAN}Stripping Metadata{RESET}\n")
        print(f"  {DIM}File: {filepath}{RESET}")

        output = args.output or filepath

        # Try exiftool first
        if strip_metadata_exiftool(filepath, output):
            print(f"  {GREEN}✓ Metadata stripped successfully (exiftool){RESET}")
        elif filepath.lower().endswith(('.jpg', '.jpeg')):
            if strip_jpeg_metadata(filepath, output):
                print(f"  {GREEN}✓ EXIF stripped successfully{RESET}")
            else:
                print(f"  {RED}✗ Failed to strip metadata{RESET}")
        else:
            print(f"  {YELLOW}⚠ Cannot strip this file type without exiftool{RESET}")
            print(f"  {DIM}Install: sudo apt install exiftool{RESET}")

        print(f"  {DIM}Output: {output}{RESET}\n")
    else:
        display_metadata(filepath)


if __name__ == '__main__':
    main()
