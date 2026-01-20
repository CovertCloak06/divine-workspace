#!/usr/bin/env python3
"""
Metadata Extractor - Extract metadata from files (EXIF, document info, etc)
Usage: metadata_extract.py [file] [--json] [--recursive]
Extracts hidden metadata for OSINT purposes
"""

import sys
import json
import argparse
import os
import struct
import zipfile
import re
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def extract_exif(filepath):
    """Extract EXIF data from images"""
    exif_data = {}

    try:
        with open(filepath, 'rb') as f:
            # Check for JPEG
            header = f.read(2)
            if header != b'\xff\xd8':
                return exif_data

            f.seek(0)
            data = f.read()

            # Find EXIF header
            exif_start = data.find(b'Exif\x00\x00')
            if exif_start == -1:
                return exif_data

            # Parse TIFF header
            tiff_start = exif_start + 6

            # Check byte order
            byte_order = data[tiff_start:tiff_start + 2]
            if byte_order == b'II':
                endian = '<'  # Little-endian
            elif byte_order == b'MM':
                endian = '>'  # Big-endian
            else:
                return exif_data

            # Simple tag extraction
            # Look for common patterns in raw data
            raw = data[exif_start:exif_start + 5000].decode('utf-8', errors='ignore')

            # GPS coordinates
            gps_match = re.search(r'GPS[^\x00]*', raw)
            if gps_match:
                exif_data['gps_data'] = True

            # Camera make/model
            for pattern, key in [(r'(?:Apple|Canon|Nikon|Sony|Samsung|Google)[^\x00]{0,50}', 'camera')]:
                match = re.search(pattern, raw)
                if match:
                    exif_data[key] = match.group(0)[:50]

            # Software
            software_match = re.search(r'(?:Adobe|Photoshop|GIMP|Lightroom)[^\x00]{0,30}', raw)
            if software_match:
                exif_data['software'] = software_match.group(0)[:50]

            # Dates
            date_match = re.search(r'\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}', raw)
            if date_match:
                exif_data['date'] = date_match.group(0)

    except Exception as e:
        exif_data['error'] = str(e)[:50]

    return exif_data


def extract_pdf_metadata(filepath):
    """Extract metadata from PDF files"""
    metadata = {}

    try:
        with open(filepath, 'rb') as f:
            content = f.read()

            # Find Info dictionary
            info_match = re.search(rb'/Info\s*<<([^>]+)>>', content)
            if info_match:
                info_data = info_match.group(1).decode('utf-8', errors='ignore')

                patterns = {
                    'title': r'/Title\s*\(([^)]+)\)',
                    'author': r'/Author\s*\(([^)]+)\)',
                    'creator': r'/Creator\s*\(([^)]+)\)',
                    'producer': r'/Producer\s*\(([^)]+)\)',
                    'creation_date': r'/CreationDate\s*\(([^)]+)\)',
                    'mod_date': r'/ModDate\s*\(([^)]+)\)',
                }

                for key, pattern in patterns.items():
                    match = re.search(pattern, info_data)
                    if match:
                        metadata[key] = match.group(1)[:100]

            # Look for XMP metadata
            xmp_match = re.search(rb'<\?xpacket[^>]*\?>(.+?)<\?xpacket end', content, re.DOTALL)
            if xmp_match:
                xmp = xmp_match.group(1).decode('utf-8', errors='ignore')

                xmp_patterns = {
                    'xmp_creator': r'<dc:creator[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>',
                    'xmp_title': r'<dc:title[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>',
                }

                for key, pattern in xmp_patterns.items():
                    match = re.search(pattern, xmp, re.DOTALL)
                    if match:
                        metadata[key] = match.group(1)[:100]

    except Exception as e:
        metadata['error'] = str(e)[:50]

    return metadata


def extract_office_metadata(filepath):
    """Extract metadata from Office documents (docx, xlsx, pptx)"""
    metadata = {}

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            # Core properties
            if 'docProps/core.xml' in zf.namelist():
                core = zf.read('docProps/core.xml').decode('utf-8', errors='ignore')

                patterns = {
                    'title': r'<dc:title>([^<]+)</dc:title>',
                    'subject': r'<dc:subject>([^<]+)</dc:subject>',
                    'creator': r'<dc:creator>([^<]+)</dc:creator>',
                    'last_modified_by': r'<cp:lastModifiedBy>([^<]+)</cp:lastModifiedBy>',
                    'created': r'<dcterms:created[^>]*>([^<]+)</dcterms:created>',
                    'modified': r'<dcterms:modified[^>]*>([^<]+)</dcterms:modified>',
                    'revision': r'<cp:revision>([^<]+)</cp:revision>',
                }

                for key, pattern in patterns.items():
                    match = re.search(pattern, core)
                    if match:
                        metadata[key] = match.group(1)[:100]

            # App properties
            if 'docProps/app.xml' in zf.namelist():
                app = zf.read('docProps/app.xml').decode('utf-8', errors='ignore')

                app_patterns = {
                    'application': r'<Application>([^<]+)</Application>',
                    'app_version': r'<AppVersion>([^<]+)</AppVersion>',
                    'company': r'<Company>([^<]+)</Company>',
                    'total_time': r'<TotalTime>([^<]+)</TotalTime>',
                    'pages': r'<Pages>([^<]+)</Pages>',
                    'words': r'<Words>([^<]+)</Words>',
                }

                for key, pattern in app_patterns.items():
                    match = re.search(pattern, app)
                    if match:
                        metadata[key] = match.group(1)[:100]

    except zipfile.BadZipFile:
        pass
    except Exception as e:
        metadata['error'] = str(e)[:50]

    return metadata


def get_file_info(filepath):
    """Get basic file information"""
    info = {}

    try:
        stat = os.stat(filepath)
        info['size'] = stat.st_size
        info['size_human'] = format_size(stat.st_size)
        info['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        info['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        info['accessed'] = datetime.fromtimestamp(stat.st_atime).isoformat()
        info['permissions'] = oct(stat.st_mode)[-3:]

        # Get mime type from extension
        ext = os.path.splitext(filepath)[1].lower()
        mime_types = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.pdf': 'application/pdf', '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.zip': 'application/zip',
        }
        info['mime_type'] = mime_types.get(ext, 'application/octet-stream')
        info['extension'] = ext

    except Exception as e:
        info['error'] = str(e)

    return info


def format_size(size):
    """Format size in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def extract_metadata(filepath):
    """Extract all metadata from a file"""
    result = {
        'file': os.path.basename(filepath),
        'path': os.path.abspath(filepath),
        'file_info': get_file_info(filepath),
        'metadata': {}
    }

    ext = os.path.splitext(filepath)[1].lower()

    # Image files
    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp']:
        result['metadata'] = extract_exif(filepath)
        result['type'] = 'image'

    # PDF files
    elif ext == '.pdf':
        result['metadata'] = extract_pdf_metadata(filepath)
        result['type'] = 'pdf'

    # Office documents
    elif ext in ['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp']:
        result['metadata'] = extract_office_metadata(filepath)
        result['type'] = 'office'

    else:
        result['type'] = 'unknown'

    return result


def display_results(result):
    """Display extracted metadata"""
    print(f"\n  {BOLD}Metadata Extraction Results{RESET}")
    print(f"  {DIM}{'═' * 55}{RESET}\n")

    print(f"  {CYAN}File:{RESET}  {result['file']}")
    print(f"  {CYAN}Type:{RESET}  {result.get('type', 'unknown')}")
    print()

    # File info
    file_info = result.get('file_info', {})
    if file_info:
        print(f"  {BOLD}File Information{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")

        print(f"  {CYAN}Size:{RESET}        {file_info.get('size_human', 'N/A')}")
        print(f"  {CYAN}Modified:{RESET}    {file_info.get('modified', 'N/A')[:19]}")
        print(f"  {CYAN}MIME Type:{RESET}   {file_info.get('mime_type', 'N/A')}")
        print()

    # Extracted metadata
    metadata = result.get('metadata', {})
    if metadata:
        print(f"  {BOLD}Extracted Metadata{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}")

        # Highlight potentially sensitive info
        sensitive_keys = ['author', 'creator', 'last_modified_by', 'company', 'gps_data', 'camera']

        for key, value in metadata.items():
            if key == 'error':
                continue

            display_key = key.replace('_', ' ').title()

            if key in sensitive_keys:
                print(f"  {YELLOW}{display_key}:{RESET}  {GREEN}{value}{RESET}")
            else:
                print(f"  {CYAN}{display_key}:{RESET}  {value}")

        print()

        # Warnings
        if metadata.get('gps_data'):
            print(f"  {RED}  WARNING: File may contain GPS location data{RESET}")
        if metadata.get('author') or metadata.get('creator') or metadata.get('last_modified_by'):
            print(f"  {YELLOW}  NOTE: File contains author/creator information{RESET}")

    else:
        print(f"  {DIM}No metadata extracted{RESET}")

    print()


def scan_directory(directory, recursive=False):
    """Scan directory for files with metadata"""
    results = []
    extensions = ['.jpg', '.jpeg', '.png', '.pdf', '.docx', '.xlsx', '.pptx']

    if recursive:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.lower().endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, file)
                    results.append(extract_metadata(filepath))
    else:
        for file in os.listdir(directory):
            if any(file.lower().endswith(ext) for ext in extensions):
                filepath = os.path.join(directory, file)
                if os.path.isfile(filepath):
                    results.append(extract_metadata(filepath))

    return results


def main():
    parser = argparse.ArgumentParser(description='Metadata Extractor')
    parser.add_argument('target', nargs='?', help='File or directory to analyze')
    parser.add_argument('--recursive', '-r', action='store_true', help='Scan directory recursively')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Metadata Extractor{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    target = args.target
    if not target:
        target = input(f"\n  {CYAN}File or directory:{RESET} ").strip()

    if not target or not os.path.exists(target):
        print(f"  {RED}Target not found{RESET}")
        sys.exit(1)

    if os.path.isfile(target):
        result = extract_metadata(target)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            display_results(result)

    elif os.path.isdir(target):
        if not args.json:
            print(f"\n  {DIM}Scanning directory...{RESET}")

        results = scan_directory(target, args.recursive)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\n  {BOLD}Found {len(results)} files with metadata{RESET}")
            print(f"  {DIM}{'─' * 50}{RESET}\n")

            for result in results[:20]:
                meta = result.get('metadata', {})
                file = result.get('file', '')
                ftype = result.get('type', 'unknown')

                # Check for sensitive data
                has_sensitive = any(k in meta for k in ['author', 'creator', 'company', 'gps_data'])
                indicator = f"{YELLOW}!{RESET}" if has_sensitive else " "

                print(f"  {indicator} {GREEN}{file:30}{RESET} [{ftype}]")
                if meta.get('author'):
                    print(f"       Author: {meta['author'][:30]}")
                if meta.get('creator'):
                    print(f"       Creator: {meta['creator'][:30]}")

            if len(results) > 20:
                print(f"\n  {DIM}... and {len(results) - 20} more files{RESET}")

            # Summary
            with_author = len([r for r in results if r.get('metadata', {}).get('author') or r.get('metadata', {}).get('creator')])
            print(f"\n  {CYAN}Files with author info:{RESET} {with_author}")
            print()


if __name__ == '__main__':
    main()
