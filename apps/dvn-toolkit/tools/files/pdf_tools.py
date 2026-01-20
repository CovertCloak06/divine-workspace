#!/usr/bin/env python3
"""
PDF Tools - Basic PDF operations (info, merge, split)
Usage: pdf_tools.py [info|merge|split|extract] <file>
"""

import os
import sys
import argparse
import subprocess

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def check_tools():
    """Check for available PDF tools"""
    tools = {}

    # Check for pdftk
    try:
        subprocess.run(['pdftk', '--version'], capture_output=True)
        tools['pdftk'] = True
    except FileNotFoundError:
        tools['pdftk'] = False

    # Check for qpdf
    try:
        subprocess.run(['qpdf', '--version'], capture_output=True)
        tools['qpdf'] = True
    except FileNotFoundError:
        tools['qpdf'] = False

    # Check for pdfinfo (poppler-utils)
    try:
        subprocess.run(['pdfinfo', '-v'], capture_output=True, stderr=subprocess.DEVNULL)
        tools['pdfinfo'] = True
    except FileNotFoundError:
        tools['pdfinfo'] = False

    # Check for ghostscript
    try:
        subprocess.run(['gs', '--version'], capture_output=True)
        tools['gs'] = True
    except FileNotFoundError:
        tools['gs'] = False

    return tools


def get_pdf_info_pdfinfo(filepath):
    """Get PDF info using pdfinfo"""
    try:
        result = subprocess.run(['pdfinfo', filepath], capture_output=True, text=True)
        if result.returncode == 0:
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    info[key.strip()] = val.strip()
            return info
    except:
        pass
    return None


def get_pdf_info_basic(filepath):
    """Get basic PDF info without external tools"""
    info = {
        'File': os.path.basename(filepath),
        'Size': f"{os.path.getsize(filepath):,} bytes",
    }

    try:
        with open(filepath, 'rb') as f:
            content = f.read(1024)

            # Check PDF header
            if content.startswith(b'%PDF-'):
                version = content[5:8].decode('ascii', errors='ignore')
                info['PDF Version'] = version

            # Try to find page count
            f.seek(0)
            full_content = f.read()
            page_count = full_content.count(b'/Type /Page') - full_content.count(b'/Type /Pages')
            if page_count > 0:
                info['Pages'] = str(page_count)
    except:
        pass

    return info


def merge_pdfs_pdftk(files, output):
    """Merge PDFs using pdftk"""
    cmd = ['pdftk'] + files + ['cat', 'output', output]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def merge_pdfs_qpdf(files, output):
    """Merge PDFs using qpdf"""
    cmd = ['qpdf', '--empty', '--pages'] + files + ['--', output]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def merge_pdfs_gs(files, output):
    """Merge PDFs using ghostscript"""
    cmd = ['gs', '-dBATCH', '-dNOPAUSE', '-q', '-sDEVICE=pdfwrite',
           f'-sOutputFile={output}'] + files
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def split_pdf_pdftk(filepath, output_dir):
    """Split PDF into pages using pdftk"""
    basename = os.path.splitext(os.path.basename(filepath))[0]
    output_pattern = os.path.join(output_dir, f'{basename}_page_%04d.pdf')
    cmd = ['pdftk', filepath, 'burst', 'output', output_pattern]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def split_pdf_qpdf(filepath, output_dir, pages):
    """Split PDF pages using qpdf"""
    basename = os.path.splitext(os.path.basename(filepath))[0]

    for page in range(1, pages + 1):
        output = os.path.join(output_dir, f'{basename}_page_{page:04d}.pdf')
        cmd = ['qpdf', filepath, '--pages', filepath, str(page), '--', output]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return False, result.stderr

    return True, None


def extract_text_pdftotext(filepath):
    """Extract text using pdftotext"""
    try:
        result = subprocess.run(['pdftotext', filepath, '-'], capture_output=True, text=True)
        return result.returncode == 0, result.stdout
    except FileNotFoundError:
        return False, "pdftotext not found"


def main():
    parser = argparse.ArgumentParser(description='PDF Tools')
    parser.add_argument('action', nargs='?', default='info',
                       choices=['info', 'merge', 'split', 'extract', 'check'])
    parser.add_argument('files', nargs='*', help='PDF file(s)')
    parser.add_argument('--output', '-o', help='Output file/directory')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📄 PDF Tools                                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    tools = check_tools()

    if args.action == 'check':
        print(f"  {BOLD}Available Tools:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")

        for tool, available in tools.items():
            status = f"{GREEN}✓ Available{RESET}" if available else f"{RED}✗ Not found{RESET}"
            print(f"  {tool:<12} {status}")

        print(f"\n  {BOLD}Install missing tools:{RESET}")
        print(f"  {DIM}sudo apt install poppler-utils pdftk qpdf ghostscript{RESET}\n")
        return

    if args.action == 'info':
        if not args.files:
            args.files = [input(f"  {CYAN}PDF file:{RESET} ").strip()]

        for filepath in args.files:
            if not filepath or not os.path.exists(filepath):
                print(f"  {RED}File not found: {filepath}{RESET}\n")
                continue

            print(f"  {BOLD}PDF Info:{RESET}")
            print(f"  {DIM}{'─' * 45}{RESET}\n")

            # Try pdfinfo first
            if tools.get('pdfinfo'):
                info = get_pdf_info_pdfinfo(filepath)
            else:
                info = get_pdf_info_basic(filepath)

            if info:
                for key, val in info.items():
                    print(f"  {CYAN}{key}:{RESET} {val}")
            else:
                # Basic info
                print(f"  {CYAN}File:{RESET} {filepath}")
                print(f"  {CYAN}Size:{RESET} {os.path.getsize(filepath):,} bytes")

            print()

    elif args.action == 'merge':
        if len(args.files) < 2:
            print(f"  {BOLD}Merge PDFs:{RESET}")
            print(f"  {DIM}Enter PDF files to merge (empty line to finish){RESET}\n")

            while True:
                filepath = input(f"  {CYAN}PDF file:{RESET} ").strip()
                if not filepath:
                    break
                if os.path.exists(filepath):
                    args.files.append(filepath)
                else:
                    print(f"  {RED}File not found: {filepath}{RESET}")

        if len(args.files) < 2:
            print(f"  {RED}Need at least 2 PDF files to merge{RESET}\n")
            return

        output = args.output or 'merged.pdf'
        print(f"\n  {BOLD}Merging {len(args.files)} files:{RESET}")
        for f in args.files:
            print(f"    {DIM}{f}{RESET}")

        print(f"\n  {YELLOW}Processing...{RESET}")

        # Try available tools
        success = False
        if tools.get('pdftk'):
            success, error = merge_pdfs_pdftk(args.files, output)
        elif tools.get('qpdf'):
            success, error = merge_pdfs_qpdf(args.files, output)
        elif tools.get('gs'):
            success, error = merge_pdfs_gs(args.files, output)
        else:
            print(f"  {RED}No PDF tools available{RESET}")
            print(f"  {DIM}Install: pdftk, qpdf, or ghostscript{RESET}\n")
            return

        if success:
            print(f"  {GREEN}✓ Merged to: {output}{RESET}\n")
        else:
            print(f"  {RED}✗ Merge failed: {error}{RESET}\n")

    elif args.action == 'split':
        if not args.files:
            args.files = [input(f"  {CYAN}PDF file to split:{RESET} ").strip()]

        filepath = args.files[0]
        if not filepath or not os.path.exists(filepath):
            print(f"  {RED}File not found: {filepath}{RESET}\n")
            return

        output_dir = args.output or os.path.dirname(filepath) or '.'
        os.makedirs(output_dir, exist_ok=True)

        print(f"  {YELLOW}Splitting {filepath}...{RESET}")

        if tools.get('pdftk'):
            success, error = split_pdf_pdftk(filepath, output_dir)
        elif tools.get('qpdf'):
            # Get page count first
            info = get_pdf_info_pdfinfo(filepath) or {}
            pages = int(info.get('Pages', 1))
            success, error = split_pdf_qpdf(filepath, output_dir, pages)
        else:
            print(f"  {RED}No PDF tools available{RESET}\n")
            return

        if success:
            print(f"  {GREEN}✓ Split to: {output_dir}{RESET}\n")
        else:
            print(f"  {RED}✗ Split failed: {error}{RESET}\n")

    elif args.action == 'extract':
        if not args.files:
            args.files = [input(f"  {CYAN}PDF file:{RESET} ").strip()]

        filepath = args.files[0]
        if not filepath or not os.path.exists(filepath):
            print(f"  {RED}File not found: {filepath}{RESET}\n")
            return

        print(f"  {BOLD}Extracted Text:{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")

        success, text = extract_text_pdftotext(filepath)
        if success:
            # Print first 2000 chars
            print(text[:2000])
            if len(text) > 2000:
                print(f"\n  {DIM}... ({len(text) - 2000} more characters){RESET}")
        else:
            print(f"  {RED}Could not extract text: {text}{RESET}")

        print()


if __name__ == '__main__':
    main()
