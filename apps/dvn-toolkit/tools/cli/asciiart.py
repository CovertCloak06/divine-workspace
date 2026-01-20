#!/usr/bin/env python3
"""
ASCII Art Generator - Create ASCII art from images or text
Usage: asciiart [image|text] [options]
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


LOCAL_FONT_DIR = os.path.expanduser('~/.local/share/figlet')

def get_figlet_fonts():
    """Get available figlet/toilet fonts from system and local dirs"""
    fonts = set()

    # Check system font dir
    try:
        result = subprocess.run(['figlet', '-I', '2'], capture_output=True, text=True)
        font_dir = result.stdout.strip()
        if os.path.isdir(font_dir):
            for f in os.listdir(font_dir):
                if f.endswith(('.flf', '.tlf')):
                    fonts.add(f.rsplit('.', 1)[0])
    except:
        pass

    # Check local font dir
    if os.path.isdir(LOCAL_FONT_DIR):
        for f in os.listdir(LOCAL_FONT_DIR):
            if f.endswith(('.flf', '.tlf')):
                fonts.add(f.rsplit('.', 1)[0])

    return sorted(fonts) if fonts else ['standard', 'slant', 'banner', 'big', 'block', 'shadow', 'small']


def get_toilet_filters():
    """Available toilet filters"""
    return ['metal', 'gay', 'border', 'flip', 'flop', '180', 'left', 'right', 'crop']


def image_to_ascii_jp2a(image_path, width=80, color=False, invert=False, chars=None):
    """Convert image to ASCII using jp2a"""
    cmd = ['jp2a', '--width=' + str(width)]
    if color:
        cmd.append('--colors')
    if invert:
        cmd.append('--invert')
    if chars:
        cmd.append('--chars=' + chars)
    cmd.append(image_path)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def image_to_ascii_caca(image_path, width=80, format='utf8'):
    """Convert image to ASCII using img2txt (libcaca)"""
    cmd = ['img2txt', '-W', str(width), '-f', format, image_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def text_to_ascii_figlet(text, font='standard', width=80):
    """Convert text to ASCII banner using figlet"""
    # Check if font exists in local dir first
    local_font = os.path.join(LOCAL_FONT_DIR, font + '.flf')
    if os.path.exists(local_font):
        cmd = ['figlet', '-d', LOCAL_FONT_DIR, '-f', font, '-w', str(width), text]
    else:
        cmd = ['figlet', '-f', font, '-w', str(width), text]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 and result.stderr:
            return f"Error: {result.stderr}"
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def text_to_ascii_toilet(text, font='standard', filter_name=None, width=80):
    """Convert text to ASCII banner using toilet"""
    cmd = ['toilet', '-f', font, '-w', str(width)]
    if filter_name:
        cmd.extend(['-F', filter_name])
    cmd.append(text)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def interactive_menu():
    """Interactive ASCII art creation menu"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║      ASCII Art Generator               ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════╝{RESET}\n")

    while True:
        print(f"{BOLD}Select mode:{RESET}")
        print(f"  {GREEN}[1]{RESET} Image to ASCII (jp2a)")
        print(f"  {GREEN}[2]{RESET} Image to ASCII (colored/caca)")
        print(f"  {GREEN}[3]{RESET} Text Banner (figlet)")
        print(f"  {GREEN}[4]{RESET} Text Banner (toilet - colored)")
        print(f"  {GREEN}[5]{RESET} Preview figlet fonts")
        print(f"  {GREEN}[6]{RESET} Preview toilet filters")
        print(f"  {GREEN}[0]{RESET} Exit")
        print()

        choice = input(f"  {CYAN}>{RESET} ").strip()

        if choice == '0':
            break

        elif choice == '1':
            # jp2a image conversion
            print(f"\n{CYAN}Image to ASCII (jp2a){RESET}")
            image = input("  Image path: ").strip()
            if not os.path.exists(image):
                print(f"  {RED}File not found{RESET}\n")
                continue

            width = input("  Width (default 80): ").strip() or '80'
            invert = input("  Invert colors? (y/n): ").strip().lower() == 'y'
            color = input("  Use colors? (y/n): ").strip().lower() == 'y'
            chars = input("  Custom chars (or Enter for default): ").strip() or None

            print(f"\n{YELLOW}Generating...{RESET}\n")
            result = image_to_ascii_jp2a(image, int(width), color, invert, chars)
            print(result)

            save = input(f"\n  {CYAN}Save to file? (path or Enter to skip):{RESET} ").strip()
            if save:
                with open(save, 'w') as f:
                    f.write(result)
                print(f"  {GREEN}Saved to {save}{RESET}")
            print()

        elif choice == '2':
            # caca colored image
            print(f"\n{CYAN}Image to ASCII (colored/caca){RESET}")
            image = input("  Image path: ").strip()
            if not os.path.exists(image):
                print(f"  {RED}File not found{RESET}\n")
                continue

            width = input("  Width (default 80): ").strip() or '80'
            fmt = input("  Format (utf8/ansi/html): ").strip() or 'utf8'

            print(f"\n{YELLOW}Generating...{RESET}\n")
            result = image_to_ascii_caca(image, int(width), fmt)
            print(result)

            save = input(f"\n  {CYAN}Save to file? (path or Enter to skip):{RESET} ").strip()
            if save:
                with open(save, 'w') as f:
                    f.write(result)
                print(f"  {GREEN}Saved to {save}{RESET}")
            print()

        elif choice == '3':
            # figlet text banner
            print(f"\n{CYAN}Text Banner (figlet){RESET}")
            text = input("  Text: ").strip()
            if not text:
                continue

            fonts = get_figlet_fonts()
            print(f"  {DIM}Fonts: {', '.join(fonts[:10])}...{RESET}")
            font = input("  Font (default 'standard'): ").strip() or 'standard'
            width = input("  Width (default 80): ").strip() or '80'

            print(f"\n{YELLOW}Generating...{RESET}\n")
            result = text_to_ascii_figlet(text, font, int(width))
            print(result)

            save = input(f"\n  {CYAN}Save to file? (path or Enter to skip):{RESET} ").strip()
            if save:
                with open(save, 'w') as f:
                    f.write(result)
                print(f"  {GREEN}Saved to {save}{RESET}")
            print()

        elif choice == '4':
            # toilet colored banner
            print(f"\n{CYAN}Text Banner (toilet - colored){RESET}")
            text = input("  Text: ").strip()
            if not text:
                continue

            filters = get_toilet_filters()
            print(f"  {DIM}Filters: {', '.join(filters)}{RESET}")
            font = input("  Font (default 'standard'): ").strip() or 'standard'
            filter_name = input("  Filter (e.g., 'metal', 'gay', or Enter): ").strip() or None

            print(f"\n{YELLOW}Generating...{RESET}\n")
            result = text_to_ascii_toilet(text, font, filter_name)
            print(result)

            save = input(f"\n  {CYAN}Save to file? (path or Enter to skip):{RESET} ").strip()
            if save:
                # Strip ANSI codes for file
                import re
                clean = re.sub(r'\x1b\[[0-9;]*m', '', result)
                with open(save, 'w') as f:
                    f.write(clean)
                print(f"  {GREEN}Saved to {save}{RESET}")
            print()

        elif choice == '5':
            # Preview figlet fonts
            print(f"\n{CYAN}Figlet Font Preview{RESET}")
            text = input("  Preview text (default 'Hello'): ").strip() or 'Hello'
            fonts = get_figlet_fonts()

            print(f"\n{YELLOW}Showing {len(fonts)} fonts...{RESET}\n")
            for font in fonts:
                print(f"{GREEN}═══ {font} ═══{RESET}")
                print(text_to_ascii_figlet(text, font, 60))
            print()

        elif choice == '6':
            # Preview toilet filters
            print(f"\n{CYAN}Toilet Filter Preview{RESET}")
            text = input("  Preview text (default 'Hello'): ").strip() or 'Hello'
            filters = get_toilet_filters()

            print(f"\n{YELLOW}Showing filters...{RESET}\n")
            for f in filters:
                print(f"{GREEN}═══ {f} ═══{RESET}")
                print(text_to_ascii_toilet(text, 'standard', f))
            print()


def main():
    parser = argparse.ArgumentParser(description='ASCII Art Generator')
    parser.add_argument('input', nargs='?', help='Image path or text')
    parser.add_argument('--mode', '-m', choices=['jp2a', 'caca', 'figlet', 'toilet'],
                        default='figlet', help='Conversion mode')
    parser.add_argument('--width', '-w', type=int, default=80, help='Output width')
    parser.add_argument('--font', '-f', default='future', help='Font name')
    parser.add_argument('--filter', '-F', help='Toilet filter (metal, gay, border, etc.)')
    parser.add_argument('--color', '-c', action='store_true', help='Enable colors (jp2a)')
    parser.add_argument('--invert', '-i', action='store_true', help='Invert colors (jp2a)')
    parser.add_argument('--chars', help='Custom character set (jp2a)')
    parser.add_argument('--output', '-o', help='Save to file')
    parser.add_argument('--interactive', '-I', action='store_true', help='Interactive mode')
    parser.add_argument('--list-fonts', action='store_true', help='List figlet fonts')
    args = parser.parse_args()

    # Interactive mode
    if args.interactive or (not args.input and not args.list_fonts):
        interactive_menu()
        return

    # List fonts
    if args.list_fonts:
        fonts = get_figlet_fonts()
        print(f"{CYAN}Available figlet fonts:{RESET}")
        for f in fonts:
            print(f"  {f}")
        return

    # Process input
    result = ""

    if args.mode == 'jp2a':
        if not os.path.exists(args.input):
            print(f"{RED}Image not found: {args.input}{RESET}")
            return
        result = image_to_ascii_jp2a(args.input, args.width, args.color, args.invert, args.chars)

    elif args.mode == 'caca':
        if not os.path.exists(args.input):
            print(f"{RED}Image not found: {args.input}{RESET}")
            return
        result = image_to_ascii_caca(args.input, args.width)

    elif args.mode == 'figlet':
        result = text_to_ascii_figlet(args.input, args.font, args.width)

    elif args.mode == 'toilet':
        result = text_to_ascii_toilet(args.input, args.font, args.filter, args.width)

    # Output
    print(result)

    if args.output:
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', result)
        with open(args.output, 'w') as f:
            f.write(clean)
        print(f"{GREEN}Saved to {args.output}{RESET}")


if __name__ == '__main__':
    main()
