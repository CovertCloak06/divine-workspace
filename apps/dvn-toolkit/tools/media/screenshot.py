#!/usr/bin/env python3
"""
Screenshot - Capture screen/window screenshots
Usage: screenshot.py [--window|--region|--full] [--output file]
"""

import os
import subprocess
import argparse
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

SCREENSHOT_DIR = os.path.expanduser('~/Pictures/Screenshots')


def check_tools():
    """Check available screenshot tools"""
    tools = {}

    for tool in ['gnome-screenshot', 'scrot', 'maim', 'import', 'spectacle', 'flameshot']:
        try:
            result = subprocess.run(['which', tool], capture_output=True)
            tools[tool] = result.returncode == 0
        except:
            tools[tool] = False

    return tools


def get_default_filename():
    """Generate default screenshot filename"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"screenshot_{timestamp}.png"


def take_screenshot_gnome(mode='full', output=None, delay=0):
    """Take screenshot using gnome-screenshot"""
    cmd = ['gnome-screenshot']

    if mode == 'window':
        cmd.append('-w')
    elif mode == 'region':
        cmd.append('-a')

    if delay > 0:
        cmd.extend(['-d', str(delay)])

    if output:
        cmd.extend(['-f', output])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def take_screenshot_scrot(mode='full', output=None, delay=0):
    """Take screenshot using scrot"""
    cmd = ['scrot']

    if mode == 'window':
        cmd.append('-u')
    elif mode == 'region':
        cmd.append('-s')

    if delay > 0:
        cmd.extend(['-d', str(delay)])

    if output:
        cmd.append(output)

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def take_screenshot_maim(mode='full', output=None, delay=0):
    """Take screenshot using maim"""
    cmd = ['maim']

    if mode == 'window':
        # Get active window ID
        try:
            xdotool = subprocess.run(['xdotool', 'getactivewindow'],
                                    capture_output=True, text=True)
            window_id = xdotool.stdout.strip()
            cmd.extend(['-i', window_id])
        except:
            pass
    elif mode == 'region':
        cmd.append('-s')

    if delay > 0:
        cmd.extend(['-d', str(delay)])

    if output:
        cmd.append(output)

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def take_screenshot_import(mode='full', output=None, delay=0):
    """Take screenshot using ImageMagick import"""
    import time

    if delay > 0:
        print(f"  {YELLOW}Waiting {delay} seconds...{RESET}")
        time.sleep(delay)

    cmd = ['import']

    if mode == 'full':
        cmd.extend(['-window', 'root'])
    elif mode == 'region':
        pass  # import default is region selection

    if output:
        cmd.append(output)
    else:
        cmd.append(get_default_filename())

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def take_screenshot_flameshot(mode='full', output=None, delay=0):
    """Take screenshot using flameshot"""
    cmd = ['flameshot']

    if mode == 'full':
        cmd.append('full')
    elif mode == 'region':
        cmd.append('gui')
    elif mode == 'window':
        cmd.append('gui')

    if output:
        cmd.extend(['-p', os.path.dirname(output) or '.'])

    if delay > 0:
        cmd.extend(['-d', str(delay * 1000)])  # flameshot uses ms

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def take_screenshot(mode='full', output=None, delay=0):
    """Take screenshot using available tool"""
    tools = check_tools()

    # Ensure output directory exists
    if output:
        os.makedirs(os.path.dirname(output) or '.', exist_ok=True)

    # Try tools in order of preference
    if tools.get('maim'):
        return take_screenshot_maim(mode, output, delay), 'maim'
    elif tools.get('scrot'):
        return take_screenshot_scrot(mode, output, delay), 'scrot'
    elif tools.get('gnome-screenshot'):
        return take_screenshot_gnome(mode, output, delay), 'gnome-screenshot'
    elif tools.get('flameshot'):
        return take_screenshot_flameshot(mode, output, delay), 'flameshot'
    elif tools.get('import'):
        return take_screenshot_import(mode, output, delay), 'import'

    return (False, "No screenshot tool available"), None


def main():
    parser = argparse.ArgumentParser(description='Screenshot Tool')
    parser.add_argument('--full', '-f', action='store_true', help='Full screen (default)')
    parser.add_argument('--window', '-w', action='store_true', help='Active window')
    parser.add_argument('--region', '-r', action='store_true', help='Select region')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--delay', '-d', type=int, default=0, help='Delay in seconds')
    parser.add_argument('--clipboard', '-c', action='store_true', help='Copy to clipboard')
    parser.add_argument('--check', action='store_true', help='Check available tools')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📸 Screenshot                                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.check:
        tools = check_tools()
        print(f"  {BOLD}Available Tools:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")

        for tool, available in tools.items():
            status = f"{GREEN}✓ Available{RESET}" if available else f"{RED}✗ Not found{RESET}"
            print(f"  {tool:<18} {status}")

        print(f"\n  {BOLD}Install:{RESET}")
        print(f"  {DIM}sudo apt install maim scrot gnome-screenshot flameshot{RESET}\n")
        return

    # Determine mode
    if args.window:
        mode = 'window'
    elif args.region:
        mode = 'region'
    else:
        mode = 'full'

    # Determine output path
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    if args.output:
        output = args.output
    else:
        output = os.path.join(SCREENSHOT_DIR, get_default_filename())

    # Display info
    mode_names = {'full': 'Full Screen', 'window': 'Active Window', 'region': 'Select Region'}
    print(f"  {CYAN}Mode:{RESET}   {mode_names[mode]}")
    print(f"  {CYAN}Output:{RESET} {output}")

    if args.delay > 0:
        print(f"  {CYAN}Delay:{RESET}  {args.delay} seconds")

    print()

    # Take screenshot
    if args.delay > 0:
        print(f"  {YELLOW}Taking screenshot in {args.delay} seconds...{RESET}")
    elif mode == 'region':
        print(f"  {YELLOW}Select a region with your mouse...{RESET}")
    else:
        print(f"  {YELLOW}Capturing...{RESET}")

    (success, error), tool = take_screenshot(mode, output, args.delay)

    if success:
        print(f"  {GREEN}✓ Screenshot saved{RESET}")
        print(f"  {DIM}Tool: {tool}{RESET}")
        print(f"  {DIM}File: {output}{RESET}")

        if os.path.exists(output):
            size = os.path.getsize(output)
            print(f"  {DIM}Size: {size:,} bytes{RESET}")

        # Copy to clipboard
        if args.clipboard:
            try:
                subprocess.run(['xclip', '-selection', 'clipboard', '-t', 'image/png',
                              '-i', output], check=True)
                print(f"  {GREEN}✓ Copied to clipboard{RESET}")
            except:
                try:
                    subprocess.run(['xsel', '--clipboard', '--input', '--type', 'image/png'],
                                  stdin=open(output, 'rb'), check=True)
                    print(f"  {GREEN}✓ Copied to clipboard{RESET}")
                except:
                    print(f"  {YELLOW}Could not copy to clipboard{RESET}")

    else:
        print(f"  {RED}✗ Screenshot failed{RESET}")
        if error:
            print(f"  {DIM}{error}{RESET}")

    print()


if __name__ == '__main__':
    main()
