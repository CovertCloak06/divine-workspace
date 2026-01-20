#!/usr/bin/env python3
"""
Clipboard Manager - Copy/paste with history
Usage: clipboard.py [copy|paste|history|clear]
"""

import os
import json
import argparse
import subprocess
import sys
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

HISTORY_FILE = os.path.expanduser('~/.dvn_clipboard_history.json')
MAX_HISTORY = 50


def get_clipboard():
    """Get current clipboard content"""
    try:
        # Try xclip first
        result = subprocess.run(['xclip', '-selection', 'clipboard', '-o'],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout
    except:
        pass

    try:
        # Try xsel
        result = subprocess.run(['xsel', '--clipboard', '--output'],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout
    except:
        pass

    try:
        # Try wl-paste (Wayland)
        result = subprocess.run(['wl-paste'],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout
    except:
        pass

    return None


def set_clipboard(text):
    """Set clipboard content"""
    try:
        # Try xclip
        process = subprocess.Popen(['xclip', '-selection', 'clipboard'],
                                   stdin=subprocess.PIPE)
        process.communicate(text.encode())
        if process.returncode == 0:
            return True
    except:
        pass

    try:
        # Try xsel
        process = subprocess.Popen(['xsel', '--clipboard', '--input'],
                                   stdin=subprocess.PIPE)
        process.communicate(text.encode())
        if process.returncode == 0:
            return True
    except:
        pass

    try:
        # Try wl-copy (Wayland)
        process = subprocess.Popen(['wl-copy'],
                                   stdin=subprocess.PIPE)
        process.communicate(text.encode())
        if process.returncode == 0:
            return True
    except:
        pass

    return False


def load_history():
    """Load clipboard history"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return []


def save_history(history):
    """Save clipboard history"""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history[-MAX_HISTORY:], f, indent=2)


def add_to_history(text):
    """Add item to history"""
    if not text or len(text.strip()) == 0:
        return

    history = load_history()

    # Remove if already exists
    history = [h for h in history if h['content'] != text]

    # Add new entry
    history.append({
        'content': text,
        'timestamp': datetime.now().isoformat(),
        'length': len(text)
    })

    save_history(history)


def format_preview(text, max_len=60):
    """Format text preview"""
    text = text.replace('\n', '↵ ').replace('\t', '→')
    if len(text) > max_len:
        return text[:max_len - 3] + '...'
    return text


def interactive_mode():
    """Interactive clipboard manager"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📋 Clipboard Manager                          ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Show current clipboard
    current = get_clipboard()
    if current:
        print(f"  {BOLD}Current:{RESET}")
        print(f"  {DIM}{format_preview(current, 50)}{RESET}")
        print(f"  {DIM}({len(current)} chars){RESET}")
    else:
        print(f"  {DIM}Clipboard empty or unavailable{RESET}")

    # Show history
    history = load_history()

    if history:
        print(f"\n  {BOLD}History:{RESET} ({len(history)} items)")
        print(f"  {DIM}{'─' * 50}{RESET}")

        for i, item in enumerate(reversed(history[-10:]), 1):
            preview = format_preview(item['content'], 45)
            timestamp = datetime.fromisoformat(item['timestamp'])
            age = datetime.now() - timestamp

            if age.days > 0:
                time_str = f"{age.days}d ago"
            elif age.seconds > 3600:
                time_str = f"{age.seconds // 3600}h ago"
            elif age.seconds > 60:
                time_str = f"{age.seconds // 60}m ago"
            else:
                time_str = "just now"

            print(f"  {CYAN}{i:>2}.{RESET} {preview}")
            print(f"      {DIM}{time_str} • {item['length']} chars{RESET}")

    print(f"\n  {BOLD}Actions:{RESET}")
    print(f"  {CYAN}[1-10]{RESET} Restore from history")
    print(f"  {CYAN}[c]{RESET} Copy from stdin  {CYAN}[p]{RESET} Paste  {CYAN}[x]{RESET} Clear  {CYAN}[q]{RESET} Quit")

    while True:
        choice = input(f"\n  {CYAN}>{RESET} ").strip().lower()

        if choice == 'q' or choice == 'quit':
            break

        elif choice == 'c':
            print(f"  {DIM}Enter text (Ctrl+D when done):{RESET}")
            try:
                text = sys.stdin.read()
                if set_clipboard(text):
                    add_to_history(text)
                    print(f"  {GREEN}Copied {len(text)} chars{RESET}")
                else:
                    print(f"  {RED}Failed to copy{RESET}")
            except:
                pass

        elif choice == 'p':
            content = get_clipboard()
            if content:
                print(f"\n{content}")
            else:
                print(f"  {DIM}Clipboard empty{RESET}")

        elif choice == 'x':
            set_clipboard('')
            print(f"  {GREEN}Clipboard cleared{RESET}")

        elif choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(history):
                item = list(reversed(history[-10:]))[idx - 1]
                if set_clipboard(item['content']):
                    print(f"  {GREEN}Restored from history{RESET}")
                else:
                    print(f"  {RED}Failed to restore{RESET}")
            else:
                print(f"  {RED}Invalid index{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Clipboard Manager')
    parser.add_argument('action', nargs='?', choices=['copy', 'paste', 'history', 'clear'],
                        help='Action to perform')
    parser.add_argument('text', nargs='*', help='Text to copy')
    parser.add_argument('--index', '-i', type=int, help='History index to restore')
    args = parser.parse_args()

    if not args.action:
        interactive_mode()
        return

    if args.action == 'copy':
        if args.text:
            text = ' '.join(args.text)
        else:
            text = sys.stdin.read()

        if set_clipboard(text):
            add_to_history(text)
            print(f"Copied {len(text)} chars")
        else:
            print("Failed to copy", file=sys.stderr)
            sys.exit(1)

    elif args.action == 'paste':
        content = get_clipboard()
        if content:
            print(content, end='')
        else:
            sys.exit(1)

    elif args.action == 'history':
        history = load_history()

        if args.index:
            if 1 <= args.index <= len(history):
                item = list(reversed(history))[args.index - 1]
                if set_clipboard(item['content']):
                    print(f"Restored from history")
            else:
                print("Invalid index", file=sys.stderr)
                sys.exit(1)
        else:
            for i, item in enumerate(reversed(history[-20:]), 1):
                preview = format_preview(item['content'], 60)
                print(f"{i:>2}. {preview}")

    elif args.action == 'clear':
        set_clipboard('')
        print("Clipboard cleared")


if __name__ == '__main__':
    main()
