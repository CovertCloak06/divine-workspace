#!/usr/bin/env python3
"""
Code Snippets Manager - Save and retrieve code snippets
Usage: snippets.py [add|list|search|get|delete]
"""

import os
import json
import argparse
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

SNIPPETS_FILE = os.path.expanduser('~/.dvn_snippets.json')


def load_snippets():
    """Load snippets from file"""
    if os.path.exists(SNIPPETS_FILE):
        try:
            with open(SNIPPETS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}


def save_snippets(snippets):
    """Save snippets to file"""
    with open(SNIPPETS_FILE, 'w') as f:
        json.dump(snippets, f, indent=2)


def add_snippet(name, code, language='', tags=None, description=''):
    """Add a new snippet"""
    snippets = load_snippets()
    snippets[name] = {
        'code': code,
        'language': language,
        'tags': tags or [],
        'description': description,
        'created': datetime.now().isoformat(),
        'updated': datetime.now().isoformat(),
    }
    save_snippets(snippets)
    return True


def get_snippet(name):
    """Get a snippet by name"""
    snippets = load_snippets()
    return snippets.get(name)


def delete_snippet(name):
    """Delete a snippet"""
    snippets = load_snippets()
    if name in snippets:
        del snippets[name]
        save_snippets(snippets)
        return True
    return False


def search_snippets(query):
    """Search snippets by name, tag, or content"""
    snippets = load_snippets()
    results = {}
    query = query.lower()

    for name, data in snippets.items():
        if query in name.lower():
            results[name] = data
        elif query in data.get('description', '').lower():
            results[name] = data
        elif query in data.get('code', '').lower():
            results[name] = data
        elif any(query in tag.lower() for tag in data.get('tags', [])):
            results[name] = data
        elif query == data.get('language', '').lower():
            results[name] = data

    return results


def interactive_add():
    """Interactively add a snippet"""
    print(f"\n  {BOLD}Add New Snippet:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}\n")

    name = input(f"  {CYAN}Name:{RESET} ").strip()
    if not name:
        return None

    language = input(f"  {CYAN}Language (optional):{RESET} ").strip()
    tags = input(f"  {CYAN}Tags (comma-separated):{RESET} ").strip()
    tags = [t.strip() for t in tags.split(',')] if tags else []
    description = input(f"  {CYAN}Description:{RESET} ").strip()

    print(f"\n  {CYAN}Code (enter 'END' on a new line to finish):{RESET}")
    lines = []
    while True:
        line = input()
        if line.strip() == 'END':
            break
        lines.append(line)

    code = '\n'.join(lines)

    if code:
        add_snippet(name, code, language, tags, description)
        return name
    return None


def print_snippet(name, data, show_code=True):
    """Pretty print a snippet"""
    print(f"  {GREEN}{name}{RESET}")
    if data.get('language'):
        print(f"    {CYAN}Language:{RESET} {data['language']}")
    if data.get('tags'):
        print(f"    {CYAN}Tags:{RESET} {', '.join(data['tags'])}")
    if data.get('description'):
        print(f"    {CYAN}Description:{RESET} {data['description']}")

    if show_code:
        print(f"    {DIM}{'─' * 40}{RESET}")
        for line in data['code'].split('\n')[:15]:
            print(f"    {line}")
        if data['code'].count('\n') > 15:
            print(f"    {DIM}... ({data['code'].count(chr(10)) - 15} more lines){RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(description='Code Snippets Manager')
    parser.add_argument('action', nargs='?', default='interactive',
                       choices=['add', 'list', 'search', 'get', 'delete', 'export', 'import', 'interactive'])
    parser.add_argument('query', nargs='?', help='Snippet name or search query')
    parser.add_argument('--language', '-l', help='Filter by language')
    parser.add_argument('--tag', '-t', help='Filter by tag')
    parser.add_argument('--copy', '-c', action='store_true', help='Copy to clipboard')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📋 Code Snippets Manager                      ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list':
        snippets = load_snippets()

        # Apply filters
        if args.language:
            snippets = {k: v for k, v in snippets.items()
                       if v.get('language', '').lower() == args.language.lower()}
        if args.tag:
            snippets = {k: v for k, v in snippets.items()
                       if args.tag.lower() in [t.lower() for t in v.get('tags', [])]}

        if not snippets:
            print(f"  {DIM}No snippets found{RESET}\n")
            return

        print(f"  {BOLD}Saved Snippets ({len(snippets)}):{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for name, data in snippets.items():
            print_snippet(name, data, show_code=False)

    elif args.action == 'search':
        if not args.query:
            args.query = input(f"  {CYAN}Search:{RESET} ").strip()

        if not args.query:
            print(f"  {RED}Search query required{RESET}\n")
            return

        results = search_snippets(args.query)

        if not results:
            print(f"  {DIM}No matches found{RESET}\n")
            return

        print(f"  {BOLD}Search Results ({len(results)}):{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for name, data in results.items():
            print_snippet(name, data, show_code=False)

    elif args.action == 'get':
        if not args.query:
            args.query = input(f"  {CYAN}Snippet name:{RESET} ").strip()

        data = get_snippet(args.query)

        if not data:
            print(f"  {RED}Snippet not found: {args.query}{RESET}\n")
            return

        print(f"  {BOLD}Snippet:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")
        print_snippet(args.query, data, show_code=True)

        if args.copy:
            try:
                import subprocess
                process = subprocess.Popen(['xclip', '-selection', 'clipboard'],
                                          stdin=subprocess.PIPE)
                process.communicate(data['code'].encode())
                print(f"  {GREEN}✓ Copied to clipboard{RESET}\n")
            except:
                pass

    elif args.action == 'add':
        name = interactive_add()
        if name:
            print(f"\n  {GREEN}✓ Added: {name}{RESET}\n")

    elif args.action == 'delete':
        if not args.query:
            args.query = input(f"  {CYAN}Snippet to delete:{RESET} ").strip()

        if args.query and delete_snippet(args.query):
            print(f"  {GREEN}✓ Deleted: {args.query}{RESET}\n")
        else:
            print(f"  {RED}Snippet not found: {args.query}{RESET}\n")

    elif args.action == 'export':
        snippets = load_snippets()
        print(json.dumps(snippets, indent=2))

    elif args.action == 'import':
        print(f"  {CYAN}Paste JSON and enter 'END' on a new line:{RESET}")
        lines = []
        while True:
            line = input()
            if line.strip() == 'END':
                break
            lines.append(line)

        try:
            data = json.loads('\n'.join(lines))
            snippets = load_snippets()
            snippets.update(data)
            save_snippets(snippets)
            print(f"\n  {GREEN}✓ Imported {len(data)} snippets{RESET}\n")
        except json.JSONDecodeError as e:
            print(f"\n  {RED}Invalid JSON: {e}{RESET}\n")

    else:
        # Interactive mode
        snippets = load_snippets()

        while True:
            print(f"  {BOLD}Options:{RESET}")
            print(f"  {CYAN}1.{RESET} List snippets")
            print(f"  {CYAN}2.{RESET} Add snippet")
            print(f"  {CYAN}3.{RESET} Search snippets")
            print(f"  {CYAN}4.{RESET} Get snippet")
            print(f"  {CYAN}5.{RESET} Delete snippet")
            print(f"  {CYAN}6.{RESET} Exit")

            choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

            if choice == '1':
                snippets = load_snippets()
                if snippets:
                    print(f"\n  {BOLD}Snippets:{RESET}")
                    for name, data in snippets.items():
                        lang = f" [{data.get('language')}]" if data.get('language') else ""
                        print(f"    {GREEN}{name}{RESET}{lang}")
                else:
                    print(f"\n  {DIM}No snippets{RESET}")
                print()

            elif choice == '2':
                name = interactive_add()
                if name:
                    print(f"\n  {GREEN}✓ Added: {name}{RESET}\n")

            elif choice == '3':
                query = input(f"\n  {CYAN}Search:{RESET} ").strip()
                if query:
                    results = search_snippets(query)
                    if results:
                        print(f"\n  {BOLD}Results:{RESET}")
                        for name in results:
                            print(f"    {GREEN}{name}{RESET}")
                    else:
                        print(f"\n  {DIM}No matches{RESET}")
                print()

            elif choice == '4':
                name = input(f"\n  {CYAN}Name:{RESET} ").strip()
                data = get_snippet(name)
                if data:
                    print(f"\n{DIM}{'─' * 50}{RESET}")
                    print(data['code'])
                    print(f"{DIM}{'─' * 50}{RESET}")
                else:
                    print(f"\n  {RED}Not found{RESET}")
                print()

            elif choice == '5':
                name = input(f"\n  {CYAN}Name:{RESET} ").strip()
                if name and delete_snippet(name):
                    print(f"  {GREEN}✓ Deleted{RESET}\n")
                else:
                    print(f"  {RED}Not found{RESET}\n")

            elif choice == '6':
                break

            else:
                print()

    print()


if __name__ == '__main__':
    main()
