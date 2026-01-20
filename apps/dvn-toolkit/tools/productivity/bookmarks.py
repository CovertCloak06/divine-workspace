#!/usr/bin/env python3
"""
Bookmark Manager - Save and organize bookmarks
Usage: bookmarks.py [add|list|search|delete|open]
"""

import os
import json
import argparse
import subprocess
import webbrowser
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

BOOKMARKS_FILE = os.path.expanduser('~/.dvn_bookmarks.json')


def load_bookmarks():
    """Load bookmarks from file"""
    if os.path.exists(BOOKMARKS_FILE):
        try:
            with open(BOOKMARKS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'bookmarks': [], 'tags': []}


def save_bookmarks(data):
    """Save bookmarks to file"""
    with open(BOOKMARKS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def add_bookmark(url, title=None, tags=None, description=''):
    """Add a new bookmark"""
    data = load_bookmarks()

    # Check for duplicate
    for bm in data['bookmarks']:
        if bm['url'] == url:
            return False, "Bookmark already exists"

    bookmark = {
        'id': len(data['bookmarks']) + 1,
        'url': url,
        'title': title or url,
        'tags': tags or [],
        'description': description,
        'created': datetime.now().isoformat(),
        'visits': 0,
    }

    data['bookmarks'].append(bookmark)

    # Update tags list
    for tag in tags or []:
        if tag not in data['tags']:
            data['tags'].append(tag)

    save_bookmarks(data)
    return True, bookmark


def delete_bookmark(identifier):
    """Delete a bookmark by ID or URL"""
    data = load_bookmarks()

    for i, bm in enumerate(data['bookmarks']):
        if str(bm['id']) == str(identifier) or bm['url'] == identifier:
            data['bookmarks'].pop(i)
            save_bookmarks(data)
            return True

    return False


def search_bookmarks(query):
    """Search bookmarks"""
    data = load_bookmarks()
    results = []
    query = query.lower()

    for bm in data['bookmarks']:
        if (query in bm['title'].lower() or
            query in bm['url'].lower() or
            query in bm.get('description', '').lower() or
            any(query in tag.lower() for tag in bm.get('tags', []))):
            results.append(bm)

    return results


def get_by_tag(tag):
    """Get bookmarks by tag"""
    data = load_bookmarks()
    return [bm for bm in data['bookmarks'] if tag.lower() in [t.lower() for t in bm.get('tags', [])]]


def open_bookmark(identifier):
    """Open bookmark in browser"""
    data = load_bookmarks()

    for bm in data['bookmarks']:
        if str(bm['id']) == str(identifier) or bm['url'] == identifier or bm['title'].lower() == identifier.lower():
            # Update visit count
            bm['visits'] = bm.get('visits', 0) + 1
            bm['last_visit'] = datetime.now().isoformat()
            save_bookmarks(data)

            # Open in browser
            webbrowser.open(bm['url'])
            return True, bm['url']

    return False, "Bookmark not found"


def main():
    parser = argparse.ArgumentParser(description='Bookmark Manager')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['add', 'list', 'search', 'delete', 'open', 'tags', 'export', 'import'])
    parser.add_argument('query', nargs='?', help='URL, search query, or bookmark ID')
    parser.add_argument('--title', '-t', help='Bookmark title')
    parser.add_argument('--tags', '-T', help='Tags (comma-separated)')
    parser.add_argument('--description', '-d', help='Description')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔖 Bookmark Manager                           ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list':
        data = load_bookmarks()
        bookmarks = data['bookmarks']

        # Filter by tag if query looks like a tag
        if args.query and args.query.startswith('#'):
            tag = args.query[1:]
            bookmarks = get_by_tag(tag)
            print(f"  {BOLD}Bookmarks tagged #{tag} ({len(bookmarks)}):{RESET}")
        else:
            print(f"  {BOLD}Bookmarks ({len(bookmarks)}):{RESET}")

        print(f"  {DIM}{'─' * 55}{RESET}\n")

        if not bookmarks:
            print(f"  {DIM}No bookmarks{RESET}\n")
            return

        for bm in bookmarks[:30]:
            tags_str = ' '.join(f"#{t}" for t in bm.get('tags', [])[:3])
            title = bm['title'][:40]

            print(f"  {CYAN}{bm['id']:>3}.{RESET} {GREEN}{title}{RESET}")
            print(f"       {DIM}{bm['url'][:50]}{RESET}")
            if tags_str:
                print(f"       {YELLOW}{tags_str}{RESET}")
            print()

        if len(bookmarks) > 30:
            print(f"  {DIM}... and {len(bookmarks) - 30} more{RESET}\n")

    elif args.action == 'add':
        url = args.query or input(f"  {CYAN}URL:{RESET} ").strip()

        if not url:
            print(f"  {RED}URL required{RESET}\n")
            return

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        title = args.title or input(f"  {CYAN}Title (optional):{RESET} ").strip() or url
        tags_str = args.tags or input(f"  {CYAN}Tags (comma-separated):{RESET} ").strip()
        tags = [t.strip() for t in tags_str.split(',')] if tags_str else []
        description = args.description or ''

        success, result = add_bookmark(url, title, tags, description)

        if success:
            print(f"\n  {GREEN}✓ Bookmark added{RESET}")
            print(f"  {DIM}ID: {result['id']}{RESET}\n")
        else:
            print(f"\n  {YELLOW}{result}{RESET}\n")

    elif args.action == 'search':
        query = args.query or input(f"  {CYAN}Search:{RESET} ").strip()

        if not query:
            print(f"  {RED}Search query required{RESET}\n")
            return

        results = search_bookmarks(query)

        print(f"  {BOLD}Search Results ({len(results)}):{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        if not results:
            print(f"  {DIM}No matches{RESET}\n")
            return

        for bm in results[:20]:
            print(f"  {CYAN}{bm['id']:>3}.{RESET} {GREEN}{bm['title'][:40]}{RESET}")
            print(f"       {DIM}{bm['url'][:50]}{RESET}")
            print()

    elif args.action == 'delete':
        identifier = args.query or input(f"  {CYAN}Bookmark ID or URL:{RESET} ").strip()

        if identifier and delete_bookmark(identifier):
            print(f"  {GREEN}✓ Bookmark deleted{RESET}\n")
        else:
            print(f"  {RED}Bookmark not found{RESET}\n")

    elif args.action == 'open':
        identifier = args.query
        if not identifier:
            # Show list and select
            data = load_bookmarks()
            if not data['bookmarks']:
                print(f"  {DIM}No bookmarks{RESET}\n")
                return

            print(f"  {BOLD}Select bookmark:{RESET}\n")
            for bm in data['bookmarks'][:15]:
                print(f"  {CYAN}{bm['id']:>3}.{RESET} {bm['title'][:40]}")

            identifier = input(f"\n  {CYAN}ID:{RESET} ").strip()

        if identifier:
            success, result = open_bookmark(identifier)
            if success:
                print(f"  {GREEN}✓ Opening: {result}{RESET}\n")
            else:
                print(f"  {RED}{result}{RESET}\n")

    elif args.action == 'tags':
        data = load_bookmarks()
        tags = data.get('tags', [])

        print(f"  {BOLD}Tags ({len(tags)}):{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")

        for tag in sorted(tags):
            count = len(get_by_tag(tag))
            print(f"  {YELLOW}#{tag}{RESET} ({count})")

        print()

    elif args.action == 'export':
        data = load_bookmarks()
        print(json.dumps(data, indent=2))

    elif args.action == 'import':
        print(f"  {CYAN}Paste JSON and enter 'END' on a new line:{RESET}")
        lines = []
        while True:
            line = input()
            if line.strip() == 'END':
                break
            lines.append(line)

        try:
            imported = json.loads('\n'.join(lines))
            data = load_bookmarks()

            count = 0
            for bm in imported.get('bookmarks', []):
                # Check for duplicate
                exists = any(b['url'] == bm['url'] for b in data['bookmarks'])
                if not exists:
                    bm['id'] = len(data['bookmarks']) + 1
                    data['bookmarks'].append(bm)
                    count += 1

            save_bookmarks(data)
            print(f"\n  {GREEN}✓ Imported {count} bookmarks{RESET}\n")
        except json.JSONDecodeError as e:
            print(f"\n  {RED}Invalid JSON: {e}{RESET}\n")


if __name__ == '__main__':
    main()
