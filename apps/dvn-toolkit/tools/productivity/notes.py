#!/usr/bin/env python3
"""
Quick Notes - Simple CLI note-taking app
Usage: notes.py [add "note"] [list] [search term] [delete id]
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

NOTES_FILE = os.path.expanduser('~/.dvn_notes.json')


def load_notes():
    """Load notes from file"""
    if os.path.exists(NOTES_FILE):
        try:
            with open(NOTES_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []


def save_notes(notes):
    """Save notes to file"""
    with open(NOTES_FILE, 'w') as f:
        json.dump(notes, f, indent=2)


def add_note(content, tags=None):
    """Add a new note"""
    notes = load_notes()

    note = {
        'id': len(notes) + 1,
        'content': content,
        'tags': tags or [],
        'created': datetime.now().isoformat(),
        'modified': datetime.now().isoformat()
    }

    notes.append(note)
    save_notes(notes)
    return note


def list_notes(limit=20, tag=None):
    """List recent notes"""
    notes = load_notes()

    if tag:
        notes = [n for n in notes if tag.lower() in [t.lower() for t in n.get('tags', [])]]

    # Sort by modified date descending
    notes.sort(key=lambda x: x.get('modified', ''), reverse=True)

    return notes[:limit]


def search_notes(query):
    """Search notes by content"""
    notes = load_notes()
    query = query.lower()

    results = []
    for note in notes:
        if query in note['content'].lower():
            results.append(note)
        elif any(query in tag.lower() for tag in note.get('tags', [])):
            results.append(note)

    return results


def delete_note(note_id):
    """Delete a note by ID"""
    notes = load_notes()

    for i, note in enumerate(notes):
        if note['id'] == note_id:
            del notes[i]
            # Re-number remaining notes
            for j, n in enumerate(notes):
                n['id'] = j + 1
            save_notes(notes)
            return True

    return False


def edit_note(note_id, new_content):
    """Edit an existing note"""
    notes = load_notes()

    for note in notes:
        if note['id'] == note_id:
            note['content'] = new_content
            note['modified'] = datetime.now().isoformat()
            save_notes(notes)
            return True

    return False


def format_date(iso_date):
    """Format ISO date for display"""
    try:
        dt = datetime.fromisoformat(iso_date)
        now = datetime.now()

        if dt.date() == now.date():
            return f"Today {dt.strftime('%H:%M')}"
        elif (now - dt).days == 1:
            return f"Yesterday {dt.strftime('%H:%M')}"
        elif (now - dt).days < 7:
            return dt.strftime('%A %H:%M')
        else:
            return dt.strftime('%Y-%m-%d')
    except:
        return iso_date


def print_note(note, show_full=False):
    """Print a single note"""
    date_str = format_date(note.get('modified', note.get('created', '')))
    content = note['content']

    if not show_full and len(content) > 80:
        content = content[:77] + '...'

    tags_str = ''
    if note.get('tags'):
        tags_str = f" {DIM}[{', '.join(note['tags'])}]{RESET}"

    print(f"  {CYAN}#{note['id']:<4}{RESET} {DIM}{date_str:<18}{RESET} {content}{tags_str}")


def interactive_mode():
    """Interactive note-taking"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📝 Quick Notes - Interactive                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Commands: add, list, search, delete, edit, tags, quit{RESET}\n")

    while True:
        cmd = input(f"  {CYAN}notes>{RESET} ").strip()

        if not cmd:
            continue

        parts = cmd.split(None, 1)
        action = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ''

        if action in ['q', 'quit', 'exit']:
            break

        elif action in ['a', 'add']:
            if not arg:
                arg = input(f"  {CYAN}Note:{RESET} ").strip()

            if arg:
                # Check for tags (#tag)
                tags = []
                words = arg.split()
                content_words = []
                for word in words:
                    if word.startswith('#'):
                        tags.append(word[1:])
                    else:
                        content_words.append(word)

                content = ' '.join(content_words)
                note = add_note(content, tags)
                print(f"  {GREEN}Added note #{note['id']}{RESET}")

        elif action in ['l', 'list']:
            tag = arg if arg else None
            notes = list_notes(tag=tag)

            if notes:
                print(f"\n  {BOLD}Recent Notes:{RESET}" + (f" (tag: {tag})" if tag else ""))
                print(f"  {DIM}{'─' * 50}{RESET}")
                for note in notes:
                    print_note(note)
                print()
            else:
                print(f"  {DIM}No notes found{RESET}")

        elif action in ['s', 'search']:
            if not arg:
                arg = input(f"  {CYAN}Search:{RESET} ").strip()

            if arg:
                results = search_notes(arg)
                if results:
                    print(f"\n  {BOLD}Search Results:{RESET} ({len(results)} found)")
                    print(f"  {DIM}{'─' * 50}{RESET}")
                    for note in results:
                        print_note(note)
                    print()
                else:
                    print(f"  {DIM}No matches found{RESET}")

        elif action in ['d', 'delete', 'rm']:
            try:
                note_id = int(arg) if arg else int(input(f"  {CYAN}Note ID:{RESET} "))
                if delete_note(note_id):
                    print(f"  {GREEN}Deleted note #{note_id}{RESET}")
                else:
                    print(f"  {RED}Note not found{RESET}")
            except ValueError:
                print(f"  {RED}Invalid ID{RESET}")

        elif action in ['e', 'edit']:
            try:
                note_id = int(arg) if arg else int(input(f"  {CYAN}Note ID:{RESET} "))
                new_content = input(f"  {CYAN}New content:{RESET} ").strip()
                if new_content and edit_note(note_id, new_content):
                    print(f"  {GREEN}Updated note #{note_id}{RESET}")
                else:
                    print(f"  {RED}Note not found or empty content{RESET}")
            except ValueError:
                print(f"  {RED}Invalid ID{RESET}")

        elif action == 'tags':
            notes = load_notes()
            all_tags = set()
            for note in notes:
                all_tags.update(note.get('tags', []))

            if all_tags:
                print(f"\n  {BOLD}Tags:{RESET} {', '.join(sorted(all_tags))}\n")
            else:
                print(f"  {DIM}No tags found{RESET}")

        elif action == 'help':
            print(f"\n  {BOLD}Commands:{RESET}")
            print(f"  {CYAN}add{RESET} <text>     Add a new note (use #tag for tags)")
            print(f"  {CYAN}list{RESET} [tag]     List recent notes")
            print(f"  {CYAN}search{RESET} <term>  Search notes")
            print(f"  {CYAN}delete{RESET} <id>    Delete a note")
            print(f"  {CYAN}edit{RESET} <id>      Edit a note")
            print(f"  {CYAN}tags{RESET}           Show all tags")
            print(f"  {CYAN}quit{RESET}           Exit\n")

        else:
            print(f"  {DIM}Unknown command. Type 'help' for commands.{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Quick Notes')
    parser.add_argument('action', nargs='?', default='interactive',
                        help='Action: add, list, search, delete')
    parser.add_argument('args', nargs='*', help='Arguments for action')
    parser.add_argument('--tag', '-t', help='Filter by tag')
    parser.add_argument('--all', '-a', action='store_true', help='Show all notes')
    args = parser.parse_args()

    if args.action == 'interactive' and not args.args:
        interactive_mode()
        return

    print(f"\n{BOLD}{CYAN}Quick Notes{RESET}\n")

    if args.action == 'add':
        content = ' '.join(args.args)
        if content:
            # Extract tags
            tags = []
            words = content.split()
            content_words = []
            for word in words:
                if word.startswith('#'):
                    tags.append(word[1:])
                else:
                    content_words.append(word)

            content = ' '.join(content_words)
            note = add_note(content, tags)
            print(f"  {GREEN}Added note #{note['id']}{RESET}")
        else:
            print(f"  {RED}No content provided{RESET}")

    elif args.action == 'list':
        limit = 100 if args.all else 20
        notes = list_notes(limit=limit, tag=args.tag)

        if notes:
            for note in notes:
                print_note(note)
        else:
            print(f"  {DIM}No notes found{RESET}")

    elif args.action == 'search':
        query = ' '.join(args.args)
        if query:
            results = search_notes(query)
            if results:
                for note in results:
                    print_note(note)
            else:
                print(f"  {DIM}No matches{RESET}")
        else:
            print(f"  {RED}Search query required{RESET}")

    elif args.action == 'delete':
        try:
            note_id = int(args.args[0])
            if delete_note(note_id):
                print(f"  {GREEN}Deleted{RESET}")
            else:
                print(f"  {RED}Not found{RESET}")
        except (IndexError, ValueError):
            print(f"  {RED}Invalid note ID{RESET}")

    else:
        # Treat as quick add
        content = ' '.join([args.action] + args.args)
        note = add_note(content)
        print(f"  {GREEN}Added note #{note['id']}{RESET}")

    print()


if __name__ == '__main__':
    main()
