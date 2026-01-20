#!/usr/bin/env python3
"""
Todo List - Simple task management
Usage: todo.py [add "task"] [done id] [list]
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
STRIKE = '\033[9m'

TODO_FILE = os.path.expanduser('~/.dvn_todos.json')


def load_todos():
    """Load todos from file"""
    if os.path.exists(TODO_FILE):
        try:
            with open(TODO_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []


def save_todos(todos):
    """Save todos to file"""
    with open(TODO_FILE, 'w') as f:
        json.dump(todos, f, indent=2)


def add_todo(text, priority='normal', due=None):
    """Add a new todo"""
    todos = load_todos()

    todo = {
        'id': len(todos) + 1,
        'text': text,
        'done': False,
        'priority': priority,
        'due': due,
        'created': datetime.now().isoformat(),
        'completed': None
    }

    todos.append(todo)
    save_todos(todos)
    return todo


def complete_todo(todo_id):
    """Mark todo as done"""
    todos = load_todos()

    for todo in todos:
        if todo['id'] == todo_id:
            todo['done'] = True
            todo['completed'] = datetime.now().isoformat()
            save_todos(todos)
            return True

    return False


def uncomplete_todo(todo_id):
    """Mark todo as not done"""
    todos = load_todos()

    for todo in todos:
        if todo['id'] == todo_id:
            todo['done'] = False
            todo['completed'] = None
            save_todos(todos)
            return True

    return False


def delete_todo(todo_id):
    """Delete a todo"""
    todos = load_todos()

    for i, todo in enumerate(todos):
        if todo['id'] == todo_id:
            del todos[i]
            # Re-number
            for j, t in enumerate(todos):
                t['id'] = j + 1
            save_todos(todos)
            return True

    return False


def clear_completed():
    """Remove all completed todos"""
    todos = load_todos()
    todos = [t for t in todos if not t['done']]

    # Re-number
    for i, t in enumerate(todos):
        t['id'] = i + 1

    save_todos(todos)
    return len(load_todos())


def format_date(iso_date):
    """Format date for display"""
    try:
        dt = datetime.fromisoformat(iso_date)
        now = datetime.now()

        if dt.date() == now.date():
            return 'Today'
        elif (dt.date() - now.date()).days == 1:
            return 'Tomorrow'
        elif (dt.date() - now.date()).days == -1:
            return 'Yesterday'
        elif (dt.date() - now.date()).days < 7:
            return dt.strftime('%A')
        else:
            return dt.strftime('%b %d')
    except:
        return iso_date


def print_todo(todo, show_date=True):
    """Print a single todo"""
    checkbox = f'{GREEN}[✓]{RESET}' if todo['done'] else f'{DIM}[ ]{RESET}'

    # Priority color
    priority_colors = {
        'high': RED,
        'normal': RESET,
        'low': DIM
    }
    color = priority_colors.get(todo.get('priority', 'normal'), RESET)

    text = todo['text']
    if todo['done']:
        text = f'{DIM}{STRIKE}{text}{RESET}'
    else:
        text = f'{color}{text}{RESET}'

    # Priority indicator
    priority_mark = ''
    if todo.get('priority') == 'high':
        priority_mark = f' {RED}!{RESET}'
    elif todo.get('priority') == 'low':
        priority_mark = f' {DIM}↓{RESET}'

    # Due date
    due_str = ''
    if todo.get('due') and not todo['done']:
        due = format_date(todo['due'])
        due_str = f' {YELLOW}[{due}]{RESET}'

    print(f"  {DIM}{todo['id']:>3}.{RESET} {checkbox} {text}{priority_mark}{due_str}")


def list_todos(show_done=False, filter_priority=None):
    """List todos"""
    todos = load_todos()

    if not show_done:
        active = [t for t in todos if not t['done']]
    else:
        active = todos

    if filter_priority:
        active = [t for t in active if t.get('priority') == filter_priority]

    # Sort: high priority first, then by due date, then by id
    def sort_key(t):
        priority_order = {'high': 0, 'normal': 1, 'low': 2}
        p = priority_order.get(t.get('priority', 'normal'), 1)
        due = t.get('due', 'z')  # z sorts after dates
        return (t['done'], p, due, t['id'])

    active.sort(key=sort_key)

    return active


def interactive_mode():
    """Interactive todo management"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ✅ Todo List                                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    while True:
        todos = list_todos()
        done_count = len([t for t in load_todos() if t['done']])
        total = len(load_todos())

        print(f"  {DIM}{'─' * 50}{RESET}")

        if todos:
            for todo in todos:
                print_todo(todo)
        else:
            print(f"  {DIM}No active tasks{RESET}")

        if done_count > 0:
            print(f"\n  {DIM}{done_count} completed task(s) hidden{RESET}")

        print(f"\n  {BOLD}Commands:{RESET}")
        print(f"  {CYAN}a{RESET} Add  {CYAN}d{RESET} Done  {CYAN}u{RESET} Undo  {CYAN}x{RESET} Delete  {CYAN}c{RESET} Clear done  {CYAN}q{RESET} Quit")

        cmd = input(f"\n  {CYAN}>{RESET} ").strip().lower()

        if cmd == 'q' or cmd == 'quit':
            break

        elif cmd == 'a' or cmd.startswith('a '):
            if cmd.startswith('a '):
                text = cmd[2:].strip()
            else:
                text = input(f"  {CYAN}Task:{RESET} ").strip()

            if text:
                # Check for priority prefix
                priority = 'normal'
                if text.startswith('!'):
                    priority = 'high'
                    text = text[1:].strip()
                elif text.startswith('-'):
                    priority = 'low'
                    text = text[1:].strip()

                todo = add_todo(text, priority=priority)
                print(f"  {GREEN}Added #{todo['id']}{RESET}")

        elif cmd.startswith('d ') or cmd == 'd':
            try:
                if cmd == 'd':
                    todo_id = int(input(f"  {CYAN}Task #:{RESET} "))
                else:
                    todo_id = int(cmd.split()[1])

                if complete_todo(todo_id):
                    print(f"  {GREEN}Completed #{todo_id}{RESET}")
                else:
                    print(f"  {RED}Task not found{RESET}")
            except (ValueError, IndexError):
                print(f"  {RED}Invalid task number{RESET}")

        elif cmd.startswith('u ') or cmd == 'u':
            try:
                if cmd == 'u':
                    todo_id = int(input(f"  {CYAN}Task #:{RESET} "))
                else:
                    todo_id = int(cmd.split()[1])

                if uncomplete_todo(todo_id):
                    print(f"  {YELLOW}Uncompleted #{todo_id}{RESET}")
                else:
                    print(f"  {RED}Task not found{RESET}")
            except (ValueError, IndexError):
                print(f"  {RED}Invalid task number{RESET}")

        elif cmd.startswith('x ') or cmd == 'x':
            try:
                if cmd == 'x':
                    todo_id = int(input(f"  {CYAN}Task #:{RESET} "))
                else:
                    todo_id = int(cmd.split()[1])

                if delete_todo(todo_id):
                    print(f"  {RED}Deleted #{todo_id}{RESET}")
                else:
                    print(f"  {RED}Task not found{RESET}")
            except (ValueError, IndexError):
                print(f"  {RED}Invalid task number{RESET}")

        elif cmd == 'c':
            clear_completed()
            print(f"  {GREEN}Cleared completed tasks{RESET}")

        elif cmd == 'all':
            print(f"\n  {BOLD}All Tasks:{RESET}")
            for todo in list_todos(show_done=True):
                print_todo(todo)

        print()

    print()


def main():
    parser = argparse.ArgumentParser(description='Todo List')
    parser.add_argument('action', nargs='?', help='Action: add, done, list, delete, clear')
    parser.add_argument('args', nargs='*', help='Arguments')
    parser.add_argument('--priority', '-p', choices=['high', 'normal', 'low'],
                        default='normal', help='Task priority')
    parser.add_argument('--all', '-a', action='store_true', help='Show all including completed')
    args = parser.parse_args()

    if not args.action or args.action == 'list':
        if args.action == 'list':
            # Non-interactive list
            print(f"\n{BOLD}{CYAN}Todo List{RESET}\n")
            todos = list_todos(show_done=args.all)

            if todos:
                for todo in todos:
                    print_todo(todo)
            else:
                print(f"  {DIM}No tasks{RESET}")

            done = len([t for t in load_todos() if t['done']])
            active = len([t for t in load_todos() if not t['done']])
            print(f"\n  {DIM}Active: {active} | Done: {done}{RESET}\n")
        else:
            interactive_mode()
        return

    if args.action == 'add':
        text = ' '.join(args.args)
        if text:
            todo = add_todo(text, priority=args.priority)
            print(f"{GREEN}Added task #{todo['id']}: {text}{RESET}")
        else:
            print(f"{RED}Task text required{RESET}")

    elif args.action == 'done':
        try:
            todo_id = int(args.args[0])
            if complete_todo(todo_id):
                print(f"{GREEN}Completed #{todo_id}{RESET}")
            else:
                print(f"{RED}Task not found{RESET}")
        except (IndexError, ValueError):
            print(f"{RED}Task ID required{RESET}")

    elif args.action == 'delete':
        try:
            todo_id = int(args.args[0])
            if delete_todo(todo_id):
                print(f"{RED}Deleted #{todo_id}{RESET}")
            else:
                print(f"{RED}Task not found{RESET}")
        except (IndexError, ValueError):
            print(f"{RED}Task ID required{RESET}")

    elif args.action == 'clear':
        clear_completed()
        print(f"{GREEN}Cleared completed tasks{RESET}")

    else:
        # Assume it's a quick add
        text = ' '.join([args.action] + args.args)
        todo = add_todo(text, priority=args.priority)
        print(f"{GREEN}Added #{todo['id']}: {text}{RESET}")


if __name__ == '__main__':
    main()
