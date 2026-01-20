#!/usr/bin/env python3
"""
Git Helper - Common git operations made easy
Usage: githelper.py [status|log|branch|stash|undo]
"""

import subprocess
import argparse
import os

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
MAGENTA = '\033[95m'


def run_git(args, capture=True):
    """Run git command"""
    try:
        result = subprocess.run(
            ['git'] + args,
            capture_output=capture,
            text=True
        )
        return result.stdout.strip() if capture else None, result.returncode
    except Exception as e:
        return str(e), 1


def is_git_repo():
    """Check if current directory is a git repo"""
    _, code = run_git(['rev-parse', '--git-dir'])
    return code == 0


def show_status():
    """Show enhanced git status"""
    print(f"\n  {BOLD}Repository Status:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    # Branch info
    branch, _ = run_git(['branch', '--show-current'])
    print(f"  {CYAN}Branch:{RESET} {GREEN}{branch}{RESET}")

    # Remote tracking
    upstream, _ = run_git(['rev-parse', '--abbrev-ref', '@{upstream}'])
    if upstream:
        ahead, _ = run_git(['rev-list', '--count', '@{upstream}..HEAD'])
        behind, _ = run_git(['rev-list', '--count', 'HEAD..@{upstream}'])
        print(f"  {CYAN}Tracking:{RESET} {upstream} ", end='')
        if ahead != '0':
            print(f"{GREEN}↑{ahead}{RESET} ", end='')
        if behind != '0':
            print(f"{RED}↓{behind}{RESET}", end='')
        print()

    # Status
    status, _ = run_git(['status', '--porcelain'])

    staged = []
    modified = []
    untracked = []

    for line in status.split('\n'):
        if not line:
            continue
        index_status = line[0]
        worktree_status = line[1]
        filename = line[3:]

        if index_status in 'MADRC':
            staged.append((index_status, filename))
        if worktree_status == 'M':
            modified.append(filename)
        if index_status == '?' and worktree_status == '?':
            untracked.append(filename)

    if staged:
        print(f"\n  {BOLD}Staged:{RESET}")
        for status_char, filename in staged[:10]:
            status_word = {'M': 'modified', 'A': 'new', 'D': 'deleted', 'R': 'renamed'}
            print(f"    {GREEN}+ {filename}{RESET} {DIM}({status_word.get(status_char, status_char)}){RESET}")

    if modified:
        print(f"\n  {BOLD}Modified:{RESET}")
        for filename in modified[:10]:
            print(f"    {YELLOW}~ {filename}{RESET}")

    if untracked:
        print(f"\n  {BOLD}Untracked:{RESET}")
        for filename in untracked[:10]:
            print(f"    {DIM}? {filename}{RESET}")

    if not staged and not modified and not untracked:
        print(f"\n  {GREEN}✓ Working tree clean{RESET}")

    print()


def show_log(count=10):
    """Show pretty git log"""
    print(f"\n  {BOLD}Recent Commits:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    log, _ = run_git([
        'log', f'-{count}',
        '--pretty=format:%h|%s|%an|%ar'
    ])

    for line in log.split('\n'):
        if not line:
            continue
        parts = line.split('|')
        if len(parts) >= 4:
            hash_val, subject, author, date = parts[0], parts[1], parts[2], parts[3]
            subject = subject[:50] + '...' if len(subject) > 53 else subject
            print(f"  {YELLOW}{hash_val}{RESET} {subject}")
            print(f"         {DIM}{author} • {date}{RESET}")
    print()


def show_branches():
    """Show branches"""
    print(f"\n  {BOLD}Branches:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    current, _ = run_git(['branch', '--show-current'])
    branches, _ = run_git(['branch', '-a', '--format=%(refname:short)|%(upstream:short)|%(committerdate:relative)'])

    local = []
    remote = []

    for line in branches.split('\n'):
        if not line:
            continue
        parts = line.split('|')
        name = parts[0]

        if name.startswith('origin/'):
            remote.append(name)
        else:
            local.append(parts)

    print(f"\n  {CYAN}Local:{RESET}")
    for parts in local:
        name = parts[0]
        marker = f"{GREEN}*{RESET} " if name == current else "  "
        tracking = f" → {parts[1]}" if len(parts) > 1 and parts[1] else ""
        print(f"  {marker}{name}{DIM}{tracking}{RESET}")

    if remote:
        print(f"\n  {CYAN}Remote:{RESET}")
        for name in remote[:10]:
            print(f"    {DIM}{name}{RESET}")
        if len(remote) > 10:
            print(f"    {DIM}... and {len(remote) - 10} more{RESET}")

    print()


def show_stash():
    """Show and manage stashes"""
    print(f"\n  {BOLD}Stash List:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    stash, _ = run_git(['stash', 'list'])

    if not stash:
        print(f"  {DIM}No stashes{RESET}")
    else:
        for line in stash.split('\n')[:10]:
            if line:
                # stash@{0}: WIP on branch: message
                parts = line.split(': ', 2)
                stash_id = parts[0]
                message = parts[2] if len(parts) > 2 else parts[1] if len(parts) > 1 else ''
                print(f"  {YELLOW}{stash_id}{RESET}: {message[:50]}")

    print(f"\n  {BOLD}Actions:{RESET}")
    print(f"  {CYAN}1.{RESET} Create new stash")
    print(f"  {CYAN}2.{RESET} Apply latest stash")
    print(f"  {CYAN}3.{RESET} Pop latest stash")
    print(f"  {CYAN}4.{RESET} Drop stash")
    print(f"  {CYAN}5.{RESET} Back")

    choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

    if choice == '1':
        msg = input(f"  {CYAN}Message:{RESET} ").strip()
        if msg:
            run_git(['stash', 'push', '-m', msg], capture=False)
        else:
            run_git(['stash'], capture=False)
    elif choice == '2':
        run_git(['stash', 'apply'], capture=False)
    elif choice == '3':
        run_git(['stash', 'pop'], capture=False)
    elif choice == '4':
        stash_id = input(f"  {CYAN}Stash ID (e.g., stash@{{0}}):{RESET} ").strip()
        if stash_id:
            run_git(['stash', 'drop', stash_id], capture=False)

    print()


def undo_menu():
    """Undo operations menu"""
    print(f"\n  {BOLD}Undo Operations:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    print(f"\n  {YELLOW}⚠ Be careful - some operations cannot be undone!{RESET}\n")

    print(f"  {CYAN}1.{RESET} Unstage files (keep changes)")
    print(f"  {CYAN}2.{RESET} Discard changes in file")
    print(f"  {CYAN}3.{RESET} Undo last commit (keep changes)")
    print(f"  {CYAN}4.{RESET} Amend last commit message")
    print(f"  {CYAN}5.{RESET} Revert a commit")
    print(f"  {CYAN}6.{RESET} Back")

    choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

    if choice == '1':
        run_git(['reset', 'HEAD'], capture=False)
        print(f"  {GREEN}Files unstaged{RESET}")

    elif choice == '2':
        status, _ = run_git(['status', '--porcelain'])
        modified = [line[3:] for line in status.split('\n') if line and line[1] == 'M']

        if modified:
            print(f"\n  Modified files:")
            for i, f in enumerate(modified[:10], 1):
                print(f"    {i}. {f}")

            file_choice = input(f"\n  {CYAN}File number (or 'all'):{RESET} ").strip()

            if file_choice.lower() == 'all':
                confirm = input(f"  {RED}Discard ALL changes? (yes/no):{RESET} ").strip()
                if confirm == 'yes':
                    run_git(['checkout', '--', '.'], capture=False)
            elif file_choice.isdigit():
                idx = int(file_choice) - 1
                if 0 <= idx < len(modified):
                    run_git(['checkout', '--', modified[idx]], capture=False)
                    print(f"  {GREEN}Changes discarded{RESET}")

    elif choice == '3':
        run_git(['reset', '--soft', 'HEAD~1'], capture=False)
        print(f"  {GREEN}Last commit undone (changes preserved){RESET}")

    elif choice == '4':
        new_msg = input(f"  {CYAN}New commit message:{RESET} ").strip()
        if new_msg:
            run_git(['commit', '--amend', '-m', new_msg], capture=False)

    elif choice == '5':
        show_log(5)
        commit_hash = input(f"  {CYAN}Commit hash to revert:{RESET} ").strip()
        if commit_hash:
            run_git(['revert', commit_hash], capture=False)

    print()


def quick_commit():
    """Quick add and commit"""
    print(f"\n  {BOLD}Quick Commit:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    # Show what will be committed
    status, _ = run_git(['status', '--porcelain'])

    if not status:
        print(f"  {DIM}Nothing to commit{RESET}\n")
        return

    # Stage all?
    print(f"\n  {CYAN}1.{RESET} Stage all changes")
    print(f"  {CYAN}2.{RESET} Stage specific files")
    print(f"  {CYAN}3.{RESET} Commit staged only")

    choice = input(f"\n  {CYAN}Choice [1]:{RESET} ").strip() or '1'

    if choice == '1':
        run_git(['add', '-A'])
        print(f"  {GREEN}All changes staged{RESET}")
    elif choice == '2':
        run_git(['add', '-i'], capture=False)

    # Commit message
    msg = input(f"\n  {CYAN}Commit message:{RESET} ").strip()

    if msg:
        output, code = run_git(['commit', '-m', msg])
        if code == 0:
            print(f"  {GREEN}✓ Committed successfully{RESET}")
        else:
            print(f"  {RED}Commit failed: {output}{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Git Helper')
    parser.add_argument('action', nargs='?', help='Action: status, log, branch, stash, undo, commit')
    parser.add_argument('--count', '-n', type=int, default=10, help='Number of items to show')
    args = parser.parse_args()

    if not is_git_repo():
        print(f"\n{RED}Not a git repository{RESET}\n")
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔀 Git Helper                                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}")

    if args.action:
        action = args.action.lower()
        if action == 'status':
            show_status()
        elif action == 'log':
            show_log(args.count)
        elif action in ['branch', 'branches']:
            show_branches()
        elif action == 'stash':
            show_stash()
        elif action == 'undo':
            undo_menu()
        elif action == 'commit':
            quick_commit()
        else:
            print(f"\n  {RED}Unknown action: {args.action}{RESET}\n")
        return

    # Interactive menu
    while True:
        print(f"\n  {BOLD}Menu:{RESET}")
        print(f"  {CYAN}1.{RESET} Status")
        print(f"  {CYAN}2.{RESET} Log")
        print(f"  {CYAN}3.{RESET} Branches")
        print(f"  {CYAN}4.{RESET} Stash")
        print(f"  {CYAN}5.{RESET} Quick Commit")
        print(f"  {CYAN}6.{RESET} Undo")
        print(f"  {CYAN}7.{RESET} Exit")

        choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

        if choice == '1':
            show_status()
        elif choice == '2':
            show_log()
        elif choice == '3':
            show_branches()
        elif choice == '4':
            show_stash()
        elif choice == '5':
            quick_commit()
        elif choice == '6':
            undo_menu()
        elif choice == '7':
            break

    print()


if __name__ == '__main__':
    main()
