#!/usr/bin/env python3
"""
Git Stats - Repository analytics and insights
Usage: gitstat [path] [--author "name"] [--since "1 month ago"]
"""

import argparse
import subprocess
import re
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

def run_git(args, cwd='.'):
    """Run git command and return output"""
    try:
        result = subprocess.run(
            ['git'] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except:
        return None

def get_commits(path='.', author=None, since=None):
    """Get commit data"""
    args = ['log', '--format=%H|%an|%ae|%at|%s', '--no-merges']
    if author:
        args.extend(['--author', author])
    if since:
        args.extend(['--since', since])

    output = run_git(args, path)
    if not output:
        return []

    commits = []
    for line in output.split('\n'):
        if '|' in line:
            parts = line.split('|', 4)
            if len(parts) >= 5:
                commits.append({
                    'hash': parts[0],
                    'author': parts[1],
                    'email': parts[2],
                    'timestamp': int(parts[3]),
                    'message': parts[4]
                })
    return commits

def get_file_changes(path='.', since=None):
    """Get file change statistics"""
    args = ['log', '--numstat', '--format=']
    if since:
        args.extend(['--since', since])

    output = run_git(args, path)
    if not output:
        return {}

    file_stats = defaultdict(lambda: {'added': 0, 'deleted': 0, 'changes': 0})
    for line in output.split('\n'):
        parts = line.split('\t')
        if len(parts) >= 3 and parts[0] != '-':
            try:
                added = int(parts[0])
                deleted = int(parts[1])
                filename = parts[2]
                file_stats[filename]['added'] += added
                file_stats[filename]['deleted'] += deleted
                file_stats[filename]['changes'] += 1
            except:
                pass
    return file_stats

def get_contributors(path='.', since=None):
    """Get contributor statistics"""
    args = ['shortlog', '-sne', '--no-merges']
    if since:
        args.extend(['--since', since])

    output = run_git(args, path)
    if not output:
        return []

    contributors = []
    for line in output.strip().split('\n'):
        match = re.match(r'\s*(\d+)\s+(.+?)\s+<(.+?)>', line)
        if match:
            contributors.append({
                'commits': int(match.group(1)),
                'name': match.group(2),
                'email': match.group(3)
            })
    return contributors

def analyze_commit_times(commits):
    """Analyze commit time patterns"""
    hours = Counter()
    days = Counter()

    for c in commits:
        dt = datetime.fromtimestamp(c['timestamp'])
        hours[dt.hour] += 1
        days[dt.strftime('%A')] += 1

    return hours, days

def bar_chart(value, max_val, width=20):
    """Create a simple bar chart"""
    if max_val == 0:
        return ''
    filled = int(width * value / max_val)
    return f"{GREEN}{'█' * filled}{RESET}"

def main():
    parser = argparse.ArgumentParser(description='Git Repository Stats')
    parser.add_argument('path', nargs='?', default='.', help='Repository path')
    parser.add_argument('--author', '-a', help='Filter by author')
    parser.add_argument('--since', '-s', default='1 year ago', help='Since date')
    parser.add_argument('--top', '-t', type=int, default=10, help='Top N items to show')
    args = parser.parse_args()

    # Verify git repo
    if not run_git(['rev-parse', '--git-dir'], args.path):
        print(f"{RED}Error: Not a git repository{RESET}")
        return

    print(f"\n{BOLD}{CYAN}Git Repository Statistics{RESET}")
    print(f"{DIM}Path: {Path(args.path).absolute()}{RESET}")
    print(f"{DIM}Since: {args.since}{RESET}\n")

    # Get data
    commits = get_commits(args.path, args.author, args.since)
    contributors = get_contributors(args.path, args.since)

    if not commits:
        print("No commits found in the specified range.")
        return

    # Basic stats
    print(f"{BOLD}Overview{RESET}")
    print(f"  Total commits: {CYAN}{len(commits)}{RESET}")
    print(f"  Contributors: {CYAN}{len(contributors)}{RESET}")

    first_date = datetime.fromtimestamp(min(c['timestamp'] for c in commits))
    last_date = datetime.fromtimestamp(max(c['timestamp'] for c in commits))
    days_active = (last_date - first_date).days + 1
    print(f"  Active days: {CYAN}{days_active}{RESET}")
    print(f"  Commits/day: {CYAN}{len(commits)/days_active:.1f}{RESET}")

    # Top contributors
    print(f"\n{BOLD}Top Contributors{RESET}")
    max_commits = contributors[0]['commits'] if contributors else 0
    for i, c in enumerate(contributors[:args.top]):
        pct = c['commits'] / len(commits) * 100
        print(f"  {i+1:2}. {c['name'][:20]:<20} {bar_chart(c['commits'], max_commits)} {c['commits']:4} ({pct:.1f}%)")

    # File changes
    file_stats = get_file_changes(args.path, args.since)
    if file_stats:
        print(f"\n{BOLD}Most Changed Files{RESET}")
        sorted_files = sorted(file_stats.items(), key=lambda x: x[1]['changes'], reverse=True)
        max_changes = sorted_files[0][1]['changes'] if sorted_files else 0
        for filename, stats in sorted_files[:args.top]:
            name = filename[-40:] if len(filename) > 40 else filename
            if len(filename) > 40:
                name = '...' + name
            print(f"  {bar_chart(stats['changes'], max_changes, 15)} {stats['changes']:3}x  {GREEN}+{stats['added']:<5}{RED}-{stats['deleted']:<5}{RESET} {name}")

    # Commit time analysis
    hours, days = analyze_commit_times(commits)

    print(f"\n{BOLD}Commit Times (by hour){RESET}")
    max_hour = max(hours.values()) if hours else 0
    for h in range(24):
        count = hours.get(h, 0)
        bar = bar_chart(count, max_hour, 30)
        print(f"  {h:02}:00 {bar} {count}")

    print(f"\n{BOLD}Commit Days{RESET}")
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    max_day = max(days.values()) if days else 0
    for day in day_order:
        count = days.get(day, 0)
        bar = bar_chart(count, max_day, 30)
        print(f"  {day[:3]} {bar} {count}")

    # Recent activity
    print(f"\n{BOLD}Recent Commits{RESET}")
    for c in commits[:5]:
        dt = datetime.fromtimestamp(c['timestamp'])
        msg = c['message'][:50] + '...' if len(c['message']) > 50 else c['message']
        print(f"  {DIM}{dt.strftime('%Y-%m-%d')}{RESET} {c['hash'][:7]} {msg}")

    print()

if __name__ == '__main__':
    main()
