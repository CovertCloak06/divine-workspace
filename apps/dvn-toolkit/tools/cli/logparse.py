#!/usr/bin/env python3
"""
Log Analyzer - Parse and summarize log files
Usage: logparse <logfile> [--level ERROR] [--since "1 hour ago"] [--top 10]
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common log patterns
LOG_PATTERNS = [
    # Standard: 2024-01-15 10:30:45 ERROR message
    re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})[^\w]*(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)[^\w]*(?P<message>.*)'),
    # Syslog: Jan 15 10:30:45 hostname service[pid]: message
    re.compile(r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<service>\S+?)(?:\[\d+\])?:\s*(?P<message>.*)'),
    # Apache/Nginx: [timestamp] [level] message
    re.compile(r'\[(?P<timestamp>[^\]]+)\]\s*\[(?P<level>\w+)\]\s*(?P<message>.*)'),
    # Simple: [LEVEL] message
    re.compile(r'\[(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\]\s*(?P<message>.*)'),
]

def parse_relative_time(time_str):
    """Parse relative time strings like '1 hour ago'"""
    now = datetime.now()
    match = re.match(r'(\d+)\s*(second|minute|hour|day|week|month)s?\s*ago', time_str, re.I)
    if match:
        amount = int(match.group(1))
        unit = match.group(2).lower()
        if unit == 'second':
            return now - timedelta(seconds=amount)
        elif unit == 'minute':
            return now - timedelta(minutes=amount)
        elif unit == 'hour':
            return now - timedelta(hours=amount)
        elif unit == 'day':
            return now - timedelta(days=amount)
        elif unit == 'week':
            return now - timedelta(weeks=amount)
        elif unit == 'month':
            return now - timedelta(days=amount * 30)
    return None

def parse_timestamp(ts_str):
    """Try to parse various timestamp formats"""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%b %d %H:%M:%S',
        '%d/%b/%Y:%H:%M:%S',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            # Handle year for syslog format
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except:
            continue
    return None

def parse_log_line(line):
    """Parse a log line using known patterns"""
    for pattern in LOG_PATTERNS:
        match = pattern.search(line)
        if match:
            groups = match.groupdict()
            return {
                'timestamp': parse_timestamp(groups.get('timestamp', '')),
                'level': groups.get('level', 'INFO').upper(),
                'message': groups.get('message', line).strip(),
                'service': groups.get('service', ''),
                'raw': line
            }
    return {'timestamp': None, 'level': 'INFO', 'message': line.strip(), 'raw': line}

def analyze_logs(filepath, level_filter=None, since=None, top_n=10):
    """Analyze log file and return statistics"""
    path = Path(filepath)
    if not path.exists():
        print(f"{RED}Error: File not found: {filepath}{RESET}")
        return

    level_counts = Counter()
    hourly_counts = defaultdict(int)
    message_patterns = Counter()
    errors = []
    total_lines = 0
    parsed_lines = 0

    # Parse since time
    since_dt = None
    if since:
        since_dt = parse_relative_time(since)

    print(f"\n{BOLD}{CYAN}Log Analysis: {path.name}{RESET}")
    print(f"{DIM}Size: {path.stat().st_size / 1024:.1f} KB{RESET}\n")

    with open(path, 'r', errors='replace') as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            entry = parse_log_line(line)

            # Time filter
            if since_dt and entry['timestamp'] and entry['timestamp'] < since_dt:
                continue

            # Level filter
            level = entry['level']
            if level.startswith('WARN'):
                level = 'WARN'

            if level_filter and level != level_filter.upper():
                continue

            parsed_lines += 1
            level_counts[level] += 1

            # Track hourly distribution
            if entry['timestamp']:
                hour = entry['timestamp'].strftime('%Y-%m-%d %H:00')
                hourly_counts[hour] += 1

            # Extract error patterns (simplify messages)
            msg = entry['message']
            # Normalize numbers and IDs
            pattern = re.sub(r'\b\d+\b', 'N', msg)
            pattern = re.sub(r'\b[0-9a-f]{8,}\b', 'ID', pattern, flags=re.I)
            pattern = pattern[:100]
            message_patterns[pattern] += 1

            # Store errors for display
            if level in ('ERROR', 'FATAL', 'CRITICAL'):
                errors.append(entry)

    # Output results
    print(f"{BOLD}Summary{RESET}")
    print(f"  Total lines: {total_lines}")
    print(f"  Parsed entries: {parsed_lines}")

    # Level distribution
    print(f"\n{BOLD}Log Levels{RESET}")
    level_colors = {'DEBUG': DIM, 'INFO': GREEN, 'WARN': YELLOW, 'WARNING': YELLOW, 'ERROR': RED, 'FATAL': RED, 'CRITICAL': RED}
    for level, count in level_counts.most_common():
        color = level_colors.get(level, RESET)
        pct = count / parsed_lines * 100 if parsed_lines else 0
        bar = '█' * int(pct / 2)
        print(f"  {color}{level:8}{RESET} {count:6} ({pct:5.1f}%) {GREEN}{bar}{RESET}")

    # Hourly distribution
    if hourly_counts:
        print(f"\n{BOLD}Hourly Activity{RESET}")
        max_count = max(hourly_counts.values())
        sorted_hours = sorted(hourly_counts.items())[-12:]  # Last 12 hours
        for hour, count in sorted_hours:
            bar_len = int(count / max_count * 30) if max_count else 0
            print(f"  {hour[-5:]} {GREEN}{'█' * bar_len}{RESET} {count}")

    # Top message patterns
    print(f"\n{BOLD}Top Message Patterns{RESET}")
    for pattern, count in message_patterns.most_common(top_n):
        display = pattern[:60] + '...' if len(pattern) > 60 else pattern
        print(f"  {count:5}x  {display}")

    # Recent errors
    if errors:
        print(f"\n{BOLD}{RED}Recent Errors ({len(errors)} total){RESET}")
        for entry in errors[-5:]:
            ts = entry['timestamp'].strftime('%H:%M:%S') if entry['timestamp'] else '??:??:??'
            msg = entry['message'][:70] + '...' if len(entry['message']) > 70 else entry['message']
            print(f"  {DIM}{ts}{RESET} {msg}")

    print()

def main():
    parser = argparse.ArgumentParser(description='Log Analyzer')
    parser.add_argument('logfile', help='Log file to analyze')
    parser.add_argument('--level', '-l', help='Filter by log level (ERROR, WARN, INFO, DEBUG)')
    parser.add_argument('--since', '-s', help='Only show logs since (e.g., "1 hour ago")')
    parser.add_argument('--top', '-t', type=int, default=10, help='Show top N patterns')
    args = parser.parse_args()

    analyze_logs(args.logfile, args.level, args.since, args.top)

if __name__ == '__main__':
    main()
