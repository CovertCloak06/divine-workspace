#!/usr/bin/env python3
"""
Logcat Parser - Android Log Analysis Tool
Parses and filters Android logcat output for security analysis
"""

import os
import sys
import re
import argparse
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional
import json

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    E = '\033[0m'

# Log level colors
LEVEL_COLORS = {
    'V': C.W,   # Verbose
    'D': C.B,   # Debug
    'I': C.G,   # Info
    'W': C.Y,   # Warning
    'E': C.R,   # Error
    'F': C.R,   # Fatal
}

# Sensitive patterns to search for
SENSITIVE_PATTERNS = {
    'API Keys': [
        r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]{16,}',
        r'authorization["\']?\s*[:=]\s*["\']?bearer\s+[\w-]+',
    ],
    'Tokens': [
        r'token["\']?\s*[:=]\s*["\']?[\w-]{20,}',
        r'jwt["\']?\s*[:=]\s*["\']?eyJ[\w-]+',
        r'session[_-]?id["\']?\s*[:=]\s*[\w-]{20,}',
    ],
    'Passwords': [
        r'password["\']?\s*[:=]\s*["\']?[^\s"\']{4,}',
        r'passwd["\']?\s*[:=]\s*["\']?[^\s"\']{4,}',
        r'pwd["\']?\s*[:=]\s*["\']?[^\s"\']{4,}',
    ],
    'URLs': [
        r'https?://[^\s"\'<>]{10,}',
    ],
    'IPs': [
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    ],
    'Emails': [
        r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b',
    ],
    'Phone Numbers': [
        r'\b\+?1?\d{10,14}\b',
    ],
    'Credit Cards': [
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    ],
    'SQL': [
        r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\s+(?:FROM|INTO|SET)',
    ],
    'Exceptions': [
        r'(?:Exception|Error|Crash|Fatal):\s*.+',
        r'at\s+[\w\.$]+\([\w]+\.java:\d+\)',
    ],
}


class LogEntry:
    """Represents a single log entry"""
    def __init__(self, raw: str):
        self.raw = raw
        self.timestamp = None
        self.pid = None
        self.tid = None
        self.level = None
        self.tag = None
        self.message = None
        self.parse()

    def parse(self):
        """Parse log entry"""
        # Format: 01-13 12:34:56.789  1234  5678 I Tag: Message
        # Or: I/Tag(1234): Message
        patterns = [
            # Standard format
            r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(\S+?):\s*(.*)$',
            # Brief format
            r'^([VDIWEF])/(\S+?)\(\s*(\d+)\):\s*(.*)$',
            # Threadtime format
            r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(.+?):\s*(.*)$',
        ]

        for pattern in patterns:
            match = re.match(pattern, self.raw.strip())
            if match:
                groups = match.groups()
                if len(groups) == 6:
                    self.timestamp = groups[0]
                    self.pid = groups[1]
                    self.tid = groups[2]
                    self.level = groups[3]
                    self.tag = groups[4]
                    self.message = groups[5]
                elif len(groups) == 4:
                    self.level = groups[0]
                    self.tag = groups[1]
                    self.pid = groups[2]
                    self.message = groups[3]
                break

    def matches_filter(self, level: str = None, tag: str = None, pid: str = None,
                       keyword: str = None) -> bool:
        """Check if entry matches filters"""
        if level and self.level and self.level not in level.upper():
            return False
        if tag and self.tag and tag.lower() not in self.tag.lower():
            return False
        if pid and self.pid and str(pid) != str(self.pid):
            return False
        if keyword and keyword.lower() not in self.raw.lower():
            return False
        return True

    def __str__(self):
        color = LEVEL_COLORS.get(self.level, C.W)
        if self.timestamp:
            return f"{C.C}{self.timestamp}{C.E} {color}{self.level}{C.E}/{C.Y}{self.tag}{C.E}: {self.message}"
        else:
            return f"{color}{self.level}{C.E}/{C.Y}{self.tag}{C.E}: {self.message}"


class LogcatParser:
    def __init__(self):
        self.entries = []
        self.stats = defaultdict(int)

    def parse_file(self, filepath: str):
        """Parse logcat file"""
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                if line.strip():
                    entry = LogEntry(line)
                    if entry.level:
                        self.entries.append(entry)
                        self.stats[entry.level] += 1
                        self.stats['total'] += 1

    def parse_text(self, text: str):
        """Parse logcat text"""
        for line in text.split('\n'):
            if line.strip():
                entry = LogEntry(line)
                if entry.level:
                    self.entries.append(entry)
                    self.stats[entry.level] += 1
                    self.stats['total'] += 1

    def filter_entries(self, level: str = None, tag: str = None, pid: str = None,
                       keyword: str = None) -> List[LogEntry]:
        """Filter log entries"""
        return [e for e in self.entries if e.matches_filter(level, tag, pid, keyword)]

    def find_sensitive_data(self) -> Dict[str, List[str]]:
        """Search for sensitive data in logs"""
        findings = defaultdict(list)

        for entry in self.entries:
            text = entry.raw

            for category, patterns in SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for match in matches:
                        if len(match) < 200:  # Avoid huge matches
                            finding = f"{entry.tag}: {match}"
                            if finding not in findings[category]:
                                findings[category].append(finding)

        return dict(findings)

    def get_errors(self) -> List[LogEntry]:
        """Get error and fatal entries"""
        return [e for e in self.entries if e.level in ['E', 'F']]

    def get_exceptions(self) -> List[Dict]:
        """Extract exception stack traces"""
        exceptions = []
        current_exception = None

        for entry in self.entries:
            if entry.level in ['E', 'F']:
                if 'Exception' in entry.message or 'Error' in entry.message:
                    if current_exception:
                        exceptions.append(current_exception)
                    current_exception = {
                        'type': entry.message.split(':')[0] if ':' in entry.message else entry.message,
                        'tag': entry.tag,
                        'timestamp': entry.timestamp,
                        'stacktrace': [entry.message]
                    }
                elif current_exception and entry.message.strip().startswith('at '):
                    current_exception['stacktrace'].append(entry.message)
                elif current_exception and 'Caused by:' in entry.message:
                    current_exception['stacktrace'].append(entry.message)
                else:
                    if current_exception:
                        exceptions.append(current_exception)
                        current_exception = None

        if current_exception:
            exceptions.append(current_exception)

        return exceptions

    def get_app_logs(self, package: str) -> List[LogEntry]:
        """Get logs for specific app package"""
        return [e for e in self.entries if package.lower() in (e.tag or '').lower() or
                package.lower() in (e.message or '').lower()]

    def get_stats(self) -> Dict:
        """Get log statistics"""
        tag_counts = defaultdict(int)
        for entry in self.entries:
            if entry.tag:
                tag_counts[entry.tag] += 1

        top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            'total': self.stats['total'],
            'by_level': {
                'Verbose': self.stats.get('V', 0),
                'Debug': self.stats.get('D', 0),
                'Info': self.stats.get('I', 0),
                'Warning': self.stats.get('W', 0),
                'Error': self.stats.get('E', 0),
                'Fatal': self.stats.get('F', 0),
            },
            'top_tags': dict(top_tags),
        }

    def export_json(self, filepath: str):
        """Export logs to JSON"""
        data = {
            'stats': self.get_stats(),
            'sensitive_data': self.find_sensitive_data(),
            'exceptions': self.get_exceptions(),
            'entries': [
                {
                    'timestamp': e.timestamp,
                    'level': e.level,
                    'tag': e.tag,
                    'pid': e.pid,
                    'message': e.message
                }
                for e in self.entries
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Logcat Parser')
    parser.add_argument('input', nargs='?', help='Input logcat file (or - for stdin)')
    parser.add_argument('-l', '--level', help='Filter by level (V,D,I,W,E,F)')
    parser.add_argument('-t', '--tag', help='Filter by tag')
    parser.add_argument('-p', '--pid', help='Filter by PID')
    parser.add_argument('-k', '--keyword', help='Filter by keyword')
    parser.add_argument('-a', '--app', help='Filter by app package')
    parser.add_argument('-e', '--errors', action='store_true', help='Show only errors')
    parser.add_argument('-s', '--sensitive', action='store_true', help='Search for sensitive data')
    parser.add_argument('-x', '--exceptions', action='store_true', help='Extract exceptions')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('-o', '--output', help='Export to JSON file')
    parser.add_argument('-n', '--lines', type=int, default=0, help='Limit output lines')

    args = parser.parse_args()

    print(f"{C.M}Logcat Parser{C.E}")
    print(f"{C.Y}Android Log Analysis Tool{C.E}\n")

    log_parser = LogcatParser()

    # Read input
    if args.input == '-' or (args.input is None and not sys.stdin.isatty()):
        text = sys.stdin.read()
        log_parser.parse_text(text)
    elif args.input:
        if not os.path.exists(args.input):
            print(f"{C.R}File not found:{C.E} {args.input}")
            sys.exit(1)
        log_parser.parse_file(args.input)
    else:
        parser.print_help()
        return

    print(f"{C.G}Parsed {log_parser.stats['total']} log entries{C.E}\n")

    # Show statistics
    if args.stats or (not any([args.errors, args.sensitive, args.exceptions, args.level, args.tag])):
        stats = log_parser.get_stats()
        print(f"{C.B}[Statistics]{C.E}")
        print(f"  Total entries: {stats['total']}")
        print(f"\n  {C.C}By Level:{C.E}")
        for level, count in stats['by_level'].items():
            if count > 0:
                print(f"    {level}: {count}")

        print(f"\n  {C.C}Top Tags:{C.E}")
        for tag, count in list(stats['top_tags'].items())[:10]:
            print(f"    {tag}: {count}")
        print()

    # Search for sensitive data
    if args.sensitive:
        print(f"{C.B}[Sensitive Data Search]{C.E}")
        findings = log_parser.find_sensitive_data()

        if findings:
            for category, items in findings.items():
                if items:
                    print(f"\n  {C.Y}{category}:{C.E}")
                    for item in items[:10]:
                        print(f"    {C.R}{item[:100]}{C.E}")
        else:
            print(f"  {C.G}No sensitive data found{C.E}")
        print()

    # Extract exceptions
    if args.exceptions:
        print(f"{C.B}[Exceptions]{C.E}")
        exceptions = log_parser.get_exceptions()

        if exceptions:
            for i, exc in enumerate(exceptions[:20], 1):
                print(f"\n  {C.R}Exception #{i}:{C.E}")
                print(f"    Type: {exc['type']}")
                print(f"    Tag: {exc['tag']}")
                if exc['timestamp']:
                    print(f"    Time: {exc['timestamp']}")
                print(f"    Stack trace:")
                for line in exc['stacktrace'][:5]:
                    print(f"      {line[:80]}")
        else:
            print(f"  {C.G}No exceptions found{C.E}")
        print()

    # Show errors
    if args.errors:
        print(f"{C.B}[Errors & Fatals]{C.E}")
        errors = log_parser.get_errors()
        for entry in errors[:50]:
            print(f"  {entry}")
        print()

    # Filter and display
    if args.level or args.tag or args.pid or args.keyword:
        entries = log_parser.filter_entries(args.level, args.tag, args.pid, args.keyword)
        print(f"{C.B}[Filtered Results] ({len(entries)} entries){C.E}")
        limit = args.lines if args.lines > 0 else len(entries)
        for entry in entries[:limit]:
            print(f"  {entry}")
        print()

    # App-specific logs
    if args.app:
        print(f"{C.B}[App Logs: {args.app}]{C.E}")
        app_logs = log_parser.get_app_logs(args.app)
        limit = args.lines if args.lines > 0 else 50
        for entry in app_logs[:limit]:
            print(f"  {entry}")
        print()

    # Export
    if args.output:
        log_parser.export_json(args.output)
        print(f"{C.G}Exported to:{C.E} {args.output}")


if __name__ == '__main__':
    main()
