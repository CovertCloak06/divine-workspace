#!/usr/bin/env python3
"""
Timer - Countdown timer and stopwatch
Usage: timer.py 5m | timer.py --stopwatch
"""

import sys
import time
import argparse
import re
import os

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def parse_duration(duration_str):
    """Parse duration string like '5m', '1h30m', '90s' """
    total_seconds = 0

    # Match patterns like 1h, 30m, 45s
    patterns = [
        (r'(\d+)\s*h', 3600),   # hours
        (r'(\d+)\s*m', 60),      # minutes
        (r'(\d+)\s*s', 1),       # seconds
    ]

    for pattern, multiplier in patterns:
        match = re.search(pattern, duration_str.lower())
        if match:
            total_seconds += int(match.group(1)) * multiplier

    # If just a number, assume minutes
    if total_seconds == 0 and duration_str.isdigit():
        total_seconds = int(duration_str) * 60

    return total_seconds


def format_time(seconds):
    """Format seconds as HH:MM:SS or MM:SS"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def display_big_time(time_str, color=CYAN):
    """Display time in big ASCII digits"""
    digits = {
        '0': ['┌───┐', '│   │', '│   │', '│   │', '└───┘'],
        '1': ['    ┐', '    │', '    │', '    │', '    ┘'],
        '2': ['┌───┐', '    │', '┌───┘', '│    ', '└───┘'],
        '3': ['┌───┐', '    │', ' ───┤', '    │', '└───┘'],
        '4': ['│   │', '│   │', '└───┤', '    │', '    ┘'],
        '5': ['┌───┐', '│    ', '└───┐', '    │', '└───┘'],
        '6': ['┌───┐', '│    ', '├───┐', '│   │', '└───┘'],
        '7': ['┌───┐', '    │', '    │', '    │', '    ┘'],
        '8': ['┌───┐', '│   │', '├───┤', '│   │', '└───┘'],
        '9': ['┌───┐', '│   │', '└───┤', '    │', '└───┘'],
        ':': ['     ', '  ●  ', '     ', '  ●  ', '     '],
    }

    lines = ['', '', '', '', '']
    for char in time_str:
        if char in digits:
            for i, line in enumerate(digits[char]):
                lines[i] += line + ' '

    for line in lines:
        print(f"  {color}{line}{RESET}")


def countdown_timer(seconds, label="Timer"):
    """Run countdown timer"""
    start_time = time.time()
    end_time = start_time + seconds

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ⏱️  Countdown Timer                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}{label}: {format_time(seconds)}{RESET}")
    print(f"  {DIM}Press Ctrl+C to stop{RESET}\n")

    try:
        while True:
            remaining = end_time - time.time()

            if remaining <= 0:
                break

            # Clear previous display
            sys.stdout.write('\033[6A')  # Move up 6 lines
            sys.stdout.write('\033[J')   # Clear to end

            # Color based on time remaining
            if remaining <= 10:
                color = RED
            elif remaining <= 60:
                color = YELLOW
            else:
                color = GREEN

            display_big_time(format_time(remaining), color)
            print()

            time.sleep(0.1)

        # Timer complete
        sys.stdout.write('\033[6A')
        sys.stdout.write('\033[J')
        display_big_time("00:00", GREEN)
        print()

        # Alert
        print(f"  {GREEN}{BOLD}⏰ TIME'S UP!{RESET}")

        # Terminal bell
        print('\a', end='')
        sys.stdout.flush()

        # Flash alert
        for _ in range(3):
            time.sleep(0.3)
            print('\a', end='')
            sys.stdout.flush()

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        remaining = seconds - elapsed
        print(f"\n\n  {YELLOW}Timer stopped{RESET}")
        print(f"  {DIM}Elapsed: {format_time(elapsed)} | Remaining: {format_time(max(0, remaining))}{RESET}")

    print()


def stopwatch():
    """Run stopwatch"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ⏱️  Stopwatch                                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Press Ctrl+C to stop, Enter for lap{RESET}\n")

    laps = []
    start_time = time.time()
    lap_start = start_time

    # Make stdin non-blocking for lap detection
    import select

    try:
        while True:
            elapsed = time.time() - start_time
            lap_time = time.time() - lap_start

            # Check for enter key (lap)
            if select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                laps.append(lap_time)
                lap_start = time.time()
                print(f"\r  {CYAN}Lap {len(laps)}:{RESET} {format_time(lap_time)}              ")

            # Clear and display
            sys.stdout.write('\033[6A')
            sys.stdout.write('\033[J')

            display_big_time(format_time(elapsed), GREEN)
            print()

            if laps:
                print(f"  {DIM}Last lap: {format_time(laps[-1])}{RESET}")
            else:
                print()

            time.sleep(0.1)

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n\n  {BOLD}Final Time:{RESET} {GREEN}{format_time(elapsed)}{RESET}")

        if laps:
            print(f"\n  {BOLD}Laps:{RESET}")
            for i, lap in enumerate(laps, 1):
                print(f"    {CYAN}Lap {i}:{RESET} {format_time(lap)}")

            avg_lap = sum(laps) / len(laps)
            print(f"  {DIM}Average lap: {format_time(avg_lap)}{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Timer and Stopwatch')
    parser.add_argument('duration', nargs='?', help='Duration (e.g., 5m, 1h30m, 90s)')
    parser.add_argument('--stopwatch', '-s', action='store_true', help='Stopwatch mode')
    parser.add_argument('--label', '-l', default='Timer', help='Timer label')
    args = parser.parse_args()

    if args.stopwatch:
        stopwatch()
    elif args.duration:
        seconds = parse_duration(args.duration)
        if seconds > 0:
            countdown_timer(seconds, args.label)
        else:
            print(f"{RED}Invalid duration. Use format like: 5m, 1h30m, 90s{RESET}")
    else:
        # Interactive mode
        print(f"\n{BOLD}{CYAN}Timer{RESET}\n")
        print(f"  {CYAN}1.{RESET} Countdown timer")
        print(f"  {CYAN}2.{RESET} Stopwatch")

        choice = input(f"\n  {CYAN}Choice:{RESET} ").strip()

        if choice == '1':
            duration = input(f"  {CYAN}Duration (e.g., 5m, 1h30m):{RESET} ").strip()
            seconds = parse_duration(duration)
            if seconds > 0:
                countdown_timer(seconds)
            else:
                print(f"  {RED}Invalid duration{RESET}")
        elif choice == '2':
            stopwatch()


if __name__ == '__main__':
    main()
