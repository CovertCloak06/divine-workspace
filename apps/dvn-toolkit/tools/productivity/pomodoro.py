#!/usr/bin/env python3
"""
Pomodoro Timer - Focus timer with work/break cycles
Usage: pomodoro.py [--work 25] [--break 5] [--long-break 15]
"""

import time
import argparse
import subprocess
import os
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def clear_line():
    """Clear the current line"""
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()


def send_notification(title, message):
    """Send desktop notification and sound"""
    try:
        subprocess.run(['notify-send', '-u', 'critical', title, message], timeout=5)
    except:
        pass

    # Try to play a sound
    try:
        subprocess.run(['paplay', '/usr/share/sounds/freedesktop/stereo/complete.oga'],
                      timeout=5, capture_output=True)
    except:
        try:
            # Beep fallback
            print('\a', end='')
        except:
            pass


def format_time(seconds):
    """Format seconds as MM:SS"""
    mins = seconds // 60
    secs = seconds % 60
    return f"{mins:02d}:{secs:02d}"


def draw_progress_bar(elapsed, total, width=40):
    """Draw a progress bar"""
    if total == 0:
        return '█' * width
    progress = elapsed / total
    filled = int(width * progress)
    bar = '█' * filled + '░' * (width - filled)
    return bar


def countdown(minutes, label, color):
    """Countdown timer with progress bar"""
    total_seconds = minutes * 60
    start_time = time.time()

    try:
        while True:
            elapsed = time.time() - start_time
            remaining = max(0, total_seconds - elapsed)

            if remaining <= 0:
                break

            # Draw timer
            bar = draw_progress_bar(elapsed, total_seconds)
            time_str = format_time(int(remaining))
            percent = int((elapsed / total_seconds) * 100)

            clear_line()
            sys.stdout.write(f"\r  {color}{label}{RESET} {bar} {time_str} ({percent}%)")
            sys.stdout.flush()

            time.sleep(0.5)

        # Timer complete
        clear_line()
        print(f"\r  {color}{label}{RESET} {'█' * 40} {GREEN}COMPLETE!{RESET}")
        return True

    except KeyboardInterrupt:
        clear_line()
        print(f"\r  {color}{label}{RESET} {YELLOW}PAUSED{RESET}")
        return False


def run_pomodoro(work_mins, break_mins, long_break_mins, cycles):
    """Run the pomodoro session"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🍅 Pomodoro Timer                             ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Work: {work_mins} min | Break: {break_mins} min | Long Break: {long_break_mins} min{RESET}")
    print(f"  {DIM}Cycles: {cycles} (long break after every 4 work sessions){RESET}")
    print(f"  {DIM}Press Ctrl+C to pause/skip{RESET}\n")

    completed_cycles = 0
    work_sessions = 0

    for cycle in range(1, cycles + 1):
        print(f"\n  {BOLD}═══ Cycle {cycle}/{cycles} ═══{RESET}\n")

        # Work phase
        print(f"  {GREEN}Starting work session ({work_mins} min)...{RESET}")
        send_notification("🍅 Pomodoro", f"Work session {cycle} started!")

        if countdown(work_mins, "🍅 WORK", RED):
            work_sessions += 1
            send_notification("☕ Break Time!", f"Work session {cycle} complete. Take a break!")

            # Determine break type
            if work_sessions % 4 == 0:
                # Long break
                print(f"\n  {CYAN}Long break time! ({long_break_mins} min){RESET}")
                if not countdown(long_break_mins, "☕ LONG BREAK", CYAN):
                    break
            else:
                # Short break
                print(f"\n  {CYAN}Short break time! ({break_mins} min){RESET}")
                if not countdown(break_mins, "☕ BREAK", GREEN):
                    break

            send_notification("🍅 Break Over", "Time to get back to work!")
            completed_cycles += 1
        else:
            # Paused during work
            choice = input(f"\n  {CYAN}[C]ontinue, [S]kip, or [Q]uit?{RESET} ").strip().lower()
            if choice == 'q':
                break
            elif choice == 's':
                continue

    print(f"\n{DIM}{'─' * 60}{RESET}")
    print(f"\n  {BOLD}Session Summary:{RESET}")
    print(f"  {GREEN}● Completed cycles: {completed_cycles}{RESET}")
    print(f"  {GREEN}● Work sessions: {work_sessions}{RESET}")
    print(f"  {GREEN}● Total focus time: {work_sessions * work_mins} minutes{RESET}\n")

    # Motivational message
    if completed_cycles >= cycles:
        print(f"  {GREEN}🎉 Amazing! You completed all {cycles} cycles!{RESET}")
    elif completed_cycles > 0:
        print(f"  {YELLOW}👍 Good effort! Keep it up!{RESET}")
    else:
        print(f"  {CYAN}No worries, try again when you're ready.{RESET}")

    print()


def interactive_menu():
    """Interactive pomodoro menu"""
    presets = {
        '1': ('Classic', 25, 5, 15, 4),
        '2': ('Short', 15, 3, 10, 6),
        '3': ('Long Focus', 50, 10, 20, 3),
        '4': ('Quick', 10, 2, 5, 4),
    }

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🍅 Pomodoro Timer                             ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {BOLD}Select a preset:{RESET}")
    for key, (name, work, brk, long_brk, cycles) in presets.items():
        print(f"  [{key}] {name}: {work}/{brk}/{long_brk} min × {cycles} cycles")
    print(f"  [c] Custom")
    print(f"  [q] Quit")

    choice = input(f"\n  {GREEN}>{RESET} ").strip().lower()

    if choice == 'q':
        return
    elif choice == 'c':
        try:
            work = int(input(f"  {CYAN}Work minutes (25):{RESET} ") or 25)
            brk = int(input(f"  {CYAN}Break minutes (5):{RESET} ") or 5)
            long_brk = int(input(f"  {CYAN}Long break minutes (15):{RESET} ") or 15)
            cycles = int(input(f"  {CYAN}Number of cycles (4):{RESET} ") or 4)
            run_pomodoro(work, brk, long_brk, cycles)
        except ValueError:
            print(f"  {RED}Invalid input{RESET}")
    elif choice in presets:
        name, work, brk, long_brk, cycles = presets[choice]
        print(f"\n  {GREEN}Starting {name} preset...{RESET}")
        run_pomodoro(work, brk, long_brk, cycles)


def main():
    parser = argparse.ArgumentParser(description='Pomodoro Timer')
    parser.add_argument('--work', '-w', type=int, default=25, help='Work duration in minutes')
    parser.add_argument('--break', '-b', dest='break_mins', type=int, default=5, help='Break duration')
    parser.add_argument('--long-break', '-l', type=int, default=15, help='Long break duration')
    parser.add_argument('--cycles', '-c', type=int, default=4, help='Number of cycles')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    args = parser.parse_args()

    if args.interactive:
        interactive_menu()
    else:
        run_pomodoro(args.work, args.break_mins, args.long_break, args.cycles)


if __name__ == '__main__':
    main()
