#!/usr/bin/env python3
"""
Cron Manager - View and manage cron jobs
Usage: cron_manager.py [list|add|delete|explain]
"""

import subprocess
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


def get_crontab():
    """Get current user's crontab"""
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        return ""
    except:
        return ""


def set_crontab(content):
    """Set crontab content"""
    try:
        process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
        process.communicate(content)
        return process.returncode == 0
    except:
        return False


def parse_cron_line(line):
    """Parse a cron line into components"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Match cron pattern
    match = re.match(r'^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$', line)
    if match:
        return {
            'minute': match.group(1),
            'hour': match.group(2),
            'day': match.group(3),
            'month': match.group(4),
            'weekday': match.group(5),
            'command': match.group(6),
            'raw': line
        }
    return None


def explain_cron(minute, hour, day, month, weekday):
    """Explain cron schedule in human-readable format"""
    parts = []

    # Special cases
    if minute == '*' and hour == '*' and day == '*' and month == '*' and weekday == '*':
        return "Every minute"

    if minute == '0' and hour == '*' and day == '*' and month == '*' and weekday == '*':
        return "Every hour"

    if minute == '0' and hour == '0' and day == '*' and month == '*' and weekday == '*':
        return "Every day at midnight"

    # Minute
    if minute == '*':
        parts.append("every minute")
    elif minute.startswith('*/'):
        parts.append(f"every {minute[2:]} minutes")
    elif ',' in minute:
        parts.append(f"at minutes {minute}")
    else:
        parts.append(f"at minute {minute}")

    # Hour
    if hour == '*':
        if minute != '*':
            parts.append("of every hour")
    elif hour.startswith('*/'):
        parts.append(f"every {hour[2:]} hours")
    elif ',' in hour:
        parts.append(f"during hours {hour}")
    else:
        parts.append(f"at hour {hour}")

    # Day of month
    if day != '*':
        if day.startswith('*/'):
            parts.append(f"every {day[2:]} days")
        else:
            parts.append(f"on day {day}")

    # Month
    months = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    if month != '*':
        if ',' in month:
            month_names = [months[int(m)] for m in month.split(',') if m.isdigit()]
            parts.append(f"in {', '.join(month_names)}")
        elif month.isdigit():
            parts.append(f"in {months[int(month)]}")

    # Weekday
    days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    if weekday != '*':
        if ',' in weekday:
            day_names = [days[int(d)] for d in weekday.split(',') if d.isdigit()]
            parts.append(f"on {', '.join(day_names)}")
        elif weekday.isdigit():
            parts.append(f"on {days[int(weekday)]}")

    return ' '.join(parts).capitalize()


def list_cron_jobs():
    """List all cron jobs"""
    content = get_crontab()
    jobs = []

    for line in content.split('\n'):
        parsed = parse_cron_line(line)
        if parsed:
            jobs.append(parsed)

    return jobs


def add_cron_job(schedule, command):
    """Add a new cron job"""
    content = get_crontab()
    new_line = f"{schedule} {command}"

    if content.strip():
        content = content.rstrip() + '\n' + new_line + '\n'
    else:
        content = new_line + '\n'

    return set_crontab(content)


def delete_cron_job(index):
    """Delete cron job by index"""
    content = get_crontab()
    lines = content.split('\n')

    job_index = 0
    new_lines = []

    for line in lines:
        parsed = parse_cron_line(line)
        if parsed:
            if job_index != index:
                new_lines.append(line)
            job_index += 1
        else:
            new_lines.append(line)

    return set_crontab('\n'.join(new_lines))


def main():
    parser = argparse.ArgumentParser(description='Cron Manager')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['list', 'add', 'delete', 'explain', 'edit'])
    parser.add_argument('--schedule', '-s', help='Cron schedule (e.g., "0 * * * *")')
    parser.add_argument('--command', '-c', help='Command to run')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ⏰ Cron Manager                               ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list':
        jobs = list_cron_jobs()

        if not jobs:
            print(f"  {DIM}No cron jobs found{RESET}\n")
            return

        print(f"  {BOLD}Cron Jobs:{RESET}")
        print(f"  {DIM}{'─' * 60}{RESET}\n")

        for i, job in enumerate(jobs):
            schedule = f"{job['minute']} {job['hour']} {job['day']} {job['month']} {job['weekday']}"
            explanation = explain_cron(job['minute'], job['hour'], job['day'],
                                       job['month'], job['weekday'])

            print(f"  {CYAN}{i+1}.{RESET} {GREEN}{schedule}{RESET}")
            print(f"     {DIM}{explanation}{RESET}")
            print(f"     {job['command'][:60]}")
            print()

    elif args.action == 'add':
        if not args.schedule:
            print(f"  {BOLD}Add Cron Job:{RESET}")
            print(f"  {DIM}{'─' * 50}{RESET}\n")
            print(f"  {BOLD}Schedule Format:{RESET}")
            print(f"  {DIM}┌───────────── minute (0-59){RESET}")
            print(f"  {DIM}│ ┌─────────── hour (0-23){RESET}")
            print(f"  {DIM}│ │ ┌───────── day of month (1-31){RESET}")
            print(f"  {DIM}│ │ │ ┌─────── month (1-12){RESET}")
            print(f"  {DIM}│ │ │ │ ┌───── day of week (0-6, Sun=0){RESET}")
            print(f"  {DIM}│ │ │ │ │{RESET}")
            print(f"  {DIM}* * * * *{RESET}\n")

            print(f"  {BOLD}Common Examples:{RESET}")
            print(f"  {CYAN}*/5 * * * *{RESET}    Every 5 minutes")
            print(f"  {CYAN}0 * * * *{RESET}      Every hour")
            print(f"  {CYAN}0 0 * * *{RESET}      Every day at midnight")
            print(f"  {CYAN}0 0 * * 0{RESET}      Every Sunday at midnight")
            print(f"  {CYAN}0 9 * * 1-5{RESET}    Weekdays at 9am\n")

            args.schedule = input(f"  {CYAN}Schedule:{RESET} ").strip()

        if not args.command:
            args.command = input(f"  {CYAN}Command:{RESET} ").strip()

        if args.schedule and args.command:
            # Validate schedule format
            parts = args.schedule.split()
            if len(parts) != 5:
                print(f"\n  {RED}Invalid schedule format (need 5 fields){RESET}\n")
                return

            if add_cron_job(args.schedule, args.command):
                print(f"\n  {GREEN}✓ Cron job added{RESET}")
                explanation = explain_cron(*parts)
                print(f"  {DIM}{explanation}{RESET}\n")
            else:
                print(f"\n  {RED}Failed to add cron job{RESET}\n")
        else:
            print(f"\n  {RED}Schedule and command required{RESET}\n")

    elif args.action == 'delete':
        jobs = list_cron_jobs()

        if not jobs:
            print(f"  {DIM}No cron jobs found{RESET}\n")
            return

        print(f"  {BOLD}Select job to delete:{RESET}\n")
        for i, job in enumerate(jobs):
            schedule = f"{job['minute']} {job['hour']} {job['day']} {job['month']} {job['weekday']}"
            print(f"  {CYAN}{i+1}.{RESET} {schedule} {job['command'][:40]}")

        choice = input(f"\n  {CYAN}Number:{RESET} ").strip()

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(jobs):
                if delete_cron_job(idx):
                    print(f"\n  {GREEN}✓ Deleted{RESET}\n")
                else:
                    print(f"\n  {RED}Failed to delete{RESET}\n")
            else:
                print(f"\n  {RED}Invalid selection{RESET}\n")
        except ValueError:
            print(f"\n  {RED}Invalid number{RESET}\n")

    elif args.action == 'explain':
        print(f"  {BOLD}Cron Expression Explainer:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        schedule = input(f"  {CYAN}Schedule (e.g., '0 * * * *'):{RESET} ").strip()

        if schedule:
            parts = schedule.split()
            if len(parts) == 5:
                explanation = explain_cron(*parts)
                print(f"\n  {GREEN}{explanation}{RESET}\n")
            else:
                print(f"\n  {RED}Invalid format (need 5 fields){RESET}\n")

    elif args.action == 'edit':
        # Open crontab in editor
        editor = os.environ.get('EDITOR', 'nano')
        subprocess.run([editor, '-'], input=get_crontab(), text=True)

    # Quick reference
    print(f"  {BOLD}Quick Reference:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}*{RESET}     Any value")
    print(f"  {CYAN}*/n{RESET}   Every n units")
    print(f"  {CYAN}n,m{RESET}   Values n and m")
    print(f"  {CYAN}n-m{RESET}   Range from n to m")
    print()


if __name__ == '__main__':
    main()
