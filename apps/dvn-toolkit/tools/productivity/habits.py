#!/usr/bin/env python3
"""
Habit Tracker - Track daily habits
Usage: habits.py [add|check|list|stats]
"""

import os
import json
import argparse
from datetime import datetime, timedelta

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

HABITS_FILE = os.path.expanduser('~/.dvn_habits.json')


def load_data():
    """Load habits data"""
    if os.path.exists(HABITS_FILE):
        try:
            with open(HABITS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'habits': [], 'completions': {}}


def save_data(data):
    """Save habits data"""
    with open(HABITS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def add_habit(name, frequency='daily', goal=1, description=''):
    """Add a new habit"""
    data = load_data()

    # Check for duplicate
    for h in data['habits']:
        if h['name'].lower() == name.lower():
            return False, "Habit already exists"

    habit = {
        'id': len(data['habits']) + 1,
        'name': name,
        'frequency': frequency,
        'goal': goal,
        'description': description,
        'created': datetime.now().isoformat(),
        'active': True,
    }

    data['habits'].append(habit)
    save_data(data)
    return True, habit


def delete_habit(identifier):
    """Delete or deactivate a habit"""
    data = load_data()

    for h in data['habits']:
        if str(h['id']) == str(identifier) or h['name'].lower() == identifier.lower():
            h['active'] = False
            save_data(data)
            return True

    return False


def check_habit(identifier, date=None, count=1):
    """Mark habit as done"""
    data = load_data()
    date = date or datetime.now().strftime('%Y-%m-%d')

    for h in data['habits']:
        if str(h['id']) == str(identifier) or h['name'].lower() == identifier.lower():
            key = f"{h['id']}:{date}"

            if key not in data['completions']:
                data['completions'][key] = 0

            data['completions'][key] += count
            save_data(data)
            return True, data['completions'][key]

    return False, "Habit not found"


def uncheck_habit(identifier, date=None):
    """Remove habit completion"""
    data = load_data()
    date = date or datetime.now().strftime('%Y-%m-%d')

    for h in data['habits']:
        if str(h['id']) == str(identifier) or h['name'].lower() == identifier.lower():
            key = f"{h['id']}:{date}"
            if key in data['completions']:
                del data['completions'][key]
                save_data(data)
                return True

    return False


def get_completions(habit_id, days=7):
    """Get completion history for a habit"""
    data = load_data()
    completions = {}

    for i in range(days):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        key = f"{habit_id}:{date}"
        completions[date] = data['completions'].get(key, 0)

    return completions


def get_streak(habit_id):
    """Calculate current streak"""
    data = load_data()

    # Find habit
    habit = None
    for h in data['habits']:
        if h['id'] == habit_id:
            habit = h
            break

    if not habit:
        return 0

    streak = 0
    current_date = datetime.now()

    while True:
        date = current_date.strftime('%Y-%m-%d')
        key = f"{habit_id}:{date}"
        count = data['completions'].get(key, 0)

        if count >= habit.get('goal', 1):
            streak += 1
            current_date -= timedelta(days=1)
        else:
            break

    return streak


def main():
    parser = argparse.ArgumentParser(description='Habit Tracker')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['add', 'check', 'uncheck', 'list', 'stats', 'delete'])
    parser.add_argument('habit', nargs='?', help='Habit name or ID')
    parser.add_argument('--goal', '-g', type=int, default=1, help='Daily goal')
    parser.add_argument('--date', '-d', help='Date (YYYY-MM-DD)')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ✅ Habit Tracker                              ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    today = datetime.now().strftime('%Y-%m-%d')

    if args.action == 'list':
        data = load_data()
        habits = [h for h in data['habits'] if h.get('active', True)]

        if not habits:
            print(f"  {DIM}No habits tracked{RESET}")
            print(f"  {DIM}Use 'habits.py add <name>' to add one{RESET}\n")
            return

        print(f"  {BOLD}Today's Habits ({today}):{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for h in habits:
            key = f"{h['id']}:{today}"
            done = data['completions'].get(key, 0)
            goal = h.get('goal', 1)
            streak = get_streak(h['id'])

            # Status indicator
            if done >= goal:
                status = f"{GREEN}✓{RESET}"
                progress = f"{GREEN}Done!{RESET}"
            elif done > 0:
                status = f"{YELLOW}◐{RESET}"
                progress = f"{YELLOW}{done}/{goal}{RESET}"
            else:
                status = f"{DIM}○{RESET}"
                progress = f"{DIM}0/{goal}{RESET}"

            # Streak
            streak_str = f" 🔥{streak}" if streak > 0 else ""

            print(f"  {status} {CYAN}{h['id']}.{RESET} {h['name']:<25} {progress}{streak_str}")

            # Show last 7 days
            completions = get_completions(h['id'], 7)
            week_str = ""
            for i in range(6, -1, -1):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                if completions.get(date, 0) >= goal:
                    week_str += f"{GREEN}■{RESET}"
                elif completions.get(date, 0) > 0:
                    week_str += f"{YELLOW}■{RESET}"
                else:
                    week_str += f"{DIM}□{RESET}"

            print(f"     {DIM}Last 7 days:{RESET} {week_str}")
            print()

    elif args.action == 'add':
        name = args.habit or input(f"  {CYAN}Habit name:{RESET} ").strip()

        if not name:
            print(f"  {RED}Habit name required{RESET}\n")
            return

        goal = args.goal

        success, result = add_habit(name, goal=goal)

        if success:
            print(f"  {GREEN}✓ Habit added: {name}{RESET}")
            print(f"  {DIM}ID: {result['id']}, Goal: {goal}/day{RESET}\n")
        else:
            print(f"  {YELLOW}{result}{RESET}\n")

    elif args.action == 'check':
        if not args.habit:
            # Show list and select
            data = load_data()
            habits = [h for h in data['habits'] if h.get('active', True)]

            if not habits:
                print(f"  {DIM}No habits to check{RESET}\n")
                return

            print(f"  {BOLD}Check off a habit:{RESET}\n")
            for h in habits:
                print(f"  {CYAN}{h['id']}.{RESET} {h['name']}")

            args.habit = input(f"\n  {CYAN}ID or name:{RESET} ").strip()

        if args.habit:
            success, count = check_habit(args.habit, args.date)
            if success:
                print(f"  {GREEN}✓ Checked! ({count} today){RESET}\n")
            else:
                print(f"  {RED}Habit not found{RESET}\n")

    elif args.action == 'uncheck':
        if not args.habit:
            args.habit = input(f"  {CYAN}Habit to uncheck:{RESET} ").strip()

        if args.habit and uncheck_habit(args.habit, args.date):
            print(f"  {GREEN}✓ Unchecked{RESET}\n")
        else:
            print(f"  {RED}Habit not found{RESET}\n")

    elif args.action == 'delete':
        if not args.habit:
            args.habit = input(f"  {CYAN}Habit to delete:{RESET} ").strip()

        if args.habit and delete_habit(args.habit):
            print(f"  {GREEN}✓ Habit deactivated{RESET}\n")
        else:
            print(f"  {RED}Habit not found{RESET}\n")

    elif args.action == 'stats':
        data = load_data()
        habits = [h for h in data['habits'] if h.get('active', True)]

        print(f"  {BOLD}Statistics:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        total_completions = 0
        for h in habits:
            streak = get_streak(h['id'])

            # Count all completions
            habit_completions = sum(1 for key in data['completions']
                                   if key.startswith(f"{h['id']}:") and data['completions'][key] > 0)

            total_completions += habit_completions

            print(f"  {CYAN}{h['name']}{RESET}")
            print(f"    Current streak: {YELLOW}{streak} days{RESET}")
            print(f"    Total completions: {habit_completions}")
            print()

        print(f"  {DIM}Total habits: {len(habits)}{RESET}")
        print(f"  {DIM}Total completions: {total_completions}{RESET}\n")


if __name__ == '__main__':
    main()
