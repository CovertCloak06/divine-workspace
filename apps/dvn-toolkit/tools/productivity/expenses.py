#!/usr/bin/env python3
"""
Expense Tracker - Track spending and budgets
Usage: expenses.py [add|list|summary|budget]
"""

import os
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

EXPENSES_FILE = os.path.expanduser('~/.dvn_expenses.json')

CATEGORIES = [
    'Food', 'Transport', 'Entertainment', 'Shopping', 'Bills',
    'Health', 'Education', 'Personal', 'Home', 'Other'
]


def load_data():
    """Load expenses data"""
    if os.path.exists(EXPENSES_FILE):
        try:
            with open(EXPENSES_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'expenses': [], 'budgets': {}, 'currency': '$'}


def save_data(data):
    """Save expenses data"""
    with open(EXPENSES_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def add_expense(amount, category, description='', date=None):
    """Add a new expense"""
    data = load_data()

    expense = {
        'id': len(data['expenses']) + 1,
        'amount': float(amount),
        'category': category,
        'description': description,
        'date': date or datetime.now().strftime('%Y-%m-%d'),
        'created': datetime.now().isoformat(),
    }

    data['expenses'].append(expense)
    save_data(data)
    return expense


def delete_expense(expense_id):
    """Delete an expense"""
    data = load_data()

    for i, exp in enumerate(data['expenses']):
        if exp['id'] == int(expense_id):
            data['expenses'].pop(i)
            save_data(data)
            return True

    return False


def get_expenses(days=30, category=None):
    """Get expenses for a period"""
    data = load_data()
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    expenses = [e for e in data['expenses'] if e['date'] >= cutoff]

    if category:
        expenses = [e for e in expenses if e['category'].lower() == category.lower()]

    return sorted(expenses, key=lambda x: x['date'], reverse=True)


def get_summary(days=30):
    """Get expense summary"""
    expenses = get_expenses(days)

    summary = {
        'total': sum(e['amount'] for e in expenses),
        'count': len(expenses),
        'by_category': defaultdict(float),
        'daily_avg': 0,
    }

    for e in expenses:
        summary['by_category'][e['category']] += e['amount']

    if days > 0:
        summary['daily_avg'] = summary['total'] / days

    return summary


def set_budget(category, amount):
    """Set monthly budget for a category"""
    data = load_data()
    data['budgets'][category] = float(amount)
    save_data(data)


def get_budget_status():
    """Get budget status for current month"""
    data = load_data()

    # Get current month expenses
    today = datetime.now()
    month_start = today.replace(day=1).strftime('%Y-%m-%d')

    monthly_expenses = [e for e in data['expenses'] if e['date'] >= month_start]

    by_category = defaultdict(float)
    for e in monthly_expenses:
        by_category[e['category']] += e['amount']

    status = {}
    for cat, budget in data.get('budgets', {}).items():
        spent = by_category.get(cat, 0)
        status[cat] = {
            'budget': budget,
            'spent': spent,
            'remaining': budget - spent,
            'percent': (spent / budget * 100) if budget > 0 else 0
        }

    return status


def main():
    parser = argparse.ArgumentParser(description='Expense Tracker')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['add', 'list', 'summary', 'budget', 'delete', 'export'])
    parser.add_argument('amount', nargs='?', type=float, help='Expense amount')
    parser.add_argument('--category', '-c', help='Category')
    parser.add_argument('--description', '-d', help='Description')
    parser.add_argument('--date', '-D', help='Date (YYYY-MM-DD)')
    parser.add_argument('--days', '-n', type=int, default=30, help='Number of days')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              💰 Expense Tracker                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    data = load_data()
    currency = data.get('currency', '$')

    if args.action == 'list':
        expenses = get_expenses(args.days, args.category)

        if not expenses:
            print(f"  {DIM}No expenses in the last {args.days} days{RESET}\n")
            return

        print(f"  {BOLD}Recent Expenses ({len(expenses)}):{RESET}")
        print(f"  {DIM}{'─' * 55}{RESET}\n")

        total = 0
        for exp in expenses[:30]:
            total += exp['amount']
            desc = exp.get('description', '')[:20] or exp['category']

            print(f"  {DIM}{exp['date']}{RESET} {CYAN}{exp['category']:<12}{RESET} "
                  f"{GREEN}{currency}{exp['amount']:>8.2f}{RESET} {DIM}{desc}{RESET}")

        print(f"\n  {BOLD}Total:{RESET} {GREEN}{currency}{total:.2f}{RESET}")

        if len(expenses) > 30:
            print(f"  {DIM}... and {len(expenses) - 30} more{RESET}")

        print()

    elif args.action == 'add':
        amount = args.amount
        if amount is None:
            amount_str = input(f"  {CYAN}Amount:{RESET} ").strip()
            try:
                amount = float(amount_str.replace(currency, '').strip())
            except:
                print(f"  {RED}Invalid amount{RESET}\n")
                return

        # Category selection
        if not args.category:
            print(f"\n  {BOLD}Categories:{RESET}")
            for i, cat in enumerate(CATEGORIES, 1):
                print(f"  {CYAN}{i:>2}.{RESET} {cat}")

            cat_input = input(f"\n  {CYAN}Category (number or name):{RESET} ").strip()

            try:
                idx = int(cat_input) - 1
                if 0 <= idx < len(CATEGORIES):
                    args.category = CATEGORIES[idx]
            except ValueError:
                args.category = cat_input.title() if cat_input else 'Other'

        args.category = args.category or 'Other'
        description = args.description or input(f"  {CYAN}Description (optional):{RESET} ").strip()

        expense = add_expense(amount, args.category, description, args.date)

        print(f"\n  {GREEN}✓ Expense added{RESET}")
        print(f"  {DIM}{currency}{amount:.2f} - {args.category}{RESET}\n")

    elif args.action == 'summary':
        summary = get_summary(args.days)

        print(f"  {BOLD}Summary (Last {args.days} days):{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")

        print(f"  {CYAN}Total Spent:{RESET}  {GREEN}{currency}{summary['total']:.2f}{RESET}")
        print(f"  {CYAN}Transactions:{RESET} {summary['count']}")
        print(f"  {CYAN}Daily Avg:{RESET}    {currency}{summary['daily_avg']:.2f}")

        print(f"\n  {BOLD}By Category:{RESET}\n")

        # Sort by amount
        sorted_cats = sorted(summary['by_category'].items(), key=lambda x: x[1], reverse=True)

        for cat, amount in sorted_cats:
            percent = (amount / summary['total'] * 100) if summary['total'] > 0 else 0
            bar_len = int(percent / 5)
            bar = '█' * bar_len

            print(f"  {cat:<15} {currency}{amount:>8.2f} {DIM}({percent:>5.1f}%){RESET} {GREEN}{bar}{RESET}")

        print()

    elif args.action == 'budget':
        if args.amount and args.category:
            set_budget(args.category, args.amount)
            print(f"  {GREEN}✓ Budget set: {args.category} = {currency}{args.amount:.2f}/month{RESET}\n")
            return

        status = get_budget_status()

        if not status:
            print(f"  {DIM}No budgets set{RESET}")
            print(f"  {DIM}Use: expenses.py budget --category Food --amount 500{RESET}\n")
            return

        print(f"  {BOLD}Budget Status (This Month):{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for cat, info in status.items():
            spent = info['spent']
            budget = info['budget']
            remaining = info['remaining']
            percent = info['percent']

            # Color based on usage
            if percent >= 100:
                color = RED
                icon = '⚠️'
            elif percent >= 80:
                color = YELLOW
                icon = '⚡'
            else:
                color = GREEN
                icon = '✓'

            # Progress bar
            bar_filled = min(20, int(percent / 5))
            bar = '█' * bar_filled + '░' * (20 - bar_filled)

            print(f"  {icon} {cat}")
            print(f"     {color}{bar}{RESET} {percent:.0f}%")
            print(f"     {DIM}Spent: {currency}{spent:.2f} / {currency}{budget:.2f}{RESET}")

            if remaining > 0:
                print(f"     {GREEN}Remaining: {currency}{remaining:.2f}{RESET}")
            else:
                print(f"     {RED}Over by: {currency}{-remaining:.2f}{RESET}")

            print()

    elif args.action == 'delete':
        expense_id = args.amount or input(f"  {CYAN}Expense ID to delete:{RESET} ").strip()

        if expense_id and delete_expense(expense_id):
            print(f"  {GREEN}✓ Expense deleted{RESET}\n")
        else:
            print(f"  {RED}Expense not found{RESET}\n")

    elif args.action == 'export':
        expenses = get_expenses(args.days)
        print(json.dumps(expenses, indent=2))


if __name__ == '__main__':
    main()
