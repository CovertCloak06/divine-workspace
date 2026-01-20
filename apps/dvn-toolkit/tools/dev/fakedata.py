#!/usr/bin/env python3
"""
Fake Data Generator - Generate realistic test data
Usage: fakedata.py [--type name|email|address|...] [--count N]
"""

import argparse
import random
import string
import json
from datetime import datetime, timedelta

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Data pools
FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Emma", "Olivia", "Ava", "Isabella", "Sophia", "Mia", "Charlotte", "Amelia",
    "Liam", "Noah", "Oliver", "Elijah", "Lucas", "Mason", "Logan", "Alexander"
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores"
]

DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
           "proton.me", "mail.com", "aol.com", "zoho.com", "fastmail.com"]

STREET_NAMES = ["Main", "Oak", "Pine", "Maple", "Cedar", "Elm", "View", "Lake",
                "Hill", "Park", "Forest", "River", "Spring", "Valley", "Meadow"]

STREET_TYPES = ["St", "Ave", "Blvd", "Dr", "Ln", "Way", "Rd", "Ct", "Pl", "Cir"]

CITIES = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia",
          "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville",
          "Fort Worth", "Columbus", "Charlotte", "Seattle", "Denver", "Boston"]

STATES = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID",
          "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS",
          "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK",
          "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV"]

COMPANIES = ["Tech", "Global", "United", "First", "National", "American", "Pacific",
             "Digital", "Smart", "Future", "Prime", "Elite", "Nova", "Apex", "Core"]

COMPANY_TYPES = ["Inc", "LLC", "Corp", "Co", "Group", "Solutions", "Systems",
                 "Services", "Industries", "Technologies", "Enterprises"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]


def fake_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def fake_first_name():
    return random.choice(FIRST_NAMES)


def fake_last_name():
    return random.choice(LAST_NAMES)


def fake_email(name=None):
    if name:
        parts = name.lower().split()
        username = f"{parts[0]}.{parts[1]}" if len(parts) > 1 else parts[0]
    else:
        first = random.choice(FIRST_NAMES).lower()
        last = random.choice(LAST_NAMES).lower()
        formats = [
            f"{first}.{last}",
            f"{first}{last}",
            f"{first[0]}{last}",
            f"{first}{random.randint(1, 99)}",
        ]
        username = random.choice(formats)
    return f"{username}@{random.choice(DOMAINS)}"


def fake_phone():
    return f"({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}"


def fake_address():
    num = random.randint(100, 9999)
    street = random.choice(STREET_NAMES)
    stype = random.choice(STREET_TYPES)
    return f"{num} {street} {stype}"


def fake_city():
    return random.choice(CITIES)


def fake_state():
    return random.choice(STATES)


def fake_zip():
    return f"{random.randint(10000, 99999)}"


def fake_full_address():
    return f"{fake_address()}, {fake_city()}, {fake_state()} {fake_zip()}"


def fake_company():
    return f"{random.choice(COMPANIES)} {random.choice(COMPANY_TYPES)}"


def fake_job_title():
    levels = ["Junior", "Senior", "Lead", "Principal", "Chief", ""]
    roles = ["Software Engineer", "Developer", "Designer", "Manager", "Analyst",
             "Consultant", "Director", "Administrator", "Specialist", "Architect"]
    level = random.choice(levels)
    role = random.choice(roles)
    return f"{level} {role}".strip()


def fake_username():
    first = random.choice(FIRST_NAMES).lower()
    num = random.randint(1, 999) if random.random() > 0.5 else ""
    return f"{first}{num}"


def fake_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choice(chars) for _ in range(length))


def fake_ipv4():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def fake_ipv6():
    return ':'.join(f'{random.randint(0, 65535):04x}' for _ in range(8))


def fake_mac():
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))


def fake_date(start_year=2020, end_year=2024):
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31)
    delta = end - start
    random_days = random.randint(0, delta.days)
    return (start + timedelta(days=random_days)).strftime("%Y-%m-%d")


def fake_datetime():
    return f"{fake_date()} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"


def fake_credit_card():
    # Generate fake (invalid) card number
    prefix = random.choice(["4", "5", "37", "6011"])
    remaining = 16 - len(prefix) - 1
    number = prefix + ''.join(str(random.randint(0, 9)) for _ in range(remaining))
    # Add check digit (simplified)
    number += str(random.randint(0, 9))
    return number


def fake_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"


def fake_url():
    words = ["example", "test", "demo", "sample", "mysite", "cool", "awesome"]
    tlds = ["com", "net", "org", "io", "dev", "app"]
    return f"https://{random.choice(words)}.{random.choice(tlds)}"


def fake_user_agent():
    return random.choice(USER_AGENTS)


def fake_uuid():
    import uuid
    return str(uuid.uuid4())


def fake_person():
    """Generate a complete fake person"""
    first = fake_first_name()
    last = fake_last_name()
    name = f"{first} {last}"
    return {
        "name": name,
        "first_name": first,
        "last_name": last,
        "email": fake_email(name),
        "phone": fake_phone(),
        "address": fake_full_address(),
        "company": fake_company(),
        "job_title": fake_job_title(),
        "username": fake_username(),
        "birthdate": fake_date(1960, 2000),
    }


GENERATORS = {
    "name": fake_name,
    "first_name": fake_first_name,
    "last_name": fake_last_name,
    "email": fake_email,
    "phone": fake_phone,
    "address": fake_address,
    "city": fake_city,
    "state": fake_state,
    "zip": fake_zip,
    "full_address": fake_full_address,
    "company": fake_company,
    "job": fake_job_title,
    "username": fake_username,
    "password": fake_password,
    "ipv4": fake_ipv4,
    "ipv6": fake_ipv6,
    "mac": fake_mac,
    "date": fake_date,
    "datetime": fake_datetime,
    "cc": fake_credit_card,
    "ssn": fake_ssn,
    "url": fake_url,
    "useragent": fake_user_agent,
    "uuid": fake_uuid,
    "person": fake_person,
}


def main():
    parser = argparse.ArgumentParser(description='Fake Data Generator')
    parser.add_argument('type', nargs='?', help='Data type to generate')
    parser.add_argument('--count', '-n', type=int, default=1, help='Number to generate')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--list', '-l', action='store_true', help='List available types')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🎭 Fake Data Generator                        ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.list or not args.type:
        print(f"  {BOLD}Available Types:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        categories = {
            "Personal": ["name", "first_name", "last_name", "email", "phone", "username", "password"],
            "Location": ["address", "city", "state", "zip", "full_address"],
            "Business": ["company", "job"],
            "Network": ["ipv4", "ipv6", "mac", "url", "useragent"],
            "Time": ["date", "datetime"],
            "IDs": ["uuid", "cc", "ssn"],
            "Complete": ["person"],
        }

        for cat, types in categories.items():
            print(f"  {YELLOW}{cat}:{RESET}")
            for t in types:
                example = GENERATORS[t]()
                if isinstance(example, dict):
                    example = "{...}"
                print(f"    {CYAN}{t:<15}{RESET} {DIM}{str(example)[:40]}{RESET}")
            print()

        if not args.type:
            return

    if args.type not in GENERATORS:
        print(f"  {RED}Unknown type: {args.type}{RESET}")
        print(f"  {DIM}Use --list to see available types{RESET}\n")
        return

    print(f"  {BOLD}Generated {args.type} ({args.count}):{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    results = []
    for _ in range(args.count):
        result = GENERATORS[args.type]()
        results.append(result)

        if not args.json:
            if isinstance(result, dict):
                for k, v in result.items():
                    print(f"  {CYAN}{k}:{RESET} {GREEN}{v}{RESET}")
                print()
            else:
                print(f"  {GREEN}{result}{RESET}")

    if args.json:
        output = results if args.count > 1 else results[0]
        print(f"  {json.dumps(output, indent=2)}")

    print()


if __name__ == '__main__':
    main()
