#!/usr/bin/env python3
"""
Google Dorker - Generate and use Google dork queries for OSINT
Usage: google_dork.py <target> [--category all]
"""

import argparse
import urllib.parse
import webbrowser

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Dork templates by category
DORKS = {
    'files': [
        ('Exposed Documents', 'site:{target} filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls'),
        ('Config Files', 'site:{target} filetype:xml OR filetype:conf OR filetype:cfg OR filetype:ini'),
        ('Database Files', 'site:{target} filetype:sql OR filetype:db OR filetype:mdb'),
        ('Backup Files', 'site:{target} filetype:bak OR filetype:old OR filetype:backup'),
        ('Log Files', 'site:{target} filetype:log'),
        ('Source Code', 'site:{target} filetype:php OR filetype:asp OR filetype:py OR filetype:js'),
        ('Environment Files', 'site:{target} filetype:env OR ".env"'),
    ],

    'sensitive': [
        ('Login Pages', 'site:{target} inurl:login OR inurl:signin OR inurl:admin'),
        ('Admin Panels', 'site:{target} inurl:admin OR inurl:administrator OR inurl:wp-admin'),
        ('Passwords in URL', 'site:{target} inurl:password OR inurl:passwd'),
        ('Exposed Credentials', 'site:{target} "password" filetype:txt OR filetype:log'),
        ('Private Keys', 'site:{target} "BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"'),
        ('AWS Keys', 'site:{target} "AKIA" OR "aws_secret_access_key"'),
        ('API Keys', 'site:{target} "api_key" OR "apikey" OR "api-key"'),
    ],

    'directories': [
        ('Directory Listing', 'site:{target} intitle:"index of"'),
        ('Parent Directory', 'site:{target} intitle:"index of" "parent directory"'),
        ('Apache Status', 'site:{target} intitle:"Apache Status"'),
        ('PHP Info', 'site:{target} intitle:"phpinfo()" OR inurl:phpinfo.php'),
        ('Git Exposed', 'site:{target} inurl:".git"'),
        ('SVN Exposed', 'site:{target} inurl:".svn"'),
        ('.htaccess', 'site:{target} filetype:htaccess'),
    ],

    'vulnerabilities': [
        ('SQL Errors', 'site:{target} "SQL syntax" OR "mysql_fetch" OR "Warning: mysql"'),
        ('PHP Errors', 'site:{target} "Warning:" "on line" filetype:php'),
        ('Debug Mode', 'site:{target} "debug" "error" "exception"'),
        ('Stack Traces', 'site:{target} "stack trace" OR "traceback"'),
        ('Server Errors', 'site:{target} "Internal Server Error" OR "500 Error"'),
        ('Test/Dev Servers', 'site:{target} inurl:test OR inurl:dev OR inurl:staging'),
    ],

    'infrastructure': [
        ('Subdomains', 'site:*.{target}'),
        ('Related Sites', 'related:{target}'),
        ('Cached Pages', 'cache:{target}'),
        ('Robots.txt', 'site:{target} inurl:robots.txt'),
        ('Sitemap', 'site:{target} inurl:sitemap.xml'),
        ('WordPress', 'site:{target} inurl:wp-content OR inurl:wp-includes'),
        ('Joomla', 'site:{target} inurl:com_content'),
        ('Drupal', 'site:{target} inurl:node/'),
    ],

    'email': [
        ('Email Addresses', 'site:{target} "@{target}"'),
        ('Contact Info', 'site:{target} "contact" "email" "@"'),
        ('Email in Files', '"{target}" filetype:txt OR filetype:csv "@"'),
    ],

    'social': [
        ('LinkedIn', 'site:linkedin.com "{target}"'),
        ('Twitter Mentions', 'site:twitter.com "{target}"'),
        ('Facebook', 'site:facebook.com "{target}"'),
        ('GitHub', 'site:github.com "{target}"'),
        ('Pastebin', 'site:pastebin.com "{target}"'),
    ],
}


def generate_dorks(target, categories=None):
    """Generate dork queries for target"""
    results = {}

    if categories is None:
        categories = DORKS.keys()

    for category in categories:
        if category in DORKS:
            results[category] = []
            for name, template in DORKS[category]:
                query = template.format(target=target)
                results[category].append((name, query))

    return results


def get_google_url(query):
    """Generate Google search URL"""
    return f"https://www.google.com/search?q={urllib.parse.quote(query)}"


def main():
    parser = argparse.ArgumentParser(description='Google Dorker')
    parser.add_argument('target', help='Target domain (example.com)')
    parser.add_argument('--category', '-c', help='Category: files, sensitive, directories, vulnerabilities, infrastructure, email, social, all')
    parser.add_argument('--open', '-o', action='store_true', help='Open first 5 results in browser')
    parser.add_argument('--list', '-l', action='store_true', help='List available categories')
    args = parser.parse_args()

    if args.list:
        print(f"\n{BOLD}{CYAN}Available Categories:{RESET}\n")
        for cat, dorks in DORKS.items():
            print(f"  {GREEN}{cat}{RESET} ({len(dorks)} dorks)")
            for name, _ in dorks[:2]:
                print(f"    {DIM}• {name}{RESET}")
            if len(dorks) > 2:
                print(f"    {DIM}  ...and {len(dorks)-2} more{RESET}")
        print()
        return

    target = args.target.replace('http://', '').replace('https://', '').strip('/')

    # Select categories
    if args.category and args.category != 'all':
        categories = [args.category]
    else:
        categories = list(DORKS.keys())

    dorks = generate_dorks(target, categories)

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔎 Google Dorker                              ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")
    print(f"  {DIM}Target: {CYAN}{target}{RESET}\n")

    opened = 0
    for category, queries in dorks.items():
        print(f"  {BOLD}{GREEN}━━━ {category.upper()} ━━━{RESET}\n")

        for name, query in queries:
            url = get_google_url(query)
            print(f"  {CYAN}{name}{RESET}")
            print(f"  {DIM}Query: {query}{RESET}")
            print(f"  {YELLOW}URL: {url}{RESET}")
            print()

            if args.open and opened < 5:
                webbrowser.open(url)
                opened += 1

    # Summary
    total = sum(len(q) for q in dorks.values())
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"\n  {BOLD}Generated {total} dork queries{RESET}")
    print(f"  {DIM}Copy URLs to browser or use --open to launch{RESET}")

    if args.open:
        print(f"\n  {GREEN}Opened first 5 queries in browser{RESET}")

    # Interactive mode
    print(f"\n  {BOLD}Quick Actions:{RESET}")
    print(f"  {DIM}Enter a number to open that query, 'q' to quit{RESET}\n")

    all_queries = [(name, query) for queries in dorks.values() for name, query in queries]

    for i, (name, _) in enumerate(all_queries[:20], 1):
        print(f"  [{i:2}] {name}")

    while True:
        try:
            choice = input(f"\n  {GREEN}>{RESET} ").strip()
            if choice.lower() == 'q':
                break
            idx = int(choice) - 1
            if 0 <= idx < len(all_queries):
                name, query = all_queries[idx]
                url = get_google_url(query)
                print(f"  {CYAN}Opening: {name}{RESET}")
                webbrowser.open(url)
        except (ValueError, KeyboardInterrupt):
            break

    print()


if __name__ == '__main__':
    main()
