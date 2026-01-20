#!/usr/bin/env python3
"""
Username Search - Check username availability across platforms
Usage: username_search.py [username] [--fast] [--json]
Checks 50+ popular platforms
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
import ssl
import concurrent.futures
import time

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Platforms to check (URL pattern, name, category)
PLATFORMS = [
    # Social Media
    {'name': 'Twitter/X', 'url': 'https://twitter.com/{user}', 'category': 'social', 'error_type': '404'},
    {'name': 'Instagram', 'url': 'https://www.instagram.com/{user}/', 'category': 'social', 'error_type': '404'},
    {'name': 'Facebook', 'url': 'https://www.facebook.com/{user}', 'category': 'social', 'error_type': 'content'},
    {'name': 'TikTok', 'url': 'https://www.tiktok.com/@{user}', 'category': 'social', 'error_type': '404'},
    {'name': 'LinkedIn', 'url': 'https://www.linkedin.com/in/{user}', 'category': 'social', 'error_type': '404'},
    {'name': 'Pinterest', 'url': 'https://www.pinterest.com/{user}/', 'category': 'social', 'error_type': '404'},
    {'name': 'Tumblr', 'url': 'https://{user}.tumblr.com', 'category': 'social', 'error_type': '404'},
    {'name': 'Reddit', 'url': 'https://www.reddit.com/user/{user}', 'category': 'social', 'error_type': '404'},
    {'name': 'Snapchat', 'url': 'https://www.snapchat.com/add/{user}', 'category': 'social', 'error_type': '404'},
    {'name': 'Mastodon', 'url': 'https://mastodon.social/@{user}', 'category': 'social', 'error_type': '404'},

    # Development
    {'name': 'GitHub', 'url': 'https://github.com/{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'GitLab', 'url': 'https://gitlab.com/{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'Bitbucket', 'url': 'https://bitbucket.org/{user}/', 'category': 'dev', 'error_type': '404'},
    {'name': 'StackOverflow', 'url': 'https://stackoverflow.com/users/{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'HackerNews', 'url': 'https://news.ycombinator.com/user?id={user}', 'category': 'dev', 'error_type': 'content'},
    {'name': 'Dev.to', 'url': 'https://dev.to/{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'Codepen', 'url': 'https://codepen.io/{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'Replit', 'url': 'https://replit.com/@{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'NPM', 'url': 'https://www.npmjs.com/~{user}', 'category': 'dev', 'error_type': '404'},
    {'name': 'PyPI', 'url': 'https://pypi.org/user/{user}/', 'category': 'dev', 'error_type': '404'},

    # Gaming
    {'name': 'Steam', 'url': 'https://steamcommunity.com/id/{user}', 'category': 'gaming', 'error_type': 'content'},
    {'name': 'Twitch', 'url': 'https://www.twitch.tv/{user}', 'category': 'gaming', 'error_type': '404'},
    {'name': 'Xbox', 'url': 'https://account.xbox.com/en-us/profile?gamertag={user}', 'category': 'gaming', 'error_type': 'content'},
    {'name': 'Discord', 'url': 'https://discord.com/users/{user}', 'category': 'gaming', 'error_type': '404'},
    {'name': 'Roblox', 'url': 'https://www.roblox.com/user.aspx?username={user}', 'category': 'gaming', 'error_type': 'content'},

    # Media
    {'name': 'YouTube', 'url': 'https://www.youtube.com/@{user}', 'category': 'media', 'error_type': '404'},
    {'name': 'Spotify', 'url': 'https://open.spotify.com/user/{user}', 'category': 'media', 'error_type': '404'},
    {'name': 'SoundCloud', 'url': 'https://soundcloud.com/{user}', 'category': 'media', 'error_type': '404'},
    {'name': 'Flickr', 'url': 'https://www.flickr.com/people/{user}/', 'category': 'media', 'error_type': '404'},
    {'name': 'Vimeo', 'url': 'https://vimeo.com/{user}', 'category': 'media', 'error_type': '404'},
    {'name': 'Dailymotion', 'url': 'https://www.dailymotion.com/{user}', 'category': 'media', 'error_type': '404'},

    # Forums/Communities
    {'name': 'Medium', 'url': 'https://medium.com/@{user}', 'category': 'community', 'error_type': '404'},
    {'name': 'Quora', 'url': 'https://www.quora.com/profile/{user}', 'category': 'community', 'error_type': '404'},
    {'name': 'ProductHunt', 'url': 'https://www.producthunt.com/@{user}', 'category': 'community', 'error_type': '404'},
    {'name': 'Keybase', 'url': 'https://keybase.io/{user}', 'category': 'community', 'error_type': '404'},
    {'name': 'About.me', 'url': 'https://about.me/{user}', 'category': 'community', 'error_type': '404'},
    {'name': 'Gravatar', 'url': 'https://gravatar.com/{user}', 'category': 'community', 'error_type': '404'},

    # Professional
    {'name': 'Dribbble', 'url': 'https://dribbble.com/{user}', 'category': 'professional', 'error_type': '404'},
    {'name': 'Behance', 'url': 'https://www.behance.net/{user}', 'category': 'professional', 'error_type': '404'},
    {'name': 'Patreon', 'url': 'https://www.patreon.com/{user}', 'category': 'professional', 'error_type': '404'},
    {'name': 'Fiverr', 'url': 'https://www.fiverr.com/{user}', 'category': 'professional', 'error_type': '404'},
    {'name': 'Upwork', 'url': 'https://www.upwork.com/freelancers/~{user}', 'category': 'professional', 'error_type': '404'},

    # Security/Hacking
    {'name': 'HackTheBox', 'url': 'https://app.hackthebox.com/users/{user}', 'category': 'security', 'error_type': '404'},
    {'name': 'TryHackMe', 'url': 'https://tryhackme.com/p/{user}', 'category': 'security', 'error_type': '404'},
    {'name': 'BugCrowd', 'url': 'https://bugcrowd.com/{user}', 'category': 'security', 'error_type': '404'},
    {'name': 'HackerOne', 'url': 'https://hackerone.com/{user}', 'category': 'security', 'error_type': '404'},
]


def check_platform(platform, username, timeout=10):
    """Check if username exists on a platform"""
    url = platform['url'].format(user=username)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            # Status 200 = found
            if platform['error_type'] == 'content':
                content = response.read().decode('utf-8', errors='ignore')
                # Check if page shows "not found" type content
                not_found_indicators = ['not found', 'doesn\'t exist', 'no user', 'page not found']
                if any(ind in content.lower() for ind in not_found_indicators):
                    return {'platform': platform['name'], 'url': url, 'found': False, 'category': platform['category']}
            return {'platform': platform['name'], 'url': url, 'found': True, 'category': platform['category']}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'platform': platform['name'], 'url': url, 'found': False, 'category': platform['category']}
        elif e.code in [403, 429]:
            return {'platform': platform['name'], 'url': url, 'found': None, 'error': 'blocked', 'category': platform['category']}
        return {'platform': platform['name'], 'url': url, 'found': None, 'error': str(e.code), 'category': platform['category']}
    except Exception as e:
        return {'platform': platform['name'], 'url': url, 'found': None, 'error': str(e)[:30], 'category': platform['category']}


def search_username(username, fast=False, show_progress=True):
    """Search username across all platforms"""
    platforms_to_check = PLATFORMS[:20] if fast else PLATFORMS
    results = []

    max_workers = 15 if fast else 10

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_platform, p, username): p for p in platforms_to_check}

        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            results.append(result)

            if show_progress:
                done = i + 1
                total = len(platforms_to_check)
                pct = int((done / total) * 100)
                bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
                print(f"\r  [{bar}] {pct}% ({done}/{total})", end='', flush=True)

    if show_progress:
        print()  # Newline after progress bar

    return results


def display_results(username, results):
    """Display search results"""
    print(f"\n  {BOLD}Username Search Results{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    print(f"  {CYAN}Username:{RESET} {BOLD}{username}{RESET}")
    print()

    # Group by status
    found = [r for r in results if r.get('found') == True]
    not_found = [r for r in results if r.get('found') == False]
    errors = [r for r in results if r.get('found') is None]

    # Summary
    print(f"  {GREEN}Found:{RESET} {len(found)} | {YELLOW}Available:{RESET} {len(not_found)} | {DIM}Errors:{RESET} {len(errors)}")
    print()

    # Found profiles
    if found:
        print(f"  {BOLD}Profiles Found ({len(found)}){RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")

        # Group by category
        by_category = {}
        for r in found:
            cat = r.get('category', 'other')
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(r)

        for category, items in sorted(by_category.items()):
            print(f"  {CYAN}{category.upper()}{RESET}")
            for item in items:
                print(f"    {GREEN}  {item['platform']}{RESET}")
                print(f"       {DIM}{item['url']}{RESET}")
            print()

    # Available (not found)
    if not_found and len(not_found) <= 20:
        print(f"  {BOLD}Available Usernames ({len(not_found)}){RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")
        for r in not_found[:10]:
            print(f"    {YELLOW}  {r['platform']}{RESET}")
        if len(not_found) > 10:
            print(f"    {DIM}... and {len(not_found) - 10} more{RESET}")
        print()

    # Errors
    if errors:
        print(f"  {BOLD}Errors/Blocked ({len(errors)}){RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")
        for r in errors[:5]:
            print(f"    {DIM}  {r['platform']}: {r.get('error', 'unknown')}{RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(description='Username Search')
    parser.add_argument('username', nargs='?', help='Username to search')
    parser.add_argument('--fast', '-f', action='store_true', help='Fast mode (top 20 sites only)')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--found-only', '-o', action='store_true', help='Only show found profiles')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Username Search Tool{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    username = args.username
    if not username:
        username = input(f"\n  {CYAN}Username to search:{RESET} ").strip()

    if not username:
        print(f"  {RED}Username required{RESET}")
        sys.exit(1)

    # Validate username
    if len(username) < 2 or len(username) > 30:
        print(f"  {YELLOW}Warning: Unusual username length{RESET}")

    if not args.json:
        mode = "fast" if args.fast else "full"
        count = 20 if args.fast else len(PLATFORMS)
        print(f"\n  {DIM}Searching {count} platforms ({mode} mode)...{RESET}\n")

    results = search_username(username, fast=args.fast, show_progress=not args.json)

    if args.found_only:
        results = [r for r in results if r.get('found') == True]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        display_results(username, results)


if __name__ == '__main__':
    main()
