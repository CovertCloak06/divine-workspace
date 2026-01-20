#!/usr/bin/env python3
"""
Username Hunter - Check if username exists across many platforms
Usage: username_check.py <username> [--timeout 5]
"""

import urllib.request
import urllib.error
import argparse
import concurrent.futures
import ssl
import json

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Sites to check - (name, url_template, check_type)
# check_type: 'status' = 200 means exists, 'not_found' = check for "not found" text
SITES = [
    # Social Media
    ('Twitter/X', 'https://twitter.com/{}', 'status'),
    ('Instagram', 'https://www.instagram.com/{}/', 'status'),
    ('Facebook', 'https://www.facebook.com/{}', 'status'),
    ('TikTok', 'https://www.tiktok.com/@{}', 'status'),
    ('LinkedIn', 'https://www.linkedin.com/in/{}', 'status'),
    ('Pinterest', 'https://www.pinterest.com/{}/', 'status'),
    ('Tumblr', 'https://{}.tumblr.com', 'status'),
    ('Reddit', 'https://www.reddit.com/user/{}', 'status'),

    # Developer
    ('GitHub', 'https://github.com/{}', 'status'),
    ('GitLab', 'https://gitlab.com/{}', 'status'),
    ('Bitbucket', 'https://bitbucket.org/{}/', 'status'),
    ('Dev.to', 'https://dev.to/{}', 'status'),
    ('HackerNews', 'https://news.ycombinator.com/user?id={}', 'content'),
    ('StackOverflow', 'https://stackoverflow.com/users/{}', 'status'),
    ('CodePen', 'https://codepen.io/{}', 'status'),
    ('Replit', 'https://replit.com/@{}', 'status'),

    # Gaming
    ('Steam', 'https://steamcommunity.com/id/{}', 'status'),
    ('Twitch', 'https://www.twitch.tv/{}', 'status'),
    ('Roblox', 'https://www.roblox.com/users/profile?username={}', 'content'),
    ('Chess.com', 'https://www.chess.com/member/{}', 'status'),

    # Creative
    ('YouTube', 'https://www.youtube.com/@{}', 'status'),
    ('SoundCloud', 'https://soundcloud.com/{}', 'status'),
    ('Spotify', 'https://open.spotify.com/user/{}', 'status'),
    ('Dribbble', 'https://dribbble.com/{}', 'status'),
    ('Behance', 'https://www.behance.net/{}', 'status'),
    ('Medium', 'https://medium.com/@{}', 'status'),

    # Tech/Community
    ('Keybase', 'https://keybase.io/{}', 'status'),
    ('Mastodon.social', 'https://mastodon.social/@{}', 'status'),
    ('Hacker.one', 'https://hackerone.com/{}', 'status'),
    ('BugCrowd', 'https://bugcrowd.com/{}', 'status'),
    ('PyPI', 'https://pypi.org/user/{}/', 'status'),
    ('NPM', 'https://www.npmjs.com/~{}', 'status'),
    ('DockerHub', 'https://hub.docker.com/u/{}', 'status'),

    # Forums
    ('HackForums', 'https://hackforums.net/member.php?action=profile&username={}', 'content'),

    # Other
    ('About.me', 'https://about.me/{}', 'status'),
    ('Gravatar', 'https://en.gravatar.com/{}', 'status'),
    ('Patreon', 'https://www.patreon.com/{}', 'status'),
    ('Ko-fi', 'https://ko-fi.com/{}', 'status'),
    ('Cash.app', 'https://cash.app/${}', 'status'),
    ('Linktree', 'https://linktr.ee/{}', 'status'),
]


def check_site(username, site_info, timeout=5):
    """Check if username exists on a site"""
    name, url_template, check_type = site_info
    url = url_template.format(username)

    # Create SSL context that doesn't verify (for speed)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = response.getcode()

        if check_type == 'status':
            if status == 200:
                return (name, url, 'found', status)
        elif check_type == 'content':
            content = response.read().decode('utf-8', errors='ignore').lower()
            if 'not found' not in content and '404' not in content:
                return (name, url, 'found', status)

        return (name, url, 'not_found', status)

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (name, url, 'not_found', 404)
        elif e.code in [403, 429]:
            return (name, url, 'blocked', e.code)
        return (name, url, 'error', e.code)

    except Exception as e:
        return (name, url, 'error', str(e)[:20])


def main():
    parser = argparse.ArgumentParser(description='Username Hunter')
    parser.add_argument('username', help='Username to search for')
    parser.add_argument('--timeout', '-t', type=int, default=5, help='Request timeout')
    parser.add_argument('--threads', type=int, default=20, help='Concurrent checks')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    username = args.username.strip()

    if not args.json:
        print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║              🔍 Username Hunter                            ║{RESET}")
        print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")
        print(f"  {DIM}Searching for: {CYAN}{username}{RESET}")
        print(f"  {DIM}Checking {len(SITES)} sites...{RESET}\n")

    found = []
    not_found = []
    errors = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_site, username, site, args.timeout): site[0]
            for site in SITES
        }

        for future in concurrent.futures.as_completed(futures):
            name, url, status, code = future.result()

            if status == 'found':
                found.append({'name': name, 'url': url})
                if not args.json:
                    print(f"  {GREEN}[+]{RESET} {name:<20} {GREEN}Found{RESET} → {CYAN}{url}{RESET}")
            elif status == 'not_found':
                not_found.append(name)
                if not args.json:
                    print(f"  {DIM}[-] {name:<20} Not found{RESET}")
            elif status == 'blocked':
                errors.append(f"{name} (blocked)")
                if not args.json:
                    print(f"  {YELLOW}[!]{RESET} {name:<20} {YELLOW}Blocked/Rate limited{RESET}")
            else:
                errors.append(f"{name} ({code})")
                if not args.json:
                    print(f"  {RED}[x]{RESET} {name:<20} {RED}Error{RESET}")

    if args.json:
        print(json.dumps({
            'username': username,
            'found': found,
            'not_found': not_found,
            'errors': errors
        }, indent=2))
    else:
        print(f"\n  {DIM}{'─' * 50}{RESET}")
        print(f"\n  {BOLD}Summary:{RESET}")
        print(f"  {GREEN}● Found on {len(found)} sites{RESET}")
        print(f"  {DIM}● Not found on {len(not_found)} sites{RESET}")
        if errors:
            print(f"  {YELLOW}● Errors/blocked: {len(errors)}{RESET}")

        if found:
            print(f"\n  {BOLD}Profile URLs:{RESET}")
            for item in found:
                print(f"    {CYAN}{item['url']}{RESET}")

        print()


if __name__ == '__main__':
    main()
