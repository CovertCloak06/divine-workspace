#!/usr/bin/env python3
"""
Social Media Reconnaissance - OSINT tool for social profiles
Usage: social_recon.py [query] [--type person|company] [--json]
Searches and analyzes social media presence
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
import urllib.parse
import ssl
import re
import concurrent.futures

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Social platforms and their URL patterns
PLATFORMS = {
    # Major social
    'twitter': {
        'url': 'https://twitter.com/{user}',
        'search': 'https://twitter.com/search?q={query}',
        'icon': '',
    },
    'instagram': {
        'url': 'https://www.instagram.com/{user}/',
        'icon': '',
    },
    'facebook': {
        'url': 'https://www.facebook.com/{user}',
        'search': 'https://www.facebook.com/search/top/?q={query}',
        'icon': '',
    },
    'linkedin': {
        'url': 'https://www.linkedin.com/in/{user}',
        'search': 'https://www.linkedin.com/search/results/all/?keywords={query}',
        'icon': '',
    },
    'tiktok': {
        'url': 'https://www.tiktok.com/@{user}',
        'icon': '',
    },

    # Dev platforms
    'github': {
        'url': 'https://github.com/{user}',
        'api': 'https://api.github.com/users/{user}',
        'icon': '',
    },
    'gitlab': {
        'url': 'https://gitlab.com/{user}',
        'icon': '',
    },
    'stackoverflow': {
        'search': 'https://stackoverflow.com/users?q={query}',
        'icon': '',
    },

    # Professional
    'medium': {
        'url': 'https://medium.com/@{user}',
        'icon': '',
    },
    'devto': {
        'url': 'https://dev.to/{user}',
        'icon': '',
    },

    # Other
    'reddit': {
        'url': 'https://www.reddit.com/user/{user}',
        'icon': '',
    },
    'pinterest': {
        'url': 'https://www.pinterest.com/{user}/',
        'icon': '',
    },
    'youtube': {
        'url': 'https://www.youtube.com/@{user}',
        'search': 'https://www.youtube.com/results?search_query={query}',
        'icon': '',
    },
    'twitch': {
        'url': 'https://www.twitch.tv/{user}',
        'icon': '',
    },
}


def check_profile(platform, username, timeout=10):
    """Check if a profile exists on a platform"""
    config = PLATFORMS.get(platform, {})
    url = config.get('url', '').format(user=username)

    if not url:
        return None

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            content = response.read().decode('utf-8', errors='ignore')[:5000]

            result = {
                'platform': platform,
                'url': url,
                'found': True,
            }

            # Try to extract additional info based on platform
            if platform == 'twitter':
                # Look for follower count
                followers_match = re.search(r'(\d+(?:,\d+)*)\s*Followers', content)
                if followers_match:
                    result['followers'] = followers_match.group(1)

            elif platform == 'github':
                # Use API for more info
                try:
                    api_url = config.get('api', '').format(user=username)
                    api_req = urllib.request.Request(api_url, headers=headers)
                    with urllib.request.urlopen(api_req, context=ctx, timeout=5) as api_resp:
                        api_data = json.loads(api_resp.read().decode())
                        result['name'] = api_data.get('name')
                        result['bio'] = api_data.get('bio')
                        result['followers'] = api_data.get('followers')
                        result['repos'] = api_data.get('public_repos')
                        result['location'] = api_data.get('location')
                        result['company'] = api_data.get('company')
                except:
                    pass

            return result

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'platform': platform, 'url': url, 'found': False}
        elif e.code in [403, 429]:
            return {'platform': platform, 'url': url, 'found': None, 'error': 'blocked'}
    except Exception as e:
        return {'platform': platform, 'url': url, 'found': None, 'error': str(e)[:30]}

    return None


def search_all_platforms(username, platforms=None, show_progress=True):
    """Search for username across all platforms"""
    results = []
    platforms_to_check = platforms or list(PLATFORMS.keys())

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_profile, p, username): p for p in platforms_to_check}

        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                results.append(result)

            if show_progress:
                done = i + 1
                total = len(platforms_to_check)
                pct = int((done / total) * 100)
                bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
                print(f"\r  [{bar}] {pct}%", end='', flush=True)

    if show_progress:
        print()

    return results


def generate_dorks(query, query_type='person'):
    """Generate search engine dorks"""
    dorks = []

    # Google dorks
    if query_type == 'person':
        dorks.extend([
            f'"{query}" site:linkedin.com',
            f'"{query}" site:twitter.com OR site:x.com',
            f'"{query}" site:facebook.com',
            f'"{query}" site:instagram.com',
            f'"{query}" site:github.com',
            f'intitle:"{query}" resume OR CV filetype:pdf',
            f'"{query}" email OR contact',
        ])
    else:  # company
        dorks.extend([
            f'site:{query}',
            f'"{query}" site:linkedin.com/company',
            f'"{query}" site:crunchbase.com',
            f'"{query}" employees site:linkedin.com',
            f'"{query}" inurl:about',
        ])

    return dorks


def analyze_name(name):
    """Analyze a name and generate username variations"""
    parts = name.lower().split()
    variations = []

    if len(parts) >= 2:
        first, last = parts[0], parts[-1]

        variations.extend([
            first + last,
            first + '.' + last,
            first + '_' + last,
            first[0] + last,
            first + last[0],
            last + first,
            last + '.' + first,
        ])

    if len(parts) == 1:
        variations.append(parts[0])

    return list(set(variations))


def display_results(query, results, dorks=None):
    """Display search results"""
    print(f"\n  {BOLD}Social Media Reconnaissance{RESET}")
    print(f"  {DIM}{'═' * 55}{RESET}\n")

    print(f"  {CYAN}Query:{RESET}  {query}")
    print()

    # Found profiles
    found = [r for r in results if r.get('found') == True]
    not_found = [r for r in results if r.get('found') == False]
    errors = [r for r in results if r.get('found') is None]

    print(f"  {GREEN}Found:{RESET} {len(found)} | {DIM}Not found:{RESET} {len(not_found)} | {YELLOW}Errors:{RESET} {len(errors)}")
    print()

    if found:
        print(f"  {BOLD}Profiles Found{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for r in found:
            print(f"  {GREEN}  {r['platform'].upper()}{RESET}")
            print(f"     {r['url']}")

            # Additional info
            if r.get('followers'):
                print(f"     {DIM}Followers: {r['followers']}{RESET}")
            if r.get('name'):
                print(f"     {DIM}Name: {r['name']}{RESET}")
            if r.get('bio'):
                print(f"     {DIM}Bio: {r['bio'][:50]}...{RESET}")
            if r.get('location'):
                print(f"     {DIM}Location: {r['location']}{RESET}")
            if r.get('company'):
                print(f"     {DIM}Company: {r['company']}{RESET}")
            if r.get('repos'):
                print(f"     {DIM}Public repos: {r['repos']}{RESET}")

            print()

    # Search dorks
    if dorks:
        print(f"  {BOLD}Search Engine Dorks{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for dork in dorks[:5]:
            encoded = urllib.parse.quote(dork)
            print(f"  {CYAN}Google:{RESET} {dork[:60]}")
            print(f"  {DIM}https://google.com/search?q={encoded[:40]}...{RESET}")
            print()


def main():
    parser = argparse.ArgumentParser(description='Social Media Reconnaissance')
    parser.add_argument('query', nargs='?', help='Username or name to search')
    parser.add_argument('--type', '-t', choices=['person', 'company'], default='person',
                       help='Query type')
    parser.add_argument('--username', '-u', action='store_true',
                       help='Treat query as exact username')
    parser.add_argument('--dorks', '-d', action='store_true', help='Generate search dorks')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Social Media Reconnaissance{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    query = args.query
    if not query:
        query = input(f"\n  {CYAN}Name or username to search:{RESET} ").strip()

    if not query:
        print(f"  {RED}Query required{RESET}")
        sys.exit(1)

    # Generate username variations if not exact username
    if args.username:
        usernames = [query]
    else:
        usernames = analyze_name(query)
        if not args.json:
            print(f"\n  {DIM}Username variations: {', '.join(usernames[:5])}{RESET}")

    if not args.json:
        print(f"\n  {DIM}Searching platforms...{RESET}\n")

    # Search for each variation
    all_results = []
    seen_urls = set()

    for username in usernames[:3]:  # Limit variations
        results = search_all_platforms(username, show_progress=not args.json)
        for r in results:
            if r.get('url') not in seen_urls:
                seen_urls.add(r.get('url'))
                r['searched_username'] = username
                all_results.append(r)

    # Generate dorks
    dorks = generate_dorks(query, args.type) if args.dorks else None

    if args.json:
        output = {
            'query': query,
            'type': args.type,
            'username_variations': usernames,
            'results': all_results,
            'dorks': dorks
        }
        print(json.dumps(output, indent=2))
    else:
        display_results(query, all_results, dorks)


if __name__ == '__main__':
    main()
