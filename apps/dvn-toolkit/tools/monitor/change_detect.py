#!/usr/bin/env python3
"""
Change Detector - Monitor websites for changes and get notified
Usage: change_detect.py <url> [--interval 300] [--selector 'div.content']
"""

import urllib.request
import urllib.error
import ssl
import hashlib
import time
import argparse
import os
import re
import json
import subprocess
import difflib
from datetime import datetime

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Storage for page states
CACHE_DIR = os.path.expanduser('~/.cache/change_detect')


def ensure_cache_dir():
    """Create cache directory if needed"""
    os.makedirs(CACHE_DIR, exist_ok=True)


def get_url_hash(url):
    """Create a safe filename from URL"""
    return hashlib.md5(url.encode()).hexdigest()


def fetch_page(url, timeout=30):
    """Fetch page content"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        content = response.read().decode('utf-8', errors='replace')
        return content, None
    except Exception as e:
        return None, str(e)


def extract_text(html):
    """Extract readable text from HTML"""
    # Remove scripts, styles
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    # Remove tags
    text = re.sub(r'<[^>]+>', ' ', html)

    # Clean whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()

    return text


def extract_selector(html, selector):
    """Basic CSS selector extraction"""
    # This is a simple implementation - real CSS selectors are complex
    # Supports: tag, .class, #id, tag.class

    pattern = None

    if selector.startswith('.'):
        # Class selector
        class_name = selector[1:]
        pattern = rf'<[^>]+class="[^"]*\b{class_name}\b[^"]*"[^>]*>(.*?)</\w+>'
    elif selector.startswith('#'):
        # ID selector
        id_name = selector[1:]
        pattern = rf'<[^>]+id="{id_name}"[^>]*>(.*?)</\w+>'
    else:
        # Tag selector (optionally with class)
        if '.' in selector:
            tag, class_name = selector.split('.', 1)
            pattern = rf'<{tag}[^>]+class="[^"]*\b{class_name}\b[^"]*"[^>]*>(.*?)</{tag}>'
        else:
            pattern = rf'<{selector}[^>]*>(.*?)</{selector}>'

    if pattern:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        return '\n'.join(matches)

    return html


def get_content_hash(content):
    """Get hash of content"""
    return hashlib.sha256(content.encode()).hexdigest()


def load_previous_state(url):
    """Load previous state from cache"""
    cache_file = os.path.join(CACHE_DIR, get_url_hash(url) + '.json')
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    return None


def save_state(url, content, hash_val):
    """Save current state to cache"""
    ensure_cache_dir()
    cache_file = os.path.join(CACHE_DIR, get_url_hash(url) + '.json')
    with open(cache_file, 'w') as f:
        json.dump({
            'url': url,
            'hash': hash_val,
            'content': content[:10000],  # Limit stored content
            'timestamp': datetime.now().isoformat()
        }, f)


def send_notification(title, message):
    """Send desktop notification"""
    try:
        subprocess.run(['notify-send', '-u', 'critical', title, message], timeout=5)
    except:
        pass


def show_diff(old_content, new_content):
    """Show diff between old and new content"""
    old_lines = old_content.split('\n')
    new_lines = new_content.split('\n')

    diff = difflib.unified_diff(old_lines, new_lines, lineterm='', n=3)

    print(f"\n  {BOLD}Changes detected:{RESET}")
    for line in list(diff)[:50]:  # Limit diff output
        if line.startswith('+') and not line.startswith('+++'):
            print(f"  {GREEN}{line}{RESET}")
        elif line.startswith('-') and not line.startswith('---'):
            print(f"  {RED}{line}{RESET}")
        elif line.startswith('@'):
            print(f"  {CYAN}{line}{RESET}")
        else:
            print(f"  {DIM}{line}{RESET}")


def check_url(url, selector=None):
    """Check URL for changes"""
    content, error = fetch_page(url)

    if error:
        return 'error', error, None

    # Apply selector if provided
    if selector:
        content = extract_selector(content, selector)

    # Extract text
    text = extract_text(content)
    current_hash = get_content_hash(text)

    # Load previous state
    previous = load_previous_state(url)

    if previous is None:
        # First check
        save_state(url, text, current_hash)
        return 'new', 'First check - baseline saved', text

    if previous['hash'] != current_hash:
        # Change detected!
        old_text = previous.get('content', '')
        save_state(url, text, current_hash)
        return 'changed', 'Content has changed!', (old_text, text)

    return 'unchanged', 'No changes', text


def main():
    parser = argparse.ArgumentParser(description='Change Detector')
    parser.add_argument('urls', nargs='*', help='URLs to monitor')
    parser.add_argument('--interval', '-i', type=int, default=300, help='Check interval in seconds')
    parser.add_argument('--selector', '-s', help='CSS selector to monitor specific element')
    parser.add_argument('--once', '-1', action='store_true', help='Check once and exit')
    parser.add_argument('--alert', '-a', action='store_true', help='Send notifications')
    parser.add_argument('--diff', '-d', action='store_true', help='Show diff on changes')
    parser.add_argument('--list', '-l', action='store_true', help='List monitored URLs')
    args = parser.parse_args()

    ensure_cache_dir()

    if args.list:
        print(f"\n{BOLD}Monitored URLs:{RESET}\n")
        for f in os.listdir(CACHE_DIR):
            if f.endswith('.json'):
                with open(os.path.join(CACHE_DIR, f)) as file:
                    data = json.load(file)
                    print(f"  {CYAN}{data['url']}{RESET}")
                    print(f"  {DIM}Last checked: {data['timestamp']}{RESET}\n")
        return

    if not args.urls:
        print(f"\n{YELLOW}No URLs specified{RESET}")
        print(f"{DIM}Usage: change_detect.py https://example.com{RESET}")
        print(f"{DIM}       change_detect.py https://site.com --selector 'div.price'{RESET}\n")
        return

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔄 Change Detector                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}URLs: {len(args.urls)}{RESET}")
    print(f"  {DIM}Interval: {args.interval}s{RESET}")
    if args.selector:
        print(f"  {DIM}Selector: {args.selector}{RESET}")
    print()

    try:
        check_num = 0
        while True:
            check_num += 1
            now = datetime.now().strftime('%H:%M:%S')
            print(f"  {DIM}[{now}] Check #{check_num}{RESET}")

            for url in args.urls:
                status, message, data = check_url(url, args.selector)

                short_url = url[:50] + '...' if len(url) > 53 else url

                if status == 'error':
                    print(f"  {RED}✗ ERROR{RESET} {short_url}")
                    print(f"    {DIM}{message}{RESET}")

                elif status == 'new':
                    print(f"  {CYAN}● NEW{RESET} {short_url}")
                    print(f"    {DIM}Baseline saved{RESET}")

                elif status == 'changed':
                    print(f"  {GREEN}★ CHANGED!{RESET} {short_url}")

                    if args.alert:
                        send_notification('Page Changed!', url)

                    if args.diff and isinstance(data, tuple):
                        show_diff(data[0], data[1])

                else:
                    print(f"  {DIM}○ unchanged{RESET} {short_url}")

            print()

            if args.once:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{CYAN}Monitor stopped.{RESET}\n")


if __name__ == '__main__':
    main()
