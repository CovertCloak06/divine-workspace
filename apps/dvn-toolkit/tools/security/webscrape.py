#!/usr/bin/env python3
"""
Web Scraper - Extract data from websites
Usage: webscrape <url> [--links] [--emails] [--images] [--text] [--forms]
"""

import re
import ssl
import argparse
from urllib.request import urlopen, Request
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


class PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.images = set()
        self.scripts = set()
        self.styles = set()
        self.forms = []
        self.emails = set()
        self.text_content = []
        self.meta = {}
        self.title = ''

        self._in_title = False
        self._in_script = False
        self._in_style = False
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == 'a' and 'href' in attrs:
            href = attrs['href']
            if not href.startswith(('javascript:', 'mailto:', '#')):
                self.links.add(urljoin(self.base_url, href))
            if href.startswith('mailto:'):
                email = href.replace('mailto:', '').split('?')[0]
                self.emails.add(email)

        elif tag == 'img' and 'src' in attrs:
            self.images.add(urljoin(self.base_url, attrs['src']))

        elif tag == 'script' and 'src' in attrs:
            self.scripts.add(urljoin(self.base_url, attrs['src']))
            self._in_script = True

        elif tag == 'link' and attrs.get('rel') == 'stylesheet':
            if 'href' in attrs:
                self.styles.add(urljoin(self.base_url, attrs['href']))

        elif tag == 'meta':
            name = attrs.get('name', attrs.get('property', ''))
            content = attrs.get('content', '')
            if name and content:
                self.meta[name] = content

        elif tag == 'title':
            self._in_title = True

        elif tag == 'style':
            self._in_style = True

        elif tag == 'form':
            self._current_form = {
                'action': urljoin(self.base_url, attrs.get('action', '')),
                'method': attrs.get('method', 'GET').upper(),
                'inputs': []
            }

        elif tag == 'input' and self._current_form:
            self._current_form['inputs'].append({
                'name': attrs.get('name', ''),
                'type': attrs.get('type', 'text'),
                'value': attrs.get('value', '')
            })

    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False
        elif tag == 'script':
            self._in_script = False
        elif tag == 'style':
            self._in_style = False
        elif tag == 'form' and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._in_script and not self._in_style:
            text = data.strip()
            if text:
                self.text_content.append(text)

                # Find emails in text
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                self.emails.update(emails)


def fetch_page(url):
    """Fetch page content"""
    if not url.startswith('http'):
        url = 'https://' + url

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
        })

        with urlopen(req, timeout=15, context=ctx) as resp:
            return resp.read().decode('utf-8', errors='replace'), resp.url
    except Exception as e:
        return None, str(e)


def categorize_links(links, base_domain):
    """Separate internal and external links"""
    internal = set()
    external = set()

    for link in links:
        parsed = urlparse(link)
        if parsed.netloc == base_domain or not parsed.netloc:
            internal.add(link)
        else:
            external.add(link)

    return internal, external


def main():
    parser = argparse.ArgumentParser(description='Web Scraper')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--links', '-l', action='store_true', help='Extract links')
    parser.add_argument('--emails', '-e', action='store_true', help='Extract emails')
    parser.add_argument('--images', '-i', action='store_true', help='Extract images')
    parser.add_argument('--text', '-t', action='store_true', help='Extract text content')
    parser.add_argument('--forms', '-f', action='store_true', help='Extract forms')
    parser.add_argument('--all', '-a', action='store_true', help='Extract everything')
    parser.add_argument('--output', '-o', help='Save output to file')
    args = parser.parse_args()

    # Default to all if nothing specified
    if not any([args.links, args.emails, args.images, args.text, args.forms, args.all]):
        args.all = True

    print(f"\n{BOLD}{CYAN}Web Scraper{RESET}")
    print(f"Target: {args.url}\n")

    html, final_url = fetch_page(args.url)
    if not html:
        print(f"{RED}Error: {final_url}{RESET}")
        return

    base_domain = urlparse(final_url).netloc

    # Parse
    parser_obj = PageParser(final_url)
    try:
        parser_obj.feed(html)
    except:
        pass

    output = []

    # Title and meta
    if parser_obj.title:
        print(f"{BOLD}Title:{RESET} {parser_obj.title.strip()}")
        output.append(f"Title: {parser_obj.title.strip()}")

    if parser_obj.meta.get('description'):
        desc = parser_obj.meta['description'][:100]
        print(f"{BOLD}Description:{RESET} {desc}...")
        output.append(f"Description: {parser_obj.meta['description']}")

    print()

    # Links
    if args.links or args.all:
        internal, external = categorize_links(parser_obj.links, base_domain)

        print(f"{BOLD}Links ({len(parser_obj.links)} total){RESET}")
        print(f"  {GREEN}Internal: {len(internal)}{RESET}")
        print(f"  {YELLOW}External: {len(external)}{RESET}")

        if internal:
            output.append(f"\n=== Internal Links ({len(internal)}) ===")
            print(f"\n  {CYAN}Internal:{RESET}")
            for link in sorted(internal)[:20]:
                print(f"    {link}")
                output.append(link)
            if len(internal) > 20:
                print(f"    {DIM}... and {len(internal) - 20} more{RESET}")

        if external:
            output.append(f"\n=== External Links ({len(external)}) ===")
            print(f"\n  {CYAN}External:{RESET}")
            for link in sorted(external)[:15]:
                print(f"    {link}")
                output.append(link)
            if len(external) > 15:
                print(f"    {DIM}... and {len(external) - 15} more{RESET}")

        print()

    # Emails
    if args.emails or args.all:
        if parser_obj.emails:
            print(f"{BOLD}Emails Found ({len(parser_obj.emails)}){RESET}")
            output.append(f"\n=== Emails ({len(parser_obj.emails)}) ===")
            for email in sorted(parser_obj.emails):
                print(f"  {GREEN}{email}{RESET}")
                output.append(email)
            print()

    # Images
    if args.images or args.all:
        if parser_obj.images:
            print(f"{BOLD}Images ({len(parser_obj.images)}){RESET}")
            output.append(f"\n=== Images ({len(parser_obj.images)}) ===")
            for img in sorted(parser_obj.images)[:20]:
                print(f"  {img}")
                output.append(img)
            if len(parser_obj.images) > 20:
                print(f"  {DIM}... and {len(parser_obj.images) - 20} more{RESET}")
            print()

    # Forms
    if args.forms or args.all:
        if parser_obj.forms:
            print(f"{BOLD}Forms ({len(parser_obj.forms)}){RESET}")
            output.append(f"\n=== Forms ({len(parser_obj.forms)}) ===")
            for i, form in enumerate(parser_obj.forms):
                print(f"\n  {CYAN}Form {i+1}:{RESET}")
                print(f"    Action: {form['action']}")
                print(f"    Method: {form['method']}")
                output.append(f"\nForm {i+1}: {form['method']} {form['action']}")
                if form['inputs']:
                    print(f"    Inputs:")
                    for inp in form['inputs']:
                        print(f"      - {inp['name']} ({inp['type']})")
                        output.append(f"  - {inp['name']} ({inp['type']})")
            print()

    # Text content
    if args.text or args.all:
        text = ' '.join(parser_obj.text_content)
        words = text.split()
        print(f"{BOLD}Text Content:{RESET} {len(words)} words")
        if args.text:  # Only show full text if explicitly requested
            print(f"\n{text[:2000]}...")
            output.append(f"\n=== Text Content ===\n{text}")

    # Scripts and styles
    if args.all:
        if parser_obj.scripts:
            print(f"\n{BOLD}Scripts ({len(parser_obj.scripts)}){RESET}")
            for script in sorted(parser_obj.scripts)[:10]:
                print(f"  {script}")

        if parser_obj.styles:
            print(f"\n{BOLD}Stylesheets ({len(parser_obj.styles)}){RESET}")
            for style in sorted(parser_obj.styles)[:10]:
                print(f"  {style}")

    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            f.write('\n'.join(output))
        print(f"\n{DIM}Saved to: {args.output}{RESET}")

    print()


if __name__ == '__main__':
    main()
