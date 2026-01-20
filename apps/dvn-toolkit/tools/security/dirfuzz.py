#!/usr/bin/env python3
"""
Directory Fuzzer - Web directory/file enumeration
Usage: dirfuzz <url> [--wordlist common.txt] [--extensions php,html] [--threads 20]
"""

import argparse
import concurrent.futures
import urllib.request
import urllib.error
import ssl
import time
from urllib.parse import urljoin

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common paths to check
COMMON_PATHS = [
    '', 'admin', 'login', 'dashboard', 'wp-admin', 'administrator', 'phpmyadmin',
    'cpanel', 'webmail', 'api', 'v1', 'v2', 'docs', 'swagger', 'graphql',
    'robots.txt', 'sitemap.xml', '.htaccess', '.git', '.git/config', '.git/HEAD',
    '.env', '.env.local', '.env.production', 'config', 'config.php', 'config.json',
    'wp-config.php', 'configuration.php', 'settings.py', 'database.yml',
    'backup', 'backups', 'dump', 'dump.sql', 'database.sql', 'db.sql',
    'uploads', 'upload', 'files', 'images', 'img', 'static', 'assets', 'media',
    'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'debug.log', 'error.log',
    'test', 'tests', 'testing', 'dev', 'development', 'staging', 'stage',
    'old', 'backup', 'bak', 'orig', 'copy', 'archive', '~', 'src', 'source',
    'include', 'includes', 'inc', 'lib', 'libs', 'vendor', 'node_modules',
    'composer.json', 'package.json', 'Gemfile', 'requirements.txt', 'Makefile',
    'readme', 'README', 'README.md', 'readme.txt', 'CHANGELOG', 'LICENSE',
    'server-status', 'server-info', 'status', 'health', 'healthcheck', 'ping',
    'info.php', 'phpinfo.php', 'test.php', 'info', 'version', '.well-known',
    'cgi-bin', 'scripts', 'bin', 'shell', 'cmd', 'command', 'exec', 'run',
    'user', 'users', 'account', 'accounts', 'profile', 'profiles', 'member',
    'register', 'signup', 'signin', 'logout', 'auth', 'oauth', 'token',
    'forgot', 'reset', 'password', 'recover', 'verify', 'confirm', 'activate',
    'download', 'export', 'import', 'report', 'reports', 'analytics', 'stats',
    'search', 'find', 'query', 'filter', 'sort', 'order', 'list', 'view',
    'create', 'add', 'new', 'edit', 'update', 'modify', 'delete', 'remove',
    'console', 'terminal', 'shell', 'ssh', 'ftp', 'sftp', 'telnet',
    'jenkins', 'travis', 'circleci', 'gitlab-ci', 'Jenkinsfile', '.gitlab-ci.yml',
    '.travis.yml', 'docker-compose.yml', 'Dockerfile', 'kubernetes', 'k8s'
]

STATUS_COLORS = {
    200: GREEN,
    201: GREEN,
    301: YELLOW,
    302: YELLOW,
    307: YELLOW,
    308: YELLOW,
    401: RED,
    403: RED,
    404: DIM,
    500: RED,
}

def check_path(base_url, path, timeout=5):
    """Check if a path exists"""
    url = urljoin(base_url, path)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                'Accept': '*/*'
            },
            method='GET'
        )

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            size = len(resp.read())
            return (url, resp.status, size, resp.headers.get('Content-Type', ''))

    except urllib.error.HTTPError as e:
        return (url, e.code, 0, '')
    except Exception:
        return None

def fuzz_directory(base_url, paths, extensions=None, threads=20, timeout=5, show_all=False):
    """Fuzz directories and files"""
    results = []

    # Generate full path list with extensions
    full_paths = set(paths)
    if extensions:
        for path in paths:
            if not any(path.endswith(f'.{ext}') for ext in extensions):
                for ext in extensions:
                    full_paths.add(f"{path}.{ext}")

    total = len(full_paths)
    checked = 0
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_path, base_url, path, timeout): path
            for path in full_paths
        }

        for future in concurrent.futures.as_completed(futures):
            checked += 1
            result = future.result()

            if result:
                url, status, size, content_type = result
                color = STATUS_COLORS.get(status, RESET)

                # Show non-404 results (or all if requested)
                if status != 404 or show_all:
                    results.append(result)
                    size_str = f"{size}B" if size < 1024 else f"{size//1024}KB"
                    print(f"  {color}[{status}]{RESET} {url} ({size_str})")

            # Progress
            if checked % 50 == 0:
                elapsed = time.time() - start_time
                rate = checked / elapsed if elapsed > 0 else 0
                print(f"\r{DIM}  Progress: {checked}/{total} ({rate:.0f}/s){RESET}", end='', flush=True)

    print(f"\r{' '*60}\r", end='')  # Clear progress line
    return results

def main():
    parser = argparse.ArgumentParser(description='Directory Fuzzer')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--wordlist', '-w', help='Custom wordlist file')
    parser.add_argument('--extensions', '-x', help='File extensions to check (comma-separated)')
    parser.add_argument('--threads', '-t', type=int, default=20, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout')
    parser.add_argument('--all', '-a', action='store_true', help='Show all responses including 404')
    parser.add_argument('--output', '-o', help='Output file')
    args = parser.parse_args()

    # Normalize URL
    url = args.url
    if not url.startswith('http'):
        url = f'https://{url}'
    if not url.endswith('/'):
        url += '/'

    # Load wordlist
    paths = COMMON_PATHS.copy()
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                custom = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                paths = list(set(paths + custom))
        except Exception as e:
            print(f"{RED}Error loading wordlist: {e}{RESET}")

    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [ext.strip().lstrip('.') for ext in args.extensions.split(',')]

    print(f"\n{BOLD}{CYAN}Directory Fuzzer{RESET}")
    print(f"Target: {url}")
    print(f"Paths: {len(paths)}")
    if extensions:
        print(f"Extensions: {', '.join(extensions)}")
    print(f"Threads: {args.threads}\n")

    print(f"{BOLD}[*] Starting scan...{RESET}")
    results = fuzz_directory(url, paths, extensions, args.threads, args.timeout, args.all)

    # Summary
    print(f"\n{BOLD}{'='*50}{RESET}")
    found = [r for r in results if r[1] != 404]
    print(f"{GREEN}Found {len(found)} interesting paths{RESET}\n")

    # Group by status
    by_status = {}
    for url, status, size, ctype in found:
        by_status.setdefault(status, []).append((url, size, ctype))

    for status in sorted(by_status.keys()):
        color = STATUS_COLORS.get(status, RESET)
        print(f"{color}{BOLD}[{status}]{RESET}")
        for url, size, ctype in by_status[status]:
            print(f"  {url}")

    # Output to file
    if args.output:
        with open(args.output, 'w') as f:
            for url, status, size, ctype in found:
                f.write(f"{status}\t{url}\t{size}\t{ctype}\n")
        print(f"\n{DIM}Results saved to: {args.output}{RESET}")

    print()

if __name__ == '__main__':
    main()
