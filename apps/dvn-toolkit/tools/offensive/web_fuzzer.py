#!/usr/bin/env python3
"""
Web Fuzzer - Directory and File Enumeration
Discovers hidden directories, files, and endpoints
For authorized security testing only

QUICK START:
    ./web_fuzzer.py -u http://target.com
    ./web_fuzzer.py -u http://target.com -w wordlist.txt
    ./web_fuzzer.py -u http://target.com -x php,html,txt
"""

import argparse
import sys
import urllib.request
import urllib.parse
import ssl
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
from queue import Queue

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    E = '\033[0m'

# Built-in wordlist (common paths)
BUILTIN_WORDLIST = [
    # Common directories
    'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php', 'dashboard',
    'panel', 'cpanel', 'admin.php', 'adminpanel', 'admin_area', 'admin-login',
    'user', 'users', 'member', 'members', 'account', 'accounts', 'profile',
    'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs', 'api-docs',
    'config', 'configuration', 'conf', 'settings', 'setup', 'install',
    'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test', 'testing', 'dev',
    'uploads', 'upload', 'files', 'file', 'media', 'images', 'img', 'assets',
    'css', 'js', 'javascript', 'scripts', 'static', 'public', 'private',
    'includes', 'include', 'inc', 'lib', 'libs', 'library', 'vendor', 'plugins',
    'data', 'database', 'db', 'sql', 'mysql', 'phpmyadmin', 'pma', 'adminer',
    'logs', 'log', 'error', 'errors', 'debug', 'trace',
    'cgi-bin', 'cgi', 'bin', 'scripts', 'shell', 'cmd',
    '.git', '.svn', '.htaccess', '.htpasswd', '.env', '.config',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'security.txt',
    'readme', 'README', 'readme.txt', 'README.md', 'CHANGELOG', 'LICENSE',
    'server-status', 'server-info', 'status', 'info', 'phpinfo', 'info.php',
    'web.config', 'web.xml', 'application.xml', 'beans.xml',
    'console', 'manager', 'webadmin', 'sysadmin', 'root',
    'portal', 'intranet', 'internal', 'secure', 'protected',
    'download', 'downloads', 'export', 'import', 'report', 'reports',
    'search', 'query', 'find', 'browse', 'view', 'show',
    'register', 'signup', 'signin', 'logout', 'forgot', 'reset', 'password',
    'blog', 'news', 'article', 'articles', 'post', 'posts', 'page', 'pages',
    'home', 'index', 'main', 'default', 'welcome',
    'contact', 'about', 'help', 'support', 'faq',
    'shop', 'store', 'cart', 'checkout', 'order', 'orders', 'payment',
    'forum', 'community', 'discuss', 'chat', 'message', 'messages',
    'health', 'healthcheck', 'ping', 'version', 'build',
]

HELP_TEXT = """
================================================================================
                    WEB FUZZER - COMPREHENSIVE GUIDE
                    Directory and Content Discovery
================================================================================

WHAT IS WEB FUZZING?
--------------------
Web fuzzing (also called directory busting or content discovery) is the process
of finding hidden files, directories, and endpoints on a web server by trying
thousands of common paths. It's like checking if http://target.com/admin exists,
then /backup, then /config... except automated and thorough.

WHY THIS MATTERS: Web servers often have sensitive content that isn't linked
anywhere - admin panels, backup files, configuration files, test pages, and
API endpoints. These hidden resources frequently contain vulnerabilities or
sensitive information that wasn't meant to be publicly accessible.


UNDERSTANDING HTTP RESPONSES
----------------------------
When you request a URL, the server responds with a status code. Understanding
these is CRITICAL for interpreting fuzzer results:

200 OK - Success
  The path exists and you can access it.
  THIS IS WHAT YOU'RE LOOKING FOR.
  → Investigate the content immediately

301/302 Redirect
  The path exists but redirects somewhere else.
  Follow the redirect - might lead somewhere interesting.
  → Check where it redirects, might be login-protected content

403 Forbidden
  THE PATH EXISTS but you're not allowed to access it.
  This is actually VALUABLE information!
  → The resource is there, just protected
  → Try bypasses: adding / at end, encoding, different HTTP methods
  → May indicate admin area or sensitive content

401 Unauthorized
  Resource exists but requires authentication.
  → Candidate for bruteforce or credential testing
  → Check what auth type (Basic, Bearer, etc.)

404 Not Found
  Path doesn't exist.
  → Usually filter these out with --hide-status 404

500 Internal Server Error
  Your request broke something on the server!
  → Potential vulnerability - server can't handle this input
  → Investigate what's special about this path

503 Service Unavailable
  Server is overloaded or you're being rate limited.
  → Reduce threads with -t
  → Add --delay


THE ART OF WORDLIST SELECTION
-----------------------------
Your wordlist is your dictionary of paths to try. Choosing the right one
is the difference between finding gold and finding nothing.

BUILT-IN WORDLIST (Default)
  Contains ~100 common paths. Good for quick initial scan.
  Paths like: admin, backup, config, api, .git, .env, etc.
  USE WHEN: Initial recon, quick check

SMALL TARGETED (100-1000 words)
  - /usr/share/seclists/Discovery/Web-Content/common.txt
  - Create your own based on target technology
  USE WHEN: Time-limited, focused testing

MEDIUM GENERAL (1000-10000 words)
  - /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
  - /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
  USE WHEN: Standard assessment, reasonable thoroughness

LARGE COMPREHENSIVE (10000+ words)
  - /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
  - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  USE WHEN: Thorough assessment, have time to spare

SPECIALIZED WORDLISTS
  - API endpoints: /usr/share/seclists/Discovery/Web-Content/api/
  - Backup files: /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
  - Config files: /usr/share/seclists/Discovery/Web-Content/Common-Configs.txt
  - CMS-specific: wordpress.txt, drupal.txt, joomla.txt


EXTENSION STRATEGY
------------------
The -x flag adds file extensions to every word in your wordlist.
This MULTIPLIES your scan size, so choose wisely.

EXAMPLE: wordlist has "config", extensions are "php,bak,txt"
  Tests: /config, /config.php, /config.bak, /config.txt

COMMON EXTENSION SETS BY TECHNOLOGY:

PHP Application:
  -x php,php.bak,php~,phps,phtml,inc

ASP.NET Application:
  -x aspx,asp,config,ashx,asmx,dll

Java Application:
  -x jsp,do,action,jsf,faces,xml

Python Application:
  -x py,pyc

Backup/Sensitive:
  -x bak,backup,old,orig,save,swp,~,txt,sql,zip,tar.gz

General Web:
  -x html,htm,js,css,json,xml,txt


WHAT TO DO WITH DIFFERENT FINDINGS
----------------------------------

FINDING: Admin panel (/admin, /dashboard, /wp-admin)
  1. Screenshot it
  2. Check for login bypass vulnerabilities
  3. Try default credentials
  4. Add to bruteforce target list
  5. Check for version disclosure

FINDING: Backup files (.bak, .old, .sql)
  1. Download immediately
  2. Search for credentials
  3. Look for database dumps
  4. Check for source code disclosure
  5. Compare to production files

FINDING: Configuration files (.env, .config, web.config)
  1. Download and analyze
  2. Extract any credentials
  3. Look for API keys
  4. Check database connection strings
  5. Identify internal hostnames/IPs

FINDING: Source control (.git, .svn, .hg)
  1. Try to download repository
  2. .git/config - shows repo URL
  3. .git/HEAD - current branch
  4. Tools like git-dumper can extract full repo
  5. Major finding - potentially full source code

FINDING: API endpoints (/api/v1/, /rest/, /graphql)
  1. Document the endpoint structure
  2. Try different HTTP methods (GET, POST, PUT, DELETE)
  3. Look for documentation (/api/docs, /swagger)
  4. Test for authentication bypass
  5. Check for IDOR vulnerabilities

FINDING: Debug/Test pages (/phpinfo.php, /test, /debug)
  1. Check what information is disclosed
  2. Look for server paths
  3. Note installed modules
  4. Document for report
  5. Can reveal internal configuration


SCENARIO-BASED USAGE
--------------------

SCENARIO: Initial reconnaissance on unknown web server
COMMAND:  ./web_fuzzer.py -u http://target.com --hide-status 404
WHY:      Using built-in wordlist for quick coverage
          Hiding 404s reduces noise, focuses on what exists
NEXT:     Review all findings, then use larger wordlist on interesting paths
          If you found /api/, fuzz http://target.com/api/ separately


SCENARIO: PHP application identified
COMMAND:  ./web_fuzzer.py -u http://target.com -x php,php.bak,inc,txt \\
              -w /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt
WHY:      PHP-specific wordlist and extensions
          .bak files might contain source code
          .inc files often have sensitive includes
NEXT:     Download any exposed PHP source code
          Look for config files with database credentials


SCENARIO: Looking for backup files specifically
COMMAND:  ./web_fuzzer.py -u http://target.com \\
              -x bak,backup,old,orig,sql,zip,tar,tar.gz \\
              --show-status 200
WHY:      Focus only on backup extensions
          Only show 200 (we want downloadable files)
NEXT:     Download everything found
          Extract and analyze for credentials


SCENARIO: Fuzzing behind authentication
COMMAND:  ./web_fuzzer.py -u http://target.com/internal \\
              --cookie "session=abc123" -H "Authorization: Bearer token"
WHY:      You have valid session - use it to discover authenticated content
          Different content appears when logged in
NEXT:     Compare to unauthenticated scan
          Look for privilege escalation paths


SCENARIO: API endpoint discovery
COMMAND:  ./web_fuzzer.py -u http://target.com/api/v1 \\
              -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt \\
              --hide-status 404,405
WHY:      API-specific wordlist
          Hiding 404 and 405 (method not allowed)
NEXT:     Test each endpoint with different HTTP methods
          Look for IDOR, auth bypass


SCENARIO: Slow target, avoid detection
COMMAND:  ./web_fuzzer.py -u http://target.com -t 5 \\
              --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \\
              -w small-wordlist.txt
WHY:      Low thread count to avoid rate limiting
          Normal user-agent to blend in
          Small wordlist for less requests
NEXT:     Gradually increase if no issues
          Monitor for IP blocks


INTERPRETING RESPONSE SIZES
---------------------------
Response size (bytes) tells you about content:

SAME SIZE FOR EVERYTHING
  Usually means custom 404 page
  Filter by size to find real content

TINY SIZE (0-100 bytes)
  Empty response, redirect, or simple error

MEDIUM SIZE (100-5000 bytes)
  Typical web page or API response
  Worth investigating

LARGE SIZE (5000+ bytes)
  Substantial content
  Could be data dump, documentation, or full page


AVOIDING DETECTION
------------------

RATE LIMITING
  Problem: Server blocks you after too many requests
  Solution: -t 10 or lower, consider using --proxy

WAF (Web Application Firewall)
  Problem: Firewall blocks scanning patterns
  Solution: Custom user-agent, lower thread count, vary timing

IP BLOCKING
  Problem: Your IP gets blacklisted
  Solution: Use proxy or VPN, reduce speed

CUSTOM 404 HANDLING
  Problem: Server returns 200 for everything with "not found" in body
  Solution: Note response sizes, filter by size


COMMON MISTAKES TO AVOID
------------------------
1. Not filtering 404s (drowns real findings in noise)
2. Wrong extensions for target technology
3. Too many threads causing blocks/errors
4. Using huge wordlist without trying small one first
5. Not following up on 403s (they mean something exists!)
6. Ignoring response sizes (can indicate custom 404s)


COMMAND REFERENCE
-----------------
TARGET:
  -u, --url URL          Base URL to fuzz

WORDLIST:
  -w, --wordlist FILE    Custom wordlist (default: built-in)
  -x, --extensions LIST  Extensions to append (php,html,txt)

FILTERING:
  --hide-status LIST     Hide these status codes (404,403)
  --show-status LIST     Only show these codes (200,301)

PERFORMANCE:
  -t, --threads NUM      Concurrent requests (default: 50)
  --timeout SEC          Request timeout (default: 10)

REQUEST OPTIONS:
  -H, --header "K: V"    Add custom header (can repeat)
  --cookie "a=b"         Send cookies
  --user-agent STRING    Custom User-Agent
  --proxy URL            Route through proxy

OUTPUT:
  -o, --output FILE      Save results to file
  -q, --quiet            Minimal output


WORDLIST LOCATIONS
------------------
Kali Linux / SecLists:
  /usr/share/seclists/Discovery/Web-Content/
  /usr/share/wordlists/dirbuster/
  /usr/share/wordlists/dirb/

Custom:
  Create based on target technology and naming conventions
================================================================================
"""

def banner():
    print(f"""{C.C}
 _    _      _       ______
| |  | |    | |     |  ____|
| |  | | ___| |__   | |__ _   _ __________ _ __
| |/\\| |/ _ \\ '_ \\  |  __| | | |_  /_  / _ \\ '__|
\\  /\\  /  __/ |_) | | |  | |_| |/ / / /  __/ |
 \\/  \\/ \\___|_.__/  |_|   \\__,_/___/___\\___|_|
{C.E}{C.Y}Directory & File Enumerator{C.E}
""")

class WebFuzzer:
    def __init__(self, base_url: str, threads: int = 50, timeout: int = 10,
                 user_agent: str = None, proxy: str = None, cookies: str = None,
                 headers: Dict = None):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (X11; Linux x86_64) Fuzzer/1.0'
        self.proxy = proxy
        self.cookies = cookies
        self.headers = headers or {}
        self.results = []
        self.lock = threading.Lock()
        self.scanned = 0
        self.total = 0

        # SSL context
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def make_request(self, url: str) -> Tuple[int, int, str]:
        """Make HTTP request, return (status, size, redirect)"""
        try:
            req_headers = {'User-Agent': self.user_agent}
            req_headers.update(self.headers)

            if self.cookies:
                req_headers['Cookie'] = self.cookies

            req = urllib.request.Request(url, headers=req_headers)

            if self.proxy:
                proxy_handler = urllib.request.ProxyHandler({
                    'http': self.proxy, 'https': self.proxy
                })
                opener = urllib.request.build_opener(
                    proxy_handler,
                    urllib.request.HTTPSHandler(context=self.ssl_ctx)
                )
            else:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=self.ssl_ctx)
                )

            response = opener.open(req, timeout=self.timeout)
            content = response.read()
            return response.status, len(content), response.url

        except urllib.error.HTTPError as e:
            try:
                content = e.read()
                return e.code, len(content), ''
            except:
                return e.code, 0, ''
        except Exception:
            return 0, 0, ''

    def fuzz_path(self, path: str, hide_status: List[int] = None,
                  show_status: List[int] = None) -> Dict:
        """Fuzz a single path"""
        url = f"{self.base_url}/{path}"
        status, size, redirect = self.make_request(url)

        with self.lock:
            self.scanned += 1

        # Filter results
        if hide_status and status in hide_status:
            return None
        if show_status and status not in show_status:
            return None
        if status == 0:
            return None

        result = {
            'path': path,
            'url': url,
            'status': status,
            'size': size,
            'redirect': redirect if redirect and redirect != url else ''
        }

        return result

    def fuzz(self, wordlist: List[str], extensions: List[str] = None,
             hide_status: List[int] = None, show_status: List[int] = None,
             quiet: bool = False) -> List[Dict]:
        """Run fuzzing scan"""
        paths = []

        # Build paths with extensions
        for word in wordlist:
            word = word.strip()
            if not word or word.startswith('#'):
                continue

            paths.append(word)

            if extensions:
                for ext in extensions:
                    paths.append(f"{word}.{ext}")

        self.total = len(paths)
        self.scanned = 0
        self.results = []

        print(f"{C.B}[*]{C.E} Fuzzing {self.total} paths with {self.threads} threads...")
        print(f"{C.B}[*]{C.E} Target: {self.base_url}")
        print()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.fuzz_path, path, hide_status, show_status): path
                for path in paths
            }

            for future in as_completed(futures):
                result = future.result()

                if result:
                    self.results.append(result)

                    # Color based on status
                    status = result['status']
                    if status == 200:
                        color = C.G
                    elif status in [301, 302]:
                        color = C.C
                    elif status == 403:
                        color = C.Y
                    elif status >= 500:
                        color = C.R
                    else:
                        color = C.W

                    if not quiet:
                        line = f"{color}[{status}]{C.E} /{result['path']:40} [{result['size']} bytes]"
                        if result.get('redirect'):
                            line += f" → {result['redirect']}"
                        print(line)

                # Progress
                if not quiet and self.scanned % 100 == 0:
                    print(f"\r{C.B}[*]{C.E} Progress: {self.scanned}/{self.total}", end='')

        elapsed = time.time() - start_time
        print(f"\n\n{C.B}[*]{C.E} Completed in {elapsed:.1f}s")
        print(f"{C.B}[*]{C.E} Found {C.G}{len(self.results)}{C.E} results")

        return self.results

def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"{C.R}[!]{C.E} Failed to load wordlist: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description='Web Directory Fuzzer')
    parser.add_argument('-u', '--url', required=False, help='Target URL')
    parser.add_argument('-w', '--wordlist', help='Wordlist file')
    parser.add_argument('-x', '--extensions', help='Extensions (php,html,txt)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout')
    parser.add_argument('--hide-status', help='Hide status codes (404,403)')
    parser.add_argument('--show-status', help='Only show status codes (200,301)')
    parser.add_argument('-H', '--header', action='append', help='Custom header')
    parser.add_argument('--cookie', help='Cookies')
    parser.add_argument('--user-agent', help='User-Agent')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('--help-full', action='store_true', help='Detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    if not args.url:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed guide")
        return

    banner()

    # Load wordlist
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            return
        print(f"{C.B}[*]{C.E} Loaded {len(wordlist)} words from {args.wordlist}")
    else:
        wordlist = BUILTIN_WORDLIST
        print(f"{C.B}[*]{C.E} Using built-in wordlist ({len(wordlist)} words)")

    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [e.strip().lstrip('.') for e in args.extensions.split(',')]

    # Parse status filters
    hide_status = None
    show_status = None
    if args.hide_status:
        hide_status = [int(s) for s in args.hide_status.split(',')]
    if args.show_status:
        show_status = [int(s) for s in args.show_status.split(',')]

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                key, val = h.split(':', 1)
                headers[key.strip()] = val.strip()

    # Create fuzzer
    fuzzer = WebFuzzer(
        base_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        cookies=args.cookie,
        headers=headers
    )

    # Run scan
    results = fuzzer.fuzz(
        wordlist=wordlist,
        extensions=extensions,
        hide_status=hide_status,
        show_status=show_status,
        quiet=args.quiet
    )

    # Summary
    print(f"\n{C.B}{'='*60}{C.E}")
    print(f"{C.B}SUMMARY{C.E}")
    print(f"{C.B}{'='*60}{C.E}")

    status_counts = {}
    for r in results:
        status = r['status']
        status_counts[status] = status_counts.get(status, 0) + 1

    for status, count in sorted(status_counts.items()):
        print(f"  Status {status}: {count} results")

    # Save output
    if args.output and results:
        with open(args.output, 'w') as f:
            for r in sorted(results, key=lambda x: x['status']):
                line = f"[{r['status']}] {r['url']} [{r['size']}]"
                if r.get('redirect'):
                    line += f" -> {r['redirect']}"
                f.write(line + '\n')
        print(f"\n{C.B}[*]{C.E} Results saved to {args.output}")

if __name__ == '__main__':
    main()
