#!/usr/bin/env python3
"""
HTTP Header Security Analyzer - Check security headers
Usage: header_analyzer.py [url] [--full] [--json]
Analyzes security headers and gives recommendations
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
import ssl

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'name': 'HSTS',
        'desc': 'Forces HTTPS connections',
        'severity': 'high',
        'good_values': ['max-age=31536000', 'includeSubDomains'],
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
    },
    'Content-Security-Policy': {
        'name': 'CSP',
        'desc': 'Prevents XSS and injection attacks',
        'severity': 'high',
        'good_values': ["default-src 'self'"],
        'recommendation': "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
    },
    'X-Frame-Options': {
        'name': 'X-Frame-Options',
        'desc': 'Prevents clickjacking',
        'severity': 'medium',
        'good_values': ['DENY', 'SAMEORIGIN'],
        'recommendation': 'Add: X-Frame-Options: DENY'
    },
    'X-Content-Type-Options': {
        'name': 'X-Content-Type-Options',
        'desc': 'Prevents MIME sniffing',
        'severity': 'medium',
        'good_values': ['nosniff'],
        'recommendation': 'Add: X-Content-Type-Options: nosniff'
    },
    'X-XSS-Protection': {
        'name': 'X-XSS-Protection',
        'desc': 'Browser XSS filter (legacy)',
        'severity': 'low',
        'good_values': ['1; mode=block'],
        'recommendation': 'Add: X-XSS-Protection: 1; mode=block (Note: deprecated, use CSP instead)'
    },
    'Referrer-Policy': {
        'name': 'Referrer-Policy',
        'desc': 'Controls referrer information',
        'severity': 'medium',
        'good_values': ['no-referrer', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'],
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
        'name': 'Permissions-Policy',
        'desc': 'Controls browser features',
        'severity': 'medium',
        'good_values': [],
        'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
    },
    'Cross-Origin-Embedder-Policy': {
        'name': 'COEP',
        'desc': 'Controls cross-origin embedding',
        'severity': 'low',
        'good_values': ['require-corp'],
        'recommendation': 'Add: Cross-Origin-Embedder-Policy: require-corp'
    },
    'Cross-Origin-Opener-Policy': {
        'name': 'COOP',
        'desc': 'Isolates browsing context',
        'severity': 'low',
        'good_values': ['same-origin'],
        'recommendation': 'Add: Cross-Origin-Opener-Policy: same-origin'
    },
    'Cross-Origin-Resource-Policy': {
        'name': 'CORP',
        'desc': 'Controls resource sharing',
        'severity': 'low',
        'good_values': ['same-origin', 'same-site'],
        'recommendation': 'Add: Cross-Origin-Resource-Policy: same-origin'
    },
}

# Headers that might leak info
INFO_LEAK_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

# Cookie security attributes
COOKIE_ATTRS = ['Secure', 'HttpOnly', 'SameSite']


def fetch_headers(url):
    """Fetch headers from URL"""
    if not url.startswith('http'):
        url = 'https://' + url

    # Create SSL context that doesn't verify (for testing)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 Security-Analyzer/1.0'})

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            return dict(response.headers), response.geturl(), response.status
    except urllib.error.HTTPError as e:
        return dict(e.headers), url, e.code
    except Exception as e:
        return None, url, str(e)


def analyze_security_headers(headers):
    """Analyze security headers"""
    results = []

    for header, config in SECURITY_HEADERS.items():
        value = headers.get(header)

        result = {
            'header': header,
            'name': config['name'],
            'description': config['desc'],
            'severity': config['severity'],
            'present': value is not None,
            'value': value,
            'recommendation': config['recommendation'] if not value else None
        }

        # Check if value is good
        if value:
            result['good'] = any(gv.lower() in value.lower() for gv in config['good_values']) if config['good_values'] else True
        else:
            result['good'] = False

        results.append(result)

    return results


def analyze_info_leaks(headers):
    """Check for information leakage headers"""
    leaks = []
    for header in INFO_LEAK_HEADERS:
        value = headers.get(header)
        if value:
            leaks.append({'header': header, 'value': value})
    return leaks


def analyze_cookies(headers):
    """Analyze cookie security"""
    cookies = []

    # Check Set-Cookie headers
    cookie_header = headers.get('Set-Cookie', '')
    if cookie_header:
        for cookie in cookie_header.split(','):
            cookie = cookie.strip()
            if not cookie:
                continue

            name = cookie.split('=')[0] if '=' in cookie else cookie.split(';')[0]

            cookie_info = {
                'name': name,
                'secure': 'Secure' in cookie,
                'httponly': 'HttpOnly' in cookie,
                'samesite': 'SameSite' in cookie,
            }

            # Check SameSite value
            if 'SameSite=Strict' in cookie:
                cookie_info['samesite_value'] = 'Strict'
            elif 'SameSite=Lax' in cookie:
                cookie_info['samesite_value'] = 'Lax'
            elif 'SameSite=None' in cookie:
                cookie_info['samesite_value'] = 'None'

            cookies.append(cookie_info)

    return cookies


def calculate_score(security_results, info_leaks):
    """Calculate security score"""
    score = 100

    # Deduct for missing security headers
    for result in security_results:
        if not result['present']:
            if result['severity'] == 'high':
                score -= 15
            elif result['severity'] == 'medium':
                score -= 10
            else:
                score -= 5
        elif not result['good']:
            score -= 5

    # Deduct for info leaks
    score -= len(info_leaks) * 5

    return max(0, score)


def get_grade(score):
    """Convert score to letter grade"""
    if score >= 90:
        return 'A', GREEN
    elif score >= 80:
        return 'B', GREEN
    elif score >= 70:
        return 'C', YELLOW
    elif score >= 60:
        return 'D', YELLOW
    else:
        return 'F', RED


def display_results(url, status, security_results, info_leaks, cookies, show_full=False):
    """Display analysis results"""
    print(f"\n  {BOLD}Header Security Analysis{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}\n")

    print(f"  {CYAN}URL:{RESET}     {url}")
    print(f"  {CYAN}Status:{RESET}  {status}")

    # Calculate and show score
    score = calculate_score(security_results, info_leaks)
    grade, color = get_grade(score)
    print(f"  {CYAN}Score:{RESET}   {color}{score}/100 (Grade: {grade}){RESET}")
    print()

    # Security headers
    print(f"  {BOLD}Security Headers{RESET}")
    print(f"  {DIM}{'─' * 45}{RESET}\n")

    present = [r for r in security_results if r['present']]
    missing = [r for r in security_results if not r['present']]

    if present:
        print(f"  {GREEN}Present:{RESET}")
        for r in present:
            status_icon = GREEN + '  ' + RESET if r['good'] else YELLOW + '  ' + RESET
            print(f"    {status_icon} {r['name']}")
            if show_full and r['value']:
                print(f"       {DIM}{r['value'][:60]}{'...' if len(r['value']) > 60 else ''}{RESET}")
        print()

    if missing:
        print(f"  {RED}Missing:{RESET}")
        for r in missing:
            sev_color = RED if r['severity'] == 'high' else YELLOW if r['severity'] == 'medium' else DIM
            print(f"    {sev_color}  {r['name']}{RESET} ({r['severity']})")
            if show_full:
                print(f"       {DIM}{r['description']}{RESET}")
        print()

    # Info leaks
    if info_leaks:
        print(f"  {BOLD}Information Leakage{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")
        for leak in info_leaks:
            print(f"    {YELLOW}  {leak['header']}: {leak['value']}{RESET}")
        print(f"\n  {DIM}Recommendation: Remove these headers to hide server info{RESET}")
        print()

    # Cookies
    if cookies:
        print(f"  {BOLD}Cookie Security{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")
        for cookie in cookies:
            issues = []
            if not cookie['secure']:
                issues.append('missing Secure')
            if not cookie['httponly']:
                issues.append('missing HttpOnly')
            if not cookie['samesite']:
                issues.append('missing SameSite')

            if issues:
                print(f"    {YELLOW}  {cookie['name']}: {', '.join(issues)}{RESET}")
            else:
                print(f"    {GREEN}  {cookie['name']}: All attributes set{RESET}")
        print()

    # Recommendations
    if show_full and missing:
        print(f"  {BOLD}Recommendations{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")
        for r in missing[:5]:  # Top 5 recommendations
            print(f"  {CYAN}{r['recommendation']}{RESET}")
            print()


def main():
    parser = argparse.ArgumentParser(description='HTTP Header Security Analyzer')
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('--full', '-f', action='store_true', help='Show full details')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  HTTP Header Security Analyzer{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    url = args.url
    if not url:
        url = input(f"\n  {CYAN}Enter URL:{RESET} ").strip()

    if not url:
        print(f"  {RED}URL required{RESET}")
        sys.exit(1)

    if not args.json:
        print(f"\n  {DIM}Fetching headers...{RESET}")

    headers, final_url, status = fetch_headers(url)

    if headers is None:
        if args.json:
            print(json.dumps({'error': str(status), 'url': url}))
        else:
            print(f"  {RED}Error: {status}{RESET}")
        sys.exit(1)

    # Analyze
    security_results = analyze_security_headers(headers)
    info_leaks = analyze_info_leaks(headers)
    cookies = analyze_cookies(headers)

    if args.json:
        output = {
            'url': final_url,
            'status': status,
            'score': calculate_score(security_results, info_leaks),
            'security_headers': security_results,
            'info_leaks': info_leaks,
            'cookies': cookies,
            'all_headers': headers
        }
        print(json.dumps(output, indent=2))
    else:
        display_results(final_url, status, security_results, info_leaks, cookies, args.full)


if __name__ == '__main__':
    main()
