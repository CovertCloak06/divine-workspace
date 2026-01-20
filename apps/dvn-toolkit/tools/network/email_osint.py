#!/usr/bin/env python3
"""
Email OSINT - Email address investigation tool
Usage: email_osint.py [email] [--breach] [--json]
Validates, analyzes, and investigates email addresses
"""

import sys
import json
import re
import argparse
import hashlib
import urllib.request
import urllib.error
import socket
import ssl

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common disposable email domains
DISPOSABLE_DOMAINS = {
    'tempmail.com', 'throwaway.email', 'guerrillamail.com', '10minutemail.com',
    'mailinator.com', 'temp-mail.org', 'fakeinbox.com', 'getnada.com',
    'maildrop.cc', 'yopmail.com', 'tempail.com', 'trashmail.com',
    'sharklasers.com', 'grr.la', 'guerrillamail.info', 'spam4.me',
    'tempr.email', 'discard.email', 'discardmail.com', 'spamgourmet.com',
    'mytemp.email', 'mohmal.com', 'tempinbox.com', 'emailondeck.com',
}

# Common free email providers
FREE_PROVIDERS = {
    'gmail.com': 'Google',
    'yahoo.com': 'Yahoo',
    'hotmail.com': 'Microsoft',
    'outlook.com': 'Microsoft',
    'live.com': 'Microsoft',
    'msn.com': 'Microsoft',
    'aol.com': 'AOL',
    'icloud.com': 'Apple',
    'me.com': 'Apple',
    'mac.com': 'Apple',
    'protonmail.com': 'ProtonMail',
    'proton.me': 'ProtonMail',
    'zoho.com': 'Zoho',
    'mail.com': 'Mail.com',
    'gmx.com': 'GMX',
    'yandex.com': 'Yandex',
    'fastmail.com': 'FastMail',
    'tutanota.com': 'Tutanota',
}


def validate_email_format(email):
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def parse_email(email):
    """Parse email into components"""
    if '@' not in email:
        return None

    local, domain = email.rsplit('@', 1)

    return {
        'local': local,
        'domain': domain.lower(),
        'full': email.lower(),
    }


def check_mx_records(domain):
    """Check if domain has MX records"""
    try:
        import subprocess
        result = subprocess.run(
            ['dig', '+short', 'MX', domain],
            capture_output=True, text=True, timeout=10
        )
        records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
        return records if records else None
    except:
        # Fallback: try socket
        try:
            socket.gethostbyname(f'mail.{domain}')
            return [f'mail.{domain}']
        except:
            return None


def check_domain_exists(domain):
    """Check if domain exists via DNS"""
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def analyze_local_part(local):
    """Analyze the local part of email"""
    analysis = {
        'length': len(local),
        'has_dots': '.' in local,
        'has_plus': '+' in local,
        'has_numbers': bool(re.search(r'\d', local)),
        'all_numbers': local.isdigit(),
        'looks_random': len(local) > 15 and bool(re.search(r'[a-z]{5,}\d{5,}', local)),
    }

    # Check for common patterns
    if re.match(r'^[a-z]+\.[a-z]+$', local):
        analysis['pattern'] = 'firstname.lastname'
    elif re.match(r'^[a-z]+_[a-z]+$', local):
        analysis['pattern'] = 'firstname_lastname'
    elif re.match(r'^[a-z]+\d{2,4}$', local):
        analysis['pattern'] = 'name+year'
    elif re.match(r'^[a-z]{1,2}\d+$', local):
        analysis['pattern'] = 'initials+numbers'
    else:
        analysis['pattern'] = 'other'

    return analysis


def check_haveibeenpwned(email):
    """Check if email appears in data breaches (using k-anonymity)"""
    # Hash the email
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Email-OSINT/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode()
            for line in data.split('\n'):
                if ':' in line:
                    hash_suffix, count = line.strip().split(':')
                    if hash_suffix == suffix:
                        return {'breached': True, 'count': int(count)}
        return {'breached': False}
    except:
        return {'breached': None, 'error': 'API unavailable'}


def check_gravatar(email):
    """Check if email has a Gravatar"""
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    url = f'https://www.gravatar.com/avatar/{email_hash}?d=404'

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            return {'has_gravatar': True, 'url': f'https://www.gravatar.com/avatar/{email_hash}'}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'has_gravatar': False}
    except:
        pass
    return {'has_gravatar': None}


def analyze_email(email):
    """Full email analysis"""
    result = {
        'email': email,
        'valid_format': False,
        'components': None,
        'domain_info': {},
        'local_analysis': {},
        'risk_factors': [],
        'risk_score': 0,
    }

    # Format validation
    if not validate_email_format(email):
        result['risk_factors'].append('Invalid email format')
        result['risk_score'] = 100
        return result

    result['valid_format'] = True

    # Parse email
    parsed = parse_email(email)
    if not parsed:
        return result

    result['components'] = parsed
    domain = parsed['domain']
    local = parsed['local']

    # Domain analysis
    result['domain_info']['domain'] = domain

    # Check if disposable
    if domain in DISPOSABLE_DOMAINS:
        result['domain_info']['type'] = 'disposable'
        result['risk_factors'].append('Disposable email domain')
        result['risk_score'] += 40
    elif domain in FREE_PROVIDERS:
        result['domain_info']['type'] = 'free'
        result['domain_info']['provider'] = FREE_PROVIDERS[domain]
    else:
        result['domain_info']['type'] = 'custom'

    # Check domain exists
    result['domain_info']['exists'] = check_domain_exists(domain)
    if not result['domain_info']['exists']:
        result['risk_factors'].append('Domain does not exist')
        result['risk_score'] += 50

    # Check MX records
    mx_records = check_mx_records(domain)
    result['domain_info']['has_mx'] = mx_records is not None
    result['domain_info']['mx_records'] = mx_records[:3] if mx_records else None
    if not mx_records:
        result['risk_factors'].append('No MX records found')
        result['risk_score'] += 20

    # Local part analysis
    result['local_analysis'] = analyze_local_part(local)

    if result['local_analysis']['looks_random']:
        result['risk_factors'].append('Local part looks randomly generated')
        result['risk_score'] += 15

    if result['local_analysis']['all_numbers']:
        result['risk_factors'].append('Local part is all numbers')
        result['risk_score'] += 10

    if len(local) < 3:
        result['risk_factors'].append('Very short local part')
        result['risk_score'] += 5

    # Cap risk score
    result['risk_score'] = min(100, result['risk_score'])

    return result


def display_results(result, breach_info=None, gravatar_info=None):
    """Display analysis results"""
    print(f"\n  {BOLD}Email Analysis Results{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    email = result['email']
    print(f"  {CYAN}Email:{RESET}  {email}")

    # Format validation
    if result['valid_format']:
        print(f"  {CYAN}Format:{RESET} {GREEN}Valid{RESET}")
    else:
        print(f"  {CYAN}Format:{RESET} {RED}Invalid{RESET}")
        return

    print()

    # Domain info
    domain_info = result.get('domain_info', {})
    print(f"  {BOLD}Domain Analysis{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"  {CYAN}Domain:{RESET}      {domain_info.get('domain')}")

    domain_type = domain_info.get('type', 'unknown')
    if domain_type == 'disposable':
        print(f"  {CYAN}Type:{RESET}        {RED}Disposable (temporary){RESET}")
    elif domain_type == 'free':
        provider = domain_info.get('provider', 'Unknown')
        print(f"  {CYAN}Type:{RESET}        {YELLOW}Free provider ({provider}){RESET}")
    else:
        print(f"  {CYAN}Type:{RESET}        {GREEN}Custom/Business{RESET}")

    exists = domain_info.get('exists')
    print(f"  {CYAN}Exists:{RESET}      {GREEN}Yes{RESET}" if exists else f"  {CYAN}Exists:{RESET}      {RED}No{RESET}")

    has_mx = domain_info.get('has_mx')
    print(f"  {CYAN}MX Records:{RESET}  {GREEN}Yes{RESET}" if has_mx else f"  {CYAN}MX Records:{RESET}  {RED}No{RESET}")

    if domain_info.get('mx_records'):
        for mx in domain_info['mx_records'][:2]:
            print(f"              {DIM}{mx}{RESET}")

    print()

    # Local part analysis
    local_info = result.get('local_analysis', {})
    print(f"  {BOLD}Local Part Analysis{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"  {CYAN}Pattern:{RESET}     {local_info.get('pattern', 'unknown')}")
    print(f"  {CYAN}Length:{RESET}      {local_info.get('length', 0)}")

    features = []
    if local_info.get('has_dots'):
        features.append('dots')
    if local_info.get('has_plus'):
        features.append('plus addressing')
    if local_info.get('has_numbers'):
        features.append('numbers')
    if features:
        print(f"  {CYAN}Features:{RESET}    {', '.join(features)}")

    print()

    # Breach check
    if breach_info:
        print(f"  {BOLD}Breach Check{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")
        if breach_info.get('breached') == True:
            count = breach_info.get('count', 'unknown')
            print(f"  {RED}  FOUND in {count} data breaches!{RESET}")
        elif breach_info.get('breached') == False:
            print(f"  {GREEN}  Not found in known breaches{RESET}")
        else:
            print(f"  {DIM}  Check unavailable{RESET}")
        print()

    # Gravatar
    if gravatar_info:
        print(f"  {BOLD}Online Presence{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")
        if gravatar_info.get('has_gravatar'):
            print(f"  {CYAN}Gravatar:{RESET}    {GREEN}Found{RESET}")
            print(f"              {DIM}{gravatar_info.get('url')}{RESET}")
        else:
            print(f"  {CYAN}Gravatar:{RESET}    {DIM}None{RESET}")
        print()

    # Risk assessment
    risk_score = result.get('risk_score', 0)
    risk_factors = result.get('risk_factors', [])

    print(f"  {BOLD}Risk Assessment{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")

    if risk_score >= 50:
        color = RED
        level = 'HIGH'
    elif risk_score >= 25:
        color = YELLOW
        level = 'MEDIUM'
    else:
        color = GREEN
        level = 'LOW'

    print(f"  {CYAN}Risk Score:{RESET}  {color}{risk_score}/100 ({level}){RESET}")

    if risk_factors:
        print(f"  {CYAN}Factors:{RESET}")
        for factor in risk_factors:
            print(f"    {YELLOW}  {factor}{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Email OSINT Tool')
    parser.add_argument('email', nargs='?', help='Email to investigate')
    parser.add_argument('--breach', '-b', action='store_true', help='Check for data breaches')
    parser.add_argument('--gravatar', '-g', action='store_true', help='Check Gravatar')
    parser.add_argument('--full', '-f', action='store_true', help='Run all checks')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Email OSINT Tool{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    email = args.email
    if not email:
        email = input(f"\n  {CYAN}Email to investigate:{RESET} ").strip()

    if not email:
        print(f"  {RED}Email required{RESET}")
        sys.exit(1)

    if not args.json:
        print(f"\n  {DIM}Analyzing email...{RESET}")

    # Main analysis
    result = analyze_email(email)

    # Optional checks
    breach_info = None
    gravatar_info = None

    if args.breach or args.full:
        if not args.json:
            print(f"  {DIM}Checking breach databases...{RESET}")
        breach_info = check_haveibeenpwned(email)
        result['breach_check'] = breach_info

    if args.gravatar or args.full:
        if not args.json:
            print(f"  {DIM}Checking Gravatar...{RESET}")
        gravatar_info = check_gravatar(email)
        result['gravatar'] = gravatar_info

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        display_results(result, breach_info, gravatar_info)


if __name__ == '__main__':
    main()
