#!/usr/bin/env python3
"""
SSL Certificate Checker - Analyze SSL/TLS certificates
Usage: ssl_check.py <domain> [--port 443]
"""

import ssl
import socket
import argparse
from datetime import datetime
import hashlib

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_certificate(hostname, port=443, timeout=10):
    """Fetch SSL certificate from server"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return cert, cert_der, cipher, version, None
    except Exception as e:
        return None, None, None, None, str(e)


def parse_cert_date(date_str):
    """Parse certificate date string"""
    try:
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
    except:
        return None


def get_cert_fingerprint(cert_der):
    """Calculate certificate fingerprints"""
    return {
        'sha256': hashlib.sha256(cert_der).hexdigest().upper(),
        'sha1': hashlib.sha1(cert_der).hexdigest().upper(),
        'md5': hashlib.md5(cert_der).hexdigest().upper()
    }


def format_subject(subject):
    """Format certificate subject"""
    parts = []
    for item in subject:
        for key, value in item:
            parts.append(f"{key}={value}")
    return ', '.join(parts)


def check_certificate(hostname, port=443):
    """Check and display certificate details"""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔒 SSL Certificate Checker                       ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Checking: {hostname}:{port}{RESET}\n")

    cert, cert_der, cipher, version, error = get_certificate(hostname, port)

    if error:
        print(f"  {RED}Error: {error}{RESET}\n")
        return

    # Certificate Info
    print(f"  {BOLD}Certificate Details:{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}")

    # Subject
    subject = cert.get('subject', ())
    print(f"  {CYAN}{'Subject:':<18}{RESET} {format_subject(subject)}")

    # Issuer
    issuer = cert.get('issuer', ())
    print(f"  {CYAN}{'Issuer:':<18}{RESET} {format_subject(issuer)}")

    # Validity
    not_before = parse_cert_date(cert.get('notBefore', ''))
    not_after = parse_cert_date(cert.get('notAfter', ''))

    if not_before:
        print(f"  {CYAN}{'Valid From:':<18}{RESET} {not_before.strftime('%Y-%m-%d %H:%M:%S')}")
    if not_after:
        days_left = (not_after - datetime.now()).days
        if days_left < 0:
            color = RED
            status = "EXPIRED"
        elif days_left < 30:
            color = RED
            status = f"{days_left} days left!"
        elif days_left < 90:
            color = YELLOW
            status = f"{days_left} days left"
        else:
            color = GREEN
            status = f"{days_left} days left"

        print(f"  {CYAN}{'Valid Until:':<18}{RESET} {not_after.strftime('%Y-%m-%d %H:%M:%S')} {color}({status}){RESET}")

    # Serial Number
    serial = cert.get('serialNumber', 'N/A')
    print(f"  {CYAN}{'Serial Number:':<18}{RESET} {serial}")

    # Version
    print(f"  {CYAN}{'Version:':<18}{RESET} {cert.get('version', 'N/A')}")

    # Subject Alternative Names
    san = cert.get('subjectAltName', ())
    if san:
        print(f"\n  {BOLD}Subject Alternative Names:{RESET}")
        for type_name, value in san[:10]:
            print(f"    {DIM}•{RESET} {value}")
        if len(san) > 10:
            print(f"    {DIM}... and {len(san)-10} more{RESET}")

    # Connection Info
    print(f"\n  {BOLD}Connection Details:{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}")
    print(f"  {CYAN}{'TLS Version:':<18}{RESET} {version}")
    if cipher:
        print(f"  {CYAN}{'Cipher Suite:':<18}{RESET} {cipher[0]}")
        print(f"  {CYAN}{'Cipher Bits:':<18}{RESET} {cipher[2]}")

    # Fingerprints
    if cert_der:
        fps = get_cert_fingerprint(cert_der)
        print(f"\n  {BOLD}Fingerprints:{RESET}")
        print(f"  {DIM}{'─' * 55}{RESET}")
        print(f"  {CYAN}{'SHA-256:':<10}{RESET} {fps['sha256'][:32]}...")
        print(f"  {CYAN}{'SHA-1:':<10}{RESET} {fps['sha1']}")
        print(f"  {CYAN}{'MD5:':<10}{RESET} {fps['md5']}")

    # Security Analysis
    print(f"\n  {BOLD}Security Analysis:{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}")

    issues = []
    warnings = []

    # Check expiry
    if not_after:
        if days_left < 0:
            issues.append("Certificate has EXPIRED")
        elif days_left < 30:
            warnings.append(f"Certificate expires in {days_left} days")

    # Check TLS version
    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0']:
        issues.append(f"Outdated protocol: {version}")
    elif version == 'TLSv1.1':
        warnings.append(f"TLS 1.1 is deprecated, consider TLS 1.2+")

    # Check cipher
    if cipher:
        weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
        for weak in weak_ciphers:
            if weak in cipher[0].upper():
                issues.append(f"Weak cipher: {cipher[0]}")
                break

    # Check self-signed
    if subject == issuer:
        warnings.append("Self-signed certificate")

    if issues:
        for issue in issues:
            print(f"  {RED}✗ {issue}{RESET}")
    if warnings:
        for warn in warnings:
            print(f"  {YELLOW}⚠ {warn}{RESET}")
    if not issues and not warnings:
        print(f"  {GREEN}✓ No obvious security issues{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='SSL Certificate Checker')
    parser.add_argument('domain', help='Domain to check')
    parser.add_argument('--port', '-p', type=int, default=443, help='Port number')
    args = parser.parse_args()

    # Clean domain
    domain = args.domain.replace('https://', '').replace('http://', '').split('/')[0]

    check_certificate(domain, args.port)


if __name__ == '__main__':
    main()
