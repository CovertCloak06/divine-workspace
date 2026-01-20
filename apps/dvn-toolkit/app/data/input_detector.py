"""
Input Type Detector - Automatically detects input type for Identity Recon
Supports: email, username, domain, IP address, phone number
"""

import re


# Input type constants
INPUT_EMAIL = 'email'
INPUT_USERNAME = 'username'
INPUT_DOMAIN = 'domain'
INPUT_IP = 'ip'
INPUT_PHONE = 'phone'
INPUT_UNKNOWN = 'unknown'

# Detection patterns
PATTERNS = {
    INPUT_EMAIL: re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    INPUT_IP: re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ),
    INPUT_PHONE: re.compile(
        r'^\+?[\d\s\-\(\)]{7,20}$'
    ),
    INPUT_DOMAIN: re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
    ),
    INPUT_USERNAME: re.compile(
        r'^[a-zA-Z][a-zA-Z0-9_-]{2,30}$'
    ),
}

# Common TLDs for domain validation
COMMON_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'us', 'uk', 'de', 'fr',
    'app', 'dev', 'tech', 'info', 'biz', 'xyz', 'online', 'site', 'cloud'
}


def detect_input_type(text: str) -> tuple:
    """
    Detect the type of input provided.

    Returns:
        tuple: (input_type, confidence, details)
        - input_type: One of INPUT_* constants
        - confidence: float 0-1 indicating detection confidence
        - details: dict with extracted information
    """
    if not text or not isinstance(text, str):
        return INPUT_UNKNOWN, 0.0, {}

    text = text.strip()

    if not text:
        return INPUT_UNKNOWN, 0.0, {}

    # Check email first (most specific pattern with @)
    if '@' in text:
        if PATTERNS[INPUT_EMAIL].match(text):
            username, domain = text.split('@', 1)
            return INPUT_EMAIL, 0.95, {
                'email': text,
                'username': username,
                'domain': domain
            }

    # Check IP address (very specific pattern)
    if PATTERNS[INPUT_IP].match(text):
        octets = text.split('.')
        return INPUT_IP, 0.99, {
            'ip': text,
            'octets': octets,
            'is_private': _is_private_ip(text)
        }

    # Check phone number
    digits_only = re.sub(r'\D', '', text)
    if len(digits_only) >= 7 and PATTERNS[INPUT_PHONE].match(text):
        return INPUT_PHONE, 0.85, {
            'phone': text,
            'digits': digits_only,
            'formatted': _format_phone(digits_only)
        }

    # Check domain (has dots, valid TLD)
    if '.' in text and not text.startswith('.'):
        if PATTERNS[INPUT_DOMAIN].match(text):
            parts = text.split('.')
            tld = parts[-1].lower()
            confidence = 0.90 if tld in COMMON_TLDS else 0.70
            return INPUT_DOMAIN, confidence, {
                'domain': text.lower(),
                'tld': tld,
                'subdomain': '.'.join(parts[:-2]) if len(parts) > 2 else None
            }

    # Default to username (alphanumeric, underscores, hyphens)
    if PATTERNS[INPUT_USERNAME].match(text):
        return INPUT_USERNAME, 0.80, {
            'username': text,
            'normalized': text.lower()
        }

    # If nothing matches but looks like text, assume username
    if text.isalnum() or re.match(r'^[\w.-]+$', text):
        return INPUT_USERNAME, 0.50, {
            'username': text,
            'normalized': text.lower()
        }

    return INPUT_UNKNOWN, 0.0, {'raw': text}


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private range"""
    octets = [int(o) for o in ip.split('.')]

    # 10.0.0.0/8
    if octets[0] == 10:
        return True
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return True
    # 127.0.0.0/8 (loopback)
    if octets[0] == 127:
        return True

    return False


def _format_phone(digits: str) -> str:
    """Format phone number for display"""
    if len(digits) == 10:
        return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    elif len(digits) == 11 and digits[0] == '1':
        return f"+1 ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
    return digits


def get_input_type_info(input_type: str) -> dict:
    """Get display information for an input type"""
    info = {
        INPUT_EMAIL: {
            'name': 'Email Address',
            'icon': '@',
            'color': '#00d4ff',
            'description': 'Search by email address'
        },
        INPUT_USERNAME: {
            'name': 'Username',
            'icon': '@',
            'color': '#00ff9f',
            'description': 'Search by username/handle'
        },
        INPUT_DOMAIN: {
            'name': 'Domain',
            'icon': 'www',
            'color': '#ff9f00',
            'description': 'Search by domain name'
        },
        INPUT_IP: {
            'name': 'IP Address',
            'icon': '#',
            'color': '#ff0040',
            'description': 'Search by IP address'
        },
        INPUT_PHONE: {
            'name': 'Phone Number',
            'icon': 'tel',
            'color': '#9f00ff',
            'description': 'Search by phone number'
        },
        INPUT_UNKNOWN: {
            'name': 'Unknown',
            'icon': '?',
            'color': '#888888',
            'description': 'Could not detect input type'
        }
    }
    return info.get(input_type, info[INPUT_UNKNOWN])
