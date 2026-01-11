#!/usr/bin/env python3
"""
OSINT (Open Source Intelligence) Tools for PKN
Ethical intelligence gathering from public sources

⚠️  LEGAL NOTICE:
These tools are for AUTHORIZED and LEGAL use only. Users must:
- Have proper authorization for reconnaissance activities
- Comply with applicable laws and regulations
- Respect privacy and terms of service
- Use responsibly and ethically

Unauthorized access, scanning, or data collection may be illegal.
"""

import re
import socket
import requests
import whois
import dns.resolver
import json
import base64
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse, quote
import subprocess

# Try to import optional dependencies
try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class OSINTTools:
    """Comprehensive OSINT toolkit for intelligence gathering"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PKN-OSINT/1.0 (Educational/Research)'
        })

    # ============================================
    # DOMAIN & DNS INTELLIGENCE
    # ============================================

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup on domain

        Returns registration info, nameservers, registrar, etc.
        """
        try:
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

            w = whois.whois(domain)

            return {
                'success': True,
                'domain': domain,
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'nameservers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else [],
                'country': w.country if hasattr(w, 'country') else None,
                'raw': str(w)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def dns_lookup(self, domain: str, record_types: List[str] = None) -> Dict[str, Any]:
        """
        Perform DNS lookups for various record types

        Args:
            domain: Domain to lookup
            record_types: List of record types (A, AAAA, MX, TXT, NS, CNAME, SOA)
        """
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

        results = {
            'success': True,
            'domain': domain,
            'records': {}
        }

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['records'][record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results['records'][record_type] = []
            except dns.resolver.NXDOMAIN:
                results['success'] = False
                results['error'] = 'Domain does not exist'
                break
            except Exception as e:
                results['records'][record_type] = {'error': str(e)}

        return results

    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup on IP address
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                'success': True,
                'ip': ip,
                'hostname': hostname
            }
        except Exception as e:
            return {'success': False, 'ip': ip, 'error': str(e)}

    def subdomain_enum(self, domain: str) -> Dict[str, Any]:
        """
        Basic subdomain enumeration using common subdomains

        Note: For comprehensive subdomain discovery, use specialized tools
        like subfinder, amass, or assetfinder externally
        """
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'portal', 'dev', 'staging', 'test', 'api', 'app', 'mobile',
            'blog', 'shop', 'store', 'vpn', 'remote', 'cloud', 'backup'
        ]

        found = []
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
            except:
                pass

        return {
            'success': True,
            'domain': domain,
            'subdomains_found': found,
            'count': len(found),
            'note': 'Basic enumeration. Use specialized tools for comprehensive discovery.'
        }

    # ============================================
    # IP & NETWORK INTELLIGENCE
    # ============================================

    def ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """
        Get geolocation data for IP address using ip-api.com
        """
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}')
            data = response.json()

            if data.get('status') == 'success':
                return {
                    'success': True,
                    'ip': ip,
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as')
                }
            else:
                return {'success': False, 'error': data.get('message', 'Unknown error')}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def port_scan_basic(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Basic port scan (common ports only)

        ⚠️  WARNING: Only scan hosts you own or have authorization to test!
        Unauthorized port scanning may be illegal.
        """
        if ports is None:
            # Common ports only
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]

        open_ports = []
        closed_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))

                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    open_ports.append({'port': port, 'service': service})
                else:
                    closed_ports.append(port)

                sock.close()
            except Exception as e:
                closed_ports.append(port)

        return {
            'success': True,
            'host': host,
            'open_ports': open_ports,
            'open_count': len(open_ports),
            'scanned_count': len(ports),
            'warning': 'Scan only authorized hosts'
        }

    # ============================================
    # EMAIL INTELLIGENCE
    # ============================================

    def email_validate(self, email: str) -> Dict[str, Any]:
        """
        Validate email format and check domain MX records
        """
        # Basic format validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return {
                'success': False,
                'email': email,
                'valid_format': False,
                'error': 'Invalid email format'
            }

        # Extract domain
        domain = email.split('@')[1]

        # Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            has_mx = len(mx_records) > 0
            mx_list = [str(mx.exchange) for mx in mx_records]
        except:
            has_mx = False
            mx_list = []

        return {
            'success': True,
            'email': email,
            'valid_format': True,
            'domain': domain,
            'has_mx_records': has_mx,
            'mx_records': mx_list
        }

    def haveibeenpwned_check(self, email: str) -> Dict[str, Any]:
        """
        Check if email appears in known data breaches (Have I Been Pwned API)

        Note: Requires API key for automated queries
        """
        try:
            # Using anonymized API (no API key needed but less detailed)
            email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix = email_hash[:5]
            suffix = email_hash[5:]

            response = self.session.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=10
            )

            if response.status_code == 200:
                hashes = response.text.split('\n')
                for hash_entry in hashes:
                    if hash_entry.startswith(suffix):
                        count = hash_entry.split(':')[1]
                        return {
                            'success': True,
                            'email': email,
                            'pwned': True,
                            'count': int(count),
                            'warning': 'Email found in breach databases'
                        }

                return {
                    'success': True,
                    'email': email,
                    'pwned': False,
                    'message': 'No breaches found'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ============================================
    # USERNAME & SOCIAL MEDIA OSINT
    # ============================================

    def username_search(self, username: str) -> Dict[str, Any]:
        """
        Search for username across popular platforms

        Checks if profile exists on various social media and websites
        """
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Medium': f'https://medium.com/@{username}',
            'DevTo': f'https://dev.to/{username}',
            'HackerNews': f'https://news.ycombinator.com/user?id={username}'
        }

        found = {}
        not_found = {}

        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    found[platform] = url
                else:
                    not_found[platform] = url
            except:
                not_found[platform] = url

        return {
            'success': True,
            'username': username,
            'found_on': found,
            'found_count': len(found),
            'not_found_on': not_found,
            'total_checked': len(platforms)
        }

    # ============================================
    # WEB INTELLIGENCE
    # ============================================

    def wayback_check(self, url: str) -> Dict[str, Any]:
        """
        Check Wayback Machine for archived versions of URL
        """
        try:
            api_url = f'http://archive.org/wayback/available?url={quote(url)}'
            response = self.session.get(api_url, timeout=10)
            data = response.json()

            if 'archived_snapshots' in data and 'closest' in data['archived_snapshots']:
                snapshot = data['archived_snapshots']['closest']
                return {
                    'success': True,
                    'url': url,
                    'archived': True,
                    'archive_url': snapshot.get('url'),
                    'timestamp': snapshot.get('timestamp'),
                    'status': snapshot.get('status')
                }
            else:
                return {
                    'success': True,
                    'url': url,
                    'archived': False,
                    'message': 'No archives found'
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def web_technologies(self, url: str) -> Dict[str, Any]:
        """
        Detect web technologies used by a website
        """
        try:
            if not url.startswith('http'):
                url = 'https://' + url

            response = self.session.get(url, timeout=10)
            headers = dict(response.headers)

            technologies = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'framework': [],
                'libraries': [],
                'cms': None
            }

            # Basic CMS detection
            content = response.text.lower()
            if 'wordpress' in content or 'wp-content' in content:
                technologies['cms'] = 'WordPress'
            elif 'joomla' in content:
                technologies['cms'] = 'Joomla'
            elif 'drupal' in content:
                technologies['cms'] = 'Drupal'

            # Framework detection
            if 'react' in content:
                technologies['libraries'].append('React')
            if 'vue' in content:
                technologies['libraries'].append('Vue.js')
            if 'angular' in content:
                technologies['libraries'].append('Angular')
            if 'jquery' in content:
                technologies['libraries'].append('jQuery')

            return {
                'success': True,
                'url': url,
                'technologies': technologies,
                'status_code': response.status_code,
                'headers': headers
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def ssl_certificate_info(self, domain: str) -> Dict[str, Any]:
        """
        Get SSL/TLS certificate information
        """
        try:
            import ssl
            import socket

            context = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    return {
                        'success': True,
                        'domain': domain,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_names': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ============================================
    # PHONE NUMBER INTELLIGENCE
    # ============================================

    def phone_number_lookup(self, number: str) -> Dict[str, Any]:
        """
        Get information about phone number

        Uses existing phonenumbers library (already in PKN)
        """
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone

            # Parse number
            parsed = phonenumbers.parse(number, None)

            return {
                'success': True,
                'number': number,
                'valid': phonenumbers.is_valid_number(parsed),
                'possible': phonenumbers.is_possible_number(parsed),
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'country': geocoder.description_for_number(parsed, 'en'),
                'carrier': carrier.name_for_number(parsed, 'en'),
                'timezone': timezone.time_zones_for_number(parsed),
                'formatted_international': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
                'formatted_national': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                )
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ============================================
    # UTILITY METHODS
    # ============================================

    def hash_generate(self, text: str) -> Dict[str, str]:
        """
        Generate multiple hash types for given text
        """
        return {
            'md5': hashlib.md5(text.encode()).hexdigest(),
            'sha1': hashlib.sha1(text.encode()).hexdigest(),
            'sha256': hashlib.sha256(text.encode()).hexdigest(),
            'sha512': hashlib.sha512(text.encode()).hexdigest()
        }

    def base64_encode(self, text: str) -> str:
        """Encode text to base64"""
        return base64.b64encode(text.encode()).decode()

    def base64_decode(self, encoded: str) -> str:
        """Decode base64 text"""
        try:
            return base64.b64decode(encoded).decode()
        except:
            return 'Invalid base64'


# Initialize tools instance
osint = OSINTTools()


# ============================================
# LANGCHAIN TOOL WRAPPERS
# ============================================

from langchain_core.tools import Tool

TOOLS = [
    Tool(
        name="whois_lookup",
        func=lambda domain: osint.whois_lookup(domain),
        description="Perform WHOIS lookup on domain. Returns registration info, nameservers, registrar. Input: domain name (e.g., 'example.com')"
    ),
    Tool(
        name="dns_lookup",
        func=lambda domain: osint.dns_lookup(domain),
        description="Perform DNS lookups for domain. Returns A, AAAA, MX, TXT, NS, CNAME records. Input: domain name"
    ),
    Tool(
        name="ip_geolocation",
        func=lambda ip: osint.ip_geolocation(ip),
        description="Get geolocation for IP address. Returns country, city, ISP, coordinates. Input: IP address"
    ),
    Tool(
        name="reverse_dns",
        func=lambda ip: osint.reverse_dns(ip),
        description="Perform reverse DNS lookup on IP. Returns hostname. Input: IP address"
    ),
    Tool(
        name="email_validate",
        func=lambda email: osint.email_validate(email),
        description="Validate email format and check MX records. Input: email address"
    ),
    Tool(
        name="username_search",
        func=lambda username: osint.username_search(username),
        description="Search for username across social media platforms. Returns found profiles. Input: username"
    ),
    Tool(
        name="wayback_check",
        func=lambda url: osint.wayback_check(url),
        description="Check Wayback Machine for archived versions. Input: URL"
    ),
    Tool(
        name="web_technologies",
        func=lambda url: osint.web_technologies(url),
        description="Detect technologies used by website. Returns server, CMS, frameworks. Input: URL"
    ),
    Tool(
        name="ssl_certificate",
        func=lambda domain: osint.ssl_certificate_info(domain),
        description="Get SSL/TLS certificate information. Input: domain name"
    ),
    Tool(
        name="phone_lookup",
        func=lambda number: osint.phone_number_lookup(number),
        description="Get phone number information (carrier, country, timezone). Input: phone number with country code"
    ),
    Tool(
        name="subdomain_enum",
        func=lambda domain: osint.subdomain_enum(domain),
        description="Basic subdomain enumeration. Input: domain name"
    ),
    Tool(
        name="port_scan",
        func=lambda host: osint.port_scan_basic(host),
        description="⚠️  AUTHORIZED USE ONLY! Scan common ports on host. Input: hostname or IP"
    )
]


# Export for easy access
__all__ = ['OSINTTools', 'osint', 'TOOLS']
