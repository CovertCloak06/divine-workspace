"""
Learning Paths Registry - Structured learning journeys
Defines paths, lessons, and their associated tools
"""

# Skill level constants
SKILL_BEGINNER = 'beginner'
SKILL_INTERMEDIATE = 'intermediate'
SKILL_ADVANCED = 'advanced'

LEARNING_PATHS = {
    'network_fundamentals': {
        'id': 'network_fundamentals',
        'name': 'Network Fundamentals',
        'icon': '<->',
        'skill_level': SKILL_BEGINNER,
        'description': 'Learn the basics of networking and how to explore networks',
        'estimated_time': '30 min',
        'prerequisites': [],
        'lessons': [
            {
                'id': 'nf_01_ip',
                'title': 'What is an IP Address?',
                'tool_id': 'ip_geolocate',
                'objective': 'Understand IP addresses and look up your own',
                'content': """An IP address is like a home address for computers on the internet.

Just like your house has a street address so mail can find you, every device
connected to the internet has an IP address so data can find it.

There are two types:
- IPv4: Like 192.168.1.1 (four numbers separated by dots)
- IPv6: Like 2001:0db8:85a3::8a2e:0370:7334 (longer, for more addresses)

In this lesson, you'll use the IP Geolocation tool to look up information
about an IP address.""",
                'exercise': {
                    'instruction': 'Look up your own public IP address',
                    'target': 'your_ip',
                    'hint': 'Search "what is my ip" in a browser first'
                }
            },
            {
                'id': 'nf_02_dns',
                'title': 'DNS - The Internet Phonebook',
                'tool_id': 'dns_lookup',
                'objective': 'Understand how domain names become IP addresses',
                'content': """DNS (Domain Name System) is like a phonebook for the internet.

When you type "google.com" in your browser, your computer needs to find
the actual IP address of Google's servers. DNS does this translation.

DNS Records you'll learn:
- A Record: Maps domain to IPv4 address
- AAAA Record: Maps domain to IPv6 address
- MX Record: Where to send email
- NS Record: Which servers manage the domain

In this lesson, you'll query DNS records for popular domains.""",
                'exercise': {
                    'instruction': 'Look up DNS records for google.com',
                    'target': 'google.com',
                    'hint': 'Try different record types like A, MX, NS'
                }
            },
            {
                'id': 'nf_03_ports',
                'title': 'Ports - Doors to Services',
                'tool_id': 'portscanner',
                'objective': 'Understand ports and scan your own machine',
                'content': """Ports are like numbered doors on a computer that services listen behind.

Common ports you should know:
- 22: SSH (secure remote access)
- 80: HTTP (web traffic)
- 443: HTTPS (secure web traffic)
- 3306: MySQL database
- 5432: PostgreSQL database

When you visit a website, your browser connects to port 80 or 443.
Port scanning checks which "doors" are open on a computer.

IMPORTANT: Only scan systems you own or have permission to scan!""",
                'exercise': {
                    'instruction': 'Scan ports 1-100 on localhost',
                    'target': 'localhost',
                    'hint': 'localhost means your own computer (127.0.0.1)'
                }
            },
            {
                'id': 'nf_04_discovery',
                'title': 'Network Discovery',
                'tool_id': 'ping_sweep',
                'objective': 'Find devices on your local network',
                'content': """Network discovery finds other devices on your network.

Your home network probably has:
- Router (usually 192.168.1.1 or 192.168.0.1)
- Your computer
- Phones, tablets, smart TVs
- IoT devices

A ping sweep sends a "hello" to each address and sees who responds.
This helps map out what's on your network.""",
                'exercise': {
                    'instruction': 'Scan your local network (e.g., 192.168.1.0/24)',
                    'target': 'local_network',
                    'hint': 'Check your IP to find your network range'
                }
            }
        ]
    },
    'osint_basics': {
        'id': 'osint_basics',
        'name': 'OSINT Basics',
        'icon': '(?)',
        'skill_level': SKILL_BEGINNER,
        'description': 'Learn Open Source Intelligence gathering techniques',
        'estimated_time': '25 min',
        'prerequisites': [],
        'lessons': [
            {
                'id': 'osint_01_intro',
                'title': 'What is OSINT?',
                'tool_id': 'google_dork',
                'objective': 'Understand OSINT and advanced search techniques',
                'content': """OSINT = Open Source Intelligence

It's the art of finding publicly available information. This includes:
- Search engines (with advanced operators)
- Social media profiles
- Public records
- Domain registration (WHOIS)
- Leaked databases (for defensive purposes)

Google Dorking uses special search operators:
- site:example.com - Search within a site
- filetype:pdf - Find specific file types
- inurl:admin - Find URLs containing "admin"
- "exact phrase" - Match exact text""",
                'exercise': {
                    'instruction': 'Generate dorks for a domain you own',
                    'target': 'your_domain',
                    'hint': 'Start with site: and filetype: operators'
                }
            },
            {
                'id': 'osint_02_username',
                'title': 'Username Hunting',
                'tool_id': 'username_check',
                'objective': 'Find accounts across platforms by username',
                'content': """People often reuse usernames across platforms.

If you know someone's username on one site, you can often find their
accounts on other platforms. This is useful for:
- Finding your own digital footprint
- Verifying someone's identity
- Investigating during authorized engagements

This tool checks 40+ platforms for a username.""",
                'exercise': {
                    'instruction': 'Search for YOUR OWN username',
                    'target': 'your_username',
                    'hint': 'Only search for usernames you own!'
                }
            },
            {
                'id': 'osint_03_email',
                'title': 'Email Intelligence',
                'tool_id': 'email_osint',
                'objective': 'Analyze email addresses for information',
                'content': """An email address reveals more than you might think:

- Domain tells you the provider or company
- Username might be reused elsewhere
- Format hints at naming conventions (first.last@company.com)
- Breach databases show if it was compromised

Email OSINT helps verify if an address is valid and what's associated.""",
                'exercise': {
                    'instruction': 'Analyze your own email address',
                    'target': 'your_email',
                    'hint': 'Check for breaches and validation'
                }
            },
            {
                'id': 'osint_04_domain',
                'title': 'Domain Research',
                'tool_id': 'whois_lookup',
                'objective': 'Extract information from domain registrations',
                'content': """WHOIS is a protocol for querying domain registration data.

You can find:
- Registrant information (sometimes hidden by privacy)
- Registration and expiration dates
- Name servers
- Registrar information

This is valuable for understanding who owns a domain and when it was
created. Older domains are often more trustworthy.""",
                'exercise': {
                    'instruction': 'Look up WHOIS for a major website',
                    'target': 'example.com',
                    'hint': 'Try popular sites like github.com'
                }
            }
        ]
    },
    'web_security': {
        'id': 'web_security',
        'name': 'Web Security Intro',
        'icon': '(!)',
        'skill_level': SKILL_INTERMEDIATE,
        'description': 'Learn web application security fundamentals',
        'estimated_time': '40 min',
        'prerequisites': ['network_fundamentals'],
        'lessons': [
            {
                'id': 'ws_01_headers',
                'title': 'HTTP Headers & Fingerprinting',
                'tool_id': 'header_analyzer',
                'objective': 'Understand HTTP headers and server information',
                'content': """HTTP headers are metadata sent with every web request/response.

Security-relevant headers:
- Server: Reveals web server software
- X-Powered-By: Shows backend technology
- Content-Security-Policy: Protects against XSS
- X-Frame-Options: Prevents clickjacking

Headers can leak valuable information about the technology stack.""",
                'exercise': {
                    'instruction': 'Analyze headers of a website',
                    'target': 'https://example.com',
                    'hint': 'Look for Server and X-Powered-By headers'
                }
            },
            {
                'id': 'ws_02_tech',
                'title': 'Technology Detection',
                'tool_id': 'techdetect',
                'objective': 'Identify technologies used by websites',
                'content': """Knowing what technology a site uses helps find vulnerabilities.

Detectable technologies:
- Web frameworks (React, Angular, WordPress)
- Web servers (Apache, Nginx, IIS)
- Programming languages (PHP, Python, Node.js)
- CMS platforms (WordPress, Drupal)
- CDN providers (Cloudflare, Akamai)

Each technology has known vulnerabilities to research.""",
                'exercise': {
                    'instruction': 'Detect technologies on a popular site',
                    'target': 'https://github.com',
                    'hint': 'Compare results with what you know about the site'
                }
            }
        ]
    }
}


def get_all_paths() -> list:
    """Get all learning paths"""
    return list(LEARNING_PATHS.values())


def get_path(path_id: str) -> dict:
    """Get a specific learning path"""
    return LEARNING_PATHS.get(path_id)


def get_lesson(path_id: str, lesson_id: str) -> dict:
    """Get a specific lesson from a path"""
    path = get_path(path_id)
    if not path:
        return None
    for lesson in path['lessons']:
        if lesson['id'] == lesson_id:
            return lesson
    return None


def get_paths_by_skill(skill_level: str) -> list:
    """Get paths matching a skill level"""
    return [p for p in LEARNING_PATHS.values() if p['skill_level'] == skill_level]
