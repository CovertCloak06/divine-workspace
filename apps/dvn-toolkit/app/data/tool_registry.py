"""
Tool Registry - Comprehensive metadata for all 126+ tools
Rich documentation, form inputs, and presets for each tool
"""

# Input field types
INPUT_TEXT = 'text'
INPUT_NUMBER = 'number'
INPUT_DROPDOWN = 'dropdown'
INPUT_CHECKBOX = 'checkbox'
INPUT_FILE = 'file'
INPUT_IP = 'ip'
INPUT_URL = 'url'
INPUT_PORT_RANGE = 'port_range'

# Tool categories with display info and beginner-friendly explanations
CATEGORIES = {
    'offensive': {
        'name': 'Offensive Security',
        'icon': 'skull',
        'description': 'Penetration testing and red team tools',
        'color': '#ff0040',
        'skill_level': 'intermediate',
        'full_explanation': '''Offensive security (also called "pentesting" or "ethical hacking")
means testing systems for security holes the same way real attackers would - but with
permission and the goal of fixing issues found.

Think of it like hiring someone to try breaking into your house to find weak spots,
so you can fix them before a real burglar finds them.''',
        'safe_use': 'ONLY use on systems you own or have written permission to test. Unauthorized testing is illegal.',
        'beginner_tools': ['ping_sweep', 'dns_lookup', 'password_gen'],
    },
    'security': {
        'name': 'Security Tools',
        'icon': 'shield',
        'description': 'Security analysis and testing utilities',
        'color': '#ffaa00',
        'skill_level': 'beginner',
        'full_explanation': '''Security tools help protect your data and accounts. They include
password generators, hash tools, and encryption utilities.

These are generally safe to use and help you maintain good security hygiene - like
creating strong passwords and checking if your credentials have been leaked.''',
        'safe_use': 'These tools are safe for personal use. Great starting point for learning.',
        'beginner_tools': ['password_gen', 'hasher'],
    },
    'network': {
        'name': 'Network Tools',
        'icon': 'network',
        'description': 'Network scanning and analysis',
        'color': '#00d4ff',
        'skill_level': 'beginner',
        'full_explanation': '''Network tools help you understand and troubleshoot computer networks.
They can look up website addresses (DNS), check if servers are online (ping), and
examine how data travels across the internet.

Like a postal inspector checking mail routes, these tools show you how internet
traffic flows from point A to point B.''',
        'safe_use': 'Most network tools are safe for learning. Only scan your own networks.',
        'beginner_tools': ['dns_lookup', 'ping_sweep', 'ssl_check', 'whois'],
    },
    'pentest': {
        'name': 'Linux Pentest',
        'icon': 'terminal',
        'description': 'Linux privilege escalation and persistence',
        'color': '#ff4444',
        'skill_level': 'advanced',
        'full_explanation': '''Linux pentest tools check for ways an attacker could gain higher
privileges on a Linux system. They find misconfigurations like weak file permissions
or vulnerable software.

Used by security professionals to audit systems before attackers can exploit them.''',
        'safe_use': 'Only run on systems you own or have explicit permission to test.',
        'beginner_tools': [],
    },
    'android': {
        'name': 'Android Security',
        'icon': 'phone',
        'description': 'Android app analysis and ADB tools',
        'color': '#a4c639',
        'skill_level': 'intermediate',
        'full_explanation': '''Android security tools help analyze mobile apps for security issues.
They can examine app permissions, extract installed apps, and check for sensitive
data exposure.

Useful for testing your own apps or understanding what permissions apps request.''',
        'safe_use': 'Safe to use on your own Android device with developer mode enabled.',
        'beginner_tools': ['app_permissions'],
    },
    'crypto': {
        'name': 'Cryptography',
        'icon': 'lock',
        'description': 'Encryption and encoding tools',
        'color': '#9c27b0',
        'skill_level': 'beginner',
        'full_explanation': '''Cryptography is the science of secret codes and secure communication.
These tools help you encode messages, encrypt files, and work with different
number systems (like binary or hexadecimal).

Like having a secret decoder ring - but for serious data protection.''',
        'safe_use': 'Safe for learning. Great for understanding how data is protected.',
        'beginner_tools': ['encoder', 'baseconv'],
    },
    'osint': {
        'name': 'OSINT',
        'icon': 'search',
        'description': 'Open source intelligence gathering',
        'color': '#2196f3',
        'skill_level': 'beginner',
        'full_explanation': '''OSINT (Open Source Intelligence) is gathering information from
publicly available sources - websites, social media, public records, etc.

Like being a digital detective using only public information. No hacking involved -
just smart searching and connecting dots from public data.''',
        'safe_use': 'Safe to use - only accesses public information. Respect privacy.',
        'beginner_tools': ['whois', 'dns_lookup'],
    },
    'forensics': {
        'name': 'Forensics',
        'icon': 'microscope',
        'description': 'Digital forensics analysis',
        'color': '#607d8b',
        'skill_level': 'intermediate',
        'full_explanation': '''Digital forensics examines computer evidence - like CSI for computers.
These tools help analyze files, recover deleted data, and investigate security incidents.

Used after a security breach to understand what happened and gather evidence.''',
        'safe_use': 'Safe to use on your own files. Used for analysis, not attacks.',
        'beginner_tools': ['hexview', 'metadata'],
    },
    'web': {
        'name': 'Web Tools',
        'icon': 'globe',
        'description': 'Web development utilities',
        'color': '#4caf50',
        'skill_level': 'beginner',
        'full_explanation': '''Web tools help with website development and debugging. They can
decode data formats, test APIs, and analyze web technologies.

Essential utilities for anyone building or maintaining websites.''',
        'safe_use': 'Safe for development and learning.',
        'beginner_tools': ['jwt_decode', 'regex_test'],
    },
    'cli': {
        'name': 'CLI Utilities',
        'icon': 'terminal',
        'description': 'Command line utilities',
        'color': '#795548',
        'skill_level': 'beginner',
        'full_explanation': '''CLI (Command Line Interface) utilities are everyday tools that run
in the terminal. They perform common tasks like generating passwords, checking
weather, or creating QR codes.

Think of them as mini-programs for getting things done quickly.''',
        'safe_use': 'Completely safe everyday utilities.',
        'beginner_tools': ['qrcode', 'weather', 'pwgen', 'sysmon'],
    },
    'dev': {
        'name': 'Developer Tools',
        'icon': 'code',
        'description': 'Development and debugging tools',
        'color': '#3f51b5',
        'skill_level': 'beginner',
        'full_explanation': '''Developer tools help programmers write and debug code. They include
code formatters, fake data generators, and version control helpers.

Essential toolkit for anyone learning to program or building software.''',
        'safe_use': 'Safe for learning and development.',
        'beginner_tools': ['fakedata', 'uuid_gen', 'json_tool'],
    },
    'files': {
        'name': 'File Tools',
        'icon': 'folder',
        'description': 'File management utilities',
        'color': '#ff9800',
        'skill_level': 'beginner',
        'full_explanation': '''File tools help organize, rename, and manage your files. They can
find duplicates, bulk rename files, and securely delete sensitive data.

Like having a smart assistant for organizing your digital files.''',
        'safe_use': 'Safe to use. Be careful with delete/shred operations.',
        'beginner_tools': ['bulk_rename', 'duplicate', 'metadata'],
    },
    'system': {
        'name': 'System Tools',
        'icon': 'settings',
        'description': 'System administration tools',
        'color': '#9e9e9e',
        'skill_level': 'beginner',
        'full_explanation': '''System tools help manage your computer - check disk usage, monitor
processes, and configure system settings.

Like having a dashboard for your computer's health and performance.''',
        'safe_use': 'Safe to use. Be careful when modifying system settings.',
        'beginner_tools': ['sysinfo', 'diskusage', 'processes'],
    },
    'productivity': {
        'name': 'Productivity',
        'icon': 'check',
        'description': 'Personal productivity tools',
        'color': '#8bc34a',
        'skill_level': 'beginner',
        'full_explanation': '''Productivity tools help you get things done - manage tasks, take
notes, track habits, and manage time.

Simple utilities to help organize your work and personal life.''',
        'safe_use': 'Completely safe everyday tools.',
        'beginner_tools': ['todo', 'notes', 'timer', 'pomodoro'],
    },
    'media': {
        'name': 'Media Tools',
        'icon': 'image',
        'description': 'Media and image utilities',
        'color': '#e91e63',
        'skill_level': 'beginner',
        'full_explanation': '''Media tools work with images, audio, and video files. They can
convert formats, take screenshots, and extract information from media files.

Useful for anyone working with photos, music, or videos.''',
        'safe_use': 'Safe to use with your own media files.',
        'beginner_tools': ['imgconvert', 'screenshot', 'color_picker'],
    },
    'monitor': {
        'name': 'Monitoring',
        'icon': 'chart',
        'description': 'System and service monitoring',
        'color': '#00bcd4',
        'skill_level': 'beginner',
        'full_explanation': '''Monitoring tools watch systems and services to detect problems.
They track uptime, detect file changes, and alert you to issues.

Like having a watchdog that monitors your systems 24/7.''',
        'safe_use': 'Safe to use for monitoring your own systems.',
        'beginner_tools': ['uptime', 'change_detect'],
    },
    'fun': {
        'name': 'Fun',
        'icon': 'star',
        'description': 'Entertainment and fun utilities',
        'color': '#ffc107',
        'skill_level': 'beginner',
        'full_explanation': '''Fun tools are just for entertainment - ASCII art, typing tests,
and visual effects. No serious purpose, just enjoyment!

Great for taking breaks and having fun with the terminal.''',
        'safe_use': 'Completely safe and fun!',
        'beginner_tools': ['cowsay', 'matrix', 'typing_test'],
    },
}


# Full tool registry with rich metadata
TOOLS = {
    # ═══════════════════════════════════════════════════════════════════════════
    # OFFENSIVE SECURITY TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'nmap_lite': {
        'id': 'nmap_lite',
        'name': 'Port Scanner',
        'script': 'nmap_lite.py',
        'category': 'offensive',
        'icon': 'network_scan',
        'skill_level': 'beginner',
        'docs': {
            'short_desc': 'Network port scanning with service detection',
            'full_desc': '''A lightweight port scanner that discovers open ports on target
systems. Identifies running services by grabbing banners and can detect
service versions. Essential for initial reconnaissance in penetration testing.''',
            'concept_explanation': {
                'title': 'What is Port Scanning?',
                'simple': '''Every computer has 65,535 "ports" - like different doors for different services.
Port 80 is for websites, port 22 for remote access (SSH), port 443 for secure websites (HTTPS).

A port scanner knocks on each door to see which ones are open. Open ports mean services
are running and potentially accessible.''',
                'analogy': '''Think of a building with many doors. Each door leads to a different office
(web server, email, database). Port scanning is like walking around checking which doors are
unlocked - it tells you what services you can potentially connect to.''',
                'why_it_matters': '''Security testers scan ports to find all accessible services on a
system. Each open port is a potential entry point that needs to be secured.''',
            },
            'when_to_use': [
                'Starting reconnaissance on a new target',
                'Need to find what services are running on a server',
                'Mapping a network to find active hosts',
                'Verifying firewall rules are working correctly',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Enter Target', 'instruction': 'Type the IP address (like 192.168.1.1) or domain name (like example.com) of the system you want to scan.', 'tip': 'Start with your own router IP to practice safely.'},
                {'step': 2, 'title': 'Choose Ports', 'instruction': 'Leave blank for common ports, or specify a range like 1-1000 or specific ports like 22,80,443.', 'tip': 'Common ports (1-1024) are usually enough for basic recon.'},
                {'step': 3, 'title': 'Select Speed', 'instruction': 'Normal is fine for most uses. Use Sneaky if you want to be less detectable.', 'tip': 'Faster scans are noisier and more likely to be detected.'},
                {'step': 4, 'title': 'Run and Wait', 'instruction': 'Press RUN and wait for results. Scanning can take from seconds to minutes.', 'tip': 'Open ports appear with their service name (HTTP, SSH, etc).'},
            ],
            'real_world_example': '''Scenario: You're testing a company's web server and
need to find all accessible services. Run a scan on common ports to discover
SSH on 22, HTTP on 80, HTTPS on 443, and maybe a database on 3306.''',
            'expected_output': 'List of open ports with service names and versions',
            'success_looks_like': '''PORT    STATE   SERVICE
22/tcp  open    ssh
80/tcp  open    http
443/tcp open    https''',
            'common_mistakes': [
                {'mistake': 'Scanning without permission', 'fix': 'ALWAYS get written permission before scanning systems you dont own.'},
                {'mistake': 'Wrong IP format', 'fix': 'Use numbers like 192.168.1.1, not http:// URLs'},
                {'mistake': 'Scanning too aggressively', 'fix': 'Start with Normal timing, not Aggressive'},
            ],
            'glossary': [
                {'term': 'Port', 'definition': 'A numbered endpoint (0-65535) for network communication'},
                {'term': 'TCP', 'definition': 'Reliable connection protocol used by most services'},
                {'term': 'Service', 'definition': 'Program listening on a port (web server, SSH, etc)'},
                {'term': 'Banner', 'definition': 'Text a service sends identifying itself and its version'},
            ],
            'warnings': [
                'Only scan systems you have permission to test',
                'Aggressive scans may trigger IDS/IPS alerts',
                'Some networks block ICMP, use TCP ping instead',
            ],
            'prerequisites': [
                'Network connectivity to target',
                'Permission to scan the target system',
            ],
            'legal_note': 'Port scanning without authorization may be illegal. Only scan systems you own or have written permission to test.',
        },
        'inputs': [
            {
                'name': 'target',
                'type': INPUT_IP,
                'label': 'Target IP/Host',
                'placeholder': '192.168.1.1 or hostname.com',
                'required': True,
                'help': 'IP address, hostname, or CIDR range (e.g., 192.168.1.0/24)',
            },
            {
                'name': 'ports',
                'type': INPUT_PORT_RANGE,
                'label': 'Port Range',
                'placeholder': '1-1000 or 22,80,443',
                'required': False,
                'help': 'Ports to scan. Leave empty for common ports.',
                'flag': '-p',
            },
            {
                'name': 'service_detection',
                'type': INPUT_CHECKBOX,
                'label': 'Detect Service Versions',
                'default': False,
                'help': 'Grab banners to identify service versions (slower)',
                'flag': '-sV',
            },
            {
                'name': 'timing',
                'type': INPUT_DROPDOWN,
                'label': 'Scan Speed',
                'options': [
                    {'value': '3', 'label': 'Normal (default)'},
                    {'value': '4', 'label': 'Aggressive (faster)'},
                    {'value': '2', 'label': 'Polite (slower, less detectable)'},
                    {'value': '1', 'label': 'Sneaky (very slow, stealthy)'},
                ],
                'default': '3',
                'help': 'Balance between speed and stealth',
                'flag': '-T',
            },
            {
                'name': 'ping_scan',
                'type': INPUT_CHECKBOX,
                'label': 'Host Discovery Only',
                'default': False,
                'help': 'Only check if hosts are alive, skip port scan',
                'flag': '--ping',
            },
        ],
        'presets': [
            {'name': 'Quick Scan', 'values': {'timing': '4', 'ports': '21-23,25,80,443,3306,8080'}},
            {'name': 'Full Scan', 'values': {'ports': '1-65535', 'service_detection': True}},
            {'name': 'Stealth Scan', 'values': {'timing': '1'}},
            {'name': 'Web Ports', 'values': {'ports': '80,443,8000,8080,8443'}},
        ],
    },

    'dns_enum': {
        'id': 'dns_enum',
        'name': 'DNS Enum',
        'script': 'dns_enum.py',
        'category': 'offensive',
        'icon': 'dns',
        'docs': {
            'short_desc': 'DNS enumeration and subdomain discovery',
            'full_desc': '''Performs comprehensive DNS enumeration including record lookups
(A, AAAA, MX, NS, TXT, SOA) and subdomain bruteforcing. Discovers hidden
subdomains that may host vulnerable services.''',
            'when_to_use': [
                'Mapping all subdomains of a target domain',
                'Finding mail servers and nameservers',
                'Looking for development/staging subdomains',
                'Gathering information before a pentest',
            ],
            'real_world_example': '''Scenario: Testing target.com - discover dev.target.com,
staging.target.com, admin.target.com which may have weaker security than
the main site.''',
            'expected_output': 'List of DNS records and discovered subdomains',
            'warnings': [
                'Subdomain bruteforcing generates many DNS queries',
                'Some domains have wildcard DNS, filter false positives',
            ],
            'prerequisites': ['DNS resolution working', 'Target domain name'],
        },
        'inputs': [
            {
                'name': 'domain',
                'type': INPUT_TEXT,
                'label': 'Target Domain',
                'placeholder': 'example.com',
                'required': True,
                'help': 'Domain to enumerate (without http://)',
            },
            {
                'name': 'subdomains',
                'type': INPUT_CHECKBOX,
                'label': 'Bruteforce Subdomains',
                'default': False,
                'help': 'Try common subdomain names',
                'flag': '-s',
            },
            {
                'name': 'all_records',
                'type': INPUT_CHECKBOX,
                'label': 'All Record Types',
                'default': False,
                'help': 'Query all DNS record types',
                'flag': '--all',
            },
        ],
        'presets': [
            {'name': 'Quick Lookup', 'values': {}},
            {'name': 'Full Enum', 'values': {'subdomains': True, 'all_records': True}},
        ],
    },

    'sqli_scanner': {
        'id': 'sqli_scanner',
        'name': 'SQLi Scanner',
        'script': 'sqli_scanner.py',
        'category': 'offensive',
        'icon': 'database',
        'skill_level': 'intermediate',
        'docs': {
            'short_desc': 'SQL injection vulnerability testing',
            'full_desc': '''Tests web application parameters for SQL injection vulnerabilities.
Supports various injection techniques including error-based, blind, and
time-based detection methods.''',
            'concept_explanation': {
                'title': 'What is SQL Injection?',
                'simple': '''SQL injection is a way to trick a website into running database commands
it shouldn't. Websites use databases to store information (users, products, etc).
When you search or log in, your input becomes part of a database query.

If the website doesn't check your input carefully, you could type special commands
that make the database give you access to data you shouldn't see - like other
users' passwords.''',
                'analogy': '''Imagine a restaurant order form where you write "1 burger AND show me
the cash register contents". If the waiter blindly follows everything you write
without checking, you'd see information you shouldn't. SQL injection works similarly
- slipping extra commands into normal inputs.''',
                'why_it_matters': '''SQL injection is one of the most dangerous web vulnerabilities.
Attackers can steal entire databases, bypass login pages, or delete data.
Testing for it helps fix these holes before attackers exploit them.''',
            },
            'when_to_use': [
                'Testing web forms for SQL injection',
                'Checking URL parameters for vulnerabilities',
                'Verifying input validation is working',
                'CTF web challenges',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Find a URL with Parameters', 'instruction': 'Look for URLs with ? followed by something=value. Example: site.com/page?id=5 or site.com/search?q=hello', 'tip': 'Parameters are the parts after ? that the website uses to fetch specific data.'},
                {'step': 2, 'title': 'Enter the Full URL', 'instruction': 'Copy and paste the complete URL including http:// and the parameter you want to test.', 'tip': 'Make sure the URL loads normally in a browser first.'},
                {'step': 3, 'title': 'Select Test Level', 'instruction': 'Start with Basic for quick tests. Use Thorough only if Basic finds nothing.', 'tip': 'Higher levels take longer but test more injection types.'},
                {'step': 4, 'title': 'Read the Results', 'instruction': 'VULNERABLE means the site has a security hole. NOT VULNERABLE means its protected.', 'tip': 'If vulnerable, the tool shows what type of injection worked.'},
            ],
            'real_world_example': '''Scenario: Found a search page at target.com/search?q=test -
test if the "q" parameter is vulnerable to SQL injection by injecting
payloads like ' OR 1=1--''',
            'expected_output': 'Vulnerability status and injection point details',
            'success_looks_like': '''[+] Testing: http://example.com/page?id=5
[+] Parameter: id
[!] VULNERABLE: Error-based SQL injection detected
[+] Payload that worked: ' OR 1=1--
[+] Database type: MySQL''',
            'common_mistakes': [
                {'mistake': 'Forgetting http://', 'fix': 'Always include the full URL starting with http:// or https://'},
                {'mistake': 'URL has no parameters', 'fix': 'The URL must have ?something=value to test. site.com/page alone wont work.'},
                {'mistake': 'Testing without permission', 'fix': 'Only test sites you own or have written authorization to test. Use practice sites like DVWA.'},
                {'mistake': 'Parameter not injectable', 'fix': 'Not all parameters are vulnerable. Try different parameters or the site may be secure.'},
            ],
            'glossary': [
                {'term': 'SQL', 'definition': 'Structured Query Language - the language used to talk to databases'},
                {'term': 'Injection', 'definition': 'Inserting malicious commands into normal user input'},
                {'term': 'Parameter', 'definition': 'The part of a URL after ? that passes data (like id=5 or search=hello)'},
                {'term': 'Payload', 'definition': 'The specific text used to test for vulnerabilities'},
                {'term': 'Error-based', 'definition': 'Injection that causes database errors revealing information'},
                {'term': 'Blind', 'definition': 'Injection where you cant see errors but can infer results'},
            ],
            'warnings': [
                'Only test applications you have permission to test',
                'May cause errors visible to users',
                'Log files will record your tests',
            ],
            'prerequisites': ['Target URL with parameters', 'Authorization to test'],
            'legal_note': 'Testing websites without authorization is illegal and can result in criminal charges. Only test your own sites or those you have explicit permission to test.',
            'safe_practice': ['DVWA (Damn Vulnerable Web App)', 'HackTheBox', 'TryHackMe', 'PortSwigger Web Security Academy'],
        },
        'inputs': [
            {
                'name': 'url',
                'type': INPUT_URL,
                'label': 'Target URL',
                'placeholder': 'http://target.com/page?id=1',
                'required': True,
                'help': 'URL with parameter to test (include the parameter)',
                'flag': '-u',
            },
            {
                'name': 'level',
                'type': INPUT_DROPDOWN,
                'label': 'Test Level',
                'options': [
                    {'value': '1', 'label': 'Basic (fast)'},
                    {'value': '2', 'label': 'Extended'},
                    {'value': '3', 'label': 'Thorough (slow)'},
                ],
                'default': '1',
                'help': 'Higher levels test more payloads',
                'flag': '--level',
            },
            {
                'name': 'technique',
                'type': INPUT_DROPDOWN,
                'label': 'Technique',
                'options': [
                    {'value': 'all', 'label': 'All techniques'},
                    {'value': 'error', 'label': 'Error-based'},
                    {'value': 'blind', 'label': 'Blind (boolean)'},
                    {'value': 'time', 'label': 'Time-based'},
                ],
                'default': 'all',
                'flag': '--technique',
            },
        ],
        'presets': [
            {'name': 'Quick Test', 'values': {'level': '1'}},
            {'name': 'Thorough', 'values': {'level': '3', 'technique': 'all'}},
        ],
    },

    'xss_scanner': {
        'id': 'xss_scanner',
        'name': 'XSS Scanner',
        'script': 'xss_scanner.py',
        'category': 'offensive',
        'icon': 'code',
        'skill_level': 'intermediate',
        'docs': {
            'short_desc': 'Cross-site scripting detection',
            'full_desc': '''Scans web pages for cross-site scripting (XSS) vulnerabilities.
Tests reflected and stored XSS by injecting various payloads and checking
if they're executed in the response.''',
            'concept_explanation': {
                'title': 'What is XSS (Cross-Site Scripting)?',
                'simple': '''XSS is when a website accidentally runs code that a hacker puts in.
Normally, when you search for "shoes", the website shows "Results for: shoes".
But what if you search for special code instead of "shoes"? If the website
isn't careful, it might RUN that code instead of just displaying it.

This lets attackers steal passwords, cookies, or take over accounts.''',
                'analogy': '''Imagine a bulletin board where anyone can post messages. If someone
posts a message saying "run to the exit screaming", most people just read it.
But if someone posts it in a way that makes people actually do it, that's
like XSS - the message becomes an action instead of just text.''',
                'why_it_matters': '''XSS vulnerabilities can:
• Steal user login sessions (cookies)
• Capture passwords as users type them
• Redirect users to fake websites
• Spread malware through trusted sites''',
            },
            'when_to_use': [
                'Testing search boxes and input fields',
                'Checking URL parameters for reflection',
                'Scanning forms for stored XSS',
                'Web application security assessment',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Find a URL with Parameters', 'instruction': 'Look for URLs like site.com/search?q=test where user input appears in the page.', 'tip': 'Search pages and comment sections are common XSS targets.'},
                {'step': 2, 'title': 'Enter the URL', 'instruction': 'Copy the full URL including http:// and the parameter you want to test.', 'tip': 'Make sure the page actually shows your search term somewhere.'},
                {'step': 3, 'title': 'Enable Form Scanning', 'instruction': 'Check "Scan Forms" to also test HTML forms on the page (login forms, contact forms).', 'tip': 'Forms are common XSS entry points.'},
                {'step': 4, 'title': 'Interpret Results', 'instruction': 'VULNERABLE means the site runs injected code. The tool shows which payload worked.', 'tip': 'Report vulnerabilities responsibly to the site owner.'},
            ],
            'common_mistakes': [
                {'mistake': 'Testing sites without permission', 'fix': 'ONLY test sites you own or have written authorization to test.'},
                {'mistake': 'URL doesnt reflect input', 'fix': 'XSS only works if your input appears in the page. Check that the site shows your search term.'},
                {'mistake': 'Browser blocking alerts', 'fix': 'Modern browsers may block some XSS. The scanner detects even if your browser blocks.'},
            ],
            'glossary': [
                {'term': 'XSS', 'definition': 'Cross-Site Scripting - injecting malicious scripts into web pages'},
                {'term': 'Reflected XSS', 'definition': 'Script is reflected back immediately (like in search results)'},
                {'term': 'Stored XSS', 'definition': 'Script is saved (like in a comment) and runs for all visitors'},
                {'term': 'Payload', 'definition': 'The test code injected to check for vulnerabilities'},
                {'term': 'Sanitization', 'definition': 'Cleaning user input to prevent code execution'},
            ],
            'success_looks_like': '''[+] Testing: http://example.com/search?q=test
[+] Scanning parameter: q
[!] VULNERABLE: Reflected XSS found!
[+] Payload: <script>alert('XSS')</script>
[+] Context: HTML body''',
            'real_world_example': '''Scenario: A search page shows "Results for: [your query]" -
test if injecting <script>alert(1)</script> gets executed.''',
            'expected_output': 'List of XSS vulnerabilities found with payloads',
            'warnings': [
                'Only test applications you own or have permission to test',
                'Payloads may be stored and affect other users',
            ],
            'prerequisites': ['Target URL', 'Authorization to test'],
            'legal_note': 'Testing websites without authorization is illegal. Only test your own sites or those with explicit permission.',
            'safe_practice': ['DVWA', 'HackTheBox', 'TryHackMe', 'PortSwigger XSS Labs'],
        },
        'inputs': [
            {
                'name': 'url',
                'type': INPUT_URL,
                'label': 'Target URL',
                'placeholder': 'http://target.com/search?q=test',
                'required': True,
                'help': 'URL to test for XSS',
                'flag': '-u',
            },
            {
                'name': 'scan_forms',
                'type': INPUT_CHECKBOX,
                'label': 'Scan Forms',
                'default': False,
                'help': 'Also scan HTML forms on the page',
                'flag': '--forms',
            },
            {
                'name': 'level',
                'type': INPUT_DROPDOWN,
                'label': 'Payload Level',
                'options': [
                    {'value': '1', 'label': 'Basic payloads'},
                    {'value': '2', 'label': 'Extended'},
                    {'value': '3', 'label': 'All payloads'},
                ],
                'default': '1',
                'flag': '--level',
            },
        ],
        'presets': [
            {'name': 'Quick Scan', 'values': {}},
            {'name': 'Full Scan', 'values': {'scan_forms': True, 'level': '3'}},
        ],
    },

    'reverse_shells': {
        'id': 'reverse_shells',
        'name': 'Reverse Shells',
        'script': 'reverse_shells.py',
        'category': 'offensive',
        'icon': 'terminal',
        'docs': {
            'short_desc': 'Generate reverse shell payloads',
            'full_desc': '''Generates reverse shell one-liners in various languages including
Bash, Python, PHP, Perl, Ruby, Netcat, and PowerShell. Useful for getting
command execution after finding an RCE vulnerability.''',
            'when_to_use': [
                'After finding command execution vulnerability',
                'Need to establish remote access during pentest',
                'CTF challenges requiring shell access',
            ],
            'real_world_example': '''Scenario: Found command injection on a Linux server -
generate a bash reverse shell to your attack machine on port 4444.''',
            'expected_output': 'Ready-to-use reverse shell command',
            'warnings': [
                'Only use on systems you have authorization to access',
                'Ensure your listener is ready before triggering',
                'Consider firewall egress rules',
            ],
            'prerequisites': ['Listener ready on attack machine', 'Network path to target'],
        },
        'inputs': [
            {
                'name': 'shell_type',
                'type': INPUT_DROPDOWN,
                'label': 'Shell Type',
                'options': [
                    {'value': 'bash', 'label': 'Bash'},
                    {'value': 'python', 'label': 'Python'},
                    {'value': 'php', 'label': 'PHP'},
                    {'value': 'perl', 'label': 'Perl'},
                    {'value': 'ruby', 'label': 'Ruby'},
                    {'value': 'nc', 'label': 'Netcat'},
                    {'value': 'powershell', 'label': 'PowerShell'},
                ],
                'required': True,
                'flag': '-t',
            },
            {
                'name': 'lhost',
                'type': INPUT_IP,
                'label': 'Your IP Address',
                'placeholder': '10.10.10.10',
                'required': True,
                'help': 'IP where your listener is running',
                'flag': '-i',
            },
            {
                'name': 'lport',
                'type': INPUT_NUMBER,
                'label': 'Your Port',
                'placeholder': '4444',
                'required': True,
                'help': 'Port your listener is on',
                'flag': '-p',
            },
            {
                'name': 'list_only',
                'type': INPUT_CHECKBOX,
                'label': 'List Available Shells',
                'default': False,
                'help': 'Show all available shell types',
                'flag': '--list',
            },
        ],
        'presets': [
            {'name': 'Bash Shell', 'values': {'shell_type': 'bash', 'lport': '4444'}},
            {'name': 'Python Shell', 'values': {'shell_type': 'python', 'lport': '4444'}},
        ],
    },

    'hash_toolkit': {
        'id': 'hash_toolkit',
        'name': 'Hash Toolkit',
        'script': 'hash_toolkit.py',
        'category': 'offensive',
        'icon': 'hash',
        'docs': {
            'short_desc': 'Hash identification and cracking',
            'full_desc': '''Identifies hash types, generates hashes from text, and performs
dictionary-based hash cracking. Supports MD5, SHA1, SHA256, SHA512,
bcrypt, and many more.''',
            'when_to_use': [
                'Found a hash and need to identify the type',
                'Need to crack password hashes',
                'Generating hashes for testing',
                'CTF crypto challenges',
            ],
            'real_world_example': '''Scenario: Dumped a database and found password hashes
like "5f4dcc3b5aa765d61d8327deb882cf99" - identify it as MD5 then crack
it with a wordlist.''',
            'expected_output': 'Hash type identification or cracked plaintext',
            'warnings': [
                'Only crack hashes you have authorization to test',
                'Complex passwords may not be in wordlists',
            ],
            'prerequisites': ['Hash to analyze', 'Wordlist for cracking'],
        },
        'inputs': [
            {
                'name': 'action',
                'type': INPUT_DROPDOWN,
                'label': 'Action',
                'options': [
                    {'value': 'identify', 'label': 'Identify Hash Type'},
                    {'value': 'generate', 'label': 'Generate Hash'},
                    {'value': 'crack', 'label': 'Crack Hash'},
                ],
                'required': True,
            },
            {
                'name': 'hash_value',
                'type': INPUT_TEXT,
                'label': 'Hash or Text',
                'placeholder': '5f4dcc3b...',
                'required': True,
                'help': 'Hash to identify/crack, or text to hash',
            },
            {
                'name': 'wordlist',
                'type': INPUT_FILE,
                'label': 'Wordlist',
                'required': False,
                'help': 'Wordlist file for cracking',
                'flag': '-w',
            },
            {
                'name': 'hash_type',
                'type': INPUT_DROPDOWN,
                'label': 'Hash Type',
                'options': [
                    {'value': 'all', 'label': 'All Types'},
                    {'value': 'md5', 'label': 'MD5'},
                    {'value': 'sha1', 'label': 'SHA1'},
                    {'value': 'sha256', 'label': 'SHA256'},
                    {'value': 'sha512', 'label': 'SHA512'},
                ],
                'default': 'all',
                'flag': '--type',
            },
        ],
        'presets': [
            {'name': 'Identify', 'values': {'action': 'identify'}},
            {'name': 'Generate MD5', 'values': {'action': 'generate', 'hash_type': 'md5'}},
        ],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'ping_sweep': {
        'id': 'ping_sweep',
        'name': 'Ping Sweep',
        'script': 'ping_sweep.py',
        'category': 'network',
        'icon': 'network',
        'skill_level': 'beginner',
        'docs': {
            'short_desc': 'Network ping sweep',
            'full_desc': '''Scans a network range to find live hosts using ICMP ping.
Quickly identifies active devices on a network segment.''',
            'concept_explanation': {
                'title': 'What is Ping Sweep?',
                'simple': '''A ping is like saying "hello, are you there?" to another computer.
It sends a tiny message and waits for a reply. If the computer responds, its online.

A ping SWEEP sends this "hello" to MANY addresses at once - for example, all 254
addresses on your home network. It quickly shows you which devices are active.''',
                'analogy': '''Imagine you move into a new apartment building and want to know
which units are occupied. You could knock on every door (1, 2, 3... 254) and see
who answers. A ping sweep does exactly this for computers on a network - it
"knocks" on each address to find who's home.''',
                'why_it_matters': '''Ping sweeps help you:
• Find all devices on your network
• Discover unknown devices that shouldn't be there
• Check if a server or device is online
• Map out a network before deeper analysis''',
            },
            'when_to_use': [
                'Mapping a network to find active hosts',
                'Initial network reconnaissance',
                'Verifying network connectivity',
                'Finding what devices are on your home network',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Find Your Network Range', 'instruction': 'Most home networks use 192.168.1.0/24 or 192.168.0.0/24. The /24 means scan addresses 1-254.', 'tip': 'Your router usually shows your network range in its settings.'},
                {'step': 2, 'title': 'Enter the Range', 'instruction': 'Type the network range like 192.168.1.0/24 to scan your local network.', 'tip': 'Start with your own home network to practice safely.'},
                {'step': 3, 'title': 'Set Timeout', 'instruction': 'Default 1000ms (1 second) is fine. Lower values scan faster but may miss slow devices.', 'tip': '500ms is good for fast local networks.'},
                {'step': 4, 'title': 'Review Results', 'instruction': 'Each IP that responds is an active device. Common ones: .1 is usually your router.', 'tip': 'Note unknown devices - they could be IoT devices, printers, or intruders.'},
            ],
            'common_mistakes': [
                {'mistake': 'Wrong network range', 'fix': 'Check your IP (usually starts with 192.168). Your network is that with .0/24 at the end.'},
                {'mistake': 'Scanning other networks', 'fix': 'Only scan networks you own or have permission to scan.'},
                {'mistake': 'Devices not showing', 'fix': 'Some devices block ping. They may be online but configured not to respond.'},
            ],
            'glossary': [
                {'term': 'Ping', 'definition': 'A network test that sends a small packet and waits for a reply'},
                {'term': 'ICMP', 'definition': 'Internet Control Message Protocol - the technology behind ping'},
                {'term': 'CIDR /24', 'definition': 'Notation meaning scan 256 addresses (0-255) in that range'},
                {'term': 'Host', 'definition': 'Any device with an IP address (computer, phone, printer, etc)'},
            ],
            'success_looks_like': '''Scanning 192.168.1.0/24...
192.168.1.1   - ALIVE (router)
192.168.1.5   - ALIVE
192.168.1.23  - ALIVE
192.168.1.105 - ALIVE
Found 4 active hosts''',
            'real_world_example': '''Scenario: Connected to a new network and need to
find all active devices - sweep 192.168.1.0/24 to discover them.''',
            'expected_output': 'List of responding IP addresses',
            'warnings': [
                'Some hosts may not respond to ping',
                'Firewalls may block ICMP',
                'Only scan networks you have permission to test',
            ],
            'prerequisites': ['Network access'],
        },
        'inputs': [
            {
                'name': 'network',
                'type': INPUT_IP,
                'label': 'Network Range',
                'placeholder': '192.168.1.0/24',
                'required': True,
                'help': 'CIDR range or IP range to sweep',
            },
            {
                'name': 'timeout',
                'type': INPUT_NUMBER,
                'label': 'Timeout (ms)',
                'placeholder': '1000',
                'default': '1000',
                'help': 'Timeout per host in milliseconds',
                'flag': '-t',
            },
        ],
        'presets': [
            {'name': 'Class C Scan', 'values': {'network': '192.168.1.0/24'}},
            {'name': 'Quick Scan', 'values': {'timeout': '500'}},
        ],
    },

    'dns_lookup': {
        'id': 'dns_lookup',
        'name': 'DNS Lookup',
        'script': 'dns_lookup.py',
        'category': 'network',
        'icon': 'dns',
        'skill_level': 'beginner',
        'docs': {
            'short_desc': 'DNS record lookup',
            'full_desc': '''Performs DNS lookups for various record types including A,
AAAA, MX, NS, TXT, CNAME, and SOA records.''',
            'concept_explanation': {
                'title': 'What is DNS?',
                'simple': '''DNS (Domain Name System) is like a phone book for the internet.
When you type "google.com", your computer asks DNS servers "what's the phone number
(IP address) for google.com?" and gets back something like 142.250.80.46.

Without DNS, you'd have to remember IP addresses for every website!''',
                'analogy': '''Imagine you want to call a friend but only know their name, not
their phone number. You look them up in a contact list (DNS) which tells you
their number (IP address). DNS does the same thing for websites - translates
friendly names into computer addresses.''',
                'why_it_matters': '''Understanding DNS helps you:
• Troubleshoot "website not loading" issues
• Find what server a website uses
• Discover mail servers and other services
• Learn how the internet actually works''',
            },
            'when_to_use': [
                'Looking up domain IP addresses',
                'Finding mail servers for a domain',
                'Checking DNS configuration',
                'Troubleshooting connection issues',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Enter Domain Name', 'instruction': 'Type a website name WITHOUT http://. For example: google.com or github.com', 'tip': 'Just the name, no slashes or pages like /about'},
                {'step': 2, 'title': 'Choose Record Type', 'instruction': 'A record shows IP address (most common). MX shows mail servers. Use "All Types" to see everything.', 'tip': 'Start with "A (IPv4)" to see the basic IP address.'},
                {'step': 3, 'title': 'Read Results', 'instruction': 'The IP address shown is where that website lives. Multiple IPs mean the site has backup servers.', 'tip': 'You can ping this IP to test connectivity.'},
            ],
            'common_mistakes': [
                {'mistake': 'Including http://', 'fix': 'Just type the domain: google.com NOT http://google.com'},
                {'mistake': 'Including paths', 'fix': 'Just the domain: github.com NOT github.com/user/repo'},
                {'mistake': 'Typos in domain', 'fix': 'Double-check spelling. gogle.com wont work.'},
            ],
            'glossary': [
                {'term': 'DNS', 'definition': 'Domain Name System - translates names to IP addresses'},
                {'term': 'A Record', 'definition': 'Maps domain to IPv4 address (like 192.168.1.1)'},
                {'term': 'MX Record', 'definition': 'Points to mail servers that handle email for the domain'},
                {'term': 'NS Record', 'definition': 'Shows which nameservers are authoritative for the domain'},
                {'term': 'TXT Record', 'definition': 'Text information, often used for verification'},
            ],
            'success_looks_like': '''Domain: example.com
A Record: 93.184.216.34
MX Record: mail.example.com (priority 10)
NS Record: ns1.example.com, ns2.example.com''',
            'expected_output': 'DNS records for the specified domain',
            'warnings': [],
            'prerequisites': ['DNS resolution working'],
        },
        'inputs': [
            {
                'name': 'domain',
                'type': INPUT_TEXT,
                'label': 'Domain',
                'placeholder': 'example.com',
                'required': True,
            },
            {
                'name': 'record_type',
                'type': INPUT_DROPDOWN,
                'label': 'Record Type',
                'options': [
                    {'value': 'A', 'label': 'A (IPv4)'},
                    {'value': 'AAAA', 'label': 'AAAA (IPv6)'},
                    {'value': 'MX', 'label': 'MX (Mail)'},
                    {'value': 'NS', 'label': 'NS (Nameserver)'},
                    {'value': 'TXT', 'label': 'TXT'},
                    {'value': 'ALL', 'label': 'All Types'},
                ],
                'default': 'A',
                'flag': '-t',
            },
        ],
        'presets': [
            {'name': 'Get IP', 'values': {'record_type': 'A'}},
            {'name': 'All Records', 'values': {'record_type': 'ALL'}},
        ],
    },

    'whois': {
        'id': 'whois',
        'name': 'WHOIS',
        'script': 'whois_lookup.py',
        'category': 'network',
        'icon': 'info',
        'docs': {
            'short_desc': 'WHOIS domain lookup',
            'full_desc': '''Queries WHOIS databases to get domain registration information
including registrar, creation date, expiration, and contact details.''',
            'when_to_use': [
                'Finding domain ownership information',
                'Checking domain registration dates',
                'OSINT reconnaissance',
            ],
            'expected_output': 'Domain registration details',
            'warnings': ['Some domains have privacy protection'],
            'prerequisites': [],
        },
        'inputs': [
            {
                'name': 'domain',
                'type': INPUT_TEXT,
                'label': 'Domain',
                'placeholder': 'example.com',
                'required': True,
            },
        ],
        'presets': [],
    },

    'ssl_check': {
        'id': 'ssl_check',
        'name': 'SSL Check',
        'script': 'ssl_check.py',
        'category': 'network',
        'icon': 'lock',
        'docs': {
            'short_desc': 'SSL certificate checker',
            'full_desc': '''Analyzes SSL/TLS certificates for validity, expiration,
and security configuration.''',
            'when_to_use': [
                'Checking certificate expiration',
                'Verifying SSL configuration',
                'Security assessments',
            ],
            'expected_output': 'Certificate details and security status',
            'warnings': [],
            'prerequisites': ['HTTPS endpoint'],
        },
        'inputs': [
            {
                'name': 'host',
                'type': INPUT_TEXT,
                'label': 'Host',
                'placeholder': 'example.com',
                'required': True,
            },
            {
                'name': 'port',
                'type': INPUT_NUMBER,
                'label': 'Port',
                'placeholder': '443',
                'default': '443',
                'flag': '-p',
            },
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'password_gen': {
        'id': 'password_gen',
        'name': 'Password Gen',
        'script': 'password_gen.py',
        'category': 'security',
        'icon': 'key',
        'skill_level': 'beginner',
        'docs': {
            'short_desc': 'Secure password generator',
            'full_desc': '''Generates cryptographically secure random passwords with
customizable length and character sets.''',
            'concept_explanation': {
                'title': 'Why Use a Password Generator?',
                'simple': '''Humans are terrible at creating random passwords. We use patterns,
birthdays, pet names - things hackers can guess. A password generator creates
truly random passwords that are much harder to crack.

A 16-character random password would take millions of years to crack by guessing!''',
                'analogy': '''Imagine picking a locker combination. You might pick 1234 or
your birthday - easy to guess! A password generator is like blindfolding yourself
and spinning the dial randomly - nobody can predict what you'll land on.''',
                'why_it_matters': '''Strong passwords protect:
• Your email and social media
• Your bank and financial accounts
• Your personal data and identity
• Your work and sensitive information''',
            },
            'when_to_use': [
                'Creating new account passwords',
                'Generating API keys',
                'Creating secure tokens',
                'Replacing weak passwords you currently use',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Choose Length', 'instruction': '16 characters is good for most uses. 32+ for high-security accounts like banking or email.', 'tip': 'Longer is always stronger! 16 is minimum recommended.'},
                {'step': 2, 'title': 'Select Character Types', 'instruction': 'Keep all boxes checked for strongest passwords. Uncheck symbols only if a site doesnt allow them.', 'tip': 'More character types = harder to crack.'},
                {'step': 3, 'title': 'Generate Multiple', 'instruction': 'Set count to 3-5 if you want options to choose from.', 'tip': 'Pick one that seems easiest to type if you need to enter it manually.'},
                {'step': 4, 'title': 'Save It Safely', 'instruction': 'Copy the password and store it in a password manager, NOT in a text file or sticky note!', 'tip': 'Use a password manager like Bitwarden, 1Password, or your phone\'s built-in manager.'},
            ],
            'common_mistakes': [
                {'mistake': 'Making passwords too short', 'fix': 'Always use at least 16 characters. 8 is too weak for modern computers.'},
                {'mistake': 'Removing character types', 'fix': 'Keep uppercase, numbers, AND symbols unless the site forbids them.'},
                {'mistake': 'Writing password on paper', 'fix': 'Use a password manager instead. Paper can be lost or seen by others.'},
                {'mistake': 'Reusing passwords', 'fix': 'Generate a unique password for EVERY account.'},
            ],
            'glossary': [
                {'term': 'Cryptographically Secure', 'definition': 'Randomness that cannot be predicted, even by powerful computers'},
                {'term': 'Character Set', 'definition': 'The types of characters used: lowercase, uppercase, numbers, symbols'},
                {'term': 'Entropy', 'definition': 'A measure of randomness/unpredictability - higher is better'},
                {'term': 'Password Manager', 'definition': 'App that securely stores all your passwords so you only remember one'},
            ],
            'success_looks_like': '''Generated Password:
K#9xMp$2vNq&8LwR

Strength: VERY STRONG
Length: 16 characters
Contains: Uppercase, lowercase, numbers, symbols''',
            'expected_output': 'Random password string',
            'warnings': ['Store passwords securely - use a password manager'],
            'prerequisites': [],
        },
        'inputs': [
            {
                'name': 'length',
                'type': INPUT_NUMBER,
                'label': 'Length',
                'placeholder': '16',
                'default': '16',
                'required': True,
                'flag': '--length',
            },
            {
                'name': 'count',
                'type': INPUT_NUMBER,
                'label': 'Count',
                'placeholder': '1',
                'default': '1',
                'help': 'Number of passwords to generate',
                'flag': '-c',
            },
            {
                'name': 'uppercase',
                'type': INPUT_CHECKBOX,
                'label': 'Include Uppercase',
                'default': True,
            },
            {
                'name': 'numbers',
                'type': INPUT_CHECKBOX,
                'label': 'Include Numbers',
                'default': True,
            },
            {
                'name': 'symbols',
                'type': INPUT_CHECKBOX,
                'label': 'Include Symbols',
                'default': True,
            },
        ],
        'presets': [
            {'name': 'Strong (16)', 'values': {'length': '16'}},
            {'name': 'Very Strong (32)', 'values': {'length': '32'}},
            {'name': 'PIN (6)', 'values': {'length': '6', 'uppercase': False, 'symbols': False}},
        ],
    },

    'hasher': {
        'id': 'hasher',
        'name': 'Hasher',
        'script': 'hasher.py',
        'category': 'security',
        'icon': 'hash',
        'skill_level': 'beginner',
        'docs': {
            'short_desc': 'Generate and identify hashes',
            'full_desc': '''Generates various hash types from input text including MD5,
SHA1, SHA256, SHA512, and more.''',
            'concept_explanation': {
                'title': 'What is a Hash?',
                'simple': '''A hash is like a digital fingerprint. You put ANY text or file in,
and you get a fixed-length code out. The same input ALWAYS gives the same hash,
but you can't reverse it to get the original back.

For example, "password" always becomes "5f4dcc3b5aa765d61d8327deb882cf99" (MD5).
But you can't turn that code back into "password" - it only works one way.''',
                'analogy': '''Imagine a meat grinder. You put beef in, and hamburger comes out.
You can always get the same hamburger from the same beef, but you can't turn
hamburger back into the original steak. Hashing works the same way - it's a
one-way transformation.''',
                'why_it_matters': '''Hashing is used everywhere:
• Storing passwords (websites don't save your actual password, just its hash)
• Verifying file downloads (check the hash matches to ensure no tampering)
• Digital signatures and blockchain
• Detecting duplicate files''',
            },
            'when_to_use': [
                'Creating file checksums',
                'Learning about password security',
                'Verifying file integrity',
                'Understanding how passwords are stored',
            ],
            'step_by_step': [
                {'step': 1, 'title': 'Enter Text', 'instruction': 'Type any text you want to hash - a word, sentence, or password you want to see the hash for.', 'tip': 'Try "password" or "hello" to see common hash values.'},
                {'step': 2, 'title': 'Choose Algorithm', 'instruction': 'Select "All Types" to see multiple hash formats, or pick a specific one like SHA256.', 'tip': 'SHA256 is the modern standard. MD5 and SHA1 are older and weaker.'},
                {'step': 3, 'title': 'Compare Hashes', 'instruction': 'Notice how even a tiny change (like "Password" vs "password") gives completely different hashes.', 'tip': 'This is called the avalanche effect - small changes cause big hash differences.'},
            ],
            'common_mistakes': [
                {'mistake': 'Expecting to reverse a hash', 'fix': 'Hashes are one-way only. You cannot recover the original text from a hash.'},
                {'mistake': 'Using MD5 for security', 'fix': 'MD5 is broken for security. Use SHA256 or better for anything sensitive.'},
                {'mistake': 'Adding extra spaces', 'fix': 'Spaces count! "hello" and "hello " give different hashes.'},
            ],
            'glossary': [
                {'term': 'Hash', 'definition': 'A fixed-length code generated from any input using a mathematical function'},
                {'term': 'MD5', 'definition': 'An older hash algorithm - 32 hex characters. Considered weak now.'},
                {'term': 'SHA256', 'definition': 'Modern secure hash - 64 hex characters. Standard for security.'},
                {'term': 'Collision', 'definition': 'When two different inputs produce the same hash (very rare for good algorithms)'},
                {'term': 'Checksum', 'definition': 'A hash used to verify a file hasnt been modified'},
            ],
            'success_looks_like': '''Input: hello

MD5:    5d41402abc4b2a76b9719d911017c592
SHA1:   aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824''',
            'expected_output': 'Hash values in various formats',
            'warnings': ['MD5 and SHA1 are considered weak - use SHA256 for security'],
            'prerequisites': [],
        },
        'inputs': [
            {
                'name': 'text',
                'type': INPUT_TEXT,
                'label': 'Text to Hash',
                'placeholder': 'Enter text...',
                'required': True,
            },
            {
                'name': 'algorithm',
                'type': INPUT_DROPDOWN,
                'label': 'Algorithm',
                'options': [
                    {'value': 'all', 'label': 'All Types'},
                    {'value': 'md5', 'label': 'MD5'},
                    {'value': 'sha1', 'label': 'SHA1'},
                    {'value': 'sha256', 'label': 'SHA256'},
                    {'value': 'sha512', 'label': 'SHA512'},
                ],
                'default': 'all',
                'flag': '--all',
            },
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # CLI UTILITIES
    # ═══════════════════════════════════════════════════════════════════════════
    'sysmon': {
        'id': 'sysmon',
        'name': 'System Monitor',
        'script': 'sysmon.py',
        'category': 'cli',
        'icon': 'monitor',
        'docs': {
            'short_desc': 'System resource monitor',
            'full_desc': '''Displays real-time system resource usage including CPU,
memory, disk, and network statistics.''',
            'when_to_use': [
                'Monitoring system performance',
                'Checking resource usage',
                'Diagnosing performance issues',
            ],
            'expected_output': 'System resource statistics',
            'warnings': [],
            'prerequisites': [],
        },
        'inputs': [
            {
                'name': 'continuous',
                'type': INPUT_CHECKBOX,
                'label': 'Continuous Update',
                'default': False,
                'help': 'Keep updating display',
                'flag': '-c',
            },
        ],
        'presets': [],
    },

    'qrcode': {
        'id': 'qrcode',
        'name': 'QR Code',
        'script': 'qrcode.py',
        'category': 'cli',
        'icon': 'qr',
        'docs': {
            'short_desc': 'QR code generator',
            'full_desc': '''Generates QR codes from text or URLs, outputting to
terminal or image file.''',
            'when_to_use': [
                'Creating QR codes for links',
                'Encoding text in QR format',
                'Quick sharing of URLs',
            ],
            'expected_output': 'QR code image or terminal display',
            'warnings': [],
            'prerequisites': [],
        },
        'inputs': [
            {
                'name': 'data',
                'type': INPUT_TEXT,
                'label': 'Data/URL',
                'placeholder': 'https://example.com',
                'required': True,
            },
            {
                'name': 'output',
                'type': INPUT_TEXT,
                'label': 'Output File',
                'placeholder': 'qrcode.png',
                'help': 'Leave empty for terminal display',
                'flag': '-o',
            },
        ],
        'presets': [],
    },

    'weather': {
        'id': 'weather',
        'name': 'Weather',
        'script': 'weather.py',
        'category': 'cli',
        'icon': 'cloud',
        'docs': {
            'short_desc': 'Weather lookup',
            'full_desc': '''Fetches current weather and forecast for a specified location.''',
            'when_to_use': [
                'Checking current weather',
                'Getting weather forecast',
            ],
            'expected_output': 'Weather conditions and forecast',
            'warnings': ['Requires internet connection'],
            'prerequisites': [],
        },
        'inputs': [
            {
                'name': 'location',
                'type': INPUT_TEXT,
                'label': 'Location',
                'placeholder': 'New York',
                'required': True,
            },
        ],
        'presets': [],
    },
}


def get_tool(tool_id):
    """Get tool metadata by ID"""
    return TOOLS.get(tool_id)


def get_tools_by_category(category):
    """Get all tools in a category"""
    return [t for t in TOOLS.values() if t['category'] == category]


def get_all_tools():
    """Get all tools"""
    return list(TOOLS.values())


def get_categories():
    """Get all categories with their tools"""
    return CATEGORIES


def search_tools(query):
    """Search tools by name or description"""
    query = query.lower()
    results = []
    for tool in TOOLS.values():
        if (query in tool['name'].lower() or
            query in tool['docs']['short_desc'].lower() or
            query in tool.get('docs', {}).get('full_desc', '').lower()):
            results.append(tool)
    return results


# Import extended tools to merge with base tools
try:
    from .tool_registry_full import EXTENDED_TOOLS
    TOOLS.update(EXTENDED_TOOLS)
except ImportError:
    pass  # Extended tools not available


def build_command(tool_id, values):
    """Build command string from form values"""
    tool = get_tool(tool_id)
    if not tool:
        return None

    parts = [tool['script']]

    for inp in tool.get('inputs', []):
        name = inp['name']
        value = values.get(name)

        if value is None or value == '':
            continue

        flag = inp.get('flag')
        input_type = inp['type']

        if input_type == INPUT_CHECKBOX:
            if value:
                parts.append(flag)
        elif flag:
            if input_type == INPUT_DROPDOWN:
                if value != inp.get('default'):
                    parts.append(f"{flag} {value}")
            else:
                parts.append(f"{flag} {value}")
        else:
            # Positional argument
            parts.append(str(value))

    return ' '.join(parts)
