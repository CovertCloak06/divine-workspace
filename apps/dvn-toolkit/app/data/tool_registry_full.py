"""
Full Tool Registry - Complete metadata for all 126+ tools
This extends the base tool_registry with all tools
"""

from .tool_registry import (
    INPUT_TEXT, INPUT_NUMBER, INPUT_DROPDOWN, INPUT_CHECKBOX,
    INPUT_FILE, INPUT_IP, INPUT_URL, INPUT_PORT_RANGE,
    CATEGORIES, TOOLS as BASE_TOOLS
)

# Extended tools - add all remaining tools with basic metadata
# These can be enhanced with full documentation over time

EXTENDED_TOOLS = {
    # ═══════════════════════════════════════════════════════════════════════════
    # OFFENSIVE SECURITY - Additional tools
    # ═══════════════════════════════════════════════════════════════════════════
    'lfi_scanner': {
        'id': 'lfi_scanner',
        'name': 'LFI Scanner',
        'script': 'lfi_scanner.py',
        'category': 'offensive',
        'icon': 'file',
        'docs': {
            'short_desc': 'Local/remote file inclusion testing',
            'full_desc': 'Tests for LFI/RFI vulnerabilities by attempting various path traversal patterns.',
            'when_to_use': ['Testing file parameter vulnerabilities', 'CTF challenges'],
            'warnings': ['Only test authorized targets'],
        },
        'inputs': [
            {'name': 'url', 'type': INPUT_URL, 'label': 'Target URL', 'required': True, 'flag': '-u'},
            {'name': 'level', 'type': INPUT_DROPDOWN, 'label': 'Test Level',
             'options': [{'value': '1', 'label': 'Basic'}, {'value': '2', 'label': 'Extended'}, {'value': '3', 'label': 'Full'}],
             'flag': '--level'},
        ],
        'presets': [{'name': 'Quick Test', 'values': {'level': '1'}}],
    },

    'web_fuzzer': {
        'id': 'web_fuzzer',
        'name': 'Web Fuzzer',
        'script': 'web_fuzzer.py',
        'category': 'offensive',
        'icon': 'web',
        'docs': {
            'short_desc': 'Directory and file enumeration',
            'full_desc': 'Discovers hidden files and directories on web servers using wordlists.',
            'when_to_use': ['Finding hidden admin panels', 'Discovering backup files'],
            'warnings': ['May trigger WAF/IDS'],
        },
        'inputs': [
            {'name': 'url', 'type': INPUT_URL, 'label': 'Target URL', 'required': True},
            {'name': 'wordlist', 'type': INPUT_FILE, 'label': 'Wordlist', 'flag': '-w'},
            {'name': 'extensions', 'type': INPUT_TEXT, 'label': 'Extensions', 'placeholder': 'php,txt,bak', 'flag': '-x'},
        ],
        'presets': [{'name': 'Quick Scan', 'values': {}}],
    },

    'bruteforce': {
        'id': 'bruteforce',
        'name': 'Bruteforce',
        'script': 'bruteforce.py',
        'category': 'offensive',
        'icon': 'key',
        'docs': {
            'short_desc': 'Credential brute force testing',
            'full_desc': 'Tests login forms and services for weak credentials.',
            'when_to_use': ['Testing password policies', 'Authorized pentests'],
            'warnings': ['Can lock accounts', 'Only use with authorization'],
        },
        'inputs': [
            {'name': 'url', 'type': INPUT_URL, 'label': 'Target URL', 'flag': '-u'},
            {'name': 'username', 'type': INPUT_TEXT, 'label': 'Username', 'flag': '-U'},
            {'name': 'wordlist', 'type': INPUT_FILE, 'label': 'Password List', 'flag': '-P'},
        ],
        'presets': [],
    },

    'webshell_gen': {
        'id': 'webshell_gen',
        'name': 'Webshell Gen',
        'script': 'webshell_gen.py',
        'category': 'offensive',
        'icon': 'terminal',
        'docs': {
            'short_desc': 'Generate webshell files',
            'full_desc': 'Creates PHP/ASP/JSP webshells for authorized penetration testing.',
            'when_to_use': ['After file upload vulnerability', 'CTF challenges'],
            'warnings': ['Only use on authorized systems'],
        },
        'inputs': [
            {'name': 'type', 'type': INPUT_DROPDOWN, 'label': 'Shell Type',
             'options': [{'value': 'php_simple', 'label': 'PHP Simple'}, {'value': 'php_full', 'label': 'PHP Full'},
                        {'value': 'asp', 'label': 'ASP'}, {'value': 'jsp', 'label': 'JSP'}],
             'flag': '-t'},
            {'name': 'output', 'type': INPUT_TEXT, 'label': 'Output File', 'flag': '-o'},
            {'name': 'obfuscate', 'type': INPUT_CHECKBOX, 'label': 'Obfuscate', 'flag': '--obfuscate'},
        ],
        'presets': [],
    },

    'wordlist_gen': {
        'id': 'wordlist_gen',
        'name': 'Wordlist Gen',
        'script': 'wordlist_gen.py',
        'category': 'offensive',
        'icon': 'list',
        'docs': {
            'short_desc': 'Custom wordlist generator',
            'full_desc': 'Generates targeted wordlists from keywords, personal info, and patterns.',
            'when_to_use': ['Creating custom password lists', 'Targeted attacks'],
        },
        'inputs': [
            {'name': 'target', 'type': INPUT_TEXT, 'label': 'Target Info', 'placeholder': 'john smith 1985', 'flag': '--target'},
            {'name': 'output', 'type': INPUT_TEXT, 'label': 'Output File', 'flag': '-o'},
        ],
        'presets': [],
    },

    'payload_encoder': {
        'id': 'payload_encoder',
        'name': 'Payload Encoder',
        'script': 'payload_encoder.py',
        'category': 'offensive',
        'icon': 'code',
        'docs': {
            'short_desc': 'Encode payloads for bypass',
            'full_desc': 'Encodes payloads in various formats to bypass filters and WAFs.',
            'when_to_use': ['Bypassing input filters', 'WAF evasion testing'],
        },
        'inputs': [
            {'name': 'payload', 'type': INPUT_TEXT, 'label': 'Payload', 'required': True, 'flag': '-p'},
            {'name': 'all', 'type': INPUT_CHECKBOX, 'label': 'All Encodings', 'flag': '--all'},
            {'name': 'url', 'type': INPUT_CHECKBOX, 'label': 'URL Encode', 'flag': '--url'},
        ],
        'presets': [],
    },

    'smb_enum': {
        'id': 'smb_enum',
        'name': 'SMB Enum',
        'script': 'smb_enum.py',
        'category': 'offensive',
        'icon': 'network',
        'docs': {
            'short_desc': 'Windows SMB share enumeration',
            'full_desc': 'Enumerates SMB shares, users, and permissions on Windows systems.',
            'when_to_use': ['Windows network enumeration', 'Finding open shares'],
        },
        'inputs': [
            {'name': 'target', 'type': INPUT_IP, 'label': 'Target IP', 'required': True},
            {'name': 'username', 'type': INPUT_TEXT, 'label': 'Username', 'flag': '-u'},
            {'name': 'password', 'type': INPUT_TEXT, 'label': 'Password', 'flag': '-p'},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'creds': {
        'id': 'creds',
        'name': 'Credential Check',
        'script': 'creds.py',
        'category': 'security',
        'docs': {
            'short_desc': 'Password strength and breach check',
            'full_desc': 'Analyzes password strength and checks against known breach databases.',
            'when_to_use': ['Checking password security', 'Breach checking'],
        },
        'inputs': [
            {'name': 'password', 'type': INPUT_TEXT, 'label': 'Password to Check', 'required': True},
            {'name': 'breach_check', 'type': INPUT_CHECKBOX, 'label': 'Check Breaches', 'flag': '--check-breach'},
        ],
        'presets': [],
    },

    'dirfuzz': {
        'id': 'dirfuzz',
        'name': 'Dir Fuzzer',
        'script': 'dirfuzz.py',
        'category': 'security',
        'docs': {'short_desc': 'Web directory enumeration'},
        'inputs': [
            {'name': 'url', 'type': INPUT_URL, 'label': 'Target URL', 'required': True},
        ],
        'presets': [],
    },

    'encoder': {
        'id': 'encoder',
        'name': 'Encoder',
        'script': 'encoder.py',
        'category': 'security',
        'docs': {'short_desc': 'Multi-format encoding/decoding'},
        'inputs': [
            {'name': 'text', 'type': INPUT_TEXT, 'label': 'Text', 'required': True},
            {'name': 'all', 'type': INPUT_CHECKBOX, 'label': 'All Formats', 'flag': '--all'},
        ],
        'presets': [],
    },

    'hashcrack': {
        'id': 'hashcrack',
        'name': 'Hash Crack',
        'script': 'hashcrack.py',
        'category': 'security',
        'docs': {'short_desc': 'Hash cracking with wordlists'},
        'inputs': [
            {'name': 'hash', 'type': INPUT_TEXT, 'label': 'Hash', 'required': True},
            {'name': 'wordlist', 'type': INPUT_FILE, 'label': 'Wordlist', 'flag': '--wordlist'},
        ],
        'presets': [],
    },

    'netsniff': {
        'id': 'netsniff',
        'name': 'Net Sniffer',
        'script': 'netsniff.py',
        'category': 'security',
        'docs': {'short_desc': 'Network packet sniffer'},
        'inputs': [
            {'name': 'interface', 'type': INPUT_TEXT, 'label': 'Interface', 'flag': '-i'},
        ],
        'presets': [],
    },

    'payloads': {
        'id': 'payloads',
        'name': 'Payloads',
        'script': 'payloads.py',
        'category': 'security',
        'docs': {'short_desc': 'Security testing payloads'},
        'inputs': [
            {'name': 'type', 'type': INPUT_DROPDOWN, 'label': 'Type',
             'options': [{'value': 'xss', 'label': 'XSS'}, {'value': 'sqli', 'label': 'SQLi'}],
             'flag': '--type'},
        ],
        'presets': [],
    },

    'portscan_adv': {
        'id': 'portscan_adv',
        'name': 'Port Scan Adv',
        'script': 'portscan_adv.py',
        'category': 'security',
        'docs': {'short_desc': 'Advanced port scanner'},
        'inputs': [
            {'name': 'target', 'type': INPUT_IP, 'label': 'Target', 'required': True},
            {'name': 'common', 'type': INPUT_CHECKBOX, 'label': 'Common Ports', 'flag': '--common'},
            {'name': 'banner', 'type': INPUT_CHECKBOX, 'label': 'Grab Banners', 'flag': '--banner'},
        ],
        'presets': [],
    },

    'recon': {
        'id': 'recon',
        'name': 'Recon',
        'script': 'recon.py',
        'category': 'security',
        'docs': {'short_desc': 'Target reconnaissance'},
        'inputs': [
            {'name': 'target', 'type': INPUT_TEXT, 'label': 'Target Domain', 'required': True},
            {'name': 'all', 'type': INPUT_CHECKBOX, 'label': 'All Checks', 'flag': '--all'},
        ],
        'presets': [],
    },

    'stego': {
        'id': 'stego',
        'name': 'Steganography',
        'script': 'stego.py',
        'category': 'security',
        'docs': {'short_desc': 'Hide data in images'},
        'inputs': [
            {'name': 'action', 'type': INPUT_DROPDOWN, 'label': 'Action',
             'options': [{'value': 'hide', 'label': 'Hide'}, {'value': 'extract', 'label': 'Extract'}]},
            {'name': 'image', 'type': INPUT_FILE, 'label': 'Image File'},
            {'name': 'data', 'type': INPUT_TEXT, 'label': 'Data/File'},
        ],
        'presets': [],
    },

    'subenum': {
        'id': 'subenum',
        'name': 'Subdomain Enum',
        'script': 'subenum.py',
        'category': 'security',
        'docs': {'short_desc': 'Subdomain enumeration'},
        'inputs': [
            {'name': 'domain', 'type': INPUT_TEXT, 'label': 'Domain', 'required': True},
        ],
        'presets': [],
    },

    'techdetect': {
        'id': 'techdetect',
        'name': 'Tech Detect',
        'script': 'techdetect.py',
        'category': 'security',
        'docs': {'short_desc': 'Detect web technologies'},
        'inputs': [
            {'name': 'url', 'type': INPUT_URL, 'label': 'URL', 'required': True},
        ],
        'presets': [],
    },

    'webscrape': {
        'id': 'webscrape',
        'name': 'Web Scraper',
        'script': 'webscrape.py',
        'category': 'security',
        'docs': {'short_desc': 'Web page scraping'},
        'inputs': [
            {'name': 'url', 'type': INPUT_URL, 'label': 'URL', 'required': True},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'arp_scan': {
        'id': 'arp_scan',
        'name': 'ARP Scan',
        'script': 'arp_scan.py',
        'category': 'network',
        'docs': {'short_desc': 'ARP network scanner'},
        'inputs': [{'name': 'network', 'type': INPUT_IP, 'label': 'Network Range'}],
        'presets': [],
    },

    'bandwidth': {
        'id': 'bandwidth',
        'name': 'Bandwidth',
        'script': 'bandwidth.py',
        'category': 'network',
        'docs': {'short_desc': 'Bandwidth monitor'},
        'inputs': [],
        'presets': [],
    },

    'banner_grab': {
        'id': 'banner_grab',
        'name': 'Banner Grab',
        'script': 'banner_grab.py',
        'category': 'network',
        'docs': {'short_desc': 'Service banner grabber'},
        'inputs': [
            {'name': 'target', 'type': INPUT_IP, 'label': 'Target', 'required': True},
            {'name': 'port', 'type': INPUT_NUMBER, 'label': 'Port', 'required': True},
        ],
        'presets': [],
    },

    'domain_recon': {
        'id': 'domain_recon',
        'name': 'Domain Recon',
        'script': 'domain_recon.py',
        'category': 'network',
        'docs': {'short_desc': 'Domain reconnaissance'},
        'inputs': [{'name': 'domain', 'type': INPUT_TEXT, 'label': 'Domain', 'required': True}],
        'presets': [],
    },

    'email_osint': {
        'id': 'email_osint',
        'name': 'Email OSINT',
        'script': 'email_osint.py',
        'category': 'network',
        'docs': {'short_desc': 'Email OSINT lookup'},
        'inputs': [{'name': 'email', 'type': INPUT_TEXT, 'label': 'Email', 'required': True}],
        'presets': [],
    },

    'header_analyzer': {
        'id': 'header_analyzer',
        'name': 'Header Analyzer',
        'script': 'header_analyzer.py',
        'category': 'network',
        'docs': {'short_desc': 'HTTP header analysis'},
        'inputs': [{'name': 'url', 'type': INPUT_URL, 'label': 'URL', 'required': True}],
        'presets': [],
    },

    'http_server': {
        'id': 'http_server',
        'name': 'HTTP Server',
        'script': 'http_server.py',
        'category': 'network',
        'docs': {'short_desc': 'Quick HTTP server'},
        'inputs': [
            {'name': 'port', 'type': INPUT_NUMBER, 'label': 'Port', 'default': '8000'},
        ],
        'presets': [],
    },

    'ip_geolocate': {
        'id': 'ip_geolocate',
        'name': 'IP Geolocate',
        'script': 'ip_geolocate.py',
        'category': 'network',
        'docs': {'short_desc': 'IP geolocation lookup'},
        'inputs': [{'name': 'ip', 'type': INPUT_IP, 'label': 'IP Address', 'required': True}],
        'presets': [],
    },

    'mac_lookup': {
        'id': 'mac_lookup',
        'name': 'MAC Lookup',
        'script': 'mac_lookup.py',
        'category': 'network',
        'docs': {'short_desc': 'MAC address lookup'},
        'inputs': [{'name': 'mac', 'type': INPUT_TEXT, 'label': 'MAC Address', 'required': True}],
        'presets': [],
    },

    'net_monitor': {
        'id': 'net_monitor',
        'name': 'Net Monitor',
        'script': 'net_monitor.py',
        'category': 'network',
        'docs': {'short_desc': 'Network traffic monitor'},
        'inputs': [],
        'presets': [],
    },

    'portscanner': {
        'id': 'portscanner',
        'name': 'Port Scanner',
        'script': 'portscanner.py',
        'category': 'network',
        'docs': {'short_desc': 'Basic port scanner'},
        'inputs': [
            {'name': 'target', 'type': INPUT_IP, 'label': 'Target', 'required': True},
            {'name': 'ports', 'type': INPUT_PORT_RANGE, 'label': 'Port Range'},
        ],
        'presets': [],
    },

    'reverse_dns': {
        'id': 'reverse_dns',
        'name': 'Reverse DNS',
        'script': 'reverse_dns.py',
        'category': 'network',
        'docs': {'short_desc': 'Reverse DNS lookup'},
        'inputs': [{'name': 'ip', 'type': INPUT_IP, 'label': 'IP Address', 'required': True}],
        'presets': [],
    },

    'social_recon': {
        'id': 'social_recon',
        'name': 'Social Recon',
        'script': 'social_recon.py',
        'category': 'network',
        'docs': {'short_desc': 'Social media recon'},
        'inputs': [{'name': 'username', 'type': INPUT_TEXT, 'label': 'Username', 'required': True}],
        'presets': [],
    },

    'speedtest': {
        'id': 'speedtest',
        'name': 'Speed Test',
        'script': 'speedtest.py',
        'category': 'network',
        'docs': {'short_desc': 'Internet speed test'},
        'inputs': [],
        'presets': [],
    },

    'ssh_manager': {
        'id': 'ssh_manager',
        'name': 'SSH Manager',
        'script': 'ssh_manager.py',
        'category': 'network',
        'docs': {'short_desc': 'SSH connection manager'},
        'inputs': [],
        'presets': [],
    },

    'subnet_calc': {
        'id': 'subnet_calc',
        'name': 'Subnet Calc',
        'script': 'subnet_calc.py',
        'category': 'network',
        'docs': {'short_desc': 'Subnet calculator'},
        'inputs': [{'name': 'cidr', 'type': INPUT_TEXT, 'label': 'CIDR', 'placeholder': '192.168.1.0/24'}],
        'presets': [],
    },

    'traceroute': {
        'id': 'traceroute',
        'name': 'Traceroute',
        'script': 'traceroute_visual.py',
        'category': 'network',
        'docs': {'short_desc': 'Visual traceroute'},
        'inputs': [{'name': 'target', 'type': INPUT_TEXT, 'label': 'Target', 'required': True}],
        'presets': [],
    },

    'username_search': {
        'id': 'username_search',
        'name': 'Username Search',
        'script': 'username_search.py',
        'category': 'network',
        'docs': {'short_desc': 'Username OSINT search'},
        'inputs': [{'name': 'username', 'type': INPUT_TEXT, 'label': 'Username', 'required': True}],
        'presets': [],
    },

    'wifi_scan': {
        'id': 'wifi_scan',
        'name': 'WiFi Scan',
        'script': 'wifi_scan.py',
        'category': 'network',
        'docs': {'short_desc': 'WiFi network scanner'},
        'inputs': [],
        'presets': [],
    },

    'wol': {
        'id': 'wol',
        'name': 'Wake on LAN',
        'script': 'wol.py',
        'category': 'network',
        'docs': {'short_desc': 'Wake on LAN utility'},
        'inputs': [{'name': 'mac', 'type': INPUT_TEXT, 'label': 'MAC Address', 'required': True}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # PENTEST TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'privesc': {
        'id': 'privesc',
        'name': 'PrivEsc Checker',
        'script': 'privesc_checker.py',
        'category': 'pentest',
        'docs': {
            'short_desc': 'Find privilege escalation vectors',
            'full_desc': 'Checks for common Linux privilege escalation paths.',
        },
        'inputs': [
            {'name': 'all', 'type': INPUT_CHECKBOX, 'label': 'All Checks', 'flag': '-a'},
            {'name': 'suid', 'type': INPUT_CHECKBOX, 'label': 'SUID/SGID', 'flag': '--suid'},
            {'name': 'caps', 'type': INPUT_CHECKBOX, 'label': 'Capabilities', 'flag': '--caps'},
        ],
        'presets': [{'name': 'Full Scan', 'values': {'all': True}}],
    },

    'persistence': {
        'id': 'persistence',
        'name': 'Persistence Check',
        'script': 'persistence_checker.py',
        'category': 'pentest',
        'docs': {'short_desc': 'Detect backdoors and persistence'},
        'inputs': [
            {'name': 'all', 'type': INPUT_CHECKBOX, 'label': 'All Checks', 'flag': '-a'},
        ],
        'presets': [],
    },

    'kernel': {
        'id': 'kernel',
        'name': 'Kernel Exploits',
        'script': 'kernel_exploits.py',
        'category': 'pentest',
        'docs': {'short_desc': 'Suggest kernel exploits'},
        'inputs': [
            {'name': 'kernel', 'type': INPUT_TEXT, 'label': 'Kernel Version', 'flag': '-k'},
            {'name': 'all', 'type': INPUT_CHECKBOX, 'label': 'Show All', 'flag': '--all'},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # ANDROID TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'adb': {
        'id': 'adb',
        'name': 'ADB Toolkit',
        'script': 'adb_toolkit.py',
        'category': 'android',
        'docs': {'short_desc': 'ADB automation commands'},
        'inputs': [
            {'name': 'command', 'type': INPUT_DROPDOWN, 'label': 'Command',
             'options': [
                 {'value': 'devices', 'label': 'List Devices'},
                 {'value': 'info', 'label': 'Device Info'},
                 {'value': 'packages', 'label': 'List Packages'},
                 {'value': 'screenshot', 'label': 'Screenshot'},
             ]},
        ],
        'presets': [],
    },

    'apk': {
        'id': 'apk',
        'name': 'APK Analyzer',
        'script': 'apk_analyzer.py',
        'category': 'android',
        'docs': {'short_desc': 'APK security analysis'},
        'inputs': [
            {'name': 'apk', 'type': INPUT_FILE, 'label': 'APK File', 'required': True},
        ],
        'presets': [],
    },

    'logcat': {
        'id': 'logcat',
        'name': 'Logcat Parser',
        'script': 'logcat_parser.py',
        'category': 'android',
        'docs': {'short_desc': 'Parse logcat for secrets'},
        'inputs': [
            {'name': 'file', 'type': INPUT_FILE, 'label': 'Log File'},
            {'name': 'secrets', 'type': INPUT_CHECKBOX, 'label': 'Find Secrets', 'flag': '-s'},
        ],
        'presets': [],
    },

    'permissions': {
        'id': 'permissions',
        'name': 'App Permissions',
        'script': 'app_permissions.py',
        'category': 'android',
        'docs': {'short_desc': 'Scan app permissions'},
        'inputs': [
            {'name': 'package', 'type': INPUT_TEXT, 'label': 'Package Name', 'flag': '-p'},
            {'name': 'risk', 'type': INPUT_NUMBER, 'label': 'Min Risk Score', 'flag': '-r'},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # CRYPTO TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'baseconv': {
        'id': 'baseconv',
        'name': 'Base Convert',
        'script': 'baseconv.py',
        'category': 'crypto',
        'docs': {'short_desc': 'Base conversion tool'},
        'inputs': [{'name': 'input', 'type': INPUT_TEXT, 'label': 'Input', 'required': True}],
        'presets': [],
    },

    'cipher': {
        'id': 'cipher',
        'name': 'Cipher',
        'script': 'cipher.py',
        'category': 'crypto',
        'docs': {'short_desc': 'Classical ciphers'},
        'inputs': [
            {'name': 'text', 'type': INPUT_TEXT, 'label': 'Text', 'required': True},
            {'name': 'cipher', 'type': INPUT_DROPDOWN, 'label': 'Cipher',
             'options': [{'value': 'caesar', 'label': 'Caesar'}, {'value': 'vigenere', 'label': 'Vigenere'},
                        {'value': 'rot13', 'label': 'ROT13'}]},
        ],
        'presets': [],
    },

    'encrypt': {
        'id': 'encrypt',
        'name': 'Encrypt',
        'script': 'encrypt.py',
        'category': 'crypto',
        'docs': {'short_desc': 'File encryption'},
        'inputs': [
            {'name': 'file', 'type': INPUT_FILE, 'label': 'File', 'required': True},
            {'name': 'password', 'type': INPUT_TEXT, 'label': 'Password', 'required': True},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # CLI UTILITIES
    # ═══════════════════════════════════════════════════════════════════════════
    'apitest': {
        'id': 'apitest',
        'name': 'API Test',
        'script': 'apitest.py',
        'category': 'cli',
        'docs': {'short_desc': 'API endpoint tester'},
        'inputs': [{'name': 'url', 'type': INPUT_URL, 'label': 'API URL', 'required': True}],
        'presets': [],
    },

    'asciiart': {
        'id': 'asciiart',
        'name': 'ASCII Art',
        'script': 'asciiart.py',
        'category': 'cli',
        'docs': {'short_desc': 'ASCII art generator'},
        'inputs': [{'name': 'text', 'type': INPUT_TEXT, 'label': 'Text', 'required': True}],
        'presets': [],
    },

    'calc': {
        'id': 'calc',
        'name': 'Calculator',
        'script': 'calc.py',
        'category': 'cli',
        'docs': {'short_desc': 'Command line calculator'},
        'inputs': [{'name': 'expr', 'type': INPUT_TEXT, 'label': 'Expression', 'required': True}],
        'presets': [],
    },

    'clipboard': {
        'id': 'clipboard',
        'name': 'Clipboard',
        'script': 'clipboard.py',
        'category': 'cli',
        'docs': {'short_desc': 'Clipboard manager'},
        'inputs': [{'name': 'text', 'type': INPUT_TEXT, 'label': 'Text', 'flag': '--copy'}],
        'presets': [],
    },

    'filefinder': {
        'id': 'filefinder',
        'name': 'File Finder',
        'script': 'filefinder.py',
        'category': 'cli',
        'docs': {'short_desc': 'Find duplicate files'},
        'inputs': [{'name': 'path', 'type': INPUT_TEXT, 'label': 'Directory', 'required': True}],
        'presets': [],
    },

    'fileorg': {
        'id': 'fileorg',
        'name': 'File Organizer',
        'script': 'fileorg.py',
        'category': 'cli',
        'docs': {'short_desc': 'Organize files by type'},
        'inputs': [
            {'name': 'path', 'type': INPUT_TEXT, 'label': 'Directory', 'required': True},
            {'name': 'by', 'type': INPUT_DROPDOWN, 'label': 'Organize By',
             'options': [{'value': 'type', 'label': 'Type'}, {'value': 'date', 'label': 'Date'}],
             'flag': '--by'},
        ],
        'presets': [],
    },

    'gitstat': {
        'id': 'gitstat',
        'name': 'Git Stats',
        'script': 'gitstat.py',
        'category': 'cli',
        'docs': {'short_desc': 'Git repository stats'},
        'inputs': [{'name': 'path', 'type': INPUT_TEXT, 'label': 'Repo Path', 'default': '.'}],
        'presets': [],
    },

    'jsonfmt': {
        'id': 'jsonfmt',
        'name': 'JSON Format',
        'script': 'jsonfmt.py',
        'category': 'cli',
        'docs': {'short_desc': 'JSON formatter'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'JSON File'}],
        'presets': [],
    },

    'logparse': {
        'id': 'logparse',
        'name': 'Log Parser',
        'script': 'logparse.py',
        'category': 'cli',
        'docs': {'short_desc': 'Log file parser'},
        'inputs': [
            {'name': 'file', 'type': INPUT_FILE, 'label': 'Log File', 'required': True},
            {'name': 'level', 'type': INPUT_DROPDOWN, 'label': 'Level',
             'options': [{'value': 'ERROR', 'label': 'Error'}, {'value': 'WARN', 'label': 'Warning'},
                        {'value': 'INFO', 'label': 'Info'}],
             'flag': '--level'},
        ],
        'presets': [],
    },

    'pwgen': {
        'id': 'pwgen',
        'name': 'Password Gen',
        'script': 'pwgen.py',
        'category': 'cli',
        'docs': {'short_desc': 'Password generator'},
        'inputs': [
            {'name': 'length', 'type': INPUT_NUMBER, 'label': 'Length', 'default': '16'},
            {'name': 'count', 'type': INPUT_NUMBER, 'label': 'Count', 'default': '1', 'flag': '-c'},
        ],
        'presets': [],
    },

    'qserver': {
        'id': 'qserver',
        'name': 'Quick Server',
        'script': 'qserver.py',
        'category': 'cli',
        'docs': {'short_desc': 'Quick HTTP server'},
        'inputs': [
            {'name': 'port', 'type': INPUT_NUMBER, 'label': 'Port', 'default': '8000'},
            {'name': 'upload', 'type': INPUT_CHECKBOX, 'label': 'Enable Upload', 'flag': '--upload'},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # DEV TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'curl_builder': {
        'id': 'curl_builder',
        'name': 'cURL Builder',
        'script': 'curl_builder.py',
        'category': 'dev',
        'docs': {'short_desc': 'Build cURL commands'},
        'inputs': [{'name': 'url', 'type': INPUT_URL, 'label': 'URL', 'required': True}],
        'presets': [],
    },

    'diff': {
        'id': 'diff',
        'name': 'Diff Tool',
        'script': 'diff_tool.py',
        'category': 'dev',
        'docs': {'short_desc': 'File diff comparison'},
        'inputs': [
            {'name': 'file1', 'type': INPUT_FILE, 'label': 'File 1', 'required': True},
            {'name': 'file2', 'type': INPUT_FILE, 'label': 'File 2', 'required': True},
        ],
        'presets': [],
    },

    'env': {
        'id': 'env',
        'name': 'Env Manager',
        'script': 'env_manager.py',
        'category': 'dev',
        'docs': {'short_desc': 'Environment manager'},
        'inputs': [],
        'presets': [],
    },

    'fakedata': {
        'id': 'fakedata',
        'name': 'Fake Data',
        'script': 'fakedata.py',
        'category': 'dev',
        'docs': {'short_desc': 'Generate fake data'},
        'inputs': [
            {'name': 'type', 'type': INPUT_DROPDOWN, 'label': 'Data Type',
             'options': [{'value': 'name', 'label': 'Name'}, {'value': 'email', 'label': 'Email'},
                        {'value': 'address', 'label': 'Address'}]},
        ],
        'presets': [],
    },

    'githelper': {
        'id': 'githelper',
        'name': 'Git Helper',
        'script': 'githelper.py',
        'category': 'dev',
        'docs': {'short_desc': 'Git helper utilities'},
        'inputs': [],
        'presets': [],
    },

    'json_tool': {
        'id': 'json_tool',
        'name': 'JSON Tool',
        'script': 'json_tool.py',
        'category': 'dev',
        'docs': {'short_desc': 'JSON manipulation'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'JSON File'}],
        'presets': [],
    },

    'lorem': {
        'id': 'lorem',
        'name': 'Lorem Ipsum',
        'script': 'lorem.py',
        'category': 'dev',
        'docs': {'short_desc': 'Lorem ipsum generator'},
        'inputs': [{'name': 'paragraphs', 'type': INPUT_NUMBER, 'label': 'Paragraphs', 'default': '3'}],
        'presets': [],
    },

    'snippets': {
        'id': 'snippets',
        'name': 'Snippets',
        'script': 'snippets.py',
        'category': 'dev',
        'docs': {'short_desc': 'Code snippets manager'},
        'inputs': [],
        'presets': [],
    },

    'uuid': {
        'id': 'uuid',
        'name': 'UUID Gen',
        'script': 'uuid_gen.py',
        'category': 'dev',
        'docs': {'short_desc': 'UUID generator'},
        'inputs': [{'name': 'count', 'type': INPUT_NUMBER, 'label': 'Count', 'default': '1'}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # FILE TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'archive': {
        'id': 'archive',
        'name': 'Archive Manager',
        'script': 'archive_manager.py',
        'category': 'files',
        'docs': {'short_desc': 'Archive management'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'Archive File'}],
        'presets': [],
    },

    'bulk_rename': {
        'id': 'bulk_rename',
        'name': 'Bulk Rename',
        'script': 'bulk_rename.py',
        'category': 'files',
        'docs': {'short_desc': 'Bulk file renaming'},
        'inputs': [
            {'name': 'path', 'type': INPUT_TEXT, 'label': 'Directory', 'required': True},
            {'name': 'pattern', 'type': INPUT_TEXT, 'label': 'Pattern'},
        ],
        'presets': [],
    },

    'duplicate': {
        'id': 'duplicate',
        'name': 'Duplicate Finder',
        'script': 'duplicate.py',
        'category': 'files',
        'docs': {'short_desc': 'Find duplicate files'},
        'inputs': [{'name': 'path', 'type': INPUT_TEXT, 'label': 'Directory', 'required': True}],
        'presets': [],
    },

    'metadata': {
        'id': 'metadata',
        'name': 'Metadata',
        'script': 'metadata.py',
        'category': 'files',
        'docs': {'short_desc': 'File metadata viewer'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'File', 'required': True}],
        'presets': [],
    },

    'pdf': {
        'id': 'pdf',
        'name': 'PDF Tools',
        'script': 'pdf_tools.py',
        'category': 'files',
        'docs': {'short_desc': 'PDF utilities'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'PDF File'}],
        'presets': [],
    },

    'shred': {
        'id': 'shred',
        'name': 'Shred',
        'script': 'shred.py',
        'category': 'files',
        'docs': {'short_desc': 'Secure file deletion'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'File', 'required': True}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SYSTEM TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'alias': {
        'id': 'alias',
        'name': 'Alias Manager',
        'script': 'alias_manager.py',
        'category': 'system',
        'docs': {'short_desc': 'Shell alias manager'},
        'inputs': [],
        'presets': [],
    },

    'backup': {
        'id': 'backup',
        'name': 'Backup Tool',
        'script': 'backup_tool.py',
        'category': 'system',
        'docs': {'short_desc': 'Backup utility'},
        'inputs': [
            {'name': 'source', 'type': INPUT_TEXT, 'label': 'Source', 'required': True},
            {'name': 'dest', 'type': INPUT_TEXT, 'label': 'Destination', 'required': True},
        ],
        'presets': [],
    },

    'cron': {
        'id': 'cron',
        'name': 'Cron Manager',
        'script': 'cron_manager.py',
        'category': 'system',
        'docs': {'short_desc': 'Cron job manager'},
        'inputs': [],
        'presets': [],
    },

    'diskusage': {
        'id': 'diskusage',
        'name': 'Disk Usage',
        'script': 'diskusage.py',
        'category': 'system',
        'docs': {'short_desc': 'Disk usage analyzer'},
        'inputs': [{'name': 'path', 'type': INPUT_TEXT, 'label': 'Path', 'default': '/'}],
        'presets': [],
    },

    'processes': {
        'id': 'processes',
        'name': 'Processes',
        'script': 'processes.py',
        'category': 'system',
        'docs': {'short_desc': 'Process manager'},
        'inputs': [],
        'presets': [],
    },

    'service': {
        'id': 'service',
        'name': 'Service Manager',
        'script': 'service_manager.py',
        'category': 'system',
        'docs': {'short_desc': 'Service manager'},
        'inputs': [],
        'presets': [],
    },

    'sysinfo': {
        'id': 'sysinfo',
        'name': 'System Info',
        'script': 'sysinfo.py',
        'category': 'system',
        'docs': {'short_desc': 'System information'},
        'inputs': [],
        'presets': [],
    },

    'usb': {
        'id': 'usb',
        'name': 'USB Info',
        'script': 'usb_info.py',
        'category': 'system',
        'docs': {'short_desc': 'USB device info'},
        'inputs': [],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # PRODUCTIVITY TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'bookmarks': {
        'id': 'bookmarks',
        'name': 'Bookmarks',
        'script': 'bookmarks.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Bookmark manager'},
        'inputs': [],
        'presets': [],
    },

    'expenses': {
        'id': 'expenses',
        'name': 'Expenses',
        'script': 'expenses.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Expense tracker'},
        'inputs': [],
        'presets': [],
    },

    'flashcards': {
        'id': 'flashcards',
        'name': 'Flashcards',
        'script': 'flashcards.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Flashcard study'},
        'inputs': [],
        'presets': [],
    },

    'habits': {
        'id': 'habits',
        'name': 'Habits',
        'script': 'habits.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Habit tracker'},
        'inputs': [],
        'presets': [],
    },

    'notes': {
        'id': 'notes',
        'name': 'Notes',
        'script': 'notes.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Note taking'},
        'inputs': [],
        'presets': [],
    },

    'pomodoro': {
        'id': 'pomodoro',
        'name': 'Pomodoro',
        'script': 'pomodoro.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Pomodoro timer'},
        'inputs': [],
        'presets': [],
    },

    'timer': {
        'id': 'timer',
        'name': 'Timer',
        'script': 'timer.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Timer/stopwatch'},
        'inputs': [{'name': 'minutes', 'type': INPUT_NUMBER, 'label': 'Minutes'}],
        'presets': [],
    },

    'todo': {
        'id': 'todo',
        'name': 'Todo',
        'script': 'todo.py',
        'category': 'productivity',
        'docs': {'short_desc': 'Todo list manager'},
        'inputs': [],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # MEDIA TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'audio': {
        'id': 'audio',
        'name': 'Audio Info',
        'script': 'audio_info.py',
        'category': 'media',
        'docs': {'short_desc': 'Audio file info'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'Audio File'}],
        'presets': [],
    },

    'color': {
        'id': 'color',
        'name': 'Color Picker',
        'script': 'color_picker.py',
        'category': 'media',
        'docs': {'short_desc': 'Color picker tool'},
        'inputs': [],
        'presets': [],
    },

    'imgconvert': {
        'id': 'imgconvert',
        'name': 'Image Convert',
        'script': 'imgconvert.py',
        'category': 'media',
        'docs': {'short_desc': 'Image converter'},
        'inputs': [
            {'name': 'input', 'type': INPUT_FILE, 'label': 'Input Image', 'required': True},
            {'name': 'format', 'type': INPUT_DROPDOWN, 'label': 'Format',
             'options': [{'value': 'png', 'label': 'PNG'}, {'value': 'jpg', 'label': 'JPG'},
                        {'value': 'webp', 'label': 'WebP'}]},
        ],
        'presets': [],
    },

    'screenshot': {
        'id': 'screenshot',
        'name': 'Screenshot',
        'script': 'screenshot.py',
        'category': 'media',
        'docs': {'short_desc': 'Screenshot tool'},
        'inputs': [],
        'presets': [],
    },

    'ytdl': {
        'id': 'ytdl',
        'name': 'YouTube DL',
        'script': 'ytdl.py',
        'category': 'media',
        'docs': {'short_desc': 'YouTube downloader'},
        'inputs': [{'name': 'url', 'type': INPUT_URL, 'label': 'Video URL', 'required': True}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # OSINT TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'google_dork': {
        'id': 'google_dork',
        'name': 'Google Dork',
        'script': 'google_dork.py',
        'category': 'osint',
        'docs': {'short_desc': 'Google dork generator'},
        'inputs': [{'name': 'domain', 'type': INPUT_TEXT, 'label': 'Target Domain'}],
        'presets': [],
    },

    'username_check': {
        'id': 'username_check',
        'name': 'Username Check',
        'script': 'username_check.py',
        'category': 'osint',
        'docs': {'short_desc': 'Username availability check'},
        'inputs': [{'name': 'username', 'type': INPUT_TEXT, 'label': 'Username', 'required': True}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # WEB TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'jwt': {
        'id': 'jwt',
        'name': 'JWT Decode',
        'script': 'jwt_decode.py',
        'category': 'web',
        'docs': {'short_desc': 'JWT token decoder'},
        'inputs': [{'name': 'token', 'type': INPUT_TEXT, 'label': 'JWT Token', 'required': True}],
        'presets': [],
    },

    'regex': {
        'id': 'regex',
        'name': 'Regex Test',
        'script': 'regex_test.py',
        'category': 'web',
        'docs': {'short_desc': 'Regex pattern tester'},
        'inputs': [
            {'name': 'pattern', 'type': INPUT_TEXT, 'label': 'Pattern', 'required': True},
            {'name': 'text', 'type': INPUT_TEXT, 'label': 'Test String'},
        ],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # FORENSICS
    # ═══════════════════════════════════════════════════════════════════════════
    'hexview': {
        'id': 'hexview',
        'name': 'Hex Viewer',
        'script': 'hexview.py',
        'category': 'forensics',
        'docs': {'short_desc': 'Hex file viewer'},
        'inputs': [{'name': 'file', 'type': INPUT_FILE, 'label': 'File', 'required': True}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITOR TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'change_detect': {
        'id': 'change_detect',
        'name': 'Change Detect',
        'script': 'change_detect.py',
        'category': 'monitor',
        'docs': {'short_desc': 'File change detector'},
        'inputs': [{'name': 'path', 'type': INPUT_TEXT, 'label': 'Path', 'required': True}],
        'presets': [],
    },

    'uptime': {
        'id': 'uptime',
        'name': 'Uptime',
        'script': 'uptime.py',
        'category': 'monitor',
        'docs': {'short_desc': 'Uptime monitor'},
        'inputs': [{'name': 'host', 'type': INPUT_TEXT, 'label': 'Host'}],
        'presets': [],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # FUN TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'cowsay': {
        'id': 'cowsay',
        'name': 'Cowsay',
        'script': 'cowsay.py',
        'category': 'fun',
        'docs': {'short_desc': 'Cowsay ASCII art'},
        'inputs': [{'name': 'message', 'type': INPUT_TEXT, 'label': 'Message', 'required': True}],
        'presets': [],
    },

    'matrix': {
        'id': 'matrix',
        'name': 'Matrix',
        'script': 'matrix.py',
        'category': 'fun',
        'docs': {'short_desc': 'Matrix rain effect'},
        'inputs': [],
        'presets': [],
    },

    'typing': {
        'id': 'typing',
        'name': 'Typing Test',
        'script': 'typing_test.py',
        'category': 'fun',
        'docs': {'short_desc': 'Typing speed test'},
        'inputs': [],
        'presets': [],
    },
}


# Merge base tools with extended tools
def get_all_tools():
    """Get all tools (base + extended)"""
    all_tools = dict(BASE_TOOLS)
    all_tools.update(EXTENDED_TOOLS)
    return all_tools


# Update the TOOLS export
TOOLS = get_all_tools()


def get_tool(tool_id):
    """Get tool by ID"""
    return TOOLS.get(tool_id)


def get_tools_by_category(category):
    """Get all tools in a category"""
    return [t for t in TOOLS.values() if t.get('category') == category]


def search_tools(query):
    """Search tools by name or description"""
    query = query.lower()
    results = []
    for tool in TOOLS.values():
        name = tool.get('name', '').lower()
        short_desc = tool.get('docs', {}).get('short_desc', '').lower()
        if query in name or query in short_desc:
            results.append(tool)
    return results
