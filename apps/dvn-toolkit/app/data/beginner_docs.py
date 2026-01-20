"""
Beginner Documentation - Extended docs for common tools
Import and merge into TOOLS dict in tool_registry.py
"""

# Beginner-friendly documentation for high-priority tools
# Format matches the 'docs' structure in tool_registry.py

BEGINNER_DOCS = {
    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK TOOLS - Commonly used, beginner-friendly
    # ═══════════════════════════════════════════════════════════════════════════
    'dns_lookup': {
        'short_desc': 'Look up DNS records for any domain',
        'full_desc': '''Query DNS servers to find the IP addresses and other records
associated with a domain name. Shows A, AAAA, MX, NS, TXT, and other DNS records.''',
        'concept_explanation': {
            'title': 'What is DNS?',
            'simple': '''DNS is like the internet's phone book. When you type "google.com"
your computer asks DNS "What's the IP address for google.com?" and DNS answers "142.250.80.46".

Without DNS, you'd have to remember IP addresses for every website!''',
            'analogy': '''Like calling 411 for a phone number. You give a name,
you get a number back that you can actually dial.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Domain', 'instruction': 'Type a domain like google.com (without http://)', 'tip': 'Just the domain name, no www needed'},
            {'step': 2, 'title': 'Choose Record Type', 'instruction': 'A for IP address, MX for mail servers, NS for name servers', 'tip': 'Start with "All" to see everything'},
            {'step': 3, 'title': 'Read Results', 'instruction': 'A records show IP addresses, MX shows email servers', 'tip': 'Multiple IPs often mean load balancing'},
        ],
        'common_mistakes': [
            {'mistake': 'Including http:// or https://', 'fix': 'Just enter the domain: example.com'},
            {'mistake': 'Expecting website content', 'fix': 'DNS only returns addresses, not page content'},
        ],
        'glossary': [
            {'term': 'A Record', 'definition': 'Maps domain to IPv4 address'},
            {'term': 'MX Record', 'definition': 'Specifies mail servers for the domain'},
            {'term': 'NS Record', 'definition': 'Name servers that manage the domain'},
            {'term': 'TTL', 'definition': 'Time To Live - how long to cache the record'},
        ],
    },

    'ping_sweep': {
        'short_desc': 'Find all active devices on a network',
        'full_desc': '''Sends ping requests to a range of IP addresses to discover
which hosts are online. Great for mapping your local network.''',
        'concept_explanation': {
            'title': 'What is a Ping Sweep?',
            'simple': '''A ping is like shouting "Hello!" and waiting for an echo.
A ping sweep shouts at every address in a range to see who responds.

It's how you find all devices on your home network - your phone, laptop,
smart TV, and anything else connected.''',
            'analogy': '''Like rolling down a street and honking at each house to see
who's home. Each house that responds (honks back) is an active device.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Find Your Network', 'instruction': 'Check your IP first (usually 192.168.1.x or 192.168.0.x)', 'tip': 'Your IP tells you what network range to scan'},
            {'step': 2, 'title': 'Enter Range', 'instruction': 'Enter range like 192.168.1.1-254 or CIDR like 192.168.1.0/24', 'tip': '/24 means scan all 254 addresses'},
            {'step': 3, 'title': 'Review Results', 'instruction': 'Active hosts will show their IP and response time', 'tip': 'Your router is usually .1'},
        ],
        'common_mistakes': [
            {'mistake': 'Scanning wrong network range', 'fix': 'Check your own IP first to confirm the network'},
            {'mistake': 'Scanning public networks', 'fix': 'Only scan your own home/office network'},
        ],
        'warnings': ['Only scan networks you own or have permission to scan'],
    },

    'whois_lookup': {
        'short_desc': 'Find who registered a domain name',
        'full_desc': '''Query WHOIS databases to find domain registration information
including owner details, registration dates, and name servers.''',
        'concept_explanation': {
            'title': 'What is WHOIS?',
            'simple': '''Every domain has to be registered with contact information,
like a deed for a house. WHOIS lets you look up this registration info.

Some owners hide their info with privacy services, but you can still see
when it was registered and who manages the DNS.''',
            'analogy': '''Like looking up property records at the county office -
who bought it, when, and through which real estate company.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Domain', 'instruction': 'Type the domain you want to research', 'tip': 'Works best with .com, .net, .org domains'},
            {'step': 2, 'title': 'Review Info', 'instruction': 'Look for registrar, dates, and name servers', 'tip': 'Old domains are often more trustworthy'},
        ],
        'glossary': [
            {'term': 'Registrar', 'definition': 'Company that sold the domain (GoDaddy, Namecheap, etc.)'},
            {'term': 'Registrant', 'definition': 'Person/company that owns the domain'},
            {'term': 'Creation Date', 'definition': 'When the domain was first registered'},
            {'term': 'Expiration Date', 'definition': 'When registration expires'},
        ],
    },

    'ip_geolocate': {
        'short_desc': 'Find the physical location of an IP address',
        'full_desc': '''Look up geographic information for an IP address including
country, city, ISP, and organization.''',
        'concept_explanation': {
            'title': 'How Does IP Geolocation Work?',
            'simple': '''IP addresses are assigned in blocks to different regions and ISPs.
Databases track which IPs belong to which locations.

It's not GPS-precise - usually city-level accuracy. VPNs can make IPs
appear from different locations.''',
            'analogy': '''Like tracking where a letter came from by its postal code -
you can tell the general area but not the exact house.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Get an IP', 'instruction': 'Enter any IP address (try your own first)', 'tip': 'Search "what is my ip" to find yours'},
            {'step': 2, 'title': 'Review Location', 'instruction': 'See country, city, and ISP information', 'tip': 'VPN IPs show the VPN server location'},
        ],
        'common_mistakes': [
            {'mistake': 'Expecting exact street address', 'fix': 'Geolocation is typically city-level accuracy'},
            {'mistake': 'Using localhost (127.0.0.1)', 'fix': 'Use your public IP, not local address'},
        ],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY TOOLS - Safe for beginners
    # ═══════════════════════════════════════════════════════════════════════════
    'hasher': {
        'short_desc': 'Generate hashes (MD5, SHA1, SHA256) from text',
        'full_desc': '''Convert text into hash values using various algorithms.
Hashes are used for password storage, file verification, and data integrity.''',
        'concept_explanation': {
            'title': 'What is a Hash?',
            'simple': '''A hash is a one-way fingerprint of data. Feed it "hello" and
you always get the same jumble of characters. Change even one letter
and the entire hash changes completely.

Websites store hashes of your password, not the actual password.
When you log in, they hash what you type and compare.''',
            'analogy': '''Like a paper shredder that always shreds the same document
into the same pattern. You can verify it was that document,
but you can't reconstruct the original from the shreds.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Text', 'instruction': 'Type any text you want to hash', 'tip': 'Try "hello" first'},
            {'step': 2, 'title': 'See Hashes', 'instruction': 'View MD5, SHA1, SHA256 outputs', 'tip': 'SHA256 is most secure for new applications'},
            {'step': 3, 'title': 'Compare', 'instruction': 'Change one letter and see how the hash changes completely', 'tip': 'This is called the "avalanche effect"'},
        ],
        'glossary': [
            {'term': 'MD5', 'definition': '128-bit hash, fast but considered weak for security'},
            {'term': 'SHA1', 'definition': '160-bit hash, deprecated for security use'},
            {'term': 'SHA256', 'definition': '256-bit hash, current standard for security'},
            {'term': 'Collision', 'definition': 'Two different inputs producing same hash (bad!)'},
        ],
    },

    'password_gen': {
        'short_desc': 'Generate strong, random passwords',
        'full_desc': '''Create cryptographically random passwords with customizable
length and character sets. Generate multiple passwords at once.''',
        'concept_explanation': {
            'title': 'What Makes a Strong Password?',
            'simple': '''Strong passwords are long (16+ characters) and random.
"correct horse battery staple" is better than "P@ssw0rd!"

Human-chosen passwords follow patterns that hackers know.
Computer-generated random passwords don't.''',
            'analogy': '''Like lottery numbers - truly random picks are safer than
"lucky numbers" everyone picks. Randomness = security.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Set Length', 'instruction': 'Choose password length (16+ recommended)', 'tip': 'Longer is always better'},
            {'step': 2, 'title': 'Choose Characters', 'instruction': 'Include uppercase, lowercase, numbers, symbols', 'tip': 'More variety = harder to crack'},
            {'step': 3, 'title': 'Generate', 'instruction': 'Copy the password to your password manager', 'tip': 'Never reuse passwords across sites'},
        ],
        'common_mistakes': [
            {'mistake': 'Making passwords too short', 'fix': 'Use at least 16 characters'},
            {'mistake': 'Memorizing instead of using a manager', 'fix': 'Use a password manager for all passwords'},
        ],
    },

    'encoder': {
        'short_desc': 'Encode and decode text (Base64, URL, HTML, etc.)',
        'full_desc': '''Convert text between different encoding formats like
Base64, URL encoding, HTML entities, and hex.''',
        'concept_explanation': {
            'title': 'What is Encoding?',
            'simple': '''Encoding transforms text into a different format that can be
safely transmitted or stored. Unlike encryption, encoding is not for security -
anyone can decode it.

Base64 turns binary data into text. URL encoding makes text safe for URLs.
HTML encoding prevents browser interpretation.''',
            'analogy': '''Like translating English to pig Latin - it looks different,
but anyone who knows the rules can understand it.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Text', 'instruction': 'Type text to encode or decode', 'tip': 'Try "Hello World"'},
            {'step': 2, 'title': 'Choose Format', 'instruction': 'Select Base64, URL, Hex, etc.', 'tip': 'Base64 is most common'},
            {'step': 3, 'title': 'Encode/Decode', 'instruction': 'Switch between encoded and decoded', 'tip': 'Encoded Base64 ends in = padding'},
        ],
        'glossary': [
            {'term': 'Base64', 'definition': 'Encodes binary as text using 64 characters'},
            {'term': 'URL Encoding', 'definition': 'Replaces unsafe URL chars with %XX'},
            {'term': 'Hex', 'definition': 'Represents bytes as two hex digits'},
        ],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # OSINT TOOLS
    # ═══════════════════════════════════════════════════════════════════════════
    'username_check': {
        'short_desc': 'Check if a username exists on 40+ platforms',
        'full_desc': '''Search for a username across popular platforms like
Twitter, GitHub, Reddit, Instagram, and more.''',
        'concept_explanation': {
            'title': 'Why Check Usernames?',
            'simple': '''People often use the same username everywhere. Finding one
account can lead to others. This is useful for:
- Checking your own digital footprint
- Verifying someone's identity
- Finding old accounts you forgot about''',
            'analogy': '''Like searching a name in multiple phone books -
same person might be listed in several cities.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Username', 'instruction': 'Type the username to search (your own!)', 'tip': 'Only search usernames you have permission to'},
            {'step': 2, 'title': 'Wait for Results', 'instruction': 'Tool checks many sites (takes a moment)', 'tip': 'Green = found, Red = not found'},
            {'step': 3, 'title': 'Review Findings', 'instruction': 'See which platforms have this username', 'tip': 'Click links to verify accounts'},
        ],
        'warnings': [
            'Only search your own username or with permission',
            'Results may include false positives',
        ],
    },

    'google_dork': {
        'short_desc': 'Generate advanced Google search queries',
        'full_desc': '''Create Google "dorks" - special search operators that
find specific types of content, files, and exposed data.''',
        'concept_explanation': {
            'title': 'What is Google Dorking?',
            'simple': '''Google has special search operators that filter results:
- site:example.com - only results from that site
- filetype:pdf - only PDF files
- intitle:"index of" - directory listings
- inurl:admin - URLs containing "admin"

Combining these finds specific, often hidden, content.''',
            'analogy': '''Like using library search filters to find exactly
the book you need - by author, year, topic, format.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Target', 'instruction': 'Type a domain to generate dorks for', 'tip': 'Start with a site you own'},
            {'step': 2, 'title': 'Select Categories', 'instruction': 'Choose what types of dorks to generate', 'tip': 'Start with basic searches'},
            {'step': 3, 'title': 'Use in Google', 'instruction': 'Copy dorks to Google search', 'tip': 'May trigger CAPTCHA if too many searches'},
        ],
        'warnings': [
            'Only search for your own organization',
            'Excessive searches may trigger Google blocks',
        ],
    },

    'email_osint': {
        'short_desc': 'Analyze email addresses for information',
        'full_desc': '''Check if an email is valid, what provider it uses,
and if it appears in known data breaches.''',
        'concept_explanation': {
            'title': 'Email Analysis',
            'simple': '''An email address reveals:
- Domain shows the provider (gmail, outlook, company email)
- Username might be reused on other sites
- Breach databases show if it was leaked
- Validation checks if it can receive email''',
            'analogy': '''Like analyzing a mailing address - you can tell
the city, whether it's a PO box, and look up the resident.''',
        },
        'step_by_step': [
            {'step': 1, 'title': 'Enter Email', 'instruction': 'Type your own email address', 'tip': 'Only analyze emails you own'},
            {'step': 2, 'title': 'Check Results', 'instruction': 'See validity, provider, and breach status', 'tip': 'Breached? Change your password!'},
        ],
        'warnings': ['Only analyze your own email addresses'],
    },
}


def get_beginner_docs(tool_id: str) -> dict:
    """Get beginner documentation for a tool"""
    return BEGINNER_DOCS.get(tool_id, {})


def has_beginner_docs(tool_id: str) -> bool:
    """Check if a tool has beginner documentation"""
    return tool_id in BEGINNER_DOCS


def get_all_documented_tools() -> list:
    """Get list of tools with beginner documentation"""
    return list(BEGINNER_DOCS.keys())
