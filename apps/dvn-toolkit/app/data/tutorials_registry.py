"""
Tutorials Registry - Step-by-step interactive tutorials for tools
Defines guided walkthroughs with field highlighting and explanations
"""

TUTORIALS = {
    'portscanner_intro': {
        'id': 'portscanner_intro',
        'tool_id': 'portscanner',
        'title': 'Your First Port Scan',
        'difficulty': 'beginner',
        'estimated_time': '3 min',
        'steps': [
            {
                'type': 'welcome',
                'title': 'Port Scanning Basics',
                'content': 'This tutorial will guide you through your first port scan.\n\nYou will learn:\n- What ports are\n- How to scan safely\n- How to read results',
            },
            {
                'type': 'explanation',
                'title': 'What are Ports?',
                'content': 'Ports are like numbered doors on a computer. Services listen on specific ports:\n\n- Port 22: SSH\n- Port 80: HTTP\n- Port 443: HTTPS\n- Port 3306: MySQL',
            },
            {
                'type': 'input_guide',
                'field': 'target',
                'title': 'Enter Target',
                'instruction': "Enter 'localhost' to scan your own machine safely.",
                'highlight': True,
                'expected': 'localhost',
                'hint': "localhost = your own computer (127.0.0.1)"
            },
            {
                'type': 'input_guide',
                'field': 'ports',
                'title': 'Select Port Range',
                'instruction': "Enter '1-100' to scan the first 100 ports.",
                'highlight': True,
                'expected': '1-100',
                'hint': "Common ports are in the 1-1024 range"
            },
            {
                'type': 'run_prompt',
                'title': 'Ready to Scan!',
                'content': 'Click RUN to start scanning.\n\nThis will check which ports are open on your machine.',
                'button_text': 'RUN SCAN'
            },
            {
                'type': 'output_guide',
                'title': 'Reading Results',
                'patterns': [
                    {'match': 'OPEN', 'explain': 'Port is accepting connections - a service is running'},
                    {'match': 'CLOSED', 'explain': 'Port rejected connection - nothing listening'},
                    {'match': 'FILTERED', 'explain': 'Firewall is blocking this port'}
                ]
            },
            {
                'type': 'complete',
                'title': 'Great Job!',
                'content': 'You completed your first port scan!\n\nNext steps:\n- Try scanning specific ports (22, 80, 443)\n- Learn about service detection',
                'badge': 'First Scan'
            }
        ]
    },
    'dns_lookup_intro': {
        'id': 'dns_lookup_intro',
        'tool_id': 'dns_lookup',
        'title': 'DNS Lookup Basics',
        'difficulty': 'beginner',
        'estimated_time': '3 min',
        'steps': [
            {
                'type': 'welcome',
                'title': 'DNS - The Internet Phonebook',
                'content': 'DNS translates domain names to IP addresses.\n\nThis tutorial teaches you:\n- How DNS works\n- Different record types\n- How to query DNS',
            },
            {
                'type': 'explanation',
                'title': 'DNS Record Types',
                'content': 'A - Maps domain to IPv4\nAAAA - Maps to IPv6\nMX - Mail servers\nNS - Name servers\nTXT - Text records\nCNAME - Aliases',
            },
            {
                'type': 'input_guide',
                'field': 'domain',
                'title': 'Enter Domain',
                'instruction': "Enter 'google.com' to look up Google's DNS records.",
                'highlight': True,
                'expected': 'google.com',
                'hint': "Try any domain you want to learn about"
            },
            {
                'type': 'run_prompt',
                'title': 'Query DNS',
                'content': 'Click RUN to query the DNS servers.',
                'button_text': 'LOOKUP'
            },
            {
                'type': 'complete',
                'title': 'DNS Expert!',
                'content': 'You now know how to look up DNS records!\n\nTry:\n- Looking up MX records for email servers\n- Checking NS records to see who manages a domain',
                'badge': 'DNS Learner'
            }
        ]
    },
    'username_check_intro': {
        'id': 'username_check_intro',
        'tool_id': 'username_check',
        'title': 'Username Hunting',
        'difficulty': 'beginner',
        'estimated_time': '2 min',
        'steps': [
            {
                'type': 'welcome',
                'title': 'Find Accounts by Username',
                'content': 'People often reuse usernames across platforms.\n\nThis tool checks 40+ sites for a username.',
            },
            {
                'type': 'explanation',
                'title': 'OSINT Ethics',
                'content': 'IMPORTANT: Only search for:\n- Your own username\n- Usernames you have permission to search\n\nThis helps you understand your digital footprint.',
            },
            {
                'type': 'input_guide',
                'field': 'username',
                'title': 'Enter Username',
                'instruction': 'Enter YOUR OWN username to see your digital presence.',
                'highlight': True,
                'hint': "Use a username you actually use online"
            },
            {
                'type': 'run_prompt',
                'title': 'Start Search',
                'content': 'Click RUN to search across 40+ platforms.',
                'button_text': 'SEARCH'
            },
            {
                'type': 'complete',
                'title': 'OSINT Basics Complete!',
                'content': 'You found your accounts across the web!\n\nConsider:\n- Are there accounts you forgot about?\n- Should you delete old accounts?',
                'badge': 'OSINT Novice'
            }
        ]
    },
    'hasher_intro': {
        'id': 'hasher_intro',
        'tool_id': 'hasher',
        'title': 'Understanding Hashes',
        'difficulty': 'beginner',
        'estimated_time': '3 min',
        'steps': [
            {
                'type': 'welcome',
                'title': 'What is Hashing?',
                'content': 'Hashing converts data into a fixed-length string.\n\nUsed for:\n- Password storage\n- File integrity\n- Digital signatures',
            },
            {
                'type': 'explanation',
                'title': 'Hash Properties',
                'content': 'Good hashes are:\n- One-way (can\'t reverse)\n- Deterministic (same input = same output)\n- Collision-resistant (unique outputs)',
            },
            {
                'type': 'input_guide',
                'field': 'text',
                'title': 'Enter Text',
                'instruction': "Enter 'hello' to see its hash.",
                'highlight': True,
                'expected': 'hello',
                'hint': "Try different inputs to see how hashes change"
            },
            {
                'type': 'run_prompt',
                'title': 'Generate Hashes',
                'content': 'Click RUN to see multiple hash algorithms.',
                'button_text': 'HASH IT'
            },
            {
                'type': 'complete',
                'title': 'Hash Expert!',
                'content': 'You understand hashing!\n\nFun fact: Change one letter and the entire hash changes completely.',
                'badge': 'Crypto Basics'
            }
        ]
    }
}


def get_tutorial(tutorial_id: str) -> dict:
    """Get a specific tutorial"""
    return TUTORIALS.get(tutorial_id)


def get_tutorial_for_tool(tool_id: str) -> dict:
    """Get tutorial for a specific tool (if exists)"""
    for tutorial in TUTORIALS.values():
        if tutorial['tool_id'] == tool_id:
            return tutorial
    return None


def get_all_tutorials() -> list:
    """Get all tutorials"""
    return list(TUTORIALS.values())


def has_tutorial(tool_id: str) -> bool:
    """Check if a tool has an associated tutorial"""
    return get_tutorial_for_tool(tool_id) is not None
