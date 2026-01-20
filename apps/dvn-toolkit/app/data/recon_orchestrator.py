"""
Recon Orchestrator - Manages tool execution for Identity Recon
Defines which tools run for each input type and orchestrates execution
"""

from .input_detector import (
    INPUT_EMAIL, INPUT_USERNAME, INPUT_DOMAIN, INPUT_IP, INPUT_PHONE
)

# Tool definitions with execution parameters
RECON_TOOLS = {
    # Email tools
    'email_osint': {
        'name': 'Email OSINT',
        'script': 'email_osint.py',
        'category': 'network',
        'description': 'Validate email, check breaches, analyze provider',
        'input_types': [INPUT_EMAIL],
        'args_template': '{email}',
        'timeout': 30,
        'priority': 1
    },
    # Username tools
    'username_check': {
        'name': 'Username Check',
        'script': 'username_check.py',
        'category': 'osint',
        'description': 'Check username across 40+ platforms',
        'input_types': [INPUT_USERNAME, INPUT_EMAIL],
        'args_template': '{username}',
        'timeout': 60,
        'priority': 1
    },
    'username_search': {
        'name': 'Username Search',
        'script': 'username_search.py',
        'category': 'network',
        'description': 'Extended search across 50+ platforms',
        'input_types': [INPUT_USERNAME, INPUT_EMAIL],
        'args_template': '{username}',
        'timeout': 60,
        'priority': 2
    },
    'social_recon': {
        'name': 'Social Recon',
        'script': 'social_recon.py',
        'category': 'network',
        'description': 'Search social media profiles',
        'input_types': [INPUT_USERNAME, INPUT_EMAIL],
        'args_template': '{username}',
        'timeout': 45,
        'priority': 2
    },
    'google_dork': {
        'name': 'Google Dorker',
        'script': 'google_dork.py',
        'category': 'osint',
        'description': 'Generate advanced search queries',
        'input_types': [INPUT_USERNAME, INPUT_EMAIL, INPUT_DOMAIN],
        'args_template': '{target}',
        'timeout': 15,
        'priority': 3
    },
    # Domain tools
    'whois_lookup': {
        'name': 'WHOIS Lookup',
        'script': 'whois_lookup.py',
        'category': 'network',
        'description': 'Domain registration information',
        'input_types': [INPUT_DOMAIN],
        'args_template': '{domain}',
        'timeout': 20,
        'priority': 1
    },
    'domain_recon': {
        'name': 'Domain Recon',
        'script': 'domain_recon.py',
        'category': 'network',
        'description': 'DNS records, subdomains, SSL certs',
        'input_types': [INPUT_DOMAIN],
        'args_template': '{domain}',
        'timeout': 45,
        'priority': 1
    },
    'dns_enum': {
        'name': 'DNS Enumeration',
        'script': 'dns_enum.py',
        'category': 'offensive',
        'description': 'Comprehensive DNS mapping',
        'input_types': [INPUT_DOMAIN],
        'args_template': '{domain}',
        'timeout': 60,
        'priority': 2
    },
    'dns_lookup': {
        'name': 'DNS Lookup',
        'script': 'dns_lookup.py',
        'category': 'network',
        'description': 'Query DNS records',
        'input_types': [INPUT_DOMAIN],
        'args_template': '{domain}',
        'timeout': 15,
        'priority': 1
    },
    'ssl_check': {
        'name': 'SSL Check',
        'script': 'ssl_check.py',
        'category': 'network',
        'description': 'Certificate information',
        'input_types': [INPUT_DOMAIN, INPUT_IP],
        'args_template': '{target}',
        'timeout': 20,
        'priority': 3
    },
    # IP tools
    'ip_geolocate': {
        'name': 'IP Geolocation',
        'script': 'ip_geolocate.py',
        'category': 'network',
        'description': 'Location, ISP, organization',
        'input_types': [INPUT_IP],
        'args_template': '{ip}',
        'timeout': 15,
        'priority': 1
    },
    'reverse_dns': {
        'name': 'Reverse DNS',
        'script': 'reverse_dns.py',
        'category': 'network',
        'description': 'Hostname from IP address',
        'input_types': [INPUT_IP],
        'args_template': '{ip}',
        'timeout': 15,
        'priority': 1
    },
    'nmap_lite': {
        'name': 'Port Scanner',
        'script': 'nmap_lite.py',
        'category': 'offensive',
        'description': 'Scan ports and detect services',
        'input_types': [INPUT_IP, INPUT_DOMAIN],
        'args_template': '{target} -p 1-1000',
        'timeout': 120,
        'priority': 3
    },
    'banner_grab': {
        'name': 'Banner Grabber',
        'script': 'banner_grab.py',
        'category': 'network',
        'description': 'Service fingerprinting',
        'input_types': [INPUT_IP, INPUT_DOMAIN],
        'args_template': '{target}',
        'timeout': 30,
        'priority': 3
    },
}

# Scan profiles (quick vs deep)
SCAN_PROFILES = {
    'quick': {
        'name': 'Quick Scan',
        'description': 'Fast reconnaissance with essential tools',
        'max_tools': 3,
        'priority_cutoff': 1
    },
    'standard': {
        'name': 'Standard Scan',
        'description': 'Balanced scan with common tools',
        'max_tools': 6,
        'priority_cutoff': 2
    },
    'deep': {
        'name': 'Deep Scan',
        'description': 'Comprehensive scan with all available tools',
        'max_tools': 15,
        'priority_cutoff': 10
    }
}


def get_tools_for_input(input_type: str, profile: str = 'standard') -> list:
    """
    Get list of tools to run for a given input type and scan profile.

    Args:
        input_type: One of INPUT_* constants
        profile: 'quick', 'standard', or 'deep'

    Returns:
        List of tool configs sorted by priority
    """
    profile_config = SCAN_PROFILES.get(profile, SCAN_PROFILES['standard'])
    tools = []

    for tool_id, tool_config in RECON_TOOLS.items():
        if input_type in tool_config['input_types']:
            if tool_config['priority'] <= profile_config['priority_cutoff']:
                tools.append({
                    'id': tool_id,
                    **tool_config
                })

    # Sort by priority
    tools.sort(key=lambda t: t['priority'])

    # Limit to max tools
    return tools[:profile_config['max_tools']]


def build_tool_args(tool_id: str, input_data: dict) -> str:
    """
    Build command line arguments for a tool.

    Args:
        tool_id: Tool identifier
        input_data: Dict with input values (email, username, domain, ip, target)

    Returns:
        Formatted argument string
    """
    tool = RECON_TOOLS.get(tool_id)
    if not tool:
        return ''

    template = tool['args_template']

    # Build substitution dict
    subs = {
        'email': input_data.get('email', ''),
        'username': input_data.get('username', ''),
        'domain': input_data.get('domain', ''),
        'ip': input_data.get('ip', ''),
        'phone': input_data.get('phone', ''),
        'target': input_data.get('target', input_data.get('domain', input_data.get('ip', '')))
    }

    # For email input, extract username
    if 'email' in input_data and '@' in input_data['email']:
        subs['username'] = input_data['email'].split('@')[0]
        subs['domain'] = input_data['email'].split('@')[1]

    # Substitute
    for key, value in subs.items():
        template = template.replace('{' + key + '}', str(value))

    return template


def get_tool_path(tool_id: str) -> str:
    """Get the full path to a tool script"""
    tool = RECON_TOOLS.get(tool_id)
    if not tool:
        return None

    category = tool['category']
    script = tool['script']

    # Build path based on category
    return f"tools/{category}/{script}"


def estimate_scan_time(tools: list) -> int:
    """Estimate total scan time in seconds"""
    return sum(t.get('timeout', 30) for t in tools)


def get_result_categories() -> dict:
    """Categories for organizing results"""
    return {
        'identity': {
            'name': 'Identity',
            'icon': 'user',
            'tools': ['email_osint']
        },
        'social': {
            'name': 'Social Profiles',
            'icon': 'users',
            'tools': ['username_check', 'username_search', 'social_recon']
        },
        'search': {
            'name': 'Search Results',
            'icon': 'search',
            'tools': ['google_dork']
        },
        'domain': {
            'name': 'Domain Info',
            'icon': 'globe',
            'tools': ['whois_lookup', 'domain_recon', 'dns_enum', 'dns_lookup']
        },
        'network': {
            'name': 'Network Info',
            'icon': 'network',
            'tools': ['ip_geolocate', 'reverse_dns', 'ssl_check']
        },
        'services': {
            'name': 'Services',
            'icon': 'server',
            'tools': ['nmap_lite', 'banner_grab']
        }
    }
