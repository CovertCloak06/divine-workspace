#!/usr/bin/env python3
"""
Update pkn.html to use modular frontend
Replaces old script tags with ES6 module imports
"""

import re
from pathlib import Path

HTML_FILE = Path('/home/gh0st/dvn/divine-workspace/apps/pkn/pkn.html')

def update_html():
    print("📝 Updating pkn.html...\n")

    content = HTML_FILE.read_text()

    # Find and replace the script loading section
    # Keep: tools.js, config.js, config.local.js (needed globals)
    # Replace: All js/*.js individual file loads with single module import

    # Pattern to match old script loads
    old_scripts = [
        r'<script src="js/capacitor-backend\.js"></script>',
        r'<script src="js/autocomplete\.js"></script>',
        r'<script src="js/agent_quality\.js"></script>',
        r'<script src="js/multi_agent_ui\.js\?v=[^"]+"></script>',
        r'<script src="app\.js\?v=[^"]+"></script>',
        r'<script type="module" src="js/main\.js\?v=[^"]+"></script>',
        r'<script src="js/files\.js\?v=[^"]+"></script>',
        r'<script src="js/osint_ui\.js"></script>',
    ]

    # Remove old script tags
    for pattern in old_scripts:
        content = re.sub(pattern, '', content, flags=re.MULTILINE)

    # Find the tools.js script tag and add our module imports after it
    tools_pattern = r'(<script src="tools\.js"></script>)'

    replacement = r'''\1
<!-- PKN Frontend Modules -->
<script type="module" src="frontend/js/pkn.js"></script>
<script src="frontend/js/core/app.js"></script>'''

    content = re.sub(tools_pattern, replacement, content)

    # Write back
    HTML_FILE.write_text(content)

    print("✅ Updated pkn.html")
    print("  ✓ Removed 8 old script tags")
    print("  ✓ Added frontend/js/pkn.js (ES6 module)")
    print("  ✓ Added frontend/js/core/app.js (legacy)")
    print("\n⚠️  Changes:")
    print("  - All modular files now loaded via frontend/js/pkn.js")
    print("  - app.js moved to frontend/js/core/app.js")
    print("  - ES6 module system enabled")


if __name__ == '__main__':
    update_html()
