#!/usr/bin/env python3
"""
Update index.html to use src/main.js
Replaces old script tags with ES6 module import
"""

import re
from pathlib import Path

HTML_FILE = Path("/home/gh0st/dvn/divine-workspace/apps/code-academy/index.html")


def update_html():
    print("📝 Updating index.html...\n")

    content = HTML_FILE.read_text()

    # Remove old script tags
    old_scripts = [
        r'<script src="js/theme-manager\.js\?v=\d+"></script>',
        r'<script src="js/progress-tracker\.js\?v=\d+"></script>',
        r'<script src="js/code-playground\.js\?v=\d+"></script>',
        r'<script src="js/academy\.js\?v=\d+" defer></script>',
    ]

    for pattern in old_scripts:
        match = re.search(pattern, content)
        if match:
            print(f"  ✓ Removing: {match.group()}")
            content = re.sub(pattern, "", content)

    # Find where to insert new script tag (before </body>)
    # Look for the last script tag or </body>
    insertion_point = content.rfind("</body>")

    if insertion_point == -1:
        print("  ❌ Could not find </body> tag")
        return

    # Insert new module script
    new_script = """    <!-- Code Academy - ES6 Modules -->
    <script type="module" src="src/main.js"></script>

"""

    content = content[:insertion_point] + new_script + content[insertion_point:]

    # Write back
    HTML_FILE.write_text(content)

    print(f"\n✅ Updated index.html")
    print(f"  ✓ Removed 4 old script tags")
    print(f"  ✓ Added src/main.js ES6 module import")
    print("\n⚠️  Changes:")
    print("  - All JavaScript now loaded via src/main.js")
    print("  - ES6 module system enabled")
    print("  - Legacy js/ files no longer loaded directly")


if __name__ == "__main__":
    update_html()
