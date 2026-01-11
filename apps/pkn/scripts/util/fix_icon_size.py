#!/usr/bin/env python3
"""Quick fix for enlarged agent selector icons"""

from pathlib import Path

PKN_DIR = Path("/home/gh0st/pkn")
CSS_FILE = PKN_DIR / "css" / "multi_agent.css"

# Backup
import shutil

shutil.copy(CSS_FILE, str(CSS_FILE) + ".bak")

content = CSS_FILE.read_text()

# Add CSS to fix icon sizes
fix_css = """
/* Fix for enlarged agent icons in header */
.header-agent-display .agent-icon {
    font-size: 20px !important;
    width: 32px;
    height: 32px;
}

.agent-mode-toggle-header .mode-btn-header {
    padding: 6px 10px !important;
    font-size: 12px !important;
}

.agent-mode-toggle-header .mode-btn-header .agent-icon {
    font-size: 16px !important;
}
"""

# Append fix to end of file
content += "\n" + fix_css

CSS_FILE.write_text(content)

print("✓ Fixed agent icon sizes")
print("✓ Backup saved to multi_agent.css.bak")
print("\nRefresh browser (Ctrl+Shift+R) to see changes")
