# PKN Developer Toolkit

Complete debugging and development tools for building and maintaining PKN.

## Quick Start

```bash
cd /home/gh0st/pkn

# Check for errors
./dev check

# Auto-fix common issues
./dev fix

# Watch files and auto-check on save
./dev watch

# Run full diagnostic
./dev diagnose

# Clean build artifacts
./dev clean
```

## Available Tools

### 1. JavaScript Error Checker (`./dev check`)
**What it does:**
- Checks import/export mismatches
- Finds typos in function names
- Validates file paths
- Detects browser compatibility issues
- Checks for undefined globals

**When to use:** Before testing in browser, after making changes

**Example output:**
```
✓ No import/export mismatches found
✗ settings.js contains 'saveProjectsFromStorage' - should be 'saveProjectsToStorage'?
✓ All imported files exist
✓ pluginManager exported to window
```

### 2. Auto-Fix (`./dev fix`)
**What it does:**
- Fixes common typos automatically
- Removes JSON import assertions
- Corrects import names

**When to use:** When error checker finds fixable issues

**Safe:** Creates backups before fixing

### 3. File Watcher (`./dev watch`)
**What it does:**
- Monitors `js/` and `plugins/` directories
- Automatically runs error checker when files change
- Instant feedback as you code

**When to use:** During active development

**Requires:** `pip3 install watchdog`

### 4. Full Diagnostic (`./dev diagnose`)
**What it does:**
- Checks server files
- Validates all plugins
- Tests HTTP endpoints
- Verifies file structure

**When to use:** Before pushing changes, troubleshooting issues

### 5. Plugin Validator (`./dev plugins`)
**What it does:**
- Deep validation of plugin structure
- Checks manifest.json files
- Validates plugin exports
- Ensures PluginBase inheritance

**When to use:** After creating/modifying plugins

### 6. Clean Build (`./dev clean`)
**What it does:**
- Removes Python cache (`__pycache__`)
- Clears log files
- Deletes temporary test files

**When to use:** Before builds, when disk space low

### 7. Browser Diagnostic (`./dev browser`)
**What it does:**
- Opens interactive browser diagnostic page
- Tests what browser has loaded
- Checks for caching issues
- Has "Clear Cache & Reload" button

**When to use:** When plugins don't load in browser

## Browser Extension Integration

The debugger extension now has a **"PKN Dev Tools"** tab!

### How to use:
1. Open http://localhost:8010/pkn.html
2. Press **F12** (DevTools)
3. Click **"PKN Dev Tools"** tab
4. Click buttons to run checks

### Features:
- **Run Check** - JavaScript error checker
- **Auto-Fix** - Fix common issues
- **Check Plugins** - Validate plugins
- **Run Diagnostic** - Full system check
- **Clean** - Remove cache files
- **Quick Actions** - Open server, docs, copy commands

## File Structure

```
/home/gh0st/pkn/
├── dev                          # Main CLI tool
├── check_js_errors.py           # Error checker
├── auto_fix.py                  # Auto-fix tool
├── file_watcher.py              # File watcher
├── diagnose_plugins.py          # Server diagnostic
├── check_plugins_detailed.py    # Plugin validator
├── clean_build.py               # Clean tool
├── browser_diagnostic.html      # Browser diagnostic page
└── debugger-extension/
    └── devtools/
        └── devtools-panel.html  # Dev Tools panel
```

## Keyboard Shortcuts

Add to `~/.bashrc` for even faster access:

```bash
alias pkn-check='cd /home/gh0st/pkn && ./dev check'
alias pkn-fix='cd /home/gh0st/pkn && ./dev fix'
alias pkn-watch='cd /home/gh0st/pkn && ./dev watch'
alias pkn-clean='cd /home/gh0st/pkn && ./dev clean'
```

Then just type:
```bash
pkn-check      # Quick check
pkn-fix        # Auto-fix
pkn-watch      # Watch mode
pkn-clean      # Clean build
```

## Workflow Examples

### Before Committing Code
```bash
./dev check        # Check for errors
./dev plugins      # Validate plugins
./dev clean        # Clean up
# If all pass → git commit
```

### During Development
```bash
# Terminal 1
./dev watch        # Auto-check on save

# Terminal 2
# Make your changes
# Watch for instant feedback in Terminal 1
```

### Troubleshooting "Plugins Not Loading"
```bash
./dev diagnose     # Check server-side
./dev browser      # Check browser-side
# Click "Clear Cache & Reload" in browser
```

### After Pulling Changes
```bash
./dev clean        # Clear old cache
./dev check        # Verify no errors
./dev diagnose     # Full system check
```

## Tips

1. **Run `./dev check` before testing** - Catches 90% of issues before browser
2. **Use `./dev watch` while coding** - Instant feedback on every save
3. **Browser issues? Try `./dev browser`** - Built-in cache clearing
4. **Extension panel is fastest** - No need to switch to terminal

## Troubleshooting

### "Command not found: ./dev"
```bash
chmod +x /home/gh0st/pkn/dev
```

### "watchdog module not found"
```bash
pip3 install watchdog
```

### "Permission denied"
```bash
chmod +x /home/gh0st/pkn/*.py
```

## What Each Tool Catches

**Error Checker:**
- Import/export mismatches ✓ (caught the saveProjectsFromStorage typo)
- JSON assertions ✓ (caught the assert syntax error)
- Missing files ✓
- Undefined globals ✓

**Plugin Validator:**
- Missing manifest.json
- Invalid JSON
- Missing plugin.js
- No export statement
- Doesn't extend PluginBase

**Browser Diagnostic:**
- Cached old files
- Module loading errors
- Missing window globals
- Service worker issues

## Advanced Usage

### Custom Checks
Add your own checks to `check_js_errors.py`:

```python
def check_my_custom_rule():
    """My custom validation"""
    # Your logic here
    pass

# Add to main():
total_errors += check_my_custom_rule()
```

### Integration with Git Hooks
Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
cd /home/gh0st/pkn
./dev check || exit 1
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

Now checks run automatically before every commit!

## Support

If a tool isn't working:
1. Check you're in `/home/gh0st/pkn` directory
2. Make sure Python scripts are executable (`chmod +x *.py`)
3. Check Python 3 is installed (`python3 --version`)
4. For browser extension, reload it in `chrome://extensions`

---

**Happy debugging! 🛠️**
