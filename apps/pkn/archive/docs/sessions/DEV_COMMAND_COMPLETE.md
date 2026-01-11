# ✅ Dev Command - Complete Tool Collection

## What You Have Now

**ALL useful tools are now in ONE command: `dev`**

Run from anywhere: `dev <command>` (alias added to ~/.bashrc)

---

## 📋 Complete Command List (17 commands)

### 🔍 Code Quality (6 commands)
```bash
dev analyze       # Run all code analysis (duplicates, scope, selectors)
dev check         # Quick plugin validation
dev check-js      # Scan for JavaScript errors
dev lint          # Run biome linter
dev format        # Auto-format code with biome
dev fix           # Auto-fix common issues
```

### 🚀 Server Management (5 commands)
```bash
dev start         # Start PKN server
dev stop          # Stop PKN server
dev restart       # Restart PKN server
dev status        # Check if server is running
dev logs          # Tail server logs (Ctrl+C to exit)
```

### 🧪 Testing & Diagnostics (4 commands)
```bash
dev test          # Run all tests
dev test-plugins  # Test plugin system
dev diagnose      # Deep plugin diagnostics
dev doctor        # Detailed health check
```

### 🔧 Maintenance (1 command)
```bash
dev clean         # Clean build artifacts
```

### 🛠️ Tools (2 commands)
```bash
dev install       # Install Chrome debugger extension
dev health        # Quick system health check
```

---

## 🗑️ Cleaned Up (Deleted 8 Scripts)

These were **one-time migration tools** already used:
- ❌ fix_all_imports.py
- ❌ fix_icon_size.py
- ❌ generate_blueprints.py
- ❌ modularize_frontend.py
- ❌ organize_frontend.py
- ❌ split_agent_manager.py
- ❌ update_pkn_html.py
- ❌ extract_routes.py

**Result**: Cleaner, more organized scripts directory!

---

## 🎯 Your Daily Workflow

### Before Starting Work:
```bash
dev health        # Check everything is working
dev start         # Start server if needed
```

### While Coding:
```bash
dev check         # Quick validation
dev format        # Clean up code
dev check-js      # Check for JS errors
```

### Before Committing:
```bash
dev analyze       # Deep code analysis
dev lint          # Check code quality
dev test          # Run tests
```

### When Something Breaks:
```bash
dev diagnose      # Plugin issues?
dev doctor        # System issues?
dev fix           # Try auto-fix
dev clean         # Clean build artifacts
```

---

## 📊 What's Behind Each Command

| Command | Script | What It Does |
|---------|--------|-------------|
| `dev analyze` | analyze_all.py | Runs 3 debugger scripts: duplicate functions, scope mismatches, missing selectors |
| `dev check` | check_plugins.py | Validates all 10 plugins have manifest.json and plugin.js |
| `dev check-js` | check_js_errors.py | Scans JavaScript files for syntax errors |
| `dev diagnose` | diagnose_plugins.py | Deep diagnostics on plugin loading issues |
| `dev doctor` | pkn_health.py | Detailed health check (more thorough than `dev health`) |
| `dev fix` | auto_fix.py | Attempts to auto-fix common issues |
| `dev clean` | clean_build.py | Removes build artifacts and cache files |
| `dev lint` | biome (npm) | Lints JavaScript/TypeScript code |
| `dev format` | biome (npm) | Auto-formats code with biome |

---

## 🎓 Scripts Behind the Scenes

### Debugger Extension Scripts (used by `dev analyze`):
- `analyze_duplicate_functions.py` - Finds duplicate function definitions
- `analyze_scope_mismatches.py` - Detects local vs window variable conflicts
- `analyze_missing_selectors.py` - Finds CSS selectors that don't exist

### PKN-Specific Scripts:
- `check_plugins.py` - Plugin validation
- `test_fixes.sh` - Testing checklist
- Plus 5 new scripts integrated today!

---

## 🚀 Try It Now!

```bash
# Reload shell to get the 'dev' alias
source ~/.bashrc

# Run from anywhere
dev help
dev health
dev analyze
```

---

## ✅ Summary

**Before**: Scattered scripts, confusing tool names, no clear workflow
**After**: ONE command, 17 organized tools, clear daily workflow

**You now have:**
- ✅ Complete tooling system
- ✅ Clean scripts directory
- ✅ One command to rule them all
- ✅ Clear documentation
- ✅ Daily workflow guide

**Everything you need is in: `dev`**
