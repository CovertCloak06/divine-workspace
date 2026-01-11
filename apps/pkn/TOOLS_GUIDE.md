# 🛠️ PKN Development Tools Guide

## What Tools Do I Have?

You have **TWO different tool systems**:

### 1️⃣ **Divine Debugger** (Chrome Extension + Python Scripts)
**Location**: `/home/gh0st/dvn/divine-workspace/apps/debugger-extension/`

This is a **dual-purpose tool**:

#### A) Chrome Extension (Visual UI)
- **What**: A DevTools panel that appears in Chrome when you press F12
- **Features**:
  - Element inspector
  - Live style editor
  - Console logger
  - Code analysis with Learning Mode (explains bugs in beginner-friendly way)
  - Interactive tutorials

- **How to Install**:
  ```
  1. Open Chrome
  2. Go to: chrome://extensions/
  3. Enable "Developer mode" (top right toggle)
  4. Click "Load unpacked"
  5. Select folder: /home/gh0st/dvn/divine-workspace/apps/debugger-extension/
  6. Done! Now press F12 on any page and you'll see "Divine Debugger" tab
  ```

#### B) Python Analysis Scripts (Command Line)
- **What**: Scripts that scan your code for bugs
- **Features**:
  - Find duplicate functions (same function in multiple files)
  - Detect scope mismatches (`openMenuElement` vs `window.openMenuElement`)
  - Find missing CSS selectors (JS references `.my-class` but it doesn't exist)
  - Comprehensive reports with fix suggestions

- **How to Use**:
  ```bash
  cd /home/gh0st/dvn/divine-workspace/apps/debugger-extension

  # Run ALL checks at once
  python3 run_all_checks.py /home/gh0st/dvn/divine-workspace/apps/pkn

  # Or run individual checks
  python3 analyze_duplicate_functions.py /home/gh0st/dvn/divine-workspace/apps/pkn
  python3 analyze_scope_mismatches.py /home/gh0st/dvn/divine-workspace/apps/pkn
  python3 analyze_missing_selectors.py /home/gh0st/dvn/divine-workspace/apps/pkn
  ```

---

### 2️⃣ **PKN-Specific Scripts** (New - Just Created)
**Location**: `/home/gh0st/dvn/divine-workspace/apps/pkn/scripts/`

These are **specialized** for PKN:

- **`check_plugins.py`**
  - Validates plugin directories
  - Checks manifest.json files
  - Shows which plugins are properly configured
  - Color-coded output (green = good, red = bad)

  ```bash
  python3 scripts/check_plugins.py
  ```

- **`test_fixes.sh`**
  - Quick checklist for testing browser fixes
  - Server status check
  - Testing guide

  ```bash
  ./scripts/test_fixes.sh
  ```

---

## Should They Be Combined?

**YES! Here's how we should organize them:**

### The Plan:
```
apps/pkn/
├── scripts/
│   ├── debug/                    # Code analysis (from debugger-extension)
│   │   ├── analyze_all.py        # Master script that runs everything
│   │   ├── duplicate_functions.py
│   │   ├── scope_mismatches.py
│   │   └── missing_selectors.py
│   ├── check/                    # Validation scripts
│   │   ├── check_plugins.py
│   │   ├── check_css.py         # New: validate CSS variables
│   │   ├── check_imports.py     # New: validate JS imports
│   │   └── check_backend.py     # New: test Flask endpoints
│   └── test_all.sh              # ONE command to run everything
```

This way:
- **ONE master command** runs all checks
- **Organized by purpose** (debug vs check vs test)
- **Reusable** - can run individually or all at once
- **Clear names** - you know what each script does

---

## What Tools Were Downloaded Yesterday?

Based on the CLAUDE.md notes, we may have installed:
- **Biome** (linter/formatter) - in divine-workspace
- **pre-commit** (git hooks)
- **pnpm** (package manager)
- **just** (task runner)

Let me check what's actually installed:
```bash
# Check if tools are installed
biome --version
pnpm --version
just --version
pre-commit --version
```

---

## The Confusion Explained

You're confused because:

1. **Debugger extension exists** but isn't installed in Chrome yet
2. **Python scripts exist** but we haven't been running them
3. **New scripts created today** (check_plugins.py) are separate
4. **Build tools** (biome, pnpm, just) may be installed but not being used

The solution: **CONSOLIDATE everything into a master tooling system**

---

## Next Steps

Want me to:
1. ✅ Install the Divine Debugger extension in Chrome?
2. ✅ Create a master `analyze_all.py` that runs every check?
3. ✅ Check which build tools are installed?
4. ✅ Create a single `./dev` command that does everything?

This will give you ONE clear tooling system instead of scattered scripts.
