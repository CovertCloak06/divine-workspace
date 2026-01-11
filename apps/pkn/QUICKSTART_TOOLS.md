# 🚀 Quick Start - All Your Tools in One Place

## TL;DR - What You Have

You have **ONE master command** that does everything: `./dev`

```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn
./dev help
```

---

## The Tools You Asked About

### ✅ YES - You have these installed:
- **pnpm** (10.28.0) - Fast package manager
- **just** (1.46.0) - Task runner  
- **pre-commit** (4.5.1) - Git hooks
- **biome** (2.3.11) - Linter/formatter

### ✅ YES - You have these tools built:
- **Divine Debugger** - Chrome extension + Python analysis scripts
- **Plugin System** - 10 plugins installed and working
- **PKN-specific scripts** - Plugin checker, test runner

### ❓ NOT USING THEM YET:
We installed them but haven't been using them! Until now...

---

## How to Use Everything (Simple!)

### 🔍 Before You Code - Check Your Code Quality

```bash
./dev check          # Quick check (plugins, CSS, etc.)
./dev analyze        # Deep analysis (duplicates, scope issues, missing selectors)
```

### 🎨 While Coding - Keep Code Clean

```bash
./dev lint           # Check for code issues
./dev format         # Auto-fix formatting
```

### 🚀 Server Management

```bash
./dev start          # Start PKN
./dev stop           # Stop PKN
./dev restart        # Restart PKN
./dev status         # Check if running
./dev logs           # Watch logs
```

### 🧪 Testing

```bash
./dev test           # Run all tests
./dev test-plugins   # Just test plugins
```

### 🛠️ Tools

```bash
./dev health         # See what's installed
./dev install        # Install Chrome debugger extension
```

---

## The Chrome Debugger Extension (Not Installed Yet!)

You have it, but it's not in Chrome yet. Let's install it:

```bash
./dev install
```

Then follow the instructions:
1. Open Chrome: `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select: `/home/gh0st/dvn/divine-workspace/apps/debugger-extension/`
5. Press F12 on any page → "Divine Debugger" tab

**What it does:**
- Visual element inspector
- Live CSS editor
- Code analysis with Learning Mode (explains bugs to beginners!)
- Interactive coding tutorials

---

## Your Daily Workflow

### Before Committing Code:

```bash
./dev analyze        # Find bugs before they happen
./dev format         # Clean up code
./dev test           # Make sure everything works
```

### Debugging Issues:

**Option 1: Command Line (Fast)**
```bash
./dev check          # Quick validation
./dev analyze        # Deep analysis
```

**Option 2: Chrome Extension (Visual)**
1. Press F12
2. Click "Divine Debugger" tab
3. Click "Code Analysis"
4. Click "Run Full Analysis"
5. Toggle "Learning Mode" for explanations

---

## What Files Were Created

```
apps/pkn/
├── dev                          # ⭐ MASTER COMMAND - use this!
├── TOOLS_GUIDE.md               # Full explanation
├── QUICKSTART_TOOLS.md          # This file
└── scripts/
    ├── analyze_all.py           # Runs all checks
    ├── check_plugins.py         # Validates plugins
    └── test_fixes.sh            # Test checklist
```

```
apps/debugger-extension/         # Chrome extension
├── popup.html                   # Extension UI
├── devtools/                    # DevTools panel
├── analyze_duplicate_functions.py
├── analyze_scope_mismatches.py
├── analyze_missing_selectors.py
├── run_all_checks.py
└── README.md                    # Full docs
```

---

## Questions Answered

**Q: "Should Python scripts be in the debugger extension?"**  
A: They ARE! And now the `./dev analyze` command uses them.

**Q: "What tools did we download yesterday?"**  
A: pnpm, just, pre-commit, biome - all installed, run `./dev health` to see.

**Q: "Have we been using them?"**  
A: Not until now! The `./dev` command ties everything together.

**Q: "How do I use them?"**  
A: Just run `./dev <command>` - it's all automated now!

---

## Try It Now!

```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn

# See all commands
./dev help

# Check system health
./dev health

# Analyze your code
./dev analyze

# Install Chrome extension
./dev install
```

---

**That's it! ONE command does everything. No more confusion!**
