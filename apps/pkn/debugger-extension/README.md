# PKN Debugger Extension - Code Quality Tools

Automated code analysis tools that catch common bugs before they hit production.

## Quick Start

```bash
# Run all checks
python debugger-extension/run_all_checks.py

# Or from workspace root
just code-quality
```

## Available Analyzers

### 1. Duplicate Function Analyzer
**File:** `analyze_duplicate_functions.py`

Finds functions defined in multiple files - a common source of shadowing bugs.

**Example bug caught:**
```javascript
// app.js line 234
function openProjectMenu() { ... }

// projects.js line 56
function openProjectMenu() { ... }  // This shadows the first one!
```

**Run standalone:**
```bash
python analyze_duplicate_functions.py /path/to/project
```

### 2. Scope Mismatch Analyzer
**File:** `analyze_scope_mismatches.py`

Finds variables used inconsistently with `window.*` prefix.

**Example bug caught:**
```javascript
// Line 100: Uses local variable
openMenuElement = menu;

// Line 200: Uses window (different variable!)
window.openMenuElement = null;
```

**Run standalone:**
```bash
python analyze_scope_mismatches.py /path/to/frontend
```

### 3. Missing Selector Analyzer
**File:** `analyze_missing_selectors.py`

Finds JavaScript references to CSS classes/IDs that don't exist.

**Example bug caught:**
```javascript
// JS references .chat-container
document.querySelector('.chat-container')

// But it doesn't exist in CSS or HTML!
// Returns null, causes errors later
```

**Run standalone:**
```bash
python analyze_missing_selectors.py /path/to/frontend
```

## Integration

### With justfile (Recommended)
```bash
just code-quality      # Run all checks
just ci                # Includes code quality in CI pipeline
```

### With pre-commit
Checks run automatically before each commit. If issues found, commit is blocked.

### Manual
```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn
python debugger-extension/run_all_checks.py .
```

## Exit Codes

- `0` - All checks passed
- `1` - One or more checks failed

## Adding New Analyzers

1. Create `analyze_*.py` in this directory
2. Follow the pattern of existing analyzers:
   - Accept path as first argument
   - Print colored output
   - Exit 0 for pass, 1 for fail
3. Add to `run_all_checks.py` checks list
4. Update this README

## Suppressing False Positives

Some issues are intentional. Document them:

```javascript
// @code-quality-ignore: duplicate-function - Intentional override for mobile
function init() { ... }
```

(Note: Suppression comments are not yet implemented - TODO for future)
