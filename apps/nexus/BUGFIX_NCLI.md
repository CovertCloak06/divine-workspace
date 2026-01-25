# Bug Fix: ncli Auto-Start Delay

**Date:** 2026-01-24
**Issue:** ncli help message triggered unnecessary Nexus startup
**Status:** ✅ Fixed and Tested

## Problem

Running `ncli` with no arguments (to see help) auto-started Nexus, causing a 5-10 second delay before showing the help message.

### User Experience Before Fix

```bash
$ ncli
⚠ Nexus not running, starting it now...

Starting Nexus services...
✓ Nexus Backend running
✓ llama.cpp running

⏳ Waiting for services to be ready...
✓ Nexus ready!

Nexus CLI - Terminal command interface

Usage: ncli <command> [args...]
...
# Total time: ~7 seconds for a simple help message
```

## Root Cause

**Logic order in ncli script (lines 17-58)**

The health check happened **before** the argument count check:

```bash
# WRONG ORDER:
1. Check if Nexus is running (line 17)
2. If not, auto-start all services (5-10s)
3. Check if user provided arguments (line 45)
4. If no args, show help and exit

# Result: Help message required full Nexus startup
```

## Solution

**Reordered the logic checks:**

```bash
# CORRECT ORDER:
1. Check if user provided arguments (line 17)
2. If no args, show help and exit immediately (~2ms)
3. Check if Nexus is running (line 32)
4. If not, auto-start services (only when needed)

# Result: Help is instant, auto-start only for actual commands
```

### Code Changes

**File:** `/home/gh0st/dvn/divine-workspace/apps/nexus/ncli`

**Change:** Moved lines 44-58 (argument check) to lines 17-30 (before health check)

```diff
+ # Check args BEFORE health check to avoid unnecessary 5-10s startup delay
+ # when user just wants help message (should be instant ~2ms)
+ # If no args, show help (don't auto-start Nexus just for help)
+ if [ $# -eq 0 ]; then
+     echo -e "${CYAN}Nexus CLI${NC} - Terminal command interface"
+     # ... help message ...
+     exit 0
+ fi
+
  # Check if Nexus is running, auto-start if not (only when user provides a command)
  if ! curl -s "$NEXUS_URL/health" >/dev/null 2>&1; then
      # ... auto-start logic ...
  fi
-
- # If no args, show help
- if [ $# -eq 0 ]; then
-     # ... help message ...
-     exit 0
- fi
```

## Verification

### User Experience After Fix

```bash
$ ncli
Nexus CLI - Terminal command interface

Usage: ncli <command> [args...]
...
# Total time: ~2ms (instant)
```

### Test Suite Results

Created automated tests in `tests/test_ncli.sh`:

```bash
Testing ncli functionality...

Test 1: ncli help (no auto-start)... ✓ Help shown in 2ms
Test 2: ncli command (with auto-start)... ✓ Nexus auto-started successfully
Test 3: ncli with Nexus running... ✓ No unnecessary startup messages

All tests passed!
```

### Performance Improvement

| Scenario | Before | After | Improvement |
|----------|--------|-------|-------------|
| `ncli` (help) | ~7000ms | ~2ms | **3500x faster** |
| `ncli /command` (stopped) | ~7500ms | ~7500ms | No change |
| `ncli /command` (running) | ~500ms | ~500ms | No change |

## Edge Cases Tested

✅ No arguments → Instant help, no auto-start
✅ Command with Nexus stopped → Auto-starts correctly
✅ Command with Nexus running → Executes immediately
✅ Invalid arguments → Passed through to backend

## Regression Prevention

**Test file created:** `tests/test_ncli.sh`

Run regression tests:
```bash
cd /home/gh0st/dvn/divine-workspace/apps/nexus
./tests/test_ncli.sh
```

## Code Review

**Reviewed by:** code-reviewer agent
**Verdict:** ✅ Ready - Clean, correct, no issues introduced

**Key findings:**
- Logic flow is correct
- All edge cases covered
- Code quality maintained
- Backwards compatible
- No security implications

## Summary

**Fixed:** ncli help message no longer auto-starts Nexus
**Impact:** 3500x faster help display (7s → 2ms)
**Risk:** None - fully backwards compatible
**Testing:** Automated tests created and passing

**Commit Message:**
```
fix(ncli): prevent auto-start on help message

ncli with no args now shows help instantly (~2ms) instead of
auto-starting Nexus first (~7s). Auto-start still works correctly
when user provides an actual command.

- Reordered argument check before health check
- Added regression tests in tests/test_ncli.sh
- Documented fix in BUGFIX_NCLI.md

Fixes: Help message performance
```
