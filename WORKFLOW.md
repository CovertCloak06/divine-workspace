# Development Workflow - ALWAYS FOLLOW THIS

## 🚨 Before Making ANY Code Changes

### 1. Run Analysis Tools FIRST
```bash
# Check current state
just check-imports                # Detect import/module issues
just check-file-sizes             # Check 200-line limit
just health                       # Check servers running

# If issues found:
just fix-imports                  # Auto-fix common import problems
```

### 2. Use Visual Debugger (Chrome Extension)
```bash
# Only if you see UI bugs or broken features:
1. Open http://localhost:8010
2. Press F12 → "Divine Debugger" tab
3. Click "🚀 Run Full Analysis"
4. Fix issues shown
```

### 3. Run Full Checks Before Committing
```bash
just ci                           # Runs: check-imports, lint, format, test, file-sizes
```

## 🛠️ When Something Breaks

### Step 1: ANALYZE (Don't Guess!)
```bash
# Run automated checks
just check-imports
cd apps/debugger-extension && python3 run_all_checks.py ../pkn

# Check browser console
# Open DevTools (F12) → Console tab
# Look for errors (red text)
```

### Step 2: FIX Using Tools
```bash
# Try auto-fix first
just fix-imports

# If that doesn't work, check the SPECIFIC error:
# - Import errors → Fix paths in modules
# - onclick not working → Add function to window.* in pkn.js
# - Module not loading → Check HTML script tags
```

### Step 3: VERIFY Fix
```bash
# Clear browser cache
Ctrl + Shift + R

# Re-run checks
just check-imports

# Test the actual feature
```

## 📋 Daily Development Checklist

### Morning (Start of Work)
- [ ] `just health` - Check all servers
- [ ] `just check-imports` - Verify codebase health
- [ ] Open DevTools extension - Quick visual check

### During Development
- [ ] Add new file → `just check-imports` immediately
- [ ] Change import paths → `just fix-imports`
- [ ] See browser error → Check Console FIRST, don't guess

### Before Committing
- [ ] `just ci` - Full checks
- [ ] Test in browser with hard refresh (Ctrl+Shift+R)
- [ ] Check no console errors (F12 → Console)

### End of Day
- [ ] `just ci` - Final verification
- [ ] Commit if all green
- [ ] Update CLAUDE.md if you learned something new

## 🚫 NEVER Do This

### ❌ Don't Manually Debug Imports
- Use `just check-imports` first
- Use `just fix-imports` to auto-fix
- **Don't** edit files blindly hoping it works

### ❌ Don't Skip the Analysis Tools
- **Don't** guess what's broken
- **Do** run the debugger extension
- **Do** check browser console

### ❌ Don't Forget Browser Cache
- **Always** hard refresh after changes: `Ctrl + Shift + R`
- Chrome aggressively caches JavaScript
- Old code = mysterious bugs

### ❌ Don't Commit Without CI
- `just ci` catches 90% of issues
- Broken builds waste everyone's time
- Run it BEFORE git commit

## 🎯 Tool Reference

### Command Line Tools
| Command | Purpose | When to Use |
|---------|---------|-------------|
| `just check-imports` | Detect import issues | Before coding, after changes |
| `just fix-imports` | Auto-fix imports | When check-imports shows errors |
| `just health` | Check servers | Start of day, after restart |
| `just ci` | Full quality checks | Before commit, after big changes |
| `just lint` | Code style | During development |
| `just format` | Auto-format code | Before commit |

### Visual Tools (Chrome Extension)
| Tool | Purpose | When to Use |
|------|---------|-------------|
| Divine Debugger | Code analysis | When UI broken, mysterious bugs |
| Browser Console (F12) | Runtime errors | When feature doesn't work |
| Network Tab (F12) | API calls | When data not loading |

### Python Analysis Scripts
```bash
cd apps/debugger-extension

# Run all checks
python3 run_all_checks.py ../pkn

# Individual checks
python3 analyze_duplicate_functions.py ../pkn
python3 analyze_scope_mismatches.py ../pkn
python3 analyze_missing_selectors.py ../pkn
```

## 📚 Related Documentation
- [CLAUDE.md](apps/pkn/CLAUDE.md) - PKN specific guide
- [debugger-extension/QUICK_START.md](apps/debugger-extension/QUICK_START.md) - Visual debugger
- [BUILD_TEMPLATE.md](BUILD_TEMPLATE.md) - Monorepo standards

## 💡 Pro Tips

### Faster Debugging
1. **Check browser console FIRST** - 80% of issues show there
2. **Run `just check-imports`** - Catches most build issues
3. **Use the Chrome extension** - Visual, beginner-friendly

### Prevent Issues
1. **Run `just ci` before committing** - Catch issues early
2. **Keep files under 200 lines** - Enforced by pre-commit
3. **Use automation** - Don't manually fix what scripts can fix

### Learn Faster
1. **Read error messages** - They tell you what's wrong
2. **Use Learning Mode** in debugger extension - Explains WHY
3. **Update CLAUDE.md** - Document solutions for next time

---

**REMEMBER: Tools exist to help you. Use them!**
