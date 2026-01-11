# Pre-Session Checklist - Run BEFORE Starting Work

## 🎯 1-Minute Quick Check

```bash
# Navigate to workspace
cd /home/gh0st/dvn/divine-workspace

# Run automated health check
just health

# Check for any broken imports/modules
just check-imports

# If errors found:
just fix-imports
```

## ✅ Expected Output (All Good)

```
🏥 Checking system health...
✅ PKN server: Running on port 8010
✅ Code Academy: Ready
✅ All dependencies installed

🔍 Checking JavaScript imports and modules...
✅ No critical errors found
```

## ❌ If You See Errors

### Import Errors
```bash
just fix-imports          # Auto-fix common issues
just check-imports        # Verify fixed
```

### Server Not Running
```bash
just dev-app pkn          # Start PKN
just dev-app code-academy # Start Code Academy
```

### Dependencies Missing
```bash
just setup                # Re-run full setup
```

## 🚀 Start Coding

Once all checks pass:
1. Open browser: http://localhost:8010
2. Open DevTools: F12
3. Check for console errors (should be none)
4. Start working!

## 📝 Remember

- **Never skip** `just check-imports` - saves hours of debugging
- **Always** hard refresh browser after changes (Ctrl+Shift+R)
- **Run** `just ci` before committing code

---

**Estimated time: 1 minute**
**Saves: Hours of frustration**
