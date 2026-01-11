# 🚀 Quick Start - Code Analysis

## 5-Minute Setup

### 1. Install the Extension
```bash
# In Chrome, go to:
chrome://extensions/

# Click "Developer mode" toggle (top right)
# Click "Load unpacked"
# Select folder: /home/gh0st/dvn/divine-workspace/apps/pkn/debugger-extension
```

### 2. Open Your Project
```bash
# Start PKN server
cd /home/gh0st/dvn/divine-workspace/apps/pkn
./pkn_control.sh start-all

# Open in browser
# Navigate to: http://localhost:8010
```

### 3. Open Code Analysis
```
1. Press F12 (open DevTools)
2. Click "Divine Debugger" tab
3. Click "🔍 Code Analysis" tab at bottom
4. Click "🚀 Run Full Analysis"
```

## What You'll See

### ✅ Clean Code (No Issues)
```
📊 Analysis Complete
Analyzed 10 files

┌──────────────────┬──────────────────┬──────────────────┐
│ 📋 Duplicate     │ 🔄 Scope         │ 🎯 Missing       │
│ Functions        │ Mismatches       │ Selectors        │
│                  │                  │                  │
│      0           │      0           │      0           │
└──────────────────┴──────────────────┴──────────────────┘

✅ All Checks Passed!
Your codebase is clean 🎉
```

### ⚠️ Issues Found
```
📊 Analysis Complete
Analyzed 10 files

┌──────────────────┬──────────────────┬──────────────────┐
│ 📋 Duplicate     │ 🔄 Scope         │ 🎯 Missing       │
│ Functions        │ Mismatches       │ Selectors        │
│                  │                  │                  │
│      3           │      5           │      2           │
└──────────────────┴──────────────────┴──────────────────┘

📋 Duplicate Functions (3)
├─ 🔴 closeHistoryMenu()
│   • app.js:2229
│   • js/utils.js:70
│
├─ 🔴 getAllModels()
│   • app.js:751
│   • app.js:867 (SAME FILE!)
│
└─ 🔴 networkAction()
    • app.js:671
    • js/main.js:80

🔄 Scope Mismatches (5)
├─ 🔴 ACTIVE_MODEL
│   Used as LOCAL in: app.js
│   Used as WINDOW.ACTIVE_MODEL in: js/models.js, js/chat.js
│
└─ ... (more issues)
```

## Understanding Results

### Color Coding
- 🟢 **Green** = No issues found (good!)
- 🟠 **Orange** = Issues found (needs attention)
- 🔴 **Red** = Critical issue (fix ASAP)

### Issue Counts
- **0-2 issues**: Excellent code quality
- **3-10 issues**: Normal for active development
- **10+ issues**: Consider refactoring

## Using Learning Mode

### Enable Explanations
```
Click "📖 Show Detailed Explanations" button

Each issue now shows:
├─ Why this matters
├─ How bugs happen
├─ How to fix
└─ Best practices
```

### Example With Explanation
```
🔴 ACTIVE_MODEL
   Used as LOCAL in: app.js
   Used as WINDOW.ACTIVE_MODEL in: js/models.js

Why this matters:
  Using a variable as both LOCAL and window.variable creates TWO
  separate variables. Changes to one won't affect the other,
  causing state sync bugs.

How bugs happen:
  // app.js
  let ACTIVE_MODEL = 'gpt-4';  // Local variable

  // js/models.js
  window.ACTIVE_MODEL = 'claude-3';  // Different variable!

  // Now you have TWO values - causes bugs!

How to fix:
  Change app.js to use window:
  window.ACTIVE_MODEL = 'gpt-4';  // Now both files share same variable

Best practices:
  Pick ONE approach (window.* or modules) and use consistently.
```

## Individual Checks

Instead of running all checks, you can run one at a time:

### Check for Duplicates Only
```
Click "📋 Duplicate Functions" button

Shows only duplicate function issues
Faster than full analysis
```

### Check for Scope Issues Only
```
Click "🔄 Scope Mismatches" button

Shows only local vs window.variable conflicts
```

### Check for Missing Elements Only
```
Click "🎯 Missing Selectors" button

Shows only CSS/HTML elements referenced but not found
```

## Tips & Tricks

### Analyze Different Project
```
1. Change URL in input box:
   http://localhost:8010  →  http://localhost:3000

2. Click "🚀 Run Full Analysis" again
```

### Re-run After Fixes
```
1. Fix issues in your code
2. Reload your project (Ctrl+R)
3. Click "🚀 Run Full Analysis" again
4. Watch issue count go down!
```

### Save Results
```
Right-click in results area
→ "Inspect Element"
→ Copy HTML
→ Paste into text file

Or just take a screenshot!
```

## Common Questions

### Q: Why is it loading forever?
**A**: Make sure your server is running at the URL you entered.
```bash
# Check if server is running:
curl http://localhost:8010/health

# Should return: {"status":"ok"}
```

### Q: It says "Error loading project"
**A**: Check the URL is correct and server is accessible.
```
✓ Correct: http://localhost:8010
✗ Wrong:   localhost:8010 (missing http://)
✗ Wrong:   http://localhost:8010/ (trailing slash may cause issues)
```

### Q: Some files aren't being analyzed
**A**: The analyzer loads specific PKN files. To add more files, edit `code-analyzer.js`:
```javascript
const filesToLoad = [
    'app.js',
    'js/main.js',
    // Add your file here:
    'js/my-new-file.js',
];
```

### Q: Can I use this on non-PKN projects?
**A**: Yes! Change the URL to any local server. The analyzer works on any JavaScript project.

### Q: How often should I run analysis?
**A**:
- **Daily**: During active development
- **Before commits**: Catch issues before pushing
- **After major changes**: Verify nothing broke
- **When debugging**: Find root cause of mysterious bugs

## Next Steps

### Learn More
- Read [LEARNING_MODE.md](LEARNING_MODE.md) for full documentation
- See [ANALYSIS_RESULTS.md](ANALYSIS_RESULTS.md) for real examples from PKN

### Contribute
- Add new analysis checks
- Improve explanations
- Create tutorials
- Report bugs

### Share
- Show other beginners this tool
- Write blog posts about your experience
- Create video tutorials
- Translate to other languages

---

**Happy coding! 🚀**
