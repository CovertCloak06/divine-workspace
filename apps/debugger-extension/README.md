# 🐞 Divine Debugger - Chrome Extension

**Visual UI Inspector, Style Editor & Interactive Code Learning Platform**

A Chrome DevTools extension designed for **beginners** - analyze code quality, debug issues, and learn best practices without touching the terminal!

## 🚀 Installation

### Load Unpacked Extension (Development)

1. **Open Chrome Extensions Page**
   ```
   chrome://extensions/
   ```

2. **Enable Developer Mode**
   - Toggle the "Developer mode" switch in the top right

3. **Load Extension**
   - Click "Load unpacked"
   - Select the `debugger-extension` folder
   - Extension icon will appear in your toolbar!

4. **Use Divine Debugger**
   - Navigate to any webpage
   - Open DevTools (F12 or Right-click → Inspect)
   - Click the "Divine Debugger" tab
   - Start debugging!

## ✨ Features

### 🔍 **NEW: Code Analysis & Learning Mode** ⭐
**No terminal required - just click buttons!**

- **🚀 One-Click Analysis**: Scan your entire codebase for common issues
- **📋 Duplicate Functions**: Find functions defined in multiple files
- **🔄 Scope Mismatches**: Detect local vs window.variable conflicts
- **🎯 Missing Selectors**: Find CSS/HTML elements referenced but not defined
- **📚 Learning Mode**: Toggle detailed explanations for each issue
  - **Why it matters** - Understand the problem
  - **How bugs happen** - See real examples
  - **How to fix** - Step-by-step instructions
  - **Best practices** - Prevent future issues

**Perfect for beginners** - Turns code analysis into an interactive learning experience!

See [LEARNING_MODE.md](LEARNING_MODE.md) for full documentation.

---

### 🎓 **NEW: Interactive Tutorial System** 🌟
**Learn by doing, not just reading!**

- **🎯 Hands-On Lessons**: Write real code and see instant results
- **📖 Two Modes**: Interactive (hands-on) or Reading (full docs)
- **🎨 Visual Learning**: Diagrams, examples, and live previews embedded in every step
- **✅ Progress Tracking**: Your progress is saved automatically
- **🏆 Completion System**: Track which lessons you've mastered

**Launch Tutorial**: Click "🎓 Start Interactive Tutorial" in the Code Analysis tab

**Available Lessons**:
- **🎯 Your First HTML Element** - Create buttons and see them appear live
- **🎨 Make It Pretty with CSS** - Add colors, padding, and styling
- **⚡ Make It DO Something** - Add click behavior with JavaScript
- **🔧 Fix Real Issues** - Learn by fixing actual code problems

**Features**:
- Code editor with syntax checking
- Interactive sliders to adjust CSS properties
- Quizzes to test understanding
- Live previews of your code
- Hints when you get stuck

See [QUICK_START.md](QUICK_START.md) for 5-minute setup guide.

---

### 🎯 Element Inspector
- Select any element on the page
- View element info (tag, ID, classes)
- Quick actions: Hide, Show, Highlight

### 🎨 Style Editor
- **Layout**: Width, height, padding, margin
- **Appearance**: Colors, border radius, opacity, z-index
- **Typography**: Font size, family, weight
- Real-time preview as you adjust

### 🖥️ Console Logger
- View console messages from the inspected page
- Filter by log level
- Clear and manage logs

### 🧪 JavaScript Evaluator
- Execute code in the inspected page context
- View results instantly
- Expression history

### 💾 Theme Management
- Save your style changes as themes
- Export to CSS files
- Load and apply saved themes

## 📖 How to Use

1. **Open DevTools** on any webpage (F12)
2. **Find "Divine Debugger" tab** in DevTools
3. **Select an element** from the dropdown or click "Inspect Element"
4. **Adjust styles** using the Style Editor panel
5. **See changes live** on the actual page
6. **Save your work** with Theme Management

## 🎨 Interface

- **Dark theme** with cyan (#00FFFF) accents
- **Left Panel**: Element inspector & quick actions
- **Right Panel**: Style editor & theme tools
- **Bottom Panel**: Console & JavaScript evaluator

## 🔧 Technical Details

### Permissions Required
- `activeTab`: Access current tab for inspection
- `storage`: Save themes and preferences
- `<all_urls>`: Inject styles into any page

### Files Structure
```
debugger-extension/
├── manifest.json           # Extension config
├── popup.html             # Extension popup
├── icons/                 # Extension icons
├── devtools/
│   ├── devtools.html      # DevTools entry point
│   ├── devtools.js        # Panel registration
│   ├── panel.html         # Main debugger UI
│   └── panel.js           # Extension logic
├── css/
│   └── debugger.css       # Styles
└── js/                    # (future enhancements)
```

## 🆚 vs Browser DevTools

**Divine Debugger** complements Chrome DevTools:
- **Simpler UI** for quick style tweaks
- **Visual controls** (sliders, color pickers)
- **Theme saving** for design iterations
- **Quick actions** for common tasks

**Chrome DevTools** is better for:
- Breakpoint debugging
- Network monitoring
- Performance profiling
- DOM manipulation

## 🔮 Future Enhancements

- [ ] Network request monitoring
- [ ] Performance metrics
- [ ] CSS animations editor
- [ ] Responsive design testing
- [ ] Element screenshot
- [ ] Style diff/compare
- [ ] Keyboard shortcuts

## 🐛 Troubleshooting

### Extension not showing in DevTools?
- Refresh the extension at `chrome://extensions/`
- Reload the page you're inspecting
- Close and reopen DevTools

### Can't modify elements?
- Check if site has CSP (Content Security Policy) restrictions
- Some sites block external modifications

### Changes not saving?
- Use "Save Theme" to persist changes
- Changes are live only - refresh reverts them

## 📝 Development

### Making Changes
1. Edit files in `debugger-extension/`
2. Go to `chrome://extensions/`
3. Click reload icon on Divine Debugger card
4. Refresh DevTools panel

### Adding Features
- **panel.js**: Main extension logic
- **panel.html**: UI structure
- **debugger.css**: Styling

## 🔍 Code Analysis Tools

The debugger-extension also includes **Python analysis scripts** to catch common bugs before they cause issues in production.

### Analysis Scripts

| Script | Purpose | Catches |
|--------|---------|---------|
| `analyze_duplicate_functions.py` | Find functions defined in multiple files | Duplicate implementations, inconsistent behavior |
| `analyze_scope_mismatches.py` | Detect local vs window.variable usage | Scope bugs, missed state changes |
| `analyze_missing_selectors.py` | Find CSS/HTML selectors referenced but not defined | Runtime errors, null element bugs |
| `run_all_checks.py` | Run all analysis checks | Complete codebase audit |

### Usage

**Run all checks:**
```bash
cd /home/gh0st/pkn/debugger-extension
python3 run_all_checks.py /home/gh0st/pkn
```

**Run individual checks:**
```bash
python3 analyze_duplicate_functions.py /home/gh0st/pkn
python3 analyze_scope_mismatches.py /home/gh0st/pkn
python3 analyze_missing_selectors.py /home/gh0st/pkn
```

### Example Output

```
❌ DUPLICATE FUNCTIONS FOUND:
============================================================

🔴 Function: openProjectMenu
   - app.js:3433
   - js/projects.js:106

⚠️  These functions may cause bugs if one is updated and the other isn't.
   Consider: Remove unused version or rename to avoid conflicts.
```

### When to Run

- **Before committing** major changes
- **After adding** new features that span multiple files
- **When debugging** mysterious bugs
- **Before production** deployments

### Integration with Development Workflow

Add to `.git/hooks/pre-commit` for automatic checking:
```bash
#!/bin/bash
cd debugger-extension
python3 run_all_checks.py /home/gh0st/pkn || exit 1
```

## 📄 License

Free to use and modify.

---

**Built with ❤️ for developers who love visual debugging and clean code**
