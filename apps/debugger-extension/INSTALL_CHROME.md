# 🚀 Install Divine Debugger in Chrome

## Quick Install (5 minutes)

### Step 1: Copy the Extension Path

The extension is located at:
```
/home/gh0st/dvn/divine-workspace/apps/debugger-extension
```

**Copy this path** (you'll need it in Step 4)

### Step 2: Open Chrome Extensions Page

**Option A**: Type in address bar:
```
chrome://extensions/
```

**Option B**: Click menu → More Tools → Extensions

### Step 3: Enable Developer Mode

1. Look at the **top right** of the extensions page
2. Find the toggle switch that says **"Developer mode"**
3. **Turn it ON** (it will turn blue)

You'll now see 3 new buttons appear:
- Load unpacked
- Pack extension
- Update

### Step 4: Load the Extension

1. Click the **"Load unpacked"** button (top left area)
2. A file browser will open
3. Navigate to: `/home/gh0st/dvn/divine-workspace/apps/debugger-extension`
4. Click **"Select"** or **"Open"**

**DONE!** You'll see a new card appear:

```
┌────────────────────────────────────────┐
│ 🐞 Divine Debugger                     │
│ Visual UI Inspector & Style Editor    │
│                                        │
│ Version: 1.0.0                         │
│ ID: abc123...                          │
│                                        │
│ [Details] [Remove] [⟳]                │
└────────────────────────────────────────┘
```

### Step 5: Test It Works

1. Navigate to **any webpage** (like http://localhost:8010)
2. Press **F12** (or Right-click → Inspect)
3. Look for a new tab at the top: **"Divine Debugger"**
4. Click it!

You should see:
- 🎯 Element Inspector panel
- 🎨 Style Editor panel
- 🔍 Code Analysis tab (bottom tabs)

---

## 🔄 Updating an Existing Extension

### If You Already Have It Installed:

**Option 1: Reload Button (Fastest)**
1. Go to `chrome://extensions/`
2. Find the "Divine Debugger" card
3. Click the **reload icon (⟳)** at the bottom right
4. **Done!** Changes are now live

**Option 2: Remove and Reinstall**
1. Go to `chrome://extensions/`
2. Find "Divine Debugger"
3. Click **"Remove"**
4. Follow "Install" steps above

---

## 📸 Visual Guide

### What You're Looking For:

**Step 3 - Developer Mode Toggle:**
```
Extensions Page - Top Right:
┌──────────────────────────────────┐
│  [🔍 Search]        Developer ⬜ OFF  │  ← Turn this ON
└──────────────────────────────────┘
```

After turning it ON:
```
Extensions Page - Top Right:
┌──────────────────────────────────┐
│  [🔍 Search]        Developer ☑ ON   │  ← Now blue/on
└──────────────────────────────────┘

New buttons appear:
[Load unpacked] [Pack extension] [Update]
       ↑
   Click this!
```

**Step 4 - File Browser:**
```
Navigate to:
/home/gh0st/dvn/divine-workspace/apps/

Then select:
debugger-extension/  ← This folder
```

**Step 5 - DevTools Tab:**
```
Chrome DevTools (F12):
[Elements] [Console] [Sources] [Network] [Divine Debugger] ← New tab!
                                              ↑
                                          Click here!
```

---

## ✅ Verification Checklist

After installation, verify it works:

- [ ] Extension appears in `chrome://extensions/`
- [ ] Extension card shows "Divine Debugger v1.0.0"
- [ ] No errors shown on the card
- [ ] Can open DevTools (F12)
- [ ] "Divine Debugger" tab appears in DevTools
- [ ] Can click Code Analysis tab
- [ ] Buttons respond to clicks

---

## 🐛 Troubleshooting

### "Load unpacked" button is greyed out
**Fix**: Turn on Developer Mode (Step 3)

### "This extension may not be listed in the Chrome Web Store"
**That's normal!** It's a local development extension. Click "Load anyway" or dismiss.

### Extension doesn't appear in DevTools
**Fix**:
1. Close DevTools (F12)
2. Reload the page (Ctrl+R)
3. Reopen DevTools (F12)
4. Look for the tab again

### Changes not showing after update
**Fix**:
1. Go to `chrome://extensions/`
2. Click reload icon (⟳) on Divine Debugger card
3. Close and reopen DevTools

### "Manifest file is missing or unreadable"
**Fix**: Make sure you selected the `debugger-extension` folder, not a file inside it

---

## 🎓 Using the Extension

Once installed:

### For Code Analysis:
1. Press F12 on http://localhost:8010
2. Click "Divine Debugger" tab
3. Click "🔍 Code Analysis" tab at bottom
4. Click "🚀 Run Full Analysis"
5. See results with color coding!

### For Style Editing:
1. Select any element on the page
2. Adjust sliders in Style Editor panel
3. See changes live on the page!

### For Learning:
1. Go to Code Analysis tab
2. Click "📖 Show Detailed Explanations"
3. Click "🎓 Start Interactive Tutorial"
4. Learn by doing!

---

## 📝 Notes

- **Extension stays installed** even after closing Chrome
- **Updating**: Just click reload icon after making changes
- **Multiple projects**: Works on any webpage, not just PKN
- **No internet required**: Runs locally, fully offline

---

**Need help?** Run: `dev install` for quick instructions
