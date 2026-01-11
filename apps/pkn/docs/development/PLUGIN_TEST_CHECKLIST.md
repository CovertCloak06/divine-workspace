# Plugin Manual Test Checklist

Open http://localhost:8010/pkn.html and follow this checklist to manually verify each plugin works.

## ✅ Plugin Manager

1. Open sidebar
2. Click **🔌 Plugins**
3. Verify all 10 plugins listed
4. Toggle plugins on/off
5. Click settings icon on any plugin
6. Verify settings modal opens

**Expected:** Plugins Manager modal shows all plugins with toggle switches

---

## ✅ 1. Welcome Message Plugin

**How to test:**
1. Clear localStorage: `localStorage.clear()`
2. Refresh page
3. Should see welcome screen with project info

**Expected:** Welcome screen appears on fresh load

---

## ✅ 2. Smart Context Detector

**How to test:**
1. Enable plugin in Plugin Manager
2. Type code in message input: `function test() { return 42; }`
3. Watch for toast notification suggesting "CODER agent"
4. Type a URL: `https://example.com`
5. Watch for toast suggesting "RESEARCHER agent"

**Expected:** Toast notifications suggest appropriate agents

---

## ✅ 3. Voice I/O

**How to test:**
1. Enable plugin in Plugin Manager
2. Look for 🎤 microphone button in input area
3. Click microphone button
4. Speak into microphone
5. Verify text appears in input
6. Enable "Auto-speak" in settings
7. Send message and listen for TTS response

**Expected:**
- Mic button appears
- Speech converts to text
- TTS reads responses (if auto-speak enabled)

**Note:** Requires browser speech API support (Chrome/Edge work best)

---

## ✅ 4. Quick Actions & Macros

**How to test:**
1. Enable plugin in Plugin Manager
2. Look for ⚡ lightning bolt button in input area
3. Click lightning bolt
4. Verify menu shows 6 pre-built actions:
   - 🐛 Debug This Code
   - 📚 Research & Summarize
   - 🔒 Security Audit
   - 💡 Explain Code
   - ⚡ Optimize Performance
   - 🧪 Generate Tests
5. Paste some code in input
6. Click "Debug This Code"
7. Watch multi-agent workflow execute

**Expected:**
- ⚡ button appears
- Menu opens with workflows
- Workflows execute sequentially

---

## ✅ 5. Agent Memory Visualization

**How to test:**
1. Enable plugin in Plugin Manager
2. Click **🧠 Agent Memory** in sidebar
3. Verify panel slides in from right
4. Send message: "I prefer TypeScript over JavaScript"
5. Check if memory was captured
6. Click "+ Add Memory" button
7. Add manual memory
8. Test export and clear functions

**Expected:**
- Memory panel appears
- Preferences extracted from messages
- Manual memories can be added
- Export downloads JSON

---

## ✅ 6. Meeting Summarizer

**How to test:**
1. Enable plugin in Plugin Manager
2. Click **📋 Meeting Summarizer** in sidebar
3. Paste meeting notes (example below)
4. Click "📊 Analyze Meeting"
5. Verify extraction of:
   - Action items
   - Decisions
   - Attendees
   - Key points
6. Test export and copy to clipboard

**Example meeting notes:**
```
Meeting: Q1 Planning
Attendees: Alice, Bob, Charlie

Decisions:
- Decided to launch new feature by March 1st
- Agreed to hire 2 new developers

Action Items:
- Alice will create design mockups
- Bob to research database options
- Charlie will update project roadmap
```

**Expected:**
- Meeting analyzed and structured
- Action items listed with owners
- Export works

---

## ✅ 7. Code Diff Viewer

**How to test:**
1. Enable plugin in Plugin Manager
2. Look for **⚖️ Diff** button in chat toolbar
3. Click Diff button
4. Click "+ New Diff"
5. Paste original code in left
6. Paste modified code in right
7. Click "Generate Diff"
8. Toggle between Split/Unified views
9. Check diff history

**Example:**
- Original: `function add(a, b) { return a + b; }`
- Modified: `function add(a, b) { return a + b + 1; }`

**Expected:**
- Side-by-side comparison
- Green for additions, red for deletions
- Statistics shown (+/- lines)

---

## ✅ 8. Code Execution Sandbox

**How to test:**
1. Enable plugin in Plugin Manager
2. Click **▶️ Code Sandbox** in sidebar
3. Enter JavaScript code:
   ```javascript
   console.log('Hello from PKN!');
   return 2 + 2;
   ```
4. Click "▶️ Run Code"
5. Verify output shows: "Hello from PKN!" and "→ 4"
6. Test with error: `throw new Error('test')`
7. Verify error displayed in red

**Expected:**
- Code executes safely
- Console output captured
- Errors shown in error pane
- Return value displayed

---

## ✅ 9. Agent Collaboration Theater

**How to test:**
1. Enable plugin in Plugin Manager
2. Click **🎭 Collaboration Theater** in sidebar
3. Theater panel slides up from bottom
4. Send multi-agent message: "Debug this code and then test it"
5. Watch agents animate on stage:
   - Agents bounce when thinking
   - Thought bubbles appear
   - Collaboration beams between agents
6. Check collaboration log at bottom

**Expected:**
- Theater shows agent avatars
- Animations when agents work
- Log shows agent communication
- Visual beams between collaborating agents

---

## ✅ 10. Dark Web OSINT

**How to test:**
1. Enable plugin in Plugin Manager
2. Click **🕵️ Dark Web OSINT** in sidebar
3. Panel opens with warning banner
4. **Breach Lookup tab:**
   - Enter email: test@example.com
   - Click "🔍 Check Breaches"
   - Verify mock breach results shown
5. **Monitoring tab:**
   - Add email to monitor
   - Verify it appears in monitored list
6. **Threat Intel tab:**
   - Click "View Feed" on any category
   - Verify threat feed displays
7. **Onion Tools tab:**
   - Enter .onion address (format: example.onion)
   - Click "🧅 Analyze"
   - Verify analysis shown

**Expected:**
- Dark red cyberpunk theme
- Warning banner visible
- All tabs functional
- Mock data displays correctly

---

## Quick Test All Plugins

**Run this in browser console:**
```javascript
// Check all plugins loaded
console.log('Registered plugins:', window.pluginManager.getAllPlugins().length);

// Should output: 10

// Check plugin names
window.pluginManager.getAllPlugins().forEach(p => {
    console.log('✓', p.manifest.name);
});
```

**Expected output:**
```
✓ Welcome Message
✓ Smart Context Detector
✓ Voice Input/Output
✓ Quick Actions & Macros
✓ Agent Memory Visualization
✓ Meeting Summarizer
✓ Code Diff Viewer
✓ Code Execution Sandbox
✓ Agent Collaboration Theater
✓ Dark Web OSINT
```

---

## Troubleshooting

### Plugin not appearing
1. Check Plugin Manager - ensure plugin is enabled
2. Check browser console (F12) for errors
3. Hard refresh: Ctrl+Shift+R

### Plugin panel not opening
1. Check if button exists in sidebar/toolbar
2. Look for `window.pluginName` in console
3. Verify onclick handlers attached

### No toast notifications
1. Check if notifications blocked in browser
2. Verify toast container exists in DOM
3. Check plugin's `showToast()` method works

---

## Test Results Template

```
[ ] Plugin Manager opens and shows all 10 plugins
[ ] Welcome Message shows on fresh load
[ ] Context Detector suggests agents
[ ] Voice I/O microphone button works
[ ] Quick Actions menu appears with 6 workflows
[ ] Agent Memory panel tracks preferences
[ ] Meeting Summarizer extracts action items
[ ] Diff Viewer compares code side-by-side
[ ] Code Sandbox executes JavaScript
[ ] Collaboration Theater animates agents
[ ] Dark Web OSINT shows breach data
```

**All checkboxes checked = All plugins working! 🎉**
