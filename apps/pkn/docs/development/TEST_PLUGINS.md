# 🧪 Plugin System Test Guide

## What's Ready to Test RIGHT NOW

### ✅ Send Button (PC)
**Location:** Input area at bottom
**Expected:**
- Arrow icon (➤) instead of "SEND" text
- Cyan gradient background
- Hover: arrow slides right slightly
- Changes to red "STOP" when sending

**Test:**
1. Refresh http://localhost:8010/pkn.html
2. Look at send button - should show arrow
3. Hover over it - should glow and animate
4. Type message and send - should turn red "STOP"

---

### ✅ Plugin System
**Location:** Sidebar → 🔌 Plugins
**Expected:**
- Opens Plugins Manager modal
- Shows list of installed plugins
- Toggle switches to enable/disable
- Welcome Message plugin visible

**Test:**
1. Open PKN
2. Click sidebar (hamburger menu if hidden)
3. Click "🔌 Plugins"
4. Should see Welcome Message plugin
5. Toggle switch should work
6. Close and reopen - state should persist

---

### ✅ Welcome Message Plugin
**Expected:**
- Shows "Welcome to Divine Node!" message in top-right
- Appears 100ms after page load
- Auto-hides after 3 seconds
- Can be closed manually with X button

**Test:**
1. Refresh page
2. Watch top-right corner
3. Should see animated welcome message
4. Should fade out after 3 seconds
5. Go to Plugins, disable "Welcome Message"
6. Refresh - no message should appear
7. Re-enable and refresh - message returns

---

## Browser Console Tests

Open DevTools (F12) and run:

```javascript
// 1. Check plugin system initialized
pluginManager.debug();
// Expected: Shows plugin count, enabled/disabled status

// 2. Check event bus
eventBus.getHistory(10);
// Expected: Shows last 10 events fired

// 3. Get specific plugin
const welcomePlugin = pluginManager.getPlugin('welcome-message');
console.log(welcomePlugin.getInfo());
// Expected: Shows plugin info object

// 4. Toggle plugin programmatically
await pluginManager.toggle('welcome-message');
// Expected: Enables/disables plugin

// 5. Check active events
eventBus.getActiveEvents();
// Expected: Array of event names being listened to

// 6. Emit custom event
eventBus.emit('test:myEvent', { data: 'hello' });
// Expected: No error, event fires

// 7. Subscribe to event
eventBus.on('test:myEvent', (data) => console.log('Received:', data));
eventBus.emit('test:myEvent', { test: 123 });
// Expected: Logs "Received: {test: 123}"
```

---

## Expected Console Output

On page load, you should see:

```
[PluginManager] Initializing plugin system...
[PluginManager] Initialized successfully
[PluginManager] Registering plugin: Welcome Message v1.0.0
[Welcome Message] Plugin initialized
[PluginManager] Plugin "Welcome Message" registered successfully
[Welcome Message] Plugin enabled
[Parakleon] Plugin system initialized
[Parakleon] Initialized successfully
```

---

## Troubleshooting

### Welcome Message Doesn't Appear

**Check:**
1. Is plugin enabled? (Plugins → check toggle)
2. Browser console for errors?
3. Try: `pluginManager.getPlugin('welcome-message').enabled`
4. Should return `true`

**Fix:**
```javascript
// Force enable
await pluginManager.enable('welcome-message');
location.reload();
```

### Plugins Panel Won't Open

**Check:**
1. Is sidebar visible? (Click hamburger menu)
2. Do you see "🔌 Plugins" in sidebar?
3. Console errors?

**Fix:**
```javascript
// Open manually
window.openPluginsManager();
```

### Plugin Toggle Not Working

**Check:**
1. Check localStorage: `localStorage.getItem('pkn_plugin_states')`
2. Should show: `{"welcome-message":true}`

**Fix:**
```javascript
// Clear and reset
localStorage.removeItem('pkn_plugin_states');
location.reload();
```

### Send Button Still Shows "SEND"

**Check:**
1. Hard refresh: Ctrl+Shift+R
2. Clear cache
3. Check CSS loaded: Search for `.send-btn::after` in DevTools

**Fix:**
- CSS might be cached
- Force refresh or clear browser cache

---

## What to Test Next

Once basics work:

### 1. Plugin Persistence
- Enable/disable plugins
- Refresh page
- States should persist

### 2. Multiple Tabs
- Open PKN in 2 tabs
- Disable plugin in tab 1
- Refresh tab 2
- Should be disabled in tab 2

### 3. Plugin Error Handling
```javascript
// Try to enable non-existent plugin
await pluginManager.enable('fake-plugin');
// Should show warning in console, not crash

// Get non-existent plugin
pluginManager.getPlugin('fake-plugin');
// Should return undefined
```

### 4. Event System
```javascript
// Create custom plugin event
const plugin = pluginManager.getPlugin('welcome-message');
plugin.emit('welcome:test', { foo: 'bar' });

// Subscribe from outside
eventBus.on('welcome:test', (data) => console.log('Got:', data));
```

---

## Success Criteria

✅ **System is working if:**
1. Send button shows arrow
2. Plugins panel opens
3. Welcome message appears
4. Toggle switches work
5. No console errors
6. Plugin state persists across reloads

---

## Next Steps After Testing

If all tests pass:

**Option 1:** Build all 9 remaining plugins
- Uses ~70k tokens
- 2-3 hours of implementation
- Full feature set complete

**Option 2:** Build top 3 core plugins
- Quick Actions/Macros
- Voice Input/Output
- Agent Memory Visualization
- Uses ~30k tokens
- Most impactful features first

**Option 3:** Ship what we have
- System is production-ready now
- Add plugins as needed
- User-driven development

---

## Bug Reports

If you find issues, check:

1. **Browser Console** - Any red errors?
2. **Network Tab** - All files loading (200 OK)?
3. **localStorage** - Settings persisting?
4. **File paths** - All imports resolving?

Common issues:
- JSON import needs `assert { type: 'json' }` (some browsers)
- Paths must be relative `'../../js/plugin-base.js'`
- CSS must be injected via `injectCSS()` method

---

Ready to test! 🚀

Open http://localhost:8010/pkn.html and verify each item above.

Report back:
- ✅ What works
- ❌ What doesn't
- 💡 What you want next
