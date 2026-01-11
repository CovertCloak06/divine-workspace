# Divine Node PWA Guide

**Progressive Web App Installation & Usage**

---

## What is a PWA?

Divine Node is now a **Progressive Web App (PWA)** - a modern web application that can be installed on your device and used like a native app, with:

- 📱 **Install like an app** - Add to home screen on Android/iOS
- 🚀 **Fast loading** - Cached files load instantly
- 📴 **Offline support** - Works without internet (limited functionality)
- 🔔 **Future features** - Push notifications, background sync (coming soon)
- 🔄 **Auto-updates** - Always get the latest version
- 💯 **100% expandable** - Can be wrapped in Capacitor for full native app

---

## Installation Guide

### Android (Chrome/Edge)

1. **Open Divine Node in browser**
   ```
   http://localhost:8010/pkn.html
   ```

2. **Look for the "Install App" button**
   - Floating button in bottom-right corner
   - Cyan with download icon
   - Click it!

3. **Alternative: Browser menu**
   - Tap the ⋮ menu
   - Select "Install app" or "Add to Home screen"
   - Tap "Install"

4. **Launch the app**
   - Find "Divine Node" icon on home screen
   - Opens in standalone mode (no browser UI)
   - Full screen experience!

### iOS (Safari)

1. **Open Divine Node in Safari**
   ```
   http://localhost:8010/pkn.html
   ```

2. **Tap the Share button** (square with arrow)

3. **Scroll down and tap "Add to Home Screen"**

4. **Tap "Add" in top-right**

5. **Launch from home screen**

### Desktop (Chrome/Edge)

1. **Open Divine Node**
   ```
   http://localhost:8010/pkn.html
   ```

2. **Click install icon** in address bar
   - Or use "Install App" button

3. **Click "Install" in the popup**

4. **Launch from:**
   - Desktop shortcut
   - Start menu (Windows)
   - Applications folder (macOS)
   - App drawer (Linux)

---

## Features

### ✅ What Works Offline

- **UI & Interface**: Full interface loads instantly
- **Cached assets**: CSS, JS, images load from cache
- **Settings**: Preferences saved locally
- **Session history**: Previous conversations accessible

### ⚠️ What Needs Internet

- **AI responses**: Requires connection to local LLM server
- **Web research**: Researcher agent needs internet
- **External APIs**: Consultant agent (Claude/GPT)
- **Image generation**: Requires server connection

### 🎯 PWA Features

1. **Fast Loading**
   - First load: Downloads and caches all files
   - Subsequent loads: Instant from cache
   - Service worker handles updates automatically

2. **Offline Fallback**
   - Shows cached UI even offline
   - Displays helpful error messages for API calls
   - Retries when connection returns

3. **App-like Experience**
   - No browser UI (when installed)
   - Full screen mode
   - Home screen icon
   - Task switcher shows app name

4. **Auto-Updates**
   - Service worker checks for updates hourly
   - Prompts to reload when update available
   - Seamless update process

---

## Using the PWA

### First Time Setup

1. **Install the PWA** (see above)

2. **Start your backend**
   ```bash
   # On PC
   ./pkn_control.sh start-all

   # On Android (Termux)
   ./termux_start.sh
   ```

3. **Open the installed app**
   - Tap home screen icon
   - Or launch from app drawer

4. **Start chatting!**
   - Works exactly like web version
   - All agents, tools, features available

### Daily Usage

```bash
# 1. Start backend (one time)
./pkn_control.sh start-all

# 2. Launch PWA from home screen
#    (no need to open browser!)

# 3. Chat with AI agents

# 4. Close app anytime
#    (backend keeps running)
```

### Uninstalling

**Android:**
1. Long-press app icon
2. Select "App info" or drag to "Uninstall"
3. Tap "Uninstall"

**iOS:**
1. Long-press app icon
2. Tap "Remove App"
3. Tap "Delete App"

**Desktop:**
- Chrome: Settings → Apps → Divine Node → Uninstall
- Edge: Settings → Apps → Divine Node → Uninstall

---

## Troubleshooting

### "Install App" button doesn't appear

**Cause:** Already installed, or browser doesn't support PWA

**Fix:**
```bash
# Check if already installed
- Look for "Divine Node" on home screen

# Check browser support
- Use Chrome, Edge, or Safari (latest versions)
- PWA not supported in Firefox on mobile

# Manual install
- Chrome: Menu → "Install app"
- Safari: Share → "Add to Home Screen"
```

### App won't load offline

**Cause:** Service worker not registered or cache failed

**Fix:**
```javascript
// Open browser console (F12)
// Check service worker status
navigator.serviceWorker.getRegistrations().then(console.log)

// Should show: [ServiceWorkerRegistration]
```

**Clear and re-cache:**
```javascript
// In browser console
navigator.serviceWorker.getRegistrations().then(regs => {
    regs.forEach(reg => reg.unregister());
});

// Then reload page to re-register
location.reload();
```

### Updates not appearing

**Cause:** Service worker holding old cache

**Fix:**
```javascript
// Force update in browser console
navigator.serviceWorker.getRegistrations().then(regs => {
    regs.forEach(reg => reg.update());
});

// Or reload: Ctrl+Shift+R (hard refresh)
```

### AI not responding in PWA

**Cause:** Backend not running or wrong URL

**Check backend:**
```bash
./pkn_control.sh status

# Should show:
# ✓ llama.cpp running
# ✓ DivineNode running
```

**Check connection:**
```bash
# Test API
curl http://localhost:8010/health

# Should return: {"status":"healthy"}
```

---

## Advanced: Expanding to Native App

### Current State: PWA ✅

```
Browser-based → Installable → Offline support → Fast loading
```

### Future: Capacitor (Native APK) 🚀

When you're ready for **full native app** with Play Store distribution:

#### Step 1: Install Capacitor

```bash
cd /home/user/pkn-multi-agent

# Install Capacitor
npm install @capacitor/core @capacitor/cli
npm install @capacitor/android

# Initialize Capacitor
npx cap init "Divine Node" "com.divinenode.app"
```

#### Step 2: Configure Capacitor

```javascript
// capacitor.config.json
{
  "appId": "com.divinenode.app",
  "appName": "Divine Node",
  "webDir": ".", // Current directory
  "bundledWebRuntime": false,
  "server": {
    "url": "http://localhost:8010",
    "cleartext": true
  }
}
```

#### Step 3: Add Android Platform

```bash
# Add Android
npx cap add android

# Sync files
npx cap sync

# Open in Android Studio
npx cap open android
```

#### Step 4: Build APK

```bash
# In Android Studio:
# Build → Build Bundle(s) / APK(s) → Build APK(s)

# Or via command line:
cd android
./gradlew assembleDebug

# APK output:
# android/app/build/outputs/apk/debug/app-debug.apk
```

#### What You Get with Capacitor:

✅ **Native Android app** (.apk file)
✅ **Play Store ready** (after signing)
✅ **Native features**:
- File system access
- Camera integration
- Push notifications
- Background execution
- Better performance

✅ **Still uses same codebase** (no rewrite!)
✅ **PWA keeps working** (both can coexist)

---

## Development

### Testing PWA Locally

```bash
# 1. Start server
./pkn_control.sh start-all

# 2. Open in browser
google-chrome http://localhost:8010/pkn.html

# 3. Open DevTools (F12)
# 4. Go to Application tab
# 5. Check:
#    - Service Workers (should show registered)
#    - Manifest (should show Divine Node)
#    - Cache Storage (should have cached files)
```

### Updating PWA

1. **Make changes** to HTML/CSS/JS

2. **Update version** in service-worker.js:
   ```javascript
   const CACHE_NAME = 'divine-node-v1.0.1'; // Increment version
   ```

3. **Reload** the app
   - Service worker detects new version
   - Shows update prompt
   - User clicks "Reload to update"

### Adding to Service Worker Cache

To cache new files:

```javascript
// In service-worker.js
const STATIC_CACHE_URLS = [
  '/pkn.html',
  '/css/main.css',
  // Add your new file here:
  '/js/new-feature.js',
  '/img/new-icon.png'
];
```

---

## Performance

### PWA vs Web Page

| Metric | Web Page | PWA (Installed) |
|--------|----------|-----------------|
| First load | 2-3s | 2-3s |
| Subsequent loads | 1-2s | **<100ms** ⚡ |
| Offline | ❌ Broken | ✅ Shows UI |
| Install size | N/A | ~5MB cached |
| Updates | Manual refresh | Auto-detected |

### PWA vs Native App (Capacitor)

| Feature | PWA | Native App |
|---------|-----|------------|
| Distribution | URL only | Play Store |
| Installation | 1 click | Download APK |
| File access | Limited | Full system |
| Performance | Excellent | Slightly better |
| Development | Same codebase | Same codebase |
| Updates | Instant | Via store |

---

## Best Practices

### For Users

1. **Install the PWA** for best experience
2. **Keep backend running** when using the app
3. **Allow notifications** (future feature)
4. **Clear cache** if having issues (Ctrl+Shift+R)

### For Developers

1. **Version your cache** in service-worker.js
2. **Test offline mode** before releasing
3. **Keep manifest.json updated** with correct info
4. **Add new files** to service worker cache list
5. **Test on real devices** (Android + iOS)

---

## Files Reference

### PWA Core Files

```
manifest.json              # App metadata, icons, theme
service-worker.js          # Offline support, caching
pkn.html                   # Updated with PWA tags
css/main.css               # PWA button styles
img/icon-192.png           # App icon (192x192)
img/icon-512.png           # App icon (512x512)
```

### How It Works

```mermaid
1. User visits URL
   ↓
2. Browser loads pkn.html
   ↓
3. Registers service-worker.js
   ↓
4. Service worker caches files
   ↓
5. Shows "Install App" button
   ↓
6. User clicks install
   ↓
7. Browser creates app icon
   ↓
8. Future visits load from cache (fast!)
```

---

## Roadmap

### Current: PWA v1.0 ✅

- ✅ Installable on all platforms
- ✅ Offline UI support
- ✅ Auto-updates
- ✅ Fast caching
- ✅ Install prompt

### Coming Soon: PWA v1.1

- 🔔 Push notifications
- 🔄 Background sync
- 📊 Offline analytics
- 🎨 Better offline UI
- 💾 IndexedDB storage

### Future: Native App

- 📱 Capacitor integration
- 🏪 Play Store release
- 🎥 Camera access
- 📁 Full file system
- ⚡ Native performance

---

## Support

### Questions?

1. **Check this guide** first
2. **Check browser console** (F12) for errors
3. **Test on different browser** (Chrome vs Safari)
4. **Clear cache** and retry

### Common Questions

**Q: Can I use PWA and web version together?**
A: Yes! They're the same app, just different entry points.

**Q: Does PWA work on iPhone?**
A: Yes! Use Safari → Share → Add to Home Screen.

**Q: Will this work offline without backend?**
A: UI works offline, but AI features need backend running.

**Q: How big is the PWA?**
A: ~5MB cached (all HTML/CSS/JS/images).

**Q: Can I publish to app stores?**
A: Not directly. Use Capacitor to build native app first.

**Q: Is this better than native app?**
A: Similar experience! Native app gets Play Store distribution.

---

## Summary

🎉 **You now have a fully functional PWA!**

**What you get:**
- Install to home screen
- Fast loading from cache
- Offline UI support
- Auto-updates
- App-like experience

**Next steps:**
1. Install the PWA
2. Use it daily
3. When ready: Expand to Capacitor for native app

**100% expandable:** Your PWA is the foundation. Capacitor wraps it into a native APK without changing any code!

---

**Enjoy your Divine Node PWA!** 🚀📱

For Capacitor expansion guide, see: `CAPACITOR_GUIDE.md` (coming soon)
