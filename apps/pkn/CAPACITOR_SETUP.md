# Divine Node - Capacitor Android App Setup

**Transform your PWA into a real Android app with auto-start Termux integration**

---

## What You're Building

A **native Android APK** that:
- ✅ Installs like any Android app
- ✅ Auto-starts Termux backend when you open it
- ✅ Shows loading screen while backend initializes
- ✅ Connects automatically once ready
- ✅ Monitors backend health and reconnects if needed
- ✅ Falls back to manual instructions if auto-start fails

---

## Prerequisites

### On Your Development Machine (PC)

```bash
# 1. Node.js and npm (already installed ✓)
node --version  # v22.21.1
npm --version   # 10.9.4

# 2. Capacitor (installed via npm ✓)
npm install @capacitor/core @capacitor/cli @capacitor/android

# 3. Android Studio (required for building APK)
# Download from: https://developer.android.com/studio
# Install with Android SDK 33+
```

### On Your Android Device

```bash
# 1. Termux (from F-Droid, NOT Google Play)
# Install from: https://f-droid.org/packages/com.termux/

# 2. Divine Node backend in Termux
cd ~
# Transfer pkn directory to Termux
# See ANDROID_PACKAGE_READY.md for transfer instructions

# 3. Termux backend tested and working
cd ~/pkn
./termux_start.sh
# Should start successfully
```

---

## Setup Steps

### Step 1: Initialize Capacitor

```bash
cd /home/user/pkn-multi-agent

# Initialize Capacitor (if not done)
npx cap init

# When prompted:
# App name: Divine Node
# App ID: com.divinenode.app
# Web directory: . (current directory)
```

**Note:** Config already created at `capacitor.config.json` ✓

### Step 2: Add Android Platform

```bash
# Add Android platform
npx cap add android

# This creates android/ directory with native Android project
```

### Step 3: Sync Web Assets

```bash
# Copy web files to Android project
npx cap sync android

# This copies:
# - pkn.html
# - All CSS, JS files
# - Images and icons
# - manifest.json
# - service-worker.js
```

### Step 4: Create Native Termux Bridge

Create the native Android plugin to communicate with Termux:

```bash
# File: android/app/src/main/java/com/divinenode/app/TermuxBridge.java
```

```java
package com.divinenode.app;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "TermuxBridge")
public class TermuxBridge extends Plugin {

    private static final String TAG = "TermuxBridge";

    @PluginMethod
    public void startBackend(PluginCall call) {
        try {
            Context context = getContext();

            // Create intent to run Termux command
            Intent intent = new Intent();
            intent.setClassName("com.termux", "com.termux.app.RunCommandService");
            intent.setAction("com.termux.RUN_COMMAND");

            // Set command path
            String scriptPath = "/data/data/com.termux/files/home/pkn/termux_start.sh";
            intent.putExtra("com.termux.RUN_COMMAND_PATH", scriptPath);
            intent.putExtra("com.termux.RUN_COMMAND_WORKDIR", "/data/data/com.termux/files/home/pkn");
            intent.putExtra("com.termux.RUN_COMMAND_BACKGROUND", true);

            Log.d(TAG, "Starting Termux backend: " + scriptPath);

            // Start the service
            context.startService(intent);

            JSObject ret = new JSObject();
            ret.put("success", true);
            ret.put("message", "Termux backend start command sent");
            call.resolve(ret);

        } catch (Exception e) {
            Log.e(TAG, "Failed to start Termux backend", e);
            call.reject("Failed to start backend: " + e.getMessage());
        }
    }

    @PluginMethod
    public void checkTermuxInstalled(PluginCall call) {
        try {
            Context context = getContext();
            boolean installed = isPackageInstalled(context, "com.termux");

            JSObject ret = new JSObject();
            ret.put("installed", installed);
            call.resolve(ret);

        } catch (Exception e) {
            call.reject("Failed to check Termux installation: " + e.getMessage());
        }
    }

    private boolean isPackageInstalled(Context context, String packageName) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
```

### Step 5: Register Plugin in MainActivity

Edit: `android/app/src/main/java/com/divinenode/app/MainActivity.java`

```java
package com.divinenode.app;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Register custom plugins
        registerPlugin(TermuxBridge.class);
    }
}
```

### Step 6: Add Android Permissions

Edit: `android/app/src/main/AndroidManifest.xml`

Add these permissions inside `<manifest>` tag:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />

<!-- Termux integration -->
<queries>
    <package android:name="com.termux" />
</queries>
```

### Step 7: Configure Network Security

Create: `android/app/src/main/res/xml/network_security_config.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
    </domain-config>
</network-security-config>
```

Reference it in `AndroidManifest.xml`:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

---

## Building the APK

### Method 1: Android Studio (Recommended)

```bash
# Open Android project in Android Studio
npx cap open android

# In Android Studio:
# 1. Wait for Gradle sync to complete
# 2. Build → Build Bundle(s) / APK(s) → Build APK(s)
# 3. Wait for build to complete
# 4. Click "locate" to find APK

# APK location:
# android/app/build/outputs/apk/debug/app-debug.apk
```

### Method 2: Command Line

```bash
cd android

# Build debug APK
./gradlew assembleDebug

# Build release APK (requires signing)
./gradlew assembleRelease

# Output:
# app/build/outputs/apk/debug/app-debug.apk
```

---

## Installing the APK

### Transfer to Android Device

**Method 1: ADB**
```bash
# Connect phone via USB
adb install android/app/build/outputs/apk/debug/app-debug.apk
```

**Method 2: File Transfer**
```bash
# Copy APK to phone
adb push android/app/build/outputs/apk/debug/app-debug.apk /sdcard/Download/

# On phone:
# 1. Open Files app
# 2. Navigate to Downloads
# 3. Tap divine-node-debug.apk
# 4. Allow "Install from Unknown Sources" if prompted
# 5. Tap "Install"
```

**Method 3: Cloud Storage**
```bash
# Upload APK to Google Drive/Dropbox
# Download on phone
# Install from Downloads
```

---

## Usage

### First Time Setup

1. **Install Termux** (from F-Droid)

2. **Setup PKN in Termux**
   ```bash
   # In Termux
   cd ~
   # Copy pkn directory (see ANDROID_PACKAGE_READY.md)
   ```

3. **Test Termux backend manually**
   ```bash
   cd ~/pkn
   ./termux_start.sh
   # Should start without errors
   ```

4. **Install Divine Node APK**
   - Tap app-debug.apk
   - Install

5. **Grant permissions** if prompted

### Daily Usage

```
1. Tap Divine Node icon
   ↓
2. App opens → Shows "Starting backend..."
   ↓
3. Sends intent to Termux
   ↓
4. Termux starts termux_start.sh
   ↓
5. Backend initializes (10-30 seconds)
   ↓
6. App detects backend ready
   ↓
7. Loading screen fades → Chat interface appears
   ↓
8. Start chatting!
```

### If Auto-Start Fails

The app will show:
```
⚠️ Backend Not Responding

[Retry] [Manual Start]
```

Click **Manual Start** to see instructions:
```
1. Open Termux
2. Run: cd ~/pkn && ./termux_start.sh
3. Return to this app
4. Click "Retry Connection"
```

---

## How It Works

### Architecture

```
Divine Node APK
    ↓
Capacitor WebView (displays pkn.html)
    ↓
capacitor-backend.js (health checks)
    ↓
TermuxBridge.java (native plugin)
    ↓
Android Intent → Termux
    ↓
Termux executes: termux_start.sh
    ↓
Flask server starts on port 8010
    ↓
llama.cpp starts on port 8000
    ↓
capacitor-backend.js detects health endpoint
    ↓
UI appears, app is ready!
```

### Communication Flow

```javascript
// 1. App starts
capacitorBackend.init()

// 2. Check if backend running
fetch('http://localhost:8010/health')

// 3. If not running, start Termux
TermuxBridge.startBackend({
  action: 'com.termux.RUN_COMMAND',
  path: '/data/data/com.termux/files/home/pkn/termux_start.sh'
})

// 4. Poll health endpoint every 1s
setInterval(() => checkBackendHealth(), 1000)

// 5. Once healthy, hide loading, show UI
hideLoadingOverlay()
```

---

## Troubleshooting

### "Backend not responding" on every launch

**Cause:** Termux path incorrect or script not executable

**Fix:**
```bash
# In Termux, verify paths
ls -la ~/pkn/termux_start.sh
# Should show: -rwxr-xr-x (executable)

# Make executable if needed
chmod +x ~/pkn/termux_start.sh

# Test manually
./termux_start.sh
```

### App shows white screen

**Cause:** Web assets not synced

**Fix:**
```bash
npx cap sync android
npx cap open android
# Rebuild in Android Studio
```

### "Termux not installed" error

**Cause:** Termux not detected by app

**Fix:**
```bash
# Install Termux from F-Droid (NOT Google Play!)
# Google Play version is outdated and won't work
```

### Backend starts but app doesn't connect

**Cause:** Wrong port or localhost not accessible

**Fix:**
```bash
# In Termux, check what's running
./pkn_control.sh status

# Should show:
# ✓ llama.cpp running (port 8000)
# ✓ DivineNode running (port 8010)

# Test from Termux
curl http://localhost:8010/health
# Should return: {"status":"healthy"}
```

### App crashes on launch

**Cause:** Missing permissions or plugin not registered

**Check:**
```bash
# 1. Verify TermuxBridge.java exists in:
# android/app/src/main/java/com/divinenode/app/

# 2. Verify MainActivity.java registers it:
# registerPlugin(TermuxBridge.class);

# 3. Rebuild app
cd android
./gradlew clean
./gradlew assembleDebug
```

---

## Advanced Configuration

### Custom Backend Port

If using different port (not 8010):

```javascript
// In js/capacitor-backend.js
this.backendUrl = 'http://localhost:YOUR_PORT';
```

```json
// In capacitor.config.json
"server": {
  "url": "http://localhost:YOUR_PORT"
}
```

### Faster Startup

To reduce wait time:

```javascript
// In js/capacitor-backend.js
this.maxRetries = 15; // Reduce from 30 (15 seconds max wait)
```

### Custom Loading Screen

Edit `js/capacitor-backend.js` → `showLoadingOverlay()` function to customize appearance.

---

## Next Steps

### For Release Version:

1. **Generate signing key**
   ```bash
   keytool -genkey -v -keystore divine-node.keystore \
     -alias divine-node -keyalg RSA -keysize 2048 -validity 10000
   ```

2. **Configure signing**
   Edit `android/app/build.gradle`:
   ```gradle
   android {
       signingConfigs {
           release {
               storeFile file("divine-node.keystore")
               storePassword "your-password"
               keyAlias "divine-node"
               keyPassword "your-password"
           }
       }
   }
   ```

3. **Build release APK**
   ```bash
   cd android
   ./gradlew assembleRelease
   ```

4. **Distribute**
   - Upload to Play Store
   - Or share APK directly

---

## Files Reference

### Core Capacitor Files

```
capacitor.config.json                 # Capacitor configuration
android/                              # Native Android project
├── app/
│   ├── src/main/
│   │   ├── java/com/divinenode/app/
│   │   │   ├── MainActivity.java     # Main activity
│   │   │   └── TermuxBridge.java     # Termux integration plugin
│   │   ├── res/
│   │   │   └── xml/
│   │   │       └── network_security_config.xml
│   │   └── AndroidManifest.xml       # Permissions and config
│   └── build.gradle                  # Build configuration
js/capacitor-backend.js               # Backend auto-start logic
```

---

## Summary

✅ **What you built:**
- Real Android APK
- Auto-starts Termux backend
- Seamless user experience
- Health monitoring
- Graceful error handling

✅ **What users see:**
```
Tap app icon → Loading screen → Chat interface
(No manual Termux commands!)
```

✅ **Future improvements:**
- Background service (keep backend running)
- Wake lock (prevent sleep)
- Notification (backend status)
- Auto-restart on crash

**Your Divine Node is now a real Android app!** 🎉📱

For Play Store publishing guide, see: `PLAY_STORE_GUIDE.md` (create when ready)
