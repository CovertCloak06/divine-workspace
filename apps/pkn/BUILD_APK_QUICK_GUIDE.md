# Quick Guide: Build Divine Node APK

**⏱️ Time Required:** 5-10 minutes (after setup)
**📍 Location:** This guide lives in `/home/gh0st/pkn/BUILD_APK_QUICK_GUIDE.md`

---

## 🎯 What You'll Get

- **APK File:** `DivineNode.apk` (12 MB)
- **Installable on:** Any Android device
- **Contains:** Your full PKN multi-agent AI system

---

## ✅ Prerequisites (One-Time Setup)

### 1. Install JDK 21
```bash
# If not already installed
sudo apt-get install openjdk-21-jdk
```

**Already have JDK 21?** Check with:
```bash
ls -la ~/.jdk/jdk-21.0.8
# or
java -version  # Should show version 21
```

### 2. Install Node.js 22
```bash
source ~/.nvm/nvm.sh
nvm install 22
nvm use 22
node --version  # Should show v22.x.x
```

### 3. Accept Android SDK Licenses (First Time Only)
```bash
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
yes | ~/.buildozer/android/platform/android-sdk/tools/bin/sdkmanager \
  --sdk_root=/home/gh0st/.buildozer/android/platform/android-sdk \
  --licenses
```

You only need to do this ONCE. Takes ~30 seconds.

---

## 🚀 Build the APK (Every Time)

### Step 1: Navigate to Project
```bash
cd /home/gh0st/pkn
```

### Step 2: Checkout Android Branch
```bash
git checkout claude/add-android-app-branch-RKG9I
git pull origin claude/add-android-app-branch-RKG9I
```

### Step 3: Sync Capacitor (If Files Changed)
```bash
source ~/.nvm/nvm.sh
nvm use 22
npx cap sync android
```

### Step 4: Build APK
```bash
cd android
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
./gradlew assembleDebug
```

**Build Time:** 1-2 minutes (after first build)

### Step 5: Get Your APK
```bash
cp app/build/outputs/apk/debug/app-debug.apk ~/Downloads/DivineNode.apk
ls -lh ~/Downloads/DivineNode.apk
```

**Done!** Your APK is in `~/Downloads/DivineNode.apk`

---

## 📱 Install on Phone

### Method 1: USB Cable
1. Connect phone via USB
2. Copy `~/Downloads/DivineNode.apk` to phone's Download folder
3. On phone: Open Files app → Downloads → Tap `DivineNode.apk`
4. Allow "Install from Unknown Sources" if prompted
5. Tap "Install"

### Method 2: ADB (Fastest)
```bash
adb install ~/Downloads/DivineNode.apk
```

### Method 3: Cloud Transfer
1. Upload to Google Drive/Dropbox
2. Download on phone
3. Install

---

## 🔧 Common Issues & Fixes

### "BUILD FAILED: SDK location not found"
**Fix:**
```bash
echo "sdk.dir=/home/gh0st/.buildozer/android/platform/android-sdk" > /home/gh0st/pkn/android/local.properties
```

### "BUILD FAILED: Could not GET maven repo"
**Fix:** Make sure you're using JDK 21:
```bash
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
```

### "BUILD FAILED: Licenses not accepted"
**Fix:** Run the license acceptance command from Prerequisites #3

### "Capacitor CLI requires NodeJS >=22.0.0"
**Fix:**
```bash
source ~/.nvm/nvm.sh
nvm use 22
```

### Build is Slow
**Fix:** Enable caching (one-time):
```bash
cat >> /home/gh0st/pkn/android/gradle.properties << EOF
org.gradle.daemon=true
org.gradle.caching=true
org.gradle.parallel=true
EOF
```

---

## 🎨 Customize Your APK

### Change App Name
Edit: `android/app/src/main/res/values/strings.xml`
```xml
<string name="app_name">Your App Name</string>
```

### Change App Icon
Replace icons in:
- `android/app/src/main/res/mipmap-mdpi/ic_launcher_foreground.png`
- `android/app/src/main/res/mipmap-hdpi/ic_launcher_foreground.png`
- `android/app/src/main/res/mipmap-xhdpi/ic_launcher_foreground.png`
- `android/app/src/main/res/mipmap-xxhdpi/ic_launcher_foreground.png`
- `android/app/src/main/res/mipmap-xxxhdpi/ic_launcher_foreground.png`

### Change Splash Screen
Replace: `android/app/src/main/res/drawable/splash.png`

---

## 🚀 Build Release APK (For Play Store)

### Step 1: Generate Signing Key
```bash
cd /home/gh0st/pkn/android
keytool -genkey -v -keystore divine-node.keystore \
  -alias divine-node \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000
```

Save the password somewhere safe!

### Step 2: Build Release
```bash
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
./gradlew assembleRelease
```

**Output:** `app/build/outputs/apk/release/app-release.apk`

---

## 📚 More Documentation

- **Detailed Troubleshooting:** `APK_BUILD_LOG.md`
- **AI Instructions:** `AI_APK_BUILD_INSTRUCTIONS.md`
- **Android Setup:** `BUILD_ON_ANDROID.md` (for building on phone)
- **Capacitor Docs:** `CAPACITOR_SETUP.md`

---

## 💡 Pro Tips

### Faster Rebuilds
```bash
# Skip tests
./gradlew assembleDebug -x test

# Offline mode (if dependencies cached)
./gradlew assembleDebug --offline

# Clean build (if things break)
./gradlew clean assembleDebug
```

### Check APK Size
```bash
ls -lh app/build/outputs/apk/debug/app-debug.apk
```

### Test APK Before Installing
```bash
# Verify signature
jarsigner -verify -verbose app/build/outputs/apk/debug/app-debug.apk

# View APK contents
unzip -l app/build/outputs/apk/debug/app-debug.apk
```

---

## 🎯 One-Command Build Script

Save this as `build_apk.sh` in `/home/gh0st/pkn/`:

```bash
#!/bin/bash
set -e

echo "🚀 Building Divine Node APK..."

# Setup environment
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
source ~/.nvm/nvm.sh
nvm use 22

# Sync and build
npx cap sync android
cd android
./gradlew assembleDebug

# Copy to Downloads
cp app/build/outputs/apk/debug/app-debug.apk ~/Downloads/DivineNode.apk

echo "✅ Done! APK at ~/Downloads/DivineNode.apk"
ls -lh ~/Downloads/DivineNode.apk
```

Make executable:
```bash
chmod +x build_apk.sh
```

Run:
```bash
./build_apk.sh
```

---

## 📞 Need Help?

1. **Check:** `APK_BUILD_LOG.md` - All errors and solutions documented
2. **GitHub:** Check issues at repository
3. **Logs:** Check `android/build/reports/` for detailed error reports

---

**That's it! You now know how to build your Android APK.** 📱🚀
