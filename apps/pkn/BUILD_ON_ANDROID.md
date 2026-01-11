# Building Divine Node APK on Android (Termux)

**Build your Android app directly on your phone - no PC required!**

---

## Overview

You can compile the Divine Node APK directly in Termux on your Android device. This guide provides step-by-step instructions for building the app entirely on your phone.

---

## Prerequisites

### 1. Termux Installed
- **Download from F-Droid** (NOT Google Play!)
- URL: https://f-droid.org/packages/com.termux/
- Version: Latest available

### 2. Storage Access
```bash
# In Termux
termux-setup-storage
# Grant permission when prompted
```

### 3. Available Space
- **Minimum:** 2GB free storage
- **Recommended:** 3GB+ free storage
- Check with: `df -h`

---

## Installation Steps

### Step 1: Update Termux Packages

```bash
# Update package lists
pkg update

# Upgrade installed packages
pkg upgrade -y
```

### Step 2: Install Build Dependencies

```bash
# Install Java (OpenJDK 17)
pkg install openjdk-17 -y

# Install Gradle build tool
pkg install gradle -y

# Install Git (if not already installed)
pkg install git -y

# Verify installations
java -version     # Should show: openjdk version "17.x.x"
gradle -v         # Should show: Gradle 8.x or higher
```

**Expected Download Size:** ~300-400MB
**Installation Time:** 5-10 minutes

### Step 3: Get the Project Code

#### Option A: Clone from Git

```bash
cd ~
git clone https://github.com/YOUR_USERNAME/pkn-multi-agent.git
cd pkn-multi-agent
git checkout claude/add-android-app-branch-RKG9I
```

#### Option B: Transfer from PC

```bash
# On PC: Create tarball
tar -czf pkn-android.tar.gz pkn-multi-agent/

# Transfer to phone (via USB/cloud/etc)
# In phone's Download folder

# In Termux: Extract
cd ~
cp /sdcard/Download/pkn-android.tar.gz .
tar -xzf pkn-android.tar.gz
cd pkn-multi-agent
```

### Step 4: Set JAVA_HOME

```bash
# Add to ~/.bashrc
echo 'export JAVA_HOME=/data/data/com.termux/files/usr' >> ~/.bashrc
echo 'export PATH=$JAVA_HOME/bin:$PATH' >> ~/.bashrc

# Reload environment
source ~/.bashrc

# Verify
echo $JAVA_HOME
# Should output: /data/data/com.termux/files/usr
```

---

## Building the APK

### Step 5: Navigate to Android Project

```bash
cd ~/pkn-multi-agent/android
```

### Step 6: Make Gradle Wrapper Executable

```bash
chmod +x gradlew
```

### Step 7: Build Debug APK

```bash
# Start the build
./gradlew assembleDebug

# This will:
# 1. Download Gradle wrapper (~100MB) - first time only
# 2. Download Android build dependencies (~200MB) - first time only
# 3. Compile Java code
# 4. Package APK
```

**First Build Time:** 15-25 minutes
**Subsequent Builds:** 2-5 minutes

**Expected Output:**
```
BUILD SUCCESSFUL in 18m 32s
45 actionable tasks: 45 executed
```

### Step 8: Locate the APK

```bash
# APK location:
ls -lh app/build/outputs/apk/debug/

# Should show:
# app-debug.apk (~15-20MB)
```

---

## Installing the APK

### Method 1: Direct Install (Termux)

```bash
# Install using package manager
pm install app/build/outputs/apk/debug/app-debug.apk

# Or using activity manager
am start -a android.intent.action.VIEW \
  -t application/vnd.android.package-archive \
  -d file:///data/data/com.termux/files/home/pkn-multi-agent/android/app/build/outputs/apk/debug/app-debug.apk
```

### Method 2: File Manager Install

```bash
# Copy APK to accessible location
cp app/build/outputs/apk/debug/app-debug.apk /sdcard/Download/divine-node.apk

# Then:
# 1. Open Files app on Android
# 2. Navigate to Downloads
# 3. Tap divine-node.apk
# 4. Allow "Install from Unknown Sources" if prompted
# 5. Tap "Install"
```

### Method 3: ADB Install (from another device)

```bash
# If you have ADB on another phone/tablet
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## Troubleshooting

### Build Fails: "JAVA_HOME not set"

**Solution:**
```bash
export JAVA_HOME=/data/data/com.termux/files/usr
./gradlew assembleDebug
```

### Build Fails: "Could not resolve dependencies"

**Solution:**
```bash
# Clear Gradle cache
rm -rf ~/.gradle/caches/

# Retry build
./gradlew assembleDebug --refresh-dependencies
```

### Build Fails: "Out of memory"

**Solution:**
```bash
# Reduce Gradle memory usage
export GRADLE_OPTS="-Xmx1024m -XX:MaxMetaspaceSize=512m"

# Edit gradle.properties
echo "org.gradle.jvmargs=-Xmx1024m -XX:MaxMetaspaceSize=512m" >> gradle.properties

# Retry build
./gradlew assembleDebug
```

### Build is Very Slow

**Tips:**
1. **Close other apps** to free RAM
2. **Plug in charger** - build uses lots of CPU
3. **Enable wake lock** - prevents sleep
   ```bash
   termux-wake-lock
   ```
4. **Use parallel builds**
   ```bash
   ./gradlew assembleDebug --parallel
   ```

### "Permission denied" Error

**Solution:**
```bash
# Make sure gradlew is executable
chmod +x gradlew

# Check file ownership
ls -la gradlew
```

---

## Build Optimization

### Speed Up Subsequent Builds

```bash
# Enable Gradle daemon
echo "org.gradle.daemon=true" >> gradle.properties

# Enable parallel builds
echo "org.gradle.parallel=true" >> gradle.properties

# Enable build cache
echo "org.gradle.caching=true" >> gradle.properties
```

### Reduce Build Time

```bash
# Build only what changed
./gradlew assembleDebug --build-cache

# Skip tests (faster)
./gradlew assembleDebug -x test

# Use offline mode (if dependencies cached)
./gradlew assembleDebug --offline
```

---

## Rebuilding After Changes

### If You Changed Web Files (HTML/CSS/JS)

```bash
# 1. Update www directory
cd ~/pkn-multi-agent
rm -rf www/*
cp pkn.html www/index.html
cp -r css js img manifest.json service-worker.js www/

# 2. Sync to Android
npx cap sync android

# 3. Rebuild APK
cd android
./gradlew assembleDebug
```

### If You Changed Native Code (Java)

```bash
# Just rebuild
cd ~/pkn-multi-agent/android
./gradlew assembleDebug
```

### Clean Build (Start Fresh)

```bash
# Clean previous build
./gradlew clean

# Build fresh
./gradlew assembleDebug
```

---

## Building Release APK

### Generate Signing Key

```bash
# Create keystore
cd ~/pkn-multi-agent/android

keytool -genkey -v -keystore divine-node.keystore \
  -alias divine-node \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000

# Answer prompts:
# - Enter keystore password: (remember this!)
# - Re-enter password
# - What is your name? Divine Node
# - What is the name of your organization? (your choice)
# - etc. (answer as you prefer)
```

### Configure Signing

Edit `app/build.gradle`:

```gradle
android {
    ...
    signingConfigs {
        release {
            storeFile file("divine-node.keystore")
            storePassword "YOUR_PASSWORD"
            keyAlias "divine-node"
            keyPassword "YOUR_PASSWORD"
        }
    }

    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

### Build Release APK

```bash
./gradlew assembleRelease

# Output:
# app/build/outputs/apk/release/app-release.apk
```

---

## Performance Tips

### For Low-End Devices

```bash
# Reduce Gradle parallelism
echo "org.gradle.workers.max=1" >> gradle.properties

# Reduce memory
export GRADLE_OPTS="-Xmx768m"

# Build with fewer resources
./gradlew assembleDebug --max-workers=1
```

### For Faster Builds on Good Devices

```bash
# Increase parallel workers
echo "org.gradle.workers.max=4" >> gradle.properties

# Increase memory (if you have 6GB+ RAM)
export GRADLE_OPTS="-Xmx2048m"

# Use all cores
./gradlew assembleDebug --parallel --max-workers=4
```

---

## Verifying the APK

### Check APK Size

```bash
ls -lh app/build/outputs/apk/debug/app-debug.apk

# Should be: 15-25MB
```

### Inspect APK Contents

```bash
# Install aapt2 (Android Asset Packaging Tool)
pkg install aapt2 -y

# View APK info
aapt2 dump badging app/build/outputs/apk/debug/app-debug.apk

# Should show:
# package: name='com.divinenode.app' versionCode='1' versionName='1.0'
# application-label:'Divine Node'
# etc.
```

### Test APK Before Installing

```bash
# Verify APK signature
jarsigner -verify -verbose -certs app/build/outputs/apk/debug/app-debug.apk
```

---

## Automated Build Script

Create `build_apk.sh` in Termux:

```bash
#!/data/data/com.termux/files/usr/bin/bash

# Divine Node APK Build Script
set -e

echo "🚀 Building Divine Node APK..."

# Set environment
export JAVA_HOME=/data/data/com.termux/files/usr

# Navigate to project
cd ~/pkn-multi-agent/android

# Acquire wake lock
termux-wake-lock

# Clean previous build
echo "🧹 Cleaning previous build..."
./gradlew clean

# Build APK
echo "🔨 Building APK..."
./gradlew assembleDebug

# Check if successful
if [ -f app/build/outputs/apk/debug/app-debug.apk ]; then
    echo "✅ Build successful!"
    echo ""
    echo "📦 APK Location:"
    ls -lh app/build/outputs/apk/debug/app-debug.apk

    # Copy to accessible location
    echo ""
    echo "📋 Copying to Download folder..."
    cp app/build/outputs/apk/debug/app-debug.apk /sdcard/Download/divine-node.apk
    echo "✅ APK available in Downloads folder"
else
    echo "❌ Build failed!"
    exit 1
fi

# Release wake lock
termux-wake-unlock

echo ""
echo "🎉 Done! Install from Downloads folder."
```

Make it executable:
```bash
chmod +x build_apk.sh
```

Run it:
```bash
./build_apk.sh
```

---

## Quick Reference

### Essential Commands

```bash
# First time setup
pkg install openjdk-17 gradle -y
export JAVA_HOME=/data/data/com.termux/files/usr

# Build APK
cd ~/pkn-multi-agent/android
./gradlew assembleDebug

# APK location
ls -lh app/build/outputs/apk/debug/app-debug.apk

# Install APK
pm install app/build/outputs/apk/debug/app-debug.apk
```

### Build Times Reference

| Build Type | First Time | Subsequent | Device |
|------------|------------|------------|---------|
| Debug | 15-25 min | 2-5 min | Mid-range (6GB RAM) |
| Debug | 25-40 min | 5-10 min | Low-end (4GB RAM) |
| Release | 20-30 min | 3-7 min | Mid-range (6GB RAM) |

### Storage Usage

| Component | Size |
|-----------|------|
| OpenJDK 17 | ~150MB |
| Gradle | ~200MB |
| Android SDK (auto-downloaded) | ~300MB |
| Build cache | ~100-200MB |
| Final APK | ~15-20MB |
| **Total** | ~800MB-1GB |

---

## Summary

✅ **You can build APKs entirely on Android!**

**Steps:**
1. Install Termux from F-Droid
2. Install Java + Gradle
3. Build with `./gradlew assembleDebug`
4. Install APK from Downloads

**Benefits:**
- No PC required
- Build anywhere
- Full control over app

**Considerations:**
- Takes longer than PC
- Uses battery
- Requires storage space

**You now have a complete Android development environment in your pocket!** 📱🚀

---

## Additional Resources

- **Termux Wiki**: https://wiki.termux.com
- **Gradle Docs**: https://docs.gradle.org
- **Capacitor Docs**: https://capacitorjs.com
- **Android Developer Guide**: https://developer.android.com

For questions about the Divine Node app specifically, see:
- `CAPACITOR_SETUP.md` - Full app documentation
- `PWA_GUIDE.md` - PWA installation guide
- `README.md` - Project overview
