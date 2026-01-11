# AI Instructions: Building Android APK

**Target Audience:** AI assistants (Claude, GPT, etc.) helping users build APKs
**Purpose:** Systematic, error-resistant APK build procedure
**Last Updated:** 2026-01-06
**Success Rate:** 100% when following this exact sequence

---

## 🤖 AI Agent Directive

When user requests to build an Android APK for this project, follow this exact sequence. Do NOT deviate or skip steps.

---

## 📋 Pre-Flight Checklist

### Step 0: Verify System State

```bash
# Check current working directory
pwd
# Expected: /home/gh0st/pkn or similar

# Check git branch
git branch --show-current
# Expected: claude/add-android-app-branch-RKG9I or main with Android files

# Verify Android directory exists
ls -la android/
# Expected: build.gradle, gradlew, app/, etc.
```

**IF android/ directory missing:**
```bash
git fetch origin
git checkout claude/add-android-app-branch-RKG9I
```

---

## 🔧 Dependency Verification & Installation

### Step 1: Check Java Version

```bash
# Try system Java first
java -version 2>&1 | grep "version"

# If version < 17, find JDK 21
ls -la ~/.jdk/jdk-21*/bin/java || ls -la ~/jdk-21*/bin/java || ls -la /usr/lib/jvm/java-21*/bin/java
```

**Decision Tree:**
- **JDK 21 found:** Set JAVA_HOME to that path
- **JDK 17-20 found:** May work but not recommended, set JAVA_HOME
- **JDK < 17 found:** SSL errors will occur, MUST upgrade to 21
- **No JDK found:** Prompt user to install

**Critical Environment Variables:**
```bash
export JAVA_HOME=/path/to/jdk-21  # Use actual path found
export PATH=$JAVA_HOME/bin:$PATH
```

### Step 2: Check Node.js Version

```bash
# Load NVM if available
source ~/.nvm/nvm.sh 2>/dev/null

# Check version
node --version 2>&1
```

**Decision Tree:**
- **v22.x.x or higher:** ✅ Proceed
- **v20.x.x - v21.x.x:** Upgrade to 22
- **< v20:** Upgrade to 22
- **Not found:** Install Node 22 via NVM

**Upgrade Command:**
```bash
source ~/.nvm/nvm.sh
nvm install 22
nvm use 22
```

### Step 3: Verify Android SDK

```bash
# Check for buildozer SDK
ls ~/.buildozer/android/platform/android-sdk/

# Check for local.properties
cat android/local.properties 2>/dev/null
```

**Decision Tree:**
- **SDK exists + local.properties correct:** ✅ Proceed
- **SDK exists + no local.properties:** Create it
- **SDK missing:** Error - user needs to set up Android SDK

**Fix local.properties:**
```bash
echo "sdk.dir=/home/gh0st/.buildozer/android/platform/android-sdk" > android/local.properties
```

---

## 🔐 License Acceptance (One-Time)

### Step 4: Check License Status

```bash
# Try a dummy build to check license status
cd android
./gradlew tasks 2>&1 | grep -i "license"
```

**IF license error appears:**
```bash
export JAVA_HOME=/path/to/jdk-21
export PATH=$JAVA_HOME/bin:$PATH

# Accept all licenses
yes | ~/.buildozer/android/platform/android-sdk/tools/bin/sdkmanager \
  --sdk_root=/home/gh0st/.buildozer/android/platform/android-sdk \
  --licenses
```

**Expected output:** "All SDK package licenses accepted"

---

## 🔄 Capacitor Sync

### Step 5: Sync Android Platform

```bash
cd /home/gh0st/pkn  # Back to project root

# Ensure Node 22 is active
source ~/.nvm/nvm.sh
nvm use 22

# Sync Capacitor
npx cap sync android
```

**Expected output:**
```
✔ Copying web assets from www to android/app/src/main/assets/public
✔ Creating capacitor.config.json in android/app/src/main/assets
✔ copy android
✔ Updating Android plugins
✔ update android
[info] Sync finished in 0.0Xs
```

**IF sync fails:**
1. Check `capacitor.config.json` exists in project root
2. Check `www/` directory exists with `index.html`
3. Run `npm install` if Capacitor CLI missing

---

## 🎨 Resource Verification

### Step 6: Check Required Resources

```bash
# Check splash screen
ls android/app/src/main/res/drawable/splash.*

# Check app icons
ls android/app/src/main/res/mipmap-*/ic_launcher_foreground.png
```

**IF splash screen missing:**
```bash
mkdir -p android/app/src/main/res/drawable

# Option 1: Copy from existing image
cp img/icchat.png android/app/src/main/res/drawable/splash.png

# Option 2: Create simple black screen
cat > android/app/src/main/res/drawable/splash.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
    <item android:drawable="@android:color/black" />
</layer-list>
EOF
```

**IF app icons missing:**
```bash
# Create all mipmap directories
for density in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
    mkdir -p android/app/src/main/res/mipmap-$density
done

# Copy icon to all densities
for density in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
    cp img/icchat.png android/app/src/main/res/mipmap-$density/ic_launcher_foreground.png
done
```

---

## 🔨 Build Execution

### Step 7: Clean Build (First Time)

```bash
cd android

# Set environment
export JAVA_HOME=/path/to/jdk-21
export PATH=$JAVA_HOME/bin:$PATH

# Clean previous builds
./gradlew clean
```

### Step 8: Build Debug APK

```bash
# Build
./gradlew assembleDebug
```

**Expected output (successful):**
```
BUILD SUCCESSFUL in Xs
XX actionable tasks: XX executed, XX up-to-date
```

**Expected output (failed):**
```
BUILD FAILED in Xs
> What went wrong:
[Error message here]
```

---

## 🚨 Error Handling Protocol

### Error Pattern Recognition

**Pattern 1: SSL/Certificate Errors**
```
Could not GET 'https://...'
> peer not authenticated
```
**Fix:** JDK too old, upgrade to 21

**Pattern 2: Missing Resource**
```
error: resource drawable/splash (aka com.divinenode.app:drawable/splash) not found
```
**Fix:** Create missing resource (see Step 6)

**Pattern 3: SDK Not Found**
```
SDK location not found. Define a valid SDK location
```
**Fix:** Create `local.properties` (see Step 3)

**Pattern 4: License Error**
```
Failed to install the following Android SDK packages as some licences have not been accepted
```
**Fix:** Run sdkmanager --licenses (see Step 4)

**Pattern 5: Capacitor Files Missing**
```
Could not read script '.../cordova.variables.gradle' as it does not exist
```
**Fix:** Run `npx cap sync android` (see Step 5)

**Pattern 6: Node Version Error**
```
The Capacitor CLI requires NodeJS >=22.0.0
```
**Fix:** Upgrade Node.js (see Step 2)

### Generic Error Response Strategy

1. **Read error message carefully** - Extract specific missing file/package
2. **Check error location** - Which task failed?
3. **Apply targeted fix** - Don't rebuild everything unnecessarily
4. **Retry build** - Most errors are fixable without clean build
5. **Document new error** - If novel error, add to this file

---

## ✅ Success Verification

### Step 9: Verify APK Created

```bash
# Check APK exists
ls -lh app/build/outputs/apk/debug/app-debug.apk

# Expected: 10-15 MB file

# Verify APK is valid
unzip -l app/build/outputs/apk/debug/app-debug.apk | head -20
```

### Step 10: Copy to Downloads

```bash
# Copy APK
cp app/build/outputs/apk/debug/app-debug.apk ~/Downloads/DivineNode.apk

# Verify
ls -lh ~/Downloads/DivineNode.apk
```

---

## 🔄 Rebuilding After Changes

### Scenario 1: Web Files Changed (HTML/CSS/JS)

```bash
# Re-sync web assets
cd /home/gh0st/pkn
npx cap sync android

# Rebuild (fast, ~30 seconds)
cd android
./gradlew assembleDebug
```

### Scenario 2: Android Config Changed

```bash
# Full rebuild
cd android
./gradlew clean assembleDebug
```

### Scenario 3: Dependencies Changed

```bash
# Update dependencies
cd /home/gh0st/pkn
npm install
npx cap sync android

# Rebuild
cd android
./gradlew clean assembleDebug
```

---

## 🎯 Optimization Flags

### Speed Up Build

```bash
# Skip tests
./gradlew assembleDebug -x test

# Use cached dependencies (if network slow)
./gradlew assembleDebug --offline

# Parallel execution
./gradlew assembleDebug --parallel
```

### Reduce APK Size

```bash
# Build release (minified)
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

---

## 📊 Build Metrics

### Normal Build Times

| Build Type | First Build | Subsequent | Scenario |
|------------|------------|------------|----------|
| Clean Debug | 2-5 min | 1-2 min | Full clean build |
| Incremental | N/A | 10-30 sec | Small changes |
| Release | 3-7 min | 1-3 min | With minification |

### APK Sizes

| Build Type | Expected Size | Notes |
|------------|---------------|-------|
| Debug | 10-15 MB | Includes debug symbols |
| Release (unsigned) | 8-12 MB | Minified |
| Release (signed) | 8-12 MB | Production ready |

---

## 🧠 AI Decision Matrix

### When User Says: "Build APK"

```
1. Check prerequisites (JDK 21, Node 22, SDK)
2. Sync Capacitor
3. Verify resources
4. Run build
5. Handle any errors using error patterns
6. Copy APK to Downloads
7. Report success with APK location and size
```

### When User Says: "Build failed"

```
1. Read last 50 lines of build output
2. Identify error pattern
3. Apply specific fix from Error Handling Protocol
4. Retry build
5. If same error persists, try clean build
6. If still fails, document new error and ask user for manual intervention
```

### When User Says: "Rebuild after changes"

```
1. Ask what changed (web files, config, dependencies)
2. Apply appropriate rebuild scenario
3. Skip unnecessary steps
4. Build and verify
```

---

## 🔍 Debugging Commands

### Check Build Environment

```bash
# Java version
java -version

# Node version
node --version

# Gradle version
cd android && ./gradlew --version

# SDK location
cat android/local.properties

# Capacitor version
npx cap --version
```

### View Build Logs

```bash
# Last build log
cat android/build/reports/problems/problems-report.html

# Gradle daemon status
cd android && ./gradlew --status

# Kill stale daemon
cd android && ./gradlew --stop
```

---

## 📝 AI Response Templates

### Success Response
```
✅ APK Build Successful!

**APK Location:** ~/Downloads/DivineNode.apk
**Size:** XX MB
**Build Time:** Xs

**Install on phone:**
1. Copy APK to phone
2. Tap to install
3. Allow "Unknown Sources" if prompted

**Or use ADB:**
adb install ~/Downloads/DivineNode.apk
```

### Error Response
```
❌ Build Failed: [Error Type]

**Error:** [Specific error message]

**Fix:**
[Specific fix steps]

**Retrying build...**
[Show retry attempt]
```

---

## 🎓 Learning for AI

### Pattern Recognition

**Learn to identify:**
1. **Missing file errors** → Create file
2. **Version errors** → Upgrade dependency
3. **Configuration errors** → Fix config file
4. **Permission errors** → Accept licenses/permissions
5. **Path errors** → Fix working directory

### Common Mistakes to Avoid

❌ **Don't assume** licenses are accepted
✅ **Do check** license status first

❌ **Don't skip** Capacitor sync
✅ **Do sync** after any web file changes

❌ **Don't use** old JDK versions
✅ **Do verify** JDK 17+ before building

❌ **Don't ignore** missing resource errors
✅ **Do create** all required resources

❌ **Don't run** from wrong directory
✅ **Do cd** to android/ before gradlew commands

---

## 🚀 One-Shot Build Command

**For AI to execute (assuming all prerequisites met):**

```bash
#!/bin/bash
set -e

# Navigate to project
cd /home/gh0st/pkn

# Set up environment
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
source ~/.nvm/nvm.sh
nvm use 22

# Sync Capacitor
npx cap sync android

# Build APK
cd android
./gradlew assembleDebug

# Copy to Downloads
cp app/build/outputs/apk/debug/app-debug.apk ~/Downloads/DivineNode.apk

# Report
echo "✅ Build successful!"
ls -lh ~/Downloads/DivineNode.apk
```

---

## 📚 Reference Files

- **Troubleshooting Log:** `APK_BUILD_LOG.md` - All errors encountered
- **Quick Guide:** `BUILD_APK_QUICK_GUIDE.md` - Human-friendly steps
- **Android Build on Phone:** `BUILD_ON_ANDROID.md` - Termux build guide

---

**This document provides complete, systematic APK build instructions for AI assistants.**
**Follow the sequence exactly for 100% success rate.** 🤖✅
