# APK Build Troubleshooting Log
**Date:** 2026-01-06
**Build Type:** Android Debug APK
**Final Result:** ✅ SUCCESS - 12MB APK created
**Build Time:** ~45 minutes (with troubleshooting)

---

## 🎯 Mission: Build Divine Node Android APK

**Starting Point:** Capacitor Android project configured by Claude on phone
**Ending Point:** Working 12MB APK ready to install
**Location:** `/home/gh0st/pkn/android/app/build/outputs/apk/debug/app-debug.apk`

---

## 🚧 Walls Hit & Solutions

### Wall #1: SSL Certificate Error (JDK 11 Too Old)
**Error:**
```
Could not GET 'https://repo.maven.apache.org/maven2/...'
> peer not authenticated
> No PSK available. Unable to resume.
```

**Root Cause:** JDK 11.0.2 (from 2019) has outdated SSL certificates that can't verify modern Maven repositories.

**Attempted Solutions:**
1. ❌ Added `--insecure` flag to Gradle (flag doesn't exist)
2. ❌ Modified Gradle properties with SSL protocols
3. ❌ Tried updating cacerts file (download failed)
4. ❌ Added custom repository URLs
5. ✅ **SOLUTION:** Upgraded to JDK 21

**Fix Commands:**
```bash
# Found existing JDK 21 in user's system
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
```

**Lesson:** Modern Android builds require JDK 17+ with current SSL certificates.

---

### Wall #2: Node.js Version Too Old
**Error:**
```
The Capacitor CLI requires NodeJS >=22.0.0
Current: v20.19.6
```

**Root Cause:** Capacitor 8.0.0 requires Node.js 22+, but system had Node 20.

**Solution:**
```bash
source ~/.nvm/nvm.sh
nvm install 22
nvm use 22
```

**Result:** ✅ Node v22.21.1 installed

**Lesson:** Check Capacitor version requirements before building.

---

### Wall #3: Capacitor Platform Not Synced
**Error:**
```
Could not read script '/home/gh0st/pkn/android/capacitor-cordova-android-plugins/cordova.variables.gradle'
as it does not exist.
```

**Root Cause:** Capacitor's Android platform files weren't generated/synced yet.

**Solution:**
```bash
npx cap sync android
```

**Result:** ✅ Synced in 0.026s, created all necessary Cordova plugin files

**Lesson:** Always run `npx cap sync android` after pulling a Capacitor project.

---

### Wall #4: Android SDK Not Found
**Error:**
```
SDK location not found. Define a valid SDK location with an ANDROID_HOME environment variable
or by setting the sdk.dir path in your project's local properties file
```

**Root Cause:** Gradle couldn't find Android SDK location (not configured in project).

**Solution:**
```bash
echo "sdk.dir=/home/gh0st/.buildozer/android/platform/android-sdk" > /home/gh0st/pkn/android/local.properties
```

**Result:** ✅ SDK found at buildozer location

**Lesson:** Android SDK path must be in `local.properties` (this file is gitignored).

---

### Wall #5: Android SDK Licenses Not Accepted
**Error:**
```
Failed to install the following Android SDK packages as some licences have not been accepted.
To build this project, accept the SDK license agreements and install the missing components
```

**Root Cause:** Google requires explicit license acceptance for Android SDK components.

**Attempted Solutions:**
1. ❌ Tried `sdkmanager --licenses` without sdk_root (failed)
2. ✅ **SOLUTION:** Used correct SDK path

**Fix Commands:**
```bash
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
yes | ~/.buildozer/android/platform/android-sdk/tools/bin/sdkmanager --sdk_root=/home/gh0st/.buildozer/android/platform/android-sdk --licenses
```

**Result:** ✅ All licenses accepted (MIPS, Android SDK, etc.)

**Lesson:** Must accept licenses before first build. Use `yes |` to auto-accept.

---

### Wall #6: Missing Splash Screen Resource
**Error:**
```
error: resource drawable/splash (aka com.divinenode.app:drawable/splash) not found.
```

**Root Cause:** Capacitor splash screen plugin expects a `splash.png` or `splash.xml` in drawable folder.

**Solution:**
```bash
mkdir -p /home/gh0st/pkn/android/app/src/main/res/drawable
cp /home/gh0st/pkn/img/icchat.png /home/gh0st/pkn/android/app/src/main/res/drawable/splash.png
```

**Result:** ✅ Splash screen created (1.4MB PNG)

**Lesson:** Capacitor requires splash screen resources even if not used.

---

### Wall #7: Missing App Icon Resources
**Error:**
```
error: resource mipmap/ic_launcher_foreground (aka com.divinenode.app:mipmap/ic_launcher_foreground) not found.
```

**Root Cause:** App launcher icon missing from all density folders.

**Solution:**
```bash
# Create all mipmap density folders
mkdir -p /home/gh0st/pkn/android/app/src/main/res/mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}

# Copy icon to all densities
for dir in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
    cp /home/gh0st/pkn/img/icchat.png \
       /home/gh0st/pkn/android/app/src/main/res/mipmap-$dir/ic_launcher_foreground.png
done
```

**Result:** ✅ Icons created for 5 screen densities

**Lesson:** Android requires icons in multiple densities (mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi).

---

### Wall #8: Working Directory Confusion
**Error:**
```
./gradlew: No such file or directory
```

**Root Cause:** Tried running `./gradlew` from `/home/gh0st/pkn` instead of `/home/gh0st/pkn/android`.

**Solution:**
```bash
cd /home/gh0st/pkn/android
./gradlew assembleDebug
```

**Result:** ✅ Gradle wrapper found and executed

**Lesson:** Always `cd` to the `android/` directory before running Gradle commands.

---

## ✅ Final Successful Build

**Command:**
```bash
cd /home/gh0st/pkn/android
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
./gradlew assembleDebug
```

**Output:**
```
BUILD SUCCESSFUL in 1s
93 actionable tasks: 13 executed, 80 up-to-date
```

**APK Created:**
- **Path:** `/home/gh0st/pkn/android/app/build/outputs/apk/debug/app-debug.apk`
- **Size:** 12 MB
- **Package:** `com.divinenode.app`
- **Version:** 1.0 (debug)

---

## 📊 Build Statistics

| Metric | Value |
|--------|-------|
| Total Walls Hit | 8 |
| Failed Attempts | 12 |
| Successful Build Attempts | 1 |
| Total Time | ~45 minutes |
| Final APK Size | 12 MB |
| Gradle Tasks Executed | 93 |

---

## 🔑 Critical Success Factors

1. **JDK 21** - Modern SSL certificates essential
2. **Node.js 22** - Required by Capacitor 8.x
3. **Capacitor Sync** - Must sync before building
4. **Android SDK Path** - Set in `local.properties`
5. **License Acceptance** - Required before first build
6. **Resources** - Splash screen and icons mandatory
7. **Working Directory** - Must be in `android/` folder

---

## 🎓 What I Learned

### For Humans:
- Android builds are complex but systematic
- Each error message is specific and fixable
- Don't give up when one solution doesn't work
- Modern tools require modern dependencies
- Resources (icons, splash) are mandatory even if unused

### For AI:
- Parse error messages carefully for specific missing resources
- Try multiple approaches systematically
- Don't assume tools work without required dependencies
- Check working directory before running commands
- Validate each step before proceeding to next

---

## 🚀 Future Optimization

### Faster Rebuilds
```bash
# Enable Gradle daemon and caching
echo "org.gradle.daemon=true" >> android/gradle.properties
echo "org.gradle.caching=true" >> android/gradle.properties
echo "org.gradle.parallel=true" >> android/gradle.properties
```

### Reduce Build Time
```bash
# Skip tests (faster)
./gradlew assembleDebug -x test

# Use cached dependencies
./gradlew assembleDebug --offline
```

### Smaller APK
```bash
# Build release APK (minified)
./gradlew assembleRelease
```

---

## 📝 Files Modified During Build

1. **android/local.properties** - Created (SDK path)
2. **android/gradle.properties** - Modified (JVM args, AndroidX)
3. **android/app/src/main/res/drawable/splash.png** - Created
4. **android/app/src/main/res/mipmap-*/ic_launcher_foreground.png** - Created (5 files)
5. **~/.gradle/gradle.properties** - Created (SSL protocols)

---

## 🎯 Key Takeaway

**The build failed 12 times but succeeded on the 13th attempt.**

**Why?** Because each failure revealed specific missing pieces:
1. Old JDK → Upgraded
2. Old Node → Upgraded
3. Not synced → Synced
4. No SDK path → Added
5. No licenses → Accepted
6. No splash → Created
7. No icons → Created
8. Wrong directory → Fixed

**Success came from systematic problem-solving, not luck.**

---

**This log documents every wall, every solution, every lesson learned.**
**Use it to build faster next time.** 🚀
