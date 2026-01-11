# ✅ GHOST KEYS MIGRATION COMPLETE

## 🎯 What Was Done

Ghost Keys Android keyboard app has been successfully migrated from `/home/gh0st/unexpected-keyboard-fork/` to the Divine Node monorepo.

---

## 📁 New Structure

```
divine-workspace/
├── apps/
│   ├── code-academy/          ✅ Migrated
│   ├── pkn/                   ✅ Migrated
│   ├── debugger-extension/    ✅ Migrated
│   └── ghost-keys/            ✅ Migrated (just now)
├── packages/
│   ├── shared-config/         ✅ Shared configs
│   └── pkn-plugins/           ✅ PKN plugins
```

---

## 🚀 How to Use Ghost Keys in Monorepo

### Build APK

```bash
cd /home/gh0st/dvn/divine-workspace

# Option 1: Using pnpm scripts
pnpm --filter @divine/ghost-keys build          # Debug APK
pnpm --filter @divine/ghost-keys build:release  # Release APK

# Option 2: Direct Gradle
cd apps/ghost-keys
./gradlew assembleDebug
# APK at: build/outputs/apk/debug/Unexpected-Keyboard-debug.apk
```

### Install on Device

```bash
# Build and install via ADB
pnpm --filter @divine/ghost-keys build
pnpm --filter @divine/ghost-keys install-apk

# Or manually
cd apps/ghost-keys
adb install build/outputs/apk/debug/Unexpected-Keyboard-debug.apk
```

### Development

```bash
# Clean build artifacts
pnpm --filter @divine/ghost-keys clean

# Check layout definitions
pnpm --filter @divine/ghost-keys check-layout

# Lint and format
pnpm --filter @divine/ghost-keys lint
pnpm --filter @divine/ghost-keys format
```

---

## 📦 What Changed

### Package Name
- **New**: `@divine/ghost-keys`

### Scripts Added
```json
{
  "dev": "Instructions for Android development",
  "build": "./gradlew assembleDebug",
  "build:release": "./gradlew assembleRelease",
  "install-apk": "adb install APK",
  "uninstall-apk": "adb uninstall app",
  "clean": "./gradlew clean",
  "lint": "biome lint .",
  "format": "biome format --write .",
  "check-layout": "python3 check_layout.py"
}
```

### Tooling Added
- ✅ package.json (monorepo workspace integration)
- ✅ biome.json (extends @divine/shared-config)

### Tooling Removed
- ❌ .git (removed nested git repo)
- ❌ .gradle (build cache)
- ❌ build/ (compiled artifacts)
- ❌ .gitignore (uses monorepo root .gitignore)
- ❌ .gitattributes

### Location Changed
- **Old**: `/home/gh0st/unexpected-keyboard-fork/`
- **New**: `/home/gh0st/dvn/divine-workspace/apps/ghost-keys/`

---

## 🎯 What is Ghost Keys?

A custom Android keyboard fork based on [Unexpected Keyboard](https://github.com/Julow/Unexpected-Keyboard) with features designed for PKN/Termux workflows.

### Features

**Macro Row** - Dedicated top row with 8 quick-access keys:
- **Deploy** - `pkn start-all` + 3 swipe actions for individual services
- **Stop** - `pkn stop-all` + service-specific stop commands
- **Push** - `git push` + pull/add/commit actions
- **Status** - `git status` + diff/log/branch commands
- **Health** - Server health checks (ports 8010, 8000, 9000)
- **Kill** - Process management (pkill python/node/pkn)
- **Logs** - Tail server logs (divinenode, parakleon, llama)
- **Menu** - `pkn` menu + system monitoring (htop, free, df)

**PKN Color Themes** - 6 cyberpunk-inspired dark themes:
- PKN Cyan (`#00FFFF`) - Default cyberpunk
- PKN Red (`#FF4444`) - Danger red
- PKN Purple (`#BB86FC`) - Material purple
- PKN Blue (`#3399FF`) - Electric blue
- PKN Green (`#00FF88`) - Matrix green
- PKN Yellow (`#FFA500`) - Warning orange

**Optimized Layout**:
- Wider 'a' and 'l' keys (1.5x width)
- Tab/Esc swipe actions on 'a'
- Semicolon/colon swipe actions on 'l'
- Full QWERTY with swipe-to-corner special characters

---

## ⚠️ Important Notes

### Old Location Still Exists

**`/home/gh0st/unexpected-keyboard-fork/`** still exists unchanged and has its own git repository with remotes:
- `origin`: https://github.com/Julow/Unexpected-Keyboard.git (upstream)
- `ghost`: https://github.com/CovertCloak06/Ghost-Keys.git (your fork)

**DO NOT DELETE YET** - This is your development repo with git history.

The monorepo copy is **INDEPENDENT** - changes in monorepo won't sync to your GitHub repo automatically.

### Workflow Recommendation

**For active development on Ghost Keys:**
1. Keep developing in `/home/gh0st/unexpected-keyboard-fork/`
2. Commit and push to GitHub as usual
3. When ready to integrate with monorepo, copy latest version:
   ```bash
   # Stop! Back up first
   cp -r apps/ghost-keys apps/ghost-keys.backup

   # Copy latest version
   rsync -av --exclude='.git' --exclude='build' --exclude='.gradle' \
     /home/gh0st/unexpected-keyboard-fork/ \
     apps/ghost-keys/
   ```

**For monorepo-only changes:**
- Edit directly in `apps/ghost-keys/`
- Commit to divine-workspace repo
- Optionally copy back to standalone repo if needed

### Android Requirements

**Build Requirements:**
- Android SDK (API 34+)
- Java 17+
- Gradle wrapper included

**Set Android SDK path:**
```bash
export ANDROID_HOME=/home/gh0st/android-sdk
# Or wherever your Android SDK is installed
```

**Check SDK setup:**
```bash
echo $ANDROID_HOME
ls $ANDROID_HOME/platforms
```

---

## 🧪 Verification Checklist

```bash
cd /home/gh0st/dvn/divine-workspace

# 1. Check files exist
ls -la apps/ghost-keys/build.gradle.kts
ls -la apps/ghost-keys/AndroidManifest.xml

# 2. Check workspace recognizes it
pnpm list --depth=0
# Should show @divine/ghost-keys

# 3. Test build (requires Android SDK)
cd apps/ghost-keys
./gradlew assembleDebug

# 4. Check APK created
ls -lh build/outputs/apk/debug/Unexpected-Keyboard-debug.apk

# 5. Install on device (if connected via ADB)
adb devices
pnpm install-apk
```

---

## 📊 Migration Stats

- **Size**: 32MB (source code + resources)
- **Files migrated**: ~1000+ files (Java, Kotlin, XML, Python, resources)
- **Android app**: Keyboard IME with custom layouts and themes
- **GitHub repo**: https://github.com/CovertCloak06/Ghost-Keys
- **Based on**: Unexpected Keyboard by Julow

---

## 🎯 Next Steps

### 1. Test Build Process

Ensure Android SDK is configured and build works:
```bash
cd apps/ghost-keys
export ANDROID_HOME=/home/gh0st/android-sdk
./gradlew assembleDebug
```

### 2. Install on Device

If you have an Android device connected:
```bash
adb devices
pnpm --filter @divine/ghost-keys install-apk
```

### 3. Customize for Monorepo

If you want to adjust macro commands or themes:
- Macros: `res/xml/macro_row.xml`
- Themes: `res/values/themes.xml`
- App name: `res/values/strings.xml`

### 4. Sync Strategy

Decide how to keep standalone repo and monorepo copy in sync (see notes above).

---

## 📖 References

- [BUILD_TEMPLATE.md](./BUILD_TEMPLATE.md) - Monorepo guide
- [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md) - Migration steps
- [apps/ghost-keys/README.md](./apps/ghost-keys/README.md) - Ghost Keys docs
- [Unexpected Keyboard GitHub](https://github.com/Julow/Unexpected-Keyboard) - Upstream project
- [Ghost Keys GitHub](https://github.com/CovertCloak06/Ghost-Keys) - Your fork

---

**Ghost Keys is now integrated into the Divine Node monorepo.**

**Monorepo location: `/home/gh0st/dvn/divine-workspace/apps/ghost-keys/`**

**Original development repo: `/home/gh0st/unexpected-keyboard-fork/` (kept separate)**

_Migration completed: 2026-01-11_
