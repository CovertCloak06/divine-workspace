# ✅ SCRIPTURE ALARM MIGRATION COMPLETE

**Date:** 2026-01-11
**App:** Scripture Alarm (Bible Verse Alarm Clock)
**Status:** ✅ SUCCESSFULLY MIGRATED TO MONOREPO

---

## 📱 App Overview

**Scripture Alarm** is an Android alarm clock app that wakes you up with Bible verses read aloud via Text-to-Speech instead of traditional alarm tones.

### Key Features
- **Scripture Wake-Up**: Wake up to God's Word being read aloud
- **Full KJV Bible**: All 31,100 verses from 66 books included
- **Multiple Source Options**: Curated categories, full Bible, specific books/chapters
- **Text-to-Speech**: Natural voice reading with customizable speed and pitch
- **Personalized Greeting**: User's name + verse
- **10 Color Themes**: 5 light + 5 dark themes
- **Repeating Alarms**: Set alarms for specific days of the week
- **Gradual Wake-Up**: Volume starts at 30% and increases over 30 seconds

### Scripture Sources
- Curated categories (Morning, Encouragement, Psalms, Proverbs, Gospels, General)
- Full Bible (random)
- Old Testament only
- New Testament only
- Specific book
- Specific chapter

---

## 🚀 Migration Summary

### Source Location
**Original:** `/home/gh0st/dvn/scripture-alarm/`

### New Location
**Monorepo:** `/home/gh0st/dvn/divine-workspace/apps/scripture-alarm/`

### Changes Made
1. ✅ Copied entire app to monorepo
2. ✅ Removed `.git` directory (standalone repo history)
3. ✅ Removed `.gradle` and `build/` directories (build artifacts)
4. ✅ Removed `local.properties` (machine-specific paths)
5. ✅ Removed `gradle/wrapper/` (kept gradlew scripts)
6. ✅ Created `package.json` as `@divine/scripture-alarm`
7. ✅ Created `biome.json` extending shared config
8. ✅ Registered with pnpm workspace (now 9 projects)

---

## 📦 Package Details

**Package Name:** `@divine/scripture-alarm`
**Version:** `1.1.0`
**Type:** Android App (Kotlin)
**License:** MIT

### NPM Scripts

```bash
# Development
pnpm --filter @divine/scripture-alarm dev

# Build debug APK
pnpm --filter @divine/scripture-alarm build

# Build release APK
pnpm --filter @divine/scripture-alarm build:release

# Install on device
pnpm --filter @divine/scripture-alarm install-apk

# Uninstall from device
pnpm --filter @divine/scripture-alarm uninstall-apk

# Clean build artifacts
pnpm --filter @divine/scripture-alarm clean

# Lint
pnpm --filter @divine/scripture-alarm lint

# Format
pnpm --filter @divine/scripture-alarm format
```

---

## 🏗️ Build Instructions

### Using Gradle (Recommended for Android)

```bash
cd /home/gh0st/dvn/divine-workspace/apps/scripture-alarm

# Build debug APK
./gradlew assembleDebug

# Build release APK
./gradlew assembleRelease

# Clean
./gradlew clean
```

### Using pnpm (from workspace root)

```bash
cd /home/gh0st/dvn/divine-workspace

# Build
pnpm --filter @divine/scripture-alarm build

# Install
pnpm --filter @divine/scripture-alarm install-apk
```

---

## 📱 Installation

### Prerequisites
- Android device with API 26+ (Android 8.0 Oreo or higher)
- ADB tools installed (for installing APK)
- Device connected via USB with debugging enabled OR wireless debugging paired

### Install APK

```bash
# Option 1: Using pnpm script
pnpm --filter @divine/scripture-alarm install-apk

# Option 2: Using adb directly
~/platform-tools/adb install -r apps/scripture-alarm/app/build/outputs/apk/debug/app-debug.apk

# Option 3: Transfer APK to device and install manually
# APK location: apps/scripture-alarm/app/build/outputs/apk/debug/app-debug.apk
```

---

## 🔧 Tech Stack

- **Language:** Kotlin
- **Build System:** Gradle (Kotlin DSL)
- **UI:** Android Views (Material Design 3)
- **Database:** SQLite (5.1MB KJV Bible database in assets/)
- **Min SDK:** 26 (Android 8.0 Oreo)
- **Target SDK:** 35 (Android 15)

### Key Dependencies
- AndroidX Core KTX
- AndroidX AppCompat
- Material Design Components
- ConstraintLayout

---

## 📂 Project Structure

```
apps/scripture-alarm/
├── app/
│   ├── src/
│   │   └── main/
│   │       ├── java/com/covertcloak/scripturealarm/
│   │       │   ├── alarm/          # Alarm scheduling and service
│   │       │   │   ├── AlarmReceiver.kt
│   │       │   │   ├── AlarmScheduler.kt
│   │       │   │   ├── AlarmService.kt
│   │       │   │   └── BootReceiver.kt
│   │       │   ├── data/           # Data models and preferences
│   │       │   │   ├── AppPreferences.kt
│   │       │   │   ├── BibleDatabase.kt
│   │       │   │   ├── BibleVerse.kt
│   │       │   │   └── BibleVerseRepository.kt
│   │       │   ├── tts/            # Text-to-Speech engine
│   │       │   │   └── ScriptureSpeaker.kt
│   │       │   └── ui/             # Activities and UI
│   │       │       ├── AlarmActivity.kt
│   │       │       ├── MainActivity.kt
│   │       │       ├── SetAlarmActivity.kt
│   │       │       └── SettingsActivity.kt
│   │       ├── res/                # Resources (layouts, themes, strings)
│   │       ├── assets/
│   │       │   └── kjv_bible.db    # Full KJV Bible (31,100 verses)
│   │       └── AndroidManifest.xml
│   └── build.gradle.kts
├── build.gradle.kts
├── settings.gradle.kts
├── gradlew
├── gradlew.bat
├── package.json                    # NEW: Monorepo integration
├── biome.json                      # NEW: Linting config
├── README.md
└── CLAUDE.md
```

---

## 🎨 Features Detail

### Alarm Features
- **Repeating Alarms**: Monday-Sunday selection
- **Full-Screen Display**: Beautiful verse display with gradient background
- **Vibration**: Brief vibration before TTS starts
- **Gradual Volume**: Starts at 30%, increases to user setting over 30 seconds
- **Personalized**: "Good morning [Name], here's your verse for today"

### Scripture Selection
- **Curated Categories**: 35+ hand-picked verses in categories
- **Full Bible**: Random verse from any of the 31,100 verses
- **Testament Selection**: Old Testament or New Testament only
- **Book Selection**: Choose from 66 books (Genesis to Revelation)
- **Chapter Selection**: Pick specific chapter (e.g., Psalm 23, Romans 8)
- **Sequential or Random**: Read through verses in order or randomly

### Voice Settings
- **Voice Selection**: Choose from all installed TTS voices
- **HD/Online Voices**: Labeled clearly in voice picker
- **Speech Speed**: 0.5x to 1.5x adjustable slider
- **Voice Pitch**: Adjustable pitch slider
- **Test Voice**: Preview voice settings before saving

### Theme Settings
- **Theme Mode**: System, Light, or Dark
- **10 Color Schemes**:
  - Light: Purple, Blue, Green, Orange, Pink
  - Dark: Dark Purple, Dark Blue, Dark Green, Dark Orange, Teal
- **Font Sizes**: Small, Medium, Large

---

## 🔗 GitHub Repository

**Original Repo:** https://github.com/CovertCloak06/scripture-alarm
**Version:** v1.1.0-beta

The app is now part of the Divine Node monorepo. The original standalone repository can be archived.

---

## ✅ Verification Checklist

- [x] App copied to `apps/scripture-alarm/`
- [x] `.git` directory removed
- [x] `.gradle` and `build/` removed
- [x] `local.properties` removed
- [x] `package.json` created (`@divine/scripture-alarm`)
- [x] `biome.json` created (extends shared config)
- [x] Registered with pnpm workspace (9 projects)
- [x] NPM scripts configured (build, install-apk, clean, etc.)
- [x] Migration documentation created

---

## 🚀 Next Steps

### 1. Test Build

```bash
cd /home/gh0st/dvn/divine-workspace/apps/scripture-alarm
./gradlew clean assembleDebug
```

### 2. Install on Device

```bash
pnpm --filter @divine/scripture-alarm install-apk
```

### 3. Commit Migration

```bash
cd /home/gh0st/dvn/divine-workspace
git add apps/scripture-alarm SCRIPTURE_ALARM_MIGRATION_COMPLETE.md
git commit -m "feat: migrate scripture-alarm to monorepo

- Add Scripture Alarm (Bible verse alarm clock) to apps/
- Kotlin Android app with full KJV Bible (31,100 verses)
- Features: TTS wake-up, 10 color themes, personalized greetings
- Package: @divine/scripture-alarm v1.1.0
- Gradle build with NPM scripts integration
- 9 workspace projects total

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

### 4. Archive Original Location (Optional)

After verification, you can archive or delete the original location:

```bash
# Archive
tar -czf ~/backups/scripture-alarm-standalone-$(date +%Y%m%d).tar.gz /home/gh0st/dvn/scripture-alarm

# Delete original (after archive verification)
rm -rf /home/gh0st/dvn/scripture-alarm
```

---

## 🎉 Summary

**Scripture Alarm** has been successfully migrated to the Divine Node monorepo!

✅ **Package:** `@divine/scripture-alarm`
✅ **Location:** `apps/scripture-alarm/`
✅ **Workspace Projects:** 9 total
✅ **Build System:** Gradle + pnpm integration
✅ **Status:** Ready for development

**ONE SOURCE OF TRUTH:** `/home/gh0st/dvn/divine-workspace/apps/scripture-alarm/`

---

_Migration completed: 2026-01-11_
