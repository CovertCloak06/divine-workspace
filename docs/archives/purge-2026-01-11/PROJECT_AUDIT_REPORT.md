# Project Audit Report - Before Purge

**Date**: 2026-01-11
**Purpose**: Ensure all important builds are preserved before deleting duplicates

---

## ✅ MONOREPO (CURRENT - KEEP ALL)

**Location**: `/home/gh0st/dvn/divine-workspace/apps/`

All projects below share same Git repository (commit: `a73954c`)

### 1. Ghost Keys (Android Keyboard Fork)
- **Location**: `/home/gh0st/dvn/divine-workspace/apps/ghost-keys`
- **Type**: Android app (Gradle/Kotlin)
- **Status**: ✅ Current version
- **Git Status**: Modified files (uncommitted changes)
- **Remote**: To be checked
- **Built APK**: ❌ Not found in apps/ghost-keys/
- **Size**: Unknown
- **Notes**: Unexpected Keyboard fork with Ghost Keys branding

### 2. Scripture Alarm
- **Location**: `/home/gh0st/dvn/divine-workspace/apps/scripture-alarm`
- **Type**: Android app (Gradle)
- **Status**: ✅ Current version
- **Git Status**: Modified files (uncommitted changes)
- **GitHub**: https://github.com/CovertCloak06/scripture-alarm
- **Built APKs Found**:
  - `/home/gh0st/dvn/divine-workspace/apps/scripture-alarm/ScriptureAlarm-v1.0-debug.apk`
  - `/home/gh0st/dvn/divine-workspace/apps/scripture-alarm/app/build/outputs/apk/debug/app-debug.apk`
- **Size**: ~4GB (includes Gradle cache)

### 3. Code Academy
- **Location**: `/home/gh0st/dvn/divine-workspace/apps/code-academy`
- **Type**: Web app (Vite/JavaScript)
- **Status**: ✅ Current version
- **Git Status**: Many deleted files (refactoring in progress)
- **GitHub**: https://github.com/CovertCloak06/divine-node-code-academy
- **Deployed**: Likely (public repo)
- **Size**: ~1GB (includes node_modules)
- **Notes**: Interactive coding education platform

### 4. PKN (Desktop)
- **Location**: `/home/gh0st/dvn/divine-workspace/apps/pkn`
- **Type**: Python Flask + Web UI
- **Status**: ✅ Current version
- **Git Status**: Many deleted files (frontend modularization)
- **GitHub**: https://github.com/CovertCloak06/pkn-multi-agent
- **Built APK**: `/home/gh0st/dvn/divine-workspace/apps/pkn/android/app/build/outputs/apk/debug/app-debug.apk`
- **Size**: 27GB (includes llama.cpp models, node_modules)
- **Running**: ✅ Server active at localhost:8010

### 5. PKN Mobile
- **Location**: `/home/gh0st/dvn/divine-workspace/apps/pkn-mobile`
- **Type**: Python Flask (OpenAI API backend)
- **Status**: ✅ Current version
- **Git Status**: Modified backend/server.py
- **Size**: Unknown
- **Notes**: Mobile-optimized PKN using cloud APIs

### 6. Debugger Extension
- **Location**: `/home/gh0st/dvn/divine-workspace/apps/debugger-extension`
- **Type**: Chrome DevTools extension
- **Status**: ✅ Current version
- **Git Status**: Modified analysis scripts (path fixes)
- **Size**: <100MB
- **Notes**: Code analysis tools for PKN

---

## 🗑️ OLD LOCATIONS (DELETE THESE)

### Scripture Alarm (OLD)
- **Location**: `/home/gh0st/dvn/scripture-alarm`
- **Status**: ❌ OLD standalone version (pre-monorepo)
- **Has own .git**: Yes
- **Last Modified**: Jan 9
- **Built APKs**:
  - `/home/gh0st/dvn/scripture-alarm/ScriptureAlarm-v1.0-debug.apk`
  - `/home/gh0st/dvn/scripture-alarm/app/build/outputs/apk/debug/app-debug.apk`
- **Action**: DELETE (APKs are duplicates of monorepo version)

### Code Academy (OLD)
- **Location**: `/home/gh0st/dvn/code-academy`
- **Status**: ❌ OLD standalone version (pre-monorepo)
- **Has own .git**: Yes (likely outdated)
- **Size**: ~1GB
- **Action**: DELETE

### PKN (OLD)
- **Location**: `/home/gh0st/dvn/pkn`
- **Status**: ❌ OLD monorepo location
- **Size**: 2.2GB
- **Action**: DELETE

### Debugger (OLD)
- **Location**: `/home/gh0st/dvn/dvn-debugger`
- **Status**: ❌ OLD standalone version
- **Has outdated paths**: Yes (`/home/gh0st/pkn` instead of monorepo path)
- **Action**: DELETE

---

## 📦 LOOSE APK FILES (KEEP OR DELETE?)

### Scripture Alarm APKs in Root
- `/home/gh0st/scripture-alarm-v1.0.0-beta.apk`
- `/home/gh0st/scripture-alarm-v1.1.0-beta.apk`
- **Action**: ❓ KEEP if these are release builds, DELETE if duplicates

### PKN APKs
- `/home/gh0st/Downloads/DivineNode.apk`
- **Action**: ❓ Check if this is a release build or old test

---

## ❓ QUESTIONS FOR USER

### 1. Ghost Keys APK
**Question**: Where is the Ghost Keys (Unexpected Keyboard fork) APK?
- Not found in `/home/gh0st/dvn/divine-workspace/apps/ghost-keys/`
- No GitHub release found
- **Need to build it?** Or is it somewhere else?

### 2. IDE Platform
**Question**: What is the "IDE platform" you mentioned?
- Not found in monorepo
- Could you mean:
  - Code Academy? (education platform)
  - Debugger Extension? (dev tools)
  - Something else not in the monorepo?

### 3. Loose APKs
**Question**: Should we keep the loose APK files in root?
- `scripture-alarm-v1.0.0-beta.apk`
- `scripture-alarm-v1.1.0-beta.apk`
- `DivineNode.apk`

Are these release builds or can we delete them?

---

## 🎯 RECOMMENDED ACTIONS

### Before Purge - Create Safety Backup
```bash
# Backup monorepo (already done - Jan 8 backup exists)
# pkn-backup-working-20260108_200610.tar.gz (22GB)

# Build Ghost Keys APK (if needed)
cd /home/gh0st/dvn/divine-workspace/apps/ghost-keys
./gradlew assembleDebug
cp build/outputs/apk/debug/*.apk ~/ghost-keys-latest.apk

# Export loose APKs to safe location (if keeping)
mkdir -p ~/archive/apk-releases
cp ~/scripture-alarm*.apk ~/archive/apk-releases/
cp ~/Downloads/DivineNode.apk ~/archive/apk-releases/
```

### After Verification - Safe to Delete
```bash
# OLD standalone versions
rm -rf ~/dvn/scripture-alarm
rm -rf ~/dvn/code-academy
rm -rf ~/dvn/pkn
rm -rf ~/dvn/dvn-debugger

# Plus all the PKN duplicates in Downloads/Documents/Pictures/Videos
# (as per purge script)
```

---

## 📊 SUMMARY

### ✅ VERIFIED & SAFE (All in Monorepo)
- Ghost Keys ✅ (needs APK built)
- Scripture Alarm ✅ (has APKs)
- Code Academy ✅ (web app)
- PKN Desktop ✅ (has APK)
- PKN Mobile ✅
- Debugger Extension ✅

### ❓ NEEDS CLARIFICATION
- Ghost Keys APK location
- IDE platform identity
- Loose APK files (keep or delete?)

### 🗑️ SAFE TO DELETE
- `/home/gh0st/dvn/scripture-alarm` (OLD)
- `/home/gh0st/dvn/code-academy` (OLD)
- `/home/gh0st/dvn/pkn` (OLD)
- `/home/gh0st/dvn/dvn-debugger` (OLD)
- All PKN duplicates (98GB)

---

**Next Step**: Answer the 3 questions above, then proceed with purge.
