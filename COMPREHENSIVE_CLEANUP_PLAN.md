# Comprehensive Documentation Cleanup Plan

**Date**: 2026-01-11
**Current State**: PKN has 48 markdown files (WAY too many)
**Goal**: Reduce to ~10-12 essential docs in root

---

## 📊 ANALYSIS

### PKN Root (48 files → TARGET: 10-12 files)

#### ✅ KEEP IN ROOT (Essential - 10 files)
```
CLAUDE.md              (47K) - AI development guide (ESSENTIAL)
README.md              (8.0K) - Main readme (keep this one)
CHANGELOG.md           (1.9K) - Version history
TODO.md                (5.2K) - Current tasks
DOCS_INDEX.md          (2.8K) - Navigation
QUICKSTART_GUIDE.md    (37K) - Quick start (comprehensive)
API_KEYS_SETUP.md      (2.0K) - API configuration
TOOLS_GUIDE.md         (4.4K) - Tool reference
PWA_GUIDE.md           (12K) - PWA installation
MOBILE_BUILD_GUIDE.md  (13K) - Mobile deployment
```

#### 🗑️ DELETE (Duplicates - 6 files)
```
Readme.md              (5.0K) - Duplicate of README.md (DELETE)
DN-Readme.md           (8.0K) - Old duplicate (DELETE)
BUILD_APK_QUICK_GUIDE.md (5.8K) - Covered in MOBILE_BUILD_GUIDE.md
AI_APK_BUILD_INSTRUCTIONS.md (12K) - Covered in MOBILE_BUILD_GUIDE.md
SETUP_GUIDE.md         (3.2K) - Covered in QUICKSTART_GUIDE.md
QUICK_REFERENCE.md     (3.6K) - Covered in TOOLS_GUIDE.md
```

#### 📦 ARCHIVE to docs/build/ (Build Docs - 7 files)
```
BUILD_README.md        (24K) - Detailed build info
BUILD_ON_ANDROID.md    (11K) - Android build process
CAPACITOR_SETUP.md     (14K) - Capacitor configuration
TERMUX_SETUP.md        (10K) - Termux deployment
TRANSFER_TO_ANDROID.md (4.7K) - Android transfer guide
ANDROID_COMPATIBILITY.md (3.9K) - Android notes
ANDROID_VS_PC_MODELS.md (8.7K) - Model comparison
```

#### 📦 ARCHIVE to docs/architecture/ (Architecture - 5 files)
```
MODULAR_STRUCTURE.md   (8.2K) - Architecture notes
ULTIMATE_AGENT_ARCHITECTURE.md (15K) - Agent design
MULTIAGENT_ROADMAP.md  (12K) - Roadmap
AGENTIC_QUALITIES.md   (16K) - Agent design philosophy
CYBERSECURITY_AGENT.md (8.1K) - Cybersecurity agent spec
```

#### 📦 ARCHIVE to docs/development/ (Dev Docs - 8 files)
```
DEV_TOOLS_README.md    (6.2K) - Dev tools guide
ADVANCED_FEATURES_GUIDE.md (13K) - Advanced features
CLAUDE_API_SETUP.md    (9.1K) - Claude API (subset of API_KEYS_SETUP.md)
PKN_CLI_README.md      (9.5K) - CLI tools
OSINT_README.md        (16K) - OSINT tools documentation
PLUGIN_TEST_CHECKLIST.md (7.1K) - Plugin testing
TEST_PLUGINS.md        (5.8K) - Plugin tests
UNCENSORED_IMAGE_MODELS.md (4.6K) - Image model notes
```

#### 📦 ARCHIVE to archive/docs/old-builds/ (Old Build Artifacts - 5 files)
```
APK_BUILD_LOG.md       (8.3K) - Old build log
ANDROID_CLEANUP_GUIDE.md (4.1K) - Old cleanup guide
ANDROID_PACKAGE_READY.md (5.1K) - Old build status
COMPREHENSIVE_AUDIT.md (8.1K) - Old audit
PLUGIN_TEST_RESULTS.md (11K) - Old test results
```

#### 📦 ARCHIVE to archive/docs/planning/ (Future Planning - 4 files)
```
FUTURE_IMPROVEMENTS.md (55K) - Future plans (HUGE file)
AI_HANDOFF_GUIDE.md    (17K) - AI handoff notes
YOUR_FREE_SYSTEM.md    (11K) - Philosophy/vision doc
RESTORE_INSTRUCTIONS.md (4.3K) - Old restore guide
```

#### ℹ️ KEEP BUT REVIEW (User-facing - 3 files)
```
QUICKSTART_TOOLS.md    (4.2K) - Quick tool reference (might consolidate with TOOLS_GUIDE.md)
UI_vs_CLI_TOOLS.md     (5.8K) - UI vs CLI comparison (useful)
CREDITS.md             (3.7K) - Attributions (keep for recognition)
```

---

## 📂 NEW STRUCTURE

```
apps/pkn/
├── CLAUDE.md                   # AI dev guide
├── README.md                   # Main readme
├── CHANGELOG.md                # Version history
├── TODO.md                     # Current tasks
├── DOCS_INDEX.md               # Navigation (UPDATE with new structure)
├── QUICKSTART_GUIDE.md         # Quick start
├── API_KEYS_SETUP.md           # API keys
├── TOOLS_GUIDE.md              # Tools reference
├── PWA_GUIDE.md                # PWA install
├── MOBILE_BUILD_GUIDE.md       # Mobile deploy
├── CREDITS.md                  # Attributions
├── UI_vs_CLI_TOOLS.md          # UI/CLI comparison
├── docs/
│   ├── build/                  # Build documentation (7 files)
│   ├── architecture/           # Architecture docs (5 files)
│   ├── development/            # Dev guides (8 files)
│   └── README.md               # Docs navigation
└── archive/
    └── docs/
        ├── sessions/           # Session history (20 files - DONE)
        ├── old-builds/         # Old build artifacts (5 files)
        └── planning/           # Future planning docs (4 files)
```

**Result**: 48 files → 12 essential in root + 20 organized in docs/ + 29 archived

---

## 🚀 EXECUTION STEPS

### Step 1: Create Directory Structure
```bash
mkdir -p apps/pkn/docs/{build,architecture,development}
mkdir -p apps/pkn/archive/docs/{old-builds,planning}
```

### Step 2: Delete Duplicates (6 files)
```bash
cd apps/pkn
rm Readme.md DN-Readme.md BUILD_APK_QUICK_GUIDE.md AI_APK_BUILD_INSTRUCTIONS.md SETUP_GUIDE.md QUICK_REFERENCE.md
```

### Step 3: Move to docs/build/ (7 files)
```bash
mv BUILD_README.md BUILD_ON_ANDROID.md CAPACITOR_SETUP.md TERMUX_SETUP.md TRANSFER_TO_ANDROID.md ANDROID_COMPATIBILITY.md ANDROID_VS_PC_MODELS.md docs/build/
```

### Step 4: Move to docs/architecture/ (5 files)
```bash
mv MODULAR_STRUCTURE.md ULTIMATE_AGENT_ARCHITECTURE.md MULTIAGENT_ROADMAP.md AGENTIC_QUALITIES.md CYBERSECURITY_AGENT.md docs/architecture/
```

### Step 5: Move to docs/development/ (8 files)
```bash
mv DEV_TOOLS_README.md ADVANCED_FEATURES_GUIDE.md CLAUDE_API_SETUP.md PKN_CLI_README.md OSINT_README.md PLUGIN_TEST_CHECKLIST.md TEST_PLUGINS.md UNCENSORED_IMAGE_MODELS.md docs/development/
```

### Step 6: Archive old builds (5 files)
```bash
mv APK_BUILD_LOG.md ANDROID_CLEANUP_GUIDE.md ANDROID_PACKAGE_READY.md COMPREHENSIVE_AUDIT.md PLUGIN_TEST_RESULTS.md archive/docs/old-builds/
```

### Step 7: Archive planning docs (4 files)
```bash
mv FUTURE_IMPROVEMENTS.md AI_HANDOFF_GUIDE.md YOUR_FREE_SYSTEM.md RESTORE_INSTRUCTIONS.md archive/docs/planning/
```

### Step 8: Update DOCS_INDEX.md
Update navigation to reflect new structure.

### Step 9: Create docs/README.md
Navigation guide for docs/ subdirectory.

### Step 10: Git Commit
```bash
git add -A
git commit -m "docs(pkn): comprehensive documentation reorganization

- Reduced root from 48 to 12 essential docs
- Organized 20 docs into docs/ subdirectory
- Archived 29 docs (old builds, planning, duplicates)
- Deleted 6 duplicate files
- Created logical doc structure (build, architecture, development)

Root now contains only user-facing essential documentation.
Technical docs moved to docs/ for easier navigation.
"
```

---

## ✅ VERIFICATION

After cleanup:
- [ ] PKN root has ~12 markdown files
- [ ] docs/ has 20 files organized in 3 subdirectories
- [ ] archive/docs/ has 29 additional archived files
- [ ] DOCS_INDEX.md updated with new structure
- [ ] docs/README.md created
- [ ] Git commit created
- [ ] No duplicate files remain

---

## 📊 BEFORE vs AFTER

| Location | Before | After | Change |
|----------|--------|-------|--------|
| PKN root | 48 files | 12 files | -36 files (75% reduction) |
| docs/ | 0 files | 20 files | +20 files (organized) |
| archive/ | 20 files | 49 files | +29 files (preserved) |

**Total docs**: 68 → 81 (no deletion, better organization)

---

## ⚠️ SAFETY

- ✅ No files deleted (except 6 clear duplicates)
- ✅ All docs preserved in archive/ or docs/
- ✅ Git commit allows rollback
- ✅ DOCS_INDEX.md provides navigation

---

**Ready to execute?** This will drastically improve discoverability and reduce root directory clutter.
