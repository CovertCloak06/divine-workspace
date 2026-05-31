# Divine Workspace Housekeeping Plan

**Date**: 2026-01-11
**Purpose**: Consolidate documentation, clean git state, organize workspace

---

## 📊 CURRENT STATE

### Documentation Chaos
- **PKN**: 68 markdown files in root (too many!)
- **PKN Archive**: 27 archived docs (already organized)
- **Code Academy**: 14 markdown files
- **Workspace Root**: 14 markdown files
- **Total**: ~120+ documentation files

### Git Working Directory
- **132 uncommitted changes** (from modularization work)
- Many deleted files from frontend refactoring
- Modified files need committing

---

## 🎯 CLEANUP TASKS

### Task 1: Archive PKN Session Docs (45 files → archive/)

**Move to `apps/pkn/archive/docs/sessions/`**:
```
SESSION_*.md (4 files)
*_COMPLETE.md (15+ files)
*_SUMMARY.md (8+ files)
*_FIX*.md (10+ files)
*_GUIDE.md (except QUICKSTART_GUIDE.md - keep in root)
```

**Keep in PKN root** (essential docs only):
```
CLAUDE.md              # AI development guide
README.md              # Main readme
CHANGELOG.md           # Version history
QUICKSTART_GUIDE.md    # Quick start
TODO.md                # Current tasks
DOCS_INDEX.md          # Navigation (update with new structure)
```

### Task 2: Archive Code Academy Session Docs

**Move to `apps/code-academy/docs/sessions/`**:
```
SESSION_SUMMARY.md
*_COMPLETE.md files
SETUP_COMPLETE.md
VERIFICATION_COMPLETE.md
```

**Keep in root**:
```
CLAUDE.md
README.md
```

### Task 3: Clean Workspace Root Docs

**Archive to `docs/archives/purge-2026-01-11/`**:
```
PKN_CLEANUP_PLAN.md          # Temporary purge docs
PKN_PURGE_PLAN.md
PHONE_PURGE_PLAN.md
COMPLETE_PURGE_PLAN.md
TOTAL_PURGE_SUMMARY.md
PROJECT_AUDIT_REPORT.md
```

**Keep in root**:
```
PURGE_COMPLETE_REPORT.md     # Final report (historical record)
CLAUDE.md                    # Workspace guide
README.md
BUILD_TEMPLATE.md
CHANGELOG.md
MIGRATION_GUIDE.md
WORKFLOW.md
PRE_SESSION_CHECKLIST.md
```

### Task 4: Commit Git Changes

**Strategy**: Commit modularization work in logical chunks

**Commit 1 - Frontend Modularization**:
```
- Deleted old monolithic files (app.js, css/main.css, etc.)
- Modified pkn.html to use new structure
- Updated imports in frontend/js/
```

**Commit 2 - Debugger Path Fixes**:
```
- Updated debugger-extension paths
- Fixed analysis scripts
- Updated documentation
```

**Commit 3 - Mobile Server Updates**:
```
- Updated pkn-mobile backend
```

**Commit 4 - Code Academy Refactoring**:
```
- Deleted old js/ files
- Updated index.html
```

**Commit 5 - Documentation Cleanup**:
```
- Archived session docs
- Updated CLAUDE.md
- Added purge report
```

### Task 5: Create Documentation Index

**Create `apps/pkn/DOCS_INDEX.md`**:
```markdown
# PKN Documentation Index

## Essential (Read These First)
- [README.md](README.md) - Project overview
- [CLAUDE.md](CLAUDE.md) - Development guide for AI assistants
- [QUICKSTART_GUIDE.md](QUICKSTART_GUIDE.md) - Get started quickly
- [CHANGELOG.md](CHANGELOG.md) - Version history

## User Guides
- [QUICKSTART_TOOLS.md](QUICKSTART_TOOLS.md) - Using PKN tools
- [TOOLS_GUIDE.md](TOOLS_GUIDE.md) - Comprehensive tool reference
- [PWA_GUIDE.md](PWA_GUIDE.md) - Progressive Web App features

## Developer Guides
- [BUILD_README.md](BUILD_README.md) - Building from source
- [API_KEYS_SETUP.md](API_KEYS_SETUP.md) - Configuring API keys
- [PLUGIN_SYSTEM_COMPLETE.md](PLUGIN_SYSTEM_COMPLETE.md) - Plugin development

## Mobile/Android
- [MOBILE_BUILD_GUIDE.md](MOBILE_BUILD_GUIDE.md) - Building for mobile
- [TERMUX_SETUP.md](TERMUX_SETUP.md) - Termux deployment
- [BUILD_ON_ANDROID.md](BUILD_ON_ANDROID.md) - Android build process

## Archived Documentation
- [archive/docs/](archive/docs/) - Historical session notes and completion reports
- [archive/docs/sessions/](archive/docs/sessions/) - Past development sessions
```

---

## 🚀 EXECUTION PLAN

### Phase 1: Documentation Archival (5 mins)

```bash
cd /home/gh0st/dvn/divine-workspace

# Create archive directories
mkdir -p apps/pkn/archive/docs/sessions
mkdir -p apps/code-academy/docs/sessions
mkdir -p docs/archives/purge-2026-01-11

# Archive PKN session docs
mv apps/pkn/SESSION_*.md apps/pkn/archive/docs/sessions/
mv apps/pkn/*_COMPLETE.md apps/pkn/archive/docs/sessions/
mv apps/pkn/*_SUMMARY.md apps/pkn/archive/docs/sessions/
mv apps/pkn/*_FIX*.md apps/pkn/archive/docs/sessions/

# Archive Code Academy session docs
mv apps/code-academy/SESSION_*.md apps/code-academy/docs/sessions/
mv apps/code-academy/*_COMPLETE.md apps/code-academy/docs/sessions/

# Archive workspace purge docs
mv *_PURGE*.md *_CLEANUP*.md PROJECT_AUDIT*.md TOTAL_PURGE*.md docs/archives/purge-2026-01-11/

echo "✅ Documentation archived"
```

### Phase 2: Create Documentation Index (2 mins)

```bash
# Create PKN docs index
cat > apps/pkn/DOCS_INDEX.md <<'EOF'
[... index content from above ...]
EOF

# Create Code Academy index
cat > apps/code-academy/DOCS_INDEX.md <<'EOF'
# Code Academy Documentation

## Essential
- README.md - Project overview
- CLAUDE.md - Development guide

## Archived
- docs/sessions/ - Past session notes
EOF

echo "✅ Documentation indices created"
```

### Phase 3: Git Commit Cleanup (10 mins)

```bash
cd /home/gh0st/dvn/divine-workspace

# Stage frontend modularization
git add apps/pkn/frontend/
git add -u apps/pkn/app.js apps/pkn/config.js apps/pkn/css/ apps/pkn/js/
git commit -m "refactor(pkn): modularize frontend structure

- Moved app.js to frontend/js/core/app.js
- Reorganized CSS into frontend/css/ with themes
- Modularized JavaScript into feature-based structure
- Updated pkn.html to use new module system

BREAKING CHANGE: Import paths updated to frontend/ structure
"

# Stage debugger path fixes
git add apps/debugger-extension/
git commit -m "fix(debugger): update paths for monorepo structure

- Fixed hardcoded paths from /home/gh0st/pkn to monorepo location
- Updated all analysis scripts
- Added PATHS_FIXED.md documentation
"

# Stage mobile updates
git add apps/pkn-mobile/
git commit -m "feat(mobile): enhance mobile server with OpenAI backend

- Switched to cloud API for reliability
- Added memory persistence
- Updated documentation
"

# Stage Code Academy refactoring
git add apps/code-academy/
git commit -m "refactor(code-academy): migrate to ES modules

- Removed legacy js/ files
- Updated index.html to use module imports
- Moved CSS to public/ directory
"

# Stage documentation cleanup
git add apps/pkn/archive/
git add apps/code-academy/docs/
git add docs/archives/
git add apps/pkn/DOCS_INDEX.md
git add PURGE_COMPLETE_REPORT.md
git commit -m "docs: archive session docs and add purge report

- Archived 45+ PKN session documents
- Archived Code Academy session docs
- Added purge completion report (118GB freed)
- Created documentation indices
"

echo "✅ Git commits complete"
```

### Phase 4: Final Verification (2 mins)

```bash
# Check git status is clean
git status

# Verify doc counts
echo "PKN root docs: $(ls apps/pkn/*.md 2>/dev/null | wc -l) (should be ~10-15)"
echo "PKN archived: $(ls apps/pkn/archive/docs/**/*.md 2>/dev/null | wc -l)"

# Verify workspace is clean
find . -name "*PURGE*.md" -o -name "*CLEANUP*.md" | grep -v "docs/archives"

echo "✅ Verification complete"
```

---

## 📈 EXPECTED RESULTS

### Documentation Structure
```
apps/pkn/
├── CLAUDE.md              # Essential
├── README.md              # Essential
├── CHANGELOG.md           # Essential
├── QUICKSTART_GUIDE.md    # Essential
├── TODO.md                # Essential
├── DOCS_INDEX.md          # Navigation (NEW)
├── [10-15 other essential docs]
└── archive/
    └── docs/
        └── sessions/      # 45+ session docs (MOVED)

apps/code-academy/
├── CLAUDE.md
├── README.md
├── DOCS_INDEX.md          # (NEW)
└── docs/
    └── sessions/          # Session docs (MOVED)

divine-workspace/
├── CLAUDE.md
├── README.md
├── PURGE_COMPLETE_REPORT.md  # Historical record
├── [8-10 essential docs]
└── docs/
    └── archives/
        └── purge-2026-01-11/  # Purge plans (MOVED)
```

### Git Status
```
On branch main
nothing to commit, working tree clean
```

---

## 🎯 SUCCESS CRITERIA

- [x] PKN root has ≤15 markdown files (down from 68)
- [x] All session docs archived
- [x] Documentation indices created
- [x] Git working tree clean (0 uncommitted files)
- [x] Commits are logical and well-messaged
- [x] No purge plan docs in workspace root

---

## 🔒 SAFETY

- **No deletion**: All docs moved to archive/, not deleted
- **Git history**: All commits preserve full history
- **Reversible**: Can `git revert` any commit if needed
- **Documented**: DOCS_INDEX.md shows where everything is

---

**Ready to execute? This will:**
1. Organize 120+ docs into logical structure
2. Commit 132 pending changes in 5 logical commits
3. Clean workspace for easier navigation
4. Make future sessions start faster (less docs to read)
