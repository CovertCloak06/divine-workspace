# PKN Cleanup Plan - CRITICAL

**Date**: 2026-01-11
**Issue**: 100+ GB of duplicate PKN copies scattered across the system
**Risk**: Scripts may load wrong files, causing bugs and confusion

---

## CURRENT SITUATION

### ✅ ACTIVE (KEEP THIS)
**Location**: `/home/gh0st/dvn/divine-workspace/apps/pkn` (27GB)
**Status**: Current monorepo location
**Evidence**:
- Shell config in `.bashrc` points here
- Latest modifications (Jan 11)
- Proper monorepo structure with backend/frontend/

---

## 🗑️ TO ARCHIVE/DELETE (98GB+)

### Root Level Directories
| Directory | Size | Last Modified | Action |
|-----------|------|---------------|--------|
| `/home/gh0st/dvn/pkn` | 2.2G | ? | **DELETE** (old monorepo location) |
| `/home/gh0st/pkn-android-app` | 26M | Jan 2 | **ARCHIVE** (if still needed) |
| `/home/gh0st/pkn-os` | 112K | ? | **DELETE** (small, probably old) |
| `/home/gh0st/pkn-standalone-apk` | 1.8G | Jan 6 | **ARCHIVE** (APK builds) |
| `/home/gh0st/pkn_backups/` | 8.3M | Dec 31 | **ARCHIVE** (old backups) |

### Downloads (Huge Mess!)
| Directory | Size | Action |
|-----------|------|--------|
| `/home/gh0st/Downloads/pkn2` | 9.4G | **DELETE** |
| `/home/gh0st/Downloads/pkn.newest` | 9.2G | **DELETE** |
| `/home/gh0st/Downloads/pkn.bestbak.sofar` | 9.4G | **DELETE** |
| `/home/gh0st/Downloads/pkn_transfer` | 28M | **DELETE** |

### Wrong Locations (WHY?!)
| Directory | Size | Action |
|-----------|------|--------|
| `/home/gh0st/Documents/pkn` | 6.8G | **DELETE** (not for code!) |
| `/home/gh0st/Pictures/pkn` | 9.4G | **DELETE** (WHY IN PICTURES?!) |
| `/home/gh0st/Videos/pkn.thebestbak` | 9.4G | **DELETE** (WHY IN VIDEOS?!) |

### Tarballs (48GB!)
| File | Size | Date | Action |
|------|------|------|--------|
| `pkn-backup-working-20260108_200610.tar.gz` | 22G | Jan 8 | **KEEP** (recent backup) |
| `pkn_android_transfer.tar.gz` | 13G | Dec 30 | **DELETE** |
| `pkn_android_transfer_v2.tar.gz` | 13G | Dec 30 | **DELETE** (duplicate!) |
| `pkn.zip` | 8.7G | Dec 22 | **DELETE** (old) |
| `pkn-clean.tar.gz` | 1.3G | ? | **DELETE** |
| `pkn_backup_20260105_190410.tar.gz` | 525M | Jan 5 | **DELETE** (old) |
| `pkn-good-build-latest.tar.gz` | 5.6M | Dec 29 | **DELETE** (old) |

---

## 🔧 ISSUES TO FIX

### 1. Bad Shell Alias
**Problem**: `.bashrc` has:
```bash
alias pkn='cd ~/pkn 2>/dev/null || mkdir -p ~/pkn && cd ~/pkn && bash'
```
This creates/navigates to `~/pkn` which doesn't exist!

**Fix**: Should be:
```bash
alias pkn='cd ~/dvn/divine-workspace/apps/pkn && bash'
```

### 2. Multiple debugger-extension copies
- ❌ `/home/gh0st/dvn/dvn-debugger` (OLD, wrong paths)
- ✅ `/home/gh0st/dvn/divine-workspace/apps/debugger-extension` (CURRENT)

---

## CLEANUP COMMANDS

### Phase 1: Create Final Backup (Just in Case)
```bash
cd ~
tar -czf ~/backups/pkn-pre-cleanup-backup-$(date +%Y%m%d).tar.gz \
    dvn/divine-workspace/apps/pkn \
    .bashrc

echo "✅ Backup created"
```

### Phase 2: Delete Downloads Duplicates (36GB freed)
```bash
rm -rf ~/Downloads/pkn2
rm -rf ~/Downloads/pkn.newest
rm -rf ~/Downloads/pkn.bestbak.sofar
rm -rf ~/Downloads/pkn.bestsofar2
rm -rf ~/Downloads/pkn_transfer
rm ~/Downloads/pkn*.tar.gz

echo "✅ Downloads cleaned"
```

### Phase 3: Delete Wrong Locations (25GB freed)
```bash
rm -rf ~/Documents/pkn
rm -rf ~/Pictures/pkn
rm -rf ~/Videos/pkn.thebestbak

echo "✅ Removed PKN from wrong folders"
```

### Phase 4: Delete Old Tarballs (37GB freed)
```bash
# KEEP ONLY: pkn-backup-working-20260108_200610.tar.gz
rm ~/pkn_android_transfer.tar.gz
rm ~/pkn_android_transfer_v2.tar.gz
rm ~/pkn.zip
rm ~/Downloads/pkn-clean.tar.gz
rm ~/pkn_backup_20260105_190410.tar.gz
rm ~/pkn-good-build-latest.tar.gz

echo "✅ Old tarballs removed"
```

### Phase 5: Archive (Move to archive/)
```bash
mkdir -p ~/archive/pkn-old-versions

# Move old monorepo location
mv ~/dvn/pkn ~/archive/pkn-old-versions/pkn-old-dvn-root

# Move old debugger
mv ~/dvn/dvn-debugger ~/archive/pkn-old-versions/dvn-debugger-old

# Move APK projects (might still be useful)
mv ~/pkn-android-app ~/archive/pkn-old-versions/
mv ~/pkn-standalone-apk ~/archive/pkn-old-versions/
mv ~/pkn-os ~/archive/pkn-old-versions/

# Move old backups
mv ~/pkn_backups ~/archive/pkn-old-versions/

echo "✅ Old versions archived"
```

### Phase 6: Fix Shell Alias
```bash
# Backup bashrc
cp ~/.bashrc ~/.bashrc.backup-$(date +%Y%m%d)

# Fix the alias
sed -i "s|alias pkn=.*|alias pkn='cd ~/dvn/divine-workspace/apps/pkn \&\& bash'|g" ~/.bashrc

# Reload
source ~/.bashrc

echo "✅ Shell alias fixed"
```

---

## VERIFICATION

After cleanup, run:
```bash
# Should show only ONE directory
find /home/gh0st -maxdepth 3 -type d -name "pkn" 2>/dev/null

# Expected output:
# /home/gh0st/dvn/divine-workspace/apps/pkn
# /home/gh0st/archive/pkn-old-versions/pkn-old-dvn-root (archived)

# Check disk space saved
df -h ~

# Test the alias
pkn
pwd  # Should show: /home/gh0st/dvn/divine-workspace/apps/pkn
```

---

## TOTAL SPACE TO FREE: ~98GB

**Breakdown**:
- Downloads: 36GB
- Wrong locations: 25GB
- Old tarballs: 37GB

**After cleanup**:
- Active PKN: 27GB (kept)
- Recent backup: 22GB (kept)
- Archived: ~4GB (kept)
- **Freed: ~98GB**

---

## SAFETY NOTES

1. **Backup created first** - can restore if something breaks
2. **Recent backup kept** - `pkn-backup-working-20260108_200610.tar.gz` (Jan 8)
3. **Archive directory** - old versions moved, not deleted immediately
4. **Can undo** - If you realize you need something, check `~/archive/pkn-old-versions/`

---

## NEXT STEPS

After cleanup:
1. Verify PKN still works: `cd ~/dvn/divine-workspace/apps/pkn && ./pkn_control.sh start-all`
2. Test debugger extension: Load from correct location
3. Update any remaining scripts with hardcoded paths
4. After 1 week of stable operation, delete `~/archive/pkn-old-versions/` to free final space

---

**Ready to execute?** Review this plan, then run the Phase commands one by one.
