# PKN PURGE PLAN - DELETE EVERYTHING OLD

**Date**: 2026-01-11
**Philosophy**: DELETE, don't archive. We have Git and one recent backup. That's enough.

---

## ✅ KEEP (ONLY THESE)

1. **Active monorepo**: `/home/gh0st/dvn/divine-workspace/apps/pkn` (27GB)
2. **One recent backup**: `~/pkn-backup-working-20260108_200610.tar.gz` (22GB, Jan 8)
3. **Git history**: Already in `.git/` folders

**Total kept**: 49GB

---

## 🔥 DELETE IMMEDIATELY (98GB)

### Directories - DELETE ALL
```bash
# Old monorepo location
rm -rf ~/dvn/pkn

# Downloads mess
rm -rf ~/Downloads/pkn2
rm -rf ~/Downloads/pkn.newest
rm -rf ~/Downloads/pkn.bestbak.sofar
rm -rf ~/Downloads/pkn.bestsofar2
rm -rf ~/Downloads/pkn_transfer

# Wrong locations (WHY WERE THESE HERE?!)
rm -rf ~/Documents/pkn
rm -rf ~/Pictures/pkn
rm -rf ~/Videos/pkn.thebestbak

# Old projects
rm -rf ~/pkn-android-app
rm -rf ~/pkn-standalone-apk
rm -rf ~/pkn-os
rm -rf ~/pkn_backups

# Old debugger
rm -rf ~/dvn/dvn-debugger
```

### Tarballs - DELETE ALL EXCEPT JAN 8
```bash
# DELETE these old backups
rm ~/pkn_android_transfer.tar.gz          # 13GB
rm ~/pkn_android_transfer_v2.tar.gz       # 13GB
rm ~/pkn.zip                              # 8.7GB
rm ~/Downloads/pkn-clean.tar.gz           # 1.3GB
rm ~/pkn_backup_20260105_190410.tar.gz    # 525MB
rm ~/pkn-good-build-latest.tar.gz         # 5.6MB
rm ~/Downloads/pkn*.tar.gz                # Any others

# KEEP ONLY THIS ONE:
# ~/pkn-backup-working-20260108_200610.tar.gz (Jan 8)
```

### Small Files
```bash
rm ~/Downloads/pkn.code-workspace
rm ~/Downloads/pkn_control_patched.sh
rm ~/Downloads/pkn_app.tar.gz
rm ~/Downloads/pkn-android.tar.gz
```

---

## FULL PURGE SCRIPT (ONE COMMAND)

```bash
#!/bin/bash
# PKN Purge - DELETE everything old

echo "🔥 PURGING OLD PKN COPIES..."
echo "This will DELETE (not archive) ~98GB of old files"
echo ""
read -p "Are you SURE? Type 'DELETE' to continue: " confirm

if [ "$confirm" != "DELETE" ]; then
    echo "Aborted."
    exit 1
fi

# Count files before
BEFORE=$(df -h ~ | tail -1 | awk '{print $3}')
echo "Disk usage before: $BEFORE"

# DELETE directories
echo "Deleting directories..."
rm -rf ~/dvn/pkn
rm -rf ~/Downloads/pkn2
rm -rf ~/Downloads/pkn.newest
rm -rf ~/Downloads/pkn.bestbak.sofar
rm -rf ~/Downloads/pkn.bestsofar2
rm -rf ~/Downloads/pkn_transfer
rm -rf ~/Documents/pkn
rm -rf ~/Pictures/pkn
rm -rf ~/Videos/pkn.thebestbak
rm -rf ~/pkn-android-app
rm -rf ~/pkn-standalone-apk
rm -rf ~/pkn-os
rm -rf ~/pkn_backups
rm -rf ~/dvn/dvn-debugger

# DELETE tarballs (except Jan 8 backup)
echo "Deleting old tarballs..."
rm -f ~/pkn_android_transfer.tar.gz
rm -f ~/pkn_android_transfer_v2.tar.gz
rm -f ~/pkn.zip
rm -f ~/Downloads/pkn-clean.tar.gz
rm -f ~/pkn_backup_20260105_190410.tar.gz
rm -f ~/pkn-good-build-latest.tar.gz
rm -f ~/Downloads/pkn*.tar.gz

# DELETE small files
echo "Deleting small files..."
rm -f ~/Downloads/pkn.code-workspace
rm -f ~/Downloads/pkn_control_patched.sh
rm -f ~/Downloads/pkn_app.tar.gz
rm -f ~/Downloads/pkn-android.tar.gz

# Fix shell alias
echo "Fixing shell alias..."
cp ~/.bashrc ~/.bashrc.backup-$(date +%Y%m%d)
sed -i "s|alias pkn=.*|alias pkn='cd ~/dvn/divine-workspace/apps/pkn \&\& bash'|g" ~/.bashrc

# Count after
AFTER=$(df -h ~ | tail -1 | awk '{print $3}')
echo ""
echo "✅ PURGE COMPLETE"
echo "Disk usage before: $BEFORE"
echo "Disk usage after:  $AFTER"
echo ""
echo "Remaining PKN files:"
find /home/gh0st -maxdepth 3 -type d -name "*pkn*" 2>/dev/null | grep -v ".claude" | grep -v "archive"
echo ""
echo "Kept: ~/dvn/divine-workspace/apps/pkn (active)"
echo "Kept: ~/pkn-backup-working-20260108_200610.tar.gz (Jan 8 backup)"
echo ""
echo "🔥 Everything else: DELETED"
```

---

## AFTER PURGE - VERIFY

```bash
# Should show ONLY these:
find ~ -maxdepth 3 -name "*pkn*" -type d 2>/dev/null | grep -v ".claude"

# Expected output:
# /home/gh0st/dvn/divine-workspace/apps/pkn (ACTIVE)
# /home/gh0st/archive/old_builds/pkn (copy) (old, tiny, ignore)

# Check backup
ls -lh ~/pkn-backup-working-20260108_200610.tar.gz

# Test PKN works
cd ~/dvn/divine-workspace/apps/pkn
./pkn_control.sh health
```

---

## WHY THIS IS SAFE

1. **Git history preserved** - All commits in `.git/`
2. **Recent backup kept** - Jan 8 tarball (if we break something)
3. **Active version untouched** - Monorepo still works
4. **Can restore if needed** - Untar the Jan 8 backup

---

## IF SOMETHING BREAKS

Worst case, restore from Jan 8 backup:
```bash
cd ~
tar -xzf pkn-backup-working-20260108_200610.tar.gz
# Figure out what we need from it
```

But realistically, we're deleting OLD copies. The active monorepo is untouched.

---

## AFTER 1 WEEK OF STABLE OPERATION

If everything works fine for a week, delete the last backup:
```bash
rm ~/pkn-backup-working-20260108_200610.tar.gz
```

Then you'll have ONLY the active monorepo. Zero duplicates. Zero archives.

---

**NO MORE ARCHIVING. JUST DELETE.**
