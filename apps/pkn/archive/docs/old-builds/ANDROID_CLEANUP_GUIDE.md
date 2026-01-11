# Android PKN Cleanup Guide

## Safe Cleanup Steps - On Your Phone

### Step 1: Find Old Installations

Open Termux and run:

```bash
# Find all PKN-related directories
echo "=== Searching for old PKN installations ==="
find /sdcard -maxdepth 2 -type d -name "*pkn*" 2>/dev/null
find /sdcard -maxdepth 2 -type d -name "*parakleon*" 2>/dev/null
find /sdcard -maxdepth 2 -type d -name "*divine*" 2>/dev/null
find $HOME -maxdepth 2 -type d -name "*pkn*" 2>/dev/null

echo ""
echo "=== Searching for old transfer files ==="
find /sdcard -name "*.tar.gz" 2>/dev/null | grep -i pkn
```

### Step 2: Stop Any Running Services

```bash
# Stop all old PKN services
pkill -f divinenode_server.py
pkill -f llama-server
pkill -f "llama.cpp.server"
pkill -f parakleon

# Check nothing is running
ps aux | grep -E "divine|pkn|parakleon|llama" | grep -v grep
```

### Step 3: Remove Old Directories

**IMPORTANT**: Only delete OLD versions, keep the NEW one you just extracted!

```bash
# List what you're about to delete (DO THIS FIRST!)
ls -ld /sdcard/pkn_old* 2>/dev/null
ls -ld /sdcard/parakleon* 2>/dev/null
ls -ld $HOME/pkn_old* 2>/dev/null

# If those look right, delete them:
# rm -rf /sdcard/pkn_old
# rm -rf /sdcard/parakleon
# rm -rf $HOME/pkn_backup

# Keep these:
# ✅ /sdcard/pkn (NEW - just extracted)
# ✅ /sdcard/pkn_android_transfer.tar.gz (backup)
```

### Step 4: Clean Old Config Files

```bash
# Check for old startup scripts
ls -la ~/.bashrc
ls -la ~/.bash_profile

# Remove old PKN references from startup
# Edit manually if needed:
# nano ~/.bashrc
# (Delete lines referencing old PKN paths)
```

### Step 5: Add New Startup Script

```bash
# Add the NEW menu to your startup
echo '' >> ~/.bashrc
echo '# PKN Startup Menu (Updated 2024-12-30)' >> ~/.bashrc
echo 'if [ -f /sdcard/pkn/termux_menu_android.sh ]; then' >> ~/.bashrc
echo '    source /sdcard/pkn/termux_menu_android.sh' >> ~/.bashrc
echo 'fi' >> ~/.bashrc
```

### Step 6: Test New Installation

```bash
# Go to new PKN directory
cd /sdcard/pkn

# Verify it's the new version
ls -la | grep "2024"  # Should see recent dates

# Check files are there
ls -la *.sh
ls -la tools/*.py

# Test menu
source termux_menu_android.sh
```

## What to Keep vs Delete

### ✅ KEEP (New Installation)
- `/sdcard/pkn/` - Fresh extraction from today
- `/sdcard/pkn_android_transfer.tar.gz` - Backup copy

### ❌ DELETE (Old Versions)
- `/sdcard/pkn_old/` - Any old backups
- `/sdcard/parakleon/` - Old project name
- `/sdcard/divinenode_old/` - Old installations
- `$HOME/pkn/` - Old Termux home installations
- Any old `.tar.gz` files

## Safe Deletion Command Template

**Before running, verify each path exists and is OLD:**

```bash
# Template - REPLACE <path> with actual old paths
# rm -rf <old_path_here>

# Example:
# rm -rf /sdcard/pkn_december_20
# rm -rf /sdcard/parakleon_backup
```

## After Cleanup Checklist

- [ ] Old directories deleted
- [ ] Old services stopped
- [ ] New menu added to ~/.bashrc
- [ ] Can open new Termux session and see updated menu
- [ ] Fresh extraction at `/sdcard/pkn` is working

## Verify Everything Works

```bash
# Close and reopen Termux
# Should see updated menu automatically

# Or manually test:
cd /sdcard/pkn
source termux_menu_android.sh

# Select option 4 to see status
# Should show all new features available
```

## If Something Goes Wrong

**You still have the backup!**

```bash
# Re-extract if needed
cd /sdcard
tar -xzf pkn_android_transfer.tar.gz
cd pkn
```

## Common Issues

### "Can't find pkn directory"
```bash
# Check extraction completed
ls -lh /sdcard/pkn

# If not there, extract again
cd /sdcard
tar -xzf pkn_android_transfer.tar.gz
```

### "Old menu still shows up"
```bash
# Edit .bashrc and remove old references
nano ~/.bashrc

# Find lines with old PKN paths and delete them
# Save: Ctrl+X, Y, Enter

# Reload
source ~/.bashrc
```

### "Permission denied"
```bash
# Make scripts executable
cd /sdcard/pkn
chmod +x *.sh
chmod +x pkn_control.sh termux_menu_android.sh
```

---

**Ready to clean up?** Run Step 1 first to see what old installations exist, then we'll decide what to delete safely.
