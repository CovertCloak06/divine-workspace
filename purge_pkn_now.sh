#!/bin/bash
# PKN Purge Script - DELETE everything old
# Run with: bash purge_pkn_now.sh

set -e

echo "🔥 PKN PURGE SCRIPT"
echo "=================="
echo ""
echo "This will DELETE (not archive) ~98GB of old PKN copies:"
echo "  - 9 duplicate PKN directories in Downloads"
echo "  - PKN in Documents, Pictures, Videos (WHY?!)"
echo "  - Old tarballs (48GB)"
echo "  - Old monorepo location (/home/gh0st/dvn/pkn)"
echo "  - Old debugger extension"
echo ""
echo "KEPT:"
echo "  ✅ /home/gh0st/dvn/divine-workspace/apps/pkn (ACTIVE)"
echo "  ✅ pkn-backup-working-20260108_200610.tar.gz (Jan 8 backup)"
echo ""
echo "⚠️  THIS CANNOT BE UNDONE (without restoring from backup)"
echo ""
read -p "Type 'DELETE' to continue: " confirm

if [ "$confirm" != "DELETE" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Starting purge..."
sleep 2

# Get disk usage before
BEFORE=$(df -h ~ | tail -1 | awk '{print $3}')

# DELETE directories
echo ""
echo "🗑️  Deleting duplicate directories..."
rm -rf ~/dvn/pkn && echo "  ✓ ~/dvn/pkn"
rm -rf ~/Downloads/pkn2 && echo "  ✓ ~/Downloads/pkn2"
rm -rf ~/Downloads/pkn.newest && echo "  ✓ ~/Downloads/pkn.newest"
rm -rf ~/Downloads/pkn.bestbak.sofar && echo "  ✓ ~/Downloads/pkn.bestbak.sofar"
rm -rf ~/Downloads/pkn.bestsofar2 && echo "  ✓ ~/Downloads/pkn.bestsofar2"
rm -rf ~/Downloads/pkn_transfer && echo "  ✓ ~/Downloads/pkn_transfer"
rm -rf ~/Documents/pkn && echo "  ✓ ~/Documents/pkn"
rm -rf ~/Pictures/pkn && echo "  ✓ ~/Pictures/pkn"
rm -rf ~/Videos/pkn.thebestbak && echo "  ✓ ~/Videos/pkn.thebestbak"
rm -rf ~/pkn-android-app && echo "  ✓ ~/pkn-android-app"
rm -rf ~/pkn-standalone-apk && echo "  ✓ ~/pkn-standalone-apk"
rm -rf ~/pkn-os && echo "  ✓ ~/pkn-os"
rm -rf ~/pkn_backups && echo "  ✓ ~/pkn_backups"
rm -rf ~/dvn/dvn-debugger && echo "  ✓ ~/dvn/dvn-debugger"

# DELETE tarballs (except Jan 8)
echo ""
echo "🗑️  Deleting old tarballs..."
rm -f ~/pkn_android_transfer.tar.gz && echo "  ✓ pkn_android_transfer.tar.gz (13GB)"
rm -f ~/pkn_android_transfer_v2.tar.gz && echo "  ✓ pkn_android_transfer_v2.tar.gz (13GB)"
rm -f ~/pkn.zip && echo "  ✓ pkn.zip (8.7GB)"
rm -f ~/Downloads/pkn-clean.tar.gz && echo "  ✓ pkn-clean.tar.gz"
rm -f ~/pkn_backup_20260105_190410.tar.gz && echo "  ✓ pkn_backup_20260105_190410.tar.gz"
rm -f ~/pkn-good-build-latest.tar.gz && echo "  ✓ pkn-good-build-latest.tar.gz"
rm -f ~/Downloads/pkn*.tar.gz 2>/dev/null && echo "  ✓ Other PKN tarballs in Downloads"

# DELETE small files
echo ""
echo "🗑️  Deleting small files..."
rm -f ~/Downloads/pkn.code-workspace 2>/dev/null && echo "  ✓ pkn.code-workspace"
rm -f ~/Downloads/pkn_control_patched.sh 2>/dev/null && echo "  ✓ pkn_control_patched.sh"
rm -f ~/Downloads/pkn_app.tar.gz 2>/dev/null && echo "  ✓ pkn_app.tar.gz"
rm -f ~/Downloads/pkn-android.tar.gz 2>/dev/null && echo "  ✓ pkn-android.tar.gz"

# Fix shell alias
echo ""
echo "🔧 Fixing shell alias in .bashrc..."
cp ~/.bashrc ~/.bashrc.backup-$(date +%Y%m%d)
sed -i "s|alias pkn=.*|alias pkn='cd ~/dvn/divine-workspace/apps/pkn \&\& bash'|g" ~/.bashrc
echo "  ✓ .bashrc updated (backup saved)"

# Get disk usage after
AFTER=$(df -h ~ | tail -1 | awk '{print $3}')

echo ""
echo "═══════════════════════════════════════"
echo "✅ PURGE COMPLETE"
echo "═══════════════════════════════════════"
echo ""
echo "Disk usage before: $BEFORE"
echo "Disk usage after:  $AFTER"
echo ""
echo "Remaining PKN directories:"
find /home/gh0st -maxdepth 3 -type d -name "*pkn*" 2>/dev/null | grep -v ".claude" | grep -v "archive" || echo "  (only showing active)"
echo ""
echo "✅ KEPT:"
echo "  - /home/gh0st/dvn/divine-workspace/apps/pkn (ACTIVE)"
echo "  - ~/pkn-backup-working-20260108_200610.tar.gz (Jan 8 backup)"
echo ""
echo "🔥 DELETED:"
echo "  - 98GB of duplicate PKN copies"
echo "  - Old tarballs"
echo "  - Wrong location copies"
echo "  - Old debugger extension"
echo ""
echo "Next steps:"
echo "  1. source ~/.bashrc  # Reload shell config"
echo "  2. cd ~/dvn/divine-workspace/apps/pkn"
echo "  3. ./pkn_control.sh health  # Verify PKN still works"
echo "  4. Load correct debugger extension in Chrome:"
echo "     /home/gh0st/dvn/divine-workspace/apps/debugger-extension"
echo ""
echo "After 1 week of stable operation, you can delete the last backup:"
echo "  rm ~/pkn-backup-working-20260108_200610.tar.gz"
echo ""
