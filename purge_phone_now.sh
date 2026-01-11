#!/bin/bash
# Phone Storage Purge Script
# Run with: bash purge_phone_now.sh

set -e

echo "📱 PHONE STORAGE PURGE SCRIPT"
echo "=============================="
echo ""

# Check if device connected
DEVICE=$(adb devices | grep -v "List" | grep "device$" | awk '{print $1}')
if [ -z "$DEVICE" ]; then
    echo "❌ No Android device connected via ADB"
    echo "Connect phone and enable USB debugging"
    exit 1
fi

echo "Device: $DEVICE"
echo ""
echo "This will DELETE from phone:"
echo "  - pkn_android_transfer.tar.gz (13GB) ❌ OLD"
echo "  - Raspberry Pi image (1.1GB) ❌ OLD"
echo "  - AndroidIDE backups (133MB) ❌ OLD"
echo ""
echo "KEPT on phone:"
echo "  ✅ AI_MODELS_BACKUP (12GB) - AI models"
echo "  ✅ pkn-mobile-deploy.tar.gz (11MB) - Current deploy"
echo "  ✅ DCIM (1.9GB) - Your photos"
echo ""
echo "Space to free: ~14GB"
echo ""
read -p "Type 'DELETE' to continue: " confirm

if [ "$confirm" != "DELETE" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Starting phone purge..."
sleep 2

# Get storage before
echo ""
echo "📊 Storage before:"
adb shell "df -h /sdcard" | tail -1

# Delete old PKN tarball (13GB)
echo ""
echo "🗑️  Deleting pkn_android_transfer.tar.gz (13GB)..."
if adb shell "test -f /sdcard/pkn_android_transfer.tar.gz" 2>/dev/null; then
    adb shell "rm /sdcard/pkn_android_transfer.tar.gz" && echo "  ✓ Deleted 13GB"
else
    echo "  ⚠ Already deleted"
fi

# Delete Raspberry Pi image (1.1GB)
echo ""
echo "🗑️  Deleting Raspberry Pi image (1.1GB)..."
if adb shell "test -f /sdcard/Download/2025-10-01-raspios-bookworm-armhf.img.xz" 2>/dev/null; then
    adb shell "rm /sdcard/Download/2025-10-01-raspios-bookworm-armhf.img.xz" && echo "  ✓ Deleted 1.1GB"
else
    echo "  ⚠ Already deleted"
fi

# Delete AndroidIDE backups (133MB)
echo ""
echo "🗑️  Deleting AndroidIDE backups (133MB)..."
if adb shell "test -f /sdcard/Download/AndroidIDE-dev.zip" 2>/dev/null; then
    adb shell "rm /sdcard/Download/AndroidIDE-dev.zip" && echo "  ✓ AndroidIDE-dev.zip deleted"
else
    echo "  ⚠ AndroidIDE-dev.zip already deleted"
fi

if adb shell "test -d /sdcard/Download/AndroidIDE-dev" 2>/dev/null; then
    adb shell "rm -rf /sdcard/Download/AndroidIDE-dev" && echo "  ✓ AndroidIDE-dev folder deleted"
else
    echo "  ⚠ AndroidIDE-dev folder already deleted"
fi

# Get storage after
echo ""
echo "📊 Storage after:"
adb shell "df -h /sdcard" | tail -1

echo ""
echo "═══════════════════════════════════════"
echo "✅ PHONE PURGE COMPLETE"
echo "═══════════════════════════════════════"
echo ""
echo "Space freed: ~14GB"
echo ""
echo "✅ KEPT on phone:"
echo ""
adb shell "du -sh /sdcard/Download/AI_MODELS_BACKUP /sdcard/DCIM /sdcard/pkn-mobile-deploy.tar.gz 2>/dev/null" | \
while read size path; do
    echo "  - $path ($size)"
done
echo ""
echo "📱 Phone storage is now clean!"
echo ""
