# Phone Storage Cleanup Plan

**Date**: 2026-01-11
**Device**: R5CXC3K0MJR (connected via ADB)
**Storage**: 126GB used / 221GB total (57% full, 95GB available)

---

## 📊 PHONE STORAGE ANALYSIS

### Current Usage
```
Total:     221GB
Used:      126GB (57%)
Available:  95GB
```

### Large Items Found

| Location | Size | Status | Action |
|----------|------|--------|--------|
| `/sdcard/pkn_android_transfer.tar.gz` | 13GB | ❌ OLD (Dec 30) | **DELETE** |
| `/sdcard/pkn-mobile-deploy.tar.gz` | 11MB | ✅ RECENT (Jan 11) | **KEEP** |
| `/sdcard/Download/AI_MODELS_BACKUP/` | 12GB | ✅ AI models | **KEEP** |
| `/sdcard/Download/` (total) | 20GB | Mixed | **CLEAN** |
| `/sdcard/DCIM/` | 1.9GB | Photos | **KEEP** |

---

## 🗑️ TO DELETE (13GB)

### 1. Old PKN Tarball (13GB)
```bash
adb shell "rm /sdcard/pkn_android_transfer.tar.gz"
```

**Why delete**:
- OLD backup from Dec 30 (2 weeks old)
- Duplicate of tarball on PC (already being deleted)
- New deployment tarball exists (11MB, Jan 11)

### 2. Download Folder Cleanup (estimate 3-5GB saved)

**Large files in Download**:
- Raspberry Pi image (1.1GB) - likely old
- AndroidIDE backup (92MB) - old install backup
- Various Magisk modules - check if still needed

**Safe to delete** (probably):
```bash
# Raspberry Pi image (already flashed?)
adb shell "rm /sdcard/Download/2025-10-01-raspios-bookworm-armhf.img.xz"

# AndroidIDE backup (41MB + 92MB)
adb shell "rm /sdcard/Download/AndroidIDE-dev.zip"
adb shell "rm -rf /sdcard/Download/AndroidIDE-dev"
```

---

## ✅ TO KEEP

### AI Models (12GB)
```
/sdcard/Download/AI_MODELS_BACKUP/
├── Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf (8.3GB)
└── mistral-7b-instruct-v0.2.Q4_K_M.gguf (4GB)
```

**Why keep**: These are LLM models for local AI. Useful and expensive to re-download.

### Recent Mobile Deploy (11MB)
```
/sdcard/pkn-mobile-deploy.tar.gz
```

**Why keep**: Latest mobile PKN deployment (Jan 11)

### Photos (1.9GB)
```
/sdcard/DCIM/
```

**Why keep**: Your photos

---

## 📱 INSTALLED APPS

### Found
- ✅ Scripture Alarm (`com.covertcloak.scripturealarm`) - INSTALLED

### Not Found
- ❓ Ghost Keys / Unexpected Keyboard - Not installed
- ❓ PKN Android app - Not installed

---

## 🔧 PHONE PURGE SCRIPT

```bash
#!/bin/bash
# Phone Storage Cleanup Script

set -e

echo "📱 PHONE STORAGE CLEANUP"
echo "======================="
echo ""
echo "Device: $(adb devices | grep -v "List" | awk '{print $1}')"
echo ""
echo "This will DELETE:"
echo "  - /sdcard/pkn_android_transfer.tar.gz (13GB)"
echo "  - /sdcard/Download/2025-10-01-raspios-bookworm-armhf.img.xz (1.1GB)"
echo "  - /sdcard/Download/AndroidIDE-dev* (133MB)"
echo ""
echo "KEPT:"
echo "  ✅ AI_MODELS_BACKUP (12GB)"
echo "  ✅ pkn-mobile-deploy.tar.gz (11MB)"
echo "  ✅ DCIM photos (1.9GB)"
echo ""
read -p "Type 'DELETE' to continue: " confirm

if [ "$confirm" != "DELETE" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Getting storage before..."
BEFORE=$(adb shell "df -h /sdcard" | tail -1 | awk '{print $3}')
echo "Used before: $BEFORE"

echo ""
echo "🗑️  Deleting old PKN tarball (13GB)..."
adb shell "rm /sdcard/pkn_android_transfer.tar.gz" && echo "  ✓ Deleted"

echo ""
echo "🗑️  Deleting Raspberry Pi image (1.1GB)..."
adb shell "rm /sdcard/Download/2025-10-01-raspios-bookworm-armhf.img.xz" 2>/dev/null && echo "  ✓ Deleted" || echo "  ⚠ Already deleted or not found"

echo ""
echo "🗑️  Deleting AndroidIDE backups (133MB)..."
adb shell "rm /sdcard/Download/AndroidIDE-dev.zip" 2>/dev/null && echo "  ✓ AndroidIDE-dev.zip deleted"
adb shell "rm -rf /sdcard/Download/AndroidIDE-dev" 2>/dev/null && echo "  ✓ AndroidIDE-dev folder deleted"

echo ""
echo "Getting storage after..."
AFTER=$(adb shell "df -h /sdcard" | tail -1 | awk '{print $3}')
echo "Used after: $AFTER"

echo ""
echo "✅ PHONE CLEANUP COMPLETE"
echo ""
echo "Space freed: ~14GB"
echo ""
echo "Remaining large items:"
adb shell "du -sh /sdcard/Download/AI_MODELS_BACKUP /sdcard/DCIM /sdcard/pkn-mobile-deploy.tar.gz" 2>/dev/null
echo ""
