#!/bin/bash
# Deploy PKN Mobile to Android phone via ADB
# Usage: ./deploy-to-phone.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Paths
SOURCE_DIR="$(dirname "$0")/.."
STAGING_DIR="/storage/emulated/0/pkn-deploy"
TERMUX_DIR="~/pkn"

echo -e "${CYAN}=== PKN Mobile Deployment ===${NC}"
echo ""

# Check if ADB is available
if ! command -v adb &> /dev/null; then
    echo -e "${RED}Error: ADB not found. Install with: sudo apt install adb${NC}"
    exit 1
fi

# Check for connected device
DEVICE=$(adb devices | grep -v "List" | grep "device" | head -1)
if [ -z "$DEVICE" ]; then
    echo -e "${RED}Error: No device connected. Connect via USB and enable USB debugging.${NC}"
    exit 1
fi

echo -e "${GREEN}Device found: ${DEVICE%$'\t'*}${NC}"
echo ""

# Create staging directory on phone
echo "Creating staging directory..."
adb shell "mkdir -p $STAGING_DIR"

# Push files
echo "Pushing files to phone..."

# Core files
echo "  - pkn.html"
adb push "$SOURCE_DIR/pkn.html" "$STAGING_DIR/pkn.html"

echo "  - service-worker.js"
adb push "$SOURCE_DIR/service-worker.js" "$STAGING_DIR/service-worker.js"

echo "  - manifest.json"
adb push "$SOURCE_DIR/manifest.json" "$STAGING_DIR/manifest.json"

echo "  - config.js"
adb push "$SOURCE_DIR/config.js" "$STAGING_DIR/config.js"

echo "  - tools.js"
adb push "$SOURCE_DIR/tools.js" "$STAGING_DIR/tools.js"

# Directories
echo "  - js/ directory"
adb push "$SOURCE_DIR/js" "$STAGING_DIR/"

echo "  - css/ directory"
adb push "$SOURCE_DIR/css" "$STAGING_DIR/"

echo "  - img/ directory (if exists)"
if [ -d "$SOURCE_DIR/img" ]; then
    adb push "$SOURCE_DIR/img" "$STAGING_DIR/"
fi

echo ""
echo -e "${GREEN}Files pushed to: $STAGING_DIR${NC}"
echo ""
echo -e "${CYAN}=== NEXT STEPS ===${NC}"
echo ""
echo "1. Open Termux on your phone"
echo ""
echo "2. Run this command to copy files:"
echo -e "   ${GREEN}cp -r /storage/emulated/0/pkn-deploy/* ~/pkn/${NC}"
echo ""
echo "3. Restart PKN server:"
echo -e "   ${GREEN}pkn-stop && pkn${NC}"
echo ""
echo "4. Clear browser cache and reload PKN"
echo "   Or add ?v=$(date +%s) to the URL"
echo ""
echo -e "${CYAN}Done!${NC}"
