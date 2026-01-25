#!/bin/bash
# Test suite for ncli command
# Ensures help is instant and auto-start works for commands

set -e

NCLI="/home/gh0st/dvn/divine-workspace/apps/nexus/ncli"
NEXUS_CONTROL="/home/gh0st/dvn/divine-workspace/apps/nexus/nexus_control.sh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Testing ncli functionality..."
echo ""

# Test 1: Help should be instant and not start Nexus
echo -n "Test 1: ncli help (no auto-start)... "
$NEXUS_CONTROL stop-all >/dev/null 2>&1
sleep 1

START_TIME=$(date +%s%N)
OUTPUT=$($NCLI 2>&1)
END_TIME=$(date +%s%N)
ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))  # Convert to milliseconds

# Check output contains usage
if echo "$OUTPUT" | grep -q "Usage: ncli"; then
    # Check it was fast (< 100ms)
    if [ $ELAPSED -lt 100 ]; then
        echo -e "${GREEN}✓${NC} Help shown in ${ELAPSED}ms"
    else
        echo -e "${YELLOW}⚠${NC} Help shown but took ${ELAPSED}ms (expected < 100ms)"
    fi
else
    echo -e "${RED}✗${NC} Help message not shown"
    exit 1
fi

# Verify Nexus did NOT start
if curl -s http://localhost:8010/health >/dev/null 2>&1; then
    echo -e "${RED}✗${NC} Test 1 FAILED: Nexus auto-started when showing help"
    exit 1
fi

# Test 2: Commands should auto-start Nexus
echo -n "Test 2: ncli command (with auto-start)... "
OUTPUT=$($NCLI "test message" 2>&1)

# Check if Nexus is now running
if curl -s http://localhost:8010/health >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Nexus auto-started successfully"
else
    echo -e "${RED}✗${NC} Auto-start failed"
    exit 1
fi

# Test 3: Subsequent commands should not show startup messages
echo -n "Test 3: ncli with Nexus running... "
OUTPUT=$($NCLI "another test" 2>&1)

if echo "$OUTPUT" | grep -q "starting it now"; then
    echo -e "${RED}✗${NC} Showed startup message when Nexus already running"
    exit 1
else
    echo -e "${GREEN}✓${NC} No unnecessary startup messages"
fi

echo ""
echo -e "${GREEN}All tests passed!${NC}"

# Cleanup
$NEXUS_CONTROL stop-all >/dev/null 2>&1
