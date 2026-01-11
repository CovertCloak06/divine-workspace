#!/bin/bash
# Test all fixes made in this session

echo "============================================"
echo " PKN Fixes - Testing Summary"
echo "============================================"
echo ""

# Check server status
echo "1. Server Status:"
if curl -s http://localhost:8010/health > /dev/null; then
    echo "   ✓ Server is running on port 8010"
else
    echo "   ✗ Server is NOT running"
    echo "     Run: cd /home/gh0st/dvn/divine-workspace/apps/pkn && ./pkn_control.sh start-all"
fi
echo ""

# Check plugins
echo "2. Plugins System:"
PLUGIN_COUNT=$(ls -1d /home/gh0st/dvn/divine-workspace/apps/pkn/plugins/*/ 2>/dev/null | wc -l)
echo "   ✓ $PLUGIN_COUNT plugins installed"
echo ""

# List what to test in browser
echo "3. Browser Testing Checklist:"
echo "   □ Open http://localhost:8010 in Chrome"
echo "   □ Press F12 to open Developer Console"
echo "   □ Check for plugin initialization messages:"
echo "     - Look for: '[Plugins] Initialized 10 plugins'"
echo ""
echo "   □ Test Cyan Theme (default):"
echo "     - Click gear icon (⚙️)"
echo "     - Click 'Themes' tab"
echo "     - Select 'Cyan' theme"
echo "     - Should show cyan (#00ffff) colors"
echo ""
echo "   □ Test Plugins Panel:"
echo "     - Click '🧩 Plugins' in sidebar"
echo "     - Should show 10 plugins:"
echo "       1. Welcome Message"
echo "       2. Smart Context Detector"
echo "       3. Voice Input/Output"
echo "       4. Quick Actions & Macros"
echo "       5. Agent Memory Visualization"
echo "       6. Meeting Summarizer"
echo "       7. Code Diff Viewer"
echo "       8. Code Execution Sandbox"
echo "       9. Agent Collaboration Theater"
echo "      10. Dark Web OSINT"
echo ""
echo "   □ Test OSINT Tools:"
echo "     - Click '🔍 OSINT Tools' in sidebar"
echo "     - Scroll down to new section"
echo "     - Should see '🔍 Tracking & Privacy' category with:"
echo "       - Tracking Pixels button"
echo "       - Privacy Check button"
echo ""

echo "============================================"
echo " Quick Commands:"
echo "============================================"
echo "Start server: ./pkn_control.sh start-all"
echo "Stop server:  ./pkn_control.sh stop-all"
echo "Check plugins: python3 scripts/check_plugins.py"
echo "Open Chrome: google-chrome http://localhost:8010"
echo ""
