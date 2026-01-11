#!/bin/bash
# Test the fixed uncensored image generator

echo "=================================================="
echo "PKN Image Generator Test"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Step 1: Checking server status...${NC}"
if curl -s http://localhost:8010/health | grep -q "ok"; then
    echo -e "${GREEN}✓ Server is running${NC}"
else
    echo -e "${RED}✗ Server not responding. Run: ./pkn_control.sh start-divinenode${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}Step 2: Testing image generation API...${NC}"
echo -e "${YELLOW}Generating test image: 'a red apple on a table'${NC}"
echo -e "${YELLOW}⏱  This will take 30-60 seconds on CPU...${NC}"
echo ""

# Make API call and save response
RESPONSE=$(curl -s -X POST http://localhost:8010/api/generate-image \
  -H "Content-Type: application/json" \
  -d '{"prompt": "a red apple on a table"}' \
  --max-time 120)

# Check if we got an error
if echo "$RESPONSE" | grep -q '"error"'; then
    echo -e "${RED}✗ Generation failed!${NC}"
    echo "Error: $(echo "$RESPONSE" | grep -o '"error":"[^"]*"')"
    echo ""
    echo "This is likely because:"
    echo "1. First run needs to download model (~4GB)"
    echo "2. CPU generation takes time"
    echo ""
    echo "Check logs: tail -f divinenode.log"
    exit 1
fi

# Check if we got image data
if echo "$RESPONSE" | grep -q '"image"'; then
    echo -e "${GREEN}✓ Image generated successfully!${NC}"
    echo ""

    # Save to HTML file for viewing
    echo "$RESPONSE" | python3 -c "
import sys, json, time
data = json.load(sys.stdin)
img_data = data.get('image', '')
if img_data:
    html = f'''<!DOCTYPE html>
<html>
<head><title>PKN Test Image</title></head>
<body style=\"margin:0;padding:20px;background:#000;color:#0ff;font-family:monospace;\">
<h2>✓ PKN Image Generator - WORKING!</h2>
<p>Generated: a red apple on a table</p>
<p>Status: Uncensored ✓ | Local ✓ | Private ✓</p>
<img src=\"{img_data}\" style=\"max-width:512px;border:2px solid #0ff;margin:20px 0;\">
<p style=\"color:#666;font-size:11px;\">Time: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
</body>
</html>'''
    with open('/tmp/pkn_test_image.html', 'w') as f:
        f.write(html)
    print('saved')
" 2>/dev/null

    if [ -f /tmp/pkn_test_image.html ]; then
        echo -e "${GREEN}✓ Test image saved to: /tmp/pkn_test_image.html${NC}"
        echo ""
        echo -e "${CYAN}Opening in browser...${NC}"
        xdg-open /tmp/pkn_test_image.html 2>/dev/null || echo "  Manually open: file:///tmp/pkn_test_image.html"
    fi
else
    echo -e "${RED}✗ No image data in response${NC}"
    echo "Response: $RESPONSE"
    exit 1
fi

echo ""
echo -e "${GREEN}=================================================="
echo "✓ ALL TESTS PASSED!"
echo "==================================================${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo "1. Open PKN in browser: http://localhost:8010/pkn.html"
echo "2. Click the image generation button (📷 icon)"
echo "3. Enter your prompt"
echo "4. Wait 30-60s for generation"
echo ""
echo -e "${YELLOW}⚠️  UNCENSORED MODE ACTIVE${NC}"
echo "   Safety filters: DISABLED"
echo "   Content policy: NONE"
echo "   100% private local generation"
echo ""
echo "See UNCENSORED_IMAGE_MODELS.md for model upgrades"
