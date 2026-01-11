#!/bin/bash
# Generate PWA icons from existing logo or create placeholder icons
# Usage: ./generate-pwa-icons.sh

set -e

IMG_DIR="./img"
SOURCE_LOGO="$IMG_DIR/logo.png"
ICON_192="$IMG_DIR/icon-192.png"
ICON_512="$IMG_DIR/icon-512.png"

echo "🎨 Generating PWA icons for Divine Node..."

# Check if ImageMagick is installed
if command -v convert &> /dev/null; then
    echo "✓ ImageMagick found"

    if [ -f "$SOURCE_LOGO" ]; then
        echo "✓ Using existing logo.png as source"

        # Generate 192x192 icon
        echo "  Creating icon-192.png..."
        convert "$SOURCE_LOGO" -resize 192x192 -background none -gravity center -extent 192x192 "$ICON_192"

        # Generate 512x512 icon
        echo "  Creating icon-512.png..."
        convert "$SOURCE_LOGO" -resize 512x512 -background none -gravity center -extent 512x512 "$ICON_512"

        echo "✓ Icons created from logo.png"
    else
        echo "⚠️  logo.png not found, creating placeholder icons..."

        # Create placeholder 192x192
        convert -size 192x192 xc:'#0a0a0a' \
                -fill '#00ffff' -font Arial-Bold -pointsize 36 \
                -gravity center -annotate +0+0 'Divine\nNode' \
                "$ICON_192"

        # Create placeholder 512x512
        convert -size 512x512 xc:'#0a0a0a' \
                -fill '#00ffff' -font Arial-Bold -pointsize 96 \
                -gravity center -annotate +0+0 'Divine\nNode' \
                "$ICON_512"

        echo "✓ Placeholder icons created"
    fi

    echo ""
    echo "✅ PWA icons generated successfully!"
    echo "   - $ICON_192"
    echo "   - $ICON_512"

else
    echo "❌ ImageMagick not found. Installing..."

    # Try to install ImageMagick based on OS
    if command -v apt-get &> /dev/null; then
        echo "  Using apt-get..."
        sudo apt-get update && sudo apt-get install -y imagemagick
    elif command -v pkg &> /dev/null; then
        echo "  Using pkg (Termux)..."
        pkg install -y imagemagick
    elif command -v brew &> /dev/null; then
        echo "  Using brew (macOS)..."
        brew install imagemagick
    else
        echo "❌ Cannot install ImageMagick automatically."
        echo ""
        echo "📝 Manual Steps:"
        echo "  1. Install ImageMagick: sudo apt-get install imagemagick"
        echo "  2. Run this script again: ./generate-pwa-icons.sh"
        echo ""
        echo "  OR manually create these files:"
        echo "  - $ICON_192 (192x192 pixels)"
        echo "  - $ICON_512 (512x512 pixels)"
        exit 1
    fi

    # Retry after installation
    echo ""
    echo "✓ ImageMagick installed. Retrying icon generation..."
    exec "$0"
fi

echo ""
echo "🎉 PWA setup complete!"
echo ""
echo "📱 Next steps:"
echo "  1. Start your server: ./pkn_control.sh start-all"
echo "  2. Open in browser: http://localhost:8010/pkn.html"
echo "  3. Look for 'Install App' button (bottom-right)"
echo "  4. Click to install as PWA!"
echo ""
echo "📖 For detailed instructions, see PWA_GUIDE.md"
