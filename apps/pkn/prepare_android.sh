#!/bin/bash
# Prepare PKN for Android/Termux Transfer
# Creates optimized package for mobile deployment

PKN_DIR="/home/gh0st/pkn"
PACKAGE_DIR="/tmp/pkn_android_package"
DATE=$(date +%Y%m%d_%H%M%S)

echo "========================================"
echo "PKN Android Package Preparation"
echo "========================================"
echo ""

# Create package directory
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

echo "📦 Creating package structure..."

# Essential directories
mkdir -p "$PACKAGE_DIR"/{css,js,img,tools,memory,uploads,llama.cpp/models}

# Core Python files
echo "  → Copying core Python files..."
cp "$PKN_DIR/divinenode_server.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/agent_manager.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/conversation_memory.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/code_context.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/local_parakleon_agent.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/local_image_gen.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/device_config.py" "$PACKAGE_DIR/"
cp "$PKN_DIR/pkn_cli.py" "$PACKAGE_DIR/" 2>/dev/null || true

# Tools directory
echo "  → Copying tools..."
cp "$PKN_DIR/tools/"*.py "$PACKAGE_DIR/tools/" 2>/dev/null || true

# Web files
echo "  → Copying web files..."
cp "$PKN_DIR/pkn.html" "$PACKAGE_DIR/"
cp "$PKN_DIR/app.js" "$PACKAGE_DIR/"
cp "$PKN_DIR/manifest.webmanifest" "$PACKAGE_DIR/" 2>/dev/null || true

# CSS files
echo "  → Copying CSS..."
cp "$PKN_DIR/css/"*.css "$PACKAGE_DIR/css/"

# JavaScript modules
echo "  → Copying JavaScript modules..."
cp "$PKN_DIR/js/"*.js "$PACKAGE_DIR/js/" 2>/dev/null || true

# Images (compress for mobile)
echo "  → Copying images..."
cp "$PKN_DIR/img/"* "$PACKAGE_DIR/img/" 2>/dev/null || true

# Configuration files
echo "  → Copying configuration..."
cp "$PKN_DIR/requirements.txt" "$PACKAGE_DIR/"
cp "$PKN_DIR/.env.example" "$PACKAGE_DIR/.env" 2>/dev/null || echo "OLLAMA_BASE=http://127.0.0.1:11434" > "$PACKAGE_DIR/.env"

# Documentation
echo "  → Copying documentation..."
cp "$PKN_DIR/README.md" "$PACKAGE_DIR/" 2>/dev/null || true
cp "$PKN_DIR/OSINT_README.md" "$PACKAGE_DIR/" 2>/dev/null || true
cp "$PKN_DIR/PKN_CLI_README.md" "$PACKAGE_DIR/" 2>/dev/null || true
cp "$PKN_DIR/ANDROID_VS_PC_MODELS.md" "$PACKAGE_DIR/" 2>/dev/null || true
cp "$PKN_DIR/COMPLETE_SYSTEM_STATUS.md" "$PACKAGE_DIR/" 2>/dev/null || true

# Copy Android model
echo "  → Copying Android model (Mistral 7B - 4.1GB)..."
echo "    This may take a minute..."
if [ -f "$PKN_DIR/llama.cpp/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf" ]; then
    cp "$PKN_DIR/llama.cpp/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf" "$PACKAGE_DIR/llama.cpp/models/"
    echo "    ✓ Model copied (4.1GB)"
else
    echo "    ⚠ Model not found - will need to download on Android"
fi

# Copy Android config
echo "  → Creating Android config..."
cp "$PKN_DIR/config_android.json" "$PACKAGE_DIR/" 2>/dev/null || python3 "$PKN_DIR/device_config.py" >/dev/null 2>&1 && cp "$PKN_DIR/config_android.json" "$PACKAGE_DIR/"

# Create Android-specific startup script
echo "  → Creating termux_start.sh..."
cat > "$PACKAGE_DIR/termux_start.sh" << 'TERMUX_EOF'
#!/data/data/com.termux/files/usr/bin/bash
# PKN Termux Startup Script
# Optimized for Android/Termux environment

PKN_DIR="$HOME/pkn"
cd "$PKN_DIR"

echo "========================================"
echo "PKN - Starting on Termux"
echo "========================================"

# Check Python
if ! command -v python &> /dev/null; then
    echo "Installing Python..."
    pkg install python -y
fi

# Install dependencies
echo "Installing Python packages..."
pip install -q flask flask-cors python-dotenv phonenumbers requests python-whois dnspython beautifulsoup4 langchain langchain-core 2>/dev/null || true

# Start server
echo "Starting PKN server on port 8010..."
echo "Access at: http://localhost:8010/pkn.html"
echo ""

python divinenode_server.py --host 0.0.0.0 --port 8010
TERMUX_EOF

chmod +x "$PACKAGE_DIR/termux_start.sh"

# Create installation instructions
echo "  → Creating INSTALL_ANDROID.md..."
cat > "$PACKAGE_DIR/INSTALL_ANDROID.md" << 'EOF'
# PKN Installation for Android (Termux)

## Prerequisites

1. Install **Termux** from F-Droid (recommended) or Play Store
2. Install **Termux:API** (optional, for extra features)

## Installation Steps

### Step 1: Setup Termux

```bash
# Update packages
pkg update && pkg upgrade

# Install required packages
pkg install python git termux-services

# Grant storage permission
termux-setup-storage
```

### Step 2: Transfer PKN Files

**Option A: Via ADB (from PC)**
```bash
# On PC:
adb push pkn_android_package /sdcard/Download/pkn

# In Termux:
cp -r /sdcard/Download/pkn ~/pkn
cd ~/pkn
```

**Option B: Download and Extract**
```bash
cd ~
# Extract transferred zip file here
unzip /sdcard/Download/pkn.zip
cd pkn
```

### Step 3: Start PKN

```bash
cd ~/pkn
bash termux_start.sh
```

### Step 4: Access PKN

Open browser and navigate to:
```
http://localhost:8010/pkn.html
```

## Termux-Specific Notes

### Performance Optimization
- Recommended: Use lightweight models (7B or smaller)
- Disable llama.cpp if device has <6GB RAM
- Use external LLM APIs (Claude, GPT) for better performance

### Storage Management
```bash
# PKN stores data in:
~/pkn/uploads/       # Uploaded files
~/pkn/memory/        # Conversation memory
```

### Auto-Start on Boot (Optional)

Create service:
```bash
mkdir -p ~/.config/termux/boot
cat > ~/.config/termux/boot/start-pkn << 'BOOT_EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/pkn
bash termux_start.sh > pkn.log 2>&1 &
BOOT_EOF
chmod +x ~/.config/termux/boot/start-pkn
```

### Troubleshooting

**Port already in use:**
```bash
# Kill existing process
pkill -f divinenode_server
# Restart
bash termux_start.sh
```

**Permission errors:**
```bash
# Fix permissions
chmod -R 755 ~/pkn
```

**Module not found:**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

## Mobile-Specific Features

✅ Responsive UI optimized for touch
✅ Reduced resource usage
✅ Works offline (when using local models)
✅ Swipe gestures supported
✅ PWA installable

## Differences from PC Version

- No llama.cpp integration by default (use external APIs)
- Simplified file operations
- Optimized for battery life
- Reduced concurrent connections

## Quick Commands

```bash
# Start PKN
cd ~/pkn && bash termux_start.sh

# Stop PKN
pkill -f divinenode_server

# View logs
tail -f ~/pkn/divinenode.log

# Update PKN
cd ~/pkn && git pull
```

## Support

For issues, check:
- https://termux.dev/en/
- https://wiki.termux.com/
EOF

# Create transfer instructions for PC
cat > "$PACKAGE_DIR/TRANSFER_VIA_ADB.txt" << 'EOF'
PKN Android Transfer Instructions (ADB)
========================================

Prerequisites:
- Android device with USB debugging enabled
- ADB installed on PC (platform-tools)
- USB cable

Steps:

1. Connect device via USB

2. Verify connection:
   adb devices

3. Push PKN to device:
   cd /tmp
   adb push pkn_android_package /sdcard/Download/pkn

4. In Termux on phone:
   pkg install python git
   cp -r /sdcard/Download/pkn ~/pkn
   cd ~/pkn
   bash termux_start.sh

5. Access in browser:
   http://localhost:8010/pkn.html

Alternative: Package as ZIP
===========================

zip -r pkn_android.zip pkn_android_package/
adb push pkn_android.zip /sdcard/Download/

In Termux:
unzip /sdcard/Download/pkn_android.zip
mv pkn_android_package ~/pkn
cd ~/pkn
bash termux_start.sh
EOF

# Calculate package size
PACKAGE_SIZE=$(du -sh "$PACKAGE_DIR" | cut -f1)

echo ""
echo "✅ Package prepared successfully!"
echo ""
echo "Package location: $PACKAGE_DIR"
echo "Package size: $PACKAGE_SIZE"
echo ""
echo "Files included:"
find "$PACKAGE_DIR" -type f | wc -l | xargs echo "  Total files:"
echo ""
echo "Next steps:"
echo "  1. Review: ls -lah $PACKAGE_DIR"
echo "  2. Transfer: adb push $PACKAGE_DIR /sdcard/Download/pkn"
echo "  3. Or create ZIP: cd /tmp && zip -r pkn_android.zip pkn_android_package/"
echo ""
echo "See: $PACKAGE_DIR/INSTALL_ANDROID.md for installation instructions"
echo "See: $PACKAGE_DIR/TRANSFER_VIA_ADB.txt for transfer instructions"
echo ""
