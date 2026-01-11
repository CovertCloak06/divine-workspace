# 📱 PKN on Android - Termux Setup Guide

**Device:** Samsung Galaxy S25 Ultra
**OS:** Android (Termux)
**Screen:** 412×915 portrait, 915×412 landscape
**Date:** December 29, 2025

---

## 🎯 What This Guide Does

This guide will help you run **PKN (Parakleon Divine Node)** natively on your Samsung Galaxy S25 Ultra using Termux. You'll have a fully functional AI assistant running locally on your phone.

---

## 📋 Prerequisites

### 1. Install Termux
- Download from **F-Droid** (recommended): https://f-droid.org/packages/com.termux/
- **DO NOT** use Google Play version (outdated and broken)

### 2. Install Termux:API (Optional but Recommended)
- Allows access to phone features (notifications, camera, etc.)
- Download from F-Droid: https://f-droid.org/packages/com.termux.api/

---

## 🚀 Quick Start (Copy & Paste)

Open Termux and run these commands:

### Step 1: Update Termux Packages

```bash
pkg update && pkg upgrade -y
```

### Step 2: Install Required Packages

```bash
# Install Python, Git, and essentials
pkg install python git wget curl -y

# Install build tools (needed for some Python packages)
pkg install clang make binutils -y
```

### Step 3: Setup Storage Access

```bash
# Allow Termux to access phone storage
termux-setup-storage

# Grant permission when prompted
```

This creates `~/storage/` with access to:
- `~/storage/downloads/` → Your phone's Downloads folder
- `~/storage/dcim/` → Camera photos
- `~/storage/shared/` → Internal storage root

---

## 📦 Transfer PKN to Your Phone

Choose one of these methods:

### Method A: Direct Transfer via USB/Cloud (Easiest)

1. **On Pop OS:**
   ```bash
   cd ~/pkn
   tar -czf pkn-mobile.tar.gz \
       --exclude='.venv' \
       --exclude='llama.cpp' \
       --exclude='__pycache__' \
       --exclude='*.pyc' \
       --exclude='.git' \
       .
   ```

2. **Transfer to phone via:**
   - USB cable → Copy to `Downloads/`
   - Google Drive, Dropbox, etc.
   - KDE Connect
   - Email to yourself

3. **In Termux:**
   ```bash
   cd ~
   mkdir pkn
   cd pkn
   tar -xzf ~/storage/downloads/pkn-mobile.tar.gz
   ```

### Method B: Git Clone (If you have a repo)

```bash
cd ~
git clone <your-repo-url> pkn
cd pkn
```

### Method C: Download Individual Files

If you just want to test with essential files:

```bash
cd ~
mkdir -p pkn
cd pkn

# Download core files
# (List specific curl commands here if needed)
```

---

## 🐍 Python Environment Setup

```bash
cd ~/pkn

# Install Python dependencies
pip install --upgrade pip
pip install flask flask-cors requests anthropic openai

# If requirements.txt exists:
pip install -r requirements.txt
```

---

## 🤖 LLM Backend Options

PKN needs an LLM backend. Choose one:

### Option 1: Use Remote API (Easiest on Phone)

**Anthropic Claude API:**
```bash
# Edit config
nano config.local.js

# Set:
# ACTIVE_PROVIDER = 'anthropic'
# ACTIVE_API_KEY = 'your-api-key-here'
```

**OpenAI API:**
```bash
# Similar process, but:
# ACTIVE_PROVIDER = 'openai'
```

### Option 2: Connect to Pop OS Server

If your phone and Pop OS are on same WiFi:

```bash
# Find your Pop OS IP (run on Pop OS):
# ip addr show | grep "inet "

# On phone, edit config:
nano ~/pkn/config.local.js

# Set backend URL to:
# "http://192.168.1.XXX:8000"  # Replace XXX with Pop OS IP
```

### Option 3: Run llama.cpp on Phone (Advanced)

**Warning:** The S25 Ultra is powerful, but large models will drain battery and heat up the device.

**For small models only (1B-3B parameters):**

```bash
# Install llama.cpp (ARM64 build)
cd ~
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp

# Build for Android
make

# Download a small model (e.g., Phi-2, TinyLlama)
mkdir models
cd models
wget <model-url>  # Download a GGUF model (~2GB)

# Run server
cd ~/llama.cpp
./server -m models/your-model.gguf -c 2048 --port 8000
```

**Keep in background with tmux:**
```bash
pkg install tmux
tmux
# Run server command
# Press Ctrl+B, then D to detach
```

---

## 🚀 Start PKN Server

### Without llama.cpp (using API):

```bash
cd ~/pkn
python divinenode_server.py
```

### With llama.cpp in background:

Terminal 1 (llama.cpp):
```bash
tmux new -s llama
cd ~/llama.cpp
./server -m models/your-model.gguf --port 8000
# Ctrl+B, D to detach
```

Terminal 2 (DivineNode):
```bash
tmux new -s divine
cd ~/pkn
python divinenode_server.py
# Ctrl+B, D to detach
```

**Check running sessions:**
```bash
tmux ls
```

**Reattach to session:**
```bash
tmux attach -t llama
# or
tmux attach -t divine
```

---

## 🌐 Access PKN on Your Phone

### Open Browser

1. **On your S25 Ultra:**
   - Open Chrome, Firefox, or Samsung Internet
   - Navigate to: `http://localhost:8010/pkn.html`

2. **You should see:**
   - Divine Node interface
   - Sidebar with Projects, Chats, etc.
   - Chat input at bottom

### Test It!

Type: **"Hello, can you help me?"**

If it responds, you're all set! 🎉

---

## 📱 Mobile-Specific Features

### Touch Optimizations (Already Added)

✅ All buttons are touch-friendly (44×44px minimum)
✅ Chat history dropdown now appears above sidebar
✅ Files panel properly layered
✅ Smooth touch scrolling
✅ No accidental text selection on double-tap

### Mobile Tips

**Portrait Mode (412×915):**
- Swipe from left edge to open sidebar
- Tap outside sidebar to close it
- Chat history menus centered on narrow screens

**Landscape Mode (915×412):**
- Compact header saves vertical space
- Same functionality as portrait

---

## 🔧 Useful Termux Commands

### Keep Screen On While Working
```bash
termux-wake-lock
# Prevent sleep

termux-wake-unlock
# Allow sleep again
```

### Check Running Processes
```bash
ps aux | grep python
ps aux | grep server
```

### Kill a Stuck Server
```bash
pkill -f divinenode_server
pkill -f llama.cpp
```

### View Logs
```bash
tail -f ~/pkn/divinenode.log
```

### Monitor Resource Usage
```bash
pkg install htop
htop
```

---

## ⚙️ Configuration Files

### Termux-Specific Config (Optional)

Create `~/pkn/config.termux.js`:

```javascript
// Termux-specific settings
const CONFIG = {
    BACKEND_URL: 'http://localhost:8000',
    PROVIDER: 'llamacpp',  // or 'anthropic', 'openai'
    API_KEY: 'your-api-key',

    // Optimize for mobile
    MAX_TOKENS: 512,  // Smaller responses for mobile
    TEMPERATURE: 0.7,

    // Disable heavy features on mobile
    ENABLE_IMAGE_GEN: false,  // Save resources
    ENABLE_FILE_UPLOADS: true,
};
```

### Detect Environment Automatically

The app can detect if it's running on Termux:

```javascript
// In config.local.js
const isMobile = /Android|iPhone|iPad/i.test(navigator.userAgent);
const isTermux = typeof Android !== 'undefined';

if (isMobile || isTermux) {
    // Use mobile-optimized settings
    CONFIG.MAX_TOKENS = 512;
}
```

---

## 📂 File Paths Reference

| Location | Termux Path | Pop OS Equivalent |
|----------|-------------|-------------------|
| PKN Home | `~/pkn/` | `/home/gh0st/pkn/` |
| Uploads | `~/pkn/uploads/` | `/home/gh0st/pkn/uploads/` |
| Logs | `~/pkn/divinenode.log` | `/home/gh0st/pkn/divinenode.log` |
| Phone Storage | `~/storage/shared/` | N/A (Android only) |
| Downloads | `~/storage/downloads/` | N/A |

---

## 🐛 Troubleshooting

### Server Won't Start

**Check if port is in use:**
```bash
netstat -tulpn | grep 8010
```

**Kill process using port:**
```bash
fuser -k 8010/tcp
```

### Python Package Errors

```bash
pip install --upgrade setuptools wheel
pip install --no-cache-dir -r requirements.txt
```

### Permission Denied Errors

```bash
chmod +x pkn_control.sh
chmod +x test_streaming.sh
```

### Out of Memory

If llama.cpp crashes:
- Use smaller model (< 2GB)
- Reduce context size: `-c 1024`
- Close other apps

### Browser Can't Connect

**Check if server is running:**
```bash
curl http://localhost:8010/health
```

**Check firewall:**
```bash
# Termux doesn't usually have firewall issues
# But check if process is listening:
ss -tulpn | grep 8010
```

---

## 🔋 Battery & Performance Tips

### Extend Battery Life

1. **Use API instead of local llama.cpp**
   - Offload compute to cloud
   - Phone only runs lightweight Flask server

2. **Run in background efficiently:**
   ```bash
   # Use tmux instead of keeping Termux open
   tmux new -s pkn
   python divinenode_server.py
   # Ctrl+B, D to detach
   # Close Termux app
   ```

3. **Enable battery saver mode:**
   - Termux will still run in background
   - May slow response times slightly

### Optimize Performance

1. **Close unused apps**
2. **Keep phone cool** (don't run llama.cpp for extended periods)
3. **Use WiFi, not mobile data** (faster, less battery drain)

---

## 📊 Expected Performance on S25 Ultra

| Task | Expected Time | Notes |
|------|---------------|-------|
| **Start server** | 3-5 seconds | Flask startup |
| **Simple query (API)** | 1-3 seconds | Network dependent |
| **Code generation (API)** | 5-15 seconds | Depends on API |
| **llama.cpp (2B model)** | 10-30 seconds | Phone will warm up |
| **llama.cpp (7B model)** | 30-120 seconds | **Not recommended** - battery drain |

---

## 🎉 You're All Set!

PKN is now running on your S25 Ultra!

### Next Steps:

1. **Test all sidebar features** (Files, Images, AI Models, Settings)
2. **Try chat history dropdown** - should work perfectly now at 412px width
3. **Test streaming responses** - words should appear one-by-one
4. **Create a project** - test full workflow

### If Everything Works:

- You have a fully functional AI assistant on your phone! 📱
- It works offline (if using llama.cpp locally)
- Responsive design optimized for your S25 Ultra

### If Issues Arise:

- Check Termux logs: `~/pkn/divinenode.log`
- Check browser console (Chrome DevTools)
- Verify server is running: `curl localhost:8010/health`

---

## 📞 Quick Reference

**Start Everything:**
```bash
cd ~/pkn
python divinenode_server.py
```

**Stop Everything:**
```bash
pkill -f divinenode_server
pkill -f llama
```

**View Logs:**
```bash
tail -20 ~/pkn/divinenode.log
```

**Access UI:**
- Browser → `http://localhost:8010/pkn.html`

---

**Optimized for Samsung Galaxy S25 Ultra** 🚀
**Portrait: 412×915 | Landscape: 915×412**

*Setup Guide v1.0 - December 29, 2025*
