# Transfer PKN to Android - Simple Guide

## Package Ready! 📦

**Location**: `/home/gh0st/pkn_android_transfer.tar.gz`
**Size**: 6.1GB (includes everything except build artifacts)

## Step-by-Step Transfer

### Method 1: USB Cable (Fastest)

1. **Connect phone to PC via USB**

2. **Copy file to phone**
   ```bash
   # On PC - Copy to phone's Download folder
   cp /home/gh0st/pkn_android_transfer.tar.gz /run/user/1000/gvfs/mtp*/*/Download/
   # OR manually drag file to phone's Download folder in file manager
   ```

3. **On phone - Open Termux and extract**
   ```bash
   # Install Termux from F-Droid (not Google Play)
   # Open Termux, then:

   cd /sdcard/Download

   # Move to better location
   mv pkn_android_transfer.tar.gz /sdcard/
   cd /sdcard

   # Extract (will take 2-3 minutes)
   tar -xzf pkn_android_transfer.tar.gz

   cd pkn
   ```

### Method 2: Cloud Transfer

1. **Upload to cloud** (Google Drive, Dropbox, etc.)
   - Upload `pkn_android_transfer.tar.gz` from PC

2. **Download on phone**
   - Download to `/sdcard/Download`
   - Follow Step 3 from Method 1

### Method 3: Local Network (No Internet Needed)

1. **On PC - Start simple HTTP server**
   ```bash
   cd /home/gh0st
   python3 -m http.server 8888
   ```

2. **Find PC's IP address**
   ```bash
   ip addr show | grep "inet " | grep -v 127.0.0.1
   # Example output: 192.168.1.100
   ```

3. **On phone - Download via browser**
   - Open browser on phone
   - Go to: `http://192.168.1.100:8888/pkn_android_transfer.tar.gz`
   - Download will start
   - Follow extraction steps from Method 1

## After Extraction - Setup on Android

```bash
# In Termux, inside /sdcard/pkn directory:

# 1. Install Python packages
pkg install python python-pip
python -m venv .venv
source .venv/bin/activate

# 2. Install dependencies (takes 5-10 minutes)
pip install -r requirements.txt

# 3. Give Termux storage permission (if asked)
termux-setup-storage

# 4. Test installation
python3 -c "from agent_manager import agent_manager; print('✅ Ready!')"

# 5. Start the server
./pkn_control.sh start-all

# Or use the menu:
./termux_menu.sh
```

## First Run on Android

1. **Start services**
   ```bash
   ./termux_menu.sh
   # Select: 1) Start All Services
   ```

2. **Open in browser**
   - Open Chrome/Firefox on phone
   - Go to: `http://127.0.0.1:8010/pkn.html`

3. **Test it**
   - Type "hello" in chat
   - Should get response from General Assistant

## Troubleshooting

### "tar: permission denied"
```bash
pkg install tar gzip
```

### "pip: command not found"
```bash
pkg install python python-pip
```

### "Server won't start"
```bash
# Check if ports are free
./pkn_control.sh status

# Stop any running services
./pkn_control.sh stop-all

# Start fresh
./pkn_control.sh start-all
```

### "Model not loading"
```bash
# Check model file exists
ls -lh llama.cpp/models/*.gguf

# Should see: Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf
```

## Optional: Skip ChromaDB (Saves Space & Time)

RAG features won't work, but everything else will:
```bash
# DON'T install these on phone (optional anyway):
# pip install chromadb sentence-transformers

# All other features work without them!
```

## What's Included

✅ All Python code and tools
✅ Advanced agent features (delegation, planning, etc.)
✅ Qwen 14B model (8.4GB)
✅ Web UI (HTML/CSS/JS)
✅ All API endpoints
✅ Control scripts (pkn_control.sh, termux_menu.sh)
✅ Documentation and guides

❌ Build artifacts (will rebuild on phone if needed)
❌ ChromaDB database (will create fresh if you install it)
❌ .venv (will create fresh on phone)

## Storage Required on Phone

- **Minimum**: 7GB free space
- **Recommended**: 10GB free space
- **Location**: /sdcard (external storage)

## Battery Tips

```bash
# Prevent Termux from sleeping
termux-wake-lock

# When done, release wake lock
termux-wake-unlock
```

## Quick Test Commands

```bash
# Test server is running
curl http://127.0.0.1:8010/health

# Test agent
curl -X POST http://127.0.0.1:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"test","mode":"auto"}'

# Test metrics
curl http://127.0.0.1:8010/api/metrics/report
```

## Next Steps After Transfer

1. ✅ Extract package
2. ✅ Install dependencies
3. ✅ Start services
4. ✅ Test in browser
5. ⚠️ Optional: Download smaller 7B model if 14B is too slow

## Need Help?

Check these files on phone after extraction:
- `ANDROID_COMPATIBILITY.md` - Full compatibility guide
- `SESSION_2024-12-30.md` - What was implemented today
- `ADVANCED_FEATURES_GUIDE.md` - How to use new features
- `CLAUDE.md` - General architecture and commands

---

**Ready to transfer!** Use Method 1 (USB) for fastest transfer. 🚀
