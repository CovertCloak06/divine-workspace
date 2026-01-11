# ⚡ Quick Test - Streaming Implementation

**Time needed:** 5 minutes
**Goal:** Verify streaming responses work correctly

---

## 🚀 Quick Start (Copy & Paste)

### Step 1: Start Services (30 seconds)

```bash
cd ~/pkn
./pkn_control.sh start-all
```

Wait ~10 seconds for services to initialize.

### Step 2: Run Automated Tests (1 minute)

```bash
cd ~/pkn
./test_streaming.sh
```

**Expected output:**
```
✓ All critical tests passed!
```

If you see this, **streaming is working!** 🎉

### Step 3: Test in Browser (2 minutes)

```bash
# Open browser (or type in address bar):
firefox http://localhost:8010/pkn.html

# Or on the same machine:
google-chrome http://localhost:8010/pkn.html
```

**In the chat:**
1. Type: `Write a Python hello world program`
2. Press Enter
3. **Watch carefully:**
   - Words should appear **one by one** (not all at once)
   - You should see a **pulsing cyan dot** (●) while streaming
   - Text should **auto-scroll** smoothly

**✅ If you see words appearing gradually = SUCCESS!**

---

## 🐛 If Tests Fail

### Services won't start?

```bash
# Check what's using the ports
lsof -i :8010  # DivineNode
lsof -i :8000  # llama.cpp

# Kill and restart
./pkn_control.sh stop-all
sleep 5
./pkn_control.sh start-all
```

### Check logs:

```bash
tail -20 ~/pkn/divinenode.log
```

### Still not working?

See `TEST_STREAMING.md` for detailed debugging steps.

---

## ✅ Success Checklist

Streaming is working if you see:

- [ ] Services start successfully
- [ ] Automated tests pass
- [ ] Browser shows Divine Node UI
- [ ] Message sends successfully
- [ ] **Words appear one-by-one (not all at once)**
- [ ] Pulsing indicator visible during response
- [ ] Response completes with metadata (time, tools)

---

## 📸 What Streaming Looks Like

**Before (non-streaming):**
```
User: Write a Python hello world
[waiting... 8 seconds... waiting...]
AI: [COMPLETE RESPONSE APPEARS AT ONCE]
```

**After (streaming):**
```
User: Write a Python hello world
AI: Here's█           [0.5s]
AI: Here's a█         [1.0s]
AI: Here's a simple█  [1.5s]
AI: Here's a simple Python█  [2.0s]
... continues smoothly ...
```

The `█` cursor blinks, text flows naturally!

---

## 🎬 Video Evidence

Record a screen capture:
1. Send message
2. Watch words appear one-by-one
3. Share if you want feedback!

---

**Ready?** Run Step 1 above! ⬆️
