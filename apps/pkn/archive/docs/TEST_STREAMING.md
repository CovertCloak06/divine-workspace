# 🧪 Streaming Implementation - Testing Guide

**Date:** December 29, 2025
**Status:** Ready for Testing

---

## ✅ Pre-Test Checklist

### 1. Syntax Validation
- ✅ **agent_manager.py** - Python syntax valid
- ✅ **divinenode_server.py** - Python syntax valid
- ✅ **multi_agent_ui.js** - JavaScript syntax valid
- ✅ **multi_agent.css** - CSS added successfully

### 2. Code Review
All streaming code has been added:
- Backend: `/api/multi-agent/chat/stream` endpoint
- Agent Manager: `execute_task_streaming()` method
- Frontend: SSE parsing and UI updates
- CSS: Pulsing indicators and animations

---

## 🚀 Testing Steps

### Step 1: Start Services

```bash
cd ~/pkn

# Option A: Start all services
./pkn_control.sh start-all

# Option B: Start individually
./pkn_control.sh start-divinenode
./pkn_control.sh start-llama

# Check status
./pkn_control.sh status
```

**Expected output:**
```
✓ DivineNode running (port 8010)
✓ llama.cpp running (port 8000)
```

### Step 2: Verify Services

```bash
# Test DivineNode is responding
curl http://localhost:8010/health

# Test llama.cpp is responding
curl http://localhost:8000/v1/models

# Test multi-agent endpoint (non-streaming)
curl -X POST http://localhost:8010/api/multi-agent/agents
```

**Expected:**
- Health check returns `{"status": "ok"}`
- Models endpoint returns list
- Agents endpoint returns 5-6 agents

### Step 3: Test Streaming Endpoint (CLI)

```bash
# Simple streaming test
curl -N -X POST http://localhost:8010/api/multi-agent/chat/stream \
  -H "Content-Type: application/json" \
  -d '{"message": "Say hello and count to 5"}'
```

**Expected output:**
```
event: start
data: {"agent": "general", "agent_name": "General Agent", "session_id": "abc123..."}

event: chunk
data: {"content": "Hello!"}

event: chunk
data: {"content": " 1,"}

event: chunk
data: {"content": " 2,"}

...

event: done
data: {"execution_time": 2.34, "tools_used": []}
```

### Step 4: Test in Browser

1. **Open Divine Node:**
   ```
   http://localhost:8010/pkn.html
   ```

2. **Open Browser Console** (F12)
   - Should see: `[MultiAgent] Initialized successfully`
   - Should see: `[QualityMonitor] Initialized`

3. **Send a test message:**
   ```
   Type: "Hello, how are you?"
   Press Enter
   ```

4. **Observe streaming behavior:**
   - ✅ User message appears immediately
   - ✅ Pulsing dot (●) appears next to agent name
   - ✅ Response text appears word-by-word
   - ✅ Blinking cursor (▊) at end of text
   - ✅ Auto-scrolls smoothly
   - ✅ Indicator disappears when done
   - ✅ Metadata (time, tools) added at end

### Step 5: Test Different Agents

**General Agent (fast):**
```
Message: "What is 2+2?"
Expected: ~2-3 second response, streams smoothly
```

**Coder Agent (slower):**
```
Message: "Write a Python function to calculate factorial"
Expected: ~8-15 second response, visible streaming
```

**Reasoner Agent:**
```
Message: "Plan how to build a REST API"
Expected: ~10-20 second response, streaming visible
```

### Step 6: Test Error Handling

**Invalid message:**
```bash
curl -N -X POST http://localhost:8010/api/multi-agent/chat/stream \
  -H "Content-Type: application/json" \
  -d '{"message": ""}'
```

**Expected:**
```
event: error
data: {"content": "No message provided"}
```

**Network interruption:**
- Send a long message
- Interrupt network (Ctrl+C on server)
- Should show error message with retry button

---

## 🔍 Debugging Guide

### Issue: Services won't start

**Check:**
```bash
# Check if ports are already in use
lsof -i :8010  # DivineNode
lsof -i :8000  # llama.cpp

# Check logs
tail -f ~/pkn/divinenode.log
tail -f ~/pkn/llama.log
```

**Fix:**
```bash
# Kill existing processes
./pkn_control.sh stop-all
# Wait 5 seconds
sleep 5
# Start again
./pkn_control.sh start-all
```

### Issue: Streaming endpoint returns 404

**Check:**
```bash
# Verify endpoint exists in server
grep -n "chat/stream" ~/pkn/divinenode_server.py
```

**Should show:**
```
979:@app.route('/api/multi-agent/chat/stream', methods=['POST'])
```

**Fix:**
```bash
# Restart DivineNode
./pkn_control.sh stop-divinenode
sleep 2
./pkn_control.sh start-divinenode
```

### Issue: No streaming, everything appears at once

**Check browser console:**
```javascript
// Should see:
[MultiAgent] Initialized successfully
[MultiAgent] Streaming error: ...
```

**Possible causes:**
1. Browser doesn't support `ReadableStream`
2. CORS issue (check network tab)
3. JavaScript error (check console)

**Fix:**
```bash
# Hard refresh browser
Ctrl + Shift + R

# Clear cache
# Browser → Settings → Clear browsing data
```

### Issue: Python errors in console

**Check:**
```bash
# Verify imports work
cd ~/pkn
source .venv/bin/activate
python3 -c "from agent_manager import agent_manager; print('OK')"
python3 -c "from conversation_memory import conversation_memory; print('OK')"
```

**If import fails:**
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: Streaming works but text is garbled

**Check CSS:**
```bash
# Verify streaming CSS exists
tail -30 ~/pkn/css/multi_agent.css | grep streaming-indicator
```

**Fix:**
```bash
# Hard refresh to reload CSS
Ctrl + Shift + F5
```

---

## 📊 Test Results Template

### Test Environment
```
OS: _________________
Browser: _________________
Python Version: _________________
Services Running: [ ] DivineNode [ ] llama.cpp
```

### Functionality Tests

| Test | Status | Notes |
|------|--------|-------|
| Services start successfully | [ ] Pass [ ] Fail | |
| Health check responds | [ ] Pass [ ] Fail | |
| Streaming endpoint accessible | [ ] Pass [ ] Fail | |
| First token appears < 2s | [ ] Pass [ ] Fail | |
| Text streams word-by-word | [ ] Pass [ ] Fail | |
| Pulsing indicator visible | [ ] Pass [ ] Fail | |
| Blinking cursor visible | [ ] Pass [ ] Fail | |
| Auto-scroll works | [ ] Pass [ ] Fail | |
| Metadata added at end | [ ] Pass [ ] Fail | |
| Error handling works | [ ] Pass [ ] Fail | |
| Session preserved | [ ] Pass [ ] Fail | |
| Mobile responsive | [ ] Pass [ ] Fail | |

### Performance Tests

| Metric | Expected | Actual | Status |
|--------|----------|--------|--------|
| Time to first token | < 2s | ___s | [ ] Pass [ ] Fail |
| Total response time | 8-15s | ___s | [ ] Pass [ ] Fail |
| UI responsiveness | Smooth | ___ | [ ] Pass [ ] Fail |
| Memory usage | < 500MB | ___MB | [ ] Pass [ ] Fail |

### Visual Tests

| Element | Expected | Actual | Status |
|---------|----------|--------|--------|
| Streaming indicator | Pulsing cyan dot | ___ | [ ] Pass [ ] Fail |
| Cursor | Blinking ▊ | ___ | [ ] Pass [ ] Fail |
| Text animation | Smooth appearance | ___ | [ ] Pass [ ] Fail |
| Auto-scroll | Follows text | ___ | [ ] Pass [ ] Fail |

---

## 🐛 Known Issues

### Issue #1: SSE not supported in old browsers
**Affected:** IE11, older Safari
**Workaround:** Automatically falls back to non-streaming
**Fix:** Detection added in code

### Issue #2: Large responses may lag UI
**Affected:** Responses > 2000 tokens
**Symptom:** UI updates slow down
**Workaround:** Batch updates (future enhancement)

### Issue #3: Network interruption loses partial response
**Affected:** All platforms
**Symptom:** Error shown, partial text lost
**Workaround:** Show error with retry button
**Fix:** Add partial response saving (future)

---

## ✅ Success Criteria

Streaming is working correctly if:

1. ✅ First token appears in < 2 seconds
2. ✅ Text appears word-by-word, not all at once
3. ✅ Pulsing indicator is visible during streaming
4. ✅ Blinking cursor appears at end of text
5. ✅ Auto-scroll keeps text visible
6. ✅ Metadata (time, tools, badges) appears at end
7. ✅ No JavaScript errors in console
8. ✅ Works on both desktop and mobile
9. ✅ Error handling shows retry button
10. ✅ Session is preserved across messages

---

## 🎬 Video Test Scenario

**Complete user flow:**

1. Open http://localhost:8010/pkn.html
2. Type: "Write a Python function to calculate the nth Fibonacci number"
3. Press Enter
4. **Observe:**
   - User message appears instantly
   - Thinking indicator starts pulsing
   - Agent name appears ("Qwen Coder")
   - First words appear within 1-2 seconds
   - Text streams in smoothly, word by word
   - Cursor blinks at the end
   - Messages auto-scroll
   - After ~10-15 seconds, streaming completes
   - Metadata appears (execution time, performance badge)
   - Thinking indicator stops
5. Type another message to verify session continues
6. **Success!** Streaming is working perfectly

---

## 📞 Support

If tests fail:

1. **Check logs:**
   ```bash
   tail -f ~/pkn/divinenode.log
   ```

2. **Check browser console:** (F12)
   - Look for error messages
   - Check network tab for failed requests

3. **Restart services:**
   ```bash
   ./pkn_control.sh stop-all
   sleep 5
   ./pkn_control.sh start-all
   ```

4. **Verify Python environment:**
   ```bash
   source ~/pkn/.venv/bin/activate
   python3 -c "import flask; print('Flask OK')"
   ```

---

## 🎉 Next Steps After Testing

Once streaming tests pass:

1. **Mark streaming as complete** ✅
2. **Move to Chain-of-Thought visualization**
3. **Document any bugs found**
4. **Create performance baseline**

---

**Happy Testing!** 🧪✨

*Test Guide Version: 1.0*
*Created: December 29, 2025*
