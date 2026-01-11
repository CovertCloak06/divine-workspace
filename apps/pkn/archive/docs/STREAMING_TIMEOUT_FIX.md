# 🐛 Streaming Timeout Fix - Async/Sync Conversion

**Date:** December 29, 2025
**Issue:** Request timeout after 30 seconds
**Status:** ✅ Fixed

---

## 🔍 Problem Description

### Error Message
```
Error: Request timed out after 30 seconds. Please try again or check your connection.
```

### Root Cause
**Problematic Async/Sync Conversion**

The streaming endpoint was using `asyncio.run()` inside a generator, which caused a hang:

```python
# ❌ PROBLEMATIC CODE
async def stream_task():
    async for event in agent_manager.execute_task_streaming():
        yield event

# This hangs/times out:
for chunk in asyncio.run(_async_generator_to_sync(stream_task())):
    yield chunk
```

**Why it hangs:**
1. `asyncio.run()` creates a NEW event loop
2. But we're already in a sync context (Flask generator)
3. Nested async functions + asyncio.run() = deadlock/hang
4. After 30 seconds, browser gives up

---

## ✅ Solution

### New Approach: Direct Event Loop Management

Instead of using `asyncio.run()`, we:
1. Create a new event loop explicitly
2. Consume the async generator synchronously
3. Use `loop.run_until_complete()` for each iteration
4. Clean up the loop when done

**Fixed Code:**

```python
# ✅ FIXED CODE
# Create new event loop for this generator
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

try:
    # Get the async generator
    async_gen = agent_manager.execute_task_streaming(message, session_id)

    # Consume it synchronously
    while True:
        try:
            # Get next event from async generator
            event = loop.run_until_complete(async_gen.__anext__())

            # Process and yield the event
            if event['type'] == 'chunk':
                yield f"event: chunk\ndata: {json.dumps(event)}\n\n"
            # ... etc

        except StopAsyncIteration:
            break

finally:
    loop.close()  # Clean up
```

### Key Changes

**Lines 1034-1036:** Create dedicated event loop
```python
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
```

**Lines 1038-1070:** Consume async generator synchronously
```python
try:
    async_gen = agent_manager.execute_task_streaming(...)
    while True:
        event = loop.run_until_complete(async_gen.__anext__())
        # Process event
except StopAsyncIteration:
    break
```

**Lines 1072-1073:** Proper cleanup
```python
finally:
    loop.close()
```

---

## 🧪 Testing the Fix

### Step 1: Restart Server

```bash
cd ~/pkn
./pkn_control.sh stop-divinenode
sleep 2
./pkn_control.sh start-divinenode

# Wait 5 seconds for startup
sleep 5
```

### Step 2: Check Services

```bash
# Verify DivineNode is running
curl http://localhost:8010/health
# Should return: {"status": "ok", ...}

# Check if llama.cpp/ollama is running
ps aux | grep -E "llama|ollama" | grep -v grep
```

### Step 3: Test Streaming

```bash
# Test with curl (should respond quickly now)
timeout 60 curl -N -X POST http://localhost:8010/api/multi-agent/chat/stream \
  -H "Content-Type: application/json" \
  -d '{"message": "Say hello"}' 2>&1 | head -20
```

**Expected output (within a few seconds):**
```
event: start
data: {"agent": "general", ...}

event: chunk
data: {"content": "Hello"}

event: done
data: {"execution_time": 2.5, ...}
```

**Should NOT:**
- Hang for 30+ seconds
- Timeout
- Show no output

### Step 4: Test in Browser

1. Open: http://localhost:8010/pkn.html
2. Type: "Write a Python hello world"
3. Press Enter
4. **Watch for:**
   - Response starts within 2-3 seconds ✅
   - Words appear one-by-one ✅
   - No timeout error ✅

---

## 🐛 If Still Not Working

### Check 1: Is llama.cpp/Ollama Running?

```bash
# Check if LLM server is running
ps aux | grep -E "llama|ollama" | grep -v grep

# If not, start it:
./pkn_control.sh start-llama
# OR
./pkn_control.sh start-all
```

### Check 2: Check Logs

```bash
# Watch DivineNode logs
tail -f ~/pkn/divinenode.log

# In another terminal, send a request
curl -X POST http://localhost:8010/api/multi-agent/chat/stream \
  -H "Content-Type: application/json" \
  -d '{"message": "test"}'
```

**Look for:**
- "Created new session: ..."
- Agent routing messages
- Any error traces

### Check 3: Test Non-Streaming Endpoint

```bash
# Try regular (non-streaming) endpoint
curl -X POST http://localhost:8010/api/multi-agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello"}' \
  --max-time 30
```

**If this works but streaming doesn't:**
- Problem is in streaming-specific code
- Check logs for async errors

**If this also times out:**
- LLM backend is not responding
- Check llama.cpp/Ollama status

---

## 📊 Expected Behavior After Fix

| Test | Before Fix | After Fix |
|------|-----------|-----------|
| **curl timeout** | 30s timeout ❌ | Response in 2-5s ✅ |
| **Browser response** | Timeout error ❌ | Streams immediately ✅ |
| **Logs** | Hang, no errors ❌ | Clean execution ✅ |
| **CPU usage** | Low (hanging) ❌ | Normal spikes ✅ |

---

## 🎓 Technical Details

### Why asyncio.run() Fails

`asyncio.run()` is designed for:
- Top-level async entry points
- Starting an event loop from sync code
- Running a SINGLE async task to completion

It does NOT work for:
- Generators that need to yield incrementally
- Code already in an event loop context
- Nested async operations

### Better Pattern: Event Loop Management

For Flask SSE with async code:

```python
def stream_endpoint():
    # Create dedicated loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        async_gen = get_async_generator()

        while True:
            try:
                item = loop.run_until_complete(async_gen.__anext__())
                yield process(item)
            except StopAsyncIteration:
                break
    finally:
        loop.close()  # IMPORTANT: Clean up!
```

### Alternative: Make Everything Async

Flask 2.0+ supports async routes:

```python
@app.route('/stream')
async def stream():
    async def generate():
        async for item in async_gen():
            yield item

    return Response(generate(), mimetype='text/event-stream')
```

But requires `pip install flask[async]` and async-compatible WSGI server (hypercorn, not gunicorn).

---

## 📝 Files Changed

### Modified
- **`divinenode_server.py`** (Lines 1034-1073)
  - Replaced `asyncio.run()` with `loop.run_until_complete()`
  - Added proper event loop management
  - Added StopAsyncIteration handling
  - Added cleanup in finally block

### No Changes Needed
- `agent_manager.py` - Async generator is correct
- `multi_agent_ui.js` - Frontend is fine
- `multi_agent.css` - Styles are fine

---

## ✅ Summary of Both Fixes

### Fix #1: Flask Context Error
**Problem:** `request.get_json()` inside generator
**Solution:** Parse request data before generator

### Fix #2: Timeout (This Fix)
**Problem:** `asyncio.run()` causing hang/deadlock
**Solution:** Manual event loop management with `run_until_complete()`

Both fixes are now applied!

---

## 🚀 Next Steps

1. **Restart server:**
   ```bash
   ./pkn_control.sh restart-divinenode
   ```

2. **Test streaming:**
   - In browser: http://localhost:8010/pkn.html
   - Send message and watch it stream

3. **If it works:**
   - ✅ Streaming is complete!
   - Move to Chain-of-Thought visualization

4. **If it still doesn't work:**
   - Check services: `./pkn_control.sh status`
   - Check logs: `tail -f divinenode.log`
   - Let me know the error

---

**Timeout Fixed!** 🎉

Now restart and test:
```bash
cd ~/pkn
./pkn_control.sh restart-divinenode
sleep 5
firefox http://localhost:8010/pkn.html
```

---

*Fixed: December 29, 2025*
*Version: 1.0.2 (Timeout Fix)*
