# PKN Mobile Troubleshooting

Solutions for common mobile/Termux issues.

**Back to:** [Main Troubleshooting](../../../docs/TROUBLESHOOTING.md) | [Mobile Deployment](./DEPLOYMENT_MOBILE.md)

**Related:**
- [Mobile CLAUDE.md](../CLAUDE.md) - Configuration reference
- [Agents Reference](../../../docs/AGENTS.md) - Agent/model issues

---

## Quick Diagnostics

```bash
# Check server
curl http://localhost:8010/health

# Check Ollama
curl http://localhost:11434/api/tags

# Check processes
pgrep -f server.py
pgrep -f ollama
```

---

## Server Issues

### Server Won't Start
**Symptom:** `python server.py` exits immediately

**Solutions:**
1. Check port: `lsof -i :8010`
2. Kill existing: `pkill -f server.py`
3. Check logs: `python server.py 2>&1 | head -50`

### Port Already in Use
```bash
lsof -i :8010
kill -9 <PID>
# Or change port in server.py
```

### "localhost refused to connect"
```bash
# Ensure server is running
pgrep -f server.py || (cd ~/pkn && python backend/server.py &)
```

---

## Ollama Issues

### Ollama Not Running
```bash
# Start Ollama
ollama serve &

# Verify
curl http://localhost:11434/api/tags
```

### Model Not Found
```bash
# List installed
ollama list

# Pull missing model
ollama pull qwen2.5-coder:7b
```

### Out of Memory
**Symptom:** Ollama crashes during inference

**Solutions:**
1. Use smaller models (7B instead of 14B)
2. Close other apps
3. Enable swap: `termux-setup-storage`

### Slow Response Times
- Normal: 7-15 seconds for 7B models
- If slower: Close background apps, check battery mode

---

## UI/PWA Issues

### Black Screen on Load
1. Clear browser cache
2. Add `?v=timestamp` to URL
3. Check service worker version

### UI Looks Broken
```bash
# Force cache clear
# Chrome: Settings → Privacy → Clear browsing data → Cached images
# Then reload with: http://localhost:8010/?v=$(date +%s)
```

### Send Button Not Working
- Check console for JavaScript errors
- Verify server is responding: `curl http://localhost:8010/health`

---

## Agent Issues

### Agent Not Responding
1. Check Ollama is running
2. Verify model is pulled
3. Check agent config in `backend/config/model_config.py`

### Security Agent Refuses Queries
**Cause:** Using censored model instead of uncensored

**Fix:** Ensure dolphin-phi or similar uncensored model:
```bash
ollama pull dolphin-phi:latest
```
See [Agents Reference](../../../docs/AGENTS.md) for uncensored requirements.

### Wrong Agent Selected
- Check classifier in `backend/agents/classifier.py`
- Use `agent_override` parameter to force specific agent

---

## Termux Issues

### Storage Permission Denied
```bash
termux-setup-storage
# Grant storage permission when prompted
```

### SSH Not Working
```bash
# Ensure sshd is running
sshd
# Check IP
ifconfig | grep inet
```

### Package Install Fails
```bash
pkg update
pkg upgrade
pkg install <package>
```

---

## Performance Tips

1. **Use lighter models** - 7B instead of 14B
2. **Close other apps** - Free up RAM
3. **Battery saver off** - Can throttle CPU
4. **Keep phone cool** - Thermal throttling slows inference

---

## Getting Help

- [Main Troubleshooting](../../../docs/TROUBLESHOOTING.md) - General issues
- [Mobile CLAUDE.md](../CLAUDE.md) - Full configuration reference
- [Documentation Index](../../../docs/INDEX.md) - All docs
