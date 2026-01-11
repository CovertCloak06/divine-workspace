# Troubleshooting Guide

**Common issues and their solutions for Divine Node Workspace**

---

## Table of Contents

- [Setup Issues](#setup-issues)
- [Server Issues](#server-issues)
- [Pre-commit Hook Issues](#pre-commit-hook-issues)
- [Testing Issues](#testing-issues)
- [Build Issues](#build-issues)
- [Import/Module Issues](#import-module-issues)
- [Performance Issues](#performance-issues)
- [Mobile-Specific Issues](#mobile-specific-issues)

---

## Setup Issues

### Just command not found

**Symptom:**
```
bash: just: command not found
```

**Solution:**
```bash
# Install just (Rust-based command runner)
# On macOS
brew install just

# On Linux
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/bin
export PATH="$HOME/bin:$PATH"

# Verify
just --version
```

### pnpm install fails

**Symptom:**
```
ERR_PNPM_NO_MATCHING_VERSION  No matching version found for...
```

**Solution:**
```bash
# Update pnpm
npm install -g pnpm@latest

# Clear cache
pnpm store prune

# Reinstall
rm -rf node_modules pnpm-lock.yaml
pnpm install
```

### Python virtual environment issues

**Symptom:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solution:**
```bash
# Recreate venv
cd apps/pkn
rm -rf .venv
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Verify
.venv/bin/python -m flask --version
```

### Pre-commit installation fails

**Symptom:**
```
pre-commit: command not found
```

**Solution:**
```bash
# Install pre-commit
pip install pre-commit

# Or via Homebrew (macOS)
brew install pre-commit

# Verify
pre-commit --version

# Install hooks
just hooks-install
```

---

## Server Issues

### Port already in use

**Symptom:**
```
OSError: [Errno 48] Address already in use
```

**Solution:**
```bash
# Find process using port
lsof -i :8010

# Kill process
kill -9 <PID>

# Or use just command
just stop

# Verify port is free
lsof -i :8010  # Should show nothing
```

### PKN server won't start

**Symptom:**
```
ImportError: No module named 'backend'
```

**Solution:**
```bash
# Ensure you're in correct directory
cd apps/pkn

# Use the root launcher
python3 server.py

# Or from workspace root
just dev-app pkn

# Check Python path
python3 -c "import sys; print('\n'.join(sys.path))"
```

### Code Academy not loading

**Symptom:**
Browser shows "Connection refused" or blank page

**Solution:**
```bash
# Start server
cd apps/code-academy
python3 -m http.server 8011

# Or from workspace root
just dev-app code-academy

# Check server is running
curl http://localhost:8011

# Check browser console for errors (F12)
```

### Health check fails

**Symptom:**
```
❌ PKN Server: Not running
```

**Solution:**
```bash
# Check if servers are actually running
ps aux | grep python

# Start servers
just dev

# Verify health
just health

# Check logs
just logs-pkn
```

---

## Pre-commit Hook Issues

### Hooks failing on commit

**Symptom:**
```
check-file-size.........................................Failed
- hook id: check-file-size
- exit code: 1
```

**Solution:**
```bash
# See which files are failing
just pre-commit-all

# Fix file size violations
just check-file-sizes

# Split large files into modules
# See docs/ARCHITECTURE.md for patterns

# Skip hooks (emergency only)
git commit --no-verify -m "emergency fix"
```

### Biome not found

**Symptom:**
```
biome check: command not found
```

**Solution:**
```bash
# Install Biome via pnpm
pnpm install

# Or install globally
npm install -g @biomejs/biome

# Verify
pnpm biome --version

# Update pre-commit
pre-commit autoupdate
```

### Ruff errors

**Symptom:**
```
ruff.................................................Failed
```

**Solution:**
```bash
# Install ruff
pip install ruff

# Auto-fix issues
ruff check --fix apps/**/*.py

# Format code
ruff format apps/**/*.py

# Or use just command
just format
```

### Secrets detected

**Symptom:**
```
Detect Secrets...........................................Failed
- hook id: detect-secrets
- exit code: 1
```

**Solution:**
```bash
# Check what was detected
pre-commit run detect-secrets --all-files

# If false positive, update baseline
detect-secrets scan --baseline .secrets.baseline

# If real secret, remove it and update baseline
git rm --cached <file-with-secret>
echo "<pattern>" >> .gitignore
detect-secrets scan --baseline .secrets.baseline
```

---

## Testing Issues

### pytest not found

**Symptom:**
```
bash: pytest: command not found
```

**Solution:**
```bash
# Install pytest in virtual environment
cd apps/pkn
.venv/bin/pip install pytest

# Or reinstall all dependencies
just setup-pkn

# Run tests with full path
.venv/bin/pytest tests/
```

### Tests failing after changes

**Symptom:**
```
FAILED tests/unit/test_agents.py::test_classification
```

**Solution:**
```bash
# Run single test with verbose output
cd apps/pkn
pytest tests/unit/test_agents.py::test_classification -v

# Check if imports changed
# Update test imports to match new structure

# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null

# Re-run
pytest tests/ -v
```

### E2E tests timing out

**Symptom:**
```
TimeoutError: Waiting for selector timed out
```

**Solution:**
```bash
# Increase timeout in playwright.config.js
# timeout: 60000  // 60 seconds

# Check if server is running
curl http://localhost:8011

# Run with headed mode to debug
cd apps/code-academy
pnpm test:e2e --headed

# Check browser console for errors
```

---

## Build Issues

### Clean build artifacts

**Symptom:**
Stale build files causing issues

**Solution:**
```bash
# Clean all build artifacts
just clean

# Or manually
rm -rf apps/*/dist
rm -rf apps/*/build
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete
```

### npm/pnpm dependency issues

**Symptom:**
```
WARN deprecated package@version
```

**Solution:**
```bash
# Update dependencies
pnpm update

# Or reset completely
rm -rf node_modules pnpm-lock.yaml
pnpm install

# Check for security issues
pnpm audit
pnpm audit fix
```

---

## Import/Module Issues

### Python import errors

**Symptom:**
```
ModuleNotFoundError: No module named 'backend.routes'
```

**Solution:**
```bash
# Check you're running from correct directory
pwd  # Should be apps/pkn or workspace root

# Use the launcher script
python3 server.py  # In apps/pkn/

# Or from workspace root
just dev-app pkn

# Check __init__.py files exist
find backend -name __init__.py

# If missing, create them
touch backend/__init__.py
touch backend/routes/__init__.py
```

### JavaScript module errors

**Symptom:**
```
Uncaught SyntaxError: Cannot use import statement outside a module
```

**Solution:**
```html
<!-- Add type="module" to script tag -->
<script type="module" src="src/main.js"></script>

<!-- NOT -->
<script src="src/main.js"></script>
```

### Symlink not working

**Symptom:**
```
FileNotFoundError: No such file or directory: 'backend/memory'
```

**Solution:**
```bash
# Check symlink exists
ls -la apps/pkn-mobile/backend/memory

# If broken, recreate with relative path
cd apps/pkn-mobile/backend
rm memory
ln -s ../../pkn/backend/memory memory

# Verify
ls -la memory
```

---

## Performance Issues

### Slow server startup

**Symptom:**
PKN server takes >30 seconds to start

**Solution:**
```bash
# Check if llama.cpp is loading large model
ls -lh apps/pkn/llama.cpp/models/

# Use smaller model or disable GPU
export CUDA_VISIBLE_DEVICES=""

# Check Python imports
python3 -X importtime server.py 2>&1 | grep "import time"

# Optimize imports (lazy loading)
```

### Slow frontend loading

**Symptom:**
Page takes >5 seconds to load

**Solution:**
```bash
# Check network tab in browser (F12)
# Look for large files or slow requests

# Minify CSS/JS (future: use Vite)
# Optimize images
# Enable browser caching

# Check server location
# Should be localhost for development
```

### High memory usage

**Symptom:**
```
PKN using >8GB RAM
```

**Solution:**
```bash
# Check which process is using memory
ps aux --sort=-%mem | head -10

# llama.cpp memory usage is normal for large models
# Use smaller model or increase swap

# Check for memory leaks
# Monitor with htop or Activity Monitor

# Restart server
just stop
just dev-app pkn
```

---

## Mobile-Specific Issues

### OpenAI API key not set

**Symptom:**
```
⚠️  OpenAI client not available: OPENAI_API_KEY environment variable not set
```

**Solution:**
```bash
# Create .env file
cd apps/pkn-mobile
cp .env.example .env

# Edit .env and add your API key
nano .env

# Export for current session
export OPENAI_API_KEY=sk-...

# Verify
echo $OPENAI_API_KEY
```

### Deployment to phone fails

**Symptom:**
```
ssh: connect to host 192.168.1.100 port 8022: Connection refused
```

**Solution:**
```bash
# On phone (Termux):
pkg install openssh
sshd

# Get phone IP
ifconfig  # Or ip addr

# On desktop, test connection
ssh -p 8022 gh0st@<phone-ip>

# If password prompt, setup SSH key
ssh-copy-id -p 8022 gh0st@<phone-ip>

# Re-run deployment
just deploy-mobile <phone-ip>
```

### Termux permissions issues

**Symptom:**
```
Permission denied: '/data/data/com.termux/files/home/pkn-mobile'
```

**Solution:**
```bash
# Fix permissions
chmod -R 755 ~/pkn-mobile

# Check ownership
ls -la ~/pkn-mobile

# If needed, fix ownership
chown -R $(whoami) ~/pkn-mobile
```

---

## General Debugging Tips

### Enable debug mode

```bash
# PKN
python3 server.py --debug

# Code Academy (browser console)
# Open DevTools (F12) → Console tab

# Check logs
just logs-pkn
```

### Get help

1. **Check documentation**
   - `CLAUDE.md` - AI assistant guide
   - `docs/ARCHITECTURE.md` - System architecture
   - App-specific `CLAUDE.md` files

2. **Run health check**
   ```bash
   just health
   just check-tools
   ```

3. **Search issues**
   ```bash
   gh issue list --search "your problem"
   ```

4. **Ask for help**
   - Open a GitHub issue
   - Include error messages
   - List steps to reproduce
   - Show environment details

---

## Still Having Issues?

If none of these solutions work:

1. **Collect diagnostics**:
   ```bash
   just health > diagnostics.txt
   just check-tools >> diagnostics.txt
   python3 --version >> diagnostics.txt
   node --version >> diagnostics.txt
   ```

2. **Open an issue** with:
   - Problem description
   - Steps to reproduce
   - Expected vs actual behavior
   - Diagnostics output
   - Error messages/logs

3. **Search existing issues**:
   ```bash
   gh issue list
   ```

---

**Last Updated**: 2026-01-10
