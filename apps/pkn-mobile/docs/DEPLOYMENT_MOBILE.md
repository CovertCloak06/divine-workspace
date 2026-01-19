# PKN Mobile Deployment Guide

Complete guide for deploying PKN on Android via Termux.

**Back to:** [Main Deployment Guide](../../../docs/DEPLOYMENT.md) | [Documentation Index](../../../docs/INDEX.md)

**Related Docs:**
- [Mobile CLAUDE.md](../CLAUDE.md) - AI assistant instructions
- [Agents Reference](../../../docs/AGENTS.md) - Agent configuration
- [Troubleshooting](./TROUBLESHOOTING_MOBILE.md) - Mobile-specific issues

## Hardware Requirements

Tested on Samsung Galaxy S24 Ultra:

| Spec | Minimum | Recommended |
|------|---------|-------------|
| RAM | 8GB | 12GB+ |
| Storage | 20GB free | 30GB+ free |
| Android | 12+ | 14+ |

## Installation

### Step 1: Install Termux

```bash
# Install from F-Droid (NOT Play Store)
# https://f-droid.org/packages/com.termux/
```

**Important:** The Play Store version is outdated and incompatible. Use F-Droid.

### Step 2: Update Termux

```bash
pkg update && pkg upgrade -y
```

### Step 3: Install Dependencies

```bash
pkg install python git openssh
pip install flask flask-cors requests langchain-core
```

### Step 4: Install Ollama

```bash
# Install Ollama for Termux
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve &
```

### Step 5: Pull Models

```bash
# Required models (see Agents Reference for full list)
ollama pull qwen:latest           # 2.3GB - General
ollama pull qwen2.5-coder:7b      # 4.7GB - Coder
ollama pull dolphin-phi:latest    # 1.6GB - Security (UNCENSORED)
ollama pull nous-hermes:latest    # 3.8GB - Reasoner (UNCENSORED)
ollama pull mistral:latest        # 4.4GB - Researcher
```

**Storage Note:** Full model set requires ~17GB. Start with essential models first.

### Step 6: Deploy PKN Mobile

```bash
# Clone or copy PKN Mobile
cd ~
git clone https://github.com/CovertCloak06/divine-workspace
cd divine-workspace/apps/pkn-mobile

# Or copy from PC via SSH
scp -r -P 8022 user@pc:/path/to/pkn-mobile ~/pkn
```

### Step 7: Start Server

```bash
cd ~/pkn  # or wherever deployed
python backend/server.py &
# Access: http://localhost:8010
```

## Quick Commands

Add to `~/.bashrc`:

```bash
alias pkn='cd ~/pkn && python backend/server.py &'
alias pkn-stop='pkill -f server.py'
alias pkn-status='pgrep -f server.py && echo "Running" || echo "Stopped"'
```

Apply changes:
```bash
source ~/.bashrc
```

## Configuration

### Model Configuration

Edit `backend/config/model_config.py`:

```python
MOBILE_LOCAL_MODELS = {
    "coder": "ollama:qwen2.5-coder:7b",
    "security": "ollama:dolphin-phi:latest",  # Must be uncensored
    "reasoner": "ollama:nous-hermes:latest",  # Must be uncensored
    "researcher": "ollama:mistral:latest",
    # ...
}
```

### Environment Variables

Create `.env` in `backend/`:

```bash
OLLAMA_BASE=http://127.0.0.1:11434
PORT=8010
# Optional cloud fallback
OPENAI_API_KEY=sk-...
```

## Uncensored Models

**REQUIRED for SECURITY agent:**

- `dolphin-phi:latest` - Fast uncensored security analysis
- `nous-hermes:latest` - Uncensored reasoning and planning

**Why uncensored?** Security analysis requires examining vulnerabilities, exploits, and attack vectors without content filtering. Standard models may refuse to analyze security issues.

See [Agents Reference](../../../docs/AGENTS.md) for detailed model requirements.

## SSH Access (Optional)

Enable SSH for remote management from your PC:

```bash
pkg install openssh
passwd  # Set password for SSH
sshd
```

Connect from PC:
```bash
# Find phone IP: ip addr show (on phone)
ssh u0_a123@192.168.1.100 -p 8022
```

Transfer files:
```bash
scp -P 8022 file.txt u0_a123@192.168.1.100:~/
```

## Performance Optimization

### Memory Management

```bash
# Check memory usage
free -h

# Kill unused processes before running PKN
pkill -f chrome
pkill -f unused-app
```

### Model Selection

For low-memory devices, use smaller models:

```python
# In model_config.py
MOBILE_LOCAL_MODELS = {
    "coder": "ollama:qwen:latest",        # 2.3GB instead of 4.7GB
    "security": "ollama:dolphin-phi:latest",  # Already small
    # ...
}
```

## Troubleshooting

See [Mobile Troubleshooting](./TROUBLESHOOTING_MOBILE.md) for comprehensive issues.

### Quick Fixes

**Port in use:**
```bash
pkill -f server.py
python backend/server.py &
```

**Ollama not running:**
```bash
ollama serve &
```

**Model missing:**
```bash
ollama list  # Check installed models
ollama pull <model-name>
```

**Out of storage:**
```bash
# Check space
df -h

# Remove unused models
ollama rm unused-model
```

## Auto-Start on Boot

Create `~/.termux/boot/start-pkn.sh`:

```bash
#!/data/data/com.termux/files/usr/bin/bash
ollama serve &
sleep 5
cd ~/pkn && python backend/server.py &
```

Make executable:
```bash
chmod +x ~/.termux/boot/start-pkn.sh
```

Install Termux:Boot from F-Droid to enable boot scripts.

## Security Considerations

### Network Security

PKN runs locally by default (`localhost:8010`). To expose on network:

```python
# In server.py
app.run(host='0.0.0.0', port=8010)  # Allows network access
```

**Warning:** Only do this on trusted networks. Consider adding authentication.

### File Permissions

```bash
# Restrict access to config files
chmod 600 backend/.env
chmod 700 backend/config/
```

## Backup and Updates

### Backup Configuration

```bash
# Backup to PC via SSH
scp -r -P 8022 u0_a123@phone-ip:~/pkn/backend/config ~/backups/
```

### Update PKN Mobile

```bash
cd ~/pkn
git pull
pip install -r requirements.txt --upgrade
pkn-stop
pkn
```

## Related Documentation

- [Main Deployment](../../../docs/DEPLOYMENT.md) - Full deployment overview
- [Agents Reference](../../../docs/AGENTS.md) - Agent and model configuration
- [Mobile CLAUDE.md](../CLAUDE.md) - AI assistant instructions
- [Mobile Troubleshooting](./TROUBLESHOOTING_MOBILE.md) - Common issues
- [Architecture Deep Dive](./ARCHITECTURE_DEEPDIVE.md) - System internals

## Platform-Specific Notes

### Samsung Devices

Works well on Galaxy S series. Tested on:
- S24 Ultra (12GB RAM) - Excellent performance
- S23 (8GB RAM) - Good with smaller models

### Google Pixel

May require:
```bash
# If Ollama install fails
pkg install proot
```

### OnePlus/Xiaomi

Some ROMs restrict background processes. Disable battery optimization for Termux:
- Settings > Apps > Termux > Battery > Unrestricted

## Support

For issues not covered here:
1. Check [Mobile Troubleshooting](./TROUBLESHOOTING_MOBILE.md)
2. Review [Agents Reference](../../../docs/AGENTS.md) for model issues
3. Check GitHub issues: https://github.com/CovertCloak06/divine-workspace/issues
