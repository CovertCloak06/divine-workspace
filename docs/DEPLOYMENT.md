# Deployment Guide

How to deploy all Divine Workspace applications.

**Related Docs:**
- [Architecture](./ARCHITECTURE.md) - System structure
- [Troubleshooting](./TROUBLESHOOTING.md) - Fix deployment issues
- [Mobile Deployment](../apps/pkn-mobile/docs/DEPLOYMENT_MOBILE.md) - Detailed mobile setup

## Quick Start

### PKN Desktop (Linux)
```bash
cd apps/pkn
./pkn_control.sh start-all
# Access: http://localhost:8010
```

### PKN Mobile (Android/Termux)
```bash
# In Termux
cd ~/pkn
pkn  # or: python backend/server.py
# Access: http://localhost:8010
```

### Code Academy
```bash
cd apps/code-academy
# Static site - serve with any web server
python -m http.server 8080
```

## PKN Desktop Deployment

### Prerequisites
- Python 3.10+
- Ollama installed and running
- 16GB+ RAM recommended
- Models pulled (see [Agents](./AGENTS.md) for model list)

### Installation
```bash
# Clone repository
git clone https://github.com/CovertCloak06/divine-workspace
cd divine-workspace/apps/pkn

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Pull required models
ollama pull qwen2.5-coder:14b
ollama pull qwen3:14b
ollama pull mistral:latest
# ... see AGENTS.md for full list
```

### Starting Services
```bash
# Start all services
./pkn_control.sh start-all

# Or start individually
./pkn_control.sh start-ollama
./pkn_control.sh start-divinenode
```

### Ports
| Service | Port |
|---------|------|
| PKN Web UI | 8010 |
| Ollama | 11434 |

## PKN Mobile Deployment

**Full guide:** [Mobile Deployment](../apps/pkn-mobile/docs/DEPLOYMENT_MOBILE.md)

### Quick Setup
1. Install Termux from F-Droid
2. Install Ollama: `pkg install ollama`
3. Clone/copy PKN Mobile to `~/pkn`
4. Pull mobile models (7B variants)
5. Run: `python backend/server.py`

### Mobile-Specific
- Uses lighter 7B models (not 14B)
- See [Mobile CLAUDE.md](../apps/pkn-mobile/CLAUDE.md) for model config
- Uncensored models required for SECURITY agent

## Code Academy Deployment

### Local Development
```bash
cd apps/code-academy
python -m http.server 8080
# Access: http://localhost:8080
```

### Production
- Static site deployment (Netlify, Vercel, GitHub Pages)
- No backend required

## Environment Variables

Create `.env` in app root:

```bash
# API Keys (optional - for cloud agents)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GROQ_API_KEY=gsk_...

# Ollama (default localhost)
OLLAMA_BASE=http://127.0.0.1:11434

# Server
PORT=8010
HOST=0.0.0.0
```

## Troubleshooting Deployment

Common issues → [Troubleshooting](./TROUBLESHOOTING.md)

### Port Already in Use
```bash
lsof -i :8010
kill -9 <PID>
```

### Ollama Not Running
```bash
ollama serve &
curl http://localhost:11434/api/tags
```

### Model Not Found
```bash
ollama list
ollama pull <model-name>
```

## Related Documentation

- [Architecture](./ARCHITECTURE.md) - System design
- [Agents](./AGENTS.md) - Agent/model configuration
- [Troubleshooting](./TROUBLESHOOTING.md) - Fix issues
- [Mobile Deployment](../apps/pkn-mobile/docs/DEPLOYMENT_MOBILE.md) - Android setup
