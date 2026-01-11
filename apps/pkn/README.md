# Divine Node (PKN - Parakleon)

**Self-hosted, privacy-first multi-agent AI system with a cyberpunk interface.**

Divine Node is a complete AI assistant platform that runs **100% locally** on your machine. No cloud dependency, no data collection, full privacy. Features 6 specialized AI agents coordinated through an intelligent routing system.

---

## 🌟 Features

### Multi-Agent System
- **💻 Coder Agent** - Code writing, debugging, refactoring (Qwen2.5-Coder-14B)
- **🧠 Reasoner Agent** - Planning, logic, problem-solving
- **🔍 Research Agent** - Web research, documentation lookup
- **⚙️ Executor Agent** - System commands, file operations
- **💬 General Agent** - Quick Q&A, simple queries (Ollama Llama-3.1)
- **👁️ Vision Agent** - Image analysis, UI debugging (LLaVA)
- **☁️ Vision Cloud** - FREE fast vision via Groq (optional)

### Privacy & Performance
- ✅ **100% Local** - All AI runs on your machine
- ✅ **No Telemetry** - Zero data collection
- ✅ **Offline Capable** - Works without internet (except cloud agents)
- ✅ **Fast** - Optimized for local inference with llama.cpp
- ✅ **Uncensored** - No content filtering on local models

### User Interface
- 🎨 **Cyberpunk Theme** - Dark/light mode with neon accents
- 💬 **Multi-Session** - Projects, favorites, archive
- 📁 **File Management** - Upload, analyze, organize files
- 🖼️ **Image Generation** - Local AI image creation
- ⌨️ **Code Editor** - Built-in Monaco-based editor
- 🔧 **Advanced Settings** - Temperature, max tokens, Top-P, penalties

---

## 🚀 Quick Start

### Prerequisites

- **Linux** (Ubuntu 22.04+, Debian, or Termux on Android)
- **Python 3.10+**
- **8GB RAM minimum** (16GB+ recommended)
- **~15GB disk space** for models

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/divine-node.git
cd divine-node

# Install Python dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Download AI models (Qwen2.5-Coder-14B)
# See MODELS.md for download links

# Start all services
./pkn_control.sh start-all

# Open browser
http://localhost:8010
```

---

## 📱 Android APK Build (NEW!)

**Want Divine Node on your Android phone?** We've got you covered!

### 📚 Build Documentation (All in Project Root)

| Document | Purpose | Audience |
|----------|---------|----------|
| **[BUILD_APK_QUICK_GUIDE.md](BUILD_APK_QUICK_GUIDE.md)** | ⚡ Fast 5-step build guide | Humans |
| **[APK_BUILD_LOG.md](APK_BUILD_LOG.md)** | 🚧 All errors & solutions encountered | Troubleshooting |
| **[AI_APK_BUILD_INSTRUCTIONS.md](AI_APK_BUILD_INSTRUCTIONS.md)** | 🤖 Systematic build protocol | AI Assistants |
| **[BUILD_ON_ANDROID.md](BUILD_ON_ANDROID.md)** | 📱 Build APK on Android/Termux | Mobile developers |

### ⚡ Quick Build (After Setup)

```bash
cd /home/gh0st/pkn
git checkout claude/add-android-app-branch-RKG9I

# Set up environment
export JAVA_HOME=/home/gh0st/.jdk/jdk-21.0.8
export PATH=$JAVA_HOME/bin:$PATH
source ~/.nvm/nvm.sh && nvm use 22

# Sync and build
npx cap sync android
cd android
./gradlew assembleDebug

# APK ready!
cp app/build/outputs/apk/debug/app-debug.apk ~/Downloads/DivineNode.apk
```

**Result:** 12MB APK in `~/Downloads/DivineNode.apk`

**Need help?** Check `APK_BUILD_LOG.md` - every error and solution is documented!

---

## 📖 Documentation

- **[Installation Guide](docs/INSTALL.md)** - Detailed setup instructions
- **[Model Setup](docs/MODELS.md)** - Download and configure AI models
- **[Architecture](docs/ARCHITECTURE.md)** - How the multi-agent system works
- **[API Reference](docs/API.md)** - Backend API documentation
- **[Contributing](CONTRIBUTING.md)** - How to contribute

---

## 🛠️ Architecture

```
┌─────────────────────────────────────────────┐
│          Divine Node Web UI                 │
│     (pkn.html, app.js, multi_agent_ui.js)   │
└─────────────────┬───────────────────────────┘
                  │
         ┌────────▼────────┐
         │  Flask Server   │
         │ divinenode_server.py │
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │ Agent Manager   │
         │ agent_manager.py │
         └────────┬────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐   ┌────▼────┐   ┌───▼───┐
│ Qwen  │   │ LLaVA   │   │ Ollama│
│ :8000 │   │  :8001  │   │:11434 │
└───────┘   └─────────┘   └───────┘
```

---

## 🎯 Usage Examples

### Code Generation
```
User: "Write a Python function to validate email addresses"
Coder Agent: [generates regex-based validator with error handling]
```

### Image Analysis
```
User: "What's wrong with this UI?" [uploads screenshot]
Vision Agent: "The submit button overlaps the input field.
CSS issue: missing margin-top: 10px on .submit-btn"
```

### Multi-Step Planning
```
User: "Plan a microservices architecture for real-time chat"
Reasoner Agent: [creates detailed architecture with diagrams]
```

---

## 🔧 Configuration

### Environment Variables

Create `.env` file:

```bash
# Local LLM Settings
LOCAL_LLM_BASE=http://127.0.0.1:8000/v1
LLAMA_MODEL_PATH=/path/to/qwen2.5-coder-14b.gguf

# Ollama (optional)
OLLAMA_BASE=http://127.0.0.1:11434

# Cloud APIs (optional)
GROQ_API_KEY=your_groq_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
```

### Model Configuration

See `docs/MODELS.md` for:
- Recommended models for each agent
- Download links (HuggingFace)
- Quantization options (Q4_K_M, Q5_K_M, etc.)
- Performance tuning

---

## 🤝 Contributing

Contributions are welcome! This project is licensed under **AGPL-3.0** with a commercial license option.

### For Open Source Contributors:
- Fork the repo
- Create a feature branch
- Submit a pull request
- All contributions under AGPL-3.0

### For Commercial Use:
Need to keep modifications private or run as SaaS? Purchase a commercial license.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

**Divine Node** is dual-licensed:

- **AGPL-3.0** - Free for personal/open-source use
- **Commercial License** - For businesses ($99-499/year)

See [LICENSE](LICENSE) for full terms.

Third-party components (AI models, libraries) have separate licenses - see [CREDITS.md](CREDITS.md).

---

## 🙏 Credits

**Built by:** gh0st
**AI Assistance:** Claude (Anthropic)

**AI Models:**
- Qwen2.5-Coder by Alibaba Cloud (Apache 2.0)
- LLaVA by Microsoft Research (Apache 2.0)
- Llama by Meta AI (Llama Community License)

**Core Dependencies:**
- llama.cpp by Georgi Gerganov (MIT)
- Flask by Pallets (BSD-3-Clause)

Full credits: [CREDITS.md](CREDITS.md)

---

## 🐛 Known Issues

See [GitHub Issues](https://github.com/yourusername/divine-node/issues) for current bugs and feature requests.

**Current Focus:**
- Send button stop functionality
- Temperature controls integration
- Vision agent English-only enforcement

---

## 🗺️ Roadmap

- [ ] Streaming responses for all agents
- [ ] Image upload for vision agents
- [ ] Plugin system for custom agents
- [ ] Mobile app (React Native)
- [ ] Docker deployment
- [ ] Team collaboration features

---

## 💬 Support

- **GitHub Issues** - Bug reports, feature requests
- **Discussions** - Questions, ideas, showcase
- **Discord** - Real-time community chat (coming soon)

---

## ⚠️ Disclaimer

Divine Node is provided "AS IS" without warranty. Use at your own risk.

AI models may generate incorrect information. Always verify critical outputs.

---

**Star ⭐ this repo if you find it useful!**
