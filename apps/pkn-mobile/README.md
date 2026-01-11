# PKN Mobile

**AI Assistant for Your Android Phone**

PKN Mobile is a simplified version of the Desktop PKN designed for mobile deployment on Android devices using Termux. It provides AI-powered assistance on-the-go with minimal resource usage.

## Features

- ☁️ **Cloud-Powered**: Uses OpenAI API (gpt-4o-mini)
- 📱 **Mobile-Optimized**: Touch-friendly UI, minimal resources
- 💬 **Conversational AI**: Natural language chat interface
- 🔗 **Shared Memory**: Conversations sync with desktop PKN
- 🚀 **Fast**: < 3 second response times
- 🪶 **Lightweight**: < 100MB storage, < 100MB RAM

## Quick Start

### Prerequisites
- Android phone with Termux installed
- OpenAI API key ([get one here](https://platform.openai.com/api-keys))
- Network connection

### Installation

1. **Install Termux** from F-Droid (not Google Play)

2. **Set up Python**:
   ```bash
   pkg install python openssh
   pip install --upgrade pip
   ```

3. **Deploy PKN Mobile**:
   ```bash
   # On your desktop:
   cd apps/pkn-mobile
   ./scripts/deploy_to_phone.sh <your-phone-ip>

   # Or manually on phone:
   git clone https://github.com/yourusername/divine-workspace
   cd divine-workspace/apps/pkn-mobile
   pip install -r requirements.txt
   ```

4. **Configure**:
   ```bash
   cp .env.example .env
   # Edit .env and add your OpenAI API key
   export OPENAI_API_KEY=sk-...
   ```

5. **Run**:
   ```bash
   python backend/server.py
   ```

6. **Access**:
   - On phone: Open browser to `http://localhost:8010`
   - From desktop: `http://<phone-ip>:8010`

## Usage

### Basic Chat
1. Open `http://localhost:8010` in your mobile browser
2. Type your message in the input box
3. Press "Send" or hit Enter
4. AI responds within seconds

### Example Queries
- "Explain Python decorators"
- "Write a bash script to backup my files"
- "What's the weather in San Francisco?" (if you add weather API)
- "Help me debug this code: [paste code]"

## Configuration

Edit `.env` file to customize:

```bash
# Required
OPENAI_API_KEY=sk-...

# Optional
OPENAI_MODEL=gpt-4o-mini    # or gpt-3.5-turbo for faster/cheaper
SERVER_PORT=8010             # change if port conflicts
```

## Differences from Desktop PKN

| Feature | Desktop | Mobile |
|---------|---------|--------|
| LLM Backend | Local (llama.cpp) | Cloud (OpenAI) |
| Multi-Agent | ✅ 6 agents | ❌ Single agent |
| Image Generation | ✅ Stable Diffusion | ❌ Disabled |
| Offline Mode | ✅ Full | ❌ Requires network |
| Resource Usage | High (8GB RAM, GPU) | Low (100MB RAM) |
| Cost | $0 (local) | ~$0.05/session |

**Full comparison**: [docs/DIFFERENCES.md](docs/DIFFERENCES.md)

## Performance

- **Cold Start**: < 5 seconds
- **First Response**: 1-3 seconds
- **Streaming**: Real-time chunks
- **Memory**: < 100MB RAM
- **Battery**: < 5% per hour

## Troubleshooting

### "Failed to fetch"
- Server not running: `python backend/server.py`
- Wrong port: Check `.env` for correct port

### "OpenAI API not configured"
- Missing API key: Add to `.env` file
- Invalid key: Verify on OpenAI dashboard

### Slow Responses
- Switch to gpt-3.5-turbo: `export OPENAI_MODEL=gpt-3.5-turbo`
- Check network connection

### Out of Credits
- OpenAI account out of credits
- Add payment method or wait for free tier reset

## Cost Estimation

**OpenAI API Costs** (as of 2026-01):
- gpt-4o-mini: $0.15 / 1M input tokens, $0.60 / 1M output tokens
- gpt-3.5-turbo: $0.50 / 1M input tokens, $1.50 / 1M output tokens

**Typical Usage**:
- 10 messages/day × 30 days = 300 messages/month
- Average: ~500 tokens/message = 150K tokens/month
- **Cost**: ~$0.05-0.20/month (gpt-4o-mini)

## Development

See [CLAUDE.md](CLAUDE.md) for comprehensive development guide.

### Local Development
```bash
cd apps/pkn-mobile
python backend/server.py --debug
```

### Testing
```bash
just test-app pkn-mobile
```

### Deploy to Phone
```bash
./scripts/deploy_to_phone.sh 192.168.1.100
```

## Architecture

- **Backend**: Python Flask (minimal, 2 routes)
- **Frontend**: Vanilla JS with inline CSS
- **LLM**: OpenAI API (streaming)
- **Storage**: File-based memory (synced with desktop)

## Security

- API keys stored in `.env` (never committed)
- Flask CORS wide open (personal use only)
- Runs in Termux sandbox (isolated)
- No shell access from UI (safer than desktop)

## Roadmap

**Future Enhancements**:
- [ ] Markdown rendering for code blocks
- [ ] Syntax highlighting
- [ ] File upload (limited by storage)
- [ ] Voice input (speech-to-text)
- [ ] Push notifications for long responses
- [ ] Offline mode (cache common responses)

**Will Not Add**:
- Local LLM (too resource-intensive)
- Multi-agent (cloud API limitations)
- Image generation (requires GPU)

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/divine-workspace/issues)
- **Docs**: [CLAUDE.md](CLAUDE.md)
- **Comparison**: [docs/DIFFERENCES.md](docs/DIFFERENCES.md)

## License

MIT

---

**Built with ❤️ for mobile AI enthusiasts**
