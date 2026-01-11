# API Keys Setup Guide

## Security Notice
API keys are now stored securely and will not be committed to version control.

## Configuration Files

### For Local Development
1. **`.env`** - Server-side environment variables (gitignored)
   - Contains your actual API keys
   - Used by Python backend services

2. **`config.local.js`** - Client-side configuration (gitignored)
   - Loads API keys into browser localStorage
   - Overrides default `config.js` settings

### Templates
- **`.env.example`** - Template for `.env` file
- **`config.js`** - Default configuration (no real keys)

## How It Works

1. **Frontend (Browser)**:
   - `config.js` is loaded first with empty/localStorage defaults
   - `config.local.js` loads your keys into localStorage
   - App reads keys from localStorage

2. **Backend (Python)**:
   - Reads `.env` file for server-side API calls
   - Use `python-dotenv` to load environment variables

## Setup Instructions

### New Installation
```bash
# 1. Copy template files
cp .env.example .env
cp config.js config.local.js  # If needed

# 2. Edit .env with your keys
nano .env

# 3. Edit config.local.js if using browser-based API calls
nano config.local.js

# 4. Install Python dependencies (includes python-dotenv)
pip install -r requirements.txt
```

### Get API Keys (Free Tiers Available)
- **OpenAI**: https://platform.openai.com/api-keys
- **HuggingFace**: https://huggingface.co/settings/tokens (free)
- **Groq**: https://console.groq.com (free, fast inference)
- **Together**: https://api.together.xyz (free tier)

### Verify Setup
```bash
# Check that .env exists and is not tracked by git
ls -la .env
git status  # Should not show .env

# Check gitignore
cat .gitignore | grep -E "\.env|config\.local"
```

## Important Notes
- ✅ `.env` and `config.local.js` are in `.gitignore`
- ✅ Never commit these files to version control
- ✅ Use `.env.example` as a template for others
- ✅ Local models (Ollama, llama.cpp) don't need API keys
