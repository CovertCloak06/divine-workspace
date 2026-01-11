# Parakleon Setup & Usage Guide

## Fixed Issues ✓

1. **Syntax Errors** - Fixed regex pattern and string escaping in app.js
2. **AI Model Bug** - Fixed `data.choices[0]` array access error
3. **Model Dropdown** - Updated with your actual installed Ollama models
4. **PhoneScan Backend** - Created server with proper error handling

## Current Status

### ✓ Working
- Send button and chat functionality
- All Ollama models (mistral, deepseek-coder, llama2-uncensored, dolphin-mixtral, glm-4.6)
- OpenAI GPT-4o-mini (with your API key)
- Message history and chat management
- Settings panel
- File upload UI

### ⚠ Requires Setup
- **PhoneScan**: Needs backend server running (see below)

## How to Use

### 1. Access the Application
Your web server is running on: **http://localhost:8010/pkn.html**

### 2. Select AI Model
Use the dropdown to choose between:
- **OpenAI: gpt-4o-mini** (uses your API key)
- **Ollama models** (runs locally, no API key needed)

### 3. Start Chatting
Type your message and click "Send" or press Enter.

## PhoneScan Setup (Optional)

The PhoneScan button requires a backend server. To enable it:

### Install Dependencies
```bash
cd /home/gh0st/pkn
pip3 install -r requirements.txt
```

### Start the PhoneScan Server
```bash
python3 phonescan_server.py
```

Server will run on: http://127.0.0.1:5000

### Usage
1. Click "Phone Scan" button
2. Enter phone number with country code (e.g., +15551234567)
3. Confirm the scan
4. Results appear in chat

## Available Models

### Ollama (Local)
- **mistral:latest** (7.2B) - General purpose
- **deepseek-coder:6.7b** (7B) - Code specialist  
- **deepseek-coder:latest** (1B) - Lighter code model
- **llama2-uncensored:latest** (7B) - Uncensored responses
- **dolphin-mixtral:latest** (46.7B) - Large advanced model
- **glm-4.6:cloud** (355B) - Cloud-based mega model

### OpenAI (Cloud)
- **gpt-4o-mini** - Fast, efficient GPT-4 variant

## Troubleshooting

### AI Not Responding
- **Check model selection**: Make sure you selected a model
- **Ollama models**: Verify Ollama is running with `ollama serve`
- **OpenAI**: Verify your API key is valid in config.js

### PhoneScan Not Working
- Make sure the backend server is running: `python3 phonescan_server.py`
- Check terminal for error messages
- Verify port 5000 is not in use

### Browser Console
Press F12 to open developer tools and check the Console tab for detailed errors.

## Technical Details

### Ports
- **8010**: Web UI (already running)
- **11434**: Ollama API (already running)
- **5000**: PhoneScan backend (needs manual start)

### Files
- `pkn.html` - Main UI
- `app.js` - Chat logic and API calls
- `tools.js` - PhoneScan and other tools
- `config.js` - API keys and settings
- `phonescan_server.py` - PhoneScan backend server

## Important note about serving the UI
Do NOT use "python -m http.server" (or similar simple static servers) to serve the project when you expect API endpoints to work. A simple static server only serves files and will 404 API requests such as /api/models/ollama or /api/generate-image. Instead start the Flask backend which serves both UI and API:

    python divinenode_server.py --host 0.0.0.0 --port 8010

Or start all services with:

    ./start_parakleon.sh
