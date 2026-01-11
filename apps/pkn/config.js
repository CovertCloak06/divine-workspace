// ===========================================
// PARAKLEON CONFIGURATION (config.js)
// ===========================================
// Cross-references:
// - App: app.js (loads ACTIVE_BASE_URL, ACTIVE_MODEL, ACTIVE_API_KEY from this config)
// - Tools: tools.js (uses PARAKLEON_API_BASE for server endpoints)
// - Server: divinenode_server.py (LOCAL_IMAGE_GEN_URL points to /api/generate-image)
// - HTML: pkn.html (model selection dropdown populated from this config)
// - Mobile: termux_menu.sh (llama.cpp server configuration)
//
// Configuration sections:
// - AI Providers: OpenAI, Groq, Together, HuggingFace, Ollama, llama.cpp
// - Image Generation: Pollinations.ai (free) and local server endpoint
// - API Keys: Add your keys here for different providers
// - Server URLs: Local llama.cpp and image generation endpoints
//
// Security Note: Never commit API keys to version control!
// ===========================================

// Parakleon Configuration
window.PARAKLEON_CONFIG = {
  // OpenAI API key and default model (cloud fallback)
  // NOTE: For security, add your API key to .env file instead of hardcoding it here
  OPENAI_API_KEY: localStorage.getItem('openai_api_key') || '',
  OPENAI_MODEL: 'gpt-4o-mini',
  // Qwen2.5-Coder (abliterated) is the default local agentic model for llama.cpp
  // This should match the filename in llama.cpp/models/
  DEFAULT_QWEN_MODEL: 'Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf',
  OLLAMA_BASE_URL: 'http://127.0.0.1:11434/v1',

  // llama.cpp local server (run: ./llama-server -m model.gguf)
  LLAMACPP_BASE_URL: 'http://127.0.0.1:8000/v1',

  // llama-server (OpenAI-compatible, default port 8000)
  LLAMA_SERVER_BASE_URL: 'http://127.0.0.1:8000/v1',

  // Free AI Providers - Add your API keys here
  GROQ_API_KEY: '',  // Get free key at: https://console.groq.com
  GROQ_MODEL: 'llama-3.3-70b-versatile',

  HUGGINGFACE_API_KEY: localStorage.getItem('huggingface_api_key') || '',  // Get free key at: https://huggingface.co/settings/tokens
  HUGGINGFACE_MODEL: 'meta-llama/Meta-Llama-3-8B-Instruct',

  TOGETHER_API_KEY: '',  // Get free key at: https://api.together.xyz
  TOGETHER_MODEL: 'meta-llama/Llama-3-70b-chat-hf',

  // Image Generation - using Pollinations.ai (100% free, no API key needed!)
  IMAGE_SERVICE: 'pollinations',  // Free, unlimited image generation
  
  // Image Generation Server - served from same server as UI
  LOCAL_IMAGE_GEN_URL: '/api/generate-image'
};
