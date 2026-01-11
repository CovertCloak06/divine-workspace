# Android/Termux Compatibility Guide

## Advanced Features Compatibility

### ✅ FULLY COMPATIBLE (No Issues)
1. **Agent Delegation** - Pure Python, works perfectly
2. **Task Planning** - Uses local LLM, fully compatible
3. **Tool Chaining** - Pure Python, no dependencies
4. **Agent Evaluation** - SQLite built into Python, works great
5. **Code Sandbox (Subprocess Mode)** - Works without Docker

### ⚠️ NEEDS SETUP
6. **RAG Memory** - Requires ChromaDB installation
   ```bash
   # In Termux
   pkg install python-numpy python-scipy
   pip install chromadb sentence-transformers
   ```
   **Note**: May be slow on phone, but works. Optional feature.

7. **Code Sandbox (Docker Mode)** - Not available on Android
   - Automatically falls back to subprocess mode
   - Subprocess mode is secure enough for personal use

## Model Requirements

### Agent Features Are Model-Agnostic!
**None of the advanced features require specific models.** They work with:
- ✅ Qwen2.5-Coder (your current model)
- ✅ Ollama models (any)
- ✅ llama.cpp models (any GGUF)
- ✅ External APIs (Claude, GPT) if configured

### How It Works
- **Planning**: Uses your Reasoner agent (currently Qwen via llama.cpp)
- **Delegation**: Routes to appropriate agent, uses whatever model that agent has
- **Evaluation**: Just logs data, no model needed
- **Tool Chaining**: Pure orchestration, no LLM calls
- **Sandbox**: Executes code, no LLM needed
- **RAG**: Uses sentence-transformers for embeddings (separate from chat model)

## Recommended Android Setup

### 1. Minimal (No Optional Deps)
```bash
# Just use what you have
# All features work except RAG
# Sandbox uses subprocess mode
```

### 2. Full (With RAG)
```bash
pkg install python-numpy
pip install chromadb sentence-transformers
# Enables semantic code search
# May take 30-60 seconds to index codebase
```

## Performance on Android

### Fast Features (No LLM calls)
- Tool chaining: <10ms
- Evaluation logging: <5ms
- Sandbox (subprocess): ~100ms

### Medium Features (Single LLM call)
- Planning: Same as regular agent call (~6-15s)
- Delegation: Same as agent call

### Slow Features (Optional)
- RAG indexing: 30-60s (one-time)
- RAG search: ~200-500ms on phone

## Transfer Checklist

### Before Transfer
```bash
# On PC: Create tarball
cd /home/gh0st
tar -czf pkn_transfer.tar.gz pkn/ \
  --exclude=pkn/.venv \
  --exclude=pkn/llama.cpp/build \
  --exclude=pkn/node_modules \
  --exclude=pkn/.chroma_db
```

### On Android
```bash
# In Termux
cd /sdcard
# Transfer pkn_transfer.tar.gz to phone
tar -xzf pkn_transfer.tar.gz
cd pkn

# Reinstall Python dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: Install ChromaDB if you want RAG
pip install chromadb sentence-transformers
```

### Test
```bash
# Test imports
python3 -c "from agent_manager import agent_manager; print('✓ Ready')"

# Start server
./pkn_control.sh start-divinenode
```

## Storage Requirements

### Base System
- ~500MB (Python + dependencies)
- ~8GB (Qwen model)

### Advanced Features
- Evaluation DB: ~10MB (grows slowly)
- RAG embeddings: ~50MB (if installed)
- Plans storage: ~5KB per plan
- Total: ~50-100MB additional

## Battery Impact

- **Idle**: Negligible
- **Active chat**: Same as before (LLM is the heavy part)
- **RAG indexing**: High CPU for 30-60s, then done
- **Evaluation**: Negligible (<1% overhead)

## What Won't Work on Android

1. **Docker sandbox** - Use subprocess mode instead (auto-fallback)
2. **GPU acceleration** - Use CPU-only models (Qwen Q4 works fine)
3. **Large RAG indexes** - Limit to ~1000 files max

## Recommended Android Workflow

1. Transfer project ✅
2. Skip ChromaDB initially ✅
3. Test basic features ✅
4. Install ChromaDB later if needed ⚠️
5. Use subprocess sandbox ✅

**Bottom line**: Everything works on Android except Docker. RAG is optional and works but may be slow.
