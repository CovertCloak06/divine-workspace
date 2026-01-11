#!/bin/bash
# pkn_control.sh - PATCHED VERSION for Qwen2.5 Agent Optimization
# Apply key performance fixes for local agent model

# ===========================================
# PKN CONTROL - Single unified server manager
# ===========================================
# Usage:
# pkn_control.sh start-all
# pkn_control.sh stop-all
# pkn_control.sh start-divinenode
# pkn_control.sh stop-divinenode
# pkn_control.sh start-llama
# pkn_control.sh stop-llama
# pkn_control.sh start-parakleon
# pkn_control.sh stop-parakleon
# pkn_control.sh status
# pkn_control.sh debug-qwen        ← NEW: Quick diagnostics

PKN_DIR="/home/gh0st/pkn"
VENV_DIR="$PKN_DIR/.venv"
GGUF_MODEL="$PKN_DIR/llama.cpp/models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf"
VISION_MODEL="$PKN_DIR/llama.cpp/models/llava-v1.6-vicuna-7b-Q4_K_M.gguf"

# Ports
DN_PORT=8010
LLAMA_PORT=8000
VISION_PORT=8001
PK_PORT=9000
OLLAMA_PORT=11434

# Colors
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[0;34m'; NC='\033[0m'

start_divinenode() {
    echo -e "${B}Starting DivineNode Flask (port $DN_PORT)...${NC}"
    cd "$PKN_DIR"
    pkill -f divinenode_server.py 2>/dev/null
    # Activate venv if exists
    if [ -d "$PKN_DIR/.venv" ]; then
        nohup "$PKN_DIR/.venv/bin/python3" divinenode_server.py --host 0.0.0.0 --port $DN_PORT > "$PKN_DIR/divinenode.log" 2>&1 &
    else
        nohup python3 divinenode_server.py --host 0.0.0.0 --port $DN_PORT > "$PKN_DIR/divinenode.log" 2>&1 &
    fi
    sleep 2
    pgrep -f divinenode_server.py > /dev/null && echo -e "${G}✓ DivineNode running${NC}" || echo -e "${R}✗ DivineNode failed${NC}"
}

stop_divinenode() {
    pkill -f divinenode_server.py 2>/dev/null && echo -e "${G}✓ DivineNode stopped${NC}" || echo -e "${Y}⚪ Not running${NC}"
}

# ===== FIXED: Optimized Qwen2.5 Parameters =====
start_llama() {
    echo -e "${B}Starting llama.cpp server (port $LLAMA_PORT) - Qwen2.5 optimized${NC}"
    if [ ! -f "$GGUF_MODEL" ]; then
        echo -e "${R}Error: Model not found at $GGUF_MODEL${NC}"
        return 1
    fi
    
    pkill -f "llama_cpp.server.*$LLAMA_PORT" 2>/dev/null
    
    if [ -d "$VENV_DIR" ]; then
        source "$VENV_DIR/bin/activate"
    fi
    
    # OPTIMIZED for Qwen2.5 agent mode:
    # - GPU layers: 45 (Qwen 14B needs most layers on GPU)
    # - Batch size: 512 (larger = faster, uses more VRAM)
    # - Context: 8192 (reasonable for agent tasks)
    # - Temperature: 0.2 (low for deterministic agent/tool calls)
    # - Threads: All CPU cores minus 2
    nohup python3 -m llama_cpp.server \
        --model "$GGUF_MODEL" \
        --host 0.0.0.0 \
        --port $LLAMA_PORT \
        --chat_format qwen \
        --n_threads $(($(nproc) - 2)) \
        --n_gpu_layers 45 \
        --n_batch 512 \
        --n_ctx 8192 \
        > "$PKN_DIR/llama.log" 2>&1 &
    
    sleep 3  # Increased: give model time to load on GPU
    
    if pgrep -f "llama_cpp.server.*$LLAMA_PORT" > /dev/null; then
        echo -e "${G}✓ llama.cpp running (Qwen2.5 optimized)${NC}"
        sleep 1  # Extra wait for full initialization
    else
        echo -e "${R}✗ llama.cpp failed${NC}"
        echo -e "${Y}Check log: tail -f $PKN_DIR/llama.log${NC}"
        return 1
    fi
}

stop_llama() {
    pkill -f "llama_cpp.server.*$LLAMA_PORT" 2>/dev/null && echo -e "${G}✓ llama.cpp stopped${NC}" || echo -e "${Y}⚪ Not running${NC}"
}

# ===== VISION: LLaVA Vision Model Server =====
start_vision() {
    echo -e "${B}Starting LLaVA vision server (port $VISION_PORT)...${NC}"

    # LLaVA requires CLIP model for vision
    CLIP_MODEL="$PKN_DIR/llama.cpp/models/mmproj-model-f16.gguf"

    if [ ! -f "$VISION_MODEL" ]; then
        echo -e "${R}Error: Vision model not found at $VISION_MODEL${NC}"
        echo -e "${Y}Download with: wget -O \"$VISION_MODEL\" \"https://huggingface.co/cjpais/llava-v1.6-vicuna-7b-gguf/resolve/main/llava-v1.6-vicuna-7b.Q4_K_M.gguf\"${NC}"
        return 1
    fi

    if [ ! -f "$CLIP_MODEL" ]; then
        echo -e "${Y}Downloading CLIP model for vision...${NC}"
        wget -O "$CLIP_MODEL" "https://huggingface.co/cjpais/llava-v1.6-vicuna-7b-gguf/resolve/main/mmproj-model-f16.gguf" 2>&1 | grep -E "saved|Downloaded|%" | tail -5
        if [ ! -f "$CLIP_MODEL" ]; then
            echo -e "${R}Failed to download CLIP model${NC}"
            return 1
        fi
    fi

    pkill -f "llama_cpp.server.*$VISION_PORT" 2>/dev/null

    if [ -d "$VENV_DIR" ]; then
        source "$VENV_DIR/bin/activate"
    fi

    # Vision model config (LLaVA):
    # - GPU layers: 35 (LLaVA 7B, less than Qwen)
    # - Context: 4096 (vision models use less context)
    # - Chat format: llava-1-5 (required for vision)
    # - CLIP model: Required for image processing
    nohup python3 -m llama_cpp.server \
        --model "$VISION_MODEL" \
        --clip_model_path "$CLIP_MODEL" \
        --host 0.0.0.0 \
        --port $VISION_PORT \
        --chat_format llava-1-5 \
        --n_threads $(($(nproc) - 2)) \
        --n_gpu_layers 35 \
        --n_batch 512 \
        --n_ctx 4096 \
        > "$PKN_DIR/vision.log" 2>&1 &

    sleep 5

    if pgrep -f "llama_cpp.server.*$VISION_PORT" > /dev/null; then
        echo -e "${G}✓ Vision server running${NC}"
    else
        echo -e "${R}✗ Vision server failed${NC}"
        echo -e "${Y}Check log: tail -f $PKN_DIR/vision.log${NC}"
        return 1
    fi
}

stop_vision() {
    pkill -f "llama_cpp.server.*$VISION_PORT" 2>/dev/null && echo -e "${G}✓ Vision server stopped${NC}" || echo -e "${Y}⚪ Not running${NC}"
}

start_parakleon() {
    echo -e "${B}Starting Parakleon API (port $PK_PORT)...${NC}"
    if [ ! -f "$PKN_DIR/parakleon_api.py" ]; then
        echo -e "${Y}Warning: parakleon_api.py not found, skipping${NC}"
        return 0
    fi
    
    pkill -f parakleon_api.py 2>/dev/null
    
    if [ -d "$VENV_DIR" ]; then
        source "$VENV_DIR/bin/activate"
    fi
    
    cd "$PKN_DIR"
    nohup python3 parakleon_api.py > "$PKN_DIR/parakleon.log" 2>&1 &
    sleep 2
    pgrep -f parakleon_api.py > /dev/null && echo -e "${G}✓ Parakleon running${NC}" || echo -e "${R}✗ Parakleon failed${NC}"
}

stop_parakleon() {
    pkill -f parakleon_api.py 2>/dev/null && echo -e "${G}✓ Parakleon stopped${NC}" || echo -e "${Y}⚪ Not running${NC}"
}

start_ollama() {
    echo -e "${B}Starting Ollama (port $OLLAMA_PORT)...${NC}"
    if ss -ltnp 2>/dev/null | grep -q ":$OLLAMA_PORT\b"; then
        echo -e "${Y}⚪ Port $OLLAMA_PORT appears to be in use; skipping start to avoid duplicate instances.${NC}"
        pgrep -f "ollama serve" > /dev/null && echo -e "${G}✓ Ollama process detected${NC}" || echo -e "${Y}⚪ Listening socket found but process not detected by pgrep${NC}"
        return 0
    fi
    
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "${B}Attempting to increase RLIMIT_MEMLOCK (ulimit -l unlimited)...${NC}"
        ulimit -l unlimited 2>/dev/null || true
    else
        echo -e "${Y}Note: not running as root; cannot increase RLIMIT_MEMLOCK from this script. If you see 'failed to mlock' warnings, run Ollama as root or increase memlock via /etc/security/limits.conf or systemd LimitMEMLOCK.${NC}"
    fi
    
    nohup ollama serve > "$PKN_DIR/ollama.log" 2>&1 &
    sleep 2
    
    if pgrep -f "ollama serve" > /dev/null || ss -ltnp 2>/dev/null | grep -q ":$OLLAMA_PORT\b"; then
        echo -e "${G}✓ Ollama running${NC}"
    else
        echo -e "${R}✗ Ollama failed${NC}"
    fi
}

stop_ollama() {
    pkill -f "ollama serve" 2>/dev/null && echo -e "${G}✓ Ollama stopped${NC}" || echo -e "${Y}⚪ Not running${NC}"
}

# ===== NEW: Debug/diagnostic function =====
debug_qwen() {
    echo -e "${B}========================================${NC}"
    echo -e "${B}Qwen2.5 Agent Diagnostics${NC}"
    echo -e "${B}========================================${NC}"
    
    # Check model file
    if [ -f "$GGUF_MODEL" ]; then
        echo -e "${G}✓ Model file exists${NC}: $(du -h "$GGUF_MODEL" | cut -f1)"
    else
        echo -e "${R}✗ Model file missing${NC}: $GGUF_MODEL"
        return 1
    fi
    
    # Check llama.cpp server
    echo -n "llama.cpp server: "
    if pgrep -f "llama_cpp.server.*$LLAMA_PORT" > /dev/null; then
        echo -e "${G}✓ Running${NC}"
    else
        echo -e "${R}✗ Not running${NC}"
        echo "Starting..."
        start_llama || return 1
    fi
    
    # Test /v1/models endpoint
    echo -n "Testing /v1/models: "
    MODELS=$(curl -s http://localhost:$LLAMA_PORT/v1/models 2>/dev/null)
    if [ ! -z "$MODELS" ] && echo "$MODELS" | grep -q '"id"'; then
        echo -e "${G}✓ Responding${NC}"
        echo "  Models: $(echo "$MODELS" | grep -o '"id":"[^"]*"' | head -1)"
    else
        echo -e "${R}✗ No response${NC}"
    fi
    
    # Test chat completions (quick)
    echo -n "Testing /v1/chat/completions: "
    RESPONSE=$(curl -s http://localhost:$LLAMA_PORT/v1/chat/completions \
        -H "Content-Type: application/json" \
        -d '{"model":"local","messages":[{"role":"user","content":"Hi"}],"max_tokens":50,"temperature":0.2}' \
        2>/dev/null)
    
    if echo "$RESPONSE" | grep -q "choices"; then
        CONTENT=$(echo "$RESPONSE" | grep -o '"content":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo -e "${G}✓ Responding${NC}"
        echo "  Sample: ${CONTENT:0:60}..."
    else
        echo -e "${R}✗ Failed${NC}"
        echo "  Response: ${RESPONSE:0:100}"
    fi
    
    # Check LangChain
    echo -n "LangChain integration: "
    python3 -c "from langchain_openai import ChatOpenAI; print('✓')" 2>/dev/null && echo -e "${G}✓ Ready${NC}" || echo -e "${R}✗ Not installed${NC}"
    
    # Recent logs
    echo -e "${B}========================================${NC}"
    echo "Recent llama.cpp log (last 5 lines):"
    tail -5 "$PKN_DIR/llama.log" 2>/dev/null || echo "(no log yet)"
    echo -e "${B}========================================${NC}"
}

status() {
    echo -e "${B}========================================${NC}"
    echo -e "${B}PKN Server Status${NC}"
    echo -e "${B}========================================${NC}"
    pgrep -f divinenode_server.py > /dev/null && echo -e "${G}✓ DivineNode (8010)${NC}" || echo -e "${R}✗ DivineNode${NC}"
    pgrep -f "llama_cpp.server.*$LLAMA_PORT" > /dev/null && echo -e "${G}✓ llama.cpp Qwen (8000)${NC}" || echo -e "${R}✗ llama.cpp Qwen${NC}"
    pgrep -f "llama_cpp.server.*$VISION_PORT" > /dev/null && echo -e "${G}✓ Vision LLaVA (8001)${NC}" || echo -e "${R}✗ Vision LLaVA${NC}"
    pgrep -f parakleon_api.py > /dev/null && echo -e "${G}✓ Parakleon (9000)${NC}" || echo -e "${R}✗ Parakleon${NC}"
    pgrep -f "ollama serve" > /dev/null && echo -e "${G}✓ Ollama (11434)${NC}" || echo -e "${R}✗ Ollama${NC}"
    echo -e "${B}========================================${NC}"
}

start_all() {
    echo -e "${B}Starting all PKN services...${NC}"
    start_divinenode
    start_llama
    start_parakleon
    start_ollama
    sleep 3
    xdg-open "http://localhost:$DN_PORT/pkn.html" 2>/dev/null &
}

stop_all() {
    echo -e "${B}Stopping all PKN services...${NC}"
    stop_divinenode
    stop_llama
    stop_parakleon
    stop_ollama
}

restart_divinenode() {
    echo "Restarting DivineNode..."
    stop_divinenode
    sleep 2
    start_divinenode
}

restart_llama() {
    echo "Restarting llama.cpp..."
    stop_llama
    sleep 2
    start_llama
}

restart_vision() {
    echo "Restarting vision server..."
    stop_vision
    sleep 2
    start_vision
}

monitor() {
    python3 "$PKN_DIR/pkn_health.py" "$@"
}

setup() {
    python3 "$PKN_DIR/pkn_setup.py"
}

cli() {
    "$PKN_DIR/pkn-cli" "${@:2}"
}

case "$1" in
    start-all) start_all ;;
    stop-all) stop_all ;;
    start-divinenode) start_divinenode ;;
    stop-divinenode) stop_divinenode ;;
    restart-divinenode) restart_divinenode ;;
    start-llama) start_llama ;;
    stop-llama) stop_llama ;;
    restart-llama) restart_llama ;;
    start-vision) start_vision ;;
    stop-vision) stop_vision ;;
    restart-vision) restart_vision ;;
    start-parakleon) start_parakleon ;;
    stop-parakleon) stop_parakleon ;;
    start-ollama) start_ollama ;;
    stop-ollama) stop_ollama ;;
    status) status ;;
    debug-qwen) debug_qwen ;;
    monitor) monitor "${@:2}" ;;
    setup) setup ;;
    cli) cli ;;
    *)
        echo "Usage: $0 {start-all|stop-all|start/stop/restart-divinenode|start/stop/restart-llama|start/stop/restart-vision|start/stop-parakleon|start/stop-ollama|status|debug-qwen|monitor|setup|cli}"
        exit 1
        ;;
esac
