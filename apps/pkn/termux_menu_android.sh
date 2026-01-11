#!/bin/bash
# ===========================================
# PKN TERMUX STARTUP MENU - UPDATED 2024-12-30
# ===========================================
# All paths updated for Android/Termux
# Supports new advanced features (RAG, Planning, Delegation, etc.)
# ===========================================

# Prevent loop - if already shown, skip
if [ "$PKN_MENU_SHOWN" = "1" ]; then
    return 2>/dev/null || exit 0
fi

# Detect PKN location
if [ -d "/sdcard/pkn" ]; then
    PKN_DIR="/sdcard/pkn"
elif [ -d "$HOME/pkn" ]; then
    PKN_DIR="$HOME/pkn"
else
    echo "❌ PKN directory not found! Extract pkn_android_transfer.tar.gz first."
    exit 1
fi

show_menu() {
    clear
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║                                        ║"
    echo "║      ⚡ DIVINE NODE / PKN ⚡             ║"
    echo "║        👑 Android Terminal 👑          ║"
    echo "║                                        ║"
    echo "╠════════════════════════════════════════╣"
    echo "║                                        ║"
    echo "║   [1] 💻  Regular Terminal             ║"
    echo "║   [2] 🚀  Start All Services           ║"
    echo "║   [3] 🛑  Stop All Services            ║"
    echo "║   [4] 📊  Server Status                ║"
    echo "║   [5] 🔧  Start Flask Only             ║"
    echo "║   [6] 🦙  Start LLM Only               ║"
    echo "║   [7] 📈  Show Agent Metrics           ║"
    echo "║   [8] 🌐  Open in Browser              ║"
    echo "║                                        ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    echo "  📂 PKN Location: $PKN_DIR"
    echo ""
    echo -n "  🎯 Select [1-8]: "
    read choice
}

start_flask() {
    echo "🔄 Starting Flask server..."

    # Kill any existing Flask instance
    pkill -f divinenode_server.py 2>/dev/null
    sleep 1

    # Clear port 8010 if occupied
    PID_8010=$(lsof -ti :8010 2>/dev/null)
    if [ -n "$PID_8010" ]; then
        echo "  Clearing port 8010..."
        kill -9 $PID_8010 2>/dev/null
        sleep 1
    fi

    # Start Flask
    cd "$PKN_DIR"

    # Activate venv if it exists
    if [ -f "$PKN_DIR/.venv/bin/activate" ]; then
        source "$PKN_DIR/.venv/bin/activate"
    fi

    nohup python divinenode_server.py --host 0.0.0.0 --port 8010 > "$PKN_DIR/server.log" 2>&1 &
    sleep 2

    if pgrep -f divinenode_server.py > /dev/null; then
        echo "✅ Flask server started (port 8010)"
    else
        echo "❌ Flask server failed to start"
        echo "   Check: $PKN_DIR/server.log"
    fi
}

start_llm() {
    echo "🔄 Starting LLM server..."

    # Kill any existing llama-server instance
    pkill -f llama-server 2>/dev/null
    pkill -f "llama.cpp.server" 2>/dev/null
    sleep 1

    # Clear port 8000 if occupied
    PID_8000=$(lsof -ti :8000 2>/dev/null)
    if [ -n "$PID_8000" ]; then
        echo "  Clearing port 8000..."
        kill -9 $PID_8000 2>/dev/null
        sleep 1
    fi

    # Find model file
    MODEL_FILE=$(find "$PKN_DIR/llama.cpp/models" -name "*.gguf" | grep -v "vocab" | head -1)

    if [ -z "$MODEL_FILE" ]; then
        echo "❌ No GGUF model found in $PKN_DIR/llama.cpp/models"
        return 1
    fi

    echo "  Using model: $(basename $MODEL_FILE)"

    # Try Python server (llama-cpp-python)
    if python -c "import llama_cpp.server" 2>/dev/null; then
        echo "  Using llama-cpp-python server..."
        cd "$PKN_DIR"
        nohup python -m llama_cpp.server \
            --model "$MODEL_FILE" \
            --host 0.0.0.0 \
            --port 8000 \
            --chat_format qwen \
            --n_ctx 8192 \
            > "$PKN_DIR/llama.log" 2>&1 &
    # Try built llama-server binary
    elif [ -f "$PKN_DIR/llama.cpp/build/bin/llama-server" ]; then
        echo "  Using compiled llama-server..."
        nohup "$PKN_DIR/llama.cpp/build/bin/llama-server" \
            -m "$MODEL_FILE" \
            --host 0.0.0.0 \
            --port 8000 \
            > "$PKN_DIR/llama.log" 2>&1 &
    else
        echo "❌ No LLM server available"
        echo "   Install: pip install llama-cpp-python"
        echo "   Or build: cd $PKN_DIR/llama.cpp && make"
        return 1
    fi

    sleep 3

    if lsof -ti :8000 > /dev/null 2>&1; then
        echo "✅ LLM server started (port 8000)"
    else
        echo "❌ LLM server failed to start"
        echo "   Check: $PKN_DIR/llama.log"
    fi
}

launch_all() {
    echo ""
    echo "🚀 Starting all services..."
    echo ""
    start_flask
    echo ""
    start_llm
    echo ""
    show_urls
    echo ""
    read -p "Press Enter to continue..."

    # Try to open browser
    am start -a android.intent.action.VIEW -d "http://127.0.0.1:8010/pkn.html" 2>/dev/null
}

stop_all() {
    echo ""
    echo "🛑 Stopping all services..."
    pkill -f divinenode_server.py 2>/dev/null && echo "✅ Flask stopped" || echo "⚪ Flask not running"
    pkill -f llama-server 2>/dev/null && echo "✅ LLM stopped" || echo "⚪ LLM not running"
    pkill -f "llama.cpp.server" 2>/dev/null
    echo ""
    read -p "Press Enter to continue..."
}

show_status() {
    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║       📊 Server Status               ║"
    echo "╠══════════════════════════════════════╣"

    # Flask status
    if pgrep -f divinenode_server.py > /dev/null; then
        echo "║ ✅ Flask: Running (port 8010)       ║"
    else
        echo "║ ❌ Flask: Stopped                   ║"
    fi

    # LLM status
    if lsof -ti :8000 > /dev/null 2>&1; then
        echo "║ ✅ LLM: Running (port 8000)         ║"
    else
        echo "║ ❌ LLM: Stopped                     ║"
    fi

    echo "╠══════════════════════════════════════╣"
    echo "║       🎯 Advanced Features           ║"
    echo "╠══════════════════════════════════════╣"

    # Check if features are available
    cd "$PKN_DIR"
    if [ -f "$PKN_DIR/.venv/bin/activate" ]; then
        source "$PKN_DIR/.venv/bin/activate"
    fi

    # Check ChromaDB (RAG)
    if python -c "import chromadb" 2>/dev/null; then
        echo "║ ✅ RAG: Available                   ║"
    else
        echo "║ ⚠️  RAG: ChromaDB not installed     ║"
    fi

    # Check Docker (Sandbox)
    if command -v docker > /dev/null 2>&1; then
        echo "║ ✅ Sandbox: Docker mode             ║"
    else
        echo "║ ⚠️  Sandbox: Subprocess mode        ║"
    fi

    echo "║ ✅ Planning: Available               ║"
    echo "║ ✅ Delegation: Available             ║"
    echo "║ ✅ Tool Chaining: Available          ║"
    echo "║ ✅ Evaluation: Available             ║"

    echo "╚══════════════════════════════════════╝"
    echo ""

    show_urls

    echo ""
    read -p "Press Enter to continue..."
}

show_urls() {
    IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -1)
    if [ -z "$IP" ]; then
        IP="127.0.0.1"
    fi

    echo "╔══════════════════════════════════════╗"
    echo "║         🌐 Access URLs               ║"
    echo "╠══════════════════════════════════════╣"
    echo "║ UI: http://$IP:8010/pkn.html"
    echo "║ API: http://$IP:8010/api/"
    echo "║ LLM: http://$IP:8000/v1/"
    echo "╚══════════════════════════════════════╝"
}

show_metrics() {
    echo ""
    echo "📈 Fetching agent metrics..."
    echo ""

    if ! pgrep -f divinenode_server.py > /dev/null; then
        echo "❌ Flask server not running. Start services first."
        read -p "Press Enter to continue..."
        return
    fi

    curl -s http://127.0.0.1:8010/api/metrics/report?days=7 | python -m json.tool 2>/dev/null || {
        echo "❌ Failed to fetch metrics"
        echo "   Make sure Flask is running and has processed some requests"
    }

    echo ""
    read -p "Press Enter to continue..."
}

open_browser() {
    echo ""
    echo "🌐 Opening browser..."
    am start -a android.intent.action.VIEW -d "http://127.0.0.1:8010/pkn.html" 2>/dev/null && {
        echo "✅ Browser opened"
    } || {
        echo "❌ Failed to open browser"
        echo "   Manually open: http://127.0.0.1:8010/pkn.html"
    }
    echo ""
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    show_menu
    case $choice in
        1)
            export PKN_MENU_SHOWN=1
            clear
            echo ""
            echo "  👋 Welcome to PKN Terminal!"
            echo "  💡 Run 'source $PKN_DIR/termux_menu_android.sh' to show menu again"
            echo ""
            cd "$PKN_DIR"
            break
            ;;
        2)
            launch_all
            ;;
        3)
            stop_all
            ;;
        4)
            show_status
            ;;
        5)
            echo ""
            start_flask
            echo ""
            read -p "Press Enter to continue..."
            ;;
        6)
            echo ""
            start_llm
            echo ""
            read -p "Press Enter to continue..."
            ;;
        7)
            show_metrics
            ;;
        8)
            open_browser
            ;;
        *)
            echo "  ⚠️  Invalid option, try again..."
            sleep 1
            ;;
    esac
done
