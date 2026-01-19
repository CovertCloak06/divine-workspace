#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  PKN Mobile - Termux Menu System
#  Cyberpunk Edition for Android/Termux
# ═══════════════════════════════════════════════════════════════════════════════

PKN_HOME="$HOME/pkn"
PKN_PORT="8010"
PKN_URL="http://127.0.0.1:${PKN_PORT}"
LOG_FILE="$PKN_HOME/data/server.log"

# ═══════════════════════════════════════════════════════════════════════════════
#  COLORS
# ═══════════════════════════════════════════════════════════════════════════════
C_RESET='\033[0m'
C_CYAN='\033[1;36m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'
C_MAGENTA='\033[1;35m'
C_BLUE='\033[1;34m'
C_DIM='\033[2m'
C_BOLD='\033[1m'

# ═══════════════════════════════════════════════════════════════════════════════
#  ANIMATIONS
# ═══════════════════════════════════════════════════════════════════════════════
typewrite() {
    local text="$1" delay="${2:-0.01}"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

spinner() {
    local pid=$1 msg="${2:-Loading}"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${C_CYAN}${spin:$i:1}${C_RESET} ${msg}..."
        i=$(( (i+1) % ${#spin} ))
        sleep 0.1
    done
    printf "\r"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════════
show_banner() {
    clear
    echo ""
    # Gh0st ASCII art - no box, blue gradient (matching PC bashrc style)
    echo -e "\033[38;2;100;149;237m       ▄▄▄▄   ▄▄          ▄▄▄▄"
    echo -e "\033[38;2;80;130;220m     ██▀▀▀▀█  ██         ██▀▀██              ██"
    echo -e "\033[38;2;65;105;225m    ██        ██▄████▄  ██    ██  ▄▄█████▄ ███████"
    echo -e "\033[38;2;50;80;200m    ██  ▄▄▄▄  ██▀   ██  ██ ██ ██  ██▄▄▄▄ ▀   ██"
    echo -e "\033[38;2;30;60;180m    ██  ▀▀██  ██    ██  ██    ██   ▀▀▀▀██▄   ██"
    echo -e "\033[38;2;20;40;160m     ██▄▄▄██  ██    ██   ██▄▄██   █▄▄▄▄▄██   ██▄▄▄"
    echo -e "\033[38;2;10;20;140m       ▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀▀▀▀▀     ▀▀▀▀\033[0m"
    echo ""
    echo -e "${C_DIM}         Divine Node • Multi-Agent AI${C_RESET}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STATUS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════
show_status() {
    local server_status ollama_status backend_mode

    # Check server
    if curl -s "$PKN_URL/health" > /dev/null 2>&1; then
        server_status="${C_GREEN}● ONLINE${C_RESET}"
    else
        server_status="${C_RED}○ OFFLINE${C_RESET}"
    fi

    # Check Ollama
    if curl -s "http://127.0.0.1:11434/api/tags" > /dev/null 2>&1; then
        ollama_status="${C_GREEN}● READY${C_RESET}"
    else
        ollama_status="${C_YELLOW}○ NOT RUNNING${C_RESET}"
    fi

    # Check backend mode
    backend_mode=$(curl -s "$PKN_URL/api/multi-agent/backend" 2>/dev/null | grep -o '"backend":"[^"]*"' | cut -d'"' -f4)
    if [ "$backend_mode" = "cloud" ]; then
        backend_mode="${C_MAGENTA}☁ CLOUD (Groq)${C_RESET}"
    elif [ "$backend_mode" = "local" ]; then
        backend_mode="${C_BLUE}🏠 LOCAL (Ollama)${C_RESET}"
    else
        backend_mode="${C_DIM}─ UNKNOWN${C_RESET}"
    fi

    echo -e "    ${C_DIM}┌────────────────────────────────┐${C_RESET}"
    echo -e "    ${C_DIM}│${C_RESET} Server:  $server_status"
    echo -e "    ${C_DIM}│${C_RESET} Ollama:  $ollama_status"
    echo -e "    ${C_DIM}│${C_RESET} Backend: $backend_mode"
    echo -e "    ${C_DIM}└────────────────────────────────┘${C_RESET}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MENU
# ═══════════════════════════════════════════════════════════════════════════════
show_menu() {
    echo -e "    ${C_CYAN}┌────────────────────────────────┐${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET} ${C_GREEN}SERVER${C_RESET}                         ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}├────────────────────────────────┤${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_GREEN}1${C_RESET}) 🚀 Start Server            ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_GREEN}2${C_RESET}) 🌐 Start + Browser         ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_YELLOW}3${C_RESET}) 🔄 Restart                 ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_RED}4${C_RESET}) ⛔ Stop                    ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_BLUE}5${C_RESET}) 📊 System Status           ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}├────────────────────────────────┤${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET} ${C_MAGENTA}BACKEND${C_RESET}                        ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}├────────────────────────────────┤${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_MAGENTA}6${C_RESET}) ☁️  Cloud (Groq)            ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_BLUE}7${C_RESET}) 🏠 Local (Ollama)          ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_CYAN}8${C_RESET}) 🦙 Start Ollama            ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}├────────────────────────────────┤${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET} ${C_DIM}DIAGNOSTICS${C_RESET}                    ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}├────────────────────────────────┤${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_DIM}9${C_RESET}) 📋 View Logs               ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET} ${C_DIM}10${C_RESET}) 🔧 Test Endpoint           ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}├────────────────────────────────┤${C_RESET}"
    echo -e "    ${C_CYAN}│${C_RESET}  ${C_GREEN}0${C_RESET}) 🐚 Exit Shell ${C_DIM}[Enter]${C_RESET}    ${C_CYAN}│${C_RESET}"
    echo -e "    ${C_CYAN}└────────────────────────────────┘${C_RESET}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ACTIONS
# ═══════════════════════════════════════════════════════════════════════════════
start_server() {
    echo -e "\n${C_CYAN}▸ Starting PKN Server...${C_RESET}"

    # Kill any existing processes
    pkill -f 'python.*backend' 2>/dev/null
    pkill -f 'python.*server' 2>/dev/null
    sleep 1

    # Verify PKN_HOME exists
    if [ ! -d "$PKN_HOME/backend" ]; then
        echo -e "${C_RED}✗ Backend not found at $PKN_HOME/backend${C_RESET}"
        echo -e "${C_DIM}  Run: git clone or copy files to $PKN_HOME${C_RESET}"
        return 1
    fi

    # Load environment variables
    if [ -f "$PKN_HOME/.env" ]; then
        set -a
        source "$PKN_HOME/.env"
        set +a
        echo -e "${C_DIM}  └─ Loaded .env${C_RESET}"
    fi

    # Create data directory
    mkdir -p "$PKN_HOME/data"
    mkdir -p "$(dirname "$LOG_FILE")"

    # Start server as Python module (CRITICAL: must use -m)
    cd "$PKN_HOME"
    echo -e "${C_DIM}  └─ Starting: python -m backend.server${C_RESET}"
    nohup python -m backend.server > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    echo -e "${C_DIM}  └─ PID: $SERVER_PID${C_RESET}"

    # Wait for startup with progress
    echo -ne "${C_CYAN}  └─ Waiting for server"
    for i in {1..15}; do
        sleep 1
        echo -n "."
        if curl -s "$PKN_URL/health" > /dev/null 2>&1; then
            echo -e "${C_RESET}"
            echo -e "${C_GREEN}✓ Server started on $PKN_URL${C_RESET}"

            # Show agent/tool counts
            status=$(curl -s "$PKN_URL/api/multi-agent/agents" 2>/dev/null)
            agents=$(echo "$status" | grep -o '"count":[0-9]*' | cut -d: -f2)
            [ -n "$agents" ] && echo -e "${C_DIM}  └─ $agents agents loaded${C_RESET}"

            # Show backend mode
            backend=$(curl -s "$PKN_URL/api/multi-agent/backend" 2>/dev/null | grep -o '"backend":"[^"]*"' | cut -d'"' -f4)
            [ -n "$backend" ] && echo -e "${C_DIM}  └─ Backend: $backend${C_RESET}"
            return 0
        fi
    done

    echo -e "${C_RESET}"
    echo -e "${C_RED}✗ Server failed to start after 15 seconds${C_RESET}"
    echo -e "${C_YELLOW}  Last 10 lines of log:${C_RESET}"
    tail -10 "$LOG_FILE" 2>/dev/null
    return 1
}

stop_server() {
    echo -e "\n${C_YELLOW}▸ Stopping PKN Server...${C_RESET}"
    pkill -f 'python.*backend' 2>/dev/null
    pkill -f 'python.*server' 2>/dev/null
    sleep 1
    # Verify stopped
    if pgrep -f 'python.*backend' > /dev/null 2>&1; then
        echo -e "${C_YELLOW}⚠ Force killing...${C_RESET}"
        pkill -9 -f 'python.*backend' 2>/dev/null
    fi
    echo -e "${C_GREEN}✓ Server stopped${C_RESET}"
}

restart_server() {
    echo -e "\n${C_CYAN}▸ Restarting PKN Server...${C_RESET}"
    stop_server
    sleep 1
    start_server
}

open_browser() {
    local cache_bust="?v=$(date +%s)"
    am start -n com.android.chrome/com.google.android.apps.chrome.Main \
        -a android.intent.action.VIEW \
        -d "${PKN_URL}${cache_bust}" \
        --ez incognito true \
        >/dev/null 2>&1
    echo -e "${C_GREEN}✓ Opened in Chrome Incognito${C_RESET}"
}

switch_backend() {
    local mode="$1"
    echo -e "\n${C_CYAN}▸ Switching to ${mode} backend...${C_RESET}"

    response=$(curl -s -X POST "$PKN_URL/api/multi-agent/backend" \
        -H "Content-Type: application/json" \
        -d "{\"backend\": \"$mode\"}" 2>&1)

    if echo "$response" | grep -q '"success":true'; then
        if [ "$mode" = "cloud" ]; then
            echo -e "${C_MAGENTA}✓ Switched to Cloud (Groq) - ~0.3s responses${C_RESET}"
        else
            echo -e "${C_BLUE}✓ Switched to Local (Ollama) - uncensored${C_RESET}"
        fi
    else
        echo -e "${C_RED}✗ Failed to switch backend${C_RESET}"
        echo -e "${C_DIM}$response${C_RESET}"
    fi
}

start_ollama() {
    echo -e "\n${C_CYAN}▸ Starting Ollama...${C_RESET}"
    if pgrep -x "ollama" > /dev/null; then
        echo -e "${C_YELLOW}⚠ Ollama already running${C_RESET}"
    else
        nohup ollama serve > /dev/null 2>&1 &
        sleep 3
        if curl -s "http://127.0.0.1:11434/api/tags" > /dev/null 2>&1; then
            echo -e "${C_GREEN}✓ Ollama started${C_RESET}"
        else
            echo -e "${C_RED}✗ Ollama failed to start${C_RESET}"
        fi
    fi
}

detailed_status() {
    echo -e "\n${C_CYAN}═══════════════ SYSTEM STATUS ═══════════════${C_RESET}\n"

    # Server health
    echo -e "${C_BOLD}Server Health:${C_RESET}"
    curl -s "$PKN_URL/health" 2>/dev/null | python -m json.tool 2>/dev/null || echo -e "${C_RED}  Not responding${C_RESET}"
    echo ""

    # Backend status
    echo -e "${C_BOLD}Backend Status:${C_RESET}"
    curl -s "$PKN_URL/api/multi-agent/backend" 2>/dev/null | python -m json.tool 2>/dev/null || echo -e "${C_RED}  Not responding${C_RESET}"
    echo ""

    # Cloud providers
    echo -e "${C_BOLD}Cloud Providers:${C_RESET}"
    curl -s "$PKN_URL/api/multi-agent/cloud/status" 2>/dev/null | python -m json.tool 2>/dev/null || echo -e "${C_DIM}  Server not running${C_RESET}"
    echo ""

    # Ollama models
    echo -e "${C_BOLD}Ollama Models:${C_RESET}"
    curl -s "http://127.0.0.1:11434/api/tags" 2>/dev/null | python -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for m in data.get('models', [])[:5]:
        size = m.get('size', 0) / 1e9
        print(f\"  • {m['name']} ({size:.1f}GB)\")
except: print('  Ollama not running')
" 2>/dev/null || echo -e "${C_YELLOW}  Ollama not running${C_RESET}"
}

view_logs() {
    echo -e "\n${C_CYAN}═══════════════ SERVER LOGS ═══════════════${C_RESET}\n"
    if [ -f "$LOG_FILE" ]; then
        tail -30 "$LOG_FILE"
    else
        echo -e "${C_DIM}No logs found${C_RESET}"
    fi
}

test_chat() {
    echo -e "\n${C_CYAN}▸ Testing chat endpoint...${C_RESET}"
    local start_time=$(date +%s.%N)

    response=$(curl -s -X POST "$PKN_URL/api/multi-agent/chat" \
        -H "Content-Type: application/json" \
        -d '{"message": "Say hello in 5 words", "mode": "auto"}' 2>&1)

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)

    if echo "$response" | grep -q '"status":"success"'; then
        local agent=$(echo "$response" | grep -o '"agent_used":"[^"]*"' | cut -d'"' -f4)
        local reply=$(echo "$response" | grep -o '"response":"[^"]*"' | cut -d'"' -f4 | head -c 50)
        echo -e "${C_GREEN}✓ Response in ${elapsed}s${C_RESET}"
        echo -e "${C_DIM}  Agent: $agent${C_RESET}"
        echo -e "${C_DIM}  Reply: $reply...${C_RESET}"
    else
        echo -e "${C_RED}✗ Chat failed${C_RESET}"
        echo -e "${C_DIM}$response${C_RESET}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  BOOT SEQUENCE
# ═══════════════════════════════════════════════════════════════════════════════
boot_sequence() {
    clear
    echo ""
    echo -e "${C_CYAN}"
    typewrite "    ▓▓▓ INITIALIZING GH0ST MOBILE ▓▓▓" 0.02
    echo -e "${C_RESET}"
    sleep 0.3

    echo -e "${C_DIM}    Loading Divine Node...${C_RESET}"
    sleep 0.2
    echo -e "${C_DIM}    Checking services...${C_RESET}"
    sleep 0.2
    echo -e "${C_GREEN}    ✓ System ready${C_RESET}"
    sleep 0.5
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    boot_sequence

    while true; do
        show_banner
        show_status
        show_menu

        echo -ne "    ${C_CYAN}▶${C_RESET} Choice: "
        read -r choice

        case "$choice" in
            1) start_server; read -p "    Press Enter..." ;;
            2) start_server && sleep 1 && open_browser; read -p "    Press Enter..." ;;
            3) restart_server; read -p "    Press Enter..." ;;
            4) stop_server; read -p "    Press Enter..." ;;
            5) detailed_status; read -p "    Press Enter..." ;;
            6) switch_backend "cloud"; read -p "    Press Enter..." ;;
            7) switch_backend "local"; read -p "    Press Enter..." ;;
            8) start_ollama; read -p "    Press Enter..." ;;
            9) view_logs; read -p "    Press Enter..." ;;
            10) test_chat; read -p "    Press Enter..." ;;
            0|q|Q|"")
                # 0, q, or just Enter exits to shell
                echo -e "\n${C_GREEN}    → Exiting to shell...${C_RESET}"
                sleep 0.3
                clear
                cd ~
                return 0
                ;;
            *) echo -e "${C_RED}    Invalid option${C_RESET}"; sleep 0.5 ;;
        esac
    done
}

main "$@"
