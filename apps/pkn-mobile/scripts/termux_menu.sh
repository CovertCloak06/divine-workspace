#!/bin/bash
PKN_HOME="$HOME/pkn-phone"
PKN_PORT="8010"
PKN_URL="http://127.0.0.1:${PKN_PORT}"

show_menu() {
    clear
    echo "╔══════════════════════════════════════╗"
    echo "║       ⚡ PKN MOBILE MENU ⚡          ║"
    echo "╠══════════════════════════════════════╣"
    echo "║  1) Start PKN Server                 ║"
    echo "║  2) Start + Open (Incognito)         ║"
    echo "║  3) Stop Server                      ║"
    echo "║  4) Check Status                     ║"
    echo "║  5) View Logs                        ║"
    echo "║  6) Open Incognito Only              ║"
    echo "║  0) Exit                             ║"
    echo "╚══════════════════════════════════════╝"
}

start_server() {
    pkill -f server.py 2>/dev/null
    sleep 1
    # Source environment variables (OpenAI API key)
    source ~/.bashrc
    cd "$PKN_HOME"
    nohup python3 server.py > server.log 2>&1 &
    sleep 3
    if curl -s "$PKN_URL/health" > /dev/null; then
        echo "✓ Server started on $PKN_URL"
    else
        echo "✗ Server failed to start"
        tail -10 server.log
    fi
}

open_browser() {
    am start -n com.android.chrome/com.google.android.apps.chrome.Main \
        -a android.intent.action.VIEW \
        -d "${PKN_URL}" \
        --ez incognito true \
        >/dev/null 2>&1
    echo "✓ Opened in Chrome Incognito"
}

stop_server() {
    pkill -f server.py 2>/dev/null
    echo "✓ Server stopped"
}

check_status() {
    if curl -s "$PKN_URL/health" > /dev/null 2>&1; then
        echo "✓ Server is RUNNING"
        curl -s "$PKN_URL/health" | python3 -m json.tool 2>/dev/null
    else
        echo "✗ Server is NOT running"
    fi
}

view_logs() {
    tail -20 "$PKN_HOME/server.log" 2>/dev/null || echo "No logs"
}

while true; do
    show_menu
    echo -n "Choice: "
    read choice
    case $choice in
        1) start_server; read -p "Press Enter..." ;;
        2) start_server; sleep 1; open_browser; read -p "Press Enter..." ;;
        3) stop_server; read -p "Press Enter..." ;;
        4) check_status; read -p "Press Enter..." ;;
        5) view_logs; read -p "Press Enter..." ;;
        6) open_browser; read -p "Press Enter..." ;;
        0) clear; exit 0 ;;
        *) echo "Invalid option"; sleep 1 ;;
    esac
done
