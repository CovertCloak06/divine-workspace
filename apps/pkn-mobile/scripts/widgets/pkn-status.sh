#!/bin/bash
# Termux:Widget - Quick Status Check
echo "═══════════════════════════════════"
echo "         PKN STATUS CHECK"
echo "═══════════════════════════════════"
echo ""

# Server
if curl -s http://127.0.0.1:8010/health > /dev/null 2>&1; then
    echo "🟢 PKN Server: ONLINE"
else
    echo "🔴 PKN Server: OFFLINE"
fi

# Ollama
if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
    echo "🟢 Ollama: RUNNING"
else
    echo "🟡 Ollama: NOT RUNNING"
fi

# Backend mode
backend=$(curl -s http://127.0.0.1:8010/api/multi-agent/backend 2>/dev/null | grep -o '"backend":"[^"]*"' | cut -d'"' -f4)
if [ -n "$backend" ]; then
    echo "📡 Backend: $backend"
fi

echo ""
echo "═══════════════════════════════════"
read -p "Press Enter..."
