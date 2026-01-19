#!/bin/bash
# Termux:Widget - Start Ollama
if pgrep -x "ollama" > /dev/null; then
    echo "Ollama already running"
else
    ollama serve &
    sleep 2
    echo "Ollama started"
fi
ollama list
read -p "Press Enter..."
