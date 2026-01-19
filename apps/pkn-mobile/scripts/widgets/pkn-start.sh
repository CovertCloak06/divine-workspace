#!/bin/bash
# Termux:Widget - Start PKN Server
cd ~/pkn
pkill -f 'python.*backend' 2>/dev/null
sleep 1
python -m backend.server &
sleep 3
echo "PKN Server started on :8010"
read -p "Press Enter..."
