#!/bin/bash
# Check if PKN server is already running on port 8010
if ! curl -s http://localhost:8010/health > /dev/null 2>&1; then
    echo "Starting PKN server..."
    cd /home/gh0st/dvn/divine-workspace/apps/pkn
    nohup python3 -m backend.server --debug --port 8010 > /tmp/pkn-server.log 2>&1 &
    # Wait for server to start
    for i in {1..10}; do
        if curl -s http://localhost:8010/health > /dev/null 2>&1; then
            echo "PKN server started successfully"
            break
        fi
        sleep 1
    done
else
    echo "PKN server already running"
fi

# Open browser (Chromium)
chromium-browser http://localhost:8010 > /dev/null 2>&1 &
