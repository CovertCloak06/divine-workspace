#!/bin/bash
# Divine Workspace IDE Launcher

# Check if dashboard server is running
if ! curl -s http://localhost:9000 > /dev/null 2>&1; then
    echo "Starting Divine Workspace IDE dashboard..."
    cd /home/gh0st/dvn/divine-workspace/dashboard
    nohup python3 server.py > /tmp/dashboard.log 2>&1 &

    # Wait for server to start
    for i in {1..10}; do
        if curl -s http://localhost:9000 > /dev/null 2>&1; then
            echo "Dashboard started successfully"
            break
        fi
        sleep 1
    done
fi

# Open in default browser
xdg-open http://localhost:9000
