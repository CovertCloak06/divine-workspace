#!/usr/bin/env python3
"""Test agent tool calling capabilities"""
import requests
import json

# Test CODER agent with file reading tool
print("🧪 Testing CODER agent with file_tools...")
response = requests.post(
    "http://localhost:8010/api/multi-agent/chat",
    json={
        "message": "Read the file /tmp/agent_tools_enabled_summary.md and tell me how many agents were enabled",
        "mode": "coder"
    },
    timeout=30
)

if response.status_code == 200:
    result = response.json()
    print(f"✅ Status: {response.status_code}")
    print(f"📝 Response: {json.dumps(result, indent=2)}")
else:
    print(f"❌ Error: {response.status_code}")
    print(f"📝 Response: {response.text}")
