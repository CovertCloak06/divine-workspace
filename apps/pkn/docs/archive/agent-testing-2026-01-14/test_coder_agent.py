#!/usr/bin/env python3
"""Test CODER agent specifically"""
import requests
import json

# Test with explicit coding task
print("🧪 Testing CODER agent with code writing task...")
response = requests.post(
    "http://localhost:8010/api/multi-agent/chat",
    json={
        "message": "Write a Python function to calculate fibonacci numbers",
        "mode": "auto",
        "agent_override": "coder"  # Force CODER agent
    },
    timeout=60
)

if response.status_code == 200:
    result = response.json()
    print(f"✅ Status: {response.status_code}")
    print(f"🤖 Agent used: {result.get('agent_used')}")
    print(f"🔧 Tools enabled: {result.get('routing', {}).get('agent_config', {}).get('tools_enabled')}")
    print(f"🛠️ Tools used: {result.get('tools_used', [])}")
    print(f"⏱️ Execution time: {result.get('execution_time')}s")
    print(f"\n📝 Response preview: {result.get('response')[:200]}...")
else:
    print(f"❌ Error: {response.status_code}")
    print(f"📝 Response: {response.text}")
