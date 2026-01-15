#!/usr/bin/env python3
"""Test simple query without agent override"""
import requests
import json

print("🧪 Testing simple query (auto routing)...")
response = requests.post(
    "http://localhost:8010/api/multi-agent/chat",
    json={
        "message": "What is 2+2?",
        "mode": "auto"
    },
    timeout=120
)

if response.status_code == 200:
    result = response.json()
    print(f"✅ Status: {response.status_code}")
    print(f"🤖 Agent used: {result.get('agent_used')}")
    print(f"🔧 Tools enabled: {result.get('routing', {}).get('agent_config', {}).get('tools_enabled')}")
    print(f"🛠️ Tools used: {result.get('tools_used', [])}")
    print(f"⏱️ Execution time: {result.get('execution_time')}s")
    print(f"\n📝 Response: {result.get('response')}")
else:
    print(f"❌ Error: {response.status_code}")
    print(f"📝 Response: {response.text}")
