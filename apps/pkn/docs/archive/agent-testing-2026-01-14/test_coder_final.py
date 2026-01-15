#!/usr/bin/env python3
"""Test CODER agent with tools"""
import requests
import json
import time

print("🧪 Testing CODER agent with tools...")
start = time.time()

try:
    response = requests.post(
        "http://localhost:8010/api/multi-agent/chat",
        json={
            "message": "Write a Python function to calculate fibonacci",
            "mode": "auto",
            "agent_override": "coder"
        },
        timeout=180
    )

    elapsed = time.time() - start

    if response.status_code == 200:
        result = response.json()
        print(f"✅ Success after {elapsed:.1f}s")
        print(f"🤖 Agent: {result.get('agent_used')}")
        print(f"🔧 Tools enabled: {result.get('routing', {}).get('agent_config', {}).get('tools_enabled')}")
        print(f"🛠️ Tools used: {result.get('tools_used', [])}")
        print(f"\n📝 Response preview:")
        print(result.get('response')[:500])
        print("\n✅ CODER agent with tools working!")
    else:
        print(f"❌ Error {response.status_code}: {response.text}")

except requests.exceptions.Timeout:
    elapsed = time.time() - start
    print(f"⏱️ Timeout after {elapsed:.1f}s")
except Exception as e:
    elapsed = time.time() - start
    print(f"❌ Error after {elapsed:.1f}s: {e}")
