#!/usr/bin/env python3
"""Test all agents with tools enabled"""
import requests
import time

def test_agent(agent_type, message, timeout=180):
    """Test a specific agent"""
    print(f"\n{'='*60}")
    print(f"Testing {agent_type.upper()} agent...")
    print(f"{'='*60}")

    start = time.time()

    try:
        response = requests.post(
            "http://localhost:8010/api/multi-agent/chat",
            json={
                "message": message,
                "mode": "auto",
                "agent_override": agent_type
            },
            timeout=timeout
        )

        elapsed = time.time() - start

        if response.status_code == 200:
            result = response.json()
            print(f"✅ SUCCESS after {elapsed:.1f}s")
            print(f"🤖 Agent: {result.get('agent_used')}")
            print(f"🔧 Tools enabled: {result.get('routing', {}).get('agent_config', {}).get('tools_enabled')}")
            print(f"🛠️ Tools used: {result.get('tools_used', [])}")
            print(f"📝 Response: {result.get('response')[:200]}...")
            return True
        else:
            print(f"❌ FAILED: HTTP {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"⏱️ TIMEOUT after {elapsed:.1f}s")
        return False
    except Exception as e:
        elapsed = time.time() - start
        print(f"❌ ERROR after {elapsed:.1f}s: {e}")
        return False

# Test agents
print("🧪 Testing All Agents with Tools Enabled")
print("="*60)

results = {}

# Test GENERAL (fast - uses ollama)
results['general'] = test_agent('general', 'Hello, how are you?', timeout=90)

# Test REASONER (uses ollama on PC? or llamacpp?)
results['reasoner'] = test_agent('reasoner', 'Plan how to build a simple web app', timeout=120)

# Test RESEARCHER (with web tools)
results['researcher'] = test_agent('researcher', 'What is Python?', timeout=120)

# Test EXECUTOR (with system tools)
results['executor'] = test_agent('executor', 'List the current directory', timeout=120)

# Test CODER (slow - uses llamacpp)
# results['coder'] = test_agent('coder', 'Write hello world in Python', timeout=180)

# Summary
print(f"\n{'='*60}")
print("SUMMARY")
print(f"{'='*60}")
for agent, success in results.items():
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{agent.upper():15} {status}")
print(f"{'='*60}")
print(f"Passed: {sum(results.values())}/{len(results)}")
